// Copyright (c) 2024 tinycc-rs contributors
// SPDX-License-Identifier: MIT OR LGPL-2.1-or-later

//! Bounds-checking runtime for the TCC compiler.
//!
//! Tracks all memory regions (stack, heap, mmap, alloca) and validates pointer
//! arithmetic and dereference operations at runtime. Provides the `__bound_*`
//! family of functions used by programs compiled with the `-b` flag.
//!
//! C equivalent: `lib/bcheck.c` (2,261 lines)
//!
//! ## Key Transformations from C
//!
//! | C Construct                  | Rust Replacement                                   |
//! |------------------------------|----------------------------------------------------|
//! | Splay tree (lines 2018-2261) | `BTreeMap<usize, Region>` with `.range()` queries  |
//! | `pthread_spinlock_t`         | `std::sync::Mutex<T>` for portable synchronization |
//! | TLS `no_checking` flag       | `thread_local!(static NO_CHECKING: Cell<i32>)`     |
//! | `malloc`/`free`              | Rust allocator (`Vec`, `Box`, automatic RAII)      |
//! | Linked lists (alloca, jmp)   | `Vec<T>` with `.retain()` and iterators            |
//! | `setjmp`/`longjmp` error     | `Result<T, TccError>` + `?` operator               |
//! | Raw pointer arithmetic       | `usize` address arithmetic (no unsafe)             |
//!
//! ## CVE Remediation
//!
//! The splay tree pointer manipulation in the original C code was a source of
//! potential memory corruption. By replacing it with a `BTreeMap`, all address
//! lookups are bounds-checked and allocation-safe by construction.
//!
//! ## Thread Safety
//!
//! The global [`BOUNDS_CHECKER`] instance is protected by a [`Mutex`]. The
//! thread-local `NO_CHECKING` flag uses `Cell<i32>` inside a `thread_local!`
//! macro, providing zero-cost per-thread enable/disable without synchronization.

use std::cell::Cell;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{LazyLock, Mutex};

use crate::error::{TccError, TccResult};

// ---------------------------------------------------------------------------
// Region type enum
// ---------------------------------------------------------------------------

/// Memory allocation type tag.
///
/// Tracks how a memory region was allocated so that `__bound_exit()` can
/// report leaked allocations with their allocation type.
///
/// C equivalent: `TCC_TYPE_NONE` through `TCC_TYPE_STRDUP` at
/// `bcheck.c` lines 200-205.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RegionType {
    /// No specific allocation type (stack regions, static variables).
    None = 0,
    /// Allocated via `malloc()`.
    Malloc = 1,
    /// Allocated via `calloc()`.
    Calloc = 2,
    /// Allocated via `realloc()`.
    Realloc = 3,
    /// Allocated via `memalign()` / `posix_memalign()`.
    Memalign = 4,
    /// Allocated via `strdup()`.
    Strdup = 5,
}

impl RegionType {
    /// Return a human-readable name for the allocation type.
    ///
    /// C equivalent: `alloc_type[]` array at `bcheck.c` line 1165.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            RegionType::None => "",
            RegionType::Malloc => "malloc",
            RegionType::Calloc => "calloc",
            RegionType::Realloc => "realloc",
            RegionType::Memalign => "memalign",
            RegionType::Strdup => "strdup",
        }
    }
}

// ---------------------------------------------------------------------------
// Region struct
// ---------------------------------------------------------------------------

/// A tracked memory region with address, size, and metadata.
///
/// In the original C code this was `struct tree_node` (a splay tree node).
/// In the Rust port, it is a plain value stored in a `BTreeMap<usize, Region>`
/// keyed by `start` address.
///
/// C equivalent: `struct tree_node` at `bcheck.c` lines 210-217.
#[derive(Debug, Clone)]
pub(crate) struct Region {
    /// Start address of the region.
    pub(crate) start: usize,
    /// Size of the region in bytes.
    pub(crate) size: usize,
    /// How this region was allocated.
    pub(crate) region_type: RegionType,
    /// `true` if the region has been freed (deferred free for use-after-free
    /// detection). Pointers into an invalid region are considered violations.
    pub(crate) is_invalid: bool,
}

// ---------------------------------------------------------------------------
// Alloca / VLA tracking
// ---------------------------------------------------------------------------

/// Alloca/VLA tracking entry.
///
/// When a function allocates stack memory via `alloca()` or a C99
/// variable-length array (VLA), the bounds checker creates an
/// `AllocaEntry` to track the allocation. On function exit
/// ([`BoundsChecker::local_delete`]), all alloca entries for the
/// exiting frame are cleaned up.
///
/// C equivalent: `struct alloca_list_struct` at `bcheck.c` lines 219-224.
#[derive(Debug, Clone)]
pub(crate) struct AllocaEntry {
    /// Frame pointer at allocation time.
    pub(crate) fp: usize,
    /// Allocated address.
    pub(crate) ptr: usize,
    /// Allocation size in bytes.
    pub(crate) size: usize,
}

// ---------------------------------------------------------------------------
// setjmp tracking
// ---------------------------------------------------------------------------

/// `setjmp` tracking entry.
///
/// Each call to `setjmp` (or `sigsetjmp`) records the frame pointers
/// so that `longjmp` can clean up stack regions and alloca entries
/// between the current frame and the saved frame.
///
/// C equivalent: `struct jmp_list_struct` at `bcheck.c` lines 246-252.
#[derive(Debug, Clone)]
pub(crate) struct JmpEntry {
    /// Pointer to `jmp_buf` environment (stored as address).
    pub(crate) penv: usize,
    /// Frame pointer saved at the `setjmp` call.
    pub(crate) fp: usize,
    /// End frame pointer (caller's frame at `setjmp` time).
    pub(crate) end_fp: usize,
    /// Thread ID that called `setjmp`.
    pub(crate) tid: u64,
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Sentinel pointer returned on bounds violation in non-fatal mode.
///
/// Corresponds to `(void *)(-2)` in C. Any dereference of this address
/// will fault, providing a clear signal that a bounds violation occurred.
///
/// C equivalent: `#define INVALID_POINTER ((void *)(-2))` at `bcheck.c`
/// line 208.
pub(crate) const INVALID_POINTER: usize = usize::MAX - 1;

/// Maximum number of deferred frees.
///
/// When a pointer is freed, its region is marked invalid and the address
/// is placed in a circular buffer of size `FREE_REUSE_SIZE`. Only when
/// the buffer wraps around is the region fully removed. This delay helps
/// detect use-after-free bugs.
///
/// C equivalent: `#define FREE_REUSE_SIZE (100)` at `bcheck.c` line 335.
const FREE_REUSE_SIZE: usize = 100;

// ---------------------------------------------------------------------------
// Thread-local no_checking flag
// ---------------------------------------------------------------------------

// Thread-local bounds checking disable flag.
//
// Each thread maintains an independent counter. When the counter is
// non-zero, all bounds checking operations are skipped. This is used
// by signal handlers and internal bounds checker operations to avoid
// recursive checking.
//
// C equivalent: TLS `no_checking` variable at `bcheck.c` lines 355-399.
// Replaces the three-way `HAVE_TLS_VAR` / `HAVE_TLS_FUNC` / `_Atomic`
// dispatch with a single portable `thread_local!` + `Cell<i32>`.
thread_local! {
    static NO_CHECKING: Cell<i32> = const { Cell::new(0) };
}

/// Check if bounds checking is currently disabled for this thread.
///
/// Returns `true` when the per-thread `NO_CHECKING` counter is non-zero,
/// indicating that bounds checks should be skipped.
#[inline]
fn is_checking_disabled() -> bool {
    NO_CHECKING.with(|nc| nc.get() != 0)
}

/// Enable or disable bounds checking for the current thread.
///
/// `no_check > 0` disables checking (increments counter).
/// `no_check < 0` re-enables checking (decrements counter).
///
/// This function is safe to call from signal handlers because it uses
/// a thread-local `Cell` (no locking required).
///
/// C equivalent: `__bounds_checking(int no_check)` at `bcheck.c`
/// lines 488-495.
pub(crate) fn bounds_checking(no_check: i32) {
    NO_CHECKING.with(|nc| {
        nc.set(nc.get().wrapping_add(no_check));
    });
}

// ---------------------------------------------------------------------------
// BoundsStatistics
// ---------------------------------------------------------------------------

/// Bounds checking operation statistics.
///
/// When enabled, tracks the number of each type of bounds checking
/// operation performed. Printed at exit when the `TCC_BOUNDS_PRINT_STATISTIC`
/// environment variable is set.
///
/// C equivalent: Statistics counters at `bcheck.c` lines 402-449.
#[derive(Debug, Default, Clone)]
pub(crate) struct BoundsStatistics {
    /// Number of `__bound_ptr_add` calls.
    pub(crate) ptr_add_count: u64,
    /// Number of `__bound_ptr_indir1` calls.
    pub(crate) ptr_indir1_count: u64,
    /// Number of `__bound_ptr_indir2` calls.
    pub(crate) ptr_indir2_count: u64,
    /// Number of `__bound_ptr_indir4` calls.
    pub(crate) ptr_indir4_count: u64,
    /// Number of `__bound_ptr_indir8` calls.
    pub(crate) ptr_indir8_count: u64,
    /// Number of `__bound_ptr_indir12` calls.
    pub(crate) ptr_indir12_count: u64,
    /// Number of `__bound_ptr_indir16` calls.
    pub(crate) ptr_indir16_count: u64,
    /// Number of `__bound_local_new` calls.
    pub(crate) local_new_count: u64,
    /// Number of `__bound_local_delete` calls.
    pub(crate) local_delete_count: u64,
    /// Number of `__bound_malloc` calls.
    pub(crate) malloc_count: u64,
    /// Number of `__bound_calloc` calls.
    pub(crate) calloc_count: u64,
    /// Number of `__bound_realloc` calls.
    pub(crate) realloc_count: u64,
    /// Number of `__bound_free` calls.
    pub(crate) free_count: u64,
    /// Number of `__bound_memalign` calls.
    pub(crate) memalign_count: u64,
    /// Number of `__bound_mmap` calls.
    pub(crate) mmap_count: u64,
    /// Number of `__bound_munmap` calls.
    pub(crate) munmap_count: u64,
    /// Number of `__bound_new_region` (alloca) calls.
    pub(crate) alloca_count: u64,
    /// Number of `__bound_setjmp` calls.
    pub(crate) setjmp_count: u64,
    /// Number of `__bound_longjmp` calls.
    pub(crate) longjmp_count: u64,
    /// Number of `__bound_memcpy` calls.
    pub(crate) memcpy_count: u64,
    /// Number of `__bound_memcmp` calls.
    pub(crate) memcmp_count: u64,
    /// Number of `__bound_memmove` calls.
    pub(crate) memmove_count: u64,
    /// Number of `__bound_memset` calls.
    pub(crate) memset_count: u64,
    /// Number of `__bound_strlen` calls.
    pub(crate) strlen_count: u64,
    /// Number of `__bound_strcpy` calls.
    pub(crate) strcpy_count: u64,
    /// Number of `__bound_strncpy` calls.
    pub(crate) strncpy_count: u64,
    /// Number of `__bound_strcmp` calls.
    pub(crate) strcmp_count: u64,
    /// Number of `__bound_strncmp` calls.
    pub(crate) strncmp_count: u64,
    /// Number of `__bound_strcat` calls.
    pub(crate) strcat_count: u64,
    /// Number of `__bound_strncat` calls.
    pub(crate) strncat_count: u64,
    /// Number of `__bound_strchr` calls.
    pub(crate) strchr_count: u64,
    /// Number of `__bound_strrchr` calls.
    pub(crate) strrchr_count: u64,
    /// Number of `__bound_strdup` calls.
    pub(crate) strdup_count: u64,
    /// Number of region lookups that found no matching region.
    pub(crate) not_found: u64,
}

impl BoundsStatistics {
    /// Print all statistics counters to stderr.
    ///
    /// C equivalent: The `fprintf(stderr, ...)` block at `bcheck.c`
    /// lines 1229-1262.
    pub(crate) fn print(&self) {
        eprintln!("bound_ptr_add_count      {}", self.ptr_add_count);
        eprintln!("bound_ptr_indir1_count   {}", self.ptr_indir1_count);
        eprintln!("bound_ptr_indir2_count   {}", self.ptr_indir2_count);
        eprintln!("bound_ptr_indir4_count   {}", self.ptr_indir4_count);
        eprintln!("bound_ptr_indir8_count   {}", self.ptr_indir8_count);
        eprintln!("bound_ptr_indir12_count  {}", self.ptr_indir12_count);
        eprintln!("bound_ptr_indir16_count  {}", self.ptr_indir16_count);
        eprintln!("bound_local_new_count    {}", self.local_new_count);
        eprintln!("bound_local_delete_count {}", self.local_delete_count);
        eprintln!("bound_malloc_count       {}", self.malloc_count);
        eprintln!("bound_calloc_count       {}", self.calloc_count);
        eprintln!("bound_realloc_count      {}", self.realloc_count);
        eprintln!("bound_free_count         {}", self.free_count);
        eprintln!("bound_memalign_count     {}", self.memalign_count);
        eprintln!("bound_mmap_count         {}", self.mmap_count);
        eprintln!("bound_munmap_count       {}", self.munmap_count);
        eprintln!("bound_alloca_count       {}", self.alloca_count);
        eprintln!("bound_setjmp_count       {}", self.setjmp_count);
        eprintln!("bound_longjmp_count      {}", self.longjmp_count);
        eprintln!("bound_memcpy_count       {}", self.memcpy_count);
        eprintln!("bound_memcmp_count       {}", self.memcmp_count);
        eprintln!("bound_memmove_count      {}", self.memmove_count);
        eprintln!("bound_memset_count       {}", self.memset_count);
        eprintln!("bound_strlen_count       {}", self.strlen_count);
        eprintln!("bound_strcpy_count       {}", self.strcpy_count);
        eprintln!("bound_strncpy_count      {}", self.strncpy_count);
        eprintln!("bound_strcmp_count        {}", self.strcmp_count);
        eprintln!("bound_strncmp_count      {}", self.strncmp_count);
        eprintln!("bound_strcat_count       {}", self.strcat_count);
        eprintln!("bound_strncat_count      {}", self.strncat_count);
        eprintln!("bound_strchr_count       {}", self.strchr_count);
        eprintln!("bound_strrchr_count      {}", self.strrchr_count);
        eprintln!("bound_strdup_count       {}", self.strdup_count);
        eprintln!("bound_not_found          {}", self.not_found);
    }
}

// ---------------------------------------------------------------------------
// BoundsChecker — central state
// ---------------------------------------------------------------------------

/// Central bounds-checking state.
///
/// Replaces the C module's global variables: `tree`, `alloca_list`,
/// `jmp_list`, `free_reuse_list`, semaphore, and configuration flags.
///
/// All state is protected by the outer [`Mutex`] in [`BOUNDS_CHECKER`].
/// Individual methods assume the lock is already held.
///
/// C equivalent: Module-level globals at `bcheck.c` lines 339-400.
///
/// ## Memory Region Tracking
///
/// The original C code used Sleator's top-down splay tree (`bcheck.c`
/// lines 2018-2261) for O(amortized log n) region lookup. The Rust port
/// replaces this with a `BTreeMap<usize, Region>` which provides:
/// - O(log n) worst-case lookup via `.range(..=addr).next_back()`
/// - O(log n) insert and delete
/// - No raw pointer manipulation (eliminates potential memory corruption)
/// - Thread-safe access via the outer `Mutex`
pub(crate) struct BoundsChecker {
    /// Memory region tracker — replaces the C splay tree.
    ///
    /// Key: start address of the region.
    /// Value: [`Region`] with size, type, and validity metadata.
    ///
    /// Uses `BTreeMap` for O(log n) range queries as mandated by
    /// AAP §0.3.1 and §0.4.4.
    regions: BTreeMap<usize, Region>,

    /// Alloca/VLA tracking list.
    ///
    /// C equivalent: `static alloca_list_type *alloca_list` at line 344.
    /// Linked list replaced by `Vec` for safe iteration and mutation.
    alloca_list: Vec<AllocaEntry>,

    /// `setjmp` tracking list.
    ///
    /// C equivalent: `static jmp_list_type *jmp_list` at line 345.
    /// Linked list replaced by `Vec` for safe iteration and mutation.
    jmp_list: Vec<JmpEntry>,

    /// Deferred free list for use-after-free detection.
    ///
    /// When a pointer is freed, its region is marked invalid and the
    /// address is stored here. Only when the circular buffer wraps
    /// around is the old entry fully removed from `regions`.
    ///
    /// C equivalent: `free_reuse_list[FREE_REUSE_SIZE]` at line 337.
    free_reuse: Vec<usize>,

    /// Circular buffer write index for `free_reuse`.
    ///
    /// C equivalent: `static unsigned int free_reuse_index` at line 336.
    free_reuse_index: usize,

    /// When `true`, print a warning for out-of-bounds `ptr_add` results.
    ///
    /// Set from the `TCC_BOUNDS_WARN_POINTER_ADD` environment variable.
    /// C equivalent: `static unsigned char print_warn_ptr_add` at line 348.
    pub(crate) print_warn_ptr_add: bool,

    /// When `true`, print debug trace for every bounds checking call.
    ///
    /// Set from the `TCC_BOUNDS_PRINT_CALLS` environment variable.
    /// C equivalent: `static unsigned char print_calls` at line 349.
    pub(crate) print_calls: bool,

    /// When `true`, print leaked heap allocations at exit.
    ///
    /// Set from the `TCC_BOUNDS_PRINT_HEAP` environment variable.
    /// C equivalent: `static unsigned char print_heap` at line 350.
    pub(crate) print_heap: bool,

    /// When `true`, print statistics counters at exit.
    ///
    /// Set from the `TCC_BOUNDS_PRINT_STATISTIC` environment variable.
    /// C equivalent: `static unsigned char print_statistic` at line 351.
    pub(crate) print_statistic: bool,

    /// Atomic flag controlling fatal/non-fatal violation handling.
    ///
    /// When `> 0`, bounds violations return `INVALID_POINTER` instead
    /// of terminating the program.
    ///
    /// C equivalent: `static _Atomic int never_fatal` at line 354.
    /// Uses `AtomicI32` with `Ordering::Relaxed` for lock-free access.
    pub(crate) never_fatal: AtomicI32,

    /// Initialization state flag.
    ///
    /// C equivalent: `static unsigned char inited` at line 347.
    inited: bool,

    /// Operation statistics counters.
    ///
    /// Always present in the struct. Counters are always incremented
    /// so that statistics are available when `print_statistic` is true.
    statistics: BoundsStatistics,
}

// ---------------------------------------------------------------------------
// BoundsChecker — constructor
// ---------------------------------------------------------------------------

impl BoundsChecker {
    /// Create a new, empty `BoundsChecker`.
    ///
    /// All configuration flags default to `false` / `0`. Use [`init`]
    /// to perform full initialization (reads environment variables,
    /// registers initial regions).
    ///
    /// [`init`]: BoundsChecker::init
    pub(crate) fn new() -> Self {
        BoundsChecker {
            regions: BTreeMap::new(),
            alloca_list: Vec::new(),
            jmp_list: Vec::new(),
            free_reuse: Vec::with_capacity(FREE_REUSE_SIZE),
            free_reuse_index: 0,
            print_warn_ptr_add: false,
            print_calls: false,
            print_heap: false,
            print_statistic: false,
            never_fatal: AtomicI32::new(0),
            inited: false,
            statistics: BoundsStatistics::default(),
        }
    }
}

// ---------------------------------------------------------------------------
// BoundsChecker — region lookup (BTreeMap replaces splay tree)
// ---------------------------------------------------------------------------

impl BoundsChecker {
    /// Look up which region contains the given address.
    ///
    /// Finds the region with the largest start address `<= addr` and
    /// verifies that `addr` falls within `[start, start + size)`.
    ///
    /// C equivalent: `splay(addr, tree)` followed by the
    /// `addr -= tree->start; if (addr >= tree->size)` checks at
    /// `bcheck.c` lines 527-538.
    ///
    /// Uses `BTreeMap::range(..=addr).next_back()` for O(log n) lookup.
    pub(crate) fn find_region(&self, addr: usize) -> Option<&Region> {
        self.regions
            .range(..=addr)
            .next_back()
            .map(|(_, region)| region)
            .filter(|region| {
                // addr must be within [start, start + size)
                addr.checked_sub(region.start)
                    .is_some_and(|rel| rel < region.size)
            })
    }

    /// Look up region by end address (inclusive).
    ///
    /// Finds the region with the largest start address `<= addr` and
    /// verifies that `addr` falls within `[start, start + size]`
    /// (inclusive of the end, unlike `find_region`).
    ///
    /// C equivalent: `splay_end(addr, tree)` at `bcheck.c` lines 2124-2172.
    pub(crate) fn find_region_by_end(&self, addr: usize) -> Option<&Region> {
        self.regions
            .range(..=addr)
            .next_back()
            .map(|(_, region)| region)
            .filter(|region| {
                // addr must be within [start, start + size]
                addr.checked_sub(region.start)
                    .is_some_and(|rel| rel <= region.size)
            })
    }

    /// Insert a new tracked memory region.
    ///
    /// If a region with the same start address already exists, it is
    /// replaced (matching the C splay_insert behavior which returns
    /// the existing node on duplicate).
    ///
    /// C equivalent: `splay_insert(addr, size, tree)` at `bcheck.c`
    /// lines 2174-2218.
    pub(crate) fn insert_region(
        &mut self,
        start: usize,
        size: usize,
        region_type: RegionType,
    ) {
        self.regions.insert(
            start,
            Region {
                start,
                size,
                region_type,
                is_invalid: false,
            },
        );
    }

    /// Remove a tracked memory region by start address.
    ///
    /// If no region with the given start address exists, this is a no-op
    /// (matching the C `splay_delete` behavior which returns the tree
    /// unchanged if the key is not found).
    ///
    /// C equivalent: `splay_delete(addr, tree)` at `bcheck.c`
    /// lines 2223-2249.
    pub(crate) fn delete_region(&mut self, start: usize) {
        self.regions.remove(&start);
    }
}

// ---------------------------------------------------------------------------
// BoundsChecker — pointer validation
// ---------------------------------------------------------------------------

impl BoundsChecker {
    /// Validate pointer arithmetic: check that `(p .. p + offset)` lies
    /// within a tracked region.
    ///
    /// Returns the validated pointer address (`p + offset`), or
    /// [`INVALID_POINTER`] if the access violates a region boundary and
    /// `never_fatal <= 0`.
    ///
    /// Special cases:
    /// - If `NO_CHECKING` is enabled, returns `p + offset` without checking.
    /// - If `p` is `0` (NULL), the operation is allowed (used by `offsetof`).
    /// - If `p` is not found in any region and `p != 0`, it is logged as
    ///   "not found" but the operation is allowed (conservative).
    ///
    /// C equivalent: `__bound_ptr_add(void *p, size_t offset)` at
    /// `bcheck.c` lines 515-559.
    pub(crate) fn ptr_add(&mut self, p: usize, offset: usize) -> usize {
        if is_checking_disabled() {
            return p.wrapping_add(offset);
        }

        self.statistics.ptr_add_count += 1;

        if let Some(region) = self.find_region(p) {
            let rel_addr = p.wrapping_sub(region.start);
            if region.is_invalid || rel_addr.wrapping_add(offset) > region.size {
                if self.print_warn_ptr_add {
                    let region_start = region.start;
                    let region_end = region
                        .start
                        .wrapping_add(region.size)
                        .wrapping_sub(1);
                    eprintln!(
                        "BCHECK: 0x{:x} is outside of the region \
                         (0x{:x}..0x{:x})",
                        p.wrapping_add(offset),
                        region_start,
                        region_end,
                    );
                }
                if self.never_fatal.load(Ordering::Relaxed) <= 0 {
                    return INVALID_POINTER;
                }
            }
        } else if p != 0 {
            // Region not found — allow NULL + offset (offsetof uses it).
            self.statistics.not_found += 1;
        }

        p.wrapping_add(offset)
    }

    /// Validate pointer indirection: check that
    /// `(p + offset .. p + offset + dsize)` lies strictly within a
    /// tracked region.
    ///
    /// Unlike [`ptr_add`], this check requires the entire accessed range
    /// (including `dsize` bytes past the offset) to be within the region.
    /// This is used for actual memory reads/writes.
    ///
    /// The `dsize` parameter corresponds to the access size: 1, 2, 4, 8,
    /// 12, or 16 bytes.
    ///
    /// C equivalent: `BOUND_PTR_INDIR(dsize)` macro at `bcheck.c`
    /// lines 564-609, instantiated for dsize = 1, 2, 4, 8, 12, 16.
    ///
    /// [`ptr_add`]: BoundsChecker::ptr_add
    pub(crate) fn ptr_indir(
        &mut self,
        p: usize,
        offset: usize,
        dsize: usize,
    ) -> usize {
        if is_checking_disabled() {
            return p.wrapping_add(offset);
        }

        // Increment the appropriate statistics counter based on dsize
        match dsize {
            1 => self.statistics.ptr_indir1_count += 1,
            2 => self.statistics.ptr_indir2_count += 1,
            4 => self.statistics.ptr_indir4_count += 1,
            8 => self.statistics.ptr_indir8_count += 1,
            12 => self.statistics.ptr_indir12_count += 1,
            16 => self.statistics.ptr_indir16_count += 1,
            _ => {}
        }

        if let Some(region) = self.find_region(p) {
            let rel_addr = p.wrapping_sub(region.start);
            let total = rel_addr
                .wrapping_add(offset)
                .wrapping_add(dsize);
            if region.is_invalid || total > region.size {
                let region_start = region.start;
                let region_end = region
                    .start
                    .wrapping_add(region.size)
                    .wrapping_sub(1);
                eprintln!(
                    "BCHECK: 0x{:x} (size {}) is outside of the region \
                     (0x{:x}..0x{:x})",
                    p.wrapping_add(offset),
                    dsize,
                    region_start,
                    region_end,
                );
                if self.never_fatal.load(Ordering::Relaxed) <= 0 {
                    return INVALID_POINTER;
                }
            }
        } else {
            self.statistics.not_found += 1;
        }

        p.wrapping_add(offset)
    }
}

// ---------------------------------------------------------------------------
// BoundsChecker — local (stack) region management
// ---------------------------------------------------------------------------

impl BoundsChecker {
    /// Register local (stack) regions on function entry.
    ///
    /// Called by compiler-generated code at the start of every function
    /// compiled with `-b`. The `regions` parameter contains
    /// `(offset, size)` pairs describing local variable locations
    /// relative to the frame pointer `fp`.
    ///
    /// For each pair, the absolute address `fp + offset` is registered
    /// as a tracked region of the given `size`.
    ///
    /// C equivalent: `__bound_local_new(void *p1)` at `bcheck.c`
    /// lines 635-662.
    pub(crate) fn local_new(&mut self, regions: &[(usize, usize)], fp: usize) {
        if is_checking_disabled() {
            return;
        }

        for &(offset, size) in regions {
            if offset != 0 {
                self.statistics.local_new_count += 1;
                let addr = offset.wrapping_add(fp);
                self.insert_region(addr, size, RegionType::None);
            }
        }
    }

    /// Unregister local (stack) regions on function exit.
    ///
    /// Called by compiler-generated code at the end of every function
    /// compiled with `-b`. Removes all stack regions, alloca entries,
    /// and setjmp entries associated with the exiting frame `fp`.
    ///
    /// The cleanup proceeds in three steps:
    /// 1. Remove stack variable regions (offset + fp pairs).
    /// 2. Remove alloca/VLA entries and their tracked regions.
    /// 3. Remove setjmp entries.
    ///
    /// C equivalent: `__bound_local_delete(void *p1)` at `bcheck.c`
    /// lines 665-738.
    pub(crate) fn local_delete(
        &mut self,
        regions: &[(usize, usize)],
        fp: usize,
    ) {
        if is_checking_disabled() {
            return;
        }

        // Step 1: Remove stack variable regions
        for &(offset, _size) in regions {
            if offset != 0 {
                self.statistics.local_delete_count += 1;
                let addr = offset.wrapping_add(fp);
                self.delete_region(addr);
            }
        }

        // Step 2: Collect alloca entries matching this frame, then
        // remove. We collect first to avoid borrow conflicts between
        // alloca_list and regions.
        let alloca_ptrs_to_remove: Vec<usize> = self
            .alloca_list
            .iter()
            .filter(|entry| entry.fp == fp)
            .map(|entry| entry.ptr)
            .collect();

        for ptr in &alloca_ptrs_to_remove {
            self.regions.remove(ptr);
        }
        self.alloca_list.retain(|entry| entry.fp != fp);

        // Step 3: Remove setjmp entries for this frame
        self.jmp_list.retain(|entry| entry.fp != fp);
    }
}

// ---------------------------------------------------------------------------
// BoundsChecker — heap operations
// ---------------------------------------------------------------------------

impl BoundsChecker {
    /// Register a heap allocation for bounds tracking.
    ///
    /// Called after `malloc` (or equivalent) returns successfully.
    /// The allocated region `[addr, addr + size)` is registered with
    /// [`RegionType::Malloc`].
    ///
    /// C equivalent: `__bound_malloc(size_t size, const void *caller)`
    /// at `bcheck.c` lines 1462-1502.
    pub(crate) fn bound_malloc(&mut self, addr: usize, size: usize) {
        self.statistics.malloc_count += 1;
        let effective_size = if size == 0 { 1 } else { size };
        self.insert_region(addr, effective_size, RegionType::Malloc);
    }

    /// Register a `calloc` allocation for bounds tracking.
    ///
    /// C equivalent: `__bound_calloc` / `calloc` at `bcheck.c`
    /// lines 1624-1665.
    pub(crate) fn bound_calloc(
        &mut self,
        addr: usize,
        nmemb: usize,
        size: usize,
    ) {
        self.statistics.calloc_count += 1;
        let total = nmemb.wrapping_mul(size);
        let effective_size = if total == 0 { 1 } else { total };
        self.insert_region(addr, effective_size, RegionType::Calloc);
    }

    /// Register a `realloc` result for bounds tracking.
    ///
    /// Removes the old region (if any) and inserts the new one.
    ///
    /// C equivalent: `__bound_realloc` / `realloc` at `bcheck.c`
    /// lines 1587-1622.
    pub(crate) fn bound_realloc(
        &mut self,
        old_addr: Option<usize>,
        new_addr: usize,
        size: usize,
    ) {
        self.statistics.realloc_count += 1;
        if let Some(old) = old_addr {
            self.delete_region(old);
        }
        let effective_size = if size == 0 { 1 } else { size };
        self.insert_region(new_addr, effective_size, RegionType::Realloc);
    }

    /// Register a `memalign` allocation for bounds tracking.
    ///
    /// C equivalent: `__bound_memalign` / `memalign` at `bcheck.c`
    /// lines 1505-1542.
    pub(crate) fn bound_memalign(&mut self, addr: usize, size: usize) {
        self.statistics.memalign_count += 1;
        let effective_size = if size == 0 { 1 } else { size };
        self.insert_region(addr, effective_size, RegionType::Memalign);
    }

    /// Free a heap allocation with bounds tracking.
    ///
    /// The region is NOT immediately removed. Instead:
    /// 1. The region is checked for double-free (already invalid).
    /// 2. The region is marked `is_invalid = true`.
    /// 3. The address is placed in the circular `free_reuse` buffer.
    /// 4. If the buffer was full, the oldest entry is fully removed.
    ///
    /// This deferred-free strategy helps detect use-after-free bugs.
    ///
    /// C equivalent: `__bound_free(void *ptr, const void *caller)` at
    /// `bcheck.c` lines 1544-1585.
    pub(crate) fn bound_free(&mut self, addr: usize) -> TccResult<()> {
        if addr == 0 {
            return Ok(());
        }

        self.statistics.free_count += 1;

        // Check if the region exists and is already invalid (double free)
        if let Some(region) = self.regions.get(&addr) {
            if region.is_invalid {
                return Err(TccError::Link(
                    "double free detected".into(),
                ));
            }
        }

        // Mark as invalid (deferred free)
        if let Some(region) = self.regions.get_mut(&addr) {
            region.is_invalid = true;
        }

        // Manage the circular deferred free buffer
        if self.free_reuse.len() >= FREE_REUSE_SIZE {
            // Buffer is full — evict the oldest entry
            let old_addr = self.free_reuse[self.free_reuse_index];
            self.regions.remove(&old_addr);
            self.free_reuse[self.free_reuse_index] = addr;
            self.free_reuse_index =
                (self.free_reuse_index + 1) % FREE_REUSE_SIZE;
        } else {
            // Buffer not yet full — append
            self.free_reuse.push(addr);
        }

        Ok(())
    }

    /// Validate that a memory range `[p, p + size)` lies within a
    /// tracked region.
    ///
    /// Used internally by memory/string operations (`memcpy`, `strlen`,
    /// etc.) to validate their source and destination pointers.
    ///
    /// Returns `Ok(())` if the range is valid, or
    /// `Err(TccError::Link(...))` if the access would be out of bounds.
    ///
    /// C equivalent: `__bound_check(const void *p, size_t size,
    /// const char *function)` at `bcheck.c` lines 1705-1711.
    pub(crate) fn bound_check(
        &mut self,
        p: usize,
        size: usize,
        function: &str,
    ) -> TccResult<()> {
        if size != 0 && self.ptr_add(p, size) == INVALID_POINTER {
            return Err(TccError::Link(format!(
                "invalid pointer 0x{p:x}, size 0x{size:x} in {function}"
            )));
        }
        Ok(())
    }

    /// Check for overlapping memory regions.
    ///
    /// Returns `true` if the ranges `[p1, p1 + n1)` and `[p2, p2 + n2)`
    /// overlap and bounds checking is enabled. Used by `memcpy` to
    /// detect overlapping source/destination buffers (which require
    /// `memmove`).
    ///
    /// C equivalent: `check_overlap(p1, n1, p2, n2, function)` at
    /// `bcheck.c` lines 1713-1728.
    pub(crate) fn check_overlap(
        &self,
        p1: usize,
        n1: usize,
        p2: usize,
        n2: usize,
        function: &str,
    ) -> bool {
        if is_checking_disabled() || n1 == 0 || n2 == 0 {
            return false;
        }

        let p1e = p1.wrapping_add(n1);
        let p2e = p2.wrapping_add(n2);

        if (p1 <= p2 && p1e > p2) || (p2 <= p1 && p2e > p1) {
            eprintln!(
                "BCHECK: overlapping regions \
                 0x{:x}(0x{:x}), 0x{:x}(0x{:x}) in {}",
                p1, n1, p2, n2, function,
            );
            return true;
        }

        false
    }
}

// ---------------------------------------------------------------------------
// BoundsChecker — setjmp / longjmp
// ---------------------------------------------------------------------------

impl BoundsChecker {
    /// Register a `setjmp` save point.
    ///
    /// Records the current frame pointers so that `longjmp` can later
    /// clean up all stack regions and alloca entries allocated between
    /// the `setjmp` and `longjmp` calls.
    ///
    /// If a `JmpEntry` with the same `env` address already exists, its
    /// frame information is updated. Otherwise a new entry is created.
    ///
    /// C equivalent: `__bound_setjmp(jmp_buf env)` at `bcheck.c`
    /// lines 797-829.
    pub(crate) fn bound_setjmp(
        &mut self,
        env: usize,
        fp: usize,
        end_fp: usize,
        tid: u64,
    ) {
        if is_checking_disabled() {
            return;
        }

        self.statistics.setjmp_count += 1;

        // Update existing entry or create new one
        if let Some(existing) =
            self.jmp_list.iter_mut().find(|j| j.penv == env)
        {
            existing.fp = fp;
            existing.end_fp = end_fp;
            existing.tid = tid;
        } else {
            self.jmp_list.push(JmpEntry {
                penv: env,
                fp,
                end_fp,
                tid,
            });
        }
    }

    /// Handle `longjmp` — clean up regions between frames.
    ///
    /// When `longjmp` is called with a `jmp_buf` registered via
    /// [`bound_setjmp`], this method:
    /// 1. Finds the matching `JmpEntry`.
    /// 2. Removes all `JmpEntry`s for the same thread that were
    ///    registered after the target `setjmp`.
    /// 3. Removes all tracked regions in the frame range
    ///    `[fp_min, fp_max]`, along with their alloca entries.
    ///
    /// C equivalent: `__bound_long_jump(jmp_buf env, int val, int sig,
    /// const char *func)` at `bcheck.c` lines 832-910.
    ///
    /// [`bound_setjmp`]: BoundsChecker::bound_setjmp
    pub(crate) fn bound_longjmp(&mut self, env: usize, tid: u64) {
        if is_checking_disabled() {
            return;
        }

        self.statistics.longjmp_count += 1;

        // Find the target jmp entry
        let target = self
            .jmp_list
            .iter()
            .find(|j| j.penv == env && j.tid == tid)
            .cloned();

        let target = match target {
            Some(t) => t,
            None => return,
        };

        let end_fp = target.end_fp;

        // Remove jmp entries for the same thread that were registered
        // after the target setjmp (those with end_fp >= target.end_fp,
        // excluding the target itself).
        self.jmp_list.retain(|j| {
            !(j.tid == tid && j.end_fp >= end_fp && j.penv != env)
        });

        // Clean up regions in the frame range [fp_min, fp_max].
        // Frame addresses between setjmp and longjmp points are being
        // unwound.
        let fp_min = target.fp.min(end_fp);
        let fp_max = target.fp.max(end_fp);

        let addrs_in_range: Vec<usize> = self
            .regions
            .range(fp_min..=fp_max)
            .map(|(&addr, _)| addr)
            .collect();

        // Remove alloca entries pointing to regions in the range
        let addrs_set: std::collections::BTreeSet<usize> =
            addrs_in_range.iter().copied().collect();
        self.alloca_list
            .retain(|entry| !addrs_set.contains(&entry.ptr));

        // Remove the regions themselves
        for addr in addrs_in_range {
            self.regions.remove(&addr);
        }
    }
}

// ---------------------------------------------------------------------------
// BoundsChecker — alloca / VLA
// ---------------------------------------------------------------------------

impl BoundsChecker {
    /// Track an alloca/VLA allocation.
    ///
    /// Called when the compiled program uses `alloca()` or declares a
    /// C99 variable-length array (VLA). The new region is registered
    /// and an `AllocaEntry` is created to associate it with the
    /// current frame.
    ///
    /// If an existing alloca entry in the same frame overlaps the new
    /// allocation, the old entry is removed first. This handles the
    /// case where VLA size changes within a loop.
    ///
    /// C equivalent: `__bound_new_region(void *p, size_t size)` at
    /// `bcheck.c` lines 741-795.
    pub(crate) fn new_region(
        &mut self,
        ptr: usize,
        size: usize,
        fp: usize,
    ) {
        if is_checking_disabled() {
            return;
        }

        self.statistics.alloca_count += 1;

        // Find overlapping alloca entries for the same frame.
        // Collect addresses to remove first to avoid borrow conflicts.
        let to_remove: Vec<usize> = self
            .alloca_list
            .iter()
            .filter(|entry| {
                if entry.fp != fp {
                    return false;
                }
                let entry_end = entry.ptr.wrapping_add(entry.size);
                let new_end = ptr.wrapping_add(size);
                (entry.ptr <= ptr && entry_end > ptr)
                    || (ptr <= entry.ptr && new_end > entry.ptr)
            })
            .map(|entry| entry.ptr)
            .collect();

        // Remove overlapping regions from the BTreeMap
        for addr in &to_remove {
            self.regions.remove(addr);
        }

        // Remove overlapping alloca entries
        self.alloca_list
            .retain(|entry| !to_remove.contains(&entry.ptr));

        // Insert the new region and alloca entry
        self.insert_region(ptr, size, RegionType::None);
        self.alloca_list.push(AllocaEntry { fp, ptr, size });
    }
}

// ---------------------------------------------------------------------------
// BoundsChecker — initialization and cleanup
// ---------------------------------------------------------------------------

impl BoundsChecker {
    /// Initialize bounds checking.
    ///
    /// Reads environment variables to configure debug output, registers
    /// initial static memory regions (if provided), and marks the
    /// checker as initialized.
    ///
    /// Called once at program startup. Subsequent calls add more static
    /// regions without re-initializing.
    ///
    /// The `initial_regions` parameter contains `(start, size)` pairs
    /// for statically-known memory regions (e.g. global variables).
    /// The `mode` parameter controls runtime behavior:
    /// - `mode < 0`: Lazy init (called from `__bound_main_arg`).
    /// - `mode == 0`: Normal init.
    /// - `mode > 0`: Init for `-run` mode.
    ///
    /// C equivalent: `__bound_init(size_t *, int)` at `bcheck.c`
    /// lines 928-1105.
    pub(crate) fn init(
        &mut self,
        initial_regions: &[(usize, usize)],
        mode: i32,
    ) {
        if !self.inited {
            self.inited = true;

            // Read configuration from environment variables
            // C equivalent: lines 950-954
            self.print_warn_ptr_add =
                std::env::var("TCC_BOUNDS_WARN_POINTER_ADD").is_ok();
            self.print_calls =
                std::env::var("TCC_BOUNDS_PRINT_CALLS").is_ok();
            self.print_heap =
                std::env::var("TCC_BOUNDS_PRINT_HEAP").is_ok();
            self.print_statistic =
                std::env::var("TCC_BOUNDS_PRINT_STATISTIC").is_ok();

            if std::env::var("TCC_BOUNDS_NEVER_FATAL").is_ok() {
                self.never_fatal.store(1, Ordering::Relaxed);
            }

            // mode parameter preserved for API compatibility. In C it
            // controlled RTLD_DEFAULT vs RTLD_NEXT for dlsym (not
            // applicable in Rust).
            let _ = mode;
        }

        // Register initial static regions
        // C equivalent: the `add_bounds:` loop at lines 1091-1099
        for &(start, size) in initial_regions {
            if start != 0 {
                self.insert_region(start, size, RegionType::None);
            }
        }
    }

    /// Shutdown bounds checking — print statistics and clean up.
    ///
    /// Performs the following cleanup steps:
    /// 1. Removes all alloca entries and their tracked regions.
    /// 2. Removes all setjmp entries.
    /// 3. Evicts all deferred-free entries.
    /// 4. Optionally prints leaked heap allocations (`print_heap`).
    /// 5. Prints statistics counters (`print_statistic`).
    /// 6. Clears all internal state.
    ///
    /// C equivalent: `__bound_exit(void)` at `bcheck.c` lines
    /// 1162-1272.
    pub(crate) fn exit(&mut self) {
        if !self.inited {
            return;
        }

        // Clean up alloca entries
        let alloca_ptrs: Vec<usize> =
            self.alloca_list.iter().map(|e| e.ptr).collect();
        for ptr in &alloca_ptrs {
            self.regions.remove(ptr);
        }
        self.alloca_list.clear();

        // Clean up jmp entries
        self.jmp_list.clear();

        // Evict all deferred-free entries
        let reuse_addrs: Vec<usize> = self.free_reuse.clone();
        for addr in &reuse_addrs {
            self.regions.remove(addr);
        }
        self.free_reuse.clear();
        self.free_reuse_index = 0;

        // Print leaked heap allocations
        if self.print_heap {
            for region in self.regions.values() {
                if region.region_type != RegionType::None {
                    eprintln!(
                        "BCHECK: {} found size {}",
                        region.region_type.as_str(),
                        region.size,
                    );
                }
            }
        }

        // Clear all remaining regions
        self.regions.clear();

        // Print statistics
        if self.print_statistic {
            self.statistics.print();
        }

        self.inited = false;
    }

    /// Remove static regions registered for a DLL on unload.
    ///
    /// C equivalent: `__bound_exit_dll(size_t *p)` at `bcheck.c`
    /// lines 1274-1293.
    pub(crate) fn exit_dll(
        &mut self,
        static_regions: &[(usize, usize)],
    ) {
        for &(start, _size) in static_regions {
            if start != 0 {
                self.delete_region(start);
            }
        }
    }

    /// Register an mmap'd region for bounds tracking.
    ///
    /// C equivalent: `__bound_mmap` at `bcheck.c` lines 1668-1683.
    pub(crate) fn bound_mmap(&mut self, addr: usize, size: usize) {
        self.statistics.mmap_count += 1;
        self.insert_region(addr, size, RegionType::None);
    }

    /// Unregister an mmap'd region.
    ///
    /// C equivalent: `__bound_munmap` at `bcheck.c` lines 1685-1699.
    pub(crate) fn bound_munmap(&mut self, addr: usize) {
        self.statistics.munmap_count += 1;
        self.delete_region(addr);
    }

    /// Register a `strdup` allocation for bounds tracking.
    ///
    /// C equivalent: `__bound_strdup(const char *s)` at `bcheck.c`
    /// lines 1994-2016.
    pub(crate) fn bound_strdup(&mut self, addr: usize, size: usize) {
        self.statistics.strdup_count += 1;
        self.insert_region(addr, size, RegionType::Strdup);
    }

    /// Register main arguments and environment for bounds tracking.
    ///
    /// Registers the `argv` array and each individual argument string,
    /// as well as the `envp` array and each environment string.
    ///
    /// C equivalent: `__bound_main_arg(int argc, char **argv,
    /// char **envp)` at `bcheck.c` lines 1107-1160.
    pub(crate) fn register_main_args(
        &mut self,
        argv_regions: &[(usize, usize)],
        envp_regions: &[(usize, usize)],
    ) {
        for &(addr, size) in argv_regions {
            if addr != 0 {
                self.insert_region(addr, size, RegionType::None);
            }
        }
        for &(addr, size) in envp_regions {
            if addr != 0 {
                self.insert_region(addr, size, RegionType::None);
            }
        }
    }

    /// Get a reference to the statistics counters.
    pub(crate) fn statistics(&self) -> &BoundsStatistics {
        &self.statistics
    }

    /// Get a mutable reference to the statistics counters.
    pub(crate) fn statistics_mut(&mut self) -> &mut BoundsStatistics {
        &mut self.statistics
    }
}

// ---------------------------------------------------------------------------
// Global mutex-protected instance
// ---------------------------------------------------------------------------

/// Global bounds checker instance protected by [`Mutex`].
///
/// All bounds checking operations go through this singleton. The
/// `Mutex` provides thread-safe access, replacing the platform-specific
/// synchronization primitives used in the C version:
/// - Linux: `pthread_spinlock_t`
/// - macOS: `dispatch_semaphore_t`
/// - Windows: `CRITICAL_SECTION`
/// - FreeBSD/OpenBSD: no locking
///
/// `LazyLock` provides lazy initialization on first access, matching
/// the C code's `if (!inited)` guard pattern.
///
/// C equivalent: Module-level `static Tree *tree` + `INIT_SEM()` /
/// `WAIT_SEM()` / `POST_SEM()` macros at `bcheck.c` lines 64-170.
///
/// AAP §0.4.4: `Mutex<BTreeMap>` for synchronization.
#[allow(clippy::incompatible_msrv)] // LazyLock requires 1.80; actual toolchain is 1.94+
pub(crate) static BOUNDS_CHECKER: LazyLock<Mutex<BoundsChecker>> =
    LazyLock::new(|| Mutex::new(BoundsChecker::new()));

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_region_type_values() {
        assert_eq!(RegionType::None as u8, 0);
        assert_eq!(RegionType::Malloc as u8, 1);
        assert_eq!(RegionType::Calloc as u8, 2);
        assert_eq!(RegionType::Realloc as u8, 3);
        assert_eq!(RegionType::Memalign as u8, 4);
        assert_eq!(RegionType::Strdup as u8, 5);
    }

    #[test]
    fn test_region_type_as_str() {
        assert_eq!(RegionType::None.as_str(), "");
        assert_eq!(RegionType::Malloc.as_str(), "malloc");
        assert_eq!(RegionType::Strdup.as_str(), "strdup");
    }

    #[test]
    fn test_invalid_pointer_constant() {
        assert_eq!(INVALID_POINTER, usize::MAX - 1);
    }

    #[test]
    fn test_bounds_checker_new() {
        let bc = BoundsChecker::new();
        assert!(bc.regions.is_empty());
        assert!(bc.alloca_list.is_empty());
        assert!(bc.jmp_list.is_empty());
        assert!(bc.free_reuse.is_empty());
        assert_eq!(bc.free_reuse_index, 0);
        assert!(!bc.print_warn_ptr_add);
        assert!(!bc.print_calls);
        assert!(!bc.print_heap);
        assert!(!bc.print_statistic);
        assert_eq!(bc.never_fatal.load(Ordering::Relaxed), 0);
        assert!(!bc.inited);
    }

    #[test]
    fn test_insert_and_find_region() {
        let mut bc = BoundsChecker::new();
        bc.insert_region(1000, 100, RegionType::Malloc);

        // Exact start
        let r = bc.find_region(1000);
        assert!(r.is_some());
        let r = r.unwrap();
        assert_eq!(r.start, 1000);
        assert_eq!(r.size, 100);

        // Inside the region
        assert!(bc.find_region(1050).is_some());
        assert_eq!(bc.find_region(1050).unwrap().start, 1000);

        // Just before the end
        assert!(bc.find_region(1099).is_some());

        // At the end (exclusive boundary)
        assert!(bc.find_region(1100).is_none());

        // Before the region
        assert!(bc.find_region(999).is_none());
    }

    #[test]
    fn test_find_region_by_end() {
        let mut bc = BoundsChecker::new();
        bc.insert_region(1000, 100, RegionType::Malloc);

        // At the end (inclusive)
        assert!(bc.find_region_by_end(1100).is_some());

        // Past the end
        assert!(bc.find_region_by_end(1101).is_none());
    }

    #[test]
    fn test_delete_region() {
        let mut bc = BoundsChecker::new();
        bc.insert_region(1000, 100, RegionType::Malloc);
        assert!(bc.find_region(1050).is_some());

        bc.delete_region(1000);
        assert!(bc.find_region(1050).is_none());

        // Deleting non-existent region is a no-op
        bc.delete_region(9999);
    }

    #[test]
    fn test_ptr_add_valid() {
        let mut bc = BoundsChecker::new();
        bc.insert_region(1000, 100, RegionType::Malloc);

        // Valid: p=1000, offset=50 -> 1050 (within [1000,1100))
        assert_eq!(bc.ptr_add(1000, 50), 1050);

        // Valid: p=1000, offset=100 -> 1100 (ptr_add allows end)
        assert_eq!(bc.ptr_add(1000, 100), 1100);
    }

    #[test]
    fn test_ptr_add_invalid() {
        let mut bc = BoundsChecker::new();
        bc.insert_region(1000, 100, RegionType::Malloc);

        // Invalid: p=1000, offset=101 -> exceeds region
        assert_eq!(bc.ptr_add(1000, 101), INVALID_POINTER);
    }

    #[test]
    fn test_ptr_add_null() {
        let mut bc = BoundsChecker::new();

        // NULL + offset is allowed (offsetof pattern)
        assert_eq!(bc.ptr_add(0, 42), 42);
    }

    #[test]
    fn test_ptr_indir_valid() {
        let mut bc = BoundsChecker::new();
        bc.insert_region(1000, 100, RegionType::Malloc);

        // Valid: p=1000, offset=0, dsize=4 -> reads [1000,1004)
        assert_eq!(bc.ptr_indir(1000, 0, 4), 1000);

        // Valid: p=1000, offset=92, dsize=8 -> reads [1092,1100)
        assert_eq!(bc.ptr_indir(1000, 92, 8), 1092);
    }

    #[test]
    fn test_ptr_indir_invalid() {
        let mut bc = BoundsChecker::new();
        bc.insert_region(1000, 100, RegionType::Malloc);

        // Invalid: p=1000, offset=97, dsize=4 -> [1097,1101) exceeds
        assert_eq!(bc.ptr_indir(1000, 97, 4), INVALID_POINTER);
    }

    #[test]
    fn test_bound_malloc_and_free() {
        let mut bc = BoundsChecker::new();
        bc.bound_malloc(2000, 64);

        assert!(bc.find_region(2000).is_some());
        assert_eq!(
            bc.find_region(2000).unwrap().region_type,
            RegionType::Malloc
        );

        let result = bc.bound_free(2000);
        assert!(result.is_ok());

        // Region still exists but is invalid
        let r = bc.regions.get(&2000);
        assert!(r.is_some());
        assert!(r.unwrap().is_invalid);
    }

    #[test]
    fn test_double_free_detection() {
        let mut bc = BoundsChecker::new();
        bc.bound_malloc(3000, 32);

        let _ = bc.bound_free(3000);
        let result = bc.bound_free(3000);
        assert!(result.is_err());

        if let Err(TccError::Link(msg)) = result {
            assert!(msg.contains("double free"));
        } else {
            panic!("Expected TccError::Link for double free");
        }
    }

    #[test]
    fn test_bound_check_valid() {
        let mut bc = BoundsChecker::new();
        bc.insert_region(5000, 256, RegionType::Malloc);

        let result = bc.bound_check(5000, 128, "test_memcpy");
        assert!(result.is_ok());
    }

    #[test]
    fn test_bound_check_invalid() {
        let mut bc = BoundsChecker::new();
        bc.insert_region(5000, 100, RegionType::Malloc);

        let result = bc.bound_check(5000, 200, "test_memcpy");
        assert!(result.is_err());
    }

    #[test]
    fn test_check_overlap_true() {
        let bc = BoundsChecker::new();
        // Overlapping: [100,200) and [150,250)
        assert!(bc.check_overlap(100, 100, 150, 100, "memcpy"));
    }

    #[test]
    fn test_check_overlap_false() {
        let bc = BoundsChecker::new();
        // Non-overlapping: [100,200) and [200,300)
        assert!(!bc.check_overlap(100, 100, 200, 100, "memcpy"));
    }

    #[test]
    fn test_check_overlap_zero_size() {
        let bc = BoundsChecker::new();
        assert!(!bc.check_overlap(100, 0, 100, 50, "memcpy"));
        assert!(!bc.check_overlap(100, 50, 100, 0, "memcpy"));
    }

    #[test]
    fn test_local_new_and_delete() {
        let mut bc = BoundsChecker::new();
        let fp: usize = 0x7FFF_0000;

        let regions = [(16, 32), (64, 128)];
        bc.local_new(&regions, fp);

        assert!(bc.find_region(fp.wrapping_add(16)).is_some());
        assert!(bc.find_region(fp.wrapping_add(64)).is_some());

        bc.local_delete(&regions, fp);

        assert!(bc.find_region(fp.wrapping_add(16)).is_none());
        assert!(bc.find_region(fp.wrapping_add(64)).is_none());
    }

    #[test]
    fn test_setjmp_and_longjmp() {
        let mut bc = BoundsChecker::new();
        let env: usize = 0x1234;
        let fp: usize = 0x5000;
        let end_fp: usize = 0x6000;
        let tid: u64 = 1;

        bc.bound_setjmp(env, fp, end_fp, tid);
        assert_eq!(bc.jmp_list.len(), 1);

        // Update existing
        bc.bound_setjmp(env, fp + 100, end_fp + 100, tid);
        assert_eq!(bc.jmp_list.len(), 1);
        assert_eq!(bc.jmp_list[0].fp, fp + 100);

        bc.bound_longjmp(env, tid);
    }

    #[test]
    fn test_new_region_alloca() {
        let mut bc = BoundsChecker::new();
        let fp: usize = 0x8000;

        bc.new_region(0x1000, 256, fp);
        assert!(bc.find_region(0x1000).is_some());
        assert_eq!(bc.alloca_list.len(), 1);

        // Overlapping alloca in same frame replaces old one
        bc.new_region(0x1000, 512, fp);
        assert!(bc.find_region(0x1000).is_some());
        assert_eq!(bc.find_region(0x1000).unwrap().size, 512);
        assert_eq!(bc.alloca_list.len(), 1);
    }

    #[test]
    fn test_init_and_exit() {
        let mut bc = BoundsChecker::new();
        let regions = [(0x1000_usize, 100_usize), (0x2000, 200)];

        bc.init(&regions, 0);
        assert!(bc.inited);
        assert!(bc.find_region(0x1000).is_some());
        assert!(bc.find_region(0x2000).is_some());

        bc.exit();
        assert!(!bc.inited);
        assert!(bc.regions.is_empty());
    }

    #[test]
    fn test_bounds_checking_toggle() {
        // Ensure we start clean
        NO_CHECKING.with(|nc| nc.set(0));

        assert!(!is_checking_disabled());

        bounds_checking(1); // disable
        assert!(is_checking_disabled());

        bounds_checking(-1); // re-enable
        assert!(!is_checking_disabled());

        // Nested disable
        bounds_checking(1);
        bounds_checking(1);
        assert!(is_checking_disabled());

        bounds_checking(-1);
        assert!(is_checking_disabled()); // still disabled (count=1)

        bounds_checking(-1);
        assert!(!is_checking_disabled()); // now enabled (count=0)
    }

    #[test]
    fn test_global_instance_accessible() {
        let guard = BOUNDS_CHECKER
            .lock()
            .expect("invariant: mutex not poisoned");
        // Just verify we can lock and access
        let _ = guard.statistics();
        drop(guard);
    }

    #[test]
    fn test_free_reuse_circular_buffer() {
        let mut bc = BoundsChecker::new();

        // Fill the free_reuse buffer
        for i in 0..FREE_REUSE_SIZE {
            let addr = (i + 1) * 1000;
            bc.bound_malloc(addr, 64);
            let _ = bc.bound_free(addr);
        }

        assert_eq!(bc.free_reuse.len(), FREE_REUSE_SIZE);
        assert_eq!(bc.free_reuse_index, 0);

        // Next free should evict the oldest entry
        let new_addr = (FREE_REUSE_SIZE + 1) * 1000;
        bc.bound_malloc(new_addr, 64);
        let _ = bc.bound_free(new_addr);

        assert_eq!(bc.free_reuse.len(), FREE_REUSE_SIZE);
        assert_eq!(bc.free_reuse_index, 1);

        // The oldest entry (1000) should have been fully removed
        assert!(bc.regions.get(&1000).is_none());
    }

    #[test]
    fn test_statistics_default() {
        let stats = BoundsStatistics::default();
        assert_eq!(stats.ptr_add_count, 0);
        assert_eq!(stats.not_found, 0);
    }

    #[test]
    fn test_bound_free_null() {
        let mut bc = BoundsChecker::new();
        let result = bc.bound_free(0);
        assert!(result.is_ok());
    }

    #[test]
    fn test_ptr_add_with_invalid_region() {
        let mut bc = BoundsChecker::new();
        bc.insert_region(4000, 100, RegionType::Malloc);
        if let Some(r) = bc.regions.get_mut(&4000) {
            r.is_invalid = true;
        }
        assert_eq!(bc.ptr_add(4000, 10), INVALID_POINTER);
    }

    #[test]
    fn test_multiple_regions_no_overlap() {
        let mut bc = BoundsChecker::new();
        bc.insert_region(1000, 100, RegionType::Malloc);
        bc.insert_region(2000, 100, RegionType::Calloc);
        bc.insert_region(3000, 100, RegionType::Realloc);

        assert_eq!(
            bc.find_region(1050).unwrap().region_type,
            RegionType::Malloc
        );
        assert_eq!(
            bc.find_region(2050).unwrap().region_type,
            RegionType::Calloc
        );
        assert_eq!(
            bc.find_region(3050).unwrap().region_type,
            RegionType::Realloc
        );

        // Gap between regions
        assert!(bc.find_region(1500).is_none());
    }

    #[test]
    fn test_local_delete_cleans_alloca() {
        let mut bc = BoundsChecker::new();
        let fp: usize = 0x9000;

        let locals = [(16, 32)];
        bc.local_new(&locals, fp);

        bc.new_region(0xA000, 128, fp);
        assert!(bc.find_region(0xA000).is_some());
        assert_eq!(bc.alloca_list.len(), 1);

        bc.local_delete(&locals, fp);

        assert!(bc.find_region(fp.wrapping_add(16)).is_none());
        assert!(bc.find_region(0xA000).is_none());
        assert!(bc.alloca_list.is_empty());
    }

    #[test]
    fn test_never_fatal_mode() {
        let mut bc = BoundsChecker::new();
        bc.insert_region(1000, 100, RegionType::Malloc);
        bc.never_fatal.store(1, Ordering::Relaxed);

        // Out-of-bounds access allowed in never_fatal mode
        let result = bc.ptr_add(1000, 200);
        assert_eq!(result, 1200);
    }

    #[test]
    fn test_bound_calloc() {
        let mut bc = BoundsChecker::new();
        bc.bound_calloc(8000, 10, 20);

        let r = bc.find_region(8000).unwrap();
        assert_eq!(r.size, 200);
        assert_eq!(r.region_type, RegionType::Calloc);
    }

    #[test]
    fn test_bound_realloc() {
        let mut bc = BoundsChecker::new();
        bc.bound_malloc(7000, 50);

        bc.bound_realloc(Some(7000), 7500, 100);

        assert!(bc.find_region(7000).is_none());
        assert!(bc.find_region(7500).is_some());
        assert_eq!(
            bc.find_region(7500).unwrap().region_type,
            RegionType::Realloc
        );
    }

    #[test]
    fn test_bound_mmap_and_munmap() {
        let mut bc = BoundsChecker::new();
        bc.bound_mmap(0x10000, 4096);
        assert!(bc.find_region(0x10000).is_some());

        bc.bound_munmap(0x10000);
        assert!(bc.find_region(0x10000).is_none());
    }

    #[test]
    fn test_exit_dll() {
        let mut bc = BoundsChecker::new();
        bc.insert_region(0x3000, 100, RegionType::None);
        bc.insert_region(0x4000, 200, RegionType::None);

        bc.exit_dll(&[(0x3000, 100), (0x4000, 200)]);
        assert!(bc.find_region(0x3000).is_none());
        assert!(bc.find_region(0x4000).is_none());
    }
}
