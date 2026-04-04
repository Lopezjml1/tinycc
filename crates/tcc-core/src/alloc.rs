// Copyright (c) TinyCC contributors. LGPL licensed.
// Ported from tcc.h (TinyAlloc) and libtcc.c (tcc_malloc/tcc_realloc/tcc_free)
// to Rust as part of the TCC C-to-Rust migration.
//
//! Arena allocator module for temporary compilation data.
//!
//! This module provides three allocation facilities that replace the C codebase's
//! memory management primitives:
//!
//! | C original | Rust replacement | Purpose |
//! |-----|-----|-----|
//! | `tcc_malloc` / `tcc_mallocz` | [`Arena::alloc`] / [`Arena::alloc_zeroed`] | General allocation |
//! | TinyAlloc (bump alloc) | [`Arena`] | Fast bulk-freeable arena allocation |
//! | Various `char buf[…]` temps | [`ScratchBuffer`] | Growable temporary string/byte buffer |
//! | `Sym` free-list recycling | [`SymPool`] | Pool of compiler symbol nodes |
//!
//! # Design Decisions
//!
//! - **No external crate**: Implemented inline without `bumpalo` dependency, per the AAP
//!   directive "prefer std + minimal crates."
//! - **OPT-03 fix**: Arena allocation is O(1) bump-pointer; bulk deallocation is O(blocks).
//! - **BUG-16 fix**: All memory is freed automatically when the Arena is dropped, thanks to
//!   Rust's RAII / `Drop` semantics. No `setjmp`/`longjmp` leak risk.
//! - **PORT-01 / PORT-02**: All sizes and offsets use `usize`; no `int`-as-size assumptions.

use std::mem;
use std::ptr;

use crate::types::Sym;

// ===========================================================================
// Drop registry entry — type-erased destructor for arena-allocated objects
// ===========================================================================

/// A type-erased destructor entry stored by the arena.
///
/// When `alloc_typed<T>()` is called for a type that implements `Drop`
/// (detected via `std::mem::needs_drop::<T>()`), the arena records the
/// pointer and a type-erased drop function. On `reset()` or `Drop`, the
/// arena iterates the registry in reverse order and calls each destructor.
///
/// This solves the OPT-03 destructor leak: types like `Sym` (which contain
/// `Option<Box<Sym>>`, `Option<Vec<i32>>`, etc.) have their owned heap data
/// properly freed when the arena is reset or dropped.
struct DropEntry {
    /// Pointer to the object within the arena block.
    ptr: *mut u8,
    /// Type-erased destructor: calls `std::ptr::drop_in_place::<T>()`.
    drop_fn: unsafe fn(*mut u8),
}

/// Type-erased drop function for a specific type `T`.
///
/// # Safety
///
/// `ptr` must point to a valid, initialized value of type `T` that has not
/// yet been dropped. The caller must ensure proper alignment.
unsafe fn drop_typed<T>(ptr: *mut u8) {
    ptr::drop_in_place(ptr as *mut T);
}

// ===========================================================================
// Constants
// ===========================================================================

/// Default arena block size: 256 KiB.
///
/// This matches TCC's `TinyAlloc` default block size (256 × 1024 bytes) as described
/// in the AAP. Each block is allocated on the heap as a contiguous `Vec<u8>`.
/// When a block is exhausted, a new one is allocated — old blocks remain valid and
/// are freed only on [`Arena::reset`] or [`Arena::drop`].
pub const DEFAULT_BLOCK_SIZE: usize = 256 * 1024;

/// Minimum block size to avoid degenerate single-byte blocks.
const MIN_BLOCK_SIZE: usize = 64;

// ===========================================================================
// Arena — Bump-pointer allocator with bulk deallocation
// ===========================================================================

/// Arena allocator for temporary compilation data.
///
/// Replaces the `TinyAlloc` arena and `tcc_malloc`/`tcc_mallocz` general-purpose
/// wrappers from the C codebase. Uses a series of fixed-size memory blocks with
/// O(1) bump-pointer allocation and O(blocks) bulk deallocation.
///
/// # Memory Layout
///
/// ```text
/// Arena
///  ├── Block 0: [ used | used | used | ··· free ··· ]
///  ├── Block 1: [ used | used | ·········· free ··· ]  ← current_block
///  └── (new blocks added as needed)
/// ```
///
/// Allocation advances the `offset` within the current block. When a request
/// exceeds the remaining space, a new block is allocated. Previous blocks remain
/// valid — their contents are never moved or freed until [`reset`](Arena::reset)
/// or the arena is dropped.
///
/// # Thread Safety
///
/// `Arena` is `Send` but not `Sync`. It must be owned by a single thread (or
/// compilation context), matching TCC's single-threaded compilation model
/// (see BUG-13: per-instance state via Rust ownership).
///
/// # Examples
///
/// ```
/// use tcc_core::alloc::Arena;
///
/// let mut arena = Arena::new();
/// let buf = arena.alloc(128);
/// assert_eq!(buf.len(), 128);
/// assert_eq!(arena.bytes_allocated(), 128);
///
/// arena.reset();
/// assert_eq!(arena.bytes_allocated(), 0);
/// ```
pub struct Arena {
    /// Heap-allocated memory blocks. Each block is a `Vec<u8>` of at least
    /// `block_size` bytes. Blocks are never resized after creation.
    blocks: Vec<Vec<u8>>,
    /// Index of the block currently being allocated from.
    current_block: usize,
    /// Byte offset within `blocks[current_block]` where the next allocation starts.
    offset: usize,
    /// Configured block size for new block creation.
    block_size: usize,
    /// Running total of bytes handed out via `alloc` / `alloc_zeroed` / `alloc_typed`.
    /// Does not include alignment padding.
    total_allocated: usize,
    /// Registry of destructors for arena-allocated objects that implement `Drop`.
    ///
    /// When `alloc_typed<T>()` allocates a type with `needs_drop::<T>() == true`,
    /// a `DropEntry` is recorded so the destructor runs on `reset()` or arena `Drop`.
    /// Entries are stored in allocation order and executed in **reverse** order
    /// (matching Rust/C++ destruction semantics).
    drop_registry: Vec<DropEntry>,
}

impl Arena {
    /// Create a new arena with the default block size ([`DEFAULT_BLOCK_SIZE`] = 256 KiB).
    ///
    /// No memory is allocated until the first call to [`alloc`](Arena::alloc).
    #[inline]
    pub fn new() -> Self {
        Self::with_block_size(DEFAULT_BLOCK_SIZE)
    }

    /// Create a new arena with a custom block size.
    ///
    /// The effective block size is clamped to at least [`MIN_BLOCK_SIZE`] (64 bytes)
    /// to prevent degenerate single-byte blocks.
    ///
    /// # Arguments
    ///
    /// * `size` — Desired block size in bytes. Values below 64 are silently raised.
    pub fn with_block_size(size: usize) -> Self {
        Arena {
            blocks: Vec::new(),
            current_block: 0,
            offset: 0,
            block_size: size.max(MIN_BLOCK_SIZE),
            total_allocated: 0,
            drop_registry: Vec::new(),
        }
    }

    /// Allocate `size` bytes from the arena, returning a mutable slice.
    ///
    /// The returned memory is **not** zero-initialized (it may contain arbitrary
    /// bytes from a recycled block after [`reset`](Arena::reset)). Use
    /// [`alloc_zeroed`](Arena::alloc_zeroed) if zero-initialization is needed.
    ///
    /// Allocation is O(1) amortized. If the current block has insufficient space,
    /// a new block of `max(block_size, size)` bytes is allocated.
    ///
    /// # Arguments
    ///
    /// * `size` — Number of bytes to allocate. Zero-size requests return an empty slice.
    ///
    /// # Panics
    ///
    /// Panics if the system allocator fails (out of memory).
    pub fn alloc(&mut self, size: usize) -> &mut [u8] {
        if size == 0 {
            return &mut [];
        }
        self.ensure_capacity(size);
        let block_idx = self.current_block;
        let start = self.offset;
        self.offset += size;
        self.total_allocated += size;

        // SAFETY: `ensure_capacity` guarantees that
        // `blocks[block_idx][start .. start + size]` is within bounds.
        // The block's backing storage is stable (never reallocated after creation).
        // No other mutable reference to this range exists because we advanced the
        // offset past it, and no prior allocation overlaps.
        //
        // We use unsafe to decouple the returned slice's lifetime from the
        // transient mutable borrow of `self`, allowing callers to hold the slice
        // while performing further (non-overlapping) arena operations through
        // separate code paths.
        unsafe {
            let ptr = self.blocks[block_idx].as_mut_ptr().add(start);
            std::slice::from_raw_parts_mut(ptr, size)
        }
    }

    /// Allocate `size` bytes from the arena, zero-initialized.
    ///
    /// Equivalent to [`alloc`](Arena::alloc) followed by `fill(0)`.
    /// Replaces `tcc_mallocz()` from the C codebase.
    ///
    /// # Arguments
    ///
    /// * `size` — Number of bytes to allocate. Zero-size requests return an empty slice.
    pub fn alloc_zeroed(&mut self, size: usize) -> &mut [u8] {
        if size == 0 {
            return &mut [];
        }
        self.ensure_capacity(size);
        let block_idx = self.current_block;
        let start = self.offset;
        self.offset += size;
        self.total_allocated += size;

        // Zero-initialize the region.
        self.blocks[block_idx][start..start + size].fill(0);

        // SAFETY: Same justification as `alloc`. The region was just zero-filled
        // and is exclusively owned by this allocation.
        unsafe {
            let ptr = self.blocks[block_idx].as_mut_ptr().add(start);
            std::slice::from_raw_parts_mut(ptr, size)
        }
    }

    /// Allocate and default-initialize a value of type `T` in the arena.
    ///
    /// The returned reference is properly aligned for `T` and initialized via
    /// [`Default::default()`]. This is the primary mechanism for arena-allocating
    /// typed compiler structures (e.g., `Sym`, `CType`).
    ///
    /// If `T` implements `Drop` (detected at compile time via `std::mem::needs_drop`),
    /// the arena registers a destructor entry so that `T::drop()` is called when the
    /// arena is reset or dropped. This prevents memory leaks for types with owned heap
    /// data (e.g., `Sym` with `Option<Box<Sym>>` and `Option<Vec<i32>>` fields).
    ///
    /// # Type Parameters
    ///
    /// * `T` — Must implement `Default`. Must be a sized, non-zero-size type.
    ///
    /// # Panics
    ///
    /// Panics if `size_of::<T>() == 0` (zero-sized types cannot be arena-allocated).
    ///
    /// # Safety
    ///
    /// This function uses `unsafe` internally. The safety contract is:
    ///
    /// 1. **Lifetime invariant**: The returned `&mut T` borrows from the arena. The
    ///    caller must ensure the arena outlives all references obtained from it.
    ///    Calling `reset()` or dropping the arena invalidates ALL outstanding references.
    ///
    /// 2. **No mutable aliasing**: Each call returns a unique, non-overlapping region.
    ///    The caller must not create additional `&mut` references to the same memory.
    ///
    /// 3. **Alignment**: The pointer is computed to satisfy `T`'s alignment requirement
    ///    based on the absolute address within the block.
    ///
    /// 4. **Initialization**: `T::default()` is written to the region before the
    ///    reference is returned, ensuring the value is fully initialized.
    ///
    /// 5. **Drop guarantee**: If `needs_drop::<T>()` is true, the destructor is
    ///    registered and will be called exactly once (on reset or arena drop).
    pub fn alloc_typed<T: Default>(&mut self) -> &mut T {
        let align = mem::align_of::<T>();
        let size = mem::size_of::<T>();
        assert!(size > 0, "Cannot arena-allocate zero-sized types");

        // We may need up to `align - 1` extra bytes for alignment padding.
        let max_padding = align.saturating_sub(1);
        let max_needed = size + max_padding;

        // Ensure the current block has enough room for the worst-case aligned allocation.
        if self.blocks.is_empty()
            || self.offset + max_needed > self.blocks[self.current_block].len()
        {
            // Allocate a new block large enough.
            let new_block_size = self.block_size.max(max_needed);
            self.blocks.push(vec![0u8; new_block_size]);
            self.current_block = self.blocks.len() - 1;
            self.offset = 0;
        }

        // Compute the properly aligned offset within the current block.
        // We align based on the **absolute** address (block base + offset) so that
        // the resulting pointer satisfies `T`'s alignment requirement regardless of
        // where the system allocator placed the block.
        let block_base = self.blocks[self.current_block].as_mut_ptr();
        let current_addr = block_base as usize + self.offset;
        let aligned_addr = (current_addr + align - 1) & !(align - 1);
        let actual_offset = aligned_addr - block_base as usize;

        // Advance past the allocated region.
        debug_assert!(
            actual_offset + size <= self.blocks[self.current_block].len(),
            "Arena block overflow after alignment (offset={}, size={}, block_len={})",
            actual_offset,
            size,
            self.blocks[self.current_block].len()
        );
        self.offset = actual_offset + size;
        self.total_allocated += size;

        // SAFETY:
        // - `aligned_addr` is correctly aligned for `T` (verified by the mask above).
        // - The region `[actual_offset .. actual_offset + size)` is within the block.
        // - No other mutable reference to this region exists.
        // - We write a valid `T` via `Default::default()` before returning the reference.
        // - If T needs dropping, we register a destructor before returning.
        unsafe {
            let ptr = block_base.add(actual_offset) as *mut T;
            ptr.write(T::default());

            // Register destructor for types that implement Drop.
            // This is checked at compile time — for Copy types, the branch is eliminated.
            if mem::needs_drop::<T>() {
                self.drop_registry.push(DropEntry {
                    ptr: ptr as *mut u8,
                    drop_fn: drop_typed::<T>,
                });
            }

            &mut *ptr
        }
    }

    /// Reset the arena, logically freeing all allocations.
    ///
    /// After reset, the arena's blocks are retained (not deallocated) so they can
    /// be reused by subsequent allocations without hitting the system allocator.
    /// The [`bytes_allocated`](Arena::bytes_allocated) counter is reset to zero.
    ///
    /// This is the "bulk free" operation that makes arena allocation attractive:
    /// instead of individually freeing hundreds of small allocations, a single
    /// `reset()` reclaims everything in O(1).
    ///
    /// # Warning
    ///
    /// All previously returned references become **invalid** after `reset()`.
    /// Using them is undefined behavior. Callers must ensure no outstanding
    /// references exist before calling this method.
    pub fn reset(&mut self) {
        // Run registered destructors in reverse allocation order.
        // This ensures that objects allocated later (which may reference objects
        // allocated earlier) are dropped first, matching Rust/C++ destruction semantics.
        self.run_destructors();

        if !self.blocks.is_empty() {
            self.current_block = 0;
            self.offset = 0;
        }
        self.total_allocated = 0;
    }

    /// Return the total number of bytes handed out to callers.
    ///
    /// This counts only the bytes requested by callers (via `alloc`, `alloc_zeroed`,
    /// `alloc_typed`). It does **not** include alignment padding or unused space at
    /// the end of blocks.
    #[inline]
    pub fn bytes_allocated(&self) -> usize {
        self.total_allocated
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    /// Run all registered destructors in reverse allocation order, then clear
    /// the registry.
    ///
    /// This is called by both `reset()` and `Drop::drop()` to ensure that
    /// arena-allocated objects with `Drop` implementations (e.g., `Sym` with
    /// `Option<Box<Sym>>` and `Option<Vec<i32>>` fields) have their owned heap
    /// data properly freed.
    ///
    /// # Safety
    ///
    /// Each registered destructor is called exactly once. After this method returns,
    /// the underlying memory in the arena blocks is considered uninitialized for
    /// the purposes of typed access — only the raw `Vec<u8>` block memory remains valid.
    fn run_destructors(&mut self) {
        // Iterate in reverse order so that later allocations are dropped first.
        for entry in self.drop_registry.drain(..).rev() {
            // SAFETY: Each DropEntry was registered by alloc_typed<T>() with a valid
            // pointer into an arena block and the correct drop_fn for that type.
            // The pointer remains valid because the arena blocks have not been freed
            // (blocks.clear() has not been called yet). Each entry is processed
            // exactly once due to drain().
            unsafe {
                (entry.drop_fn)(entry.ptr);
            }
        }
    }

    /// Ensure the current block has at least `needed` bytes of free space.
    ///
    /// If the arena has no blocks, or the current block's remaining capacity is
    /// insufficient, a new block is allocated. The new block size is
    /// `max(self.block_size, needed)` to handle requests larger than the default
    /// block size.
    fn ensure_capacity(&mut self, needed: usize) {
        let has_space = !self.blocks.is_empty()
            && self.offset + needed <= self.blocks[self.current_block].len();
        if !has_space {
            let new_size = self.block_size.max(needed);
            self.blocks.push(vec![0u8; new_size]);
            self.current_block = self.blocks.len() - 1;
            self.offset = 0;
        }
    }
}

impl Default for Arena {
    /// Creates an arena with the default block size ([`DEFAULT_BLOCK_SIZE`]).
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for Arena {
    fn drop(&mut self) {
        // Run all registered destructors before freeing the backing memory.
        // This ensures that Drop types (e.g., Sym with Box/Vec fields) have their
        // owned heap data properly freed — solving the OPT-03 destructor leak.
        self.run_destructors();

        // All blocks are `Vec<u8>` and are freed automatically by `Vec::drop`.
        // This satisfies BUG-16: no memory leaked on error paths, because Rust's
        // RAII guarantees `drop` runs even during stack unwinding.
        //
        // Explicitly clear the block list for clarity (Vec::drop would do this
        // anyway, but this makes the intent explicit).
        self.blocks.clear();
        self.total_allocated = 0;
    }
}

// ===========================================================================
// ScratchBuffer — Growable temporary byte/string buffer
// ===========================================================================

/// A growable scratch buffer for temporary string and byte-data construction.
///
/// Replaces the various fixed-size `char buf[…]` temporary buffers scattered
/// throughout the C codebase (e.g., in `tccpp.c` for token assembly, in `tccelf.c`
/// for section name construction, in `tccgen.c` for error message formatting).
///
/// Unlike [`Arena`], a `ScratchBuffer` is designed for **repeated reuse**: call
/// [`clear`](ScratchBuffer::clear) to empty it, then build up new content. The
/// underlying allocation is retained across clears to amortize heap allocation.
///
/// # Examples
///
/// ```
/// use tcc_core::alloc::ScratchBuffer;
///
/// let mut buf = ScratchBuffer::new();
/// buf.push_str("hello");
/// buf.push(b' ');
/// buf.push_str("world");
/// assert_eq!(buf.as_str().unwrap(), "hello world");
/// assert_eq!(buf.len(), 11);
///
/// buf.clear();
/// assert!(buf.is_empty());
/// ```
pub struct ScratchBuffer {
    /// Underlying growable byte storage.
    data: Vec<u8>,
}

impl ScratchBuffer {
    /// Create a new, empty scratch buffer with no pre-allocated capacity.
    #[inline]
    pub fn new() -> Self {
        ScratchBuffer { data: Vec::new() }
    }

    /// Create a new scratch buffer with the given initial capacity.
    ///
    /// The buffer starts empty but has room for at least `cap` bytes before
    /// needing to reallocate.
    ///
    /// # Arguments
    ///
    /// * `cap` — Initial capacity in bytes.
    #[inline]
    pub fn with_capacity(cap: usize) -> Self {
        ScratchBuffer {
            data: Vec::with_capacity(cap),
        }
    }

    /// Append a single byte to the buffer.
    ///
    /// # Arguments
    ///
    /// * `byte` — The byte value to append.
    #[inline]
    pub fn push(&mut self, byte: u8) {
        self.data.push(byte);
    }

    /// Append all bytes of a UTF-8 string slice to the buffer.
    ///
    /// # Arguments
    ///
    /// * `s` — The string slice whose bytes will be appended.
    #[inline]
    pub fn push_str(&mut self, s: &str) {
        self.data.extend_from_slice(s.as_bytes());
    }

    /// Clear the buffer contents, retaining the allocated capacity.
    ///
    /// After this call, [`len`](ScratchBuffer::len) returns 0 and
    /// [`is_empty`](ScratchBuffer::is_empty) returns `true`, but the
    /// underlying heap allocation is preserved for reuse.
    #[inline]
    pub fn clear(&mut self) {
        self.data.clear();
    }

    /// Return the buffer contents as a byte slice.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Attempt to interpret the buffer contents as a UTF-8 string.
    ///
    /// # Errors
    ///
    /// Returns [`std::str::Utf8Error`] if the buffer contains invalid UTF-8.
    #[inline]
    pub fn as_str(&self) -> Result<&str, std::str::Utf8Error> {
        std::str::from_utf8(&self.data)
    }

    /// Return the number of bytes currently in the buffer.
    #[inline]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Return `true` if the buffer contains no bytes.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

impl Default for ScratchBuffer {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// SymPool — Pool allocator for Sym structures
// ===========================================================================

/// Pool allocator specialized for [`Sym`] (compiler symbol) structures.
///
/// During compilation, TCC allocates large numbers of `Sym` nodes for variables,
/// functions, struct fields, macro definitions, labels, and enum constants.
/// These nodes are typically allocated in bursts during a scope and freed in bulk
/// when the scope closes.
///
/// `SymPool` wraps an [`Arena`] to provide:
/// - O(1) allocation of properly initialized `Sym` nodes.
/// - O(1) bulk deallocation via [`reset`](SymPool::reset).
/// - Zero per-allocation overhead (no free-list metadata per node).
///
/// This replaces the C codebase's `sym_free_first` free-list pattern and the
/// `__sym_malloc` / `sym_free` / `sym_malloc` functions.
///
/// # Examples
///
/// ```
/// use tcc_core::alloc::SymPool;
///
/// let mut pool = SymPool::new();
/// let sym = pool.alloc_sym();
/// sym.v = 42;
/// assert_eq!(pool.allocated_count, 1);
///
/// pool.reset();
/// assert_eq!(pool.allocated_count, 0);
/// ```
pub struct SymPool {
    /// Backing arena for `Sym`-sized allocations.
    arena: Arena,
    /// Number of `Sym` nodes allocated since the last [`reset`](SymPool::reset).
    pub allocated_count: usize,
}

impl SymPool {
    /// Create a new symbol pool with default arena block size.
    ///
    /// The arena is sized to fit many `Sym` nodes per block. With
    /// `DEFAULT_BLOCK_SIZE` = 256 KiB and `size_of::<Sym>()` typically ~200 bytes,
    /// each block holds over 1,000 symbols before a new block is needed.
    pub fn new() -> Self {
        SymPool {
            arena: Arena::new(),
            allocated_count: 0,
        }
    }

    /// Allocate and default-initialize a new [`Sym`] from the pool.
    ///
    /// The returned `Sym` has all fields set to their `Default` values:
    /// - `v = 0`, `r = 0`, `c = 0`, `sym_scope = 0`
    /// - `type_` = `CType { t: VT_INT, ref_sym: None }`
    /// - All `Option` fields (`next`, `prev`, `prev_tok`, `d`) = `None`
    /// - All attribute structs (`a`, `f`) = zero/false
    ///
    /// The caller should immediately set the relevant fields for the symbol's
    /// intended use.
    ///
    /// # Performance
    ///
    /// O(1) amortized — bump-pointer allocation within the arena, plus a
    /// `Default::default()` initialization.
    pub fn alloc_sym(&mut self) -> &mut Sym {
        self.allocated_count += 1;
        self.arena.alloc_typed::<Sym>()
    }

    /// Reset the pool, freeing all allocated `Sym` nodes.
    ///
    /// This calls destructors for all allocated `Sym` objects (via the arena's
    /// drop registry), properly freeing any owned heap data such as
    /// `Option<Box<Sym>>` and `Option<Vec<i32>>` fields. After reset, all
    /// previously returned `&mut Sym` references are **invalid**.
    /// The `allocated_count` is reset to zero. The underlying arena blocks are
    /// retained for reuse.
    pub fn reset(&mut self) {
        self.arena.reset();
        self.allocated_count = 0;
    }
}

impl Default for SymPool {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Arena tests
    // -----------------------------------------------------------------------

    #[test]
    fn arena_new_default() {
        let arena = Arena::new();
        assert_eq!(arena.bytes_allocated(), 0);
        assert!(arena.blocks.is_empty());
        assert_eq!(arena.block_size, DEFAULT_BLOCK_SIZE);
    }

    #[test]
    fn arena_with_block_size() {
        let arena = Arena::with_block_size(1024);
        assert_eq!(arena.block_size, 1024);
    }

    #[test]
    fn arena_with_block_size_minimum() {
        // Block size below minimum is clamped to MIN_BLOCK_SIZE.
        let arena = Arena::with_block_size(1);
        assert_eq!(arena.block_size, MIN_BLOCK_SIZE);
    }

    #[test]
    fn arena_alloc_zero() {
        let mut arena = Arena::new();
        let buf = arena.alloc(0);
        assert!(buf.is_empty());
        assert_eq!(arena.bytes_allocated(), 0);
    }

    #[test]
    fn arena_alloc_basic() {
        let mut arena = Arena::with_block_size(256);
        let buf = arena.alloc(64);
        assert_eq!(buf.len(), 64);
        assert_eq!(arena.bytes_allocated(), 64);
    }

    #[test]
    fn arena_alloc_fills_block_then_grows() {
        let mut arena = Arena::with_block_size(128);

        // First allocation fits in block 0.
        let _a = arena.alloc(100);
        assert_eq!(arena.blocks.len(), 1);
        assert_eq!(arena.current_block, 0);
        assert_eq!(arena.offset, 100);

        // Second allocation exceeds remaining (28 bytes) → new block.
        let _b = arena.alloc(64);
        assert_eq!(arena.blocks.len(), 2);
        assert_eq!(arena.current_block, 1);
        assert_eq!(arena.offset, 64);
        assert_eq!(arena.bytes_allocated(), 164);
    }

    #[test]
    fn arena_alloc_oversized() {
        // Request larger than block_size.
        let mut arena = Arena::with_block_size(64);
        let buf = arena.alloc(256);
        assert_eq!(buf.len(), 256);
        assert_eq!(arena.bytes_allocated(), 256);
        // The block should be at least 256 bytes.
        assert!(arena.blocks[arena.current_block].len() >= 256);
    }

    #[test]
    fn arena_alloc_zeroed_basic() {
        let mut arena = Arena::with_block_size(256);
        let buf = arena.alloc_zeroed(128);
        assert_eq!(buf.len(), 128);
        assert!(buf.iter().all(|&b| b == 0));
        assert_eq!(arena.bytes_allocated(), 128);
    }

    #[test]
    fn arena_alloc_zeroed_zero_size() {
        let mut arena = Arena::new();
        let buf = arena.alloc_zeroed(0);
        assert!(buf.is_empty());
    }

    #[test]
    fn arena_alloc_typed_u32() {
        let mut arena = Arena::with_block_size(256);
        let val: &mut u32 = arena.alloc_typed::<u32>();
        assert_eq!(*val, 0u32); // Default for u32 is 0
        *val = 42;
        assert_eq!(*val, 42);
        // Check alignment: the pointer must be aligned for u32.
        let ptr = val as *const u32;
        assert_eq!(ptr as usize % mem::align_of::<u32>(), 0);
    }

    #[test]
    fn arena_alloc_typed_u64() {
        let mut arena = Arena::with_block_size(256);
        // Force a small offset to test alignment padding.
        let _byte = arena.alloc(1);
        let val: &mut u64 = arena.alloc_typed::<u64>();
        assert_eq!(*val, 0u64);
        let ptr = val as *const u64;
        assert_eq!(
            ptr as usize % mem::align_of::<u64>(),
            0,
            "u64 must be properly aligned"
        );
    }

    #[test]
    fn arena_alloc_typed_sym() {
        let mut arena = Arena::with_block_size(4096);
        let sym: &mut Sym = arena.alloc_typed::<Sym>();
        assert_eq!(sym.v, 0);
        assert_eq!(sym.c, 0);
        assert!(sym.next.is_none());
        let ptr = sym as *const Sym;
        assert_eq!(
            ptr as usize % mem::align_of::<Sym>(),
            0,
            "Sym must be properly aligned"
        );
    }

    #[test]
    #[should_panic(expected = "Cannot arena-allocate zero-sized types")]
    fn arena_alloc_typed_zst_panics() {
        let mut arena = Arena::new();
        let _: &mut () = arena.alloc_typed::<()>();
    }

    #[test]
    fn arena_reset() {
        let mut arena = Arena::with_block_size(128);
        let _ = arena.alloc(100);
        let _ = arena.alloc(100);
        assert!(arena.blocks.len() >= 2);
        let block_count = arena.blocks.len();

        arena.reset();
        assert_eq!(arena.bytes_allocated(), 0);
        assert_eq!(arena.offset, 0);
        assert_eq!(arena.current_block, 0);
        // Blocks are retained for reuse.
        assert_eq!(arena.blocks.len(), block_count);
    }

    #[test]
    fn arena_reset_reuse() {
        let mut arena = Arena::with_block_size(256);
        let _ = arena.alloc(128);
        arena.reset();
        // Allocate again — should reuse block 0 without creating a new one.
        let _ = arena.alloc(128);
        assert_eq!(arena.blocks.len(), 1);
        assert_eq!(arena.bytes_allocated(), 128);
    }

    #[test]
    fn arena_bytes_allocated_tracks_correctly() {
        let mut arena = Arena::with_block_size(1024);
        let _ = arena.alloc(10);
        let _ = arena.alloc(20);
        let _ = arena.alloc_zeroed(30);
        assert_eq!(arena.bytes_allocated(), 60);
    }

    #[test]
    fn arena_default_trait() {
        let arena = Arena::default();
        assert_eq!(arena.block_size, DEFAULT_BLOCK_SIZE);
        assert_eq!(arena.bytes_allocated(), 0);
    }

    #[test]
    fn arena_multiple_typed_allocations() {
        let mut arena = Arena::with_block_size(4096);
        for i in 0u32..50 {
            let val: &mut u32 = arena.alloc_typed::<u32>();
            *val = i;
            assert_eq!(*val, i);
            let ptr = val as *const u32;
            assert_eq!(ptr as usize % mem::align_of::<u32>(), 0);
        }
        assert_eq!(
            arena.bytes_allocated(),
            50 * mem::size_of::<u32>()
        );
    }

    // -----------------------------------------------------------------------
    // ScratchBuffer tests
    // -----------------------------------------------------------------------

    #[test]
    fn scratch_new_empty() {
        let buf = ScratchBuffer::new();
        assert!(buf.is_empty());
        assert_eq!(buf.len(), 0);
    }

    #[test]
    fn scratch_with_capacity() {
        let buf = ScratchBuffer::with_capacity(256);
        assert!(buf.is_empty());
        assert_eq!(buf.len(), 0);
        // Capacity is at least 256.
        assert!(buf.data.capacity() >= 256);
    }

    #[test]
    fn scratch_push_byte() {
        let mut buf = ScratchBuffer::new();
        buf.push(b'A');
        buf.push(b'B');
        assert_eq!(buf.len(), 2);
        assert_eq!(buf.as_bytes(), b"AB");
    }

    #[test]
    fn scratch_push_str() {
        let mut buf = ScratchBuffer::new();
        buf.push_str("hello");
        assert_eq!(buf.len(), 5);
        assert_eq!(buf.as_str().unwrap(), "hello");
    }

    #[test]
    fn scratch_push_mixed() {
        let mut buf = ScratchBuffer::new();
        buf.push_str("key");
        buf.push(b'=');
        buf.push_str("value");
        assert_eq!(buf.as_str().unwrap(), "key=value");
        assert_eq!(buf.len(), 9);
    }

    #[test]
    fn scratch_clear() {
        let mut buf = ScratchBuffer::new();
        buf.push_str("temporary data");
        assert!(!buf.is_empty());

        buf.clear();
        assert!(buf.is_empty());
        assert_eq!(buf.len(), 0);
        assert_eq!(buf.as_bytes(), b"");
    }

    #[test]
    fn scratch_clear_retains_capacity() {
        let mut buf = ScratchBuffer::new();
        buf.push_str("some reasonably long string to force allocation");
        let cap_before = buf.data.capacity();
        buf.clear();
        assert!(buf.data.capacity() >= cap_before);
    }

    #[test]
    fn scratch_as_str_invalid_utf8() {
        let mut buf = ScratchBuffer::new();
        buf.push(0xFF);
        buf.push(0xFE);
        assert!(buf.as_str().is_err());
    }

    #[test]
    fn scratch_as_bytes() {
        let mut buf = ScratchBuffer::new();
        buf.push(1);
        buf.push(2);
        buf.push(3);
        assert_eq!(buf.as_bytes(), &[1, 2, 3]);
    }

    #[test]
    fn scratch_default_trait() {
        let buf = ScratchBuffer::default();
        assert!(buf.is_empty());
    }

    // -----------------------------------------------------------------------
    // SymPool tests
    // -----------------------------------------------------------------------

    #[test]
    fn sympool_new() {
        let pool = SymPool::new();
        assert_eq!(pool.allocated_count, 0);
    }

    #[test]
    fn sympool_alloc_sym_basic() {
        let mut pool = SymPool::new();
        let sym = pool.alloc_sym();
        // Verify default values.
        assert_eq!(sym.v, 0);
        assert_eq!(sym.r, 0);
        assert_eq!(sym.c, 0);
        assert_eq!(sym.sym_scope, 0);
        assert!(sym.next.is_none());
        assert!(sym.prev.is_none());
        assert!(sym.prev_tok.is_none());
        assert!(sym.d.is_none());
        assert_eq!(sym.asm_label, 0);
        assert_eq!(pool.allocated_count, 1);
    }

    #[test]
    fn sympool_alloc_sym_modify() {
        let mut pool = SymPool::new();
        let sym = pool.alloc_sym();
        sym.v = 0x1234;
        sym.c = 42;
        assert_eq!(sym.v, 0x1234);
        assert_eq!(sym.c, 42);
    }

    #[test]
    fn sympool_alloc_sym_alignment() {
        let mut pool = SymPool::new();
        let sym = pool.alloc_sym();
        let ptr = sym as *const Sym;
        assert_eq!(
            ptr as usize % mem::align_of::<Sym>(),
            0,
            "Allocated Sym must be properly aligned"
        );
    }

    #[test]
    fn sympool_alloc_multiple() {
        let mut pool = SymPool::new();
        for _ in 0..100 {
            let sym = pool.alloc_sym();
            sym.v = 1;
        }
        assert_eq!(pool.allocated_count, 100);
    }

    #[test]
    fn sympool_reset() {
        let mut pool = SymPool::new();
        for _ in 0..10 {
            let sym = pool.alloc_sym();
            sym.v = 99;
        }
        assert_eq!(pool.allocated_count, 10);

        pool.reset();
        assert_eq!(pool.allocated_count, 0);
        assert_eq!(pool.arena.bytes_allocated(), 0);
    }

    #[test]
    fn sympool_reset_reuse() {
        let mut pool = SymPool::new();
        for _ in 0..10 {
            let _ = pool.alloc_sym();
        }
        pool.reset();
        // Allocate again after reset — should reuse arena blocks.
        for _ in 0..10 {
            let sym = pool.alloc_sym();
            sym.v = 7;
        }
        assert_eq!(pool.allocated_count, 10);
    }

    #[test]
    fn sympool_default_trait() {
        let pool = SymPool::default();
        assert_eq!(pool.allocated_count, 0);
    }

    // -----------------------------------------------------------------------
    // Integration / stress tests
    // -----------------------------------------------------------------------

    #[test]
    fn arena_many_small_allocations() {
        let mut arena = Arena::with_block_size(1024);
        for _ in 0..1000 {
            let buf = arena.alloc(8);
            assert_eq!(buf.len(), 8);
        }
        assert_eq!(arena.bytes_allocated(), 8000);
    }

    #[test]
    fn arena_alternating_sizes() {
        let mut arena = Arena::with_block_size(512);
        for i in 0..100 {
            let size = if i % 2 == 0 { 4 } else { 128 };
            let buf = arena.alloc(size);
            assert_eq!(buf.len(), size);
        }
        assert_eq!(arena.bytes_allocated(), 50 * 4 + 50 * 128);
    }

    #[test]
    fn scratch_large_content() {
        let mut buf = ScratchBuffer::new();
        for _ in 0..10_000 {
            buf.push(b'x');
        }
        assert_eq!(buf.len(), 10_000);
        assert!(buf.as_str().unwrap().chars().all(|c| c == 'x'));
    }

    #[test]
    fn sympool_many_syms() {
        let mut pool = SymPool::new();
        for i in 0..500 {
            let sym = pool.alloc_sym();
            sym.v = i;
            sym.c = i * 10;
        }
        assert_eq!(pool.allocated_count, 500);
    }

    #[test]
    fn constant_default_block_size() {
        assert_eq!(DEFAULT_BLOCK_SIZE, 256 * 1024);
    }
}
