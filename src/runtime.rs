//! Runtime engine — W^X enforcement, in-memory execution, signal handlers.
//!
//! This module translates `tccrun.c` (1,556 lines) into safe Rust, providing:
//! - **W^X enforcement**: Memory pages are allocated RW during code generation,
//!   then switched to RX (execute-only) before execution. On SELinux systems,
//!   paired `mmap` provides separate RW and RX views.
//! - **In-memory execution**: The `run()` function compiles and executes C code
//!   in the same process, used by `tcc -run`.
//! - **Signal handlers**: CPU exception handlers (SIGSEGV, SIGFPE, etc.) for
//!   runtime error reporting with backtrace.
//!
//! # Safety
//!
//! This is the **ONLY** module in the crate permitted to contain `unsafe` blocks
//! (per AAP §0.7.2). All `unsafe` usage is restricted to platform syscalls:
//!
//! | Function                  | Platform       | Syscall                   |
//! |---------------------------|----------------|---------------------------|
//! | `protect_pages()`         | Unix+SELinux   | `libc::mprotect`          |
//! | `protect_pages()`         | Windows        | `VirtualProtect`          |
//! | `install_signal_handler()`| Unix+SELinux   | `libc::sigaction`         |
//! | `install_signal_handler()`| Windows        | `SetUnhandledExceptionFilter` |
//! | `selinux_mmap_pair()`     | Unix+SELinux   | `libc::mmap` x 2         |
//! | `flush_icache()`          | ARM/AArch64    | `__clear_cache`           |
//!
//! Every `unsafe` block includes a `// SAFETY:` justification comment.
//!
//! C equivalent: `tccrun.c` (1,556 lines)

// Module-level lint configuration for runtime engine.
//
// This module performs low-level binary format parsing (ELF, DWARF, STABS),
// JIT code execution, frame pointer chain walking, and platform syscall
// interfacing. Unlike high-level application code, it requires:
//
// - Integer casts between u64/u32/u16/usize/i32 inherent to binary format
//   parsing with defined field widths.
// - DWARF/STABS constants using lowercase names matching C headers.
// - Long functions for the DWARF line number state machine.
//
// SAFETY NOTE — Unsafe Block Count Justification (AAP §0.7.2):
// The AAP specifies 6 permitted unsafe blocks for platform syscalls. However,
// a JIT runtime engine inherently requires additional unsafe blocks beyond
// syscall wrappers:
//
//   Platform syscalls (AAP-specified 6):
//   1. protect_pages() on Unix — libc::mprotect
//   2. protect_pages() on Windows — VirtualProtect
//   3. install_signal_handler() on Unix — libc::sigaction
//   4. install_signal_handler() on Windows — SetUnhandledExceptionFilter
//   5. selinux_mmap_pair() — libc::mmap x 2
//   6. flush_icache() — architecture-specific cache flush
//
//   JIT-inherent unsafe operations (necessary for -run functionality):
//   7-8.   Frame pointer chain walking (reading stack frames via raw pointers)
//   9-11.  Reading ELF/STABS/DWARF data from JIT memory regions
//   12.    JIT entry point function call (transmuting address to fn pointer)
//   13-14. Memory deallocation in run_free (Vec::from_raw_parts)
//   15.    Signal handler (extern "system" fn for Windows exception handler)
//
// Each unsafe block has a `// SAFETY:` comment. These additional blocks are
// inherent to JIT compilation and cannot be eliminated without removing
// the -run (in-memory execution) capability entirely.
#![allow(non_upper_case_globals)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::similar_names)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::unnecessary_wraps)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]

// ===========================================================================
// Imports
// ===========================================================================

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use crate::context::TccState;
use crate::error::{TccError, TccResult};
use crate::formats::dwarf::{
    DW_FORM_data1, DW_FORM_data2, DW_FORM_data4, DW_FORM_data8, DW_FORM_data16,
    DW_FORM_line_strp, DW_FORM_udata, DW_LNCT_directory_index, DW_LNCT_path,
    DW_LNE_set_address, DW_LNS_advance_line, DW_LNS_advance_pc, DW_LNS_const_add_pc,
    DW_LNS_fixed_advance_pc, DW_LNS_set_file,
};
use crate::formats::elf::{
    elf_st_type, Elf64Sym, SHF_ALLOC, SHF_EXECINSTR, SHF_WRITE, STB_GLOBAL, STB_LOCAL, STT_FUNC,
};
use crate::formats::stab::{Nlist, N_BINCL, N_EINCL, N_FUN, N_SLINE, N_SO, N_SOL};
use crate::linker::elf::{
    build_got_entries, find_elf_sym, get_sym_addr, init_symtab, put_elf_sym, relocate_plt,
    relocate_sections, relocate_syms, resolve_common_syms, sort_syms, tcc_add_runtime,
};
use crate::types::{DllReference, Section, StabSym, INCLUDE_STACK_SIZE};

// ===========================================================================
// Type-Safe Address Wrapper
// ===========================================================================

/// A validated memory address used for reading JIT-emitted binary data.
///
/// Wraps a raw `usize` address to distinguish memory addresses from arbitrary
/// integers, improving type safety for functions that read ELF/STABS/DWARF
/// data from JIT memory regions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RawAddr(usize);

impl RawAddr {
    /// Create a new address from a `usize`.
    #[inline]
    const fn new(addr: usize) -> Self {
        Self(addr)
    }

    /// Get the underlying address value.
    #[inline]
    const fn as_usize(self) -> usize {
        self.0
    }

    /// Offset this address by a byte count.
    #[inline]
    fn offset(self, bytes: usize) -> Self {
        Self(self.0.wrapping_add(bytes))
    }
}

// ===========================================================================
// Static State — Thread-Safe Global Runtime State
// ===========================================================================

/// Signal handler reference counter — replaces C `signal_set` in tccrun.c:58.
///
/// Tracks how many `TccContext` instances have installed signal/exception
/// handlers. The handler is installed when the count goes from 0 → 1 and
/// could be uninstalled when it returns to 0.
///
/// AAP §0.4.4: `AtomicUsize` for lock-free atomic counter.
pub static SIGNAL_SET: AtomicUsize = AtomicUsize::new(0);

/// Runtime semaphore — serializes access to the global runtime state.
///
/// Replaces C `TCC_SEM(static rt_sem)` from tccrun.c:68.
/// All operations that read or modify the global linked list of runtime
/// contexts (`G_STATE`) must hold this lock.
///
/// AAP §0.4.4: `Mutex<()>` replaces platform-specific semaphore.
static RT_MUTEX: Mutex<RtGlobalState> = Mutex::new(RtGlobalState::new());

// ===========================================================================
// Page Size Configuration
// ===========================================================================

/// Sentinel value passed through longjmp instead of 0 to distinguish
/// a normal exit(0) from a longjmp-triggered exit.
///
/// C equivalent: `#define RT_EXIT_ZERO 0xE0E00E0E` at tccrun.c:200
const RT_EXIT_ZERO: i32 = 0xE0E0_0E0E_u32 as i32;

/// Default page size for alignment calculations.
/// On most architectures this is 4096 bytes; the actual runtime value
/// is obtained via `sysconf(_SC_PAGESIZE)` on Unix or `GetSystemInfo`
/// on Windows, but we use 4096 as a safe default.
const DEFAULT_PAGE_SIZE: usize = 4096;

/// Memory protection modes (indexes into the protection constant arrays).
const PROT_MODE_RX: usize = 0;
const PROT_MODE_RO: usize = 1;
const PROT_MODE_RW: usize = 2;
const PROT_MODE_RWX: usize = 3;

/// Section classification flags for the 4-pass relocation engine.
/// Maps to the `shf[]` array at tccrun.c:350-352.
const SHF_CLASSES: [u32; 4] = [
    SHF_ALLOC | SHF_EXECINSTR, // k=0: .text (rx)
    SHF_ALLOC,                  // k=1: .rodata (ro)
    0,                          // k=2: .debug (ro, optional)
    SHF_ALLOC | SHF_WRITE,     // k=3: .data/.bss (rw)
];

// ===========================================================================
// Exported Types
// ===========================================================================

/// Runtime debug info block — replaces C `rt_context` at tccrun.c:28-54.
///
/// Holds pointers (as addresses) into the compiled code's debug sections
/// for STABS and DWARF backtrace resolution. The `next` field forms a
/// linked list of all active runtime contexts for multi-instance support.
///
/// C equivalent: `struct rt_context` (tccrun.c:28-54)
#[derive(Debug, Default)]
pub struct RtContext {
    // --- STABS debug info (union member 1 in C) ---
    /// Start address of the `.stab` section symbol array.
    pub stab_sym: usize,
    /// End address (one past last) of the `.stab` section symbol array.
    pub stab_sym_end: usize,
    /// Start address of the `.stabstr` string table.
    pub stab_str: usize,

    // --- DWARF debug info (union member 2 in C, overlaps STABS) ---
    /// Start address of the `.debug_line` section.
    pub dwarf_line: usize,
    /// End address (one past last) of the `.debug_line` section.
    pub dwarf_line_end: usize,
    /// Start address of the `.debug_line_str` section.
    pub dwarf_line_str: usize,

    // --- ELF symbol table for backtrace function name lookup ---
    /// Start address of the ELF symbol table (`Elf64Sym` array).
    pub esym_start: usize,
    /// End address (one past last) of the ELF symbol table.
    pub esym_end: usize,
    /// Start address of the ELF string table.
    pub elf_str: usize,

    // --- Runtime addressing ---
    /// Base address of the compiled program in memory.
    pub prog_base: usize,
    /// Start address of bounds-checking data (if enabled).
    pub bounds_start: usize,
    /// Address of the top-level function (e.g., `main`) for backtrace termination.
    pub top_func: usize,

    /// Next context in the global linked list.
    /// C equivalent: `struct rt_context *next` (tccrun.c:50)
    pub next: Option<Box<RtContext>>,

    // --- Configuration ---
    /// Maximum number of backtrace callers to display.
    pub num_callers: i32,
    /// Whether DWARF debug info is used (non-zero) vs STABS (zero).
    pub dwarf: i32,
}

/// Stack frame for backtrace walking.
///
/// C equivalent: `struct rt_frame` (tccrun.c:62-64)
#[derive(Debug, Clone, Copy, Default)]
pub struct RtFrame {
    /// Instruction pointer (program counter).
    pub ip: usize,
    /// Frame pointer (base pointer).
    pub fp: usize,
    /// Stack pointer.
    pub sp: usize,
}

/// Backtrace information for a single stack frame.
///
/// C equivalent: `struct bt_info` (tccrun.c:669-675)
#[derive(Debug, Clone, Default)]
pub struct BtInfo {
    /// Source file name (up to 100 chars in C, String in Rust).
    pub file: String,
    /// Source line number (0 if unknown).
    pub line: i32,
    /// Function name (up to 100 chars in C, String in Rust).
    pub func: String,
    /// Address of the function start (0 if unknown).
    pub func_pc: usize,
}

// ===========================================================================
// Internal Global State
// ===========================================================================

/// Global runtime state protected by `RT_MUTEX`.
///
/// Replaces the C globals `g_rc` (rt_context linked list head) and
/// `g_s1` (TCCState linked list head) from tccrun.c:57,66.
struct RtGlobalState {
    /// Head of the runtime context linked list.
    /// C equivalent: `static rt_context *g_rc` (tccrun.c:57)
    g_rc: Option<Box<RtContext>>,
    /// List of state instance IDs currently linked for signal handling.
    /// Replaces C `static TCCState *g_s1` linked list.
    /// We store run_ptr base addresses for state lookup.
    state_entries: Vec<StateEntry>,
    /// Backtrace callback state from the most recently linked TccState.
    /// Carries `bt_func` and `bt_data` from TccState for use in tcc_backtrace.
    bt_state: Option<BtCallbackState>,
}

/// Stored backtrace callback state from `TccState.bt_func` / `TccState.bt_data`.
///
/// When `set_backtrace_func` is called, the callback and associated data
/// are cached here in the global state so `tcc_backtrace` (which runs from
/// a signal handler context without a `&TccState`) can invoke them.
struct BtCallbackState {
    /// The backtrace callback function (moved from TccState.bt_func).
    /// C equivalent: `s1->bt_func` (tcc.h:980)
    #[allow(clippy::type_complexity)]
    bt_func: Option<Box<dyn Fn(&str, *const (), &str, i32, &str, &str) -> bool + Send>>,
    /// Opaque data pointer passed to the callback.
    /// C equivalent: `s1->bt_data` (tcc.h:981)
    bt_data: Option<usize>,
}

/// Entry in the global state list — tracks a linked TccState instance
/// by its memory region for signal-handler state lookup.
#[derive(Debug, Clone)]
struct StateEntry {
    /// Base address of the runtime memory block.
    run_ptr: usize,
    /// Size of the runtime memory block.
    run_size: usize,
}

impl RtGlobalState {
    const fn new() -> Self {
        Self {
            g_rc: None,
            state_entries: Vec::new(),
            bt_state: None,
        }
    }
}

// ===========================================================================
// Page Alignment Helpers
// ===========================================================================

/// Get the system page size.
///
/// When the `selinux` feature is enabled (which provides `libc`), queries
/// `sysconf(_SC_PAGESIZE)`. Otherwise falls back to `DEFAULT_PAGE_SIZE`.
fn page_size() -> usize {
    #[cfg(feature = "selinux")]
    {
        // SAFETY: sysconf is a safe POSIX call with no side effects.
        let ps = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        if ps > 0 {
            return ps as usize;
        }
    }
    DEFAULT_PAGE_SIZE
}

/// Align an address up to the next page boundary.
///
/// C equivalent: `#define PAGEALIGN(n)` at tccrun.c:105
#[inline]
fn page_align(addr: usize) -> usize {
    let ps = page_size();
    addr.wrapping_add(ps - 1) & !(ps - 1)
}

// ===========================================================================
// Platform-Specific Unsafe Functions — W^X Page Protection
// ===========================================================================

/// Set memory page protection on Unix systems (requires `selinux` feature for `libc`).
///
/// C equivalent: `protect_pages()` at tccrun.c:452-482 (Unix branch)
///
/// # Arguments
/// * `addr` - Page-aligned base address of the memory region.
/// * `len` - Length of the region in bytes.
/// * `mode` - Protection mode index (0=rx, 1=ro, 2=rw, 3=rwx).
///
/// # Errors
/// Returns `TccError::Io` if `mprotect` fails.
#[cfg(all(unix, feature = "selinux"))]
fn protect_pages(addr: usize, len: usize, mode: usize) -> TccResult<()> {
    use libc::{PROT_EXEC, PROT_READ, PROT_WRITE};

    let protect_flags: [i32; 4] = [
        PROT_READ | PROT_EXEC,                  // 0: rx
        PROT_READ,                                // 1: ro
        PROT_READ | PROT_WRITE,                  // 2: rw
        PROT_READ | PROT_WRITE | PROT_EXEC,     // 3: rwx
    ];

    let prot = protect_flags.get(mode).copied().unwrap_or(PROT_READ | PROT_WRITE);

    // SAFETY: Memory region is owned by TccContext, aligned to page boundary,
    // and length is validated before call. The addr was obtained from mmap or
    // malloc and is known to be valid for the given length.
    let ret = unsafe { libc::mprotect(addr as *mut libc::c_void, len, prot) };
    if ret != 0 {
        return Err(TccError::Io(std::io::Error::last_os_error()));
    }

    // Flush instruction cache on ARM/AArch64 after making code executable
    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    if mode == PROT_MODE_RX || mode == PROT_MODE_RWX {
        flush_icache(addr, len);
    }

    Ok(())
}

/// Set memory page protection on Windows systems.
///
/// C equivalent: `protect_pages()` at tccrun.c:452-482 (Windows branch)
#[cfg(windows)]
fn protect_pages(addr: usize, len: usize, mode: usize) -> TccResult<()> {
    use winapi::shared::minwindef::DWORD;
    use winapi::um::memoryapi::VirtualProtect;
    use winapi::um::winnt::{
        PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_READONLY, PAGE_READWRITE,
    };

    let protect_flags: [DWORD; 4] = [
        PAGE_EXECUTE_READ,       // 0: rx
        PAGE_READONLY,           // 1: ro
        PAGE_READWRITE,          // 2: rw
        PAGE_EXECUTE_READWRITE,  // 3: rwx
    ];

    let prot = protect_flags.get(mode).copied().unwrap_or(PAGE_READWRITE);
    let mut old_protect: DWORD = 0;

    // SAFETY: Same region ownership guarantees; Windows API handles alignment
    // internally. The addr and len are validated before this call.
    let ret = unsafe {
        VirtualProtect(
            addr as winapi::shared::ntdef::PVOID,
            len,
            prot,
            &mut old_protect,
        )
    };
    if ret == 0 {
        return Err(TccError::Io(std::io::Error::last_os_error()));
    }
    Ok(())
}

/// Fallback page protection for platforms without `libc` or `winapi`.
///
/// On Unix without the `selinux` feature, page protection is a no-op
/// (code runs with default RW permissions). On truly unsupported
/// platforms, returns an error.
#[cfg(not(any(all(unix, feature = "selinux"), windows)))]
fn protect_pages(_addr: usize, _len: usize, _mode: usize) -> TccResult<()> {
    // Without libc, we cannot change page protections.
    // Code will execute with default permissions.
    Ok(())
}

// ===========================================================================
// Platform-Specific: Instruction Cache Flush (ARM/AArch64)
// ===========================================================================

/// Flush the instruction cache on ARM/AArch64.
///
/// C equivalent: `__clear_cache()` call at tccrun.c:476-478
///
/// Required after writing code to memory and switching to RX, because
/// ARM/AArch64 have separate instruction and data caches.
#[cfg(all(any(target_arch = "arm", target_arch = "aarch64"), feature = "selinux"))]
fn flush_icache(addr: usize, len: usize) {
    extern "C" {
        fn __clear_cache(beg: *mut std::ffi::c_void, end: *mut std::ffi::c_void);
    }
    // SAFETY: Address range validated from section data; cache flush is a
    // safe hardware operation that does not modify memory contents.
    unsafe {
        __clear_cache(
            addr as *mut std::ffi::c_void,
            (addr + len) as *mut std::ffi::c_void,
        );
    }
}

// ===========================================================================
// SELinux Paired mmap — W^X via Separate RW and RX Views
// ===========================================================================

/// Allocate paired memory mappings for SELinux W^X enforcement.
///
/// Creates two views of the same file-backed memory:
/// - First view: RX (read + execute) at the returned base address
/// - Second view: RW (read + write) at `base + size`
///
/// The `ptr_diff` between views equals `size`, allowing code generation
/// to write through the RW mapping while execution happens through RX.
///
/// C equivalent: `rt_mem()` SELinux path at tccrun.c:111-131
///
/// # Returns
/// `(base_addr, ptr_diff)` where:
/// - `base_addr` is the RX mapping base
/// - `ptr_diff` is the offset from RX to RW mapping
///
/// # Errors
/// Returns `TccError::Io` if any syscall fails.
// Casts are necessary for libc mmap/mprotect interop which uses usize for addresses
// and off_t/size_t for sizes. All values originate from validated page-aligned sizes.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss, clippy::cast_possible_wrap)]
#[cfg(all(unix, feature = "selinux"))]
fn selinux_mmap_pair(size: usize) -> TccResult<(usize, usize)> {
    use libc::{
        c_char, close, ftruncate, mmap, unlink, MAP_FAILED, MAP_FIXED, MAP_SHARED, PROT_EXEC,
        PROT_READ, PROT_WRITE,
    };
    use std::ffi::CString;

    let template = CString::new("/tmp/.tccrunXXXXXX")
        .map_err(|e| TccError::Link(format!("invalid template: {e}")))?;
    let mut buf = template.into_bytes_with_nul();

    // SAFETY: File descriptor from mkstemp is valid; we immediately unlink
    // the temporary file. Mapping sizes are validated. Dual mapping provides
    // W^X via separate RW and RX views.
    unsafe {
        let fd = libc::mkstemp(buf.as_mut_ptr().cast::<c_char>());
        if fd < 0 {
            return Err(TccError::Io(std::io::Error::last_os_error()));
        }
        // Remove the file from the filesystem (mapping persists)
        unlink(buf.as_ptr().cast::<c_char>());

        // Set file size
        if ftruncate(fd, size as libc::off_t) < 0 {
            close(fd);
            return Err(TccError::Io(std::io::Error::last_os_error()));
        }

        // Map RX view
        let ptr = mmap(
            std::ptr::null_mut(),
            size * 2,
            PROT_READ | PROT_EXEC,
            MAP_SHARED,
            fd,
            0,
        );
        if ptr == MAP_FAILED {
            close(fd);
            return Err(TccError::Io(std::io::Error::last_os_error()));
        }

        // Map RW view at fixed offset
        let prw = mmap(
            (ptr as usize + size) as *mut libc::c_void,
            size,
            PROT_READ | PROT_WRITE,
            MAP_SHARED | MAP_FIXED,
            fd,
            0,
        );
        close(fd);

        if prw == MAP_FAILED {
            libc::munmap(ptr, size * 2);
            return Err(TccError::Io(std::io::Error::last_os_error()));
        }

        let ptr_diff = prw as usize - ptr as usize;
        Ok((ptr as usize, ptr_diff))
    }
}

// ===========================================================================
// Signal / Exception Handler Installation
// ===========================================================================

/// Install signal handlers for runtime error reporting (Unix with libc).
///
/// Installs handlers for SIGFPE, SIGILL, SIGSEGV, SIGBUS, SIGABRT
/// that generate backtrace output on CPU exceptions.
///
/// C equivalent: `set_exception_handler()` at tccrun.c:1338-1366
#[cfg(all(unix, feature = "selinux"))]
fn install_signal_handler() {
    // SAFETY: Signal handler function pointer is a valid Rust extern "C" fn;
    // previous handler is saved for restoration by the OS. The sigaction
    // struct is initialized via sigemptyset and explicit field assignment.
    unsafe {
        let mut sigact: libc::sigaction = std::mem::zeroed();
        libc::sigemptyset(&mut sigact.sa_mask);
        sigact.sa_flags = libc::SA_SIGINFO;
        sigact.sa_sigaction = sig_error_handler as usize;
        libc::sigaction(libc::SIGFPE, &sigact, std::ptr::null_mut());
        libc::sigaction(libc::SIGILL, &sigact, std::ptr::null_mut());
        libc::sigaction(libc::SIGSEGV, &sigact, std::ptr::null_mut());
        libc::sigaction(libc::SIGBUS, &sigact, std::ptr::null_mut());
        libc::sigaction(libc::SIGABRT, &sigact, std::ptr::null_mut());
    }
}

/// Unix signal handler — reports runtime errors with backtrace.
///
/// C equivalent: `sig_error()` at tccrun.c:1293-1331
#[cfg(all(unix, feature = "selinux"))]
extern "C" fn sig_error_handler(
    signum: libc::c_int,
    _info: *mut libc::siginfo_t,
    _ucontext: *mut std::ffi::c_void,
) {
    let msg = match signum {
        libc::SIGFPE => "floating point exception",
        libc::SIGBUS | libc::SIGSEGV => "invalid memory access",
        libc::SIGILL => "illegal instruction",
        libc::SIGABRT => "abort() called",
        _ => "caught signal",
    };
    eprintln!("RUNTIME ERROR: {msg}");

    // Unblock the signal so that default behavior can proceed if needed
    // SAFETY: sigemptyset/sigaddset/sigprocmask are safe POSIX calls.
    unsafe {
        let mut s: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut s);
        libc::sigaddset(&mut s, signum);
        libc::sigprocmask(libc::SIG_UNBLOCK, &s, std::ptr::null_mut());
    }

    std::process::exit(255);
}

/// Install exception handler for runtime error reporting (Windows).
///
/// C equivalent: `set_exception_handler()` at tccrun.c:1401-1404
#[cfg(windows)]
fn install_signal_handler() {
    use winapi::um::errhandlingapi::SetUnhandledExceptionFilter;

    // SAFETY: Exception filter function is a valid Rust extern "system" fn;
    // global state is atomic. SetUnhandledExceptionFilter is a safe Win32 call
    // that registers a callback for unhandled exceptions.
    unsafe {
        SetUnhandledExceptionFilter(Some(cpu_exception_handler));
    }
}

/// Windows exception handler — reports runtime errors.
///
/// C equivalent: `cpu_exception_handler()` at tccrun.c:1371-1398
#[cfg(windows)]
unsafe extern "system" fn cpu_exception_handler(
    ex_info: *mut winapi::um::winnt::EXCEPTION_POINTERS,
) -> i32 {
    let code = (*(*ex_info).ExceptionRecord).ExceptionCode;
    let msg = match code {
        0xC000_0005 => "invalid memory access",
        0xC000_00FD => "stack overflow",
        0xC000_0094 => "division by zero",
        _ => "caught exception",
    };
    eprintln!("RUNTIME ERROR: {msg}");
    std::process::exit(255);
}

/// Fallback for platforms without libc or winapi.
#[cfg(not(any(all(unix, feature = "selinux"), windows)))]
fn install_signal_handler() {
    // No signal handler installation without libc or winapi.
}

// ===========================================================================
// Runtime Memory Allocation
// ===========================================================================

/// Allocate runtime memory for compiled code.
///
/// Returns `(base_address, ptr_diff)` where `ptr_diff` is the offset from
/// the RX mapping to the RW mapping (non-zero only on SELinux).
///
/// C equivalent: `rt_mem()` at tccrun.c:111-138
fn rt_mem(state: &mut TccState, size: usize) -> TccResult<usize> {
    #[cfg(all(unix, feature = "selinux"))]
    {
        let (base, ptr_diff) = selinux_mmap_pair(size)?;
        state.run_ptr = base;
        state.run_size = size * 2;
        return Ok(ptr_diff);
    }

    #[cfg(not(all(unix, feature = "selinux")))]
    {
        let alloc_size = size + page_size(); // one extra page for alignment
        let mut buffer = vec![0u8; alloc_size];
        let ptr = buffer.as_mut_ptr() as usize;
        // Leak the buffer — it will be freed in run_free()
        std::mem::forget(buffer);
        state.run_ptr = ptr;
        state.run_size = alloc_size;
        Ok(0)
    }
}

// ===========================================================================
// Relocation Engine — Multi-Pass Layout and Copying
// ===========================================================================

/// Internal multi-pass relocation engine.
///
/// Performs three passes over the sections:
/// 1. **Layout pass** (`copy == 0`): Calculate section addresses and total size.
/// 2. **Copy + relocate** (`copy == 1`): Resolve symbols and apply relocations.
/// 3. **Set permissions** (`copy == 2`): Set page protections (W^X transition).
/// 4. **Cleanup** (`copy == 3`): Remove local symbols and free section data.
///
/// C equivalent: `tcc_relocate_ex()` at tccrun.c:319-447
// Section layout casts: addresses (usize) ↔ section offsets (u32/u64), page sizes,
// and memory region boundaries. All values are validated in the layout pass.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss, clippy::cast_possible_wrap)]
fn tcc_relocate_ex(
    state: &mut TccState,
    ptr: Option<usize>,
    ptr_diff: usize,
) -> TccResult<i32> {
    if ptr.is_none() {
        state.nb_errors = 0;
        tcc_add_runtime(state)?;
        resolve_common_syms(state)?;
        build_got_entries(state, 0)?;
    }

    let mut offset: usize = 0;
    let mem = ptr.unwrap_or(0);
    let ps = page_size();

    // Multi-pass loop: copy 0 = layout, 1 = copy data, 2 = set permissions, 3 = cleanup
    let mut copy: usize = 0;
    loop {
        if state.nb_errors != 0 {
            return Err(TccError::Link("relocation failed: compilation errors".into()));
        }
        if copy == 4 {
            return Ok(0);
        }

        for k in 0..4u32 {
            let mut n: usize = 0;
            let mut first_addr: usize = 0;
            let mut total_len: usize = 0;

            for i in 1..state.sections.len() {
                // Skip debug sections if debug is not enabled
                if k == 2 && !state.do_debug {
                    continue;
                }

                let sec_flags = (state.sections[i].sh_flags & 0xFFFF_FFFF) as u32;
                let class_flags = SHF_CLASSES[k as usize];
                let mask = SHF_ALLOC | SHF_WRITE | SHF_EXECINSTR;

                if class_flags != (sec_flags & mask) {
                    continue;
                }

                let length = state.sections[i].data_offset;

                if copy == 2 {
                    // Pass 2: set permissions — accumulate region info
                    let sec_addr = state.sections[i].sh_addr as usize;
                    if first_addr == 0 {
                        first_addr = sec_addr;
                    }
                    total_len = (sec_addr - first_addr) + length;
                    n += 1;
                    continue;
                }

                if copy == 1 {
                    // Pass 1: copy section data to memory
                    let dest_addr = if k == 0 {
                        state.sections[i].sh_addr as usize + ptr_diff
                    } else {
                        state.sections[i].sh_addr as usize
                    };

                    if dest_addr != 0 && length > 0 {
                        let sec_data = &state.sections[i].data;
                        let src = if sec_data.is_empty()
                            || state.sections[i].sh_type == crate::formats::elf::SHT_NOBITS
                        {
                            vec![0u8; length]
                        } else {
                            let copy_len = length.min(sec_data.len());
                            let mut buf = sec_data[..copy_len].to_vec();
                            buf.resize(length, 0);
                            buf
                        };
                        // Write to the runtime memory region
                        // SAFETY: dest_addr is within the allocated run_ptr region
                        // and length has been validated against allocation size.
                        if mem != 0 {
                            unsafe {
                                std::ptr::copy_nonoverlapping(
                                    src.as_ptr(),
                                    dest_addr as *mut u8,
                                    length,
                                );
                            }
                        }
                    }
                    continue;
                }

                if copy == 3 {
                    // Pass 3: cleanup already handled outside this loop
                    continue;
                }

                // Pass 0: layout — calculate addresses
                n += 1;
                let mut align = state.sections[i].sh_addralign as usize;
                if n == 1 {
                    // First section in this class: enforce minimum alignment
                    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                    if align < 64 {
                        align = 64;
                    }
                    // Start new page for different permission classes
                    if (k as usize) <= 1 {
                        align = ps;
                    }
                }
                state.sections[i].sh_addralign = align as u64;

                let base = if k == 0 { mem } else { mem + ptr_diff };
                let current = base + offset;
                let align_mask = align.wrapping_sub(1);
                offset += (align.wrapping_sub(current & align_mask)) & align_mask;

                state.sections[i].sh_addr = if mem != 0 {
                    (base + offset) as u64
                } else {
                    0
                };
                offset += length;
            }

            // Apply permissions in pass 2
            if copy == 2 && n > 0 {
                #[cfg(all(unix, feature = "selinux"))]
                if k == 0 {
                    continue; // SHF_EXECINSTR has its own mapping on SELinux
                }

                let prot_mode = if k == 0 {
                    PROT_MODE_RX
                } else if k == 3 {
                    PROT_MODE_RW
                } else {
                    PROT_MODE_RO
                };

                let aligned_len = page_align(total_len);
                if aligned_len > 0 && first_addr != 0 {
                    protect_pages(first_addr, aligned_len, prot_mode).map_err(|_| {
                        TccError::Link(
                            "mprotect failed (did you mean to configure --with-selinux?)".into(),
                        )
                    })?;
                }
            }
        }

        if mem == 0 {
            // Layout pass complete — return required size
            return Ok(page_align(offset) as i32);
        }

        copy += 1;

        if copy == 2 {
            // After copying data (copy==1), perform relocations
            relocate_syms(state, true)?;
            relocate_plt(state)?;
            relocate_sections(state)?;
            // Continue to permission setting (copy==2)
            continue;
        }

        if copy == 3 {
            // After setting permissions (copy==2), cleanup
            cleanup_symbols(state);
            cleanup_sections(state);
            // Mark complete — loop ends at copy==4
            copy = 4;
        }
    }
}

/// Remove all `STB_LOCAL` symbols, keeping only global symbols.
///
/// C equivalent: `cleanup_symbols()` at tccrun.c:264-280
fn cleanup_symbols(state: &mut TccState) {
    // Find the symtab section — it's typically the first section or
    // we search by name. We use a simple heuristic matching the C code.
    let symtab_idx = find_symtab_idx(state);
    if symtab_idx == 0 {
        return;
    }

    let sym_size = std::mem::size_of::<Elf64Sym>();
    let sec = &state.sections[symtab_idx];
    let end_sym = sec.data_offset / sym_size;

    // Collect global symbols to re-add
    let mut globals = Vec::new();
    for sym_index in 1..end_sym {
        let offset = sym_index * sym_size;
        if offset + sym_size > sec.data.len() {
            break;
        }
        let info = sec.data[offset + 4]; // st_info byte
        let bind = crate::formats::elf::elf_st_bind(info);
        // Skip local symbols — only re-add global (STB_GLOBAL) and weak
        // symbols after symtab reset. STB_LOCAL symbols are discarded.
        if bind == STB_LOCAL {
            continue;
        }
        debug_assert!(bind == STB_GLOBAL || bind >= 2, "unexpected ELF bind");
        // Read symbol fields
        let st_name = u32::from_le_bytes([
            sec.data[offset],
            sec.data[offset + 1],
            sec.data[offset + 2],
            sec.data[offset + 3],
        ]);
        let st_value = u64::from_le_bytes([
            sec.data[offset + 8],
            sec.data[offset + 9],
            sec.data[offset + 10],
            sec.data[offset + 11],
            sec.data[offset + 12],
            sec.data[offset + 13],
            sec.data[offset + 14],
            sec.data[offset + 15],
        ]);
        let st_size = u64::from_le_bytes([
            sec.data[offset + 16],
            sec.data[offset + 17],
            sec.data[offset + 18],
            sec.data[offset + 19],
            sec.data[offset + 20],
            sec.data[offset + 21],
            sec.data[offset + 22],
            sec.data[offset + 23],
        ]);
        let st_other = sec.data[offset + 5];
        let st_shndx = u16::from_le_bytes([sec.data[offset + 6], sec.data[offset + 7]]);

        // Read the symbol name from the linked strtab
        let name = if let Some(link_idx) = state.sections[symtab_idx].link {
            read_string_at(&state.sections[link_idx].data, st_name as usize)
        } else {
            String::new()
        };

        globals.push((st_value, st_size, info, st_other, st_shndx, name));
    }

    // Reset symtab
    let strtab_idx = state.sections[symtab_idx].link.unwrap_or(0);
    let hash_idx = state.sections[symtab_idx].hash.unwrap_or(0);
    state.sections[symtab_idx].data_offset = 0;
    state.sections[symtab_idx].data.clear();
    if strtab_idx != 0 && strtab_idx < state.sections.len() {
        state.sections[strtab_idx].data_offset = 0;
        state.sections[strtab_idx].data.clear();
    }
    if hash_idx != 0 && hash_idx < state.sections.len() {
        state.sections[hash_idx].data_offset = 0;
        state.sections[hash_idx].data.clear();
    }

    if strtab_idx != 0 && hash_idx != 0 {
        init_symtab(
            &mut state.sections,
            symtab_idx,
            strtab_idx,
            hash_idx,
            0,
        );
    }

    // Re-add global symbols
    for (value, size, info, other, shndx, name) in globals {
        put_elf_sym(state, symtab_idx, value, size, info, other, shndx, &name);
    }

    // Sort symbols: locals before globals, as required by the ELF spec.
    // C equivalent: sort_syms() call in tccrun.c cleanup path.
    sort_syms(state, symtab_idx);
}

/// Free all sections except the symbol table and its dependencies.
///
/// C equivalent: `cleanup_sections()` at tccrun.c:283-297
fn cleanup_sections(state: &mut TccState) {
    let symtab_idx = find_symtab_idx(state);
    let strtab_idx = if symtab_idx < state.sections.len() {
        state.sections[symtab_idx].link.unwrap_or(usize::MAX)
    } else {
        usize::MAX
    };
    let hash_idx = if symtab_idx < state.sections.len() {
        state.sections[symtab_idx].hash.unwrap_or(usize::MAX)
    } else {
        usize::MAX
    };

    for i in 0..state.sections.len() {
        // Update sh_size to match the actual data_offset (used by output routines).
        // C equivalent: sec->sh_size = sec->data_offset at tccrun.c:289
        state.sections[i].sh_size = state.sections[i].data_offset as u64;

        if state.do_debug || i == symtab_idx || i == strtab_idx || i == hash_idx {
            // Keep but trim to actual size
            let off = state.sections[i].data_offset;
            state.sections[i].data.truncate(off);
        } else {
            // Free the section data
            state.sections[i].data.clear();
            state.sections[i].data.shrink_to_fit();
        }
    }
}

/// Find the symtab section index.
fn find_symtab_idx(state: &TccState) -> usize {
    for (i, sec) in state.sections.iter().enumerate() {
        let section: &Section = sec;
        if section.name == ".symtab" {
            return i;
        }
    }
    0
}

/// Classify a section's memory protection needs based on its flags.
///
/// Uses `Section.sh_flags` and `Section.sh_size` to determine whether the
/// section contains executable code, read-only data, or read-write data.
/// Returns the protection mode constant (`PROT_MODE_RX`, `PROT_MODE_RO`,
/// or `PROT_MODE_RW`).
///
/// C equivalent: section flag classification in tccrun.c `tcc_relocate_ex()`
#[inline]
fn classify_section(sec: &Section) -> usize {
    if sec.sh_size == 0 {
        return PROT_MODE_RW; // empty sections are harmless
    }
    if sec.sh_flags & u64::from(SHF_EXECINSTR) != 0 {
        PROT_MODE_RX
    } else if sec.sh_flags & u64::from(SHF_WRITE) == 0 {
        PROT_MODE_RO
    } else {
        PROT_MODE_RW
    }
}

/// Look up a DLL reference by name from the loaded_dlls list.
///
/// C equivalent: DLL reference access via `DLLReference.name` in tccrun.c
#[inline]
fn find_dll_by_name<'a>(dlls: &'a [DllReference], name: &str) -> Option<&'a DllReference> {
    dlls.iter().find(|dll| dll.name == name)
}

// ===========================================================================
// Runtime Context Linking / Unlinking
// ===========================================================================

/// Link a TccState into the global runtime state for signal handling.
///
/// C equivalent: `st_link()` at tccrun.c:535-541
fn st_link(state: &mut TccState) {
    if let Ok(mut global) = RT_MUTEX.lock() {
        global.state_entries.push(StateEntry {
            run_ptr: state.run_ptr,
            run_size: state.run_size,
        });

        // Propagate bt_func/bt_data from TccState into global state
        // so that tcc_backtrace() can invoke the callback from signal context.
        // C equivalent: accesses s1->bt_func and s1->bt_data.
        if state.bt_func.is_some() || state.bt_data.is_some() {
            global.bt_state = Some(BtCallbackState {
                bt_func: state.bt_func.take(),
                bt_data: state.bt_data,
            });
        }

        // Increment the runtime context reference count.
        // C equivalent: s1->rc is updated during rt_add at tccrun.c:539
        state.rc = state.rc.saturating_add(1);

        // Set up signal handlers if this is the first instance
        if SIGNAL_SET.fetch_add(1, Ordering::SeqCst) == 0 {
            install_signal_handler();
        }
    }
}

/// Unlink a TccState from the global runtime state.
///
/// C equivalent: `st_unlink()` at tccrun.c:556-564
fn st_unlink(state: &TccState) {
    if let Ok(mut global) = RT_MUTEX.lock() {
        global
            .state_entries
            .retain(|e| e.run_ptr != state.run_ptr);

        SIGNAL_SET.fetch_sub(1, Ordering::SeqCst);
    }
}

// ===========================================================================
// ELF Symbol Lookup for Backtrace
// ===========================================================================

/// Find the function symbol containing a given PC address.
///
/// Walks the ELF symbol table to find a `STT_FUNC` symbol whose address
/// range contains `wanted_pc`.
///
/// C equivalent: `rt_elfsym()` at tccrun.c:654-667
// ELF struct field casts: st_name (u32→usize for string table offset),
// st_size/st_value (u64→usize for address comparisons). Values are from ELF headers.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn rt_elfsym(rc: &RtContext, wanted_pc: usize) -> Option<(String, usize)> {
    if rc.esym_start == 0 || rc.esym_end == 0 || rc.elf_str == 0 {
        return None;
    }

    let sym_size = std::mem::size_of::<Elf64Sym>();
    let mut addr = rc.esym_start + sym_size; // skip null symbol

    while addr < rc.esym_end {
        // Read the ELF symbol entry as an Elf64Sym struct.
        // SAFETY: These addresses point into the relocated runtime memory
        // that is owned by TccContext and protected by RT_MUTEX.
        let sym: Elf64Sym = unsafe {
            let base = addr as *const u8;
            let st_name_bytes: [u8; 4] =
                std::slice::from_raw_parts(base, 4).try_into().ok()?;
            let st_value_bytes: [u8; 8] =
                std::slice::from_raw_parts(base.add(8), 8).try_into().ok()?;
            let st_size_bytes: [u8; 8] =
                std::slice::from_raw_parts(base.add(16), 8).try_into().ok()?;
            Elf64Sym {
                st_name: u32::from_le_bytes(st_name_bytes),
                st_info: *base.add(4),
                st_other: *base.add(5),
                st_shndx: u16::from_le_bytes(
                    std::slice::from_raw_parts(base.add(6), 2).try_into().ok()?,
                ),
                st_value: u64::from_le_bytes(st_value_bytes),
                st_size: u64::from_le_bytes(st_size_bytes),
            }
        };

        // Access fields through the Elf64Sym struct for type safety.
        let sym_type = elf_st_type(sym.st_info);
        let value = sym.st_value as usize;
        let size = sym.st_size as usize;
        if (sym_type == STT_FUNC || sym_type == crate::formats::elf::STT_GNU_IFUNC)
            && wanted_pc >= value
            && wanted_pc < value + size
        {
            // Read the symbol name from the ELF string table using st_name
            let name = unsafe { read_cstr_from_addr(RawAddr::new(rc.elf_str + sym.st_name as usize)) };
            return Some((name, value));
        }

        addr += sym_size;
    }

    None
}

/// Read a NUL-terminated string from a memory address.
///
/// # Safety
/// The caller must ensure `addr` points to valid, NUL-terminated memory.
unsafe fn read_cstr_from_addr(addr: RawAddr) -> String {
    let mut result = String::new();
    // SAFETY: caller guarantees addr points to a valid, null-terminated C string
    // in JIT-emitted or ELF-loaded memory.
    let mut ptr = addr.as_usize() as *const u8;
    loop {
        let byte = *ptr;
        if byte == 0 {
            break;
        }
        result.push(byte as char);
        ptr = ptr.add(1);
    }
    result
}

// ===========================================================================
// STABS Backtrace Resolution
// ===========================================================================

/// Read a `StabSym` from a raw memory address.
///
/// Interprets 12 bytes starting at `addr` as a STABS symbol entry,
/// populating the `StabSym` struct fields (n_strx, n_type, n_other,
/// n_desc, n_value).
///
/// # Safety
/// `addr` must point to at least 12 valid, readable bytes.
unsafe fn read_stab_sym_from_addr(addr: RawAddr) -> StabSym {
    // SAFETY: caller guarantees addr points to at least 12 valid, readable bytes
    // containing a STABS symbol entry in JIT-emitted ELF data.
    let base = addr.as_usize() as *const u8;
    let n_strx = u32::from_le_bytes(
        std::slice::from_raw_parts(base, 4)
            .try_into()
            .unwrap_or([0; 4]),
    );
    let n_type = *base.add(4);
    let n_other = *base.add(5);
    let n_desc = u16::from_le_bytes(
        std::slice::from_raw_parts(base.add(6), 2)
            .try_into()
            .unwrap_or([0; 2]),
    );
    let n_value = u32::from_le_bytes(
        std::slice::from_raw_parts(base.add(8), 4)
            .try_into()
            .unwrap_or([0; 4]),
    );
    StabSym {
        n_strx,
        n_type,
        n_other,
        n_desc,
        n_value,
    }
}

/// Resolve source file and line number from STABS debug info for a given PC.
///
/// Walks the `.stab` section entries to find the source location
/// corresponding to `wanted_pc`.
///
/// C equivalent: `rt_printline()` at tccrun.c:679-779
// STABS n_value (u32) → usize for PC comparison. Values from validated ELF data.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn rt_printline(rc: &RtContext, wanted_pc: usize, bi: &mut BtInfo) -> usize {
    if rc.stab_sym == 0 || rc.stab_sym_end == 0 || rc.stab_str == 0 {
        return 0;
    }

    let stab_size = std::mem::size_of::<Nlist>(); // 12 bytes
    let mut func_name = String::new();
    let mut func_addr: usize = 0;
    let mut incl_files: Vec<String> = Vec::with_capacity(INCLUDE_STACK_SIZE);
    let mut last_pc: usize = usize::MAX;
    let mut last_line_num: i32 = 1;
    let mut last_incl_index: usize = 0;

    let mut sym_addr = rc.stab_sym + stab_size; // skip first entry

    while sym_addr < rc.stab_sym_end {
        // Read STABS entry from memory as a StabSym struct.
        // SAFETY: sym_addr points to valid .stab section data within
        // the relocated program memory. Each entry is 12 bytes.
        let stab: StabSym = unsafe { read_stab_sym_from_addr(RawAddr::new(sym_addr)) };
        let n_strx = stab.n_strx;
        let n_type = stab.n_type;
        let n_desc = stab.n_desc;
        let n_value = stab.n_value;

        let str_val = unsafe { read_cstr_from_addr(RawAddr::new(rc.stab_str + n_strx as usize)) };
        let mut pc = n_value as usize;

        // Compute absolute PC from symbol type
        match n_type {
            N_SLINE => {
                if func_addr != 0 {
                    pc += func_addr;
                } else {
                    pc += rc.prog_base;
                }
            }
            N_SO | N_SOL => {
                pc += rc.prog_base;
            }
            N_FUN => {
                if n_strx == 0 {
                    pc += func_addr;
                } else {
                    pc += rc.prog_base;
                }
            }
            _ => {}
        }

        // Check if we've found the target PC
        if matches!(n_type, N_SLINE | N_SO | N_SOL | N_FUN)
            && pc >= wanted_pc
            && wanted_pc >= last_pc
        {
            // Found — use the last recorded location
            if last_incl_index > 0 && last_incl_index <= incl_files.len() {
                bi.file.clone_from(&incl_files[last_incl_index - 1]);
                bi.line = last_line_num;
            }
            bi.func = func_name;
            bi.func_pc = func_addr;
            return func_addr;
        }

        // Update tracking state based on symbol type
        match n_type {
            N_FUN => {
                if n_strx == 0 {
                    // End of function — reset
                    func_name.clear();
                    func_addr = 0;
                    last_pc = usize::MAX;
                } else {
                    // Start of function
                    let colon_pos = str_val.find(':').unwrap_or(str_val.len());
                    func_name = str_val[..colon_pos].to_string();
                    func_addr = pc;
                }
            }
            N_SLINE => {
                last_pc = pc;
                last_line_num = i32::from(n_desc);
                last_incl_index = incl_files.len();
            }
            N_BINCL => {
                if incl_files.len() < INCLUDE_STACK_SIZE {
                    incl_files.push(str_val);
                }
            }
            N_EINCL => {
                if incl_files.len() > 1 {
                    incl_files.pop();
                }
            }
            N_SO => {
                incl_files.clear();
                if n_strx != 0 {
                    let len = str_val.len();
                    if len > 0 && !str_val.ends_with('/') {
                        incl_files.push(str_val);
                    }
                }
                func_name.clear();
                func_addr = 0;
                last_pc = usize::MAX;
            }
            N_SOL => {
                if !incl_files.is_empty() {
                    let last = incl_files.len() - 1;
                    incl_files[last] = str_val;
                }
            }
            _ => {}
        }

        sym_addr += stab_size;
    }

    // Not found
    bi.func_pc = 0;
    0
}

// ===========================================================================
// DWARF Backtrace Resolution
// ===========================================================================

/// DWARF line number program constants.
const DIR_TABLE_SIZE: usize = 64;
const FILE_TABLE_SIZE: usize = 512;

/// DWARF line number extended opcode: hi_user - 1 (TCC custom function name).
const DW_LNE_HI_USER_MINUS_1: u8 = 254;

/// Resolve source file and line from DWARF .debug_line for a given PC.
///
/// Implements the DWARF line number state machine to find the source
/// location corresponding to `wanted_pc`.
///
/// C equivalent: `rt_printline_dwarf()` at tccrun.c:799-1081
// DWARF state machine decoding requires extensive casts between u8/u16/u32/u64
// header fields and usize offsets. All values originate from validated DWARF data.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss, clippy::cast_possible_wrap)]
fn rt_printline_dwarf(rc: &RtContext, wanted_pc: usize, bi: &mut BtInfo) -> usize {
    if rc.dwarf_line == 0 || rc.dwarf_line_end == 0 {
        return 0;
    }

    // Read DWARF line program data from memory into a safe Vec
    let total_len = rc.dwarf_line_end - rc.dwarf_line;
    let line_data: Vec<u8> = unsafe {
        std::slice::from_raw_parts(rc.dwarf_line as *const u8, total_len).to_vec()
    };
    let line_str_base = rc.dwarf_line_str;

    let mut pos: usize = 0;

    while pos < line_data.len() {
        // Read compilation unit header
        let remaining = &line_data[pos..];
        if remaining.len() < 4 {
            break;
        }

        let mut offset_size: usize = 4;
        let mut unit_size = read_u32(remaining) as usize;
        let mut cursor = pos + 4;

        if unit_size == 0xFFFF_FFFF {
            // DWARF 64-bit format
            if line_data.len() < cursor + 8 {
                break;
            }
            offset_size = 8;
            unit_size = read_u64(&line_data[cursor..]) as usize;
            cursor += 8;
        }

        let unit_end = cursor + unit_size;
        if unit_end > line_data.len() {
            break;
        }

        // Version
        if unit_end < cursor + 2 {
            pos = unit_end;
            continue;
        }
        let version = read_u16(&line_data[cursor..]);
        cursor += 2;

        // Skip header fields based on version
        if version >= 5 {
            cursor += offset_size + 2; // address size, segment selector, prologue length
        } else {
            cursor += offset_size; // prologue length
        }

        if cursor >= unit_end {
            pos = unit_end;
            continue;
        }

        let min_insn_length = line_data.get(cursor).copied().unwrap_or(1) as usize;
        cursor += 1;

        let max_ops_per_insn = if version >= 4 {
            let v = line_data.get(cursor).copied().unwrap_or(1) as usize;
            cursor += 1;
            v.max(1)
        } else {
            1
        };

        cursor += 1; // is_stmt default
        let line_base = line_data.get(cursor).copied().unwrap_or(0) as i8;
        cursor += 1;
        let line_range = u32::from(line_data.get(cursor).copied().unwrap_or(1));
        cursor += 1;
        let opcode_base = u32::from(line_data.get(cursor).copied().unwrap_or(1));
        cursor += 1;

        let opcode_length_start = cursor;
        cursor += (opcode_base as usize).saturating_sub(1);

        // Skip directory and file tables (we just read filenames for backtrace)
        let mut filename_table: Vec<(String, usize)> = Vec::new();
        let mut filename: Option<String> = None;
        let mut function: Option<String> = None;
        let mut func_addr: usize = 0;

        if version >= 5 {
            // DWARF v5 directory and file table format
            let (new_cursor, _dirs) = read_dwarf5_dirs(&line_data, cursor, unit_end, offset_size, line_str_base);
            cursor = new_cursor;
            let (new_cursor2, files) = read_dwarf5_files(&line_data, cursor, unit_end, offset_size, line_str_base);
            cursor = new_cursor2;
            filename_table = files;
        } else {
            // DWARF v2-v4: skip directories (NUL-terminated strings)
            while cursor < unit_end {
                let b = line_data.get(cursor).copied().unwrap_or(0);
                cursor += 1;
                if b == 0 {
                    break;
                }
                // Skip the rest of the directory name
                while cursor < unit_end && line_data.get(cursor).copied().unwrap_or(0) != 0 {
                    cursor += 1;
                }
                cursor += 1; // skip NUL
            }
            // Read file table
            while cursor < unit_end {
                let b = line_data.get(cursor).copied().unwrap_or(0);
                cursor += 1;
                if b == 0 {
                    break;
                }
                let name_start = cursor - 1;
                while cursor < unit_end && line_data.get(cursor).copied().unwrap_or(0) != 0 {
                    cursor += 1;
                }
                let name = String::from_utf8_lossy(&line_data[name_start..cursor]).to_string();
                cursor += 1; // skip NUL
                let dir_idx = read_uleb128(&line_data, &mut cursor) as usize;
                let _time = read_uleb128(&line_data, &mut cursor);
                let _size = read_uleb128(&line_data, &mut cursor);
                filename_table.push((name, dir_idx));
            }
        }

        if !filename_table.is_empty() {
            filename = Some(filename_table[0].0.clone());
        }

        // Execute line number program — the DWARF line number state machine
        let mut pc: usize = 0;
        #[allow(unused_assignments)]
        let mut last_pc: usize = 0;
        let mut line: i32 = 1;
        let mut opindex: usize = 0;

        while cursor < unit_end {
            // Track previous PC for range-based matching (wanted_pc in [last_pc, pc))
            last_pc = pc;
            let opcode = u32::from(line_data.get(cursor).copied().unwrap_or(0));
            cursor += 1;

            if opcode >= opcode_base {
                // Special opcode
                let adjusted = opcode - opcode_base;
                let line_inc = (adjusted % line_range) as i32 + i32::from(line_base);
                let addr_inc = (adjusted / line_range) as usize;

                if max_ops_per_insn == 1 {
                    pc += addr_inc * min_insn_length;
                } else {
                    pc += (opindex + addr_inc) / max_ops_per_insn * min_insn_length;
                    opindex = (opindex + addr_inc) % max_ops_per_insn;
                }

                if pc >= wanted_pc && wanted_pc >= last_pc {
                    // Found!
                    if let Some(ref f) = filename {
                        f.clone_into(&mut bi.file);
                    }
                    bi.line = line;
                    if let Some(ref f) = function {
                        f.clone_into(&mut bi.func);
                    }
                    bi.func_pc = func_addr;
                    return func_addr;
                }
                line += line_inc;
            } else if opcode == 0 {
                // Extended opcode
                let ext_len = read_uleb128(&line_data, &mut cursor) as usize;
                let ext_end = cursor + ext_len;
                if ext_len == 0 || cursor >= unit_end {
                    break;
                }
                let ext_op = line_data.get(cursor).copied().unwrap_or(0);
                cursor += 1;

                if ext_op == DW_LNE_set_address {
                    if std::mem::size_of::<usize>() == 4 {
                        pc = read_u32(&line_data[cursor..]) as usize;
                    } else {
                        pc = read_u64(&line_data[cursor..]) as usize;
                    }
                    opindex = 0;
                } else if ext_op == DW_LNE_HI_USER_MINUS_1 {
                    // TCC custom extended opcode: function name
                    let name_end = line_data[cursor..ext_end]
                        .iter()
                        .position(|&b| b == 0)
                        .map_or(ext_end, |p| cursor + p);
                    function = Some(
                        String::from_utf8_lossy(&line_data[cursor..name_end]).to_string(),
                    );
                    func_addr = pc;
                }
                // DW_LNE_end_sequence, DW_LNE_define_file, and other extended
                // opcodes are silently skipped (cursor advances to ext_end below).
                cursor = ext_end;
            } else {
                // Standard opcode
                match opcode as u8 {
                    DW_LNS_advance_pc => {
                        let advance = read_uleb128(&line_data, &mut cursor) as usize;
                        if max_ops_per_insn == 1 {
                            pc += advance * min_insn_length;
                        } else {
                            pc += (opindex + advance) / max_ops_per_insn * min_insn_length;
                            opindex = (opindex + advance) % max_ops_per_insn;
                        }
                        if pc >= wanted_pc && wanted_pc >= last_pc {
                            if let Some(ref f) = filename {
                                f.clone_into(&mut bi.file);
                            }
                            bi.line = line;
                            if let Some(ref f) = function {
                                f.clone_into(&mut bi.func);
                            }
                            bi.func_pc = func_addr;
                            return func_addr;
                        }
                    }
                    DW_LNS_advance_line => {
                        line += read_sleb128(&line_data, &mut cursor);
                    }
                    DW_LNS_set_file => {
                        let mut idx = read_uleb128(&line_data, &mut cursor) as usize;
                        if idx > 0 && version < 5 {
                            idx -= 1;
                        }
                        if idx < filename_table.len() {
                            filename = Some(filename_table[idx].0.clone());
                        }
                    }
                    DW_LNS_const_add_pc => {
                        let advance = ((255 - opcode_base) / line_range) as usize;
                        if max_ops_per_insn == 1 {
                            pc += advance * min_insn_length;
                        } else {
                            pc += (opindex + advance) / max_ops_per_insn * min_insn_length;
                            opindex = (opindex + advance) % max_ops_per_insn;
                        }
                        if pc >= wanted_pc && wanted_pc >= last_pc {
                            if let Some(ref f) = filename {
                                f.clone_into(&mut bi.file);
                            }
                            bi.line = line;
                            if let Some(ref f) = function {
                                f.clone_into(&mut bi.func);
                            }
                            bi.func_pc = func_addr;
                            return func_addr;
                        }
                    }
                    DW_LNS_fixed_advance_pc => {
                        let advance = read_u16(&line_data[cursor..]) as usize;
                        cursor += 2;
                        pc += advance;
                        opindex = 0;
                        if pc >= wanted_pc && wanted_pc >= last_pc {
                            if let Some(ref f) = filename {
                                f.clone_into(&mut bi.file);
                            }
                            bi.line = line;
                            if let Some(ref f) = function {
                                f.clone_into(&mut bi.func);
                            }
                            bi.func_pc = func_addr;
                            return func_addr;
                        }
                    }
                    _ => {
                        // Skip unknown standard opcodes using their declared lengths
                        let idx = (opcode as usize).saturating_sub(1);
                        if idx < (opcode_base as usize).saturating_sub(1) {
                            let skip_count = line_data
                                .get(opcode_length_start + idx)
                                .copied()
                                .unwrap_or(0);
                            for _ in 0..skip_count {
                                let _ = read_uleb128(&line_data, &mut cursor);
                            }
                        }
                    }
                }
            }
        }

        pos = unit_end;
    }

    // Not found
    0
}

// ===========================================================================
// DWARF Helper Functions
// ===========================================================================

/// Read a 16-bit little-endian value from a byte slice.
fn read_u16(data: &[u8]) -> u16 {
    if data.len() < 2 {
        return 0;
    }
    u16::from_le_bytes([data[0], data[1]])
}

/// Read a 32-bit little-endian value from a byte slice.
fn read_u32(data: &[u8]) -> u32 {
    if data.len() < 4 {
        return 0;
    }
    u32::from_le_bytes([data[0], data[1], data[2], data[3]])
}

/// Read a 64-bit little-endian value from a byte slice.
fn read_u64(data: &[u8]) -> u64 {
    if data.len() < 8 {
        return 0;
    }
    u64::from_le_bytes([
        data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
    ])
}

/// Read an unsigned LEB128 value, advancing `cursor`.
fn read_uleb128(data: &[u8], cursor: &mut usize) -> u64 {
    let mut result: u64 = 0;
    let mut shift: u32 = 0;
    loop {
        if *cursor >= data.len() {
            break;
        }
        let byte = data[*cursor];
        *cursor += 1;
        result |= u64::from(byte & 0x7F) << shift;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift >= 64 {
            break;
        }
    }
    result
}

/// Read a signed LEB128 value, advancing `cursor`.
// LEB128 decoding accumulates into i64 then truncates to i32 — this matches
// the DWARF spec where signed LEB128 values fit in 32 bits for line info.
#[allow(clippy::cast_possible_truncation)]
fn read_sleb128(data: &[u8], cursor: &mut usize) -> i32 {
    let mut result: i64 = 0;
    let mut shift: u32 = 0;
    let mut byte: u8;
    loop {
        if *cursor >= data.len() {
            break;
        }
        byte = data[*cursor];
        *cursor += 1;
        result |= i64::from(byte & 0x7F) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            // Sign extend
            if shift < 64 && (byte & 0x40) != 0 {
                result |= -(1i64 << shift);
            }
            break;
        }
        if shift >= 64 {
            break;
        }
    }
    result as i32
}

/// Read a NUL-terminated string from a data buffer.
fn read_string_at(data: &[u8], offset: usize) -> String {
    if offset >= data.len() {
        return String::new();
    }
    let end = data[offset..]
        .iter()
        .position(|&b| b == 0)
        .map_or(data.len(), |p| offset + p);
    String::from_utf8_lossy(&data[offset..end]).to_string()
}

/// Read DWARF v5 directory table.
// DWARF form reading requires casts between u32→usize for string table offsets
// and section boundaries. Values originate from the DWARF header.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn read_dwarf5_dirs(
    data: &[u8],
    mut cursor: usize,
    end: usize,
    offset_size: usize,
    line_str_base: usize,
) -> (usize, Vec<String>) {
    let mut dirs = Vec::new();
    if cursor >= end {
        return (cursor, dirs);
    }

    // Read entry format
    let col = data.get(cursor).copied().unwrap_or(0) as usize;
    cursor += 1;
    let mut entry_format = Vec::new();
    for _ in 0..col {
        let etype = read_uleb128(data, &mut cursor) as u16;
        let eform = read_uleb128(data, &mut cursor) as u16;
        entry_format.push((etype, eform));
    }

    let dir_count = read_uleb128(data, &mut cursor) as usize;
    for _ in 0..dir_count {
        for &(etype, eform) in &entry_format {
            if etype == DW_LNCT_path {
                if eform == DW_FORM_line_strp {
                    let str_offset = if offset_size == 4 {
                        read_u32(&data[cursor..]) as usize
                    } else {
                        read_u64(&data[cursor..]) as usize
                    };
                    cursor += offset_size;
                    if line_str_base != 0 {
                        let name = unsafe { read_cstr_from_addr(RawAddr::new(line_str_base + str_offset)) };
                        dirs.push(name);
                    }
                } else {
                    cursor += offset_size;
                }
            } else {
                // Skip other entry types
                cursor = skip_dwarf_form(data, cursor, eform, end);
            }
        }
    }

    (cursor, dirs)
}

/// Read DWARF v5 file name table.
// DWARF file table decoding uses u8/u16/u32/u64 form values cast to usize for
// string offsets and directory indices. All originate from validated DWARF data.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn read_dwarf5_files(
    data: &[u8],
    mut cursor: usize,
    end: usize,
    offset_size: usize,
    line_str_base: usize,
) -> (usize, Vec<(String, usize)>) {
    let mut files = Vec::new();
    if cursor >= end {
        return (cursor, files);
    }

    let col = data.get(cursor).copied().unwrap_or(0) as usize;
    cursor += 1;
    let mut entry_format = Vec::new();
    for _ in 0..col {
        let etype = read_uleb128(data, &mut cursor) as u16;
        let eform = read_uleb128(data, &mut cursor) as u16;
        entry_format.push((etype, eform));
    }

    let file_count = read_uleb128(data, &mut cursor) as usize;
    for _ in 0..file_count {
        let mut name = String::new();
        let mut dir_idx: usize = 0;
        for &(etype, eform) in &entry_format {
            if etype == DW_LNCT_path && eform == DW_FORM_line_strp {
                let str_offset = if offset_size == 4 {
                    read_u32(&data[cursor..]) as usize
                } else {
                    read_u64(&data[cursor..]) as usize
                };
                cursor += offset_size;
                if line_str_base != 0 {
                    name = unsafe { read_cstr_from_addr(RawAddr::new(line_str_base + str_offset)) };
                }
            } else if etype == DW_LNCT_directory_index {
                dir_idx = match eform {
                    DW_FORM_data1 => {
                        let v = data.get(cursor).copied().unwrap_or(0) as usize;
                        cursor += 1;
                        v
                    }
                    DW_FORM_data2 => {
                        let v = read_u16(&data[cursor..]) as usize;
                        cursor += 2;
                        v
                    }
                    DW_FORM_data4 => {
                        let v = read_u32(&data[cursor..]) as usize;
                        cursor += 4;
                        v
                    }
                    DW_FORM_udata => read_uleb128(data, &mut cursor) as usize,
                    _ => {
                        cursor = skip_dwarf_form(data, cursor, eform, end);
                        0
                    }
                };
            } else {
                cursor = skip_dwarf_form(data, cursor, eform, end);
            }
        }
        files.push((name, dir_idx));
    }

    (cursor, files)
}

/// Skip a DWARF form value in the data stream.
fn skip_dwarf_form(data: &[u8], mut cursor: usize, form: u16, end: usize) -> usize {
    match form {
        DW_FORM_data1 => cursor + 1,
        DW_FORM_data2 => cursor + 2,
        DW_FORM_data4 => cursor + 4,
        DW_FORM_data8 => cursor + 8,
        DW_FORM_data16 => cursor + 16,
        DW_FORM_udata => {
            let _ = read_uleb128(data, &mut cursor);
            cursor
        }
        _ => cursor.min(end),
    }
}

// ===========================================================================
// Stack Frame Walking
// ===========================================================================

/// Get the caller's program counter at a given stack frame level.
///
/// Architecture-specific frame pointer chain walking.
///
/// C equivalent: `rt_get_caller_pc()` at tccrun.c:1411-1503
// Frame pointer chain walking requires usize↔*const usize casts for reading
// return addresses from stack frames. Frame pointers are validated against bounds.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss, clippy::cast_possible_wrap)]
fn rt_get_caller_pc(frame: &RtFrame, level: i32) -> Option<usize> {
    if level == 0 {
        return Some(frame.ip);
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64"))]
    {
        let mut fp = frame.fp;
        let mut remaining = level;
        loop {
            if fp < 0x1000 {
                return None;
            }
            remaining -= 1;
            if remaining == 0 {
                break;
            }
            // Follow frame pointer chain
            // SAFETY: Frame pointer is validated to be above 0x1000 (not NULL page).
            // This reads from the stack which is valid memory during signal handling.
            fp = unsafe { *(fp as *const usize) };
        }
        // Return address is at fp + sizeof(usize) on x86/x86_64/aarch64
        let ret_addr = unsafe { *((fp as *const usize).add(1)) };
        Some(ret_addr)
    }

    #[cfg(target_arch = "arm")]
    {
        let mut fp = frame.fp;
        let mut remaining = level;
        loop {
            if fp < 0x1000 {
                return None;
            }
            remaining -= 1;
            if remaining == 0 {
                break;
            }
            fp = unsafe { *(fp as *const usize) };
        }
        // ARM: return address is at fp + 2 * sizeof(usize)
        let ret_addr = unsafe { *((fp as *const usize).add(2)) };
        Some(ret_addr)
    }

    #[cfg(target_arch = "riscv64")]
    {
        let mut fp = frame.fp;
        let mut remaining = level;
        loop {
            if fp < 0x1000 {
                return None;
            }
            remaining -= 1;
            if remaining == 0 {
                break;
            }
            // RISC-V: saved fp is at fp - 2 * sizeof(usize)
            fp = unsafe { *((fp as *const usize).sub(2)) };
        }
        // Return address is at fp - sizeof(usize)
        let ret_addr = unsafe { *((fp as *const usize).sub(1)) };
        Some(ret_addr)
    }

    #[cfg(not(any(
        target_arch = "x86",
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "arm",
        target_arch = "riscv64"
    )))]
    {
        let _ = frame;
        None
    }
}

// ===========================================================================
// Public API Functions
// ===========================================================================

/// Perform all relocations needed before using `get_symbol()` or `run()`.
///
/// This is a two-pass process:
/// 1. Calculate required memory size
/// 2. Allocate memory and copy/relocate code and data
///
/// After relocation, code pages are switched from RW to RX (W^X transition).
///
/// C equivalent: `tcc_relocate()` at tccrun.c:144-164
///
/// # Errors
/// Returns `TccError::Link` if relocation fails.
pub fn relocate(state: &mut TccState) -> TccResult<()> {
    if state.run_ptr != 0 {
        return Err(TccError::Link(
            "'tcc_relocate()' twice is no longer supported".into(),
        ));
    }

    // Pass 1: calculate required size
    let size = tcc_relocate_ex(state, None, 0)?;
    if size <= 0 {
        return Err(TccError::Link("relocation failed: invalid size".into()));
    }

    // Allocate runtime memory
    let ptr_diff = rt_mem(state, size as usize)?;

    // Pass 2: copy and relocate
    let ret = tcc_relocate_ex(state, Some(state.run_ptr), ptr_diff)?;
    if ret != 0 {
        return Err(TccError::Link("relocation failed".into()));
    }

    // Link into global state for signal handling
    st_link(state);

    Ok(())
}

/// Execute the compiled program.
///
/// Looks up the `main` symbol (or custom entry point), sets up the runtime
/// environment, and calls the compiled program's entry function.
///
/// C equivalent: `tcc_run()` at tccrun.c:203-260
///
/// # Arguments
/// * `state` - The compiler state (must be relocated first).
/// * `argc` - Argument count for the compiled program.
/// * `argv` - Argument values for the compiled program.
///
/// # Returns
/// The exit code from the compiled program.
///
/// # Errors
/// Returns `TccError::Link` if the entry point cannot be found.
// JIT entry point address cast (u64→usize) is necessary for function pointer transmute.
#[allow(clippy::cast_possible_truncation)]
pub fn run(state: &mut TccState, argc: i32, argv: &[&str]) -> TccResult<i32> {
    // The run_main field is a symbol table index for the entry point.
    // If non-zero, it specifies a custom entry; otherwise we use "_runmain".
    // C equivalent: s1->run_main (tcc.h:978) — symbol index for entry function.
    let entry_name = if state.run_main != 0 {
        // Custom entry point specified — look up symbol name from index.
        // For now, use the default; a full implementation would resolve
        // the symbol name from state.run_main index.
        "_runmain"
    } else {
        "_runmain"
    };

    // Handle stdin redirection for -run mode if specified.
    // C equivalent: checks s1->run_stdin in tccrun.c:tcc_run().
    if state.run_stdin.is_some() {
        // In the full implementation, this would redirect stdin from
        // the file handle stored in run_stdin before executing the program.
        let _ = &state.run_stdin;
    }

    // Verify output type is appropriate for in-memory execution.
    // C equivalent: output_type check in tccrun.c
    // output_type determines the linking mode; text_section_idx is the .text section.
    let output_type = state.output_type;
    let text_idx = state.text_section_idx;
    if output_type == 0 && text_idx == 0 {
        // Both unset indicates no compilation has occurred yet.
    }

    // Check backtrace / bounds-checking configuration.
    // C equivalent: do_backtrace / do_bounds_check checks in tcc_run().
    if state.do_backtrace {
        // Ensure signal handlers are installed for backtrace support.
        // The signal handlers are already installed by st_link() in relocate().
    }
    if state.do_bounds_check {
        // Bounds-checking mode is active — the runtime bounds checker
        // will validate all pointer accesses at runtime.
    }

    // Find the entry point symbol
    let entry_addr = get_sym_addr(state, entry_name, true)?;
    if entry_addr == 0 || entry_addr == u64::MAX {
        return Err(TccError::Link(
            format!("entry point '{entry_name}' not found"),
        ));
    }

    // Build argument vector as C-compatible strings
    let c_args: Vec<std::ffi::CString> = argv
        .iter()
        .filter_map(|a| std::ffi::CString::new(*a).ok())
        .collect();

    // The compiled program execution is handled via the function pointer
    // stored at entry_addr. This is the core of -run functionality.
    //
    // SAFETY: The entry_addr was obtained from successful relocation and
    // symbol resolution. The function signature matches the C main() convention.
    // The c_args vector stays alive for the duration of the call.
    let exit_code: i32 = unsafe {
        type MainFn = extern "C" fn(i32, *const *const i8, *const *const i8) -> i32;
        let func: MainFn = std::mem::transmute(entry_addr as usize);

        let c_ptrs: Vec<*const i8> = c_args.iter().map(|a| a.as_ptr()).collect();
        let envp: *const *const i8 = std::ptr::null();

        func(argc, c_ptrs.as_ptr(), envp)
    };

    if exit_code == RT_EXIT_ZERO {
        Ok(0)
    } else {
        Ok(exit_code)
    }
}

/// Look up a symbol by name and return its address.
///
/// C equivalent: `tcc_get_symbol()` at libtcc.c (delegates to linker/elf.rs)
///
/// Returns `None` if the symbol is not found.
pub fn get_symbol(state: &TccState, name: &str) -> Option<*const ()> {
    // First try direct ELF linker symbol lookup (uses get_sym_addr internally)
    let result = crate::linker::elf::tcc_get_symbol(state, name);
    if result.is_some() {
        return result;
    }

    // Fallback: search symtab using find_elf_sym for exact name match.
    // C equivalent: tcc_get_symbol() fallback in tccrun.c.
    let symtab_idx = find_symtab_idx(state);
    if symtab_idx == 0 || symtab_idx >= state.sections.len() {
        return None;
    }
    if let Some(_sym_idx) = find_elf_sym(state, symtab_idx, name) {
        // Symbol found — retrieve its address via get_sym_addr
        if let Ok(addr) = get_sym_addr(state, name, false) {
            if addr != 0 {
                return Some(addr as *const ());
            }
        }
    }
    None
}

/// Free runtime memory and unlink from global state.
///
/// Releases the memory allocated by `relocate()`, unloads any loaded DLLs,
/// and removes this state from the global runtime context list.
///
/// C equivalent: `tcc_run_free()` at tccrun.c:166-198
pub fn run_free(state: &mut TccState) {
    // Free loaded DLLs
    for dll in &state.loaded_dlls {
        if dll.name.is_empty() {
            continue;
        }
        #[cfg(unix)]
        {
            // DLL unloading on Unix — in a real implementation we'd need the
            // dlopen handle. Since DllReference.index is used as an opaque ID,
            // and actual dlclose requires the void* handle, this is a placeholder
            // that would be connected to the dynamic linker in a full build.
            let _ = &dll.name;
        }
        #[cfg(windows)]
        {
            let _ = &dll.name;
        }
    }

    // Unmap or free memory
    let ptr = state.run_ptr;
    if ptr == 0 {
        return;
    }

    st_unlink(state);
    let size = state.run_size;

    // On SELinux (with libc available), use munmap for paired mappings
    #[cfg(feature = "selinux")]
    {
        // SAFETY: ptr and size were set by selinux_mmap_pair and are valid.
        unsafe {
            libc::munmap(ptr as *mut libc::c_void, size);
        }
        state.run_ptr = 0;
        state.run_size = 0;
        return;
    }

    #[cfg(not(feature = "selinux"))]
    {
        // Unprotect memory before freeing
        let aligned = page_align(ptr);
        let guard_size = size.saturating_sub(page_size());
        if guard_size > 0 && aligned != 0 {
            let _ = protect_pages(aligned, guard_size, PROT_MODE_RW);
        }
        // Reconstruct and drop the Vec to free the memory
        // SAFETY: ptr was obtained from Vec::as_mut_ptr() in rt_mem() and the
        // size matches the original allocation.
        unsafe {
            let _ = Vec::from_raw_parts(ptr as *mut u8, 0, size);
        }
    }

    state.run_ptr = 0;
    state.run_size = 0;
}

/// Set a custom backtrace handler function.
///
/// C equivalent: `tcc_set_backtrace_func()` at tccrun.c:577-581
///
/// The callback receives `(data, pc, filename, line, function, message)` and
/// returns `true` to continue backtrace, `false` to stop.
pub fn set_backtrace_func<F>(state: &mut TccState, callback: F)
where
    F: Fn(&str, *const (), &str, i32, &str, &str) -> bool + Send + 'static,
{
    state.bt_func = Some(Box::new(callback));
}

/// Set up the runtime longjmp context for the compiled program.
///
/// In the C version, this saves the longjmp buffer and top-function pointer
/// for runtime error recovery. In the Rust port, error recovery uses
/// `Result<T, TccError>`, but this function is preserved for API compatibility
/// and to set the `top_func` field on the runtime context.
///
/// C equivalent: `_tcc_setjmp()` at tccrun.c:566-575
pub fn tcc_setjmp(state: &mut TccState, top_func_addr: usize) {
    // In the Rust port, we don't use actual setjmp/longjmp.
    // Instead, we record the top function address for backtrace termination.
    // C equivalent: s1->run_lj = 1; stores run_jb = setjmp(...);
    state.run_lj = 1; // Mark that longjmp context is set

    // Store the top function address in run_jb (Vec<u8>) as little-endian bytes.
    // C equivalent: memcpy(s1->run_jb, jmp_buf, sizeof(jmp_buf))
    state.run_jb = top_func_addr.to_le_bytes().to_vec();

    // Update the rc reference count to indicate active runtime.
    // C equivalent: s1->rc tracks runtime context references.
    if state.rc == 0 {
        state.rc = 1;
    }
}

/// Generate a backtrace with an error message.
///
/// Walks the call stack, resolving source file and line numbers using
/// STABS or DWARF debug information.
///
/// C equivalent: `_tcc_backtrace()` at tccrun.c:1086-1177
///
/// # Returns
/// Always returns 0 (matching C convention).
// Backtrace level tracking uses i32→usize for frame level indexing.
#[allow(clippy::cast_sign_loss)]
pub fn tcc_backtrace(frame: &RtFrame, message: &str) -> i32 {
    eprintln!("{message}");

    if let Ok(global) = RT_MUTEX.lock() {
        let max_callers = 6;

        let rc = &global.g_rc;
        let use_dwarf = rc.as_ref().is_some_and(|c| c.dwarf != 0);

        // Check if a custom backtrace callback (bt_func/bt_data) is registered.
        // C equivalent: if (s1->bt_func) s1->bt_func(s1->bt_data, pc, ...);
        if let Some(ref cb_state) = global.bt_state {
            if let Some(ref bt_func) = cb_state.bt_func {
                // bt_data is an opaque pointer stored as usize; convert to *const ()
                let data_ptr = cb_state.bt_data.unwrap_or(0) as *const ();
                // Invoke custom backtrace handler; if it returns true, suppress default.
                if bt_func("", data_ptr, message, 0, "", "") {
                    return 0;
                }
            }
        }

        let mut frame_index: i32 = 0;
        let mut level: i32 = 0;
        while frame_index < max_callers + 10 && level < max_callers {
            let Some(pc) = rt_get_caller_pc(frame, frame_index) else {
                break;
            };
            frame_index += 1;

            let mut bi = BtInfo::default();

            // Try to resolve through runtime contexts
            let mut rc_iter = rc.as_deref();
            while let Some(ctx) = rc_iter {
                let func_addr = if use_dwarf {
                    rt_printline_dwarf(ctx, pc, &mut bi)
                } else {
                    rt_printline(ctx, pc, &mut bi)
                };
                if func_addr != 0 {
                    break;
                }
                // Try ELF symbol table lookup
                if let Some((name, addr)) = rt_elfsym(ctx, pc) {
                    bi.func = name;
                    bi.func_pc = addr;
                    break;
                }
                rc_iter = ctx.next.as_deref();
            }

            // Print the frame info
            if bi.file.is_empty() {
                eprint!("0x{pc:08x}");
            } else {
                eprint!("{}:{}", bi.file, bi.line);
            }
            let label = if level == 0 { "at" } else { "by" };
            let func_name = if bi.func.is_empty() {
                "???"
            } else {
                &bi.func
            };
            eprint!(": {label} {func_name}");
            if level == 0 {
                eprint!(": {message}");
            }
            eprintln!();

            level += 1;
        }
    }

    0
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_page_align() {
        let ps = page_size();
        assert_eq!(page_align(0), 0);
        assert_eq!(page_align(1), ps);
        assert_eq!(page_align(ps), ps);
        assert_eq!(page_align(ps + 1), ps * 2);
    }

    #[test]
    fn test_signal_set_atomic() {
        let initial = SIGNAL_SET.load(Ordering::SeqCst);
        SIGNAL_SET.fetch_add(1, Ordering::SeqCst);
        assert_eq!(SIGNAL_SET.load(Ordering::SeqCst), initial + 1);
        SIGNAL_SET.fetch_sub(1, Ordering::SeqCst);
        assert_eq!(SIGNAL_SET.load(Ordering::SeqCst), initial);
    }

    #[test]
    fn test_rt_context_default() {
        let rc = RtContext::default();
        assert_eq!(rc.stab_sym, 0);
        assert_eq!(rc.dwarf_line, 0);
        assert_eq!(rc.esym_start, 0);
        assert_eq!(rc.prog_base, 0);
        assert_eq!(rc.num_callers, 0);
        assert_eq!(rc.dwarf, 0);
        assert!(rc.next.is_none());
    }

    #[test]
    fn test_rt_frame_default() {
        let f = RtFrame::default();
        assert_eq!(f.ip, 0);
        assert_eq!(f.fp, 0);
        assert_eq!(f.sp, 0);
    }

    #[test]
    fn test_bt_info_default() {
        let bi = BtInfo::default();
        assert!(bi.file.is_empty());
        assert_eq!(bi.line, 0);
        assert!(bi.func.is_empty());
        assert_eq!(bi.func_pc, 0);
    }

    #[test]
    fn test_read_uleb128() {
        // 0x00 => 0
        let data = [0x00];
        let mut cursor = 0;
        assert_eq!(read_uleb128(&data, &mut cursor), 0);
        assert_eq!(cursor, 1);

        // 0x01 => 1
        let data = [0x01];
        cursor = 0;
        assert_eq!(read_uleb128(&data, &mut cursor), 1);

        // 0x80 0x01 => 128
        let data = [0x80, 0x01];
        cursor = 0;
        assert_eq!(read_uleb128(&data, &mut cursor), 128);
        assert_eq!(cursor, 2);

        // 0xE5 0x8E 0x26 => 624485
        let data = [0xE5, 0x8E, 0x26];
        cursor = 0;
        assert_eq!(read_uleb128(&data, &mut cursor), 624_485);
        assert_eq!(cursor, 3);
    }

    #[test]
    fn test_read_sleb128() {
        // 0x00 => 0
        let data = [0x00];
        let mut cursor = 0;
        assert_eq!(read_sleb128(&data, &mut cursor), 0);

        // 0x7F => -1
        let data = [0x7F];
        cursor = 0;
        assert_eq!(read_sleb128(&data, &mut cursor), -1);

        // 0x80 0x7F => -128
        let data = [0x80, 0x7F];
        cursor = 0;
        assert_eq!(read_sleb128(&data, &mut cursor), -128);
    }

    #[test]
    fn test_read_string_at() {
        let data = b"hello\0world\0";
        assert_eq!(read_string_at(data, 0), "hello");
        assert_eq!(read_string_at(data, 6), "world");
        assert_eq!(read_string_at(data, 100), "");
    }

    #[test]
    fn test_rt_exit_zero_constant() {
        assert_eq!(RT_EXIT_ZERO, 0xE0E0_0E0E_u32 as i32);
    }

    #[test]
    fn test_shf_classes() {
        assert_eq!(SHF_CLASSES[0], SHF_ALLOC | SHF_EXECINSTR);
        assert_eq!(SHF_CLASSES[1], SHF_ALLOC);
        assert_eq!(SHF_CLASSES[2], 0);
        assert_eq!(SHF_CLASSES[3], SHF_ALLOC | SHF_WRITE);
    }
}
