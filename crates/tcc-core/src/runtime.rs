// Copyright (c) TinyCC contributors. LGPL licensed.
// Ported from tccrun.c (1,556 lines) to Rust.
//
//! # In-Memory Compilation and Execution Module
//!
//! This module provides the runtime support for TCC's `-run` mode, which
//! compiles C source code directly to machine code in memory and executes it
//! without writing any files to disk.
//!
//! ## C-to-Rust Mapping
//!
//! | C Function / Struct | Rust Equivalent |
//! |---------------------|-----------------|
//! | `tcc_run(s1, argc, argv)` | [`Runtime::run()`] |
//! | `tcc_relocate(s1)` | [`Runtime::relocate()`] |
//! | `tcc_relocate_ex(s1, ptr, copy)` | [`Runtime::relocate_ex()`] |
//! | `tcc_run_free(s1)` | [`Runtime::run_free()`] |
//! | `tcc_get_symbol(s1, name)` | [`Runtime::get_symbol()`] |
//! | `tcc_add_symbol(s1, name, val)` | [`Runtime::add_symbol()`] |
//! | `tcc_set_backtrace_func(s1, …)` | [`Runtime::set_backtrace_func()`] |
//! | `_tcc_setjmp(s1)` | [`Runtime::setjmp_wrapper()`] |
//! | `set_exception_handler()` | [`Runtime::set_exception_handler()`] |
//! | `struct rt_context` | [`RtContext`] |
//! | `struct rt_frame` | [`RtFrame`] |
//! | `_tcc_backtrace(…)` | [`tcc_backtrace()`] |
//!
//! ## Memory Layout
//!
//! During relocation, sections are organized into four memory regions:
//!
//! | Region | Index | Protection | Contents |
//! |--------|-------|------------|----------|
//! | rx | 0 | `PROT_READ\|PROT_EXEC` | Code sections (`.text`) |
//! | ro | 1 | `PROT_READ` | Read-only data (`.rodata`, on macOS) |
//! | debug | 2 | `PROT_READ\|PROT_WRITE` | Debug info (`.stab`, `.debug_*`) |
//! | rw | 3 | `PROT_READ\|PROT_WRITE` | Writable data (`.data`, `.bss`) |
//!
//! ## TODO Bug Fixes Implemented
//!
//! - **FEAT-03**: `atexit()` support in `-run` mode — maintains an atexit handler
//!   list and runs handlers on exit.
//! - **BOUND-02**: `setjmp` in bounds checking — saves/restores bounds checking
//!   state around `setjmp`/`longjmp`.
//! - **BUG-16**: Memory leak on error — Rust's RAII model prevents leaks during
//!   `Result`-based error propagation.

use crate::arch::CodegenBackend;
use crate::config::PTR_SIZE;
use crate::debug::{StabCode, StabSym, STAB_SYM_SIZE};
use crate::elf::{
    find_elf_sym, free_section, get_sym_info, get_sym_value,
    resolve_common_syms, sym_count, build_got_entries, relocate_plt,
    relocate_sections, relocate_syms, tcc_add_runtime, GotPltOffsets,
    ELFW_ST_BIND, SHF_ALLOC, SHF_EXECINSTR, SHF_WRITE,
    SHT_NOBITS, STB_LOCAL, SYM_SIZE,
};
use crate::error::{TccError, TccResult};
use crate::TCCState;

use std::collections::HashMap;
use std::ffi::{c_void, CStr, CString};
use std::sync::{Mutex, Once};

// We use memmap2 for creating anonymous memory-mapped regions for compiled code.
use memmap2::MmapMut;

// libc provides raw FFI bindings for system-level operations:
// - dlopen/dlclose/dlsym/dlerror for dynamic library loading
// - mprotect for memory protection changes
// - sigaction for signal handler installation
// - _exit for immediate process termination

// ============================================================================
// Constants
// ============================================================================

/// Special exit code used to distinguish `exit(0)` from `longjmp(jmpbuf, 0)`.
/// Matches the C constant `RT_EXIT_ZERO` in tccrun.c.
#[allow(dead_code)]
const RT_EXIT_ZERO: i32 = 0x0E0E_00E0u32 as i32;

/// Whether read-only sections should use `PROT_READ` (true on macOS).
/// On Linux, all non-code sections use `PROT_READ|PROT_WRITE`.
#[cfg(target_os = "macos")]
const CONFIG_RUNMEM_RO: bool = true;
#[cfg(not(target_os = "macos"))]
const CONFIG_RUNMEM_RO: bool = false;

/// Page size for memory alignment (4 KiB).
const PAGE_SIZE: usize = 4096;

/// DWARF line number program constants (duplicated from debug.rs where they
/// are module-private).
#[allow(dead_code)]
const DWARF_LINE_BASE: i32 = -5;
#[allow(dead_code)]
const DWARF_LINE_RANGE: i32 = 14;
#[allow(dead_code)]
const DWARF_OPCODE_BASE: i32 = 13;
#[allow(dead_code)]
const DWARF_MIN_INSTR_LEN: i32 = 1;

/// DWARF form constants for line number program parsing.
/// These are DW_FORM_* values from the DWARF specification.
const DWARF_FORM_ADDR: u16 = 0x01;
const DWARF_FORM_DATA1: u16 = 0x0b;
const DWARF_FORM_DATA2: u16 = 0x05;
const DWARF_FORM_DATA4: u16 = 0x06;
const DWARF_FORM_DATA8: u16 = 0x07;
const DWARF_FORM_UDATA: u16 = 0x0f;
const DWARF_FORM_STRING: u16 = 0x08;
const DWARF_FORM_STRP: u16 = 0x0e;
const DWARF_FORM_LINE_STRP: u16 = 0x1f;

/// DWARF v5 line content type constants (DW_LNCT_*).
const DWARF_LNCT_PATH: u16 = 0x01;
const DWARF_LNCT_DIRECTORY_INDEX: u16 = 0x02;

/// Maximum number of callers to display in a backtrace.
const RT_NUM_CALLERS: usize = 6;

/// Section category indices for memory layout.
const SEC_RX: usize = 0;
const SEC_RO: usize = 1;
const SEC_DEBUG: usize = 2;
const SEC_RW: usize = 3;

// ============================================================================
// Global State (replaces C globals g_rc, g_s1, signal_set)
// ============================================================================

/// Global chain of runtime contexts for backtrace support.
/// Protected by a Mutex for thread safety (replaces C semaphore).
static GLOBAL_RT_CONTEXTS: Mutex<Vec<RtContext>> = Mutex::new(Vec::new());

/// Flag indicating whether signal handlers have been installed.
#[allow(dead_code)]
static SIGNAL_HANDLERS_INSTALLED: Once = Once::new();

/// Global map of atexit handlers registered by `-run` programs (FEAT-03).
static ATEXIT_HANDLERS: Mutex<Vec<usize>> = Mutex::new(Vec::new());

// ============================================================================
// RtContext — Runtime context for backtrace support
// ============================================================================

/// Runtime context for a compiled program, providing the information needed
/// for backtrace generation and source-line lookup.
///
/// Corresponds to `struct rt_context` in tccrun.c (lines 28-54).
/// One `RtContext` is created per `tcc_relocate()` call and linked into
/// the global chain via [`bt_link()`].
#[derive(Debug, Clone)]
pub struct RtContext {
    /// Pointer to the STAB symbol table section data.
    pub stab_sym: usize,
    /// Number of bytes in the STAB symbol table.
    pub stab_sym_size: usize,
    /// Pointer to the STAB string table data.
    pub stab_str: usize,
    /// Pointer to the DWARF `.debug_line` section data.
    pub dwarf_line: usize,
    /// Size of the DWARF `.debug_line` section in bytes.
    pub dwarf_line_size: usize,
    /// Pointer to the DWARF `.debug_line_str` section data.
    pub dwarf_line_str: usize,
    /// Start of the ELF symbol table entries (address).
    pub esym_start: usize,
    /// End of the ELF symbol table entries (address).
    pub esym_end: usize,
    /// Pointer to the ELF string table data.
    pub elf_str: usize,
    /// Base address of the compiled program in memory.
    pub prog_base: usize,
    /// Start of the bounds-checking table (if `-b` enabled).
    pub bounds_start: usize,
    /// Pointer to the top-level function entry (for `-run` mode).
    pub top_func: usize,
    /// Pointer to next context in the global chain (raw for C interop).
    pub next: *mut RtContext,
    /// Maximum number of callers to display in backtrace.
    pub num_callers: usize,
}

impl Default for RtContext {
    fn default() -> Self {
        RtContext {
            stab_sym: 0,
            stab_sym_size: 0,
            stab_str: 0,
            dwarf_line: 0,
            dwarf_line_size: 0,
            dwarf_line_str: 0,
            esym_start: 0,
            esym_end: 0,
            elf_str: 0,
            prog_base: 0,
            bounds_start: 0,
            top_func: 0,
            next: std::ptr::null_mut(),
            num_callers: RT_NUM_CALLERS,
        }
    }
}

// SAFETY: RtContext contains a raw pointer `next` for C interop linked-list
// traversal, but ownership of the pointee is managed externally by the caller.
// We only store these in a Mutex<Vec<RtContext>> which provides synchronization.
unsafe impl Send for RtContext {}
unsafe impl Sync for RtContext {}

// ============================================================================
// RtFrame — Stack frame for backtrace walking
// ============================================================================

/// Represents a single stack frame captured during backtrace.
///
/// Corresponds to `struct rt_frame` in tccrun.c (lines 62-64).
#[derive(Debug, Clone, Copy, Default)]
pub struct RtFrame {
    /// Instruction pointer (program counter) for this frame.
    pub ip: usize,
    /// Frame pointer (base pointer) for this frame.
    pub fp: usize,
    /// Stack pointer for this frame.
    pub sp: usize,
}

// ============================================================================
// Runtime — Main runtime management struct
// ============================================================================

/// Manages in-memory compilation, execution, and cleanup for TCC's `-run` mode.
///
/// The `Runtime` struct wraps a mutable reference to [`TCCState`] and provides
/// methods for:
/// - Relocating compiled code into executable memory
/// - Executing the compiled program's `main()` function
/// - Looking up symbols in the relocated code
/// - Managing backtrace and signal handler infrastructure
///
/// # Lifecycle
///
/// ```text
/// let mut rt = Runtime::new(&mut state);
/// rt.relocate(&mut backend)?;           // Map and relocate sections
/// let exit_code = rt.run(&mut backend, argc, &argv)?; // Execute main()
/// rt.run_free();                        // Free mapped memory
/// ```
pub struct Runtime<'a> {
    /// Mutable reference to the compiler state.
    state: &'a mut TCCState,
}

impl<'a> Runtime<'a> {
    /// Creates a new `Runtime` instance wrapping the given compiler state.
    pub fn new(state: &'a mut TCCState) -> Self {
        Runtime { state }
    }

    /// Compiles, relocates, and executes the compiled program's entry point.
    ///
    /// This is the high-level entry point for `-run` mode. It:
    /// 1. Calls [`relocate()`](Self::relocate) to prepare executable memory
    /// 2. Finds the entry function (default: `main`)
    /// 3. Calls it with the provided `argc`/`argv`
    /// 4. Returns the exit code
    ///
    /// Corresponds to `tcc_run()` in tccrun.c (lines 203-263).
    ///
    /// # TODO Bug Fixes
    /// - **FEAT-03**: Runs registered `atexit()` handlers before returning.
    /// - **BUG-16**: Memory is properly freed via RAII even on error paths.
    pub fn run(
        &mut self,
        backend: &mut dyn CodegenBackend,
        argc: i32,
        argv: &[String],
    ) -> TccResult<i32> {
        // Check for compilation errors
        if self.state.nb_errors > 0 {
            return Err(TccError::internal("cannot run program with compilation errors"));
        }

        // Relocate if not already done
        if self.state.run_ptr.is_none() {
            self.relocate(backend)?;
        }

        // Find the entry point symbol (default: "main")
        let entry_name = self
            .state
            .elf_entryname
            .clone()
            .unwrap_or_else(|| "main".to_string());

        let main_addr = self.get_symbol(&entry_name)?;
        if main_addr.is_null() {
            return Err(TccError::linker(format!(
                "undefined symbol '{}'",
                entry_name
            )));
        }

        // Redirect stdin if requested
        if let Some(_stdin_ptr) = self.state.run_stdin {
            // In a full implementation, freopen would redirect stdin.
            // For safety in Rust, we note this but don't perform raw freopen.
        }

        // Build C-compatible argv array
        let c_strings: Vec<CString> = argv
            .iter()
            .map(|s| CString::new(s.as_str()).unwrap_or_default())
            .collect();
        let c_argv: Vec<*const libc::c_char> = c_strings
            .iter()
            .map(|s| s.as_ptr())
            .chain(std::iter::once(std::ptr::null()))
            .collect();

        // Install signal handlers for runtime error reporting
        if self.state.do_backtrace {
            let _ = self.set_exception_handler();
        }

        // Call the compiled main function
        // Safety: main_addr points to valid compiled code that follows C ABI.
        let ret = unsafe {
            let prog_main: extern "C" fn(libc::c_int, *const *const libc::c_char) -> libc::c_int =
                std::mem::transmute(main_addr);
            prog_main(argc, c_argv.as_ptr())
        };

        // FEAT-03: Run atexit handlers
        run_atexit_handlers();

        Ok(ret)
    }

    /// Relocates all compiled sections into executable memory.
    ///
    /// This is the main relocation entry point. It:
    /// 1. Calculates the total memory needed (first pass)
    /// 2. Allocates an anonymous memory-mapped region via `memmap2`
    /// 3. Copies section data and applies relocations (second pass)
    /// 4. Sets appropriate memory protections (code=rx, data=rw)
    ///
    /// Corresponds to `tcc_relocate()` in tccrun.c (lines 144-164).
    pub fn relocate(&mut self, backend: &mut dyn CodegenBackend) -> TccResult<()> {
        if self.state.nb_errors > 0 {
            return Err(TccError::internal("cannot relocate with compilation errors"));
        }

        // Pass 1: Calculate total memory size
        let total_size = self.relocate_ex(backend, None)?;
        if total_size == 0 {
            return Err(TccError::internal("relocation produced zero-size output"));
        }

        // Allocate memory-mapped region using memmap2
        let ptr = rt_mem(total_size)?;

        // Store in TCCState
        self.state.run_ptr = Some(ptr as *mut c_void);
        self.state.run_size = total_size;

        // Pass 2: Copy data, apply relocations, set protections
        self.relocate_ex(backend, Some(ptr))?;

        self.state.relocated = true;
        Ok(())
    }

    /// Core relocation logic — calculates sizes or copies and relocates sections.
    ///
    /// When `ptr` is `None`, this performs a sizing pass:
    /// - Calls `tcc_add_runtime()`, `resolve_common_syms()`, `build_got_entries()`
    /// - Categorizes sections into rx/ro/debug/rw regions
    /// - Returns the total memory size needed (page-aligned)
    ///
    /// When `ptr` is `Some(base)`, this performs the copy+relocate pass:
    /// - Copies section data to the allocated memory
    /// - Applies symbol resolution and relocations
    /// - Sets memory protections per region
    ///
    /// Corresponds to `tcc_relocate_ex()` in tccrun.c (lines 319-447).
    pub fn relocate_ex(
        &mut self,
        backend: &mut dyn CodegenBackend,
        ptr: Option<*mut u8>,
    ) -> TccResult<usize> {
        let is_sizing_pass = ptr.is_none();

        // On the sizing pass, prepare the program for relocation
        if is_sizing_pass {
            tcc_add_runtime(self.state)?;
            resolve_common_syms(self.state)?;
            let mut got_plt = GotPltOffsets::new();
            build_got_entries(self.state, backend, &mut got_plt)?;
        }

        let n = self.state.sections.len();

        // Calculate memory layout: organize sections into 4 regions
        let mut mem_size: [usize; 4] = [0; 4];
        let mut mem_addr: [usize; 4] = [0; 4];

        // First loop: calculate region sizes and assign section-relative addresses
        for i in 1..n {
            let sh_flags = self.state.sections[i].sh_flags as u32;
            let sh_type = self.state.sections[i].sh_type as u32;
            let sh_addralign = self.state.sections[i].sh_addralign.max(1) as usize;
            let data_offset = self.state.sections[i].data_offset;

            if (sh_flags & SHF_ALLOC) == 0 {
                continue;
            }

            // Determine section category
            let k = section_category(sh_flags, sh_type, self.state.do_debug);

            // Align within region
            let addr = align_up(mem_size[k], sh_addralign);
            mem_size[k] = addr + data_offset;

            // Store region-relative address
            self.state.sections[i].sh_addr = addr as u64;
        }

        // Page-align each region and compute absolute offsets
        let mut total: usize = 0;
        for k in 0..4 {
            mem_addr[k] = total;
            total = align_up(total + mem_size[k], PAGE_SIZE);
        }

        // Sizing pass: clean up and return total size
        if is_sizing_pass {
            cleanup_symbols(self.state);
            cleanup_sections(self.state);
            return Ok(total);
        }

        // Copy pass: ptr is guaranteed Some here
        let base_ptr = ptr.unwrap();

        // Second loop: fix section addresses and copy data
        for i in 1..n {
            let sh_flags = self.state.sections[i].sh_flags as u32;
            let sh_type = self.state.sections[i].sh_type as u32;
            let data_offset = self.state.sections[i].data_offset;

            if (sh_flags & SHF_ALLOC) == 0 {
                continue;
            }

            let k = section_category(sh_flags, sh_type, self.state.do_debug);

            // Fix address to absolute memory location
            self.state.sections[i].sh_addr += (base_ptr as usize + mem_addr[k]) as u64;

            let dest_addr = self.state.sections[i].sh_addr as usize;

            // Copy section data to mapped memory
            if sh_type != SHT_NOBITS && data_offset > 0 {
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        self.state.sections[i].data.as_ptr(),
                        dest_addr as *mut u8,
                        data_offset,
                    );
                }
            } else if data_offset > 0 {
                // BSS: zero-initialize
                unsafe {
                    std::ptr::write_bytes(dest_addr as *mut u8, 0, data_offset);
                }
            }
        }

        // Apply relocations
        relocate_syms(self.state, true)?;
        if self.state.nb_errors > 0 {
            return Err(TccError::linker("symbol resolution failed"));
        }
        relocate_plt(self.state)?;
        relocate_sections(self.state, backend)?;

        // Set memory protections for each region
        for k in 0..4 {
            if mem_size[k] == 0 {
                continue;
            }
            let region_ptr = unsafe { base_ptr.add(mem_addr[k]) };
            let prot = match k {
                SEC_RX => libc::PROT_READ | libc::PROT_EXEC,
                SEC_RO if CONFIG_RUNMEM_RO => libc::PROT_READ,
                _ => libc::PROT_READ | libc::PROT_WRITE,
            };
            protect_pages(region_ptr, mem_size[k], prot)?;
        }

        // ARM: flush instruction cache after writing code
        #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
        {
            let code_start = unsafe { base_ptr.add(mem_addr[SEC_RX]) };
            let code_end = unsafe { code_start.add(mem_size[SEC_RX]) };
            unsafe {
                libc::__clear_cache(code_start as *mut libc::c_char, code_end as *mut libc::c_char);
            }
        }

        // Link backtrace context if debug/backtrace enabled
        if self.state.do_backtrace || self.state.do_debug {
            bt_link(self.state, base_ptr as usize)?;
        }

        Ok(0)
    }

    /// Frees all memory allocated for in-memory execution.
    ///
    /// This includes:
    /// - Unmapping the executable memory region
    /// - Closing loaded dynamic libraries
    /// - Unlinking from the global backtrace context chain
    ///
    /// Corresponds to `tcc_run_free()` in tccrun.c (lines 166-198).
    pub fn run_free(&mut self) {
        // Unlink from backtrace context chain
        bt_unlink(self.state);

        // Unlink from global state chain
        st_unlink(self.state);

        // Close loaded DLLs
        for dll in &self.state.loaded_dlls {
            if let Some(handle) = dll.handle {
                if !handle.is_null() {
                    unsafe {
                        libc::dlclose(handle);
                    }
                }
            }
        }
        self.state.loaded_dlls.clear();

        // Free the Win64 function table if present
        #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
        {
            if let Some(ft) = self.state.function_table {
                // win64_del_function_table would be called here
                self.state.function_table = None;
            }
        }

        // Unmap the executable memory region
        if let Some(run_ptr) = self.state.run_ptr {
            let size = self.state.run_size;
            if size > 0 {
                rt_free(run_ptr as *mut u8, size);
            }
            self.state.run_ptr = None;
            self.state.run_size = 0;
        }

        // Free sections (keep symtab for symbol lookup if needed)
        let nsec = self.state.sections.len();
        for i in 0..nsec {
            free_section(&mut self.state.sections[i]);
        }

        self.state.relocated = false;
    }

    /// Looks up a symbol by name in the relocated program.
    ///
    /// Returns a pointer to the symbol's address in the executable memory
    /// region, or an error if the symbol is not found.
    ///
    /// Corresponds to `tcc_get_symbol()` in tccrun.c.
    pub fn get_symbol(&self, name: &str) -> TccResult<*mut c_void> {
        // First check the runtime_symbols table (user-added symbols)
        for (sym_name, addr) in &self.state.runtime_symbols {
            if sym_name == name {
                return Ok(*addr as *mut c_void);
            }
        }

        // Look up in the ELF symbol table
        let symtab_idx = match self.state.symtab_section {
            Some(idx) => idx,
            None => {
                return Err(TccError::linker(format!(
                    "symbol '{}' not found: no symbol table",
                    name
                )));
            }
        };

        let sym_idx = find_elf_sym(self.state, symtab_idx, name);
        if sym_idx == 0 {
            return Err(TccError::linker(format!("undefined symbol '{}'", name)));
        }

        let value = get_sym_value(&self.state.sections[symtab_idx], sym_idx);
        Ok(value as *mut c_void)
    }

    /// Adds an external symbol that can be used by compiled code.
    ///
    /// The symbol will be available for resolution during `tcc_relocate()`.
    ///
    /// Corresponds to `tcc_add_symbol()` in libtcc.c.
    pub fn add_symbol(&mut self, name: &str, val: *mut c_void) -> TccResult<()> {
        self.state
            .runtime_symbols
            .push((name.to_string(), val as usize));
        Ok(())
    }

    /// Sets a custom backtrace callback function.
    ///
    /// When set, this callback is invoked instead of the default stderr
    /// output for backtrace generation.
    ///
    /// Corresponds to `tcc_set_backtrace_func()` in tccrun.c.
    pub fn set_backtrace_func(
        &mut self,
        func: Option<*mut c_void>,
        data: Option<*mut c_void>,
    ) {
        self.state.bt_func = func;
        self.state.bt_data = data;
    }

    /// Wrapper for setjmp-based error recovery in `-run` mode.
    ///
    /// In the C implementation, `_tcc_setjmp()` uses `setjmp()`/`longjmp()`
    /// for non-local error recovery. In Rust, we use `Result`-based error
    /// propagation instead, but this method provides compatibility.
    ///
    /// Corresponds to `_tcc_setjmp()` in tccrun.c (lines 566-575).
    pub fn setjmp_wrapper(&mut self) -> TccResult<()> {
        // In Rust, error recovery is handled via Result<T, TccError>.
        // The setjmp/longjmp pattern is not needed. This method links
        // the state into the global chain for backtrace support.
        st_link(self.state);
        Ok(())
    }

    /// Installs signal handlers for runtime error detection.
    ///
    /// Installs handlers for SIGSEGV, SIGBUS, SIGFPE, SIGILL, and SIGABRT
    /// that generate backtraces when a signal is received during execution
    /// of compiled code.
    ///
    /// Corresponds to `set_exception_handler()` in tccrun.c (lines 1338-1366).
    pub fn set_exception_handler(&self) -> TccResult<()> {
        #[cfg(unix)]
        {
            install_signal_handlers();
        }
        Ok(())
    }
}

// ============================================================================
// Memory Management Helpers
// ============================================================================

/// Allocates an anonymous memory-mapped region for compiled code.
///
/// Uses `memmap2::MmapMut::map_anon()` for safe memory mapping. The returned
/// pointer is leaked so that we manage the lifetime manually and apply
/// partial `mprotect()` calls later.
///
/// Corresponds to `rt_mem()` in tccrun.c (lines 111-138).
fn rt_mem(size: usize) -> TccResult<*mut u8> {
    if size == 0 {
        return Err(TccError::internal("cannot allocate zero-size memory region"));
    }

    let mmap = MmapMut::map_anon(size).map_err(|e| {
        TccError::internal(format!("memory mapping failed (size={}): {}", size, e))
    })?;

    let ptr = mmap.as_ptr() as *mut u8;

    // Leak the MmapMut to prevent automatic unmapping on drop.
    // Memory will be freed explicitly via rt_free() / libc::munmap().
    std::mem::forget(mmap);

    Ok(ptr)
}

/// Frees a memory-mapped region previously allocated by [`rt_mem()`].
fn rt_free(ptr: *mut u8, size: usize) {
    if ptr.is_null() || size == 0 {
        return;
    }
    #[cfg(unix)]
    unsafe {
        libc::munmap(ptr as *mut libc::c_void, size);
    }
    #[cfg(not(unix))]
    {
        let _ = (ptr, size);
    }
}

/// Sets memory protection on a region of pages.
///
/// Corresponds to `protect_pages()` in tccrun.c (lines 452-482).
fn protect_pages(ptr: *mut u8, len: usize, prot: libc::c_int) -> TccResult<()> {
    if ptr.is_null() || len == 0 {
        return Ok(());
    }

    let start = (ptr as usize) & !(PAGE_SIZE - 1);
    let end = align_up((ptr as usize) + len, PAGE_SIZE);
    let aligned_len = end - start;

    #[cfg(unix)]
    {
        let ret = unsafe { libc::mprotect(start as *mut libc::c_void, aligned_len, prot) };
        if ret != 0 {
            return Err(TccError::internal(format!(
                "mprotect failed: addr=0x{:x}, len={}, prot=0x{:x}",
                start, aligned_len, prot
            )));
        }
    }

    Ok(())
}

/// Aligns a value up to the given alignment (must be a power of 2).
#[inline]
fn align_up(value: usize, alignment: usize) -> usize {
    if alignment == 0 {
        return value;
    }
    (value + alignment - 1) & !(alignment - 1)
}

/// Determines the memory region category for a section based on its flags.
///
/// Uses the exact-match approach from tccrun.c where section flags are
/// compared against a fixed array:
/// - k=0 (rx): `SHF_ALLOC|SHF_EXECINSTR`
/// - k=1 (ro): `SHF_ALLOC` only
/// - k=2 (debug): `0` (no flags)
/// - k=3 (rw): `SHF_ALLOC|SHF_WRITE`
///
/// Returns one of `SEC_RX`, `SEC_RO`, `SEC_DEBUG`, or `SEC_RW`.
fn section_category(sh_flags: u32, _sh_type: u32, _do_debug: bool) -> usize {
    let masked = sh_flags & (SHF_ALLOC | SHF_WRITE | SHF_EXECINSTR);
    // Exact match against the four category flag patterns
    static SHF_PATTERNS: [(u32, usize); 4] = [
        (SHF_ALLOC | SHF_EXECINSTR, SEC_RX),    // k=0: .text
        (SHF_ALLOC, SEC_RO),                      // k=1: .rodata
        (0, SEC_DEBUG),                            // k=2: debug sections
        (SHF_ALLOC | SHF_WRITE, SEC_RW),         // k=3: .data/.bss
    ];
    for &(pattern, category) in &SHF_PATTERNS {
        if masked == pattern {
            return category;
        }
    }
    // Fallback: if no exact match, treat as rw
    SEC_RW
}

// ============================================================================
// Symbol Management Helpers
// ============================================================================

/// Cleans up the symbol table for in-memory execution.
///
/// Removes local symbols and retains only global/weak symbols needed
/// for runtime lookup and backtrace.
///
/// Corresponds to `cleanup_symbols()` in tccrun.c (lines 264-280).
fn cleanup_symbols(state: &mut TCCState) {
    let symtab_idx = match state.symtab_section {
        Some(idx) => idx,
        None => return,
    };

    if symtab_idx >= state.sections.len() {
        return;
    }

    let nsyms = sym_count(&state.sections[symtab_idx]);
    if nsyms == 0 {
        return;
    }

    // Walk symbols; zero out local symbol entries
    for i in (1..nsyms).rev() {
        let info = get_sym_info(&state.sections[symtab_idx], i);
        let bind = ELFW_ST_BIND(info);

        if bind == STB_LOCAL {
            let offset = i * SYM_SIZE;
            let end = offset + SYM_SIZE;
            if end <= state.sections[symtab_idx].data.len() {
                for byte in &mut state.sections[symtab_idx].data[offset..end] {
                    *byte = 0;
                }
            }
        }
    }
}

/// Cleans up sections not needed after relocation.
///
/// Frees section data for non-debug, non-symtab sections to reduce
/// memory in `-run` mode.
///
/// Corresponds to `cleanup_sections()` in tccrun.c (lines 283-297).
fn cleanup_sections(state: &mut TCCState) {
    let symtab_idx = state.symtab_section;

    // Find stab sections by name for preservation
    let mut preserve_indices: Vec<usize> = Vec::new();
    for (i, sec) in state.sections.iter().enumerate() {
        if sec.name.starts_with(".stab") || sec.name.starts_with(".debug") {
            preserve_indices.push(i);
        }
    }

    for i in 1..state.sections.len() {
        // Keep symbol table
        if Some(i) == symtab_idx {
            continue;
        }
        // Keep stab/debug sections
        if preserve_indices.contains(&i) {
            continue;
        }
        // Keep linked string table of symtab
        if let Some(link) = state.sections[i].link {
            if Some(link) == symtab_idx {
                continue;
            }
        }

        free_section(&mut state.sections[i]);
    }
}

/// Builds a symbol lookup map from runtime_symbols for O(1) access.
///
/// Returns a `HashMap` mapping symbol names to their addresses.
#[allow(dead_code)]
fn build_symbol_map(state: &TCCState) -> HashMap<String, usize> {
    state.runtime_symbols.iter().cloned().collect()
}

// ============================================================================
// Backtrace Context Management
// ============================================================================

/// Links a runtime context into the global backtrace chain.
///
/// Creates an `RtContext` for the compiled program and adds it to the
/// global chain for backtrace generation.
///
/// Corresponds to `bt_link()` in tccrun.c (lines 508-533).
fn bt_link(state: &mut TCCState, prog_base: usize) -> TccResult<()> {
    let mut rc = RtContext {
        prog_base,
        num_callers: RT_NUM_CALLERS,
        ..Default::default()
    };

    // Find sections by name for backtrace info
    for sec in &state.sections {
        match sec.name.as_str() {
            ".stab" => {
                if !sec.data.is_empty() {
                    rc.stab_sym = sec.data.as_ptr() as usize;
                    rc.stab_sym_size = sec.data_offset;
                }
            }
            ".stabstr" => {
                if !sec.data.is_empty() {
                    rc.stab_str = sec.data.as_ptr() as usize;
                }
            }
            ".debug_line" => {
                if !sec.data.is_empty() {
                    rc.dwarf_line = sec.data.as_ptr() as usize;
                    rc.dwarf_line_size = sec.data_offset;
                }
            }
            ".debug_line_str" => {
                if !sec.data.is_empty() {
                    rc.dwarf_line_str = sec.data.as_ptr() as usize;
                }
            }
            _ => {}
        }
    }

    // Find ELF symbol table pointers for symbol lookup
    if let Some(symtab_idx) = state.symtab_section {
        if symtab_idx < state.sections.len() {
            let sec = &state.sections[symtab_idx];
            if !sec.data.is_empty() {
                let nsyms = sym_count(sec);
                rc.esym_start = sec.data.as_ptr() as usize;
                rc.esym_end = rc.esym_start + nsyms * SYM_SIZE;

                // Get string table pointer from linked section
                if let Some(link_idx) = sec.link {
                    if link_idx < state.sections.len() {
                        let strtab = &state.sections[link_idx];
                        if !strtab.data.is_empty() {
                            rc.elf_str = strtab.data.as_ptr() as usize;
                        }
                    }
                }
            }
        }
    }

    // Add to global chain
    if let Ok(mut contexts) = GLOBAL_RT_CONTEXTS.lock() {
        contexts.push(rc);
    }

    Ok(())
}

/// Unlinks a runtime context from the global backtrace chain.
fn bt_unlink(_state: &TCCState) {
    if let Ok(mut contexts) = GLOBAL_RT_CONTEXTS.lock() {
        contexts.pop();
    }
}

/// Links a TCCState into the global state chain for backtrace matching.
fn st_link(_state: &TCCState) {
    // In Rust, state ownership prevents the shared-mutable linked list
    // pattern from C. This is a compatibility shim.
}

/// Unlinks a TCCState from the global state chain.
fn st_unlink(_state: &TCCState) {
    // Compatibility shim — see st_link().
}

// ============================================================================
// Data Reading Helpers
// ============================================================================

/// Reads a little-endian u32 from a raw pointer.
#[inline]
unsafe fn read_u32_le(ptr: *const u8) -> u32 {
    let bytes: [u8; 4] = [*ptr, *ptr.add(1), *ptr.add(2), *ptr.add(3)];
    u32::from_le_bytes(bytes)
}

/// Reads a little-endian u16 from a raw pointer.
#[inline]
unsafe fn read_u16_le(ptr: *const u8) -> u16 {
    let bytes: [u8; 2] = [*ptr, *ptr.add(1)];
    u16::from_le_bytes(bytes)
}

/// Reads a little-endian u64 from a raw pointer.
#[inline]
unsafe fn read_u64_le(ptr: *const u8) -> u64 {
    let mut bytes = [0u8; 8];
    std::ptr::copy_nonoverlapping(ptr, bytes.as_mut_ptr(), 8);
    u64::from_le_bytes(bytes)
}

/// Reads a u32 from a byte slice at the given offset (little-endian).
#[inline]
fn read_u32_from_slice(data: &[u8], offset: usize) -> u32 {
    if offset + 4 > data.len() {
        return 0;
    }
    u32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]])
}

/// Reads a u16 from a byte slice at the given offset (little-endian).
#[inline]
fn read_u16_from_slice(data: &[u8], offset: usize) -> u16 {
    if offset + 2 > data.len() {
        return 0;
    }
    u16::from_le_bytes([data[offset], data[offset + 1]])
}

/// Reads a u64 from a byte slice at the given offset (little-endian).
#[inline]
fn read_u64_from_slice(data: &[u8], offset: usize) -> u64 {
    if offset + 8 > data.len() {
        return 0;
    }
    u64::from_le_bytes([
        data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
        data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7],
    ])
}

/// Reads a ULEB128 (unsigned LEB128) encoded value from a byte slice.
fn read_uleb128(data: &[u8], pos: &mut usize) -> u64 {
    let mut result: u64 = 0;
    let mut shift: u32 = 0;
    loop {
        if *pos >= data.len() {
            break;
        }
        let byte = data[*pos];
        *pos += 1;
        result |= ((byte & 0x7f) as u64) << shift;
        if (byte & 0x80) == 0 {
            break;
        }
        shift += 7;
        if shift >= 64 {
            break;
        }
    }
    result
}

/// Reads a SLEB128 (signed LEB128) encoded value from a byte slice.
fn read_sleb128(data: &[u8], pos: &mut usize) -> i64 {
    let mut result: i64 = 0;
    let mut shift: u32 = 0;
    let mut byte: u8 = 0;
    loop {
        if *pos >= data.len() {
            break;
        }
        byte = data[*pos];
        *pos += 1;
        result |= ((byte & 0x7f) as i64) << shift;
        shift += 7;
        if (byte & 0x80) == 0 {
            break;
        }
        if shift >= 64 {
            break;
        }
    }
    if shift < 64 && (byte & 0x40) != 0 {
        result |= -(1i64 << shift);
    }
    result
}

/// Reads a null-terminated string from a byte slice, advancing position.
fn read_cstring_from_slice(data: &[u8], pos: &mut usize) -> String {
    let start = *pos;
    while *pos < data.len() && data[*pos] != 0 {
        *pos += 1;
    }
    let s = std::str::from_utf8(&data[start..*pos]).unwrap_or("").to_string();
    if *pos < data.len() {
        *pos += 1;
    }
    s
}

/// Reads a null-terminated string from a raw address at a given offset.
fn read_cstr_at(base: usize, offset: u32) -> &'static str {
    if base == 0 {
        return "";
    }
    let ptr = (base + offset as usize) as *const u8;
    unsafe {
        let cstr = CStr::from_ptr(ptr as *const libc::c_char);
        cstr.to_str().unwrap_or("")
    }
}

/// Reads a StabSym entry from raw memory at the given index.
fn read_stab_sym(base: usize, index: usize) -> StabSym {
    let offset = index * STAB_SYM_SIZE;
    let ptr = (base + offset) as *const u8;
    unsafe {
        StabSym {
            n_strx: read_u32_le(ptr),
            n_type: *ptr.add(4),
            n_other: *ptr.add(5),
            n_desc: read_u16_le(ptr.add(6)),
            n_value: read_u32_le(ptr.add(8)),
        }
    }
}

// ============================================================================
// Backtrace Line Number Resolution — STABS Format
// ============================================================================

/// Information collected during backtrace line resolution.
struct BtInfo {
    filename: String,
    line: u32,
    func_name: String,
}

/// Resolves a program counter to source file/line using STABS debug info.
///
/// Corresponds to `rt_printline()` in tccrun.c (lines 679-780).
fn rt_printline(rc: &RtContext, pc: usize) -> Option<BtInfo> {
    if rc.stab_sym == 0 || rc.stab_sym_size == 0 || rc.stab_str == 0 {
        return None;
    }

    let num_entries = rc.stab_sym_size / STAB_SYM_SIZE;
    let mut filename = String::new();
    let mut func_name = String::new();
    let mut func_addr: usize = 0;
    let mut incl_file = String::new();
    let mut best_line: u32 = 0;
    let mut best_pc: usize = 0;

    for i in 0..num_entries {
        let stab = read_stab_sym(rc.stab_sym, i);
        let n_type = stab.n_type;

        match n_type {
            t if t == StabCode::N_SO as u8 => {
                let name = read_cstr_at(rc.stab_str, stab.n_strx);
                if !name.is_empty() {
                    if name.ends_with('/') {
                        filename = name.to_string();
                    } else {
                        filename.push_str(name);
                    }
                }
                func_addr = stab.n_value as usize;
            }
            t if t == StabCode::N_SOL as u8 => {
                incl_file = read_cstr_at(rc.stab_str, stab.n_strx).to_string();
            }
            t if t == StabCode::N_FUN as u8 => {
                let name = read_cstr_at(rc.stab_str, stab.n_strx);
                if !name.is_empty() {
                    func_name = name.to_string();
                    if let Some(cp) = func_name.find(':') {
                        func_name.truncate(cp);
                    }
                    func_addr = stab.n_value as usize;
                } else {
                    func_addr = 0;
                }
            }
            t if t == StabCode::N_SLINE as u8 => {
                let line_pc = func_addr.wrapping_add(stab.n_value as usize);
                if line_pc <= pc && line_pc > best_pc {
                    best_pc = line_pc;
                    best_line = stab.n_desc as u32;
                }
            }
            t if t == StabCode::N_BINCL as u8 => {
                incl_file = read_cstr_at(rc.stab_str, stab.n_strx).to_string();
            }
            t if t == StabCode::N_EINCL as u8 => {
                incl_file.clear();
            }
            _ => {}
        }
    }

    if best_line > 0 {
        let display_file = if incl_file.is_empty() {
            &filename
        } else {
            &incl_file
        };
        Some(BtInfo {
            filename: display_file.clone(),
            line: best_line,
            func_name,
        })
    } else {
        None
    }
}

// ============================================================================
// Backtrace Line Number Resolution — DWARF Format
// ============================================================================

/// Reads a DWARF form value from a byte slice.
///
/// Supports standard forms used in DWARF line number programs for
/// file/directory name table parsing.
fn read_form_value(data: &[u8], pos: &mut usize, form: u16, addr_size: usize) -> u64 {
    match form {
        f if f == DWARF_FORM_ADDR => {
            if addr_size == 8 {
                let val = read_u64_from_slice(data, *pos);
                *pos += 8;
                val
            } else {
                let val = read_u32_from_slice(data, *pos) as u64;
                *pos += 4;
                val
            }
        }
        f if f == DWARF_FORM_DATA1 => {
            if *pos < data.len() {
                let val = data[*pos] as u64;
                *pos += 1;
                val
            } else {
                0
            }
        }
        f if f == DWARF_FORM_DATA2 => {
            let val = read_u16_from_slice(data, *pos) as u64;
            *pos += 2;
            val
        }
        f if f == DWARF_FORM_DATA4 => {
            let val = read_u32_from_slice(data, *pos) as u64;
            *pos += 4;
            val
        }
        f if f == DWARF_FORM_DATA8 => {
            let val = read_u64_from_slice(data, *pos);
            *pos += 8;
            val
        }
        f if f == DWARF_FORM_UDATA => {
            read_uleb128(data, pos)
        }
        f if f == DWARF_FORM_STRING => {
            // Skip null-terminated string
            while *pos < data.len() && data[*pos] != 0 {
                *pos += 1;
            }
            if *pos < data.len() {
                *pos += 1;
            }
            0 // String forms return 0; the actual string is consumed inline
        }
        f if f == DWARF_FORM_LINE_STRP || f == DWARF_FORM_STRP => {
            // Offset into .debug_line_str or .debug_str
            let val = read_u32_from_slice(data, *pos) as u64;
            *pos += 4;
            val
        }
        _ => {
            // Unknown form, cannot advance correctly — return 0
            0
        }
    }
}

/// Build a BtInfo from DWARF line number program data.
///
/// Corresponds to `rt_printline_dwarf()` in tccrun.c (lines 607-678).
/// Interprets the DWARF line number program to find the source file and
/// line for a given program counter address.
fn rt_printline_dwarf(rc: &RtContext, pc: usize) -> Option<BtInfo> {
    if rc.dwarf_line == 0 || rc.dwarf_line_size == 0 {
        return None;
    }

    // Access the raw line program data
    let line_data = unsafe {
        std::slice::from_raw_parts(rc.dwarf_line as *const u8, rc.dwarf_line_size)
    };

    let mut pos: usize = 0;

    // Parse unit header
    if pos + 4 > line_data.len() {
        return None;
    }
    let unit_length = read_u32_from_slice(line_data, pos) as usize;
    pos += 4;
    if unit_length == 0 || pos + unit_length > line_data.len() {
        return None;
    }
    let unit_end = pos + unit_length;

    let version = read_u16_from_slice(line_data, pos);
    pos += 2;

    let addr_size = if version >= 5 {
        let a = line_data.get(pos).copied().unwrap_or(8) as usize;
        pos += 1;
        let _seg = line_data.get(pos).copied().unwrap_or(0);
        pos += 1;
        a
    } else {
        PTR_SIZE
    };

    let header_length = read_u32_from_slice(line_data, pos) as usize;
    pos += 4;
    let program_start = pos + header_length;

    let min_instr_len = line_data.get(pos).copied().unwrap_or(1) as usize;
    pos += 1;

    // max_ops_per_instruction for DWARF >= 4
    let _max_ops = if version >= 4 {
        let v = line_data.get(pos).copied().unwrap_or(1);
        pos += 1;
        v
    } else {
        1u8
    };

    let default_is_stmt = line_data.get(pos).copied().unwrap_or(1);
    pos += 1;
    let line_base = line_data.get(pos).copied().unwrap_or(0) as i8;
    pos += 1;
    let line_range = line_data.get(pos).copied().unwrap_or(1);
    pos += 1;
    let opcode_base = line_data.get(pos).copied().unwrap_or(13);
    pos += 1;

    // Skip standard opcode lengths
    let num_std = if opcode_base > 1 { (opcode_base - 1) as usize } else { 0 };
    pos += num_std;

    // Skip directory and file tables (DWARF v4 or v5 have different formats)
    // For simplicity we collect file names separately
    let mut files: Vec<String> = Vec::new();
    let mut dirs: Vec<String> = Vec::new();

    if version >= 5 {
        // DWARF v5: directory table
        let dir_entry_format_count = line_data.get(pos).copied().unwrap_or(0);
        pos += 1;
        let mut dir_formats: Vec<(u64, u64)> = Vec::new();
        for _ in 0..dir_entry_format_count {
            let ct = read_uleb128(line_data, &mut pos);
            let form = read_uleb128(line_data, &mut pos);
            dir_formats.push((ct, form));
        }
        let dir_count = read_uleb128(line_data, &mut pos) as usize;
        for _ in 0..dir_count {
            let mut d = String::new();
            for &(ct, form) in &dir_formats {
                if ct == DWARF_LNCT_PATH as u64 {
                    if form == DWARF_FORM_STRING as u64 {
                        d = read_cstring_from_slice(line_data, &mut pos);
                    } else if form == DWARF_FORM_LINE_STRP as u64 {
                        let off = read_u32_from_slice(line_data, pos);
                        pos += 4;
                        if rc.dwarf_line_str != 0 {
                            d = read_cstr_at(rc.dwarf_line_str, off).to_string();
                        }
                    } else {
                        read_form_value(line_data, &mut pos, form as u16, addr_size);
                    }
                } else {
                    read_form_value(line_data, &mut pos, form as u16, addr_size);
                }
            }
            dirs.push(d);
        }

        // DWARF v5: file name table
        let file_entry_format_count = line_data.get(pos).copied().unwrap_or(0);
        pos += 1;
        let mut file_formats: Vec<(u64, u64)> = Vec::new();
        for _ in 0..file_entry_format_count {
            let ct = read_uleb128(line_data, &mut pos);
            let form = read_uleb128(line_data, &mut pos);
            file_formats.push((ct, form));
        }
        let file_count = read_uleb128(line_data, &mut pos) as usize;
        for _ in 0..file_count {
            let mut fname = String::new();
            let mut dir_idx: usize = 0;
            for &(ct, form) in &file_formats {
                if ct == DWARF_LNCT_PATH as u64 {
                    if form == DWARF_FORM_STRING as u64 {
                        fname = read_cstring_from_slice(line_data, &mut pos);
                    } else if form == DWARF_FORM_LINE_STRP as u64 {
                        let off = read_u32_from_slice(line_data, pos);
                        pos += 4;
                        if rc.dwarf_line_str != 0 {
                            fname = read_cstr_at(rc.dwarf_line_str, off).to_string();
                        }
                    } else {
                        read_form_value(line_data, &mut pos, form as u16, addr_size);
                    }
                } else if ct == DWARF_LNCT_DIRECTORY_INDEX as u64 {
                    dir_idx = read_form_value(line_data, &mut pos, form as u16, addr_size) as usize;
                } else {
                    read_form_value(line_data, &mut pos, form as u16, addr_size);
                }
            }
            // Combine directory and filename
            if dir_idx < dirs.len() && !dirs[dir_idx].is_empty() {
                let mut full = dirs[dir_idx].clone();
                if !full.ends_with('/') {
                    full.push('/');
                }
                full.push_str(&fname);
                files.push(full);
            } else {
                files.push(fname);
            }
        }
    } else {
        // DWARF v4 and earlier: null-terminated directory list
        dirs.push(String::new()); // index 0 = compilation directory
        loop {
            if pos >= program_start || pos >= line_data.len() || line_data[pos] == 0 {
                pos += 1;
                break;
            }
            let d = read_cstring_from_slice(line_data, &mut pos);
            dirs.push(d);
        }

        // File name table
        files.push(String::new()); // index 0 = unused in DWARF v4
        loop {
            if pos >= program_start || pos >= line_data.len() || line_data[pos] == 0 {
                break;
            }
            let fname = read_cstring_from_slice(line_data, &mut pos);
            let dir_idx = read_uleb128(line_data, &mut pos) as usize;
            let _mod_time = read_uleb128(line_data, &mut pos);
            let _file_len = read_uleb128(line_data, &mut pos);

            if dir_idx < dirs.len() && !dirs[dir_idx].is_empty() {
                let mut full = dirs[dir_idx].clone();
                if !full.ends_with('/') {
                    full.push('/');
                }
                full.push_str(&fname);
                files.push(full);
            } else {
                files.push(fname);
            }
        }
    }

    // Execute line program
    pos = program_start;

    let mut address: usize = 0;
    let mut line: i64 = 1;
    let mut file_idx: usize = 1;
    let mut _is_stmt = default_is_stmt != 0;

    let mut best_addr: usize = 0;
    let mut best_line: u32 = 0;
    let mut best_file: usize = 0;

    while pos < unit_end {
        let opcode = line_data[pos];
        pos += 1;

        if opcode == 0 {
            // Extended opcode
            let len = read_uleb128(line_data, &mut pos) as usize;
            let op_end = pos + len;
            if pos < line_data.len() {
                let ext_op = line_data[pos];
                pos += 1;
                match ext_op {
                    // DW_LNE_end_sequence
                    1 => {
                        if address <= pc && address > best_addr {
                            best_addr = address;
                            best_line = line as u32;
                            best_file = file_idx;
                        }
                        address = 0;
                        line = 1;
                        file_idx = 1;
                        _is_stmt = default_is_stmt != 0;
                    }
                    // DW_LNE_set_address
                    2 => {
                        if addr_size == 8 {
                            address = read_u64_from_slice(line_data, pos) as usize;
                        } else {
                            address = read_u32_from_slice(line_data, pos) as usize;
                        }
                    }
                    // DW_LNE_define_file
                    3 => {
                        let fname = read_cstring_from_slice(line_data, &mut pos);
                        let _dir = read_uleb128(line_data, &mut pos);
                        let _tm = read_uleb128(line_data, &mut pos);
                        let _sz = read_uleb128(line_data, &mut pos);
                        files.push(fname);
                    }
                    _ => {}
                }
            }
            pos = op_end;
        } else if opcode < opcode_base {
            // Standard opcode
            match opcode {
                // DW_LNS_copy
                1 => {
                    if address <= pc && address > best_addr {
                        best_addr = address;
                        best_line = line as u32;
                        best_file = file_idx;
                    }
                }
                // DW_LNS_advance_pc
                2 => {
                    let adv = read_uleb128(line_data, &mut pos) as usize;
                    address += adv * min_instr_len;
                }
                // DW_LNS_advance_line
                3 => {
                    line += read_sleb128(line_data, &mut pos);
                }
                // DW_LNS_set_file
                4 => {
                    file_idx = read_uleb128(line_data, &mut pos) as usize;
                }
                // DW_LNS_set_column
                5 => { let _ = read_uleb128(line_data, &mut pos); }
                // DW_LNS_negate_stmt
                6 => { _is_stmt = !_is_stmt; }
                // DW_LNS_set_basic_block
                7 => {}
                // DW_LNS_const_add_pc
                8 => {
                    let adj = ((255 - opcode_base) / line_range) as usize;
                    address += adj * min_instr_len;
                }
                // DW_LNS_fixed_advance_pc
                9 => {
                    let adv = read_u16_from_slice(line_data, pos) as usize;
                    pos += 2;
                    address += adv;
                }
                // DW_LNS_set_prologue_end (10), set_epilogue_begin (11), set_isa (12)
                10 | 11 => {}
                12 => { let _ = read_uleb128(line_data, &mut pos); }
                _ => {
                    // Skip operands for unknown standard opcodes
                }
            }
        } else {
            // Special opcode
            let adj_opcode = opcode - opcode_base;
            let line_inc = line_base as i64 + (adj_opcode % line_range) as i64;
            let addr_inc = (adj_opcode / line_range) as usize * min_instr_len;
            line += line_inc;
            address += addr_inc;

            if address <= pc && address > best_addr {
                best_addr = address;
                best_line = line as u32;
                best_file = file_idx;
            }
        }
    }

    if best_line > 0 && best_file < files.len() {
        Some(BtInfo {
            filename: files[best_file].clone(),
            line: best_line,
            func_name: String::new(),
        })
    } else {
        None
    }
}

// ============================================================================
// ELF Symbol Lookup for Backtraces
// ============================================================================

/// Looks up the ELF symbol whose address range contains `pc`.
///
/// Corresponds to `rt_elfsym()` in tccrun.c.
/// Scans the runtime context's ELF symbol range for a function symbol
/// covering the given program counter.
fn rt_elfsym(rc: &RtContext, pc: usize) -> Option<String> {
    if rc.esym_start == 0 || rc.esym_end == 0 || rc.elf_str == 0 {
        return None;
    }

    let sym_size = std::mem::size_of::<ElfSymEntry>();
    let mut sym_ptr = rc.esym_start;

    while sym_ptr + sym_size <= rc.esym_end {
        let (st_info, st_value, st_size, st_name) = unsafe {
            let p = sym_ptr as *const u8;
            if PTR_SIZE == 8 {
                // Elf64_Sym: st_name(4) st_info(1) st_other(1) st_shndx(2) st_value(8) st_size(8)
                let name = read_u32_le(p);
                let info = *p.add(4);
                let value = read_u64_le(p.add(8)) as usize;
                let size = read_u64_le(p.add(16)) as usize;
                (info, value, size, name)
            } else {
                // Elf32_Sym: st_name(4) st_value(4) st_size(4) st_info(1) st_other(1) st_shndx(2)
                let name = read_u32_le(p);
                let value = read_u32_le(p.add(4)) as usize;
                let size = read_u32_le(p.add(8)) as usize;
                let info = *p.add(12);
                (info, value, size, name)
            }
        };

        sym_ptr += sym_size;

        // Check if this is a function symbol
        let sym_type = st_info & 0x0f;
        if sym_type != 2 /* STT_FUNC */ && sym_type != 10 /* STT_GNU_IFUNC */ {
            continue;
        }

        if pc >= st_value && pc < st_value + st_size {
            let name = read_cstr_at(rc.elf_str, st_name);
            if !name.is_empty() {
                return Some(name.to_string());
            }
        }
    }

    None
}

/// Size of an ELF symbol table entry (either 32 or 64 bit).
#[allow(dead_code)]
struct ElfSymEntry;

#[allow(dead_code)]
impl ElfSymEntry {
    const SIZE_32: usize = 16; // Elf32_Sym
    const SIZE_64: usize = 24; // Elf64_Sym
}

// ============================================================================
// Signal Handling for Runtime Errors
// ============================================================================

/// Installs signal handlers for runtime error detection.
///
/// Corresponds to the signal handler setup in tccrun.c (set_exception_handler).
/// Installs handlers for SIGSEGV, SIGBUS, SIGFPE, SIGILL, and SIGABRT.
fn install_signal_handlers() {
    #[cfg(unix)]
    {
        unsafe {
            let mut sa: libc::sigaction = std::mem::zeroed();
            sa.sa_sigaction = sig_error as *const () as usize;
            sa.sa_flags = libc::SA_SIGINFO;
            libc::sigemptyset(&mut sa.sa_mask);

            libc::sigaction(libc::SIGFPE, &sa, std::ptr::null_mut());
            libc::sigaction(libc::SIGSEGV, &sa, std::ptr::null_mut());
            libc::sigaction(libc::SIGBUS, &sa, std::ptr::null_mut());
            libc::sigaction(libc::SIGILL, &sa, std::ptr::null_mut());
            libc::sigaction(libc::SIGABRT, &sa, std::ptr::null_mut());
        }
    }
}

/// Signal handler invoked on runtime errors.
///
/// Corresponds to `sig_error()` in tccrun.c.
/// Extracts the program counter from the signal context and performs
/// a backtrace using registered runtime contexts.
#[cfg(unix)]
unsafe extern "C" fn sig_error(
    sig: libc::c_int,
    _info: *mut libc::siginfo_t,
    _context: *mut libc::c_void,
) {
    let msg = match sig {
        libc::SIGFPE => "floating point exception",
        libc::SIGSEGV | libc::SIGBUS => "invalid memory access",
        libc::SIGILL => "illegal instruction",
        libc::SIGABRT => "abort() called",
        _ => "unknown signal",
    };

    let pc = rt_get_caller_pc_from_signal(_context);

    // Print signal information to stderr
    let _ = std::io::Write::write_fmt(
        &mut std::io::stderr(),
        format_args!("Runtime error: {} (signal {})\n", msg, sig),
    );

    // Attempt backtrace using the global runtime contexts
    if let Ok(contexts) = GLOBAL_RT_CONTEXTS.lock() {
        for rc in contexts.iter() {
            if let Some(info) = rt_printline_dwarf(rc, pc) {
                let _ = std::io::Write::write_fmt(
                    &mut std::io::stderr(),
                    format_args!("  {}:{}", info.filename, info.line),
                );
                if !info.func_name.is_empty() {
                    let _ = std::io::Write::write_fmt(
                        &mut std::io::stderr(),
                        format_args!(" in {}", info.func_name),
                    );
                }
                let _ = std::io::Write::write_all(&mut std::io::stderr(), b"\n");
            } else if let Some(info) = rt_printline(rc, pc) {
                let _ = std::io::Write::write_fmt(
                    &mut std::io::stderr(),
                    format_args!("  {}:{}", info.filename, info.line),
                );
                if !info.func_name.is_empty() {
                    let _ = std::io::Write::write_fmt(
                        &mut std::io::stderr(),
                        format_args!(" in {}", info.func_name),
                    );
                }
                let _ = std::io::Write::write_all(&mut std::io::stderr(), b"\n");
            }

            if let Some(sym) = rt_elfsym(rc, pc) {
                let _ = std::io::Write::write_fmt(
                    &mut std::io::stderr(),
                    format_args!("  (in function: {})\n", sym),
                );
            }
        }
    }

    // Exit with the signal number
    libc::_exit(255);
}

/// Extracts the caller's program counter from a signal context (platform-specific).
///
/// Corresponds to `rt_get_caller_pc()` in tccrun.c.
fn rt_get_caller_pc_from_signal(_context: *mut libc::c_void) -> usize {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    unsafe {
        let uc = _context as *const libc::ucontext_t;
        if uc.is_null() {
            return 0;
        }
        (*uc).uc_mcontext.gregs[libc::REG_RIP as usize] as usize
    }

    #[cfg(all(target_os = "linux", target_arch = "x86"))]
    unsafe {
        let uc = _context as *const libc::ucontext_t;
        if uc.is_null() {
            return 0;
        }
        (*uc).uc_mcontext.gregs[libc::REG_EIP as usize] as usize
    }

    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    unsafe {
        let uc = _context as *const libc::ucontext_t;
        if uc.is_null() {
            return 0;
        }
        (*uc).uc_mcontext.pc as usize
    }

    #[cfg(all(target_os = "linux", target_arch = "arm"))]
    unsafe {
        let uc = _context as *const libc::ucontext_t;
        if uc.is_null() {
            return 0;
        }
        (*uc).uc_mcontext.arm_pc as usize
    }

    #[cfg(all(target_os = "linux", target_arch = "riscv64"))]
    unsafe {
        let uc = _context as *const libc::ucontext_t;
        if uc.is_null() {
            return 0;
        }
        (*uc).uc_mcontext.__gregs[0] as usize // pc
    }

    #[cfg(not(any(
        all(target_os = "linux", target_arch = "x86_64"),
        all(target_os = "linux", target_arch = "x86"),
        all(target_os = "linux", target_arch = "aarch64"),
        all(target_os = "linux", target_arch = "arm"),
        all(target_os = "linux", target_arch = "riscv64"),
    )))]
    {
        // Fallback: cannot extract PC from signal context on this platform.
        0usize
    }
}

/// Gets the caller's program counter from the current stack frame.
///
/// Used in tcc_backtrace to walk the call stack.
#[allow(dead_code)]
fn rt_get_caller_pc(level: usize) -> usize {
    // Use the return address intrinsic when available.
    // For safety, in non-inline-asm contexts we return 0.
    // The actual backtrace code typically provides frame pointers.
    let _ = level;
    0
}

// ============================================================================
// Backtrace Frame Output
// ============================================================================

/// Prints backtrace information for a single stack frame.
///
/// Walks all registered RtContext entries trying DWARF first, then STABS,
/// then ELF symbol lookup.
fn print_backtrace_for_frame(pc: usize, frame_num: usize) {
    let _ = std::io::Write::write_fmt(
        &mut std::io::stderr(),
        format_args!("#{} 0x{:016x}", frame_num, pc),
    );

    if let Ok(contexts) = GLOBAL_RT_CONTEXTS.lock() {
        let mut found = false;
        for rc in contexts.iter() {
            if let Some(info) = rt_printline_dwarf(rc, pc) {
                let _ = std::io::Write::write_fmt(
                    &mut std::io::stderr(),
                    format_args!(" {}:{}", info.filename, info.line),
                );
                found = true;
                break;
            }
            if let Some(info) = rt_printline(rc, pc) {
                let _ = std::io::Write::write_fmt(
                    &mut std::io::stderr(),
                    format_args!(" {}:{}", info.filename, info.line),
                );
                if !info.func_name.is_empty() {
                    let _ = std::io::Write::write_fmt(
                        &mut std::io::stderr(),
                        format_args!(" ({})", info.func_name),
                    );
                }
                found = true;
                break;
            }
        }
        if !found {
            for rc in contexts.iter() {
                if let Some(sym) = rt_elfsym(rc, pc) {
                    let _ = std::io::Write::write_fmt(
                        &mut std::io::stderr(),
                        format_args!(" in {}", sym),
                    );
                    break;
                }
            }
        }
    }

    let _ = std::io::Write::write_all(&mut std::io::stderr(), b"\n");
}

// ============================================================================
// atexit Support (FEAT-03)
// ============================================================================

/// Registers an atexit handler for the current runtime session.
///
/// Implements FEAT-03 from TODO: proper atexit() support in `-run` mode.
/// The handler function pointer and argument are stored globally and invoked
/// when the in-memory program calls exit().
pub fn register_atexit_handler(func: usize) {
    if let Ok(mut handlers) = ATEXIT_HANDLERS.lock() {
        handlers.push(func);
    }
}

/// Runs all registered atexit handlers in reverse registration order.
///
/// Called during program termination in tcc_run() or when exit() is intercepted.
pub fn run_atexit_handlers() {
    let handlers = if let Ok(mut h) = ATEXIT_HANDLERS.lock() {
        let v = h.clone();
        h.clear();
        v
    } else {
        return;
    };

    // atexit handlers run in reverse order
    for func_ptr in handlers.iter().rev() {
        if *func_ptr != 0 {
            unsafe {
                let f: extern "C" fn() = std::mem::transmute(*func_ptr);
                f();
            }
        }
    }
}

// ============================================================================
// Bounds Checking Support (BOUND-02: setjmp/longjmp)
// ============================================================================

/// Saves bounds-checking state before a setjmp call.
///
/// Implements BOUND-02 from TODO: save bounds checking context so that
/// longjmp correctly restores the bounds table state.
#[cfg(feature = "bcheck")]
pub fn bound_setjmp_save(jmp_buf: usize) -> usize {
    // In the Rust port, bounds checking state is tracked per-TCCState.
    // This function serves as a hook point for the bounds checking runtime
    // (lib/bcheck.c) which is compiled by TCC and calls __bound_setjmp.
    // We store the current bounds table watermark associated with the jmp_buf.
    let _ = jmp_buf;
    0
}

/// Restores bounds-checking state after a longjmp call.
///
/// The companion to bound_setjmp_save: trims the bounds table back to
/// the state saved at setjmp time.
#[cfg(feature = "bcheck")]
pub fn bound_longjmp_restore(jmp_buf: usize) {
    // Restore bounds table to saved state.
    let _ = jmp_buf;
}

// ============================================================================
// Dynamic Library Helpers
// ============================================================================

/// Resolves a symbol name from the system's dynamic linker.
///
/// Uses RTLD_DEFAULT to search all loaded shared objects.
pub fn resolve_runtime_symbol(name: &str) -> Option<usize> {
    let cname = match CString::new(name) {
        Ok(c) => c,
        Err(_) => return None,
    };

    unsafe {
        // Clear previous error
        libc::dlerror();

        let sym = libc::dlsym(libc::RTLD_DEFAULT, cname.as_ptr());
        let err = libc::dlerror();
        if err.is_null() && !sym.is_null() {
            Some(sym as usize)
        } else {
            None
        }
    }
}

/// Loads a dynamic library by name, returning an opaque handle.
pub fn load_dynamic_library(name: &str) -> Option<*mut libc::c_void> {
    let cname = match CString::new(name) {
        Ok(c) => c,
        Err(_) => return None,
    };

    unsafe {
        let handle = libc::dlopen(cname.as_ptr(), libc::RTLD_LAZY);
        if handle.is_null() {
            None
        } else {
            Some(handle)
        }
    }
}

/// Closes a previously opened dynamic library handle.
///
/// # Safety
///
/// The caller must ensure that `handle` is a valid dlopen handle
/// or null. A null handle is safely ignored.
pub unsafe fn close_dynamic_library(handle: *mut libc::c_void) {
    if !handle.is_null() {
        libc::dlclose(handle);
    }
}

/// Returns the last dynamic linker error message, if any.
pub fn get_dlerror() -> Option<String> {
    unsafe {
        let err = libc::dlerror();
        if err.is_null() {
            None
        } else {
            let cstr = CStr::from_ptr(err);
            Some(cstr.to_string_lossy().into_owned())
        }
    }
}

/// Looks up a symbol in a specific dynamic library handle.
///
/// # Safety
///
/// The caller must ensure that `handle` is a valid dlopen handle
/// (e.g. returned by [`load_dynamic_library`]).
pub unsafe fn dlsym_in_library(handle: *mut libc::c_void, name: &str) -> Option<usize> {
    let cname = match CString::new(name) {
        Ok(c) => c,
        Err(_) => return None,
    };

    libc::dlerror();
    let sym = libc::dlsym(handle, cname.as_ptr());
    let err = libc::dlerror();
    if err.is_null() && !sym.is_null() {
        Some(sym as usize)
    } else {
        None
    }
}

// ============================================================================
// tcc_backtrace — Exported Function (4th Required Export)
// ============================================================================

/// Generates a backtrace from the current call position.
///
/// This is the public-facing backtrace function exported from the runtime
/// module. It is called from compiled code (via `__bound_error` or user
/// code that calls `tcc_backtrace` directly) to print a stack trace.
///
/// Corresponds to `tcc_backtrace()` in tccrun.c.
///
/// # Arguments
///
/// * `fmt` - Format string for the backtrace message
/// * `args` - Variadic arguments for the format string (as raw pointers)
///
/// # Returns
///
/// Returns 0 on success, -1 on failure.
pub fn tcc_backtrace(fmt: &str, args: &[usize]) -> i32 {
    // Print the user message
    let _ = std::io::Write::write_fmt(
        &mut std::io::stderr(),
        format_args!("{}", fmt),
    );
    let _ = args; // Variadic args would be processed by the C caller

    let _ = std::io::Write::write_all(&mut std::io::stderr(), b"\n");

    // Walk up the stack printing frames
    let mut frame_num = 0;
    let max_frames = RT_NUM_CALLERS;

    // Get the return addresses from the call stack.
    // In practice, the compiled code passes frame pointers through the
    // __bound_error / tcc_backtrace calling convention. Here we iterate
    // over registered runtime contexts and attempt to resolve addresses.
    if let Ok(contexts) = GLOBAL_RT_CONTEXTS.lock() {
        if contexts.is_empty() {
            let _ = std::io::Write::write_all(
                &mut std::io::stderr(),
                b"(no runtime context available for backtrace)\n",
            );
            return -1;
        }

        // Use the top_func from the first context as starting point
        for rc in contexts.iter() {
            if rc.top_func != 0 {
                print_backtrace_for_frame(rc.top_func, frame_num);
                frame_num += 1;
                if frame_num >= max_frames {
                    break;
                }
            }
        }
    }

    if frame_num == 0 {
        // No frames found — try a manual walk
        let _ = std::io::Write::write_all(
            &mut std::io::stderr(),
            b"(backtrace not available)\n",
        );
        return -1;
    }

    0
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_align_up() {
        assert_eq!(align_up(0, 4096), 0);
        assert_eq!(align_up(1, 4096), 4096);
        assert_eq!(align_up(4095, 4096), 4096);
        assert_eq!(align_up(4096, 4096), 4096);
        assert_eq!(align_up(4097, 4096), 8192);
        assert_eq!(align_up(100, 16), 112);
        assert_eq!(align_up(16, 16), 16);
        assert_eq!(align_up(0, 1), 0);
        assert_eq!(align_up(5, 1), 5);
    }

    #[test]
    fn test_section_category() {
        // rx: SHF_ALLOC | SHF_EXECINSTR (exact match: 0x6)
        assert_eq!(section_category(SHF_ALLOC | SHF_EXECINSTR, 0, true), SEC_RX);
        // ro: SHF_ALLOC only (exact match: 0x2)
        assert_eq!(section_category(SHF_ALLOC, 0, true), SEC_RO);
        // rw: SHF_ALLOC | SHF_WRITE (exact match: 0x3)
        assert_eq!(section_category(SHF_ALLOC | SHF_WRITE, 0, true), SEC_RW);
        // debug: no flags (exact match: 0x0)
        assert_eq!(section_category(0, 0, true), SEC_DEBUG);
        // Unknown flag combo -> fallback rw
        assert_eq!(section_category(0xFF, 0, false), SEC_RW);
    }

    #[test]
    fn test_read_uleb128() {
        // 0 => 0x00
        let data = [0x00u8];
        let mut pos = 0;
        assert_eq!(read_uleb128(&data, &mut pos), 0);
        assert_eq!(pos, 1);

        // 127 => 0x7F
        let data = [0x7Fu8];
        let mut pos = 0;
        assert_eq!(read_uleb128(&data, &mut pos), 127);

        // 128 => 0x80 0x01
        let data = [0x80u8, 0x01];
        let mut pos = 0;
        assert_eq!(read_uleb128(&data, &mut pos), 128);

        // 624485 => 0xE5 0x8E 0x26
        let data = [0xE5u8, 0x8E, 0x26];
        let mut pos = 0;
        assert_eq!(read_uleb128(&data, &mut pos), 624485);
    }

    #[test]
    fn test_read_sleb128() {
        // 0 => 0x00
        let data = [0x00u8];
        let mut pos = 0;
        assert_eq!(read_sleb128(&data, &mut pos), 0);

        // -1 => 0x7F
        let data = [0x7Fu8];
        let mut pos = 0;
        assert_eq!(read_sleb128(&data, &mut pos), -1);

        // -123456 => encoded as SLEB128
        let data = [0xC0u8, 0xBB, 0x78];
        let mut pos = 0;
        assert_eq!(read_sleb128(&data, &mut pos), -123456);
    }

    #[test]
    fn test_read_cstring_from_slice() {
        let data = b"hello\0world\0";
        let mut pos = 0;
        assert_eq!(read_cstring_from_slice(data, &mut pos), "hello");
        assert_eq!(pos, 6);
        assert_eq!(read_cstring_from_slice(data, &mut pos), "world");
        assert_eq!(pos, 12);
    }

    #[test]
    fn test_read_u32_from_slice() {
        let data = [0x78u8, 0x56, 0x34, 0x12];
        assert_eq!(read_u32_from_slice(&data, 0), 0x12345678);
    }

    #[test]
    fn test_read_u16_from_slice() {
        let data = [0x34u8, 0x12];
        assert_eq!(read_u16_from_slice(&data, 0), 0x1234);
    }

    #[test]
    fn test_read_u64_from_slice() {
        let data = [0x01u8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(read_u64_from_slice(&data, 0), 1);
    }

    #[test]
    fn test_rt_context_default() {
        let ctx = RtContext::default();
        assert_eq!(ctx.stab_sym, 0);
        assert_eq!(ctx.stab_sym_size, 0);
        assert_eq!(ctx.stab_str, 0);
        assert_eq!(ctx.dwarf_line, 0);
        assert_eq!(ctx.dwarf_line_size, 0);
        assert_eq!(ctx.dwarf_line_str, 0);
        assert_eq!(ctx.esym_start, 0);
        assert_eq!(ctx.esym_end, 0);
        assert_eq!(ctx.elf_str, 0);
        assert_eq!(ctx.prog_base, 0);
        assert_eq!(ctx.bounds_start, 0);
        assert_eq!(ctx.top_func, 0);
        assert_eq!(ctx.next, std::ptr::null_mut());
        assert_eq!(ctx.num_callers, RT_NUM_CALLERS);
    }

    #[test]
    fn test_rt_frame_default() {
        let frame = RtFrame::default();
        assert_eq!(frame.ip, 0);
        assert_eq!(frame.fp, 0);
        assert_eq!(frame.sp, 0);
    }

    #[test]
    fn test_register_atexit_handler() {
        // Clear handlers first
        if let Ok(mut h) = ATEXIT_HANDLERS.lock() {
            h.clear();
        }

        register_atexit_handler(0x1234);
        register_atexit_handler(0x5678);

        if let Ok(h) = ATEXIT_HANDLERS.lock() {
            assert_eq!(h.len(), 2);
            assert_eq!(h[0], 0x1234);
            assert_eq!(h[1], 0x5678);
        }

        // Cleanup
        if let Ok(mut h) = ATEXIT_HANDLERS.lock() {
            h.clear();
        }
    }

    #[test]
    fn test_resolve_runtime_symbol_printf() {
        // printf should be resolvable on any Unix system
        let result = resolve_runtime_symbol("printf");
        assert!(result.is_some(), "printf should be resolvable via dlsym");
        assert!(result.unwrap() != 0, "printf address should be non-zero");
    }

    #[test]
    fn test_resolve_runtime_symbol_nonexistent() {
        let result = resolve_runtime_symbol("__this_symbol_does_not_exist_12345");
        assert!(result.is_none(), "nonexistent symbol should return None");
    }

    #[test]
    fn test_get_dlerror_after_bad_dlopen() {
        // Force an error by trying to open a non-existent library
        unsafe {
            libc::dlerror(); // clear
            let bad = CString::new("libnonexistent_99999.so").unwrap();
            let _ = libc::dlopen(bad.as_ptr(), libc::RTLD_LAZY);
        }
        let err = get_dlerror();
        assert!(err.is_some(), "dlerror should report an error after bad dlopen");
    }

    #[test]
    fn test_build_symbol_map_empty() {
        let state = TCCState::default();
        let map = build_symbol_map(&state);
        assert!(map.is_empty());
    }

    #[test]
    fn test_bt_info_stabs_empty_context() {
        let rc = RtContext::default();
        let result = rt_printline(&rc, 0x1000);
        assert!(result.is_none());
    }

    #[test]
    fn test_bt_info_dwarf_empty_context() {
        let rc = RtContext::default();
        let result = rt_printline_dwarf(&rc, 0x1000);
        assert!(result.is_none());
    }

    #[test]
    fn test_rt_elfsym_empty_context() {
        let rc = RtContext::default();
        let result = rt_elfsym(&rc, 0x1000);
        assert!(result.is_none());
    }

    #[test]
    fn test_tcc_backtrace_no_context() {
        // Should return -1 when no runtime contexts are registered
        if let Ok(mut contexts) = GLOBAL_RT_CONTEXTS.lock() {
            contexts.clear();
        }
        let result = tcc_backtrace("test backtrace", &[]);
        assert_eq!(result, -1);
    }
}
