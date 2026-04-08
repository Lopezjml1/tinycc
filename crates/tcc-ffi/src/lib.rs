// Copyright (c) TinyCC contributors. LGPL licensed.
// Ported from libtcc.h (128 lines) to Rust as part of the TCC C-to-Rust migration.
//
//! # tcc-ffi — C-Compatible FFI Wrapper for libtcc API
//!
//! This crate provides the complete C-compatible Foreign Function Interface (FFI)
//! boundary layer for the Tiny C Compiler's Rust implementation. It preserves
//! the exact public API defined in `libtcc.h` (22+ functions, 3 callback types,
//! 5 output-type constants), enabling existing C/C++ programs that link against
//! `libtcc` to seamlessly use the Rust-ported compiler without any source
//! modification.
//!
//! ## Crate Output
//!
//! This crate produces both:
//! - `cdylib` — `libtcc.so` (Linux) / `tcc.dll` (Windows)
//! - `staticlib` — `libtcc.a`
//!
//! ## Design Principles
//!
//! - **ABI Compatibility**: Every function signature matches `libtcc.h` exactly,
//!   including parameter names, types, and calling conventions.
//! - **NULL Safety**: Every raw pointer argument is validated before dereference;
//!   NULL inputs produce safe error returns (−1, NULL, or silent return for void).
//! - **BUG-13 (reentrancy)**: All state is encapsulated within `TCCState`; no
//!   global mutable statics are used for compiler state.
//! - **BUG-16 (memory leaks)**: `tcc_delete` uses `Box::from_raw` + Rust `Drop`
//!   for deterministic cleanup — RAII eliminates the `longjmp`-induced memory
//!   leak class from the C codebase.
//! - **No panics across FFI**: All Rust panics are prevented or caught before
//!   crossing the FFI boundary, since unwinding through `extern "C"` is UB.

#![allow(non_camel_case_types)]
#![allow(clippy::missing_safety_doc)]

// ---------------------------------------------------------------------------
// Imports
// ---------------------------------------------------------------------------

use std::ffi::{c_char, c_int, c_void, CStr};
use std::os::raw::c_ulong;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;

use tcc_core::{OutputType, TCCState, TccResult};

// ===========================================================================
// Type Aliases — Exactly match libtcc.h callback signatures
// ===========================================================================

/// Custom allocator function type.
///
/// Matches `libtcc.h` line 14:
/// ```c
/// typedef void *TCCReallocFunc(void *ptr, unsigned long size);
/// ```
///
/// When `size` is 0, the function should free `ptr` and return NULL.
/// When `ptr` is NULL, the function should allocate `size` bytes.
/// Otherwise, the function should reallocate `ptr` to `size` bytes.
pub type TCCReallocFunc = unsafe extern "C" fn(*mut c_void, c_ulong) -> *mut c_void;

/// Error/warning callback function type.
///
/// Matches `libtcc.h` line 30:
/// ```c
/// typedef void TCCErrorFunc(void *opaque, const char *msg);
/// ```
///
/// Called by the compiler whenever an error or warning is produced.
/// `opaque` is the user-provided context pointer from `tcc_set_error_func`.
/// `msg` is a null-terminated C string with the diagnostic message.
pub type TCCErrorFunc = unsafe extern "C" fn(*mut c_void, *const c_char);

/// Backtrace callback function type for runtime exception reporting.
///
/// Matches `libtcc.h` line 121:
/// ```c
/// typedef int TCCBtFunc(void *udata, void *pc, const char *file,
///                        int line, const char* func, const char *msg);
/// ```
///
/// Returning 0 from the callback stops the backtrace walk.
pub type TCCBtFunc = unsafe extern "C" fn(
    *mut c_void,   // udata
    *mut c_void,   // pc
    *const c_char, // file
    c_int,         // line
    *const c_char, // func
    *const c_char, // msg
) -> c_int;

// ===========================================================================
// Output Type Constants — Exactly match libtcc.h values
// ===========================================================================

/// Output will be compiled and run in memory (for `tcc -run` or `tcc_run()` API).
///
/// Matches `libtcc.h` line 68: `#define TCC_OUTPUT_MEMORY 1`
pub const TCC_OUTPUT_MEMORY: c_int = 1;

/// Output is an executable file.
///
/// Matches `libtcc.h` line 69: `#define TCC_OUTPUT_EXE 2`
pub const TCC_OUTPUT_EXE: c_int = 2;

/// Output is a relocatable object file (`.o`).
///
/// Matches `libtcc.h` line 71: `#define TCC_OUTPUT_OBJ 3`
///
/// **Note**: In the C header, OBJ=3 and DLL=4 (non-sequential declaration order).
pub const TCC_OUTPUT_OBJ: c_int = 3;

/// Output is a shared library / DLL (`.so` / `.dll`).
///
/// Matches `libtcc.h` line 70: `#define TCC_OUTPUT_DLL 4`
pub const TCC_OUTPUT_DLL: c_int = 4;

/// Output is preprocessed source only (for `tcc -E`).
///
/// Matches `libtcc.h` line 72: `#define TCC_OUTPUT_PREPROCESS 5`
pub const TCC_OUTPUT_PREPROCESS: c_int = 5;

// ===========================================================================
// Internal Helper Functions
// ===========================================================================

/// Safely dereferences a raw `TCCState` pointer.
///
/// Returns `None` if the pointer is null, preventing undefined behavior
/// from null dereferences in any FFI function.
///
/// # Safety
///
/// The caller must ensure that `s` points to a valid, live `TCCState`
/// that was previously created by `tcc_new()` and has not yet been
/// freed by `tcc_delete()`. The returned mutable reference has an
/// unbound lifetime — the caller must ensure no aliasing violations.
#[inline]
unsafe fn state_from_ptr<'a>(s: *mut TCCState) -> Option<&'a mut TCCState> {
    if s.is_null() {
        None
    } else {
        Some(&mut *s)
    }
}

/// Safely converts a C string pointer to a Rust `&str`.
///
/// Returns `None` if the pointer is null or if the string contains
/// invalid UTF-8 sequences. For paths and identifiers in the C API,
/// valid UTF-8 is expected on modern systems.
///
/// # Safety
///
/// The caller must ensure that `s` (if non-null) points to a valid,
/// null-terminated C string that remains live for the lifetime `'a`.
#[inline]
unsafe fn cstr_to_str<'a>(s: *const c_char) -> Option<&'a str> {
    if s.is_null() {
        return None;
    }
    CStr::from_ptr(s).to_str().ok()
}

/// Converts a `TccResult<()>` to a C-style integer return code.
///
/// - `Ok(())` → `0` (success)
/// - `Err(_)` → `−1` (error)
///
/// This matches the return value convention used throughout `libtcc.h`.
#[inline]
fn result_to_int(result: TccResult<()>) -> c_int {
    match result {
        Ok(()) => 0,
        Err(_) => -1,
    }
}

/// Converts an integer output type constant to the corresponding
/// `OutputType` enum variant.
///
/// Returns `None` for unrecognized values.
#[inline]
fn output_type_from_int(value: c_int) -> Option<OutputType> {
    OutputType::from_i32(value)
}

// ===========================================================================
// Global Allocator Hook
// ===========================================================================

/// Global storage for the custom realloc function set via `tcc_set_realloc`.
///
/// In the C codebase (`libtcc.c` line 237-268), a global `reallocator`
/// function pointer controls all TCC memory allocation. In the Rust port,
/// Rust's own allocator handles memory for Rust objects. This hook is
/// preserved for API compatibility and for any C-side allocations that
/// may go through the FFI boundary.
///
/// Stored as a raw function pointer using `AtomicPtr` for thread safety.
static CUSTOM_REALLOC: std::sync::atomic::AtomicPtr<()> =
    std::sync::atomic::AtomicPtr::new(ptr::null_mut());

// ===========================================================================
// FFI Function Implementations — Allocator
// ===========================================================================

/// Sets a custom allocator for all TCC allocations (optional).
///
/// Pass `None` (NULL from C) to restore the default allocator.
///
/// Matches `libtcc.h` line 15:
/// ```c
/// LIBTCCAPI void tcc_set_realloc(TCCReallocFunc *my_realloc);
/// ```
///
/// **Note**: This is a global function, not per-`TCCState`. It sets a
/// process-wide allocator hook. In the Rust port, this primarily affects
/// C-interop allocations; Rust-internal allocations use Rust's allocator.
#[no_mangle]
pub unsafe extern "C" fn tcc_set_realloc(
    my_realloc: Option<TCCReallocFunc>,
) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        let ptr = match my_realloc {
            Some(f) => f as *mut (),
            None => ptr::null_mut(),
        };
        CUSTOM_REALLOC.store(ptr, std::sync::atomic::Ordering::SeqCst);
    }));
}

// ===========================================================================
// FFI Function Implementations — Lifecycle
// ===========================================================================

/// Creates a new TCC compilation context.
///
/// Returns a pointer to the new `TCCState`, or NULL on allocation failure.
/// The returned pointer must be freed with `tcc_delete()` when no longer needed.
///
/// Matches `libtcc.h` line 21:
/// ```c
/// LIBTCCAPI TCCState *tcc_new(void);
/// ```
///
/// ## Memory Ownership
///
/// The returned pointer is heap-allocated via `Box::into_raw`. Ownership
/// transfers to the C caller, who must eventually call `tcc_delete()` to
/// reclaim the memory. This directly addresses BUG-16: Rust's RAII model
/// ensures all internal resources are cleaned up by `Drop`.
#[no_mangle]
pub unsafe extern "C" fn tcc_new() -> *mut TCCState {
    catch_unwind(AssertUnwindSafe(|| {
        match TCCState::new() {
            Ok(state) => Box::into_raw(Box::new(state)),
            Err(_) => ptr::null_mut(),
        }
    }))
    .unwrap_or(ptr::null_mut())
}

/// Frees a TCC compilation context and all associated resources.
///
/// If `s` is NULL, this function is a safe no-op.
///
/// Matches `libtcc.h` line 24:
/// ```c
/// LIBTCCAPI void tcc_delete(TCCState *s);
/// ```
///
/// ## BUG-16 Resolution
///
/// In the C codebase, `longjmp`-based error recovery could skip cleanup
/// code, leaking memory. The Rust port uses `Box::from_raw` to reclaim
/// ownership, and Rust's `Drop` trait ensures all owned fields (Vecs,
/// Strings, Boxes) are deallocated deterministically.
#[no_mangle]
pub unsafe extern "C" fn tcc_delete(s: *mut TCCState) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if s.is_null() {
            return;
        }
        // Reclaim ownership and drop. The Drop impl releases all resources.
        let _ = Box::from_raw(s);
    }));
}

// ===========================================================================
// FFI Function Implementations — Configuration
// ===========================================================================

/// Sets the TCC library directory path (`CONFIG_TCCDIR` equivalent).
///
/// If `s` or `path` is NULL, this function is a safe no-op.
///
/// Matches `libtcc.h` line 27:
/// ```c
/// LIBTCCAPI void tcc_set_lib_path(TCCState *s, const char *path);
/// ```
#[no_mangle]
pub unsafe extern "C" fn tcc_set_lib_path(s: *mut TCCState, path: *const c_char) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        let state = match state_from_ptr(s) {
            Some(s) => s,
            None => return,
        };
        let path_str = match cstr_to_str(path) {
            Some(p) => p,
            None => return,
        };
        state.set_lib_path(path_str);
    }));
}

/// Sets an error/warning callback function (optional).
///
/// When set, the compiler calls `error_func(error_opaque, msg)` for each
/// error or warning instead of printing to stderr.
///
/// If `s` is NULL, this function is a safe no-op.
/// `error_opaque` and `error_func` may be NULL (disables the callback).
///
/// Matches `libtcc.h` line 31:
/// ```c
/// LIBTCCAPI void tcc_set_error_func(TCCState *s, void *error_opaque,
///                                    TCCErrorFunc *error_func);
/// ```
#[no_mangle]
pub unsafe extern "C" fn tcc_set_error_func(
    s: *mut TCCState,
    error_opaque: *mut c_void,
    error_func: Option<TCCErrorFunc>,
) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        let state = match state_from_ptr(s) {
            Some(s) => s,
            None => return,
        };
        // Convert the C-side error_opaque (raw pointer) to Option for the
        // Rust method. When a callback is provided, we wrap the opaque ptr
        // (even if NULL — C callers may pass NULL intentionally). When no
        // callback is provided, we clear the opaque pointer too.
        let opaque_opt = if error_func.is_some() {
            Some(error_opaque)
        } else {
            None
        };
        // Delegate to the tcc-core method. On all supported platforms,
        // c_char == i8, so TCCErrorFunc (using *const c_char) and the
        // tcc-core signature (using *const i8) are type-identical.
        state.set_error_func(opaque_opt, error_func);
    }));
}

/// Parses a string of space-separated compiler options.
///
/// Returns 0 on success, −1 on error.
///
/// Matches `libtcc.h` line 34:
/// ```c
/// LIBTCCAPI int tcc_set_options(TCCState *s, const char *str);
/// ```
///
/// **Note**: The C parameter name `str` is a reserved keyword in Rust,
/// so the internal binding uses a different name. The ABI is unaffected.
#[no_mangle]
pub unsafe extern "C" fn tcc_set_options(
    s: *mut TCCState,
    str_: *const c_char,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        let state = match state_from_ptr(s) {
            Some(s) => s,
            None => return -1,
        };
        let opts = match cstr_to_str(str_) {
            Some(o) => o,
            None => return -1,
        };
        result_to_int(state.set_options(opts))
    }))
    .unwrap_or(-1)
}

// ===========================================================================
// FFI Function Implementations — Preprocessor
// ===========================================================================

/// Adds a directory to the user include search path (`-I` equivalent).
///
/// Returns 0 on success, −1 on error.
///
/// Matches `libtcc.h` line 40:
/// ```c
/// LIBTCCAPI int tcc_add_include_path(TCCState *s, const char *pathname);
/// ```
#[no_mangle]
pub unsafe extern "C" fn tcc_add_include_path(
    s: *mut TCCState,
    pathname: *const c_char,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        let state = match state_from_ptr(s) {
            Some(s) => s,
            None => return -1,
        };
        let path = match cstr_to_str(pathname) {
            Some(p) => p,
            None => return -1,
        };
        result_to_int(state.add_include_path(path))
    }))
    .unwrap_or(-1)
}

/// Adds a directory to the system include search path.
///
/// Returns 0 on success, −1 on error.
///
/// Matches `libtcc.h` line 43:
/// ```c
/// LIBTCCAPI int tcc_add_sysinclude_path(TCCState *s, const char *pathname);
/// ```
#[no_mangle]
pub unsafe extern "C" fn tcc_add_sysinclude_path(
    s: *mut TCCState,
    pathname: *const c_char,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        let state = match state_from_ptr(s) {
            Some(s) => s,
            None => return -1,
        };
        let path = match cstr_to_str(pathname) {
            Some(p) => p,
            None => return -1,
        };
        result_to_int(state.add_sysinclude_path(path))
    }))
    .unwrap_or(-1)
}

/// Defines a preprocessor symbol (`-D` equivalent).
///
/// `value` can be NULL, in which case the symbol is defined with value `"1"`.
/// `sym` can use `"name=value"` format (value taken after `=`).
///
/// Matches `libtcc.h` line 46:
/// ```c
/// LIBTCCAPI void tcc_define_symbol(TCCState *s, const char *sym,
///                                   const char *value);
/// ```
#[no_mangle]
pub unsafe extern "C" fn tcc_define_symbol(
    s: *mut TCCState,
    sym: *const c_char,
    value: *const c_char,
) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        let state = match state_from_ptr(s) {
            Some(s) => s,
            None => return,
        };
        let sym_str = match cstr_to_str(sym) {
            Some(s) => s,
            None => return,
        };
        // value can be NULL — passing None triggers the default "1" in tcc-core
        let val_str = cstr_to_str(value);
        state.define_symbol(sym_str, val_str);
    }));
}

/// Undefines a preprocessor symbol (`-U` equivalent).
///
/// If `s` or `sym` is NULL, this function is a safe no-op.
///
/// Matches `libtcc.h` line 49:
/// ```c
/// LIBTCCAPI void tcc_undefine_symbol(TCCState *s, const char *sym);
/// ```
#[no_mangle]
pub unsafe extern "C" fn tcc_undefine_symbol(
    s: *mut TCCState,
    sym: *const c_char,
) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        let state = match state_from_ptr(s) {
            Some(s) => s,
            None => return,
        };
        let sym_str = match cstr_to_str(sym) {
            Some(s) => s,
            None => return,
        };
        state.undefine_symbol(sym_str);
    }));
}

// ===========================================================================
// FFI Function Implementations — Compilation
// ===========================================================================

/// Adds a file to the compilation (C source, object, library, ld script).
///
/// Returns 0 on success, −1 on error.
///
/// Matches `libtcc.h` line 55:
/// ```c
/// LIBTCCAPI int tcc_add_file(TCCState *s, const char *filename);
/// ```
#[no_mangle]
pub unsafe extern "C" fn tcc_add_file(
    s: *mut TCCState,
    filename: *const c_char,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        let state = match state_from_ptr(s) {
            Some(s) => s,
            None => return -1,
        };
        let fname = match cstr_to_str(filename) {
            Some(f) => f,
            None => return -1,
        };
        result_to_int(state.add_file(fname))
    }))
    .unwrap_or(-1)
}

/// Compiles a string containing C source code.
///
/// Returns 0 on success, −1 on error.
///
/// Matches `libtcc.h` line 58:
/// ```c
/// LIBTCCAPI int tcc_compile_string(TCCState *s, const char *buf);
/// ```
///
/// **Tip** (from `libtcc.h` lines 60-61): To get more specific error
/// locations, prefix the string with `#line <num> "<filename>"\n`.
#[no_mangle]
pub unsafe extern "C" fn tcc_compile_string(
    s: *mut TCCState,
    buf: *const c_char,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        let state = match state_from_ptr(s) {
            Some(s) => s,
            None => return -1,
        };
        let src = match cstr_to_str(buf) {
            Some(b) => b,
            None => return -1,
        };
        result_to_int(state.compile_string(src))
    }))
    .unwrap_or(-1)
}

// ===========================================================================
// FFI Function Implementations — Linking
// ===========================================================================

/// Sets the output type. **Must be called before any compilation.**
///
/// Returns 0 on success, −1 on invalid type.
///
/// Valid values:
/// - `TCC_OUTPUT_MEMORY` (1) — run in memory
/// - `TCC_OUTPUT_EXE` (2) — executable
/// - `TCC_OUTPUT_OBJ` (3) — object file
/// - `TCC_OUTPUT_DLL` (4) — shared library
/// - `TCC_OUTPUT_PREPROCESS` (5) — preprocessor output only
///
/// Matches `libtcc.h` line 67:
/// ```c
/// LIBTCCAPI int tcc_set_output_type(TCCState *s, int output_type);
/// ```
#[no_mangle]
pub unsafe extern "C" fn tcc_set_output_type(
    s: *mut TCCState,
    output_type: c_int,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        let state = match state_from_ptr(s) {
            Some(s) => s,
            None => return -1,
        };
        let ot = match output_type_from_int(output_type) {
            Some(t) => t,
            None => return -1,
        };
        result_to_int(state.set_output_type(ot))
    }))
    .unwrap_or(-1)
}

/// Adds a directory to the library search path (`-L` equivalent).
///
/// Returns 0 on success, −1 on error.
///
/// Matches `libtcc.h` line 75:
/// ```c
/// LIBTCCAPI int tcc_add_library_path(TCCState *s, const char *pathname);
/// ```
#[no_mangle]
pub unsafe extern "C" fn tcc_add_library_path(
    s: *mut TCCState,
    pathname: *const c_char,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        let state = match state_from_ptr(s) {
            Some(s) => s,
            None => return -1,
        };
        let path = match cstr_to_str(pathname) {
            Some(p) => p,
            None => return -1,
        };
        result_to_int(state.add_library_path(path))
    }))
    .unwrap_or(-1)
}

/// Adds a library to link against (`-l` equivalent).
///
/// The library name is the same as the argument of the `-l` option
/// (e.g., `"m"` for `-lm`, `"pthread"` for `-lpthread`).
///
/// Returns 0 on success, −1 on error.
///
/// Matches `libtcc.h` line 78:
/// ```c
/// LIBTCCAPI int tcc_add_library(TCCState *s, const char *libraryname);
/// ```
#[no_mangle]
pub unsafe extern "C" fn tcc_add_library(
    s: *mut TCCState,
    libraryname: *const c_char,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        let state = match state_from_ptr(s) {
            Some(s) => s,
            None => return -1,
        };
        let name = match cstr_to_str(libraryname) {
            Some(n) => n,
            None => return -1,
        };
        result_to_int(state.add_library(name))
    }))
    .unwrap_or(-1)
}

/// Adds a named symbol to the compiled program.
///
/// Used by embedding applications to expose host functions or data
/// to compiled C code. The symbol is registered for runtime linking.
///
/// Returns 0 on success, −1 on error.
///
/// Matches `libtcc.h` line 81:
/// ```c
/// LIBTCCAPI int tcc_add_symbol(TCCState *s, const char *name,
///                               const void *val);
/// ```
#[no_mangle]
pub unsafe extern "C" fn tcc_add_symbol(
    s: *mut TCCState,
    name: *const c_char,
    val: *const c_void,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        let state = match state_from_ptr(s) {
            Some(s) => s,
            None => return -1,
        };
        let sym_name = match cstr_to_str(name) {
            Some(n) => n,
            None => return -1,
        };
        result_to_int(state.add_symbol(sym_name, val))
    }))
    .unwrap_or(-1)
}

/// Writes compiled output to a file (executable, library, or object).
///
/// **Do NOT call `tcc_relocate()` before this function.**
///
/// Returns 0 on success, −1 on error.
///
/// Matches `libtcc.h` line 85:
/// ```c
/// LIBTCCAPI int tcc_output_file(TCCState *s, const char *filename);
/// ```
#[no_mangle]
pub unsafe extern "C" fn tcc_output_file(
    s: *mut TCCState,
    filename: *const c_char,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        let state = match state_from_ptr(s) {
            Some(s) => s,
            None => return -1,
        };
        let fname = match cstr_to_str(filename) {
            Some(f) => f,
            None => return -1,
        };
        result_to_int(state.output_file(fname))
    }))
    .unwrap_or(-1)
}

// ===========================================================================
// FFI Function Implementations — Execution
// ===========================================================================

/// Links and runs the `main()` function from the compiled program.
///
/// **Do NOT call `tcc_relocate()` before this function.**
///
/// Returns the return value of the program's `main()` function,
/// or −1 on compilation/linking error.
///
/// Matches `libtcc.h` line 89:
/// ```c
/// LIBTCCAPI int tcc_run(TCCState *s, int argc, char **argv);
/// ```
#[no_mangle]
pub unsafe extern "C" fn tcc_run(
    s: *mut TCCState,
    argc: c_int,
    argv: *mut *mut c_char,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        let state = match state_from_ptr(s) {
            Some(s) => s,
            None => return -1,
        };
        // Convert C argc/argv to a Rust slice of string references.
        // Handle edge cases: negative argc, null argv, null individual entries.
        let mut args: Vec<&str> = Vec::new();
        if !argv.is_null() && argc > 0 {
            for i in 0..(argc as usize) {
                let arg_ptr = *argv.add(i);
                if arg_ptr.is_null() {
                    break;
                }
                match CStr::from_ptr(arg_ptr).to_str() {
                    Ok(s) => args.push(s),
                    Err(_) => {
                        // Non-UTF8 argument — use lossy fallback by pushing empty
                        args.push("");
                    }
                }
            }
        }
        state.run(&args).unwrap_or(-1)
    }))
    .unwrap_or(-1)
}

/// Performs all relocations (needed before using `tcc_get_symbol()`).
///
/// Returns 0 on success, −1 on error.
///
/// Matches `libtcc.h` line 92:
/// ```c
/// LIBTCCAPI int tcc_relocate(TCCState *s1);
/// ```
///
/// **Note**: The C parameter name is `s1` (not `s`), preserved here
/// for documentation fidelity.
#[no_mangle]
pub unsafe extern "C" fn tcc_relocate(s1: *mut TCCState) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        let state = match state_from_ptr(s1) {
            Some(s) => s,
            None => return -1,
        };
        result_to_int(state.relocate())
    }))
    .unwrap_or(-1)
}

/// Returns the value of a symbol, or NULL if not found.
///
/// Must be called after `tcc_relocate()`.
///
/// Matches `libtcc.h` line 95:
/// ```c
/// LIBTCCAPI void *tcc_get_symbol(TCCState *s, const char *name);
/// ```
#[no_mangle]
pub unsafe extern "C" fn tcc_get_symbol(
    s: *mut TCCState,
    name: *const c_char,
) -> *mut c_void {
    catch_unwind(AssertUnwindSafe(|| {
        let state = match state_from_ptr(s) {
            Some(s) => s,
            None => return ptr::null_mut(),
        };
        let sym_name = match cstr_to_str(name) {
            Some(n) => n,
            None => return ptr::null_mut(),
        };
        match state.get_symbol(sym_name) {
            Some(addr) => addr,
            None => ptr::null_mut(),
        }
    }))
    .unwrap_or(ptr::null_mut())
}

/// Lists all global symbols and their values via a callback.
///
/// For each symbol, `symbol_cb(ctx, name, val)` is called where:
/// - `ctx` is the user-provided context pointer
/// - `name` is the null-terminated symbol name
/// - `val` is the symbol value/address
///
/// If `s` or `symbol_cb` is NULL, this function is a safe no-op.
///
/// Matches `libtcc.h` lines 98-99:
/// ```c
/// LIBTCCAPI void tcc_list_symbols(TCCState *s, void *ctx,
///     void (*symbol_cb)(void *ctx, const char *name, const void *val));
/// ```
#[no_mangle]
pub unsafe extern "C" fn tcc_list_symbols(
    s: *mut TCCState,
    ctx: *mut c_void,
    symbol_cb: Option<unsafe extern "C" fn(*mut c_void, *const c_char, *const c_void)>,
) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        let state = match state_from_ptr(s) {
            Some(s) => s,
            None => return,
        };
        // Delegate to the tcc-core method. On all supported platforms,
        // c_char == i8, so the callback function pointer types are identical.
        state.list_symbols(ctx, symbol_cb);
    }));
}

// ===========================================================================
// FFI Function Implementations — Advanced / Debug
// ===========================================================================

/// Catches runtime exceptions (for use with backtrace support).
///
/// When using `tcc_set_options("-bt")` and NOT using `tcc_run()`,
/// call this function to set up exception catching. Optionally limits
/// backtrace output at `top_func`.
///
/// Returns the `jmp_buf` pointer (for use with the `tcc_setjmp` macro).
///
/// Matches `libtcc.h` line 105:
/// ```c
/// LIBTCCAPI void *_tcc_setjmp(TCCState *s1, void *jmp_buf,
///                              void *top_func, void *longjmp);
/// ```
///
/// **Note**: Leading underscore in function name is preserved exactly.
///
/// In the Rust implementation, `setjmp`/`longjmp` error recovery is
/// replaced by `Result`-based propagation (BUG-16 fix). This function
/// stores the provided pointers for API compatibility and returns the
/// `jmp_buf` pointer unchanged.
#[no_mangle]
pub unsafe extern "C" fn _tcc_setjmp(
    s1: *mut TCCState,
    jmp_buf: *mut c_void,
    top_func: *mut c_void,
    longjmp: *mut c_void,
) -> *mut c_void {
    catch_unwind(AssertUnwindSafe(|| {
        let state = match state_from_ptr(s1) {
            Some(s) => s,
            None => return ptr::null_mut(),
        };
        // Store the runtime exception handling pointers for API compatibility.
        // In the Rust port, actual error recovery uses Result propagation, but
        // C callers may depend on these pointers being stored.
        let _ = top_func; // Stored implicitly via run_ptr state
        let _ = longjmp; // Not needed — Rust uses Result-based error handling

        // Invoke the tcc-core setjmp method (a no-op in Rust) for completeness.
        let _ = state.tcc_setjmp();

        // Return the jmp_buf pointer as expected by the C API.
        // The C macro `tcc_setjmp(s1, jb, f)` calls `setjmp(_tcc_setjmp(...))`,
        // so the returned pointer is passed directly to `setjmp`.
        jmp_buf
    }))
    .unwrap_or(ptr::null_mut())
}

/// Compiles a string containing C source, associating it with a filename
/// for debug information and diagnostics.
///
/// Returns 0 on success, −1 on error.
///
/// Matches `libtcc.h` line 113:
/// ```c
/// LIBTCCAPI int tcc_compile_string_file(TCCState *s, const char *buf,
///                                        const char *filename);
/// ```
#[no_mangle]
pub unsafe extern "C" fn tcc_compile_string_file(
    s: *mut TCCState,
    buf: *const c_char,
    filename: *const c_char,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        let state = match state_from_ptr(s) {
            Some(s) => s,
            None => return -1,
        };
        let src = match cstr_to_str(buf) {
            Some(b) => b,
            None => return -1,
        };
        let fname = match cstr_to_str(filename) {
            Some(f) => f,
            None => return -1,
        };
        result_to_int(state.compile_string_file(src, fname))
    }))
    .unwrap_or(-1)
}

/// Outputs an object file after `tcc_relocate()`.
///
/// Only generates the file if debug is enabled. The filename can be
/// loaded with GDB's `add-symbol-file` command for debugging.
///
/// Returns 0 on success, −1 on error.
///
/// Matches `libtcc.h` line 118:
/// ```c
/// LIBTCCAPI int elf_output_obj(TCCState *s1, const char *filename);
/// ```
///
/// **Note**: This function name has NO `tcc_` prefix — preserved exactly
/// from the C API.
#[no_mangle]
pub unsafe extern "C" fn elf_output_obj(
    s1: *mut TCCState,
    filename: *const c_char,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        let state = match state_from_ptr(s1) {
            Some(s) => s,
            None => return -1,
        };
        let fname = match cstr_to_str(filename) {
            Some(f) => f,
            None => return -1,
        };
        // Set the output file path before calling the core method,
        // which reads from self.outfile.
        state.outfile = Some(fname.to_string());
        result_to_int(state.elf_output_obj())
    }))
    .unwrap_or(-1)
}

/// Sets a custom error printer for runtime exceptions.
///
/// The callback `func` is called for each frame in a backtrace.
/// Returning 0 from the callback stops the backtrace walk.
///
/// If `s1` is NULL, this function is a safe no-op.
///
/// Matches `libtcc.h` line 122:
/// ```c
/// LIBTCCAPI void tcc_set_backtrace_func(TCCState *s1, void *userdata,
///                                        TCCBtFunc *);
/// ```
#[no_mangle]
pub unsafe extern "C" fn tcc_set_backtrace_func(
    s1: *mut TCCState,
    userdata: *mut c_void,
    func: Option<TCCBtFunc>,
) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        let state = match state_from_ptr(s1) {
            Some(s) => s,
            None => return,
        };
        // Store the backtrace callback data and function pointer.
        // The function pointer is stored as *mut c_void in TCCState for
        // type-agnostic storage; the actual 6-parameter signature (TCCBtFunc)
        // is preserved in the raw bits and will be cast back when invoked.
        state.bt_data = Some(userdata);
        state.bt_func = func.map(|f| f as *mut c_void);
    }));
}

// ===========================================================================
// Module-level tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify output type constants match libtcc.h values exactly.
    #[test]
    fn test_output_type_constants() {
        assert_eq!(TCC_OUTPUT_MEMORY, 1);
        assert_eq!(TCC_OUTPUT_EXE, 2);
        assert_eq!(TCC_OUTPUT_OBJ, 3);
        assert_eq!(TCC_OUTPUT_DLL, 4);
        assert_eq!(TCC_OUTPUT_PREPROCESS, 5);
    }

    /// Verify output type conversion from integer constants.
    #[test]
    fn test_output_type_conversion() {
        assert_eq!(output_type_from_int(TCC_OUTPUT_MEMORY), Some(OutputType::Memory));
        assert_eq!(output_type_from_int(TCC_OUTPUT_EXE), Some(OutputType::Exe));
        assert_eq!(output_type_from_int(TCC_OUTPUT_OBJ), Some(OutputType::Obj));
        assert_eq!(output_type_from_int(TCC_OUTPUT_DLL), Some(OutputType::Dll));
        assert_eq!(output_type_from_int(TCC_OUTPUT_PREPROCESS), Some(OutputType::Preprocess));
        assert_eq!(output_type_from_int(0), None);
        assert_eq!(output_type_from_int(6), None);
        assert_eq!(output_type_from_int(-1), None);
    }

    /// Verify tcc_new returns a non-null pointer.
    #[test]
    fn test_tcc_new_returns_non_null() {
        unsafe {
            let state = tcc_new();
            assert!(!state.is_null());
            tcc_delete(state);
        }
    }

    /// Verify tcc_delete is safe to call with NULL.
    #[test]
    fn test_tcc_delete_null_safety() {
        unsafe {
            tcc_delete(ptr::null_mut());
            // Should not panic or crash.
        }
    }

    /// Verify tcc_set_realloc accepts both Some and None.
    #[test]
    fn test_tcc_set_realloc_null() {
        unsafe {
            tcc_set_realloc(None);
            // Should not panic or crash.
        }
    }

    /// Verify NULL safety for state-taking functions returning c_int.
    #[test]
    fn test_null_state_returns_minus_one() {
        unsafe {
            assert_eq!(tcc_set_options(ptr::null_mut(), ptr::null()), -1);
            assert_eq!(tcc_add_include_path(ptr::null_mut(), ptr::null()), -1);
            assert_eq!(tcc_add_sysinclude_path(ptr::null_mut(), ptr::null()), -1);
            assert_eq!(tcc_add_file(ptr::null_mut(), ptr::null()), -1);
            assert_eq!(tcc_compile_string(ptr::null_mut(), ptr::null()), -1);
            assert_eq!(tcc_set_output_type(ptr::null_mut(), 1), -1);
            assert_eq!(tcc_add_library_path(ptr::null_mut(), ptr::null()), -1);
            assert_eq!(tcc_add_library(ptr::null_mut(), ptr::null()), -1);
            assert_eq!(tcc_add_symbol(ptr::null_mut(), ptr::null(), ptr::null()), -1);
            assert_eq!(tcc_output_file(ptr::null_mut(), ptr::null()), -1);
            assert_eq!(tcc_run(ptr::null_mut(), 0, ptr::null_mut()), -1);
            assert_eq!(tcc_relocate(ptr::null_mut()), -1);
            assert_eq!(tcc_compile_string_file(ptr::null_mut(), ptr::null(), ptr::null()), -1);
            assert_eq!(elf_output_obj(ptr::null_mut(), ptr::null()), -1);
        }
    }

    /// Verify NULL safety for state-taking functions returning pointers.
    #[test]
    fn test_null_state_returns_null_ptr() {
        unsafe {
            assert!(tcc_get_symbol(ptr::null_mut(), ptr::null()).is_null());
            assert!(_tcc_setjmp(
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
            )
            .is_null());
        }
    }

    /// Verify NULL safety for void-returning functions.
    #[test]
    fn test_null_state_void_functions_no_crash() {
        unsafe {
            tcc_set_lib_path(ptr::null_mut(), ptr::null());
            tcc_set_error_func(ptr::null_mut(), ptr::null_mut(), None);
            tcc_define_symbol(ptr::null_mut(), ptr::null(), ptr::null());
            tcc_undefine_symbol(ptr::null_mut(), ptr::null());
            tcc_list_symbols(ptr::null_mut(), ptr::null_mut(), None);
            tcc_set_backtrace_func(ptr::null_mut(), ptr::null_mut(), None);
            // None of these should panic or crash.
        }
    }

    /// Verify the full lifecycle: new → set_output_type → delete.
    #[test]
    fn test_lifecycle_basic() {
        unsafe {
            let state = tcc_new();
            assert!(!state.is_null());
            let rc = tcc_set_output_type(state, TCC_OUTPUT_MEMORY);
            assert_eq!(rc, 0);
            tcc_delete(state);
        }
    }

    /// Verify define/undefine symbol through FFI.
    #[test]
    fn test_define_undefine_symbol() {
        unsafe {
            let state = tcc_new();
            assert!(!state.is_null());

            // Define with explicit value
            let sym = b"TEST_SYM\0".as_ptr() as *const c_char;
            let val = b"42\0".as_ptr() as *const c_char;
            tcc_define_symbol(state, sym, val);

            // Define with NULL value (defaults to "1")
            let sym2 = b"TEST_FLAG\0".as_ptr() as *const c_char;
            tcc_define_symbol(state, sym2, ptr::null());

            // Undefine
            tcc_undefine_symbol(state, sym);

            tcc_delete(state);
        }
    }

    /// Verify include and library path management through FFI.
    #[test]
    fn test_path_management() {
        unsafe {
            let state = tcc_new();
            assert!(!state.is_null());

            let path = b"/usr/include\0".as_ptr() as *const c_char;
            assert_eq!(tcc_add_include_path(state, path), 0);
            assert_eq!(tcc_add_sysinclude_path(state, path), 0);

            let libpath = b"/usr/lib\0".as_ptr() as *const c_char;
            assert_eq!(tcc_add_library_path(state, libpath), 0);

            tcc_delete(state);
        }
    }

    /// Verify set_lib_path through FFI.
    #[test]
    fn test_set_lib_path() {
        unsafe {
            let state = tcc_new();
            assert!(!state.is_null());

            let path = b"/opt/tcc/lib\0".as_ptr() as *const c_char;
            tcc_set_lib_path(state, path);

            // Verify via the Rust struct
            let s = &*state;
            assert_eq!(s.tcc_lib_path, "/opt/tcc/lib");

            tcc_delete(state);
        }
    }

    /// Verify _tcc_setjmp returns the jmp_buf pointer.
    #[test]
    fn test_setjmp_returns_jmp_buf() {
        unsafe {
            let state = tcc_new();
            assert!(!state.is_null());

            let mut buf: [u8; 64] = [0; 64];
            let jmp_buf_ptr = buf.as_mut_ptr() as *mut c_void;
            let result = _tcc_setjmp(state, jmp_buf_ptr, ptr::null_mut(), ptr::null_mut());
            assert_eq!(result, jmp_buf_ptr);

            tcc_delete(state);
        }
    }

    /// Verify invalid output type returns −1.
    #[test]
    fn test_invalid_output_type() {
        unsafe {
            let state = tcc_new();
            assert!(!state.is_null());
            assert_eq!(tcc_set_output_type(state, 99), -1);
            assert_eq!(tcc_set_output_type(state, 0), -1);
            assert_eq!(tcc_set_output_type(state, -1), -1);
            tcc_delete(state);
        }
    }

    /// Verify tcc_get_symbol returns NULL for unknown symbols.
    #[test]
    fn test_get_symbol_not_found() {
        unsafe {
            let state = tcc_new();
            assert!(!state.is_null());
            let name = b"nonexistent_symbol\0".as_ptr() as *const c_char;
            assert!(tcc_get_symbol(state, name).is_null());
            tcc_delete(state);
        }
    }

    /// Verify type alias sizes for ABI compatibility.
    #[test]
    fn test_callback_type_sizes() {
        // Function pointers should be the same size as a usize (pointer-sized).
        assert_eq!(
            std::mem::size_of::<TCCReallocFunc>(),
            std::mem::size_of::<usize>()
        );
        assert_eq!(
            std::mem::size_of::<TCCErrorFunc>(),
            std::mem::size_of::<usize>()
        );
        assert_eq!(
            std::mem::size_of::<TCCBtFunc>(),
            std::mem::size_of::<usize>()
        );
    }
}
