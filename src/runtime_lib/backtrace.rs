//! Backtrace infrastructure for the TCC runtime.
//!
//! Provides backtrace initialization, logging, and Windows DLL helper resolution
//! for programs compiled with tinycc-rs. Combines functionality from three C source files:
//! - `lib/bt-exe.c` (69 lines) — runtime context chain management and signal handler setup
//! - `lib/bt-log.c` (57 lines) — backtrace message formatting with fallback
//! - `lib/bt-dll.c` (75 lines) — Windows DLL symbol redirection stubs
//!
//! The backtrace system supports:
//! - Runtime context chain: a `Vec<RtContext>` protected by `Mutex`, replacing the C
//!   linked-list `g_rc` pointer protected by `rt_wait_sem`/`rt_post_sem` semaphores
//! - Signal/exception handler installation for crash reporting (delegated to `runtime.rs`)
//! - Format-string backtrace output with configurable handler and stderr fallback
//! - Windows DLL symbol resolution for bounds-checking helpers
//!
//! # Safety
//!
//! This module contains **no `unsafe` blocks**. All pointer operations become `usize`
//! addresses; actual platform calls (signal handlers, Windows API) are delegated to
//! `src/runtime.rs` which is the only module permitted to use `unsafe` per AAP §0.7.2.

// This module's items are pub(crate) and consumed by sibling modules (runtime.rs,
// bcheck.rs, etc.) that may be built in parallel. Allow dead_code to prevent false
// positives during incremental compilation.
#![allow(dead_code)]

use std::sync::Mutex;

/// Type alias for the backtrace handler callback function.
///
/// A handler receives a reference to the backtrace frame and a pre-formatted
/// message string, returning the number of characters processed.
///
/// C equivalent: function pointer `_tcc_backtrace` (weak symbol in `bt-log.c`).
pub(crate) type BacktraceHandler<'a> = Option<&'a dyn Fn(&RtFrame, &str) -> i32>;

// ---------------------------------------------------------------------------
// Core types (from bt-log.c and tccrun.c included via bt-exe.c)
// ---------------------------------------------------------------------------

/// Backtrace frame capturing instruction, frame, and stack pointers.
///
/// C equivalent: `struct rt_frame { void *ip, *fp, *sp; }` in `bt-log.c` lines 21–23.
///
/// Used to capture the execution state at the point where a backtrace is requested.
/// The three pointers are stored as `usize` (address-sized integers) instead of
/// raw pointers, maintaining memory safety while preserving the information.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct RtFrame {
    /// Instruction pointer (return address) at the backtrace capture site.
    pub(crate) ip: usize,
    /// Frame pointer — points to the caller's stack frame.
    pub(crate) fp: usize,
    /// Stack pointer — top of the stack at the capture site.
    pub(crate) sp: usize,
}

impl RtFrame {
    /// Create a new `RtFrame` with the given instruction, frame, and stack pointers.
    ///
    /// # Arguments
    /// * `ip` — Instruction pointer (return address)
    /// * `fp` — Frame pointer
    /// * `sp` — Stack pointer
    pub(crate) fn new(ip: usize, fp: usize, sp: usize) -> Self {
        Self { ip, fp, sp }
    }
}

/// Runtime context node in the backtrace chain.
///
/// C equivalent: `rt_context` struct from `tccrun.c` (included via `bt-exe.c`
/// with `CONFIG_TCC_BACKTRACE_ONLY`). Contains debug symbol tables,
/// bounds-checking start pointer, text section bounds, and the top-level
/// function address.
///
/// In the C version, `rt_context` nodes form a singly-linked list via a `next`
/// pointer. In Rust, they are stored in a `Vec<RtContext>` protected by a `Mutex`,
/// eliminating all raw pointer manipulation.
#[derive(Debug)]
pub(crate) struct RtContext {
    /// STABS symbol table base address.
    ///
    /// Points to the start of the `.stab` section data for this module.
    /// Used by `rt_printline` to resolve instruction pointers to source locations.
    pub(crate) stab_sym: usize,

    /// STABS string table base address.
    ///
    /// Points to the `.stabstr` section data containing file and function names
    /// referenced by the STABS entries at `stab_sym`.
    pub(crate) stab_str: usize,

    /// Number of STABS entries in the symbol table.
    ///
    /// C equivalent: `stab_sym_cnt` field in `rt_context`.
    pub(crate) stab_count: usize,

    /// Bounds-checking data start address (0 if no bounds checking).
    ///
    /// When non-zero, this field triggers bounds-checker initialization
    /// in `bt_init` (equivalent to `__bound_init(p->bounds_start, -1)` in C)
    /// and cleanup in `bt_exit` (equivalent to `__bound_exit_dll(p->bounds_start)`).
    pub(crate) bounds_start: usize,

    /// Top-level function address (main for executables, 0 for DLLs).
    ///
    /// In the C version, this is set to `main` via a weak symbol declaration
    /// when `is_exe` is true during `__bt_init`. Used by the exception handler
    /// to determine the stack unwinding boundary.
    pub(crate) top_func: usize,

    /// Text section base address for this module.
    ///
    /// All instruction pointers within this module fall in the range
    /// `[text_base, text_base + text_size)`.
    pub(crate) text_base: usize,

    /// Text section size in bytes for this module.
    pub(crate) text_size: usize,
}

impl RtContext {
    /// Create a new `RtContext` with the given parameters.
    ///
    /// All fields are set explicitly — there are no optional or defaultable fields.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        stab_sym: usize,
        stab_str: usize,
        stab_count: usize,
        bounds_start: usize,
        top_func: usize,
        text_base: usize,
        text_size: usize,
    ) -> Self {
        Self {
            stab_sym,
            stab_str,
            stab_count,
            bounds_start,
            top_func,
            text_base,
            text_size,
        }
    }

    /// Check whether an instruction pointer falls within this context's text section.
    ///
    /// Returns `true` if `ip` is in the range `[text_base, text_base + text_size)`.
    pub(crate) fn contains_ip(&self, ip: usize) -> bool {
        ip >= self.text_base && ip < self.text_base.saturating_add(self.text_size)
    }
}

// ---------------------------------------------------------------------------
// Global backtrace context chain (from bt-exe.c)
// ---------------------------------------------------------------------------

/// Global backtrace context chain protected by mutex.
///
/// C equivalent: `g_rc` global pointer + `rt_wait_sem`/`rt_post_sem` semaphore pair
/// in `bt-exe.c`. The C version uses a singly-linked list of `rt_context` nodes;
/// the Rust version uses a `Vec<RtContext>` which provides bounds-checked access,
/// automatic growth, and safe iteration.
///
/// `Mutex::new()` is const since Rust 1.63 and `Vec::new()` is const since Rust 1.39,
/// so this static initialization is valid at MSRV 1.70.
static RT_CHAIN: Mutex<Vec<RtContext>> = Mutex::new(Vec::new());

// ---------------------------------------------------------------------------
// bt-exe.c functions: bt_init, bt_exit, pstrcpy
// ---------------------------------------------------------------------------

/// Initialize backtrace support for an executable or DLL.
///
/// C equivalent: `__bt_init(rt_context *p, int is_exe)` in `bt-exe.c` lines 15–36.
///
/// This function performs three tasks:
/// 1. If `bounds_start` is set on the context, the bounds checker should be
///    initialized (this is delegated to the `bcheck` module — the caller is
///    responsible for calling `bcheck::init` separately if needed).
/// 2. Adds the context to the global chain under mutex protection, replacing
///    the C pattern of `rt_wait_sem(); p->next = g_rc; g_rc = p; rt_post_sem();`.
/// 3. If `is_exe` is true, the caller should set up the exception/signal handler
///    (delegated to `runtime.rs`).
///
/// # Arguments
/// * `ctx` — The runtime context to add to the backtrace chain. Ownership is
///   transferred to the global chain.
/// * `is_exe` — `true` if this is the main executable (sets up top-level
///   exception handling), `false` for shared libraries/DLLs.
///
/// # Panics
/// Panics if the backtrace chain mutex is poisoned (indicates a prior panic
/// while holding the lock — an unrecoverable state).
pub(crate) fn bt_init(ctx: RtContext, is_exe: bool) {
    // Note: If ctx.bounds_start != 0, the caller should invoke bounds checker
    // initialization. This is equivalent to the C weak-symbol call:
    //   if (p->bounds_start) __bound_init(p->bounds_start, -1);
    // The actual bcheck::init call is made by the caller (runtime.rs) since
    // this module has no dependency on the bcheck module.

    // Add to chain under mutex protection.
    // C equivalent: rt_wait_sem(); p->next = g_rc; g_rc = p; rt_post_sem();
    let mut chain = RT_CHAIN.lock().expect("invariant: backtrace chain lock poisoned");
    chain.push(ctx);

    if is_exe {
        // In the C version: p->top_func = main; set_exception_handler();
        // Signal/exception handler setup is delegated to runtime.rs since it
        // requires platform-specific unsafe code (sigaction / SetUnhandledExceptionFilter).
        // The top_func field should already be set by the caller before calling bt_init.
    }
}

/// Remove a runtime context from the backtrace chain.
///
/// C equivalent: `__bt_exit(rt_context *p)` in `bt-exe.c` lines 38–57.
///
/// Performs two tasks:
/// 1. If the removed context has a non-zero `bounds_start`, the caller should
///    invoke bounds checker cleanup (equivalent to `__bound_exit_dll(p->bounds_start)`).
/// 2. Removes the context from the global chain by matching `text_base`, replacing
///    the C linked-list traversal with `Vec::retain()`.
///
/// # Arguments
/// * `text_base` — The text section base address identifying which context to remove.
///   This uniquely identifies a loaded module (each module has a distinct text section).
///
/// # Returns
/// `true` if a context was found and removed, `false` if no matching context existed.
///
/// # Panics
/// Panics if the backtrace chain mutex is poisoned.
pub(crate) fn bt_exit(text_base: usize) -> bool {
    let mut chain = RT_CHAIN.lock().expect("invariant: backtrace chain lock poisoned");
    let initial_len = chain.len();

    // Note: If the removed context has bounds_start != 0, the caller should invoke
    // __bound_exit_dll equivalent cleanup. We check for bounds_start before removal.
    // The caller (runtime.rs) handles this.

    // C equivalent: for (pp = &g_rc; rc = *pp, rc; pp = &rc->next)
    //                   if (rc == p) { *pp = rc->next; break; }
    chain.retain(|ctx| ctx.text_base != text_base);

    chain.len() < initial_len
}

/// Copy a string with truncation into a fixed-size buffer.
///
/// C equivalent: `pstrcpy(char *buf, size_t buf_size, const char *s)` in
/// `bt-exe.c` lines 60–68.
///
/// Copies at most `buf.len() - 1` bytes from `s` into `buf`, then null-terminates.
/// This is the safe Rust equivalent of the C bounded string copy — no buffer
/// overflow is possible because all operations use checked slice indexing.
///
/// # Arguments
/// * `buf` — Destination buffer. Must have capacity for at least 1 byte (the null
///   terminator). If empty, nothing is written.
/// * `s` — Source byte slice to copy.
///
/// # Returns
/// The number of bytes copied (not counting the null terminator).
///
/// # Examples
/// ```ignore
/// let mut buf = [0u8; 10];
/// let copied = pstrcpy(&mut buf, b"hello");
/// assert_eq!(copied, 5);
/// assert_eq!(&buf[..6], b"hello\0");
/// ```
pub(crate) fn pstrcpy(buf: &mut [u8], s: &[u8]) -> usize {
    if buf.is_empty() {
        return 0;
    }

    // Copy at most buf_size - 1 bytes (reserve one for null terminator).
    // C equivalent: int l = strlen(s); if (l >= buf_size) l = buf_size - 1;
    let max_copy = buf.len().saturating_sub(1);
    let copy_len = s.len().min(max_copy);

    // C equivalent: memcpy(buf, s, l);
    buf[..copy_len].copy_from_slice(&s[..copy_len]);

    // C equivalent: buf[l] = 0;
    buf[copy_len] = 0;

    copy_len
}

// ---------------------------------------------------------------------------
// bt-log.c functions: tcc_backtrace_log, parse_backtrace_format
// ---------------------------------------------------------------------------

/// Result of parsing a backtrace format string.
///
/// Contains the stripped message body and a flag indicating whether a trailing
/// newline should be appended (matching the C version's `nl` variable behavior).
struct BacktraceFormatResult<'a> {
    /// The message body after stripping `^...^` prefix and `\x01` marker.
    message: &'a str,
    /// Whether to append a trailing newline (`true` by default; set to `false`
    /// when the `\x01` no-newline marker is present).
    add_newline: bool,
}

/// Parse a backtrace format string, handling `^` delimiter and `\x01` no-newline marker.
///
/// C equivalent: format parsing at `bt-log.c` lines 41–49.
///
/// The format string may contain two special prefixes:
/// 1. **`^prefix^`**: A caret-delimited prefix (e.g., `^file:line^message`). The prefix
///    and both carets are stripped, leaving only the message body. This prefix typically
///    contains source location information for structured backtrace output.
/// 2. **`\x01`**: A SOH (Start of Heading) byte that suppresses the trailing newline.
///    This allows multiple backtrace messages to be concatenated on a single line.
///
/// The `^prefix^` stripping is applied first, then the `\x01` check.
///
/// # Arguments
/// * `fmt` — The raw format string, possibly containing `^...^` prefix and/or `\x01` marker.
///
/// # Returns
/// A `BacktraceFormatResult` with the stripped message and newline flag.
fn parse_backtrace_format(fmt: &str) -> BacktraceFormatResult<'_> {
    let mut s = fmt;

    // Step 1: Strip '^...^' prefix if present.
    // C equivalent: if (fmt[0] == '^' && (p = strchr(fmt + 1, fmt[0])))
    //                   fmt = p + 1;
    if s.starts_with('^') {
        if let Some(pos) = s[1..].find('^') {
            // pos is relative to s[1..], so the second '^' is at index pos+1 in s.
            // Skip past the second '^': new start is at pos + 2.
            s = &s[pos + 2..];
        }
    }

    // Step 2: Strip '\x01' no-newline marker if present.
    // C equivalent: if (fmt[0] == '\001') ++fmt, nl = "";
    let add_newline = !s.starts_with('\x01');
    if !add_newline {
        s = &s[1..];
    }

    BacktraceFormatResult {
        message: s,
        add_newline,
    }
}

/// Format and output a backtrace message.
///
/// C equivalent: `tcc_backtrace(const char *fmt, ...)` in `bt-log.c` lines 28–52.
///
/// If a full backtrace handler is registered (from `tccrun` / `runtime.rs`), this
/// function delegates to it with the captured frame and pre-formatted message. The
/// handler is equivalent to the C weak symbol `_tcc_backtrace`.
///
/// If **no** handler is available (fallback mode), the function parses the format
/// string prefix and outputs directly to stderr:
/// - `'^'` delimiter: skip the `^prefix^` portion (typically contains source location)
/// - `'\x01'` prefix byte: suppress the trailing newline
///
/// # Arguments
/// * `frame` — The backtrace frame capturing IP/FP/SP at the call site.
/// * `fmt` — The pre-formatted message string (may contain `^...^` and `\x01` prefixes).
/// * `backtrace_handler` — Optional handler function. If `Some`, the handler receives
///   the frame and message and returns the number of characters processed. If `None`,
///   falls back to stderr output.
///
/// # Returns
/// The number of characters written/processed.
pub(crate) fn tcc_backtrace_log(
    frame: &RtFrame,
    fmt: &str,
    backtrace_handler: BacktraceHandler<'_>,
) -> i32 {
    if let Some(handler) = backtrace_handler {
        // Delegate to the full backtrace handler (equivalent to _tcc_backtrace).
        // C equivalent: ret = _tcc_backtrace(&f, fmt, ap);
        handler(frame, fmt)
    } else {
        // Fallback: parse format string prefix and output to stderr.
        // C equivalent: vfprintf(stderr, fmt, ap); fprintf(stderr, "%s", nl); fflush(stderr);
        let result = parse_backtrace_format(fmt);

        if result.add_newline {
            eprintln!("{}", result.message);
        } else {
            eprint!("{}", result.message);
            // Flush stderr explicitly, matching the C `fflush(stderr)` call.
            // Use fully-qualified path to avoid adding a top-level import.
            let _ = <std::io::Stderr as std::io::Write>::flush(&mut std::io::stderr());
        }

        // Return the number of characters written.
        // C: ret = vfprintf(stderr, fmt, ap);
        // Use saturating conversion from usize to i32 to avoid panic on huge messages.
        i32::try_from(result.message.len()).unwrap_or(i32::MAX)
    }
}

/// Find the runtime context that contains the given instruction pointer.
///
/// Searches the global backtrace chain for a context whose text section
/// encompasses `ip`. This is used during stack unwinding to resolve
/// instruction pointers to their owning module's debug information.
///
/// # Arguments
/// * `ip` — The instruction pointer to look up.
///
/// # Returns
/// A tuple of `(stab_sym, stab_str, stab_count, text_base)` for the matching
/// context, or `None` if no context contains the given `ip`.
///
/// # Panics
/// Panics if the backtrace chain mutex is poisoned.
pub(crate) fn find_context_by_ip(ip: usize) -> Option<(usize, usize, usize, usize)> {
    let chain = RT_CHAIN.lock().expect("invariant: backtrace chain lock poisoned");
    for ctx in chain.iter() {
        if ctx.contains_ip(ip) {
            return Some((ctx.stab_sym, ctx.stab_str, ctx.stab_count, ctx.text_base));
        }
    }
    None
}

/// Get a snapshot of all registered runtime contexts.
///
/// Returns the text base and size of each registered context. Useful for
/// the runtime engine to enumerate all loaded modules during stack unwinding.
///
/// # Panics
/// Panics if the backtrace chain mutex is poisoned.
pub(crate) fn get_chain_snapshot() -> Vec<(usize, usize)> {
    let chain = RT_CHAIN.lock().expect("invariant: backtrace chain lock poisoned");
    chain.iter().map(|ctx| (ctx.text_base, ctx.text_size)).collect()
}

/// Check whether any registered context has bounds checking enabled.
///
/// Returns the `bounds_start` address of the first context that has bounds
/// checking active, or `None` if no contexts use bounds checking.
///
/// # Panics
/// Panics if the backtrace chain mutex is poisoned.
pub(crate) fn find_bounds_start() -> Option<usize> {
    let chain = RT_CHAIN.lock().expect("invariant: backtrace chain lock poisoned");
    chain.iter().find(|ctx| ctx.bounds_start != 0).map(|ctx| ctx.bounds_start)
}

// ---------------------------------------------------------------------------
// bt-dll.c: Windows DLL symbol redirection stubs
// ---------------------------------------------------------------------------

/// Windows DLL symbol redirection table and initialization.
///
/// C equivalent: `REDIR_ALL` macro and `all_ptrs`/`all_names` in `bt-dll.c` lines 7–53,
/// plus `__bt_init_dll(int bcheck)` at lines 55–74.
///
/// When a DLL compiled with bounds checking is loaded on Windows, it needs to resolve
/// 28 symbols (3 backtrace + 25 bounds-checking) from the host executable. The C version
/// uses `GetProcAddress(GetModuleHandle(NULL), name)` for each symbol and stores the
/// resolved pointers in a struct, with inline assembly `jmp *` stubs for redirection.
///
/// In the Rust version, the actual Windows API calls are delegated to `runtime.rs`
/// (the only permitted `unsafe` boundary). This module provides:
/// - Symbol name constants matching the C `REDIR_ALL` macro
/// - A `DllSymbolTable` struct using `HashMap<String, usize>` for resolved addresses
/// - An `init_dll_symbols` function that accepts a resolver callback
#[cfg(target_os = "windows")]
pub(crate) mod dll_stubs {
    use std::collections::HashMap;

    /// Backtrace symbol names that are always resolved (regardless of bounds checking).
    ///
    /// C equivalent: First 3 entries of `REDIR_ALL` macro in `bt-dll.c` lines 8–10.
    pub(crate) const BACKTRACE_SYMBOLS: &[&str] = &[
        "__bt_init",
        "__bt_exit",
        "tcc_backtrace",
    ];

    /// Bounds-checking symbol names, resolved only when bounds checking is active.
    ///
    /// C equivalent: Remaining 25 entries of `REDIR_ALL` macro in `bt-dll.c` lines 12–37.
    /// These correspond to the `__bound_*` family of functions exported by `bcheck.rs`.
    ///
    /// In the C version, `__bt_init_dll(bcheck=false)` stops iterating before
    /// `__bound_ptr_add`, resolving only the 3 backtrace symbols. When `bcheck=true`,
    /// all 28 symbols are resolved.
    pub(crate) const BOUND_SYMBOLS: &[&str] = &[
        "__bound_ptr_add",
        "__bound_ptr_indir1",
        "__bound_ptr_indir2",
        "__bound_ptr_indir4",
        "__bound_ptr_indir8",
        "__bound_ptr_indir12",
        "__bound_ptr_indir16",
        "__bound_local_new",
        "__bound_local_delete",
        "__bound_new_region",
        "__bound_free",
        "__bound_malloc",
        "__bound_realloc",
        "__bound_memcpy",
        "__bound_memcmp",
        "__bound_memmove",
        "__bound_memset",
        "__bound_strlen",
        "__bound_strcpy",
        "__bound_strncpy",
        "__bound_strcmp",
        "__bound_strncmp",
        "__bound_strcat",
        "__bound_strchr",
        "__bound_strdup",
    ];

    /// Resolved symbol addresses for DLL redirection.
    ///
    /// C equivalent: `all_ptrs` struct in `bt-dll.c` line 46.
    ///
    /// Stores the resolved addresses of backtrace and bounds-checking symbols
    /// as a `HashMap<String, usize>`. The C version uses a struct with one
    /// `void*` field per symbol; the Rust version uses a dynamic map for
    /// flexibility and safety.
    #[derive(Debug)]
    pub(crate) struct DllSymbolTable {
        /// Map from symbol name to resolved address.
        pub(crate) symbols: HashMap<String, usize>,
    }

    impl DllSymbolTable {
        /// Look up a resolved symbol address by name.
        ///
        /// Returns `Some(address)` if the symbol was resolved, `None` otherwise.
        pub(crate) fn get_symbol(&self, name: &str) -> Option<usize> {
            self.symbols.get(name).copied()
        }

        /// Get the total number of resolved symbols.
        pub(crate) fn symbol_count(&self) -> usize {
            self.symbols.len()
        }
    }

    /// Initialize DLL symbol redirection by resolving symbols from the host executable.
    ///
    /// C equivalent: `__bt_init_dll(int bcheck)` in `bt-dll.c` lines 55–74.
    ///
    /// The function iterates through the backtrace symbols (always) and bounds-checking
    /// symbols (only if `bcheck` is `true`), calling the `resolver` for each symbol name.
    /// If any symbol cannot be resolved, returns an error with a descriptive message
    /// matching the C version's `MessageBox`/`fprintf` fatal error.
    ///
    /// # Arguments
    /// * `bcheck` — If `true`, resolve all 28 symbols (backtrace + bounds). If `false`,
    ///   resolve only the 3 backtrace symbols.
    /// * `resolver` — A callback that takes a symbol name and returns its resolved
    ///   address, or `None` if the symbol was not found. In production, this wraps
    ///   `GetProcAddress(GetModuleHandle(NULL), name)` from `runtime.rs`.
    ///
    /// # Returns
    /// * `Ok(DllSymbolTable)` — All required symbols were resolved successfully.
    /// * `Err(String)` — A symbol could not be resolved. The error message matches
    ///   the C format: `"Error: function '<name>()' not found in executable.
    ///   (Need -bt or -b for linking the exe.)"`.
    pub(crate) fn init_dll_symbols(
        bcheck: bool,
        resolver: impl Fn(&str) -> Option<usize>,
    ) -> Result<DllSymbolTable, String> {
        let mut table = DllSymbolTable {
            symbols: HashMap::new(),
        };

        // Always resolve backtrace symbols.
        // C equivalent: do { *p = GetProcAddress(GetModuleHandle(NULL), s); ... }
        for &name in BACKTRACE_SYMBOLS {
            let addr = resolver(name).ok_or_else(|| {
                format!(
                    "Error: function '{}()' not found in executable. \
                     (Need -bt or -b for linking the exe.)",
                    name
                )
            })?;
            table.symbols.insert(name.to_string(), addr);
        }

        // Resolve bounds-checking symbols only if bounds checking is active.
        // C equivalent: while (*s && (bcheck || p < &all_ptrs.__bound_ptr_add))
        if bcheck {
            for &name in BOUND_SYMBOLS {
                let addr = resolver(name).ok_or_else(|| {
                    format!(
                        "Error: function '{}()' not found in executable. \
                         (Need -bt or -b for linking the exe.)",
                        name
                    )
                })?;
                table.symbols.insert(name.to_string(), addr);
            }
        }

        Ok(table)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rt_frame_default() {
        let frame = RtFrame::default();
        assert_eq!(frame.ip, 0);
        assert_eq!(frame.fp, 0);
        assert_eq!(frame.sp, 0);
    }

    #[test]
    fn test_rt_frame_new() {
        let frame = RtFrame::new(0x1000, 0x2000, 0x3000);
        assert_eq!(frame.ip, 0x1000);
        assert_eq!(frame.fp, 0x2000);
        assert_eq!(frame.sp, 0x3000);
    }

    #[test]
    fn test_rt_context_contains_ip() {
        let ctx = RtContext::new(0, 0, 0, 0, 0, 0x4000, 0x1000);
        assert!(ctx.contains_ip(0x4000));
        assert!(ctx.contains_ip(0x4FFF));
        assert!(!ctx.contains_ip(0x5000));
        assert!(!ctx.contains_ip(0x3FFF));
    }

    #[test]
    fn test_pstrcpy_basic() {
        let mut buf = [0u8; 10];
        let copied = pstrcpy(&mut buf, b"hello");
        assert_eq!(copied, 5);
        assert_eq!(&buf[..6], b"hello\0");
    }

    #[test]
    fn test_pstrcpy_truncation() {
        let mut buf = [0u8; 4];
        let copied = pstrcpy(&mut buf, b"hello world");
        assert_eq!(copied, 3);
        assert_eq!(&buf[..4], b"hel\0");
    }

    #[test]
    fn test_pstrcpy_empty_source() {
        let mut buf = [0u8; 10];
        let copied = pstrcpy(&mut buf, b"");
        assert_eq!(copied, 0);
        assert_eq!(buf[0], 0);
    }

    #[test]
    fn test_pstrcpy_empty_buffer() {
        let mut buf: [u8; 0] = [];
        let copied = pstrcpy(&mut buf, b"hello");
        assert_eq!(copied, 0);
    }

    #[test]
    fn test_pstrcpy_single_byte_buffer() {
        let mut buf = [0xFFu8; 1];
        let copied = pstrcpy(&mut buf, b"hello");
        assert_eq!(copied, 0);
        assert_eq!(buf[0], 0);
    }

    #[test]
    fn test_parse_backtrace_format_plain() {
        let result = parse_backtrace_format("hello world");
        assert_eq!(result.message, "hello world");
        assert!(result.add_newline);
    }

    #[test]
    fn test_parse_backtrace_format_caret_prefix() {
        let result = parse_backtrace_format("^file.c:42^error message");
        assert_eq!(result.message, "error message");
        assert!(result.add_newline);
    }

    #[test]
    fn test_parse_backtrace_format_no_newline() {
        let result = parse_backtrace_format("\x01continued message");
        assert_eq!(result.message, "continued message");
        assert!(!result.add_newline);
    }

    #[test]
    fn test_parse_backtrace_format_caret_and_no_newline() {
        let result = parse_backtrace_format("^loc^\x01message");
        assert_eq!(result.message, "message");
        assert!(!result.add_newline);
    }

    #[test]
    fn test_parse_backtrace_format_single_caret() {
        // Only one caret — no stripping occurs.
        let result = parse_backtrace_format("^incomplete");
        assert_eq!(result.message, "^incomplete");
        assert!(result.add_newline);
    }

    #[test]
    fn test_tcc_backtrace_log_with_handler() {
        let frame = RtFrame::new(0x1000, 0x2000, 0x3000);
        let handler = |_f: &RtFrame, msg: &str| -> i32 {
            i32::try_from(msg.len()).unwrap_or(0)
        };
        let ret = tcc_backtrace_log(&frame, "test message", Some(&handler));
        assert_eq!(ret, 12); // "test message".len() == 12
    }

    #[test]
    fn test_tcc_backtrace_log_fallback() {
        let frame = RtFrame::default();
        let ret = tcc_backtrace_log(&frame, "fallback", None);
        assert_eq!(ret, 8); // "fallback".len() == 8
    }

    #[test]
    fn test_bt_init_and_exit() {
        // Clear any leftover state from other tests.
        {
            let mut chain = RT_CHAIN.lock().expect("lock");
            chain.clear();
        }

        let ctx = RtContext::new(0x100, 0x200, 10, 0, 0, 0x5000, 0x1000);
        bt_init(ctx, false);

        // Verify context was added.
        {
            let chain = RT_CHAIN.lock().expect("lock");
            assert_eq!(chain.len(), 1);
            assert_eq!(chain[0].text_base, 0x5000);
        }

        // Remove context.
        let removed = bt_exit(0x5000);
        assert!(removed);

        // Verify chain is empty.
        {
            let chain = RT_CHAIN.lock().expect("lock");
            assert!(chain.is_empty());
        }
    }

    #[test]
    fn test_bt_exit_nonexistent() {
        // Clear any leftover state.
        {
            let mut chain = RT_CHAIN.lock().expect("lock");
            chain.clear();
        }

        let removed = bt_exit(0xDEAD);
        assert!(!removed);
    }

    #[test]
    fn test_find_context_by_ip() {
        // Clear any leftover state.
        {
            let mut chain = RT_CHAIN.lock().expect("lock");
            chain.clear();
        }

        let ctx = RtContext::new(0xA00, 0xB00, 5, 0, 0, 0x8000, 0x2000);
        bt_init(ctx, false);

        let found = find_context_by_ip(0x9000);
        assert!(found.is_some());
        let (stab_sym, stab_str, stab_count, text_base) = found.unwrap();
        assert_eq!(stab_sym, 0xA00);
        assert_eq!(stab_str, 0xB00);
        assert_eq!(stab_count, 5);
        assert_eq!(text_base, 0x8000);

        // IP outside range.
        assert!(find_context_by_ip(0xA001).is_none());

        // Clean up.
        bt_exit(0x8000);
    }
}
