// Allow dead_code at module level: this runtime library module's public types
// will be consumed by src/runtime.rs and src/context.rs once those modules are
// fully wired up. During incremental crate assembly, no consumers exist yet.
#![allow(dead_code)]

//! Constructor/destructor handling for the TCC runtime.
//!
//! Provides `_runmain` entry-point logic, constructor/destructor array iteration,
//! and `atexit`/`on_exit` registration tables used by programs compiled with `tcc -run`.
//!
//! C equivalent: `lib/runmain.c` (87 lines)
//!
//! ## Overview
//!
//! When a program is executed via `tcc -run`, the runtime needs to:
//! 1. Run constructors from the `.init_array` section (non-Windows)
//! 2. Call the program's `main()` function
//! 3. Run destructors from the `.fini_array` section (reverse order)
//! 4. Execute registered `atexit`/`on_exit` handlers in LIFO order
//!
//! This module provides the data structures and logic to manage these lifecycle
//! phases. The actual function dispatch (calling function pointers stored as
//! `usize` addresses) is performed by the runtime engine (`src/runtime.rs`),
//! not by this module directly — keeping this module entirely safe Rust.
//!
//! ## C-to-Rust Translation Notes
//!
//! - **Fixed-size arrays → `Vec`**: The C code uses `rt_exitfunc[32]` and
//!   `rt_exitarg[32]` fixed arrays. We replace these with a `Vec<ExitHandler>`
//!   pre-allocated to capacity 32, preserving the 32-slot limit while gaining
//!   bounds-checking safety.
//! - **Global mutable state → owned structs**: The C code uses `static` globals
//!   for the exit handler table. We use owned `ExitHandlerTable` instances that
//!   live inside the `TccContext`, eliminating mutable global state.
//! - **Raw pointers → `usize`**: Function pointers (`void*`) and arguments are
//!   stored as `usize` addresses. The runtime dispatches these via controlled
//!   `unsafe` blocks in `src/runtime.rs`, not here.
//! - **Platform gating**: `run_ctors` and `_runmain` logic is non-Windows in the
//!   C source (guarded by `#ifndef _WIN32`). Rust equivalents use
//!   `#[cfg(not(target_os = "windows"))]` where applicable.

/// Maximum number of exit handlers that can be registered.
///
/// C equivalent: Fixed-size arrays `rt_exitfunc[32]` and `rt_exitarg[32]` at lines 30–31
/// of `lib/runmain.c`. The limit of 32 is preserved for behavioral equivalence with
/// the original implementation.
const MAX_EXIT_HANDLERS: usize = 32;

/// Backtrace frame structure for exit handling.
///
/// C equivalent: `struct rt_frame { void *ip, *fp, *sp; }` at lines 58–60 of
/// `lib/runmain.c`. Used by `exit()` (line 64) to construct a frame for
/// `__rt_exit()` to unwind through.
///
/// In the Rust port, raw `void*` pointers are replaced with `usize` addresses,
/// eliminating the need for raw pointer types in the public interface.
///
/// # Examples
///
/// ```ignore
/// let frame = RtFrame {
///     ip: entry_address,
///     fp: 0,  // Terminal frame
///     sp: stack_top,
/// };
/// ```
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RtFrame {
    /// Instruction pointer — address of the current function.
    ///
    /// C equivalent: `void *ip` field. In `exit()` (line 70), this is set to
    /// the address of the `exit` function itself.
    pub ip: usize,

    /// Frame pointer — base of the current stack frame.
    ///
    /// C equivalent: `void *fp` field. In `exit()` (line 69), this is set to
    /// `0` (NULL) to indicate the terminal frame in a backtrace chain.
    pub fp: usize,

    /// Stack pointer — current stack position.
    ///
    /// C equivalent: `void *sp` field.
    pub sp: usize,
}

impl RtFrame {
    /// Creates a new backtrace frame with the given instruction, frame, and stack pointers.
    ///
    /// # Arguments
    ///
    /// * `ip` — Instruction pointer address
    /// * `fp` — Frame pointer address (0 for terminal frame)
    /// * `sp` — Stack pointer address
    pub fn new(ip: usize, fp: usize, sp: usize) -> Self {
        Self { ip, fp, sp }
    }

    /// Creates a terminal backtrace frame for `exit()`.
    ///
    /// C equivalent: The frame constructed at lines 66–70 of `lib/runmain.c`:
    /// ```c
    /// rt_frame f;
    /// f.fp = 0;
    /// f.ip = exit;
    /// ```
    ///
    /// The frame pointer is set to 0 to signal the end of the backtrace chain.
    pub fn terminal(exit_fn_addr: usize) -> Self {
        Self {
            ip: exit_fn_addr,
            fp: 0,
            sp: 0,
        }
    }
}

/// An exit handler entry with function address and argument.
///
/// C equivalent: Paired `rt_exitfunc[n]` + `rt_exitarg[n]` at lines 30–31 of
/// `lib/runmain.c`. Each entry stores a function address and an optional argument
/// that will be passed when the handler is invoked during program exit.
///
/// The handler function signature (from the C perspective) is:
/// `void handler(int exit_code, void *arg)`
///
/// In Rust, both the function address and argument are stored as `usize` values.
/// The runtime engine is responsible for casting these back to callable function
/// pointers via controlled `unsafe` blocks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExitHandler {
    /// The handler function address — callable as `fn(i32, usize)`.
    ///
    /// C equivalent: `rt_exitfunc[n]` — a `void*` storing the function pointer.
    pub func: usize,

    /// Optional argument passed to the handler at invocation time.
    ///
    /// C equivalent: `rt_exitarg[n]` — a `void*` storing the argument.
    /// For handlers registered via `atexit()`, this is always 0.
    pub arg: usize,
}

impl ExitHandler {
    /// Creates a new exit handler entry.
    ///
    /// # Arguments
    ///
    /// * `func` — Address of the handler function
    /// * `arg` — Argument to pass to the handler (0 for `atexit`-registered handlers)
    pub fn new(func: usize, arg: usize) -> Self {
        Self { func, arg }
    }
}

/// Exit handler table managing `atexit`/`on_exit` registrations.
///
/// C equivalent: Global arrays `rt_exitfunc[32]`, `rt_exitarg[32]`, and counter
/// `__rt_nr_exit` at lines 30–32 of `lib/runmain.c`.
///
/// This struct replaces the C global mutable state with an owned, bounded collection.
/// The table enforces a maximum of 32 handlers (matching the C implementation's
/// fixed-size arrays) and provides LIFO (last-in, first-out) execution order for
/// registered handlers.
///
/// # Capacity
///
/// The maximum number of handlers is [`MAX_EXIT_HANDLERS`] (32), matching the
/// C implementation. Attempting to register more than 32 handlers will return
/// an error, equivalent to the C code returning `1` from `on_exit()`.
///
/// # Examples
///
/// ```ignore
/// let mut table = ExitHandlerTable::new();
/// table.on_exit(handler_addr, arg_addr).expect("registration succeeded");
/// table.atexit(cleanup_addr).expect("registration succeeded");
///
/// // At exit time, run handlers in reverse registration order
/// let dispatch_list = table.run_on_exit(exit_code);
/// for (func, arg, code) in dispatch_list {
///     // Runtime dispatches the call
/// }
/// ```
pub struct ExitHandlerTable {
    /// Registered exit handlers in registration order.
    /// LIFO execution: last registered handler runs first.
    handlers: Vec<ExitHandler>,
}

impl ExitHandlerTable {
    /// Creates a new, empty exit handler table.
    ///
    /// C equivalent: Zero-initialization of `rt_exitfunc[]`, `rt_exitarg[]`,
    /// and `__rt_nr_exit = 0` at lines 30–32 of `lib/runmain.c`.
    ///
    /// The internal vector is pre-allocated with capacity for [`MAX_EXIT_HANDLERS`]
    /// (32) entries to avoid reallocation during handler registration, matching the
    /// fixed-size C array behavior.
    pub fn new() -> Self {
        Self {
            handlers: Vec::with_capacity(MAX_EXIT_HANDLERS),
        }
    }

    /// Register an `on_exit` handler with an argument.
    ///
    /// C equivalent: `on_exit(void *function, void *arg)` at lines 41–51 of
    /// `lib/runmain.c`.
    ///
    /// The handler will be called during program exit with the signature
    /// `handler(exit_code, arg)` where `exit_code` is the program's return value.
    ///
    /// # Arguments
    ///
    /// * `func` — Address of the handler function
    /// * `arg` — Argument to pass to the handler at invocation time
    ///
    /// # Returns
    ///
    /// * `Ok(())` — Handler successfully registered
    /// * `Err(())` — Table is full (32 handlers maximum). C equivalent: `return 1;`
    ///
    /// # Integer Safety
    ///
    /// The capacity check uses `self.handlers.len() < MAX_EXIT_HANDLERS` which is
    /// a safe `usize` comparison — no signed/unsigned coercion issues.
    pub fn on_exit(&mut self, func: usize, arg: usize) -> Result<(), ()> {
        if self.handlers.len() < MAX_EXIT_HANDLERS {
            self.handlers.push(ExitHandler { func, arg });
            Ok(())
        } else {
            // Table full — C equivalent returns 1 at line 50
            Err(())
        }
    }

    /// Register an `atexit` handler (no argument).
    ///
    /// C equivalent: `atexit(void (*function)(void))` at lines 53–56 of
    /// `lib/runmain.c`. This is a thin wrapper around [`on_exit`](Self::on_exit)
    /// with `arg = 0`, exactly matching the C implementation:
    /// ```c
    /// int atexit(void (*function)(void)) {
    ///     return on_exit(function, 0);
    /// }
    /// ```
    ///
    /// # Arguments
    ///
    /// * `func` — Address of the handler function
    ///
    /// # Returns
    ///
    /// * `Ok(())` — Handler successfully registered
    /// * `Err(())` — Table is full (32 handlers maximum)
    pub fn atexit(&mut self, func: usize) -> Result<(), ()> {
        self.on_exit(func, 0)
    }

    /// Produce a list of exit handlers to run, in reverse registration order.
    ///
    /// C equivalent: `__run_on_exit(int ret)` at lines 34–39 of `lib/runmain.c`:
    /// ```c
    /// void __run_on_exit(int ret) {
    ///     int n = __rt_nr_exit;
    ///     while (n)
    ///         --n, ((void(*)(int,void*))rt_exitfunc[n])(ret, rt_exitarg[n]);
    /// }
    /// ```
    ///
    /// Rather than calling function pointers directly (which would require `unsafe`),
    /// this method returns a `Vec` of `(func_addr, arg, exit_code)` tuples for the
    /// runtime engine to dispatch. The handlers are returned in LIFO order (last
    /// registered first), matching the C implementation's reverse iteration.
    ///
    /// # Arguments
    ///
    /// * `exit_code` — The program's exit code, passed to each handler
    ///
    /// # Returns
    ///
    /// A vector of `(func_address, arg, exit_code)` tuples in execution order
    /// (reverse registration order).
    pub fn run_on_exit(&self, exit_code: i32) -> Vec<(usize, usize, i32)> {
        self.handlers
            .iter()
            .rev()
            .map(|h| (h.func, h.arg, exit_code))
            .collect()
    }

    /// Get the current number of registered exit handlers.
    ///
    /// C equivalent: Reading `__rt_nr_exit` at line 32 of `lib/runmain.c`.
    ///
    /// # Returns
    ///
    /// The number of handlers currently registered (0..=32).
    pub fn count(&self) -> usize {
        self.handlers.len()
    }

    /// Check whether the exit handler table is full.
    ///
    /// Returns `true` if the table has reached its maximum capacity of 32 handlers.
    pub fn is_full(&self) -> bool {
        self.handlers.len() >= MAX_EXIT_HANDLERS
    }

    /// Clear all registered exit handlers.
    ///
    /// Useful for resetting the handler table between runs or during cleanup.
    pub fn clear(&mut self) {
        self.handlers.clear();
    }

    /// Get an immutable reference to the registered handlers slice.
    ///
    /// Handlers are in registration order (first registered = first element).
    pub fn handlers(&self) -> &[ExitHandler] {
        &self.handlers
    }
}

impl Default for ExitHandlerTable {
    fn default() -> Self {
        Self::new()
    }
}

/// Constructor array descriptor for `.init_array` section iteration.
///
/// C equivalent: The extern symbol pair `_init_array_start` / `_init_array_end`
/// at lines 11–12 of `lib/runmain.c`, iterated by `run_ctors()` at lines 13–18.
///
/// In the C implementation, constructors are called with `(argc, argv, envp)`.
/// The constructor function signature is:
/// `void constructor(int argc, char **argv, char **envp)`
///
/// In the Rust port, constructor addresses are stored as `usize` values. The
/// runtime engine is responsible for invoking them with the appropriate arguments.
///
/// # Platform Notes
///
/// Constructor execution is non-Windows only in the original C code (guarded by
/// `#ifndef _WIN32`). The Rust runtime should apply the same platform gating when
/// dispatching constructors.
pub struct ConstructorArray {
    /// Function addresses from the `.init_array` section, in forward order.
    ///
    /// C equivalent: Addresses between `_init_array_start` and `_init_array_end`.
    pub entries: Vec<usize>,
}

impl ConstructorArray {
    /// Creates a new, empty constructor array.
    ///
    /// Constructor entries are populated by the linker backend when processing
    /// the `.init_array` section of the compiled program.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Creates a constructor array from a pre-populated list of function addresses.
    ///
    /// # Arguments
    ///
    /// * `addrs` — Function addresses in the order they should be called
    pub fn from_entries(addrs: Vec<usize>) -> Self {
        Self { entries: addrs }
    }

    /// Get the constructor addresses in forward execution order.
    ///
    /// C equivalent: `run_ctors(int argc, char **argv, char **env)` at lines 13–18
    /// of `lib/runmain.c`:
    /// ```c
    /// static void run_ctors(int argc, char **argv, char **env) {
    ///     int i = 0;
    ///     while (&_init_array_start[i] != _init_array_end)
    ///         (*_init_array_start[i++])(argc, argv, env);
    /// }
    /// ```
    ///
    /// Returns a slice of addresses in forward order — each should be called
    /// with `(argc, argv, envp)` by the runtime.
    pub fn get_constructors(&self) -> &[usize] {
        &self.entries
    }

    /// Returns the number of constructors in the array.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns whether the constructor array is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Default for ConstructorArray {
    fn default() -> Self {
        Self::new()
    }
}

/// Destructor array descriptor for `.fini_array` section iteration.
///
/// C equivalent: The extern symbol pair `_fini_array_start` / `_fini_array_end`
/// at lines 21–22 of `lib/runmain.c`, iterated in reverse by `run_dtors()` at
/// lines 23–28.
///
/// In the C implementation, destructors take no arguments:
/// `void destructor(void)`
///
/// The C code iterates backwards through the array:
/// ```c
/// static void run_dtors(void) {
///     int i = 0;
///     while (&_fini_array_end[i] != _fini_array_start)
///         (*_fini_array_end[--i])();
/// }
/// ```
///
/// In the Rust port, destructor addresses are stored as `usize` values and
/// retrieved in reverse order via [`get_destructors_reversed`](Self::get_destructors_reversed).
///
/// # Platform Notes
///
/// Unlike constructors, destructor execution is cross-platform in the original
/// C code (not guarded by `#ifndef _WIN32`).
pub struct DestructorArray {
    /// Function addresses from the `.fini_array` section, in forward (storage) order.
    ///
    /// C equivalent: Addresses between `_fini_array_start` and `_fini_array_end`.
    /// Destructors are stored in forward order but executed in reverse.
    pub entries: Vec<usize>,
}

impl DestructorArray {
    /// Creates a new, empty destructor array.
    ///
    /// Destructor entries are populated by the linker backend when processing
    /// the `.fini_array` section of the compiled program.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Creates a destructor array from a pre-populated list of function addresses.
    ///
    /// # Arguments
    ///
    /// * `addrs` — Function addresses in storage order (will be reversed for execution)
    pub fn from_entries(addrs: Vec<usize>) -> Self {
        Self { entries: addrs }
    }

    /// Get the destructor addresses in reverse execution order.
    ///
    /// C equivalent: `run_dtors(void)` at lines 23–28 of `lib/runmain.c`:
    /// ```c
    /// static void run_dtors(void) {
    ///     int i = 0;
    ///     while (&_fini_array_end[i] != _fini_array_start)
    ///         (*_fini_array_end[--i])();
    /// }
    /// ```
    ///
    /// Returns a new `Vec` containing addresses in reverse order — each should be
    /// called with no arguments by the runtime.
    pub fn get_destructors_reversed(&self) -> Vec<usize> {
        self.entries.iter().rev().copied().collect()
    }

    /// Returns the number of destructors in the array.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns whether the destructor array is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Default for DestructorArray {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── RtFrame tests ──────────────────────────────────────────────────

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
    fn test_rt_frame_terminal() {
        let frame = RtFrame::terminal(0xDEAD);
        assert_eq!(frame.ip, 0xDEAD);
        assert_eq!(frame.fp, 0);
        assert_eq!(frame.sp, 0);
    }

    #[test]
    fn test_rt_frame_clone_and_copy() {
        let frame = RtFrame::new(1, 2, 3);
        let cloned = frame;
        assert_eq!(frame, cloned);
    }

    // ── ExitHandler tests ──────────────────────────────────────────────

    #[test]
    fn test_exit_handler_new() {
        let handler = ExitHandler::new(0x4000, 0x5000);
        assert_eq!(handler.func, 0x4000);
        assert_eq!(handler.arg, 0x5000);
    }

    #[test]
    fn test_exit_handler_atexit_style() {
        let handler = ExitHandler::new(0x4000, 0);
        assert_eq!(handler.arg, 0);
    }

    // ── ExitHandlerTable tests ─────────────────────────────────────────

    #[test]
    fn test_exit_handler_table_new_is_empty() {
        let table = ExitHandlerTable::new();
        assert_eq!(table.count(), 0);
        assert!(!table.is_full());
    }

    #[test]
    fn test_exit_handler_table_default() {
        let table = ExitHandlerTable::default();
        assert_eq!(table.count(), 0);
    }

    #[test]
    fn test_on_exit_registers_handler() {
        let mut table = ExitHandlerTable::new();
        assert!(table.on_exit(0x1000, 0x2000).is_ok());
        assert_eq!(table.count(), 1);
        assert_eq!(table.handlers()[0].func, 0x1000);
        assert_eq!(table.handlers()[0].arg, 0x2000);
    }

    #[test]
    fn test_atexit_registers_with_zero_arg() {
        let mut table = ExitHandlerTable::new();
        assert!(table.atexit(0x3000).is_ok());
        assert_eq!(table.count(), 1);
        assert_eq!(table.handlers()[0].func, 0x3000);
        assert_eq!(table.handlers()[0].arg, 0);
    }

    #[test]
    fn test_on_exit_full_table_returns_error() {
        let mut table = ExitHandlerTable::new();
        for i in 0..MAX_EXIT_HANDLERS {
            assert!(table.on_exit(i, 0).is_ok());
        }
        assert!(table.is_full());
        assert_eq!(table.count(), 32);
        // 33rd registration should fail
        assert!(table.on_exit(0xFFFF, 0).is_err());
        assert_eq!(table.count(), 32);
    }

    #[test]
    fn test_atexit_full_table_returns_error() {
        let mut table = ExitHandlerTable::new();
        for i in 0..MAX_EXIT_HANDLERS {
            assert!(table.atexit(i).is_ok());
        }
        assert!(table.atexit(0xFFFF).is_err());
    }

    #[test]
    fn test_run_on_exit_reverse_order() {
        let mut table = ExitHandlerTable::new();
        table.on_exit(0xA, 0x1).unwrap();
        table.on_exit(0xB, 0x2).unwrap();
        table.on_exit(0xC, 0x3).unwrap();

        let dispatch = table.run_on_exit(42);
        assert_eq!(dispatch.len(), 3);
        // LIFO order: C, B, A
        assert_eq!(dispatch[0], (0xC, 0x3, 42));
        assert_eq!(dispatch[1], (0xB, 0x2, 42));
        assert_eq!(dispatch[2], (0xA, 0x1, 42));
    }

    #[test]
    fn test_run_on_exit_empty_table() {
        let table = ExitHandlerTable::new();
        let dispatch = table.run_on_exit(0);
        assert!(dispatch.is_empty());
    }

    #[test]
    fn test_run_on_exit_single_handler() {
        let mut table = ExitHandlerTable::new();
        table.on_exit(0xDEAD, 0xBEEF).unwrap();
        let dispatch = table.run_on_exit(-1);
        assert_eq!(dispatch.len(), 1);
        assert_eq!(dispatch[0], (0xDEAD, 0xBEEF, -1));
    }

    #[test]
    fn test_clear_removes_all_handlers() {
        let mut table = ExitHandlerTable::new();
        table.on_exit(1, 2).unwrap();
        table.on_exit(3, 4).unwrap();
        assert_eq!(table.count(), 2);

        table.clear();
        assert_eq!(table.count(), 0);
        assert!(!table.is_full());
        // Can register again after clearing
        assert!(table.on_exit(5, 6).is_ok());
        assert_eq!(table.count(), 1);
    }

    // ── ConstructorArray tests ─────────────────────────────────────────

    #[test]
    fn test_constructor_array_new_is_empty() {
        let ctors = ConstructorArray::new();
        assert!(ctors.is_empty());
        assert_eq!(ctors.len(), 0);
        assert_eq!(ctors.get_constructors(), &[]);
    }

    #[test]
    fn test_constructor_array_default() {
        let ctors = ConstructorArray::default();
        assert!(ctors.is_empty());
    }

    #[test]
    fn test_constructor_array_from_entries() {
        let ctors = ConstructorArray::from_entries(vec![0x100, 0x200, 0x300]);
        assert_eq!(ctors.len(), 3);
        assert!(!ctors.is_empty());
        assert_eq!(ctors.get_constructors(), &[0x100, 0x200, 0x300]);
    }

    #[test]
    fn test_constructors_forward_order() {
        let ctors = ConstructorArray::from_entries(vec![0xA, 0xB, 0xC]);
        let addrs = ctors.get_constructors();
        // Forward order preserved: A, B, C
        assert_eq!(addrs[0], 0xA);
        assert_eq!(addrs[1], 0xB);
        assert_eq!(addrs[2], 0xC);
    }

    #[test]
    fn test_constructor_entries_mutable() {
        let mut ctors = ConstructorArray::new();
        ctors.entries.push(0x1000);
        ctors.entries.push(0x2000);
        assert_eq!(ctors.get_constructors(), &[0x1000, 0x2000]);
    }

    // ── DestructorArray tests ──────────────────────────────────────────

    #[test]
    fn test_destructor_array_new_is_empty() {
        let dtors = DestructorArray::new();
        assert!(dtors.is_empty());
        assert_eq!(dtors.len(), 0);
        assert_eq!(dtors.get_destructors_reversed(), Vec::<usize>::new());
    }

    #[test]
    fn test_destructor_array_default() {
        let dtors = DestructorArray::default();
        assert!(dtors.is_empty());
    }

    #[test]
    fn test_destructor_array_from_entries() {
        let dtors = DestructorArray::from_entries(vec![0x100, 0x200, 0x300]);
        assert_eq!(dtors.len(), 3);
        assert!(!dtors.is_empty());
    }

    #[test]
    fn test_destructors_reversed_order() {
        let dtors = DestructorArray::from_entries(vec![0xA, 0xB, 0xC]);
        let reversed = dtors.get_destructors_reversed();
        // Reverse order: C, B, A
        assert_eq!(reversed, vec![0xC, 0xB, 0xA]);
    }

    #[test]
    fn test_destructors_reversed_single() {
        let dtors = DestructorArray::from_entries(vec![0x42]);
        let reversed = dtors.get_destructors_reversed();
        assert_eq!(reversed, vec![0x42]);
    }

    #[test]
    fn test_destructor_entries_mutable() {
        let mut dtors = DestructorArray::new();
        dtors.entries.push(0x1000);
        dtors.entries.push(0x2000);
        dtors.entries.push(0x3000);
        let reversed = dtors.get_destructors_reversed();
        assert_eq!(reversed, vec![0x3000, 0x2000, 0x1000]);
    }

    // ── Integration-style tests ────────────────────────────────────────

    #[test]
    fn test_full_lifecycle() {
        // Simulate: constructors → main → destructors → exit handlers
        let ctors = ConstructorArray::from_entries(vec![0x100, 0x200]);
        let dtors = DestructorArray::from_entries(vec![0x300, 0x400]);
        let mut exit_table = ExitHandlerTable::new();

        // Phase 1: Get constructors (forward)
        let ctor_addrs = ctors.get_constructors();
        assert_eq!(ctor_addrs, &[0x100, 0x200]);

        // Phase 2: main() runs (simulated)
        let exit_code: i32 = 0;

        // Phase 3: Register exit handlers during main()
        exit_table.on_exit(0x500, 0xA).unwrap();
        exit_table.atexit(0x600).unwrap();

        // Phase 4: Get destructors (reverse)
        let dtor_addrs = dtors.get_destructors_reversed();
        assert_eq!(dtor_addrs, vec![0x400, 0x300]);

        // Phase 5: Run exit handlers (LIFO)
        let exit_dispatch = exit_table.run_on_exit(exit_code);
        assert_eq!(exit_dispatch.len(), 2);
        assert_eq!(exit_dispatch[0], (0x600, 0, 0)); // atexit handler first (LIFO)
        assert_eq!(exit_dispatch[1], (0x500, 0xA, 0)); // on_exit handler second
    }

    #[test]
    fn test_exit_code_propagated_correctly() {
        let mut table = ExitHandlerTable::new();
        table.on_exit(0x1, 0x2).unwrap();

        // Positive exit code
        let dispatch = table.run_on_exit(0);
        assert_eq!(dispatch[0].2, 0);

        // Non-zero exit code
        let dispatch = table.run_on_exit(1);
        assert_eq!(dispatch[0].2, 1);

        // Negative exit code (signal-style)
        let dispatch = table.run_on_exit(-1);
        assert_eq!(dispatch[0].2, -1);

        // Large exit code
        let dispatch = table.run_on_exit(127);
        assert_eq!(dispatch[0].2, 127);
    }

    #[test]
    fn test_max_handlers_boundary() {
        let mut table = ExitHandlerTable::new();

        // Fill to exactly MAX - 1
        for i in 0..MAX_EXIT_HANDLERS - 1 {
            assert!(table.on_exit(i, 0).is_ok());
        }
        assert_eq!(table.count(), 31);
        assert!(!table.is_full());

        // Fill the last slot
        assert!(table.on_exit(31, 0).is_ok());
        assert_eq!(table.count(), 32);
        assert!(table.is_full());

        // One more should fail
        assert!(table.on_exit(32, 0).is_err());
        assert_eq!(table.count(), 32);
    }
}
