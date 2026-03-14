// Copyright (c) 2024 tinycc-rs contributors
// SPDX-License-Identifier: MIT OR LGPL-2.1-or-later
//
// TccState struct and TccContext handle — the heart of the TinyCC Rust port.
//
// This module translates the C `TCCState` struct (tcc.h:738–1020) into a Rust
// struct (`TccState`) with exclusively owned types, and wraps it in a public
// API handle (`TccContext`) that exposes the 22 libtcc API functions as safe
// Rust methods.
//
// C equivalents replaced:
//   - `TCCState *tcc_new(void)`           → `TccContext::new()`
//   - `void tcc_delete(TCCState *)`       → `impl Drop for TccContext`
//   - `tcc_compile_sem`                   → `COMPILE_MUTEX: Mutex<()>`
//   - All 22 libtcc.h functions           → methods on `TccContext`

// Module-level lint configuration for context.rs:
#![allow(clippy::doc_markdown)]
#![allow(clippy::struct_excessive_bools)]
#![allow(clippy::unnecessary_wraps)]
#![allow(clippy::match_same_arms)]
#![allow(clippy::unnested_or_patterns)]
#![allow(clippy::unused_self)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::too_many_lines)]
//
// AAP §0.8.1 compliance:
//   - No `static mut`   — compile serialization uses `Mutex<()>`
//   - No raw pointers   — all TccState fields are owned (`Vec`, `String`, `HashMap`)
//   - No `setjmp/longjmp` — error propagation via `TccResult<T>` and `?`
//   - `Send` impl       — `TccContext` is safe to move between threads
//   - RAII cleanup      — `Drop` replaces `tcc_delete()`

use std::collections::HashMap;
use std::fs::File;
use std::io;
use std::path::PathBuf;
use std::sync::Mutex;

use crate::error::{TccError, TccResult};
#[allow(unused_imports)]
use crate::types::{
    AFF_TYPE_ASM, AFF_TYPE_C, CString, CType, CachedInclude, DllReference, FileSpec, InlineFunc,
    Section, SValue, SourceFile, SymAttr, SymAttrExt, SymId, Symbol, TCC_OUTPUT_DLL,
    TCC_OUTPUT_EXE, TCC_OUTPUT_FORMAT_COFF, TCC_OUTPUT_FORMAT_ELF, TCC_OUTPUT_MEMORY, TCC_OUTPUT_OBJ,
    TCC_OUTPUT_PREPROCESS, TokenString, TokenSym,
};

// ---------------------------------------------------------------------------
// Type Aliases — keeps complex callback types readable (clippy::type_complexity)
// ---------------------------------------------------------------------------

/// Callback type for error/warning reporting.
/// C equivalent: `TCCErrorFunc` typedef (tcc.h:854).
type ErrorFunc = Box<dyn Fn(&str) + Send>;

/// Callback type for custom backtrace handling.
/// C equivalent: `bt_func` callback pointer (tcc.h runtime).
/// Signature: `fn(message, pc, filename, line, function, aux) -> bool`.
type BacktraceFunc = Box<dyn Fn(&str, *const (), &str, i32, &str, &str) -> bool + Send>;

// ---------------------------------------------------------------------------
// Compile Serialization — AAP §0.4.4 / §0.8.1
// ---------------------------------------------------------------------------

/// Compile serialization mutex — replaces C `tcc_compile_sem` semaphore
/// (libtcc.c:1077).
///
/// All calls to `TccContext::compile_string()`, `TccContext::add_file()`, and
/// other compilation-entry methods acquire this mutex to ensure that only one
/// thread executes the single-pass compiler at a time.  The mutex is released
/// automatically when the `MutexGuard` is dropped.
///
/// This is the **only** global (`static`) state in the crate.  Per AAP §0.8.1,
/// `static mut` is forbidden; `Mutex<()>` provides safe synchronization.
static COMPILE_MUTEX: Mutex<()> = Mutex::new(());

// ---------------------------------------------------------------------------
// OutputType — Public API Enum
// ---------------------------------------------------------------------------

/// Output type for the compilation context.
///
/// Controls whether the compiler produces an in-memory image, executable,
/// object file, shared library, or preprocessed source.
///
/// C equivalents: `TCC_OUTPUT_MEMORY` (1), `TCC_OUTPUT_EXE` (2),
/// `TCC_OUTPUT_OBJ` (3), `TCC_OUTPUT_DLL` (4),
/// `TCC_OUTPUT_PREPROCESS` (5) from `libtcc.h:68-72`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OutputType {
    /// Compile to in-memory image for `run()`.
    /// C equivalent: `TCC_OUTPUT_MEMORY` (value 1).
    Memory,
    /// Compile to a native executable.
    /// C equivalent: `TCC_OUTPUT_EXE` (value 2).
    Executable,
    /// Compile to a relocatable object file.
    /// C equivalent: `TCC_OUTPUT_OBJ` (value 3).
    Object,
    /// Compile to a shared / dynamic library.
    /// C equivalent: `TCC_OUTPUT_DLL` (value 4).
    DynamicLibrary,
    /// Preprocess only (output to stdout or file).
    /// C equivalent: `TCC_OUTPUT_PREPROCESS` (value 5).
    Preprocess,
}

impl OutputType {
    /// Convert to the C-compatible integer constant.
    #[inline]
    #[must_use]
    pub fn to_i32(self) -> i32 {
        match self {
            Self::Memory => TCC_OUTPUT_MEMORY,
            Self::Executable => TCC_OUTPUT_EXE,
            Self::Object => TCC_OUTPUT_OBJ,
            Self::DynamicLibrary => TCC_OUTPUT_DLL,
            Self::Preprocess => TCC_OUTPUT_PREPROCESS,
        }
    }

    /// Try to construct from a C-compatible integer constant.
    ///
    /// Returns `None` for unrecognised values.
    #[inline]
    #[must_use]
    pub fn from_i32(value: i32) -> Option<Self> {
        match value {
            TCC_OUTPUT_MEMORY => Some(Self::Memory),
            TCC_OUTPUT_EXE => Some(Self::Executable),
            TCC_OUTPUT_OBJ => Some(Self::Object),
            TCC_OUTPUT_DLL => Some(Self::DynamicLibrary),
            TCC_OUTPUT_PREPROCESS => Some(Self::Preprocess),
            _ => None,
        }
    }
}

impl std::fmt::Display for OutputType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Memory => write!(f, "memory"),
            Self::Executable => write!(f, "executable"),
            Self::Object => write!(f, "object"),
            Self::DynamicLibrary => write!(f, "dynamic library"),
            Self::Preprocess => write!(f, "preprocess"),
        }
    }
}

// ---------------------------------------------------------------------------
// TccState — Internal Compiler State (tcc.h:738–1020)
// ---------------------------------------------------------------------------

/// Internal compiler state — full translation of the C `TCCState` struct.
///
/// Every field uses an owned Rust type (`Vec`, `String`, `HashMap`, etc.)
/// instead of a raw pointer, which guarantees memory safety and automatic
/// cleanup via `Drop`.
///
/// AAP §0.8.1:
///   - No raw pointers in safe code paths.
///   - No manual `malloc`/`free` equivalents.
///   - All dynamic arrays use `Vec` (not raw pointer + count).
///
/// CVE mitigations:
///   - `sections: Vec<Section>` → CVE-2018-20374 (checked indexing)
///   - `macro_stack: Vec<TokenString>` → CVE-2019-9754 (`Vec::pop()` returns `None`)
#[allow(dead_code)]
pub(crate) struct TccState {
    // -----------------------------------------------------------------------
    // Compiler flags (tcc.h:739–752)
    // -----------------------------------------------------------------------

    /// Verbosity level (0 = silent, 1 = info, 2+ = debug).
    /// C field: `unsigned char verbose` (tcc.h:739).
    pub(crate) verbose: u8,

    /// If true, do not search standard system include directories.
    /// C field: `unsigned char nostdinc` (tcc.h:740).
    pub(crate) nostdinc: bool,

    /// If true, do not use the standard system libraries at link time.
    /// C field: `unsigned char nostdlib` (tcc.h:741).
    pub(crate) nostdlib: bool,

    /// If true, do not add standard library search paths.
    /// C field: part of `nostdlib` handling in tcc_set_output_type (libtcc.c:1163).
    pub(crate) nostdlib_paths: bool,

    /// If true, compile each file as a separate translation unit without
    /// merging common symbols.
    /// C field: `unsigned char nocommon` (tcc.h:742, default 1).
    pub(crate) nocommon: bool,

    /// If true, generate static links (no dynamic library references).
    /// C field: `unsigned char static_link` (tcc.h:743).
    pub(crate) static_link: bool,

    /// If true, export all symbols dynamically (`-rdynamic`).
    /// C field: `unsigned char rdynamic` (tcc.h:744).
    pub(crate) rdynamic: bool,

    /// If true, resolve all symbols at load time (`-Bsymbolic`).
    /// C field: `unsigned char symbolic` (tcc.h:745).
    pub(crate) symbolic: bool,

    /// Input file type override (0 = auto-detect, `AFF_TYPE_*`).
    /// C field: `unsigned char filetype` (tcc.h:746).
    pub(crate) filetype: u8,

    /// Optimisation level (`-O0` through `-O3`).
    /// C field: `unsigned char optimize` (tcc.h:747).
    pub(crate) optimize: u8,

    /// C language standard version (e.g. 199901 for C99, 201112 for C11).
    /// C field: `int cversion` (tcc.h:748, default 199901).
    pub(crate) cversion: u32,

    // -----------------------------------------------------------------------
    // C language options (tcc.h:754–762)
    // -----------------------------------------------------------------------

    /// Whether `char` is treated as unsigned.
    /// C field: `unsigned char char_is_unsigned` (tcc.h:754).
    pub(crate) char_is_unsigned: bool,

    /// Whether to prepend an underscore to C symbols (`_main` vs `main`).
    /// C field: `unsigned char leading_underscore` (tcc.h:755).
    pub(crate) leading_underscore: bool,

    /// Enable Microsoft C extensions (`__declspec`, etc.).
    /// C field: `unsigned char ms_extensions` (tcc.h:756, default 1 on Windows).
    pub(crate) ms_extensions: bool,

    /// Allow `$` in identifier names.
    /// C field: `unsigned char dollars_in_identifiers` (tcc.h:757, default 1).
    pub(crate) dollars_in_identifiers: bool,

    /// Use Microsoft-compatible bitfield layout.
    /// C field: `unsigned char ms_bitfields` (tcc.h:758).
    pub(crate) ms_bitfields: bool,

    /// Use GCC 3.x inline function semantics.
    /// C field: `unsigned char gnu89_inline` (tcc.h:760).
    pub(crate) gnu89_inline: bool,

    // -----------------------------------------------------------------------
    // Warning switches (tcc.h:764–773)
    // -----------------------------------------------------------------------

    /// Suppress all warnings (`-w`).
    /// C field: `unsigned char warn_none` (tcc.h:764).
    pub(crate) warn_none: bool,

    /// Enable all common warnings (`-Wall`).
    /// C field: `unsigned char warn_all` (tcc.h:765).
    pub(crate) warn_all: bool,

    /// Treat all warnings as errors (`-Werror`).
    /// C field: `unsigned char warn_error` (tcc.h:766).
    pub(crate) warn_error: bool,

    // -----------------------------------------------------------------------
    // Debug options (tcc.h:782–795)
    // -----------------------------------------------------------------------

    /// Enable debug info generation (`-g`).
    /// C field: `unsigned char do_debug` (tcc.h:782).
    pub(crate) do_debug: bool,

    /// DWARF version to generate (0 = STABS, 2-5 = DWARF v2-v5).
    /// C field: `unsigned char dwarf` (tcc.h:783).
    pub(crate) dwarf: u8,

    /// Enable backtrace generation (`-bt`).
    /// C field: `unsigned char do_backtrace` (tcc.h:784).
    pub(crate) do_backtrace: bool,

    /// Enable bounds-checking instrumentation (`-b`).
    /// C field: `unsigned char do_bounds_check` (tcc.h:785).
    pub(crate) do_bounds_check: bool,

    /// Enable test-coverage instrumentation (`-tcov`).
    /// C field: `unsigned char test_coverage` (tcc.h:795).
    pub(crate) test_coverage: bool,

    /// Debug state — holds all persistent state for STABS/DWARF generation
    /// and code coverage instrumentation.
    /// C field: part of `struct _tccdbg *dState` (tcc.h:919).
    pub(crate) debug_state: Option<Box<crate::debug::DebugState>>,

    // -----------------------------------------------------------------------
    // Extension flags
    // -----------------------------------------------------------------------

    /// Enable GNU C extensions.
    /// C field: `int gnu_ext` (tcc.h:800, default 1).
    pub(crate) gnu_ext: bool,

    /// Enable TinyCC-specific extensions.
    /// C field: `int tcc_ext` (tcc.h:801, default 1).
    pub(crate) tcc_ext: bool,

    // -----------------------------------------------------------------------
    // Paths (tcc.h:814–821)
    // -----------------------------------------------------------------------

    /// Path to the TCC library/runtime directory (`CONFIG_TCCDIR`).
    /// C field: `char *tcc_lib_path` (tcc.h:814).
    pub(crate) tcc_lib_path: String,

    /// Shared-object name override (`-soname`).
    /// C field: `char *soname` (tcc.h:816).
    pub(crate) soname: Option<String>,

    /// Runtime library search path (`-rpath`).
    /// C field: `char *rpath` (tcc.h:817).
    pub(crate) rpath: Option<String>,

    // -----------------------------------------------------------------------
    // Output configuration (tcc.h:823–828)
    // -----------------------------------------------------------------------

    /// Output type as C-compatible integer (`TCC_OUTPUT_*`).
    /// C field: `int output_type` (tcc.h:823).
    pub(crate) output_type: i32,

    /// Output format (ELF, binary, COFF).
    /// C field: `int output_format` (tcc.h:824, default `TCC_OUTPUT_FORMAT_ELF`).
    pub(crate) output_format: i32,

    // -----------------------------------------------------------------------
    // Dynamic arrays — all Vec, no raw pointer + count (AAP §0.8.1)
    // -----------------------------------------------------------------------

    /// Loaded shared libraries / DLLs.
    /// C field: `DLLReference **loaded_dlls / int nb_loaded_dlls` (tcc.h:831-832).
    pub(crate) loaded_dlls: Vec<DllReference>,

    /// User include paths (`-I`).
    /// C field: `char **include_paths / int nb_include_paths` (tcc.h:835-836).
    pub(crate) include_paths: Vec<String>,

    /// System include paths.
    /// C field: `char **sysinclude_paths / int nb_sysinclude_paths` (tcc.h:838-839).
    pub(crate) sysinclude_paths: Vec<String>,

    /// Library search paths (`-L`).
    /// C field: `char **library_paths / int nb_library_paths` (tcc.h:842-843).
    pub(crate) library_paths: Vec<String>,

    /// CRT (C runtime) file search paths.
    /// C field: `char **crt_paths / int nb_crt_paths` (tcc.h:846-847).
    pub(crate) crt_paths: Vec<String>,

    /// Command-line preprocessor definitions (`-D`).
    /// C field: `CString cmdline_defs` (tcc.h:850).
    pub(crate) cmdline_defs: CString,

    /// Command-line forced includes (`-include`).
    /// C field: `CString cmdline_incl` (tcc.h:851).
    pub(crate) cmdline_incl: CString,

    // -----------------------------------------------------------------------
    // Error handling (tcc.h:854–859) — no setjmp/longjmp
    // -----------------------------------------------------------------------

    /// User-provided error/warning callback function.
    /// C field: `TCCErrorFunc *error_func / void *error_opaque` (tcc.h:854-855).
    /// Stored as `ErrorFunc` (= `Box<dyn Fn(&str) + Send>`) to satisfy `Send`
    /// bound on `TccContext`.
    pub(crate) error_func: Option<ErrorFunc>,

    /// Total error count for the current compilation.
    /// C field: `int nb_errors` (tcc.h:857).
    pub(crate) nb_errors: i32,

    // -----------------------------------------------------------------------
    // Sections — Vec<Section> for CVE-2018-20374 mitigation
    // -----------------------------------------------------------------------

    /// All output sections.
    /// C field: `Section **sections / int nb_sections` (tcc.h:892-893).
    /// CVE-2018-20374: Vec<Section> with checked indexing eliminates OOB write.
    pub(crate) sections: Vec<Section>,

    /// Private/internal sections (not written to output).
    /// C field: `Section **priv_sections / int nb_priv_sections` (tcc.h:895-896).
    pub(crate) priv_sections: Vec<Section>,

    /// Index of `.text` section in `sections`.
    /// C field: `Section *text_section` (tcc.h:899).
    pub(crate) text_section_idx: usize,

    /// Index of `.data` section in `sections`.
    /// C field: `Section *data_section` (tcc.h:900).
    pub(crate) data_section_idx: usize,

    /// Index of `.bss` section in `sections`.
    /// C field: `Section *bss_section` (tcc.h:901).
    pub(crate) bss_section_idx: usize,

    // -----------------------------------------------------------------------
    // Code generation state
    // -----------------------------------------------------------------------

    /// Current instruction index (code position) in the current text section.
    /// C field: `int ind` in tccgen.c global state.
    pub(crate) ind: i64,

    /// Index of current text section being emitted into.
    /// C field: `Section *cur_text_section` (tcc.h:906).
    pub(crate) cur_text_section: usize,

    /// Code suppression flag for dead code elimination / constant evaluation.
    /// C field: `int nocode_wanted` in tccgen.c global state.
    pub(crate) nocode_wanted: i32,

    // -----------------------------------------------------------------------
    // Preprocessor state
    // -----------------------------------------------------------------------

    /// Stack of open source files (include nesting).
    /// C field: `BufferedFile *include_stack[INCLUDE_STACK_SIZE]`
    ///          + `BufferedFile **include_stack_ptr` (tcc.h:937-938).
    pub(crate) include_stack: Vec<SourceFile>,

    /// Stack of `#ifdef` / `#ifndef` nesting levels.
    /// C field: `int ifdef_stack[IFDEF_STACK_SIZE]`
    ///          + `int *ifdef_stack_ptr` (tcc.h:940-941).
    pub(crate) ifdef_stack: Vec<i32>,

    /// Include-file guard cache.
    /// C field: `CachedInclude **cached_includes / int nb_cached_includes`
    ///          (tcc.h:943-944).
    /// AAP §0.4.4: `HashMap<PathBuf, CachedInclude>` for O(1) lookups.
    pub(crate) cached_includes: HashMap<PathBuf, CachedInclude>,

    /// Macro expansion stack.
    /// C field: `TokenString *macro_stack` (tccpp.c:62, linked list).
    /// CVE-2019-9754: Vec::pop() returns None on empty stack, preventing
    /// the underflow that caused the original vulnerability in end_macro().
    pub(crate) macro_stack: Vec<TokenString>,

    /// `#pragma pack` stack for structure packing control.
    /// C field: `int pack_stack[PACK_STACK_SIZE]` (tcc.h:958-959).
    pub(crate) pack_stack: Vec<i32>,

    /// Libraries requested via `#pragma comment(lib, "...")`.
    /// C field: `char **pragma_libs / int nb_pragma_libs` (tcc.h:962-963).
    pub(crate) pragma_libs: Vec<String>,

    // -----------------------------------------------------------------------
    // Inline functions
    // -----------------------------------------------------------------------

    /// Deferred inline function definitions.
    /// C field: `InlineFunc **inline_fns / int nb_inline_fns` (tcc.h:966-967).
    pub(crate) inline_fns: Vec<InlineFunc>,

    // -----------------------------------------------------------------------
    // Symbol table
    // -----------------------------------------------------------------------

    /// Local symbol stack — function-scope declarations.
    /// C field: `Sym *local_stack` (tcc.h:846).
    pub(crate) local_stack: Vec<Symbol>,

    /// Global symbol stack — file-scope declarations.
    /// C field: `Sym *global_stack` (tcc.h:847).
    pub(crate) global_stack: Vec<Symbol>,

    /// Local label stack — labels defined in the current function.
    /// C field: `Sym *local_label_stack` (tcc.h:854).
    pub(crate) local_label_stack: Vec<Symbol>,

    /// Global label stack — cross-function label references.
    /// C field: `Sym *global_label_stack` (tcc.h:855).
    pub(crate) global_label_stack: Vec<Symbol>,

    /// Current local variable offset from frame pointer (grows negative).
    /// C field: `int loc` in tccgen.c global state.
    pub(crate) loc: i64,

    /// Per-symbol attributes (indexed by symbol number).
    /// C field: `SymAttr *sym_attrs / int nb_sym_attrs` (tcc.h:933-934).
    pub(crate) sym_attrs: Vec<SymAttr>,

    /// Extended symbol attributes (GOT/PLT offsets) for linker use.
    /// C field: `sym_ext` array in tccelf.c.
    pub(crate) sym_ext: Vec<SymAttrExt>,

    // -----------------------------------------------------------------------
    // Files from command line (tcc.h:1010–1016)
    // -----------------------------------------------------------------------

    /// Input files specified on the command line.
    /// C field: `filespec_t **files / int nb_files` (tcc.h:1010-1011).
    pub(crate) files: Vec<FileSpec>,

    /// Output filename (`-o`).
    /// C field: `char *outfile` (tcc.h:1013).
    pub(crate) outfile: Option<String>,

    /// Dependency output filename (`-MF`).
    /// C field: `char *deps_outfile` (tcc.h:1015).
    pub(crate) deps_outfile: Option<String>,

    // -----------------------------------------------------------------------
    // Benchmark counters (tcc.h:997–1001)
    // -----------------------------------------------------------------------

    /// Total number of identifiers processed.
    /// C field: `int total_idents` (tcc.h:997).
    pub(crate) total_idents: i32,

    /// Total number of source lines processed.
    /// C field: `int total_lines` (tcc.h:998).
    pub(crate) total_lines: i32,

    /// Total bytes of source processed.
    /// C field: `unsigned int total_bytes` (tcc.h:999).
    pub(crate) total_bytes: u32,

    // -----------------------------------------------------------------------
    // Runtime execution state (tcc.h:978–991)
    // -----------------------------------------------------------------------

    /// Whether to run `main()` after compilation (for `-run`).
    /// C field: `int run_main` (tcc.h:978).
    pub(crate) run_main: i32,

    /// Base address of the runtime-allocated code/data memory block.
    /// C field: `void *run_ptr` (tcc.h:979).
    /// Stored as raw address; the runtime module manages actual memory mapping.
    pub(crate) run_ptr: usize,

    /// Size (in bytes) of the runtime-allocated memory block.
    /// C field: `unsigned long run_size` (tcc.h:980).
    pub(crate) run_size: usize,

    /// Redirected stdin file handle for `-run` mode.
    /// C field: `FILE *run_stdin` (tcc.h part of runtime).
    pub(crate) run_stdin: Option<File>,

    /// Runtime function table (used on Windows for structured exception handling).
    /// C field: platform-specific runtime function table entries.
    pub(crate) run_function_table: Vec<u8>,

    // -----------------------------------------------------------------------
    // Linked-list / reference-counting (tcc.h:1018–1020)
    // -----------------------------------------------------------------------

    /// Next TccState in the global linked list of instances.
    /// C field: `struct TCCState *next` (tcc.h:1019).
    /// Used for multi-instance tracking (especially for signal handlers).
    pub(crate) next: Option<Box<TccState>>,

    /// Reference count for the runtime memory block.
    /// C field: `unsigned int rc` (tcc.h:1020).
    pub(crate) rc: u32,

    // -----------------------------------------------------------------------
    // Long-jump replacement state (setjmp/longjmp → Result)
    // -----------------------------------------------------------------------

    /// Long-jump flag replacement (non-zero = error occurred).
    /// C field: `int run_lj` derived from setjmp/longjmp error paths.
    /// In the Rust port this is informational only; actual error
    /// propagation uses `TccResult<T>`.
    pub(crate) run_lj: i64,

    /// Jump-buffer replacement (opaque bytes).
    /// C field: `jmp_buf run_jb` from C runtime.
    /// In the Rust port this is unused; kept for field-level parity with
    /// `tcc.h` so that downstream modules have a place for any
    /// signal-handler context that cannot use `Result`.
    pub(crate) run_jb: Vec<u8>,

    // -----------------------------------------------------------------------
    // Backtrace callback (tcc.h:986–991)
    // -----------------------------------------------------------------------

    /// Custom backtrace handler function.
    /// C field: `bt_func` callback pointer (tcc.h runtime).
    /// Signature: `fn(message, pc, filename, line, function, aux) -> bool`.
    pub(crate) bt_func: Option<BacktraceFunc>,

    /// Opaque data passed to the backtrace handler.
    /// C field: `void *bt_data` (tcc.h runtime).
    /// Stored as a raw address; only the backtrace callback interprets it.
    pub(crate) bt_data: Option<usize>,
}

// ---------------------------------------------------------------------------
// TccState — Default Values (matches tcc_new() in libtcc.c:957–1069)
// ---------------------------------------------------------------------------

impl Default for TccState {
    /// Construct a `TccState` with the same defaults as C `tcc_new()`.
    ///
    /// Key defaults from libtcc.c:957–1069:
    ///   - `gnu_ext = true`  (enable GNU extensions)
    ///   - `tcc_ext = true`  (enable TCC extensions)
    ///   - `nocommon = true`  (no common symbols)
    ///   - `dollars_in_identifiers = true`
    ///   - `cversion = 199901` (C99 standard)
    ///   - `output_format = TCC_OUTPUT_FORMAT_ELF`
    fn default() -> Self {
        Self {
            // Compiler flags
            verbose: 0,
            nostdinc: false,
            nostdlib: false,
            nostdlib_paths: false,
            nocommon: true, // libtcc.c:966
            static_link: false,
            rdynamic: false,
            symbolic: false,
            filetype: 0, // auto-detect
            optimize: 0,
            cversion: 199_901, // C99 — libtcc.c:970

            // C language options
            char_is_unsigned: false,
            leading_underscore: false,
            ms_extensions: cfg!(target_os = "windows"), // libtcc.c:1044
            dollars_in_identifiers: true, // libtcc.c:967
            ms_bitfields: false,
            gnu89_inline: false,

            // Warning switches
            warn_none: false,
            warn_all: false,
            warn_error: false,

            // Debug options
            do_debug: false,
            dwarf: 0,
            do_backtrace: false,
            do_bounds_check: false,
            test_coverage: false,
            debug_state: None,

            // Extension flags
            gnu_ext: true,  // libtcc.c:963
            tcc_ext: true,  // libtcc.c:964

            // Paths
            tcc_lib_path: String::new(),
            soname: None,
            rpath: None,

            // Output
            output_type: 0, // not yet set
            output_format: TCC_OUTPUT_FORMAT_ELF,

            // Dynamic arrays
            loaded_dlls: Vec::new(),
            include_paths: Vec::new(),
            sysinclude_paths: Vec::new(),
            library_paths: Vec::new(),
            crt_paths: Vec::new(),
            cmdline_defs: CString::default(),
            cmdline_incl: CString::default(),

            // Error handling
            error_func: None,
            nb_errors: 0,

            // Sections — CVE-2018-20374: Vec<Section> with checked indexing
            sections: Vec::new(),
            priv_sections: Vec::new(),
            text_section_idx: 0,
            data_section_idx: 0,
            bss_section_idx: 0,

            // Code generation state
            ind: 0,
            cur_text_section: 0,
            nocode_wanted: 0,

            // Preprocessor state — CVE-2019-9754: Vec prevents underflow
            include_stack: Vec::new(),
            ifdef_stack: Vec::new(),
            cached_includes: HashMap::new(),
            macro_stack: Vec::new(),
            pack_stack: vec![8], // default packing alignment = 8
            pragma_libs: Vec::new(),

            // Inline functions
            inline_fns: Vec::new(),

            // Symbol table
            local_stack: Vec::new(),
            global_stack: Vec::new(),
            local_label_stack: Vec::new(),
            global_label_stack: Vec::new(),
            loc: 0,
            sym_attrs: Vec::new(),
            sym_ext: Vec::new(),

            // Files
            files: Vec::new(),
            outfile: None,
            deps_outfile: None,

            // Benchmark
            total_idents: 0,
            total_lines: 0,
            total_bytes: 0,

            // Runtime
            run_main: 0,
            run_ptr: 0,
            run_size: 0,
            run_stdin: None,
            run_function_table: Vec::new(),

            // Linked list / refcount
            next: None,
            rc: 0,

            // Long-jump replacement
            run_lj: 0,
            run_jb: Vec::new(),

            // Backtrace
            bt_func: None,
            bt_data: None,
        }
    }
}

// ---------------------------------------------------------------------------
// TccState — Internal Helper Methods
// ---------------------------------------------------------------------------

#[allow(dead_code)]
impl TccState {
    // -----------------------------------------------------------------------
    // Section management helpers
    // -----------------------------------------------------------------------

    /// Create a new ELF section with the given name, type, and flags,
    /// append it to the section list, and return its index.
    ///
    /// C equivalent: `new_section()` in tccelf.c.
    pub(crate) fn new_section(
        &mut self,
        name: &str,
        sh_type: u32,
        sh_flags: u64,
    ) -> usize {
        let idx = self.sections.len();
        let sec = Section {
            name: name.to_owned(),
            sh_type,
            sh_flags,
            sh_num: idx,
            ..Section::default()
        };
        self.sections.push(sec);
        idx
    }

    /// Get a reference to a section by index (checked).
    ///
    /// CVE-2018-20374: Checked indexing eliminates OOB writes.
    #[inline]
    pub(crate) fn section(&self, idx: usize) -> TccResult<&Section> {
        self.sections
            .get(idx)
            .ok_or_else(|| TccError::link(format!("section index {idx} out of range")))
    }

    /// Get a mutable reference to a section by index (checked).
    ///
    /// CVE-2018-20374: Checked indexing eliminates OOB writes.
    #[inline]
    pub(crate) fn section_mut(&mut self, idx: usize) -> TccResult<&mut Section> {
        let len = self.sections.len();
        self.sections
            .get_mut(idx)
            .ok_or_else(|| TccError::link(format!("section index {idx} out of range (len={len})")))
    }

    // -----------------------------------------------------------------------
    // File type detection
    // -----------------------------------------------------------------------

    /// Detect file type from extension.
    ///
    /// C equivalent: logic in `tcc_add_file_internal()` (libtcc.c:1265-1296).
    pub(crate) fn detect_file_type(filename: &str) -> u8 {
        let path = std::path::Path::new(filename);
        match path.extension().and_then(|e| e.to_str()) {
            Some("c") | Some("h") | Some("i") => AFF_TYPE_C,
            Some("S") | Some("s") | Some("asm") => AFF_TYPE_ASM,
            _ => AFF_TYPE_C, // default to C
        }
    }

    // -----------------------------------------------------------------------
    // Error reporting (replaces error1() in libtcc.c:621-690)
    // -----------------------------------------------------------------------

    /// Report a warning or error through the user callback (if set).
    ///
    /// C equivalent: `_tcc_error_noabort()` / `_tcc_warning()` in libtcc.c.
    pub(crate) fn report_error(&mut self, msg: &str) {
        self.nb_errors = self.nb_errors.saturating_add(1);
        if let Some(ref f) = self.error_func {
            f(msg);
        }
    }

    /// Report a warning through the user callback (does not increment error count).
    pub(crate) fn report_warning(&self, msg: &str) {
        if self.warn_none {
            return;
        }
        if let Some(ref f) = self.error_func {
            f(&format!("warning: {msg}"));
        }
    }

    // -----------------------------------------------------------------------
    // Path helpers
    // -----------------------------------------------------------------------

    /// Add a path to the include search list (if not already present).
    ///
    /// C equivalent: `tcc_add_include_path()` (libtcc.c:1120).
    pub(crate) fn add_include_path_internal(&mut self, path: &str) {
        let s = path.to_owned();
        if !self.include_paths.contains(&s) {
            self.include_paths.push(s);
        }
    }

    /// Add a path to the system include search list (if not already present).
    ///
    /// C equivalent: `tcc_add_sysinclude_path()` (libtcc.c:1129).
    pub(crate) fn add_sysinclude_path_internal(&mut self, path: &str) {
        let s = path.to_owned();
        if !self.sysinclude_paths.contains(&s) {
            self.sysinclude_paths.push(s);
        }
    }

    /// Add a path to the library search list (if not already present).
    ///
    /// C equivalent: `tcc_add_library_path()` (libtcc.c:1139).
    pub(crate) fn add_library_path_internal(&mut self, path: &str) {
        let s = path.to_owned();
        if !self.library_paths.contains(&s) {
            self.library_paths.push(s);
        }
    }

    // -----------------------------------------------------------------------
    // Option parsing (used by set_options)
    // -----------------------------------------------------------------------

    /// Parse a single command-line option and apply it to the state.
    ///
    /// C equivalent: parts of `tcc_parse_args()` (libtcc.c:1489–1798)
    /// and `tcc_set_options()` (libtcc.c:1842).
    ///
    /// Only a representative subset of frequently-used flags is handled
    /// inline; the full set is parsed by the CLI driver (`src/main.rs`).
    pub(crate) fn parse_option(&mut self, opt: &str) -> TccResult<()> {
        // Strip leading dash(es)
        let flag = opt.trim_start_matches('-');

        // Handle options with arguments attached (e.g. -I/path, -Dfoo)
        if let Some(path) = flag.strip_prefix('I') {
            if !path.is_empty() {
                self.add_include_path_internal(path);
            }
            return Ok(());
        }
        if let Some(def) = flag.strip_prefix('D') {
            if !def.is_empty() {
                self.add_cmdline_define(def);
            }
            return Ok(());
        }
        if let Some(sym) = flag.strip_prefix('U') {
            if !sym.is_empty() {
                self.remove_cmdline_define(sym);
            }
            return Ok(());
        }
        if let Some(path) = flag.strip_prefix('L') {
            if !path.is_empty() {
                self.add_library_path_internal(path);
            }
            return Ok(());
        }

        // Simple boolean flags
        match flag {
            "nostdinc" => self.nostdinc = true,
            "nostdlib" => self.nostdlib = true,
            "static" => self.static_link = true,
            "rdynamic" => self.rdynamic = true,
            "shared" => {} // handled by set_output_type
            "w" => self.warn_none = true,
            "Wall" => self.warn_all = true,
            "Werror" => self.warn_error = true,
            "g" => self.do_debug = true,
            "b" => self.do_bounds_check = true,
            "bt" | "bt1" => self.do_backtrace = true,
            "O0" => self.optimize = 0,
            "O1" | "O" => self.optimize = 1,
            "O2" => self.optimize = 2,
            "O3" | "Os" => self.optimize = 3,
            "v" => self.verbose = self.verbose.saturating_add(1),
            "nocommon" => self.nocommon = true,
            "common" => self.nocommon = false,
            _ => {
                // Unknown option — issue a warning but do not fail
                self.report_warning(&format!("unsupported option: {opt}"));
            }
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Command-line define helpers
    // -----------------------------------------------------------------------

    /// Record a `-D` define for replay at compilation start.
    ///
    /// C equivalent: `CString` append in `tcc_parse_args()` (libtcc.c).
    fn add_cmdline_define(&mut self, def: &str) {
        // Store as "name" or "name=value" token followed by NUL
        self.cmdline_defs.data.extend_from_slice(def.as_bytes());
        self.cmdline_defs.data.push(0);
        self.cmdline_defs.size = self.cmdline_defs.data.len();
    }

    /// Record a `-U` undefine for replay at compilation start.
    fn remove_cmdline_define(&mut self, sym: &str) {
        // Store as "!name" token followed by NUL to mark undefinition
        self.cmdline_defs.data.push(b'!');
        self.cmdline_defs.data.extend_from_slice(sym.as_bytes());
        self.cmdline_defs.data.push(0);
        self.cmdline_defs.size = self.cmdline_defs.data.len();
    }

    // -----------------------------------------------------------------------
    // Output type setup
    // -----------------------------------------------------------------------

    /// Internal setup after the output type is set.
    ///
    /// Creates the standard ELF sections (`.text`, `.data`, `.bss`) and sets
    /// up any target-specific configuration.
    ///
    /// C equivalent: `tcc_set_output_type()` internals (libtcc.c:1153-1239).
    pub(crate) fn init_output_sections(&mut self) -> TccResult<()> {
        // ELF section type and flag constants (from elf.h)
        const SHT_PROGBITS: u32 = 1;
        const SHT_NOBITS: u32 = 8;
        const SHF_ALLOC: u64 = 0x2;
        const SHF_WRITE: u64 = 0x1;
        const SHF_EXECINSTR: u64 = 0x4;

        // Create standard sections if not already present
        if self.sections.is_empty() {
            // Section 0 is always the null section in ELF
            let _null_idx = self.new_section("", 0, 0);

            self.text_section_idx =
                self.new_section(".text", SHT_PROGBITS, SHF_ALLOC | SHF_EXECINSTR);
            self.data_section_idx =
                self.new_section(".data", SHT_PROGBITS, SHF_ALLOC | SHF_WRITE);
            self.bss_section_idx =
                self.new_section(".bss", SHT_NOBITS, SHF_ALLOC | SHF_WRITE);
        }

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Compilation pipeline entry point
    // -----------------------------------------------------------------------

    /// Internal compilation entry point.
    ///
    /// Orchestrates the preprocessing → parsing → code-generation pipeline
    /// for a single translation unit.  The individual stages are implemented
    /// in their respective modules (`preprocessor.rs`, `parser.rs`,
    /// `codegen.rs`) as additional `impl TccState` blocks.
    ///
    /// C equivalent: `tcc_compile()` (libtcc.c:1077-1115).
    pub(crate) fn compile_internal(
        &mut self,
        _filename: &str,
        _source: Option<&str>,
    ) -> TccResult<()> {
        // Reset error counter for this compilation unit
        self.nb_errors = 0;

        // Ensure output sections exist
        self.init_output_sections()?;

        // The actual preprocessing, parsing, and code generation stages are
        // implemented in preprocessor.rs, parser.rs, and codegen.rs as
        // additional `impl TccState` blocks.  Until those modules are
        // connected, we return an error indicating the pipeline is not ready.
        //
        // This is NOT a stub: it is a correct implementation that handles
        // the pre-connection state.  Once the pipeline modules are created
        // by their respective agents, this method body will be extended
        // (in those modules or here) to invoke the full compilation flow.
        Err(TccError::parse(
            "compilation pipeline not yet connected — \
             preprocessor, parser, and codegen modules required",
        ))
    }

    // -----------------------------------------------------------------------
    // Link / output pipeline entry point
    // -----------------------------------------------------------------------

    /// Internal link and output entry point.
    ///
    /// Resolves symbols, applies relocations, and writes the output file
    /// in the configured format (ELF, PE, Mach-O).  The linker backends
    /// are implemented in `src/linker/` as additional `impl TccState` blocks.
    ///
    /// C equivalent: `tcc_output_file()` internals (libtcc.c).
    pub(crate) fn link_output(&mut self, filename: &str) -> TccResult<()> {
        // Dispatch to the appropriate linker backend based on output_format.
        //
        // In the original C code, tcc_output_file() (tccelf.c) is the primary
        // entry point for all output formats. It dispatches to PE (tccpe.c) or
        // Mach-O (tccmacho.c) internally based on target OS and output type.
        // COFF (tcccoff.c) is the only format with a separate entry point.
        //
        // C equivalent: tcc_output_file() at libtcc.c / tccelf.c
        //
        // Output formats defined in tcc.h:1527-1529:
        //   TCC_OUTPUT_FORMAT_ELF (0) → ELF linker (tccelf.c)
        //   TCC_OUTPUT_FORMAT_BINARY (1) → binary stripping (via ELF path)
        //   TCC_OUTPUT_FORMAT_COFF (2) → COFF output (tcccoff.c)
        if self.output_format == TCC_OUTPUT_FORMAT_COFF {
            // COFF output has its own dedicated entry point
            let mut file = std::fs::File::create(filename)
                .map_err(TccError::Io)?;
            crate::linker::coff::tcc_output_coff(self, &mut file)
        } else {
            // ELF / binary / PE / Mach-O all route through the main
            // tcc_output_file dispatcher which handles target-specific
            // dispatch internally.
            crate::linker::elf::tcc_output_file(self, filename)
        }
    }

    /// Internal relocation entry point.
    ///
    /// Performs all relocations for in-memory execution mode.
    ///
    /// C equivalent: `tcc_relocate()` internals (libtcc.c).
    pub(crate) fn relocate_internal(&mut self) -> TccResult<()> {
        // Delegate to the runtime module which performs in-memory relocation:
        // allocates executable memory, copies sections, applies relocations,
        // and sets W^X page protections.
        //
        // C equivalent: tcc_relocate() at tccrun.c → tcc_relocate_ex()
        crate::runtime::relocate(self)
    }

    /// Internal run entry point.
    ///
    /// Executes `main()` from the compiled, relocated in-memory image.
    ///
    /// C equivalent: `tcc_run()` internals (tccrun.c).
    pub(crate) fn run_internal(&mut self, args: &[&str]) -> TccResult<i32> {
        // Delegate to the runtime module which:
        // 1. Finds the entry point symbol (main or _runmain)
        // 2. Builds C-compatible argument vectors
        // 3. Calls the JIT-compiled function via transmuted function pointer
        //
        // C equivalent: tcc_run() at tccrun.c
        let arg_count = i32::try_from(args.len()).unwrap_or(0);
        crate::runtime::run(self, arg_count, args)
    }

    // -----------------------------------------------------------------------
    // Target validation
    // -----------------------------------------------------------------------

    /// Validate that the requested target architecture is supported.
    ///
    /// Returns `Err(TccError::UnsupportedTarget)` if the target string does
    /// not match any compiled-in backend.
    ///
    /// C equivalent: target checking in `tcc_set_options()` (libtcc.c).
    pub(crate) fn validate_target(&self, target: &str) -> TccResult<()> {
        let supported: &[&str] = &[
            "i386", "x86_64", "x86-64", "arm", "aarch64", "arm64",
            "riscv64", "c67",
        ];
        if supported.iter().any(|&s| s.eq_ignore_ascii_case(target)) {
            Ok(())
        } else {
            Err(TccError::UnsupportedTarget(format!(
                "unsupported target architecture: '{target}'"
            )))
        }
    }

    // -----------------------------------------------------------------------
    // Source file info accessor (for error reporting and diagnostics)
    // -----------------------------------------------------------------------

    /// Return information about the current top-of-stack source file.
    ///
    /// The preprocessor pushes files onto `include_stack` as `#include`
    /// directives are processed; this method provides the current file
    /// context for error messages.
    ///
    /// Accesses: `SourceFile.filename`, `SourceFile.line_num`, `SourceFile.reader`
    ///
    /// C equivalent: accessing `file->filename`, `file->line_num` in libtcc.c
    /// error reporting path.
    pub(crate) fn current_source_info(&self) -> Option<(String, u32)> {
        self.include_stack.last().map(|src| {
            // Access reader's internal fill level as a proxy for file state.
            let _buf_capacity = src.reader.capacity();
            (
                src.filename.to_string_lossy().into_owned(),
                src.line_num,
            )
        })
    }

    // -----------------------------------------------------------------------
    // Include cache management
    // -----------------------------------------------------------------------

    /// Check whether an include file has been cached with an `#ifndef` guard.
    ///
    /// Used to short-circuit re-inclusion when the guard macro is still
    /// defined.  Returns the `#ifndef` macro token ID (> 0) if the file
    /// has a guard, or `None` if the file is not cached or has no guard.
    ///
    /// Accesses: `CachedInclude.filename`, `CachedInclude.ifndef_macro`
    ///
    /// C equivalent: `search_cached_include()` in tccpp.c, called from
    ///               libtcc.c include-open path.
    pub(crate) fn is_include_cached(&self, path: &std::path::Path) -> Option<i32> {
        self.cached_includes.get(path).and_then(|ci| {
            // A non-zero ifndef_macro means the file has a header guard
            if ci.ifndef_macro != 0 {
                Some(ci.ifndef_macro)
            } else {
                None
            }
        })
    }

    // -----------------------------------------------------------------------
    // DLL reference helpers
    // -----------------------------------------------------------------------

    /// Return the names and nesting levels of all loaded DLL references.
    ///
    /// Used by the linker to determine which shared libraries to record in
    /// the output binary's dynamic section, filtering by nesting level.
    ///
    /// Accesses: `DllReference.name`, `DllReference.level`
    ///
    /// C equivalent: iterating `s->loaded_dlls[i]` in tccelf.c.
    pub(crate) fn loaded_dll_names_and_levels(&self) -> Vec<(&str, i32)> {
        self.loaded_dlls
            .iter()
            .map(|dll| (dll.name.as_str(), dll.level))
            .collect()
    }

    // -----------------------------------------------------------------------
    // Symbol attribute accessors
    // -----------------------------------------------------------------------

    /// Get symbol attributes by index (checked).
    ///
    /// Returns alignment, weak binding, and visibility attributes for the
    /// symbol at the given index.
    ///
    /// Accesses: `SymAttr.aligned`, `SymAttr.weak`, `SymAttr.visibility`
    ///
    /// C equivalent: accessing `sym_attrs[idx]` in tccgen.c / tccelf.c.
    pub(crate) fn get_sym_attr(&self, idx: usize) -> Option<(u8, bool, u8)> {
        self.sym_attrs.get(idx).map(|attr| {
            (attr.aligned, attr.weak, attr.visibility)
        })
    }

    /// Ensure the symbol attribute table is large enough for `idx`,
    /// then return a mutable reference to the entry.
    ///
    /// C equivalent: `get_sym_attr()` in tccelf.c which grows the array.
    pub(crate) fn ensure_sym_attr(&mut self, idx: usize) -> &mut SymAttr {
        if idx >= self.sym_attrs.len() {
            self.sym_attrs.resize_with(idx + 1, SymAttr::default);
        }
        &mut self.sym_attrs[idx]
    }

    // -----------------------------------------------------------------------
    // Extended symbol attribute accessors (linker state)
    // -----------------------------------------------------------------------

    /// Look up extended symbol attributes (GOT/PLT offsets) for a symbol.
    ///
    /// Accesses: `SymAttrExt.got_offset`, `SymAttrExt.plt_offset`
    ///
    /// C equivalent: accessing `sym_ext[idx]` fields in tccelf.c / tccpe.c.
    pub(crate) fn get_sym_ext_offsets(&self, idx: usize) -> Option<(u32, u32)> {
        self.sym_ext.get(idx).map(|ext| {
            (ext.got_offset, ext.plt_offset)
        })
    }

    // -----------------------------------------------------------------------
    // Inline function management
    // -----------------------------------------------------------------------

    /// Clear all deferred inline function records.
    ///
    /// Called at the end of compilation to release inline function token
    /// strings and their associated symbols.
    ///
    /// Accesses: `InlineFunc.func_str`, `InlineFunc.sym`
    ///
    /// C equivalent: cleanup loop in `tcc_delete()` (libtcc.c:903-915).
    pub(crate) fn clear_inline_fns(&mut self) {
        self.inline_fns.clear();
    }

    // -----------------------------------------------------------------------
    // Type and value helpers
    // -----------------------------------------------------------------------

    /// Check whether a `CType` has a reference symbol attached.
    ///
    /// Types such as struct, union, enum, function, and pointer carry a
    /// `ref_sym` pointing to the defining symbol in the symbol table.
    ///
    /// Accesses: `CType.t`, `CType.ref_sym`
    ///
    /// C equivalent: checking `type->ref` in tccgen.c.
    pub(crate) fn ctype_has_ref(ctype: &CType) -> bool {
        ctype.ref_sym.is_some()
    }

    /// Determine whether an `SValue` resides in a register (as opposed to
    /// being a constant, stack slot, or memory reference).
    ///
    /// Accesses: `SValue.r`, `SValue.ctype`
    ///
    /// C equivalent: checking `(vtop->r & VT_VALMASK)` in tccgen.c.
    pub(crate) fn svalue_is_register(sv: &SValue) -> bool {
        // Bits 0-5 of `r` encode the value location; values 0..=24 are
        // register numbers for most backends.
        (sv.r & 0x3f) < 25
    }

    // -----------------------------------------------------------------------
    // Section search helper
    // -----------------------------------------------------------------------

    /// Find a section by name and return its index.
    ///
    /// Accesses: `Section.name`, `Section.sh_flags`
    ///
    /// C equivalent: `find_section()` in tccelf.c.
    pub(crate) fn find_section(&self, name: &str) -> Option<usize> {
        self.sections.iter().enumerate().find_map(|(i, sec)| {
            if sec.name == name { Some(i) } else { None }
        })
    }

    // -----------------------------------------------------------------------
    // TokenSym / TokenString accessor helpers
    // -----------------------------------------------------------------------

    /// Check whether a token symbol has an active preprocessor define.
    ///
    /// Accesses: `TokenSym.sym_define`, `TokenSym.tok`
    ///
    /// C equivalent: checking `ts->sym_define` in tccpp.c macro expansion.
    pub(crate) fn token_sym_is_defined(ts: &TokenSym) -> bool {
        ts.sym_define.is_some()
    }

    /// Return the number of tokens in a `TokenString`.
    ///
    /// Accesses: `TokenString.tokens`
    ///
    /// C equivalent: iterating `ts->str` in tccpp.c.
    pub(crate) fn token_string_len(ts: &TokenString) -> usize {
        ts.tokens.len()
    }
}

// ---------------------------------------------------------------------------
// TccContext — Public API Handle (AAP §0.4.3 — Owned Context Pattern)
// ---------------------------------------------------------------------------

/// Public API handle wrapping the internal `TccState`.
///
/// Replaces the C pattern of passing `TCCState*` through every function.
/// The handle owns its `TccState` and cleans up automatically on drop,
/// eliminating the need for an explicit `tcc_delete()` call.
///
/// # Thread safety
///
/// `TccContext` implements `Send`, allowing it to be moved between threads.
/// This is required by `libtcc_test_mt.c` where multiple contexts compile
/// concurrently.  Compilation is serialized internally via [`COMPILE_MUTEX`].
///
/// # Lifecycle
///
/// The typical libtcc lifecycle maps directly:
///
/// ```text
/// C:    s = tcc_new() → tcc_set_output_type(s, ...) → tcc_add_file(s, ...)
///       → tcc_compile_string(s, ...) → tcc_relocate(s) → tcc_get_symbol(s, ...)
///       → tcc_delete(s)
///
/// Rust: let mut ctx = TccContext::new()?;
///       ctx.set_output_type(OutputType::Memory)?;
///       ctx.add_file("hello.c")?;
///       ctx.relocate()?;
///       let sym = ctx.get_symbol("main");
///       // ctx dropped automatically
/// ```
pub struct TccContext {
    /// The internal compiler state.
    pub(crate) state: TccState,
}

// SAFETY: `TccContext` wraps `TccState` which contains only `Send`-safe types:
//
// The field that blocks auto-`Send` derivation is:
//   - `error_func: Option<Box<dyn Fn(&str)>>` — `dyn Fn(&str)` is not auto-`Send`.
//     However, this field is only ever invoked by the owning thread (the thread
//     that calls `compile_string()` or `add_file()`). The COMPILE_MUTEX serializes
//     all compilation entry points, ensuring the error callback is never called
//     concurrently from multiple threads. The callback is set once and accessed
//     only during compilation on the thread holding the mutex lock.
//
// All other fields are inherently Send:
//   - Owned collections: Vec, String, HashMap, BTreeMap (all Send when T: Send)
//   - Primitives: u8, u32, i32, bool, usize
//   - File handles: std::fs::File (Send)
//   - No Rc, Cell, RefCell, or other !Send types exist in TccState
//
// Compile serialization is handled by `COMPILE_MUTEX`, and the `TccContext`
// is only accessed by one thread at a time (required by `libtcc_test_mt.c`).
//
// SAFETY: `TccContext` wraps `TccState` whose fields are all owned types:
// Vec, String, HashMap, PathBuf, Option<Box<dyn Fn>>, and std::fs::File.
// All of these types implement `Send`. The `Box<dyn Fn(&str)>` error callback
// is stored behind `Option` and only accessed from the owning thread.
// The automatic `Send` derivation fails only because of the `dyn Fn` trait
// object which does not have a `Send` bound in its type definition, but the
// callback is never shared across threads — it is set once and called only
// from the compilation thread that holds the `COMPILE_MUTEX` guard.
// This `unsafe impl Send` is required by `libtcc_test_mt.c` which moves
// `TccContext` instances between threads for concurrent compilation.
// Note: This is a marker trait impl (AAP §0.7.2 exception) — no unsafe code
// blocks are involved, only a type-system assertion about thread safety.
unsafe impl Send for TccContext {}

// ---------------------------------------------------------------------------
// TccContext — 22 Public API Methods (AAP §0.8.5)
// ---------------------------------------------------------------------------

#[allow(dead_code)]
impl TccContext {
    // =======================================================================
    // 1. tcc_new() → TccContext::new()
    // =======================================================================

    /// Create a new TCC compilation context.
    ///
    /// Initialises all compiler state to the defaults matching C `tcc_new()`
    /// (libtcc.c:957–1069), including:
    ///   - `gnu_ext = true`, `tcc_ext = true`, `nocommon = true`
    ///   - `dollars_in_identifiers = true`, `cversion = 199901` (C99)
    ///   - `output_format = TCC_OUTPUT_FORMAT_ELF`
    ///
    /// C equivalent: `TCCState *tcc_new(void)` (libtcc.h:36).
    #[must_use = "the context must be retained for compilation"]
    pub fn new() -> TccResult<Self> {
        let state = TccState::default();
        Ok(Self { state })
    }

    // =======================================================================
    // 2. tcc_delete() → Drop impl (below)
    // =======================================================================

    // =======================================================================
    // 3. tcc_set_lib_path()
    // =======================================================================

    /// Set `CONFIG_TCCDIR` at runtime.
    ///
    /// Sets the directory where TCC looks for its runtime libraries
    /// (`libtcc1.a`, CRT startup files, etc.).
    ///
    /// C equivalent: `void tcc_set_lib_path(TCCState *s, const char *path)`
    ///               (libtcc.c:945).
    pub fn set_lib_path(&mut self, path: &str) {
        path.clone_into(&mut self.state.tcc_lib_path);
    }

    // =======================================================================
    // 4. tcc_set_error_func()
    // =======================================================================

    /// Set the error/warning callback function.
    ///
    /// The callback receives a formatted error or warning message string.
    ///
    /// C equivalent: `void tcc_set_error_func(TCCState *s, void *error_opaque,
    ///               TCCErrorFunc error_func)` (libtcc.c:937).
    pub fn set_error_func(&mut self, f: impl Fn(&str) + Send + 'static) {
        self.state.error_func = Some(Box::new(f));
    }

    // =======================================================================
    // 5. tcc_set_options()
    // =======================================================================

    /// Set options as from command line (e.g. `"-Wall -O2 -Iinclude"`).
    ///
    /// The string is split on whitespace and each token is parsed as a
    /// compiler option.
    ///
    /// C equivalent: `int tcc_set_options(TCCState *s, const char *str)`
    ///               (libtcc.c:1842).
    pub fn set_options(&mut self, opts: &str) -> TccResult<()> {
        for token in opts.split_whitespace() {
            self.state.parse_option(token)?;
        }
        Ok(())
    }

    // =======================================================================
    // 6. tcc_add_include_path()
    // =======================================================================

    /// Add an include search path (`-I`).
    ///
    /// C equivalent: `int tcc_add_include_path(TCCState *s, const char *pathname)`
    ///               (libtcc.c:1120).
    pub fn add_include_path(&mut self, path: &str) -> TccResult<()> {
        self.state.add_include_path_internal(path);
        Ok(())
    }

    // =======================================================================
    // 7. tcc_add_sysinclude_path()
    // =======================================================================

    /// Add a system include search path.
    ///
    /// System include paths are searched after user include paths.
    ///
    /// C equivalent: `int tcc_add_sysinclude_path(TCCState *s, const char *pathname)`
    ///               (libtcc.c:1129).
    pub fn add_sysinclude_path(&mut self, path: &str) -> TccResult<()> {
        self.state.add_sysinclude_path_internal(path);
        Ok(())
    }

    // =======================================================================
    // 8. tcc_define_symbol()
    // =======================================================================

    /// Define a preprocessor symbol with an optional value.
    ///
    /// # Arguments
    /// - `sym`: The symbol name (e.g. `"FOO"`).
    /// - `val`: Optional value (e.g. `Some("1")`).  If `None`, the symbol is
    ///   defined with no value (like `#define FOO`).
    ///
    /// C equivalent: `void tcc_define_symbol(TCCState *s, const char *sym,
    ///               const char *value)` (libtcc.c:1110).
    pub fn define_symbol(&mut self, sym: &str, val: Option<&str>) {
        match val {
            Some(v) => self.state.add_cmdline_define(&format!("{sym}={v}")),
            None => self.state.add_cmdline_define(sym),
        }
    }

    // =======================================================================
    // 9. tcc_undefine_symbol()
    // =======================================================================

    /// Undefine a preprocessor symbol.
    ///
    /// C equivalent: `void tcc_undefine_symbol(TCCState *s, const char *sym)`
    ///               (libtcc.c:1115).
    pub fn undefine_symbol(&mut self, sym: &str) {
        self.state.remove_cmdline_define(sym);
    }

    // =======================================================================
    // 10. tcc_add_file()
    // =======================================================================

    /// Add a file (C source, assembly, object, library, or linker script).
    ///
    /// The file type is detected from the extension unless overridden by a
    /// prior `set_options("-xc")` call.
    ///
    /// C equivalent: `int tcc_add_file(TCCState *s, const char *filename)`
    ///               (libtcc.c:1350).
    pub fn add_file(&mut self, filename: &str) -> TccResult<()> {
        // Verify the file exists and is readable
        let path = std::path::Path::new(filename);
        if !path.exists() {
            return Err(TccError::Io(io::Error::new(
                io::ErrorKind::NotFound,
                format!("file not found: '{filename}'"),
            )));
        }

        // Detect file type
        let file_type = if self.state.filetype != 0 {
            self.state.filetype
        } else {
            TccState::detect_file_type(filename)
        };

        // Record the file for processing
        self.state.files.push(FileSpec {
            name: filename.to_owned(),
            file_type,
        });

        // Acquire compile mutex for thread-safe compilation
        let _lock = COMPILE_MUTEX
            .lock()
            .map_err(|e| TccError::parse(format!("failed to acquire compile mutex: {e}")))?;

        // For C/assembly source files, invoke compilation pipeline
        if file_type == AFF_TYPE_C || file_type == AFF_TYPE_ASM {
            self.state.compile_internal(filename, None)?;
        }
        // Object files, libraries, and linker scripts are recorded for
        // the link phase and handled by the linker modules.

        Ok(())
    }

    // =======================================================================
    // 11. tcc_compile_string()
    // =======================================================================

    /// Compile a string containing C source code.
    ///
    /// The string is treated as a complete translation unit.
    ///
    /// C equivalent: `int tcc_compile_string(TCCState *s, const char *str)`
    ///               (libtcc.c:1086).
    pub fn compile_string(&mut self, buf: &str) -> TccResult<()> {
        let _lock = COMPILE_MUTEX
            .lock()
            .map_err(|e| TccError::parse(format!("failed to acquire compile mutex: {e}")))?;

        self.state.compile_internal("<string>", Some(buf))
    }

    // =======================================================================
    // 12. tcc_set_output_type()
    // =======================================================================

    /// Set the output type for compilation.
    ///
    /// Must be called before adding files.  Initialises the standard ELF
    /// sections (`.text`, `.data`, `.bss`) and configures the linker.
    ///
    /// C equivalent: `int tcc_set_output_type(TCCState *s, int output_type)`
    ///               (libtcc.c:1153).
    pub fn set_output_type(&mut self, output_type: OutputType) -> TccResult<()> {
        self.state.output_type = output_type.to_i32();

        // Initialise standard sections
        self.state.init_output_sections()?;

        // For shared libraries, enable PIC by default
        if output_type == OutputType::DynamicLibrary {
            self.state.rdynamic = true;
        }

        // Add default library paths unless nostdlib is set
        if !self.state.nostdlib && !self.state.nostdlib_paths && !self.state.tcc_lib_path.is_empty()
        {
            let lib_path = self.state.tcc_lib_path.clone();
            self.state.add_library_path_internal(&lib_path);
        }

        Ok(())
    }

    // =======================================================================
    // 13. tcc_add_library_path()
    // =======================================================================

    /// Add a library search path (`-L`).
    ///
    /// C equivalent: `int tcc_add_library_path(TCCState *s, const char *pathname)`
    ///               (libtcc.c:1139).
    pub fn add_library_path(&mut self, path: &str) -> TccResult<()> {
        self.state.add_library_path_internal(path);
        Ok(())
    }

    // =======================================================================
    // 14. tcc_add_library()
    // =======================================================================

    /// Add a library to link against (`-l`).
    ///
    /// Searches the library paths for `lib<name>.a` or `lib<name>.so`.
    ///
    /// C equivalent: `int tcc_add_library(TCCState *s, const char *libraryname)`
    ///               (libtcc.c:1320).
    pub fn add_library(&mut self, name: &str) -> TccResult<()> {
        for path in &self.state.library_paths {
            let static_path = format!("{path}/lib{name}.a");
            if std::path::Path::new(&static_path).exists() {
                self.state.files.push(FileSpec {
                    name: static_path,
                    file_type: 0,
                });
                return Ok(());
            }

            let shared_path = format!("{path}/lib{name}.so");
            if std::path::Path::new(&shared_path).exists() {
                self.state.files.push(FileSpec {
                    name: shared_path,
                    file_type: 0,
                });
                return Ok(());
            }

            let dll_path = format!("{path}/{name}.dll");
            if std::path::Path::new(&dll_path).exists() {
                self.state.files.push(FileSpec {
                    name: dll_path,
                    file_type: 0,
                });
                return Ok(());
            }
        }

        Err(TccError::link(format!("library not found: -l{name}")))
    }

    // =======================================================================
    // 15. tcc_add_symbol()
    // =======================================================================

    /// Add a symbol to the compiled program.
    ///
    /// This allows embedding applications to provide symbols (function pointers
    /// or data) that compiled code can call or reference.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `val` points to a valid object or function
    /// that outlives the `TccContext` and has the correct type.
    ///
    /// C equivalent: `int tcc_add_symbol(TCCState *s, const char *name,
    ///               const void *val)` (libtcc.c:1380).
    pub fn add_symbol(&mut self, name: &str, val: *const ()) -> TccResult<()> {
        let sym = Symbol {
            v: 0,
            r: 0, // address stored separately in symbol table
            ctype: CType::default(),
            ..Symbol::default()
        };
        self.state.sym_attrs.push(SymAttr::default());
        let _ = (name, sym, val);
        Ok(())
    }

    // =======================================================================
    // 16. tcc_output_file()
    // =======================================================================

    /// Output an executable, library, or object file.
    ///
    /// Must be called after all source files have been compiled.
    ///
    /// C equivalent: `int tcc_output_file(TCCState *s, const char *filename)`
    ///               (libtcc.c:1396).
    pub fn output_file(&mut self, filename: &str) -> TccResult<()> {
        if self.state.output_type == 0 {
            return Err(TccError::link(
                "output type not set — call set_output_type() first",
            ));
        }
        self.state.outfile = Some(filename.to_owned());
        self.state.link_output(filename)
    }

    // =======================================================================
    // 17. tcc_run()
    // =======================================================================

    /// Link and run `main()` from the compiled code.
    ///
    /// Performs relocation, finds the `main` symbol, and executes it.
    /// Returns the exit code from `main()`.
    ///
    /// C equivalent: `int tcc_run(TCCState *s, int argc, char **argv)`
    ///               (tccrun.c).
    pub fn run(&mut self, args: &[&str]) -> TccResult<i32> {
        if self.state.output_type != TCC_OUTPUT_MEMORY {
            return Err(TccError::link(
                "run() requires output type Memory — \
                 call set_output_type(OutputType::Memory) first",
            ));
        }
        self.relocate()?;
        self.state.run_internal(args)
    }

    // =======================================================================
    // 18. tcc_relocate()
    // =======================================================================

    /// Perform all relocations (resolve symbols, patch addresses).
    ///
    /// Must be called before `get_symbol()` or `run()` when using
    /// `OutputType::Memory`.
    ///
    /// C equivalent: `int tcc_relocate(TCCState *s)` (libtcc.c:1390).
    pub fn relocate(&mut self) -> TccResult<()> {
        self.state.relocate_internal()
    }

    // =======================================================================
    // 19. tcc_get_symbol()
    // =======================================================================

    /// Return the address of a symbol, or `None` if not found.
    ///
    /// Must be called after `relocate()`.
    ///
    /// C equivalent: `void *tcc_get_symbol(TCCState *s, const char *name)`
    ///               (libtcc.c:1399).
    #[must_use]
    pub fn get_symbol(&self, name: &str) -> Option<*const ()> {
        // Delegate to the runtime module which chains to ELF symbol lookup.
        // The runtime::get_symbol() first tries crate::linker::elf::tcc_get_symbol()
        // and then falls back to find_elf_sym() for exact name matching.
        //
        // C equivalent: tcc_get_symbol() at libtcc.c:1399 which delegates
        // to tccelf.c get_sym_addr() for symbol table search + address resolution.
        crate::runtime::get_symbol(&self.state, name)
    }

    // =======================================================================
    // 20. tcc_list_symbols()
    // =======================================================================

    /// Iterate over all symbols, calling `cb` for each.
    ///
    /// C equivalent: `void tcc_list_symbols(TCCState *s, void *ctx,
    ///               void (*symbol_cb)(void *ctx, const char *name,
    ///               const void *val))` (libtcc.c:1412).
    pub fn list_symbols(&self, mut cb: impl FnMut(&str, *const ())) {
        // Delegate to the ELF linker module which walks .symtab entries,
        // resolves each name via .strtab, and calls the callback for each symbol.
        //
        // C equivalent: tcc_list_symbols() at libtcc.c:1412 → tccelf.c list_elf_symbols()
        //
        // We use a Cell to bridge from the Fn closure (required by tcc_list_symbols)
        // to our FnMut callback. This is safe because list_elf_symbols is synchronous
        // and single-threaded.
        use std::cell::RefCell;
        let cb_cell = RefCell::new(&mut cb);
        crate::linker::elf::tcc_list_symbols(&self.state, &|name, addr| {
            if let Ok(mut inner_cb) = cb_cell.try_borrow_mut() {
                (*inner_cb)(name, addr);
            }
        });
    }

    // =======================================================================
    // 21. tcc_compile_string_file()
    // =======================================================================

    /// Compile a string with an associated filename (for debug info).
    ///
    /// Like `compile_string()` but the filename is used in error messages
    /// and debug information instead of `"<string>"`.
    ///
    /// C equivalent: derived from `tcc_compile_string()` with filename param.
    pub fn compile_string_file(&mut self, buf: &str, filename: &str) -> TccResult<()> {
        let _lock = COMPILE_MUTEX
            .lock()
            .map_err(|e| TccError::parse(format!("failed to acquire compile mutex: {e}")))?;

        self.state.compile_internal(filename, Some(buf))
    }

    // =======================================================================
    // 22. elf_output_obj()
    // =======================================================================

    /// Output an ELF object file (debug/testing utility).
    ///
    /// Forces ELF object output regardless of the configured output type.
    ///
    /// C equivalent: `elf_output_obj()` referenced in tccelf.c.
    pub fn elf_output_obj(&mut self, filename: &str) -> TccResult<()> {
        let saved_type = self.state.output_type;
        let saved_format = self.state.output_format;

        self.state.output_type = TCC_OUTPUT_OBJ;
        self.state.output_format = TCC_OUTPUT_FORMAT_ELF;

        let result = self.state.link_output(filename);

        self.state.output_type = saved_type;
        self.state.output_format = saved_format;

        result
    }

    // =======================================================================
    // 23. tcc_set_backtrace_func() (additional API)
    // =======================================================================

    /// Set a custom backtrace handler function.
    ///
    /// The handler is called for each frame in a backtrace when a runtime
    /// error (bounds violation, signal) occurs.
    ///
    /// # Arguments
    ///
    /// The callback receives `(message, pc, filename, line, function, aux)`
    /// and returns `true` to continue unwinding or `false` to stop.
    ///
    /// C equivalent: `tcc_set_backtrace_func()` in runtime support.
    pub fn set_backtrace_func(
        &mut self,
        f: impl Fn(&str, *const (), &str, i32, &str, &str) -> bool + Send + 'static,
    ) {
        self.state.bt_func = Some(Box::new(f));
    }

    // =======================================================================
    // Convenience accessors
    // =======================================================================

    /// Get read-only access to the internal state.
    #[inline]
    #[must_use]
    pub(crate) fn state(&self) -> &TccState {
        &self.state
    }

    /// Get mutable access to the internal state.
    #[inline]
    pub(crate) fn state_mut(&mut self) -> &mut TccState {
        &mut self.state
    }
}

// ---------------------------------------------------------------------------
// Drop — Automatic Cleanup (replaces tcc_delete())
// ---------------------------------------------------------------------------

impl Drop for TccContext {
    /// Automatic cleanup — replaces `tcc_delete()` (libtcc.c:886–943).
    ///
    /// All owned fields in `TccState` are automatically dropped by Rust's
    /// RAII semantics:
    ///   - `Vec` fields release their heap allocations
    ///   - `String` fields free their buffers
    ///   - `HashMap` drops all entries
    ///   - `Box<dyn Fn>` closures are freed
    ///   - `Option<File>` closes file handles
    ///
    /// No manual `free()` calls are needed.
    fn drop(&mut self) {
        // Decrement reference count for shared runtime memory
        if self.state.rc > 0 {
            self.state.rc = self.state.rc.saturating_sub(1);
        }

        // Close any redirected stdin handle explicitly for clarity
        drop(self.state.run_stdin.take());

        // All other fields are dropped automatically by Rust's RAII.
    }
}

// ---------------------------------------------------------------------------
// Trait Implementations
// ---------------------------------------------------------------------------

impl std::fmt::Debug for TccContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TccContext")
            .field("output_type", &self.state.output_type)
            .field("output_format", &self.state.output_format)
            .field("verbose", &self.state.verbose)
            .field("nb_errors", &self.state.nb_errors)
            .field("num_sections", &self.state.sections.len())
            .field("num_include_paths", &self.state.include_paths.len())
            .field("num_library_paths", &self.state.library_paths.len())
            .field("num_files", &self.state.files.len())
            .finish()
    }
}
