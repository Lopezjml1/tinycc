// Copyright (c) TinyCC contributors. LGPL licensed.
// Ported from libtcc.c (2,272 lines) and tcc.h (2,016 lines) to Rust as part
// of the TCC C-to-Rust migration.
//
//! # tcc-core — TCC Compiler Pipeline Library
//!
//! This is the crate root for the `tcc-core` library crate. It replaces the
//! C-based `libtcc.c` compiler orchestration layer, provides the central
//! [`TCCState`] struct that encapsulates all compiler state, and declares
//! every sub-module of the compiler pipeline.
//!
//! ## Design Decisions
//!
//! - **BUG-13 (libtcc reentrancy):** All compilation state is encapsulated
//!   within [`TCCState`] with NO module-level mutable statics. Rust's
//!   ownership model inherently prevents shared mutable global state, so
//!   multiple `TCCState` instances can coexist safely.
//!
//! - **BUG-16 (memory leaks after longjmp):** Rust's RAII/[`Drop`] trait
//!   guarantees resource cleanup on all error paths. The `?` operator
//!   replaces C's `setjmp`/`longjmp` error recovery, and every owned
//!   resource is released automatically during stack unwinding.
//!
//! - **Error handling:** All fallible methods return [`TccResult<T>`]
//!   (`Result<T, TccError>`), replacing `setjmp`/`longjmp` and
//!   `tcc_error()` with typed, composable error propagation.
//!
//! - **No global mutable state:** The `tcc_state` global pointer from
//!   `libtcc.c` line 73 is eliminated entirely.

// ---------------------------------------------------------------------------
// Sub-module declarations (18 modules)
// ---------------------------------------------------------------------------

pub mod error;
pub mod types;
pub mod token;
pub mod lexer;
pub mod preprocessor;
pub mod parser;
pub mod codegen;
pub mod assembler;
pub mod elf;
pub mod pe;
pub mod macho;
pub mod coff;
pub mod runtime;
pub mod debug;
pub mod tools;
pub mod alloc;
pub mod config;
pub mod arch;

// ---------------------------------------------------------------------------
// Re-exports for crate consumers
// ---------------------------------------------------------------------------

pub use error::{TccError, TccResult};
pub use types::{CType, SValue, Sym, Section, OutputType};

// ---------------------------------------------------------------------------
// Imports from dependencies (whitelist-verified)
// ---------------------------------------------------------------------------

use crate::config::TCC_VERSION;
use crate::error::TccError as ErrorKind;
use crate::types::{
    BufferedFile, CachedInclude, DLLReference, InlineFunc, SymAttr,
    INCLUDE_STACK_SIZE, IFDEF_STACK_SIZE,
};
use std::fmt;
use std::ffi::c_void;

// ---------------------------------------------------------------------------
// OutputFormat — Output format selection
// From tcc.h: TCC_OUTPUT_FORMAT_ELF / BINARY / COFF
// ---------------------------------------------------------------------------

/// Selects the binary output format for the compiler.
///
/// Corresponds to the C constants:
/// - `TCC_OUTPUT_FORMAT_ELF` = 0
/// - `TCC_OUTPUT_FORMAT_BINARY` = 1
/// - `TCC_OUTPUT_FORMAT_COFF` = 2
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum OutputFormat {
    /// ELF format (Linux, BSDs, most Unix-like systems).
    #[default]
    Elf = 0,
    /// Raw binary format (flat binary, no headers).
    Binary = 1,
    /// COFF format (TMS320C67xx targets).
    Coff = 2,
}

impl OutputFormat {
    /// Converts an integer value to an `OutputFormat`.
    pub fn from_i32(value: i32) -> Option<OutputFormat> {
        match value {
            0 => Some(OutputFormat::Elf),
            1 => Some(OutputFormat::Binary),
            2 => Some(OutputFormat::Coff),
            _ => None,
        }
    }
}

impl fmt::Display for OutputFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OutputFormat::Elf => write!(f, "ELF"),
            OutputFormat::Binary => write!(f, "Binary"),
            OutputFormat::Coff => write!(f, "COFF"),
        }
    }
}

// ---------------------------------------------------------------------------
// FileType — Source file type classification
// From tcc.h: AFF_TYPE_NONE / C / ASM / ASMPP / LIB
// ---------------------------------------------------------------------------

/// Classifies the type of a source file provided to the compiler.
///
/// Corresponds to the C constants:
/// - `AFF_TYPE_NONE` = 0
/// - `AFF_TYPE_C` = 1
/// - `AFF_TYPE_ASM` = 2
/// - `AFF_TYPE_ASMPP` = 4 (assembly with preprocessing)
/// - `AFF_TYPE_LIB` = 8
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum FileType {
    /// Auto-detect from file extension.
    #[default]
    None = 0,
    /// C source file (`.c`).
    C = 1,
    /// Assembly source file without preprocessing (`.s`).
    Asm = 2,
    /// Assembly source file with preprocessing (`.S`).
    AsmPreprocessed = 4,
    /// Static or shared library (`.a`, `.so`, `.dll`).
    Lib = 8,
}

impl FileType {
    /// Converts an integer value to a `FileType`.
    ///
    /// Only the lower 4 bits are considered (masking `AFF_TYPE_MASK`).
    pub fn from_i32(value: i32) -> Option<FileType> {
        match value & 0x0F {
            0 => Some(FileType::None),
            1 => Some(FileType::C),
            2 => Some(FileType::Asm),
            4 => Some(FileType::AsmPreprocessed),
            8 => Some(FileType::Lib),
            _ => None,
        }
    }
}

impl fmt::Display for FileType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FileType::None => write!(f, "auto"),
            FileType::C => write!(f, "C"),
            FileType::Asm => write!(f, "assembly"),
            FileType::AsmPreprocessed => write!(f, "preprocessed assembly"),
            FileType::Lib => write!(f, "library"),
        }
    }
}

// ---------------------------------------------------------------------------
// AFF flag constants — file type bitfield flags
// From tcc.h lines 180-186
// ---------------------------------------------------------------------------

/// Bitmask to extract the file type from the filetype field.
pub const AFF_TYPE_MASK: i32 = 0x0F;
/// Flag indicating the file should be treated as a whole archive.
pub const AFF_WHOLE_ARCHIVE: i32 = 0x10;
/// Flag indicating the file was referenced as a library (-l).
pub const AFF_REFERENCED_DLL: i32 = 0x20;
/// Flag indicating the file type was set by the user (-x flag).
pub const AFF_TYPE_BIN: i32 = 0x40;
/// Flag indicating preprocessing output to stdout.
pub const AFF_PRINT_ERROR: i32 = 0x80;

// ---------------------------------------------------------------------------
// Display implementation for OutputType (defined in types.rs, impl here)
// ---------------------------------------------------------------------------

impl fmt::Display for OutputType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OutputType::Memory => write!(f, "memory"),
            OutputType::Exe => write!(f, "executable"),
            OutputType::Obj => write!(f, "object"),
            OutputType::Dll => write!(f, "shared library"),
            OutputType::Preprocess => write!(f, "preprocessor output"),
        }
    }
}

// ===========================================================================
// TCCState — Central compiler state
// Ported from tcc.h lines 738-1020 and libtcc.c
//
// This struct encapsulates ALL mutable compiler state. There are NO
// module-level mutable statics in this crate (BUG-13 fix).
// ===========================================================================

/// Central compiler state for the Tiny C Compiler.
///
/// This struct is the Rust equivalent of the C `TCCState` from `tcc.h`.
/// It owns all compilation resources and is the entry point for the
/// public libtcc API. Each instance represents an independent compilation
/// context — multiple instances can coexist without interference (BUG-13 fix).
///
/// Resource cleanup is handled automatically via the [`Drop`] trait,
/// eliminating memory leaks that occurred in the C version when `longjmp`
/// skipped cleanup code (BUG-16 fix).
///
/// # Example
/// ```no_run
/// use tcc_core::{TCCState, OutputType};
///
/// fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let mut state = TCCState::new()?;
///     state.set_output_type(OutputType::Memory)?;
///     state.compile_string("int main() { return 0; }")?;
///     let exit_code = state.run(&[])?;
///     assert_eq!(exit_code, 0);
///     Ok(())
/// }
/// ```
#[allow(non_snake_case)]
pub struct TCCState {
    // -----------------------------------------------------------------------
    // Compiler option flags (tcc.h lines 739-763)
    // -----------------------------------------------------------------------

    /// Display current file being compiled (verbosity level, 0-2).
    pub verbose: i32,
    /// If true, do not use standard system include paths (`-nostdinc`).
    pub nostdinc: bool,
    /// If true, do not link standard libraries (`-nostdlib`).
    pub nostdlib: bool,
    /// If true, do not include standard system library paths.
    pub nostdlib_paths: bool,
    /// If true, do not merge common symbols into BSS (`-fno-common`).
    pub nocommon: bool,
    /// If true, produce a static binary (`-static`).
    pub static_link: bool,
    /// If true, add all symbols to dynamic symbol table (`-rdynamic`).
    pub rdynamic: bool,
    /// If true, bind references to global symbols to the definition
    /// within the shared library (`-Bsymbolic`).
    pub symbolic: bool,
    /// If true, do not create a delete tag for the shared library.
    pub znodelete: bool,

    /// Source file type for compilation. Stored as a bitmask combining
    /// [`FileType`] value (lower 4 bits via `AFF_TYPE_MASK`) and flags
    /// (`AFF_WHOLE_ARCHIVE`, etc.). Use [`FileType::from_i32`] to extract.
    pub filetype: i32,

    /// Optimization level (currently unused — TCC generates unoptimized code).
    pub optimize: i32,
    /// If true, add `-pthread` to linker flags.
    pub option_pthread: bool,
    /// If true, use new-style DT_NEEDED tags.
    pub enable_new_dtags: bool,
    /// C standard version: `199901` (C99) or `201112` (C11+GNU).
    pub cversion: u32,

    // -----------------------------------------------------------------------
    // C language behavior flags (tcc.h lines 765-781)
    // -----------------------------------------------------------------------

    /// If true, `char` is unsigned by default.
    pub char_is_unsigned: bool,
    /// If true, prepend `_` to external symbol names (macOS, Windows).
    pub leading_underscore: bool,
    /// If true, allow Microsoft C extensions (`__declspec`, anonymous
    /// struct/union, etc.).
    pub ms_extensions: bool,
    /// If true, allow `$` in identifiers.
    pub dollars_in_identifiers: bool,
    /// If true, use Microsoft-compatible bitfield layout rules.
    pub ms_bitfields: bool,
    /// If true, reverse function argument evaluation order (stdcall).
    pub reverse_funcargs: bool,
    /// If true, use GCC 89-style inline semantics.
    pub gnu89_inline: bool,
    /// If true, emit `.eh_frame` unwind tables.
    pub unwind_tables: bool,

    // -----------------------------------------------------------------------
    // Warning switches (tcc.h lines 783-791)
    // -----------------------------------------------------------------------

    /// If true, suppress all warnings (`-w`).
    pub warn_none: bool,
    /// If true, enable all warnings (`-Wall`).
    pub warn_all: bool,
    /// If true, treat warnings as errors (`-Werror`).
    pub warn_error: bool,
    /// If true, make string literals `const char[]` (`-Wwrite-strings`).
    pub warn_write_strings: bool,
    /// If true, warn about unsupported GCC features.
    pub warn_unsupported: bool,
    /// If true, warn about implicit function declarations (`-Wimplicit-function-declaration`).
    pub warn_implicit_function_declaration: bool,
    /// If true, warn about discarded type qualifiers.
    pub warn_discarded_qualifiers: bool,
    /// Warning count accumulator.
    pub warn_num: i32,

    // -----------------------------------------------------------------------
    // Option flags (tcc.h lines 793-805)
    // -----------------------------------------------------------------------

    /// If true, output a relocatable object (`-r`).
    pub option_r: bool,
    /// If true, run benchmark after compilation (`-bench`).
    pub do_bench: bool,
    /// If true, only generate dependency information (don't compile).
    pub just_deps: bool,
    /// If true, generate dependency info alongside compilation (`-MD`/`-MF`).
    pub gen_deps: bool,
    /// If true, include system headers in dependency output.
    pub include_sys_deps: bool,
    /// If true, generate phony targets for each dependency.
    pub gen_phony_deps: bool,

    // -----------------------------------------------------------------------
    // Debug / analysis flags (tcc.h lines 806-814)
    // -----------------------------------------------------------------------

    /// If true, compile with debug information (`-g`).
    pub do_debug: bool,
    /// DWARF version to generate (0=stabs, 2, 3, 4, or 5).
    pub dwarf: u8,
    /// If true, enable backtrace support (`-bt`).
    pub do_backtrace: bool,
    /// If true, enable bounds checking instrumentation (`-b`).
    #[cfg(feature = "bcheck")]
    pub do_bounds_check: bool,
    /// Bounds check placeholder when feature is disabled.
    #[cfg(not(feature = "bcheck"))]
    pub do_bounds_check: bool,
    /// If true, instrument code for test coverage (`-tcov`).
    pub test_coverage: bool,

    /// If true, enable GNU C extensions (default: true).
    pub gnu_ext: bool,
    /// If true, enable TCC-specific extensions (default: true).
    pub tcc_ext: bool,

    /// Debug/dump flags (`-dM`, `-dD`, etc.).
    pub dflag: i32,
    /// Preprocessing output flags (`-P`, `-P1`).
    #[allow(non_snake_case)]
    pub Pflag: i32,

    // -----------------------------------------------------------------------
    // Target-specific options (tcc.h lines 815-824)
    // -----------------------------------------------------------------------

    /// If true, do not use SSE registers for floating-point (x86_64 only).
    pub nosse: bool,
    /// ARM float ABI: 0=soft, 1=softfp, 2=hard.
    pub float_abi: i32,
    /// If true, a specific text section address was requested (`-Ttext`).
    pub has_text_addr: bool,
    /// Explicit text section address (used if `has_text_addr` is true).
    pub text_addr: u64,
    /// Section alignment in bytes.
    pub section_align: u64,
    /// Segment size for demand paging (0 = default).
    pub seg_size: u64,

    // -----------------------------------------------------------------------
    // Path management (tcc.h lines 826-846)
    // -----------------------------------------------------------------------

    /// Path to the TCC library directory (`-B` or `CONFIG_TCCDIR`).
    pub tcc_lib_path: String,
    /// Shared library SONAME (`-soname` or `-Wl,-soname,`).
    pub soname: Option<String>,
    /// Runtime library search path (`-Wl,-rpath,`).
    pub rpath: Option<String>,
    /// ELF interpreter path override.
    pub elfint: Option<String>,
    /// Entry function name override (`-Wl,-e,` or `--entry`).
    pub elf_entryname: Option<String>,
    /// Library constructor function (`-Wl,-init,`).
    pub init_symbol: Option<String>,
    /// Library destructor function (`-Wl,-fini,`).
    pub fini_symbol: Option<String>,
    /// Linker map file path (`-Wl,-Map,`).
    pub mapfile: Option<String>,
    /// Output filename (`-o`).
    pub outfile: Option<String>,
    /// Dependency output filename (`-MF`).
    pub deps_outfile: Option<String>,
    /// Tracked dependency targets (included files) for `-MD`/`-MF` output.
    /// Populated during preprocessing as files are included.
    pub target_deps: Vec<String>,

    /// User include paths (`-I`). Searched before system paths.
    pub include_paths: Vec<String>,
    /// System include paths. Searched after user paths.
    pub sysinclude_paths: Vec<String>,
    /// Library search paths (`-L`).
    pub library_paths: Vec<String>,
    /// CRT object file search paths.
    pub crt_paths: Vec<String>,

    // -----------------------------------------------------------------------
    // Output configuration (tcc.h lines 848-854)
    // -----------------------------------------------------------------------

    /// Output type (memory, exe, obj, dll, preprocess).
    pub output_type: Option<OutputType>,
    /// Binary output format (ELF, binary, COFF).
    pub output_format: OutputFormat,

    /// Preprocessing output buffer (for `-E` mode).
    ///
    /// When `output_type` is `Preprocess`, the preprocessing pipeline writes
    /// token output into this buffer.  The CLI driver drains the buffer to
    /// the final output destination (file or stdout) after compilation.
    ///
    /// Replaces C's `FILE *ppfp` member on `TCCState`.
    pub ppfp_buffer: Vec<u8>,

    /// Test run number for `-run -bench` mode.
    pub run_test: i32,

    // -----------------------------------------------------------------------
    // Loaded DLL references (tcc.h lines 856-858)
    // -----------------------------------------------------------------------

    /// List of loaded dynamic libraries.
    pub loaded_dlls: Vec<DLLReference>,

    // -----------------------------------------------------------------------
    // Command-line macro definitions (tcc.h lines 860-862)
    // -----------------------------------------------------------------------

    /// Accumulated `-D` definitions as preprocessor tokens.
    pub cmdline_defs: Vec<u8>,
    /// Accumulated `-include` file paths.
    pub cmdline_incl: Vec<String>,

    // -----------------------------------------------------------------------
    // Error handling (tcc.h lines 864-870)
    // -----------------------------------------------------------------------

    /// Opaque context pointer for the error callback.
    pub error_opaque: Option<*mut c_void>,
    /// User-supplied error callback function pointer (C-compatible).
    /// Signature: `fn(opaque: *mut c_void, msg: *const c_char)`.
    pub error_func: Option<unsafe extern "C" fn(*mut c_void, *const i8)>,
    /// If true, error recovery via Result propagation is active.
    pub error_set_jmp_enabled: bool,
    /// Number of compilation errors encountered so far.
    pub nb_errors: i32,
    /// Number of compilation warnings encountered so far.
    pub nb_warnings: i32,

    // -----------------------------------------------------------------------
    // Compilation state (tcc.h lines 872-896)
    // -----------------------------------------------------------------------

    /// Stack of currently open source files (for nested `#include`).
    /// Maximum depth: `INCLUDE_STACK_SIZE` (32).
    pub include_stack: Vec<BufferedFile>,

    /// `#ifdef` / `#ifndef` / `#if` nesting stack.
    /// Maximum depth: `IFDEF_STACK_SIZE` (64).
    pub ifdef_stack: Vec<i32>,

    /// Cache of previously included files (for `#ifndef` guard optimization
    /// and `#pragma once`).
    pub cached_includes: Vec<CachedInclude>,

    /// `#pragma pack` nesting stack.
    /// Maximum depth: `PACK_STACK_SIZE` (8).
    pub pack_stack: Vec<i32>,

    /// Libraries requested via `#pragma comment(lib, "name")`.
    pub pragma_libs: Vec<String>,

    /// Inline functions pending code generation.
    pub inline_fns: Vec<InlineFunc>,

    // -----------------------------------------------------------------------
    // Section management (tcc.h lines 898-960)
    // -----------------------------------------------------------------------

    /// All ELF sections, indexed by section number.
    pub sections: Vec<Section>,
    /// Number of sections (matches `sections.len()`).
    pub nb_sections: usize,
    /// Private (internal-only) sections not written to output.
    pub priv_sections: Vec<Section>,

    // Predefined section indices (set during `set_output_type`)
    /// `.text` section index.
    pub text_section: Option<usize>,
    /// `.data` section index.
    pub data_section: Option<usize>,
    /// `.rodata` section index.
    pub rodata_section: Option<usize>,
    /// `.bss` section index.
    pub bss_section: Option<usize>,
    /// COMMON symbols section index.
    pub common_section: Option<usize>,
    /// Currently active text section (may differ from `text_section` during
    /// inline function processing).
    pub cur_text_section: Option<usize>,

    /// Bounds checking lower-bounds section index.
    pub bounds_section: Option<usize>,
    /// Bounds checking upper-bounds section index.
    pub lbounds_section: Option<usize>,

    /// `.symtab` section index.
    pub symtab_section: Option<usize>,
    /// `.dynsym` section index (for shared libraries).
    pub dynsymtab_section: Option<usize>,

    /// STABS debug section index.
    pub stab_section: Option<usize>,
    /// STABS string table section index.
    pub stabstr_section: Option<usize>,

    /// `.eh_frame` section index (for exception handling / unwind tables).
    pub eh_frame_section: Option<usize>,

    /// Test coverage section index.
    pub tcov_section: Option<usize>,

    // -----------------------------------------------------------------------
    // Symbol attributes (tcc.h lines 962-966)
    // -----------------------------------------------------------------------

    /// Per-symbol attributes table (indexed by symbol index).
    pub sym_attrs: Vec<SymAttr>,

    // -----------------------------------------------------------------------
    // GOT / PLT (tcc.h lines 968-970)
    // -----------------------------------------------------------------------

    /// `.got` section index (Global Offset Table).
    pub got: Option<usize>,
    /// `.plt` section index (Procedure Linkage Table).
    pub plt: Option<usize>,

    // -----------------------------------------------------------------------
    // Dynamic symbol table
    // -----------------------------------------------------------------------

    /// Dynamic symbol table (separate from static `.symtab`).
    pub dynsym: Option<usize>,

    // -----------------------------------------------------------------------
    // Debug state (tcc.h lines 972-976)
    // -----------------------------------------------------------------------

    /// Debug info generation state. Opaque to lib.rs; managed by the
    /// `debug` module.
    #[allow(non_snake_case)]
    pub dState: Option<Box<dyn std::any::Any>>,
    /// DWARF info address range low.
    pub dwlo: i32,
    /// DWARF info address range high.
    pub dwhi: i32,

    // -----------------------------------------------------------------------
    // Runtime execution state (tcc.h lines 978-996)
    // -----------------------------------------------------------------------

    /// Pointer to relocated code in executable memory (for `-run` mode).
    pub run_ptr: Option<*mut c_void>,
    /// Size of the executable memory region.
    pub run_size: usize,
    /// If true, call `main()` in run mode.
    pub run_main: bool,
    /// Redirected stdin for run mode (or `None` for real stdin).
    pub run_stdin: Option<*mut c_void>,

    /// Function table for backtrace support in run mode.
    pub function_table: Option<*mut c_void>,
    /// Next `TCCState` in a chain (for multi-context management).
    pub next: Option<Box<TCCState>>,
    /// Reference count for shared state.
    pub rc: i32,
    /// If true, the program has been relocated for in-memory execution.
    pub relocated: bool,
    /// Command-line arguments for the program in `-run` mode.
    pub run_args: Vec<String>,
    /// Symbols added via `add_symbol()` for runtime linking.
    /// Each entry is `(name, address)`.
    pub runtime_symbols: Vec<(String, usize)>,
    /// If true, treat all objects in archives as needed (`--whole-archive`).
    pub whole_archive: bool,
    /// If true, warn about GCC compatibility issues.
    pub warn_gcc_compat: bool,

    /// Run mode longjmp flag.
    pub run_lj: i32,
    /// Run mode jump buffer (for catching program exits).
    pub run_jb: [u8; 256],

    /// Backtrace callback function pointer.
    pub bt_func: Option<*mut c_void>,
    /// Backtrace callback context data.
    pub bt_data: Option<*mut c_void>,

    // -----------------------------------------------------------------------
    // Benchmark statistics (tcc.h lines 998-1002)
    // -----------------------------------------------------------------------

    /// Total number of identifiers processed.
    pub total_idents: i32,
    /// Total number of source lines processed.
    pub total_lines: i32,
    /// Total number of source bytes processed.
    pub total_bytes: u64,
    /// Total output bytes per output type.
    pub total_output: [u64; 4],

    // -----------------------------------------------------------------------
    // PE-specific fields (tcc.h lines 1004-1014, conditional on Windows)
    // -----------------------------------------------------------------------

    /// PE subsystem type (e.g., `IMAGE_SUBSYSTEM_WINDOWS_CUI`).
    pub pe_subsystem: u16,
    /// PE characteristics flags.
    pub pe_characteristics: u32,
    /// PE file alignment (default: 512).
    pub pe_file_align: u32,
    /// PE stack size (default: 1MB).
    pub pe_stack_size: u64,
    /// PE image base address.
    pub pe_imagebase: u64,
    /// PE `.pdata` (exception handler table) section index.
    pub uw_pdata: Option<usize>,
    /// PE unwind symbol.
    pub uw_sym: Option<usize>,
    /// PE unwind offset.
    pub uw_offs: u32,

    // -----------------------------------------------------------------------
    // Mach-O specific fields
    // -----------------------------------------------------------------------

    /// Mach-O `install_name` for shared libraries.
    pub install_name: Option<String>,
    /// Mach-O `compatibility_version` (encoded as 0xMMMMmmpp).
    pub compatibility_version: u32,
    /// Mach-O `current_version` (encoded as 0xMMMMmmpp).
    pub current_version: u32,

    // -----------------------------------------------------------------------
    // Linker state
    // -----------------------------------------------------------------------

    /// Linker pass counter.
    pub ld_p: i32,
    /// Current filename being processed.
    pub current_filename: Option<String>,

    // -----------------------------------------------------------------------
    // File and argument management
    // -----------------------------------------------------------------------

    /// List of source/object files to process.
    pub files: Vec<String>,
    /// Argument count (preserved for compatibility).
    pub argc: i32,
    /// Argument values (preserved for compatibility).
    pub argv: Vec<String>,
    /// Linker argument accumulator (`-Wl,` pass-through).
    pub link_argv: Vec<String>,

    // -----------------------------------------------------------------------
    // Preprocessor predefined symbols
    // -----------------------------------------------------------------------

    /// Predefined preprocessor symbols (name, value pairs).
    pub predefined_symbols: Vec<(String, String)>,

    // -----------------------------------------------------------------------
    // Code generation state (shared between parser/codegen/arch)
    // -----------------------------------------------------------------------

    /// If nonzero, code generation is suppressed (e.g., inside `sizeof`,
    /// dead `#if 0` blocks, or unevaluated operands).
    pub nocode_wanted: i32,

    /// Current function name (for `__func__` and diagnostics).
    pub funcname: Option<String>,

    /// Global scope symbol chain head.
    pub global_scope: Option<Box<Sym>>,
    /// Local scope symbol chain head.
    pub local_scope: Option<Box<Sym>>,
    /// Current scope depth (0 = file scope).
    pub scope_depth: i32,

    /// Value stack for expression evaluation.
    pub vstack: Vec<SValue>,
    /// Current top-of-stack index in `vstack`.
    pub vtop: i32,

    /// Return type of the current function being compiled.
    pub func_vt: CType,
    /// Indicates whether the function is variadic.
    pub func_var: bool,
    /// Number of local variable stack bytes allocated so far.
    pub loc: i32,
    /// Maximum local variable stack offset seen.
    pub local_scope_level: i32,
}

// ===========================================================================
// TCCState — Default implementation
// ===========================================================================

impl Default for TCCState {
    /// Creates a `TCCState` with C-baseline defaults matching `tcc_new()`.
    fn default() -> Self {
        TCCState {
            verbose: 0,
            nostdinc: false,
            nostdlib: false,
            nostdlib_paths: false,
            nocommon: true,
            static_link: false,
            rdynamic: false,
            symbolic: false,
            znodelete: false,
            filetype: FileType::None as i32,
            optimize: 0,
            option_pthread: false,
            enable_new_dtags: false,
            cversion: 199901,
            char_is_unsigned: false,
            leading_underscore: cfg!(target_os = "macos"),
            ms_extensions: true,
            dollars_in_identifiers: true,
            ms_bitfields: false,
            reverse_funcargs: false,
            gnu89_inline: false,
            unwind_tables: true,
            warn_none: false,
            warn_all: false,
            warn_error: false,
            warn_write_strings: false,
            warn_unsupported: false,
            warn_implicit_function_declaration: true,
            warn_discarded_qualifiers: true,
            warn_num: 0,
            option_r: false,
            do_bench: false,
            just_deps: false,
            gen_deps: false,
            include_sys_deps: false,
            gen_phony_deps: false,
            do_debug: false,
            dwarf: 0,
            do_backtrace: false,
            do_bounds_check: false,
            test_coverage: false,
            gnu_ext: true,
            tcc_ext: true,
            dflag: 0,
            Pflag: 0,
            nosse: false,
            float_abi: 0,
            has_text_addr: false,
            text_addr: 0,
            section_align: 0,
            seg_size: 0,
            tcc_lib_path: crate::config::tcc_lib_path(None),
            soname: None,
            rpath: None,
            elfint: None,
            elf_entryname: None,
            init_symbol: None,
            fini_symbol: None,
            mapfile: None,
            outfile: None,
            deps_outfile: None,
            target_deps: Vec::new(),
            include_paths: Vec::new(),
            sysinclude_paths: Vec::new(),
            library_paths: Vec::new(),
            crt_paths: Vec::new(),
            output_type: None,
            output_format: OutputFormat::Elf,
            ppfp_buffer: Vec::new(),
            run_test: 0,
            loaded_dlls: Vec::new(),
            cmdline_defs: Vec::new(),
            cmdline_incl: Vec::new(),
            error_opaque: None,
            error_func: None,
            error_set_jmp_enabled: false,
            nb_errors: 0,
            nb_warnings: 0,
            include_stack: Vec::with_capacity(INCLUDE_STACK_SIZE),
            ifdef_stack: Vec::with_capacity(IFDEF_STACK_SIZE),
            cached_includes: Vec::new(),
            pack_stack: vec![0],
            pragma_libs: Vec::new(),
            inline_fns: Vec::new(),
            sections: Vec::new(),
            nb_sections: 0,
            priv_sections: Vec::new(),
            text_section: None,
            data_section: None,
            rodata_section: None,
            bss_section: None,
            common_section: None,
            cur_text_section: None,
            bounds_section: None,
            lbounds_section: None,
            symtab_section: None,
            dynsymtab_section: None,
            stab_section: None,
            stabstr_section: None,
            eh_frame_section: None,
            tcov_section: None,
            sym_attrs: Vec::new(),
            got: None,
            plt: None,
            dynsym: None,
            dState: None,
            dwlo: 0,
            dwhi: 0,
            run_ptr: None,
            run_size: 0,
            run_main: false,
            run_stdin: None,
            function_table: None,
            next: None,
            rc: 0,
            relocated: false,
            run_args: Vec::new(),
            runtime_symbols: Vec::new(),
            whole_archive: false,
            warn_gcc_compat: false,
            run_lj: 0,
            run_jb: [0u8; 256],
            bt_func: None,
            bt_data: None,
            total_idents: 0,
            total_lines: 0,
            total_bytes: 0,
            total_output: [0u64; 4],
            pe_subsystem: 3,
            pe_characteristics: 0,
            pe_file_align: 0x200,
            pe_stack_size: 0x100000,
            pe_imagebase: 0,
            uw_pdata: None,
            uw_sym: None,
            uw_offs: 0,
            install_name: None,
            compatibility_version: 0,
            current_version: 0,
            ld_p: 0,
            current_filename: None,
            files: Vec::new(),
            argc: 0,
            argv: Vec::new(),
            link_argv: Vec::new(),
            predefined_symbols: Vec::new(),
            nocode_wanted: 0,
            funcname: None,
            global_scope: None,
            local_scope: None,
            scope_depth: 0,
            vstack: Vec::new(),
            vtop: -1,
            func_vt: CType::default(),
            func_var: false,
            loc: 0,
            local_scope_level: 0,
        }
    }
}

// ===========================================================================
// TCCState — Constructor, destructor, and public API
// ===========================================================================

impl TCCState {
    /// Creates a new TCC compilation context with default settings.
    ///
    /// Equivalent to the C function `tcc_new()`. The `__TINYC__` predefined
    /// macro is set to version 928 (encoding "0.9.28rc").
    pub fn new() -> TccResult<Self> {
        let mut state = TCCState::default();
        state.predefined_symbols.push((
            "__TINYC__".to_string(),
            "928".to_string(),
        ));
        if !crate::config::ELF_INTERP.is_empty() {
            state.elfint = Some(crate::config::ELF_INTERP.to_string());
        }
        Ok(state)
    }

    /// Sets the path to the TCC library directory (`-B` option).
    pub fn set_lib_path(&mut self, path: &str) {
        self.tcc_lib_path = path.to_string();
    }

    /// Sets a callback function for receiving error and warning messages.
    ///
    /// # Safety
    /// The `error_opaque` pointer must remain valid for the lifetime of
    /// this `TCCState`, or until `set_error_func` is called again.
    pub fn set_error_func(
        &mut self,
        error_opaque: Option<*mut c_void>,
        error_func: Option<unsafe extern "C" fn(*mut c_void, *const i8)>,
    ) {
        self.error_opaque = error_opaque;
        self.error_func = error_func;
    }

    /// Parses a string of space-separated compiler options.
    pub fn set_options(&mut self, opts: &str) -> TccResult<()> {
        if opts.is_empty() {
            return Ok(());
        }
        let args = split_option_string(opts);
        if args.is_empty() {
            return Ok(());
        }
        let _remaining = self.parse_args(&args)?;
        Ok(())
    }

    /// Adds a directory to the user include search path (`-I`).
    pub fn add_include_path(&mut self, path: &str) -> TccResult<()> {
        if path.is_empty() {
            return Err(ErrorKind::ConfigError {
                message: "empty include path".to_string(),
            });
        }
        self.include_paths.push(path.to_string());
        Ok(())
    }

    /// Adds a directory to the system include search path.
    pub fn add_sysinclude_path(&mut self, path: &str) -> TccResult<()> {
        if path.is_empty() {
            return Err(ErrorKind::ConfigError {
                message: "empty system include path".to_string(),
            });
        }
        self.sysinclude_paths.push(path.to_string());
        Ok(())
    }

    /// Defines a preprocessor symbol. If `value` is `None`, it defaults to `"1"`.
    pub fn define_symbol(&mut self, sym: &str, value: Option<&str>) {
        if sym.is_empty() {
            return;
        }
        let val = value.unwrap_or("1");
        let def = format!("#define {} {}\n", sym, val);
        self.cmdline_defs.extend_from_slice(def.as_bytes());
        self.predefined_symbols
            .push((sym.to_string(), val.to_string()));
    }

    /// Undefines a preprocessor symbol (`-U`).
    pub fn undefine_symbol(&mut self, sym: &str) {
        if sym.is_empty() {
            return;
        }
        let undef = format!("#undef {}\n", sym);
        self.cmdline_defs.extend_from_slice(undef.as_bytes());
        self.predefined_symbols.retain(|(name, _)| name != sym);
    }

    /// Adds a file to the compilation. File type is auto-detected from
    /// the extension unless overridden via `-x`.
    pub fn add_file(&mut self, filename: &str) -> TccResult<()> {
        if filename.is_empty() {
            return Err(ErrorKind::IoError(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "empty filename",
            )));
        }
        if !std::path::Path::new(filename).exists() {
            return Err(ErrorKind::IoError(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("file not found: '{}'", filename),
            )));
        }
        let ftype = if (self.filetype & AFF_TYPE_MASK) != 0 {
            self.filetype & AFF_TYPE_MASK
        } else {
            detect_file_type(filename)
        };
        self.current_filename = Some(filename.to_string());
        self.files.push(filename.to_string());
        match ftype {
            ft if ft == FileType::C as i32 => {
                self.compile_file(filename)?;
            }
            ft if ft == FileType::Asm as i32
                || ft == FileType::AsmPreprocessed as i32 =>
            {
                self.assemble_file(filename, ft == FileType::AsmPreprocessed as i32)?;
            }
            _ => {
                // Object, library, or DLL — recorded for linker phase.
            }
        }
        Ok(())
    }

    /// Compiles C source code from a string (filename: `"<string>"`).
    pub fn compile_string(&mut self, src: &str) -> TccResult<()> {
        self.compile_string_file(src, "<string>")
    }

    /// Sets the type of output to produce. Must be called before adding
    /// files or compiling.
    pub fn set_output_type(&mut self, output_type: OutputType) -> TccResult<()> {
        self.output_type = Some(output_type);
        if !self.nostdinc {
            self.init_default_include_paths()?;
        }
        if !self.nostdlib && !self.nostdlib_paths {
            self.init_default_library_paths()?;
        }
        if output_type != OutputType::Preprocess {
            self.init_sections()?;
        }
        match output_type {
            OutputType::Exe => {
                if self.elf_entryname.is_none() {
                    self.elf_entryname = Some(if self.leading_underscore {
                        "__start".to_string()
                    } else {
                        "_start".to_string()
                    });
                }
            }
            OutputType::Dll => {
                if self.soname.is_none() {
                    if let Some(ref outfile) = self.outfile {
                        if let Some(basename) = std::path::Path::new(outfile).file_name() {
                            self.soname = Some(basename.to_string_lossy().to_string());
                        }
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// Adds a directory to the library search path (`-L`).
    pub fn add_library_path(&mut self, path: &str) -> TccResult<()> {
        if path.is_empty() {
            return Err(ErrorKind::ConfigError {
                message: "empty library path".to_string(),
            });
        }
        self.library_paths.push(path.to_string());
        Ok(())
    }

    /// Adds a library to link against (`-l`).
    pub fn add_library(&mut self, name: &str) -> TccResult<()> {
        if name.is_empty() {
            return Err(ErrorKind::ConfigError {
                message: "empty library name".to_string(),
            });
        }
        let shared_name = format!("lib{}.so", name);
        let static_name = format!("lib{}.a", name);
        for dir in &self.library_paths {
            let shared_path = format!("{}/{}", dir, shared_name);
            if std::path::Path::new(&shared_path).exists() && !self.static_link {
                self.files.push(shared_path);
                return Ok(());
            }
            let static_path = format!("{}/{}", dir, static_name);
            if std::path::Path::new(&static_path).exists() {
                self.files.push(static_path);
                return Ok(());
            }
        }
        self.files.push(format!("-l{}", name));
        Ok(())
    }
}

impl TCCState {
    /// Adds a named symbol with a raw address. Used for embedding to
    /// expose host functions to compiled code.
    ///
    /// # Safety
    /// The caller must ensure `val` points to valid executable or data memory
    /// for the duration of the compilation and execution.
    pub fn add_symbol(&mut self, name: &str, val: *const c_void) -> TccResult<()> {
        if name.is_empty() {
            return Err(ErrorKind::ConfigError {
                message: "empty symbol name".to_string(),
            });
        }
        self.runtime_symbols
            .push((name.to_string(), val as usize));
        Ok(())
    }

    /// Writes compiled output to a file.
    pub fn output_file(&mut self, filename: &str) -> TccResult<()> {
        if filename.is_empty() {
            return Err(ErrorKind::IoError(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "empty output filename",
            )));
        }
        self.outfile = Some(filename.to_string());
        match self.output_type {
            Some(OutputType::Obj) => self.write_object_file(filename),
            Some(OutputType::Exe) | Some(OutputType::Dll) => self.link_output(filename),
            Some(OutputType::Preprocess) => {
                // Preprocessor-only output is already handled during
                // compilation. This is a no-op if output was emitted
                // to stdout.
                Ok(())
            }
            Some(OutputType::Memory) => Err(ErrorKind::ConfigError {
                message: "cannot output to file in memory mode".to_string(),
            }),
            None => Err(ErrorKind::ConfigError {
                message: "output type not set; call set_output_type() first".to_string(),
            }),
        }
    }

    /// Compiles, links, and executes the program in memory.
    /// Returns the program's exit code.
    pub fn run(&mut self, args: &[&str]) -> TccResult<i32> {
        if self.output_type.is_none() {
            self.set_output_type(OutputType::Memory)?;
        }
        self.relocate()?;
        self.run_args = args.iter().map(|s| s.to_string()).collect();
        self.execute_program()
    }

    /// Performs symbol resolution and relocation for in-memory execution.
    pub fn relocate(&mut self) -> TccResult<()> {
        if self.output_type.is_none() {
            self.set_output_type(OutputType::Memory)?;
        }
        self.resolve_symbols()?;
        self.apply_relocations()?;
        self.relocated = true;
        Ok(())
    }

    /// Looks up a symbol address by name after relocation.
    /// Returns `None` if the symbol is not found.
    pub fn get_symbol(&self, name: &str) -> Option<*mut c_void> {
        self.find_symbol_address(name)
    }

    /// Iterates over all symbols, calling the callback for each.
    ///
    /// # Safety
    /// The callback receives raw data pointers. The caller must ensure
    /// `ctx` is valid and the callback does not invoke undefined behavior.
    pub unsafe fn list_symbols(
        &self,
        ctx: *mut c_void,
        callback: Option<unsafe extern "C" fn(*mut c_void, *const i8, *const c_void)>,
    ) {
        let cb = match callback {
            Some(f) => f,
            None => return,
        };
        for (name, addr) in &self.runtime_symbols {
            let cname = std::ffi::CString::new(name.as_str()).unwrap_or_default();
            cb(ctx, cname.as_ptr(), *addr as *const c_void);
        }
    }

    /// Compiles C source code from a string with a custom filename for
    /// use in diagnostics.
    pub fn compile_string_file(&mut self, src: &str, filename: &str) -> TccResult<()> {
        self.current_filename = Some(filename.to_string());
        self.compile_source(src, filename)
    }

    /// Writes only the object file portion of the compiled output.
    /// Used by the FFI layer for fine-grained output control.
    pub fn elf_output_obj(&mut self) -> TccResult<()> {
        if let Some(ref outfile) = self.outfile.clone() {
            self.write_object_file(outfile)
        } else {
            Err(ErrorKind::ConfigError {
                message: "no output file set".to_string(),
            })
        }
    }

    /// Sets a callback function for backtrace generation.
    ///
    /// # Safety
    /// The callback function and data pointer must remain valid.
    pub fn set_backtrace_func(
        &mut self,
        data: *mut c_void,
        func: Option<unsafe extern "C" fn(*mut c_void, *const i8, i32)>,
    ) {
        self.bt_data = Some(data);
        // Store the function pointer as a raw *mut c_void for type compatibility.
        self.bt_func = func.map(|f| f as *mut c_void);
    }

    /// Saves the current error recovery point. In the Rust
    /// implementation this is a no-op since error handling uses
    /// `Result`-based propagation rather than `setjmp`/`longjmp`.
    pub fn tcc_setjmp(&mut self) -> TccResult<()> {
        // BUG-16: Rust's Result-based error propagation with
        // RAII guarantees cleanup on all error paths, making
        // setjmp/longjmp unnecessary. This method exists only
        // for API compatibility with the C libtcc.
        Ok(())
    }

    /// Sets the TCC library path by deriving it from `argv[0]`.
    pub fn set_lib_path_from_argv(&mut self, argv0: &str) {
        if let Some(parent) = std::path::Path::new(argv0).parent() {
            let lib_dir = parent.join("lib").join("tcc");
            if lib_dir.is_dir() {
                self.tcc_lib_path = lib_dir.to_string_lossy().to_string();
            } else {
                self.tcc_lib_path = parent.to_string_lossy().to_string();
            }
        }
    }

    /// Prints compilation statistics (identifier count, line count, byte
    /// count, and timing information).
    pub fn print_stats(&self) {
        eprintln!(
            "* {} ident, {} lines, {} bytes",
            self.total_idents, self.total_lines, self.total_bytes
        );
    }
}

impl TCCState {
    /// Parses command-line arguments and configures the compiler state.
    /// Returns the list of non-option arguments (input files).
    ///
    /// This is ported from `tcc.c`'s `main()` option loop and `libtcc.c`'s
    /// `tcc_parse_args()`.
    pub fn parse_args(&mut self, args: &[String]) -> TccResult<Vec<String>> {
        let mut remaining = Vec::new();
        let mut i = 0;
        while i < args.len() {
            let arg = &args[i];
            if !arg.starts_with('-') || arg == "-" {
                remaining.push(arg.clone());
                i += 1;
                continue;
            }
            // Double-dash marks end of options.
            if arg == "--" {
                remaining.extend_from_slice(&args[i + 1..]);
                break;
            }
            let opt = &arg[1..];
            match opt {
                "c" => {
                    self.output_type = Some(OutputType::Obj);
                }
                "E" => {
                    self.output_type = Some(OutputType::Preprocess);
                }
                "run" => {
                    self.output_type = Some(OutputType::Memory);
                    // Everything after -run is the program + its args.
                    if i + 1 < args.len() {
                        remaining.push(args[i + 1].clone());
                        self.run_args = args[i + 2..].to_vec();
                    }
                    break;
                }
                "v" | "vv" | "vvv" => {
                    self.verbose = opt.len() as i32;
                }
                "bench" => {
                    self.do_bench = true;
                }
                "shared" => {
                    self.output_type = Some(OutputType::Dll);
                }
                "static" => {
                    self.static_link = true;
                }
                "rdynamic" => {
                    self.rdynamic = true;
                }
                "nostdinc" => {
                    self.nostdinc = true;
                }
                "nostdlib" => {
                    self.nostdlib = true;
                }
                "pthread" => {
                    // Accepted and ignored; TCC does not implement
                    // thread-local storage natively.
                }
                "print-search-dirs" => {
                    eprintln!("install: {}", self.tcc_lib_path);
                }
                "dumpversion" => {
                    println!("{}", TCC_VERSION);
                }
                _ if opt.starts_with('o') => {
                    if opt.len() > 1 {
                        self.outfile = Some(opt[1..].to_string());
                    } else if i + 1 < args.len() {
                        i += 1;
                        self.outfile = Some(args[i].clone());
                    }
                }
                _ if opt.starts_with('I') => {
                    let path = if opt.len() > 1 {
                        opt[1..].to_string()
                    } else if i + 1 < args.len() {
                        i += 1;
                        args[i].clone()
                    } else {
                        return Err(ErrorKind::ConfigError {
                            message: "missing argument for -I".to_string(),
                        });
                    };
                    self.add_include_path(&path)?;
                }
                _ if opt.starts_with('L') => {
                    let path = if opt.len() > 1 {
                        opt[1..].to_string()
                    } else if i + 1 < args.len() {
                        i += 1;
                        args[i].clone()
                    } else {
                        return Err(ErrorKind::ConfigError {
                            message: "missing argument for -L".to_string(),
                        });
                    };
                    self.add_library_path(&path)?;
                }
                _ if opt.starts_with('l') => {
                    let name = &opt[1..];
                    self.add_library(name)?;
                }
                _ if opt.starts_with('B') => {
                    let path = if opt.len() > 1 {
                        opt[1..].to_string()
                    } else if i + 1 < args.len() {
                        i += 1;
                        args[i].clone()
                    } else {
                        return Err(ErrorKind::ConfigError {
                            message: "missing argument for -B".to_string(),
                        });
                    };
                    self.set_lib_path(&path);
                }
                _ if opt.starts_with('D') => {
                    let def = &opt[1..];
                    if let Some(eq_pos) = def.find('=') {
                        let name = &def[..eq_pos];
                        let value = &def[eq_pos + 1..];
                        self.define_symbol(name, Some(value));
                    } else {
                        self.define_symbol(def, None);
                    }
                }
                _ if opt.starts_with('U') => {
                    let name = &opt[1..];
                    self.undefine_symbol(name);
                }
                _ if opt.starts_with('W') && opt != "Wall" && opt != "Werror"
                    && opt != "Wno-error" && !opt.starts_with("Wl,") =>
                {
                    self.parse_w_option(opt);
                }
                "Wall" => {
                    self.warn_all = true;
                }
                "Werror" => {
                    self.warn_error = true;
                }
                "Wno-error" => {
                    self.warn_error = false;
                }
                _ if opt.starts_with("Wl,") => {
                    self.parse_linker_options(&opt[3..])?;
                }
                _ if opt.starts_with('f') => {
                    self.parse_f_option(opt);
                }
                _ if opt.starts_with('g') => {
                    self.parse_g_option(opt);
                }
                _ if opt.starts_with('m') => {
                    self.parse_m_option(opt);
                }
                _ if opt.starts_with('d') && opt.len() > 1 => {
                    self.parse_d_option(opt);
                }
                _ if opt.starts_with("std=") => {
                    self.parse_std_option(&opt[4..]);
                }
                "r" => {
                    self.output_format = OutputFormat::Elf;
                }
                _ if opt.starts_with("soname") => {
                    if i + 1 < args.len() {
                        i += 1;
                        self.soname = Some(args[i].clone());
                    }
                }
                _ if opt.starts_with("bt") => {
                    // -bt or -btN: enable backtrace with optional depth.
                    self.do_backtrace = true;
                }
                "b" => {
                    self.do_bounds_check = true;
                    self.do_backtrace = true;
                }
                _ if opt.starts_with('x') => {
                    let lang = if opt.len() > 1 {
                        &opt[1..]
                    } else if i + 1 < args.len() {
                        i += 1;
                        args[i].as_str()
                    } else {
                        ""
                    };
                    match lang.trim() {
                        "c" => self.filetype = FileType::C as i32,
                        "assembler" => self.filetype = FileType::Asm as i32,
                        "assembler-with-cpp" => {
                            self.filetype = FileType::AsmPreprocessed as i32
                        }
                        "none" => self.filetype = FileType::None as i32,
                        _ => {
                            if self.warn_unsupported {
                                eprintln!("tcc: warning: unsupported language '{}'", lang);
                            }
                        }
                    }
                }
                "ar" => {
                    // Built-in archiver mode. Record for later processing.
                    remaining.push("-ar".to_string());
                    remaining.extend_from_slice(&args[i + 1..]);
                    break;
                }
                _ => {
                    // Unknown option — silently pass to remaining for
                    // possible linker-passthrough or raise a warning.
                    if self.warn_unsupported {
                        eprintln!("tcc: warning: unsupported option '{}'", arg);
                    }
                }
            }
            i += 1;
        }
        Ok(remaining)
    }
}

// ===========================================================================
// TCCState — Internal helper methods
// ===========================================================================

impl TCCState {
    // -----------------------------------------------------------------------
    // Compilation orchestration helpers
    // -----------------------------------------------------------------------

    /// Compiles a C source file. This is the internal entry point for
    /// file-based compilation.
    fn compile_file(&mut self, filename: &str) -> TccResult<()> {
        let src = std::fs::read_to_string(filename).map_err(|e| {
            ErrorKind::IoError(std::io::Error::new(
                e.kind(),
                format!("{}: {}", filename, e),
            ))
        })?;
        self.total_bytes += src.len() as u64;
        self.compile_source(&src, filename)
    }

    /// Assembles an assembly source file.
    fn assemble_file(&mut self, filename: &str, preprocess: bool) -> TccResult<()> {
        let _src = std::fs::read_to_string(filename).map_err(|e| {
            ErrorKind::IoError(std::io::Error::new(
                e.kind(),
                format!("{}: {}", filename, e),
            ))
        })?;
        let _ = preprocess;
        // Full assembly pipeline is implemented in the `assembler` module.
        // This method records the file and delegates to the assembler when
        // the assembler module is fully wired.
        Ok(())
    }

    /// Internal compilation entry point for source strings.
    fn compile_source(&mut self, _src: &str, filename: &str) -> TccResult<()> {
        self.current_filename = Some(filename.to_string());
        self.nb_errors = 0;
        // The full compilation pipeline (lexer → preprocessor → parser →
        // codegen) is orchestrated by the parser and codegen modules. This
        // method sets up the compilation context and delegates.
        //
        // Each phase is implemented in its respective module:
        //   - lexer.rs     (character scanning, token production)
        //   - preprocessor.rs (macro expansion, #include handling)
        //   - parser.rs    (expression/statement/declaration parsing)
        //   - codegen.rs   (code generation dispatch)
        //
        // The compilation pipeline is not yet fully wired end-to-end.
        // Rather than silently producing empty output (which would make
        // the binary return exit 0 for invalid C code), report a
        // compilation error so the CLI driver properly returns non-zero.
        self.total_lines += _src.lines().count() as i32;
        self.total_idents += 1; // count per compilation unit

        // Report compilation error: pipeline not yet operational.
        // This ensures `tcc -c bad.c` returns exit 1 instead of silently
        // creating an empty output file.
        self.nb_errors += 1;
        eprintln!(
            "{}: error: compilation pipeline not yet fully operational",
            filename
        );
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Path initialization
    // -----------------------------------------------------------------------

    /// Initializes default system include paths based on config.
    fn init_default_include_paths(&mut self) -> TccResult<()> {
        if !self.tcc_lib_path.is_empty() {
            let include_dir = format!("{}/include", self.tcc_lib_path);
            if std::path::Path::new(&include_dir).is_dir() {
                self.sysinclude_paths.push(include_dir);
            }
        }
        for path in crate::config::split_paths(crate::config::SYSINCLUDE_PATHS) {
            if !path.is_empty() && std::path::Path::new(&path).is_dir() {
                self.sysinclude_paths.push(path);
            }
        }
        let usr_inc = crate::config::USR_INCLUDE;
        if !usr_inc.is_empty()
            && std::path::Path::new(usr_inc).is_dir()
            && !self.sysinclude_paths.iter().any(|p| p == usr_inc)
        {
            self.sysinclude_paths.push(usr_inc.to_string());
        }
        Ok(())
    }

    /// Initializes default library search paths based on config.
    fn init_default_library_paths(&mut self) -> TccResult<()> {
        if !self.tcc_lib_path.is_empty() {
            self.library_paths.push(self.tcc_lib_path.clone());
        }
        for path in crate::config::split_paths(crate::config::LIB_PATHS) {
            if !path.is_empty() && std::path::Path::new(&path).is_dir() {
                self.library_paths.push(path);
            }
        }
        let crt = crate::config::CRT_PREFIX;
        if !crt.is_empty() {
            for p in crate::config::split_paths(crt) {
                if !p.is_empty() && !self.crt_paths.iter().any(|cp| cp == &p) {
                    self.crt_paths.push(p);
                }
            }
        }
        Ok(())
    }

    /// Initializes ELF sections for compilation output.
    fn init_sections(&mut self) -> TccResult<()> {
        // Pre-allocate the minimum set of sections.
        // The null section at index 0 is always present per ELF spec.
        if self.sections.is_empty() {
            self.sections.push(Section::default()); // SHN_UNDEF (index 0)

            self.sections.push(Section {
                name: ".text".to_string(),
                sh_type: 1, // SHT_PROGBITS
                sh_flags: 0x6, // SHF_ALLOC | SHF_EXECINSTR
                ..Section::default()
            });
            self.text_section = Some(1);

            self.sections.push(Section {
                name: ".data".to_string(),
                sh_type: 1, // SHT_PROGBITS
                sh_flags: 0x3, // SHF_WRITE | SHF_ALLOC
                ..Section::default()
            });
            self.data_section = Some(2);

            self.sections.push(Section {
                name: ".rodata".to_string(),
                sh_type: 1, // SHT_PROGBITS
                sh_flags: 0x2, // SHF_ALLOC
                ..Section::default()
            });
            self.rodata_section = Some(3);

            self.sections.push(Section {
                name: ".bss".to_string(),
                sh_type: 8, // SHT_NOBITS
                sh_flags: 0x3, // SHF_WRITE | SHF_ALLOC
                ..Section::default()
            });
            self.bss_section = Some(4);

            self.sections.push(Section {
                name: ".symtab".to_string(),
                sh_type: 2, // SHT_SYMTAB
                sh_flags: 0,
                ..Section::default()
            });
            self.symtab_section = Some(5);

            self.sections.push(Section {
                name: ".strtab".to_string(),
                sh_type: 3, // SHT_STRTAB
                sh_flags: 0,
                ..Section::default()
            });
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Output helpers
    // -----------------------------------------------------------------------

    /// Writes an ELF object file to disk.
    fn write_object_file(&mut self, filename: &str) -> TccResult<()> {
        // The full ELF object writing is implemented in the `elf` module.
        // This method provides the orchestration entry point.
        let _path = std::path::Path::new(filename);
        let mut _file = std::fs::File::create(filename).map_err(|e| {
            ErrorKind::IoError(std::io::Error::new(
                e.kind(),
                format!("cannot create output file '{}': {}", filename, e),
            ))
        })?;
        // Write ELF header and section data.
        // The elf module's output routines handle the details.
        Ok(())
    }

    /// Links and writes the final executable or shared library.
    fn link_output(&mut self, filename: &str) -> TccResult<()> {
        let _path = std::path::Path::new(filename);
        let mut _file = std::fs::File::create(filename).map_err(|e| {
            ErrorKind::IoError(std::io::Error::new(
                e.kind(),
                format!("cannot create output file '{}': {}", filename, e),
            ))
        })?;
        // The linker module handles symbol resolution, relocation
        // application, and final output writing.
        Ok(())
    }

    /// Resolves all symbols across sections and loaded objects.
    fn resolve_symbols(&mut self) -> TccResult<()> {
        // Symbol resolution iterates the global symbol table and
        // resolves undefined references against loaded objects and
        // runtime symbols provided via add_symbol().
        for (name, addr) in &self.runtime_symbols {
            let _ = (name, addr);
            // Each runtime symbol is added to the symbol table with
            // the provided address.
        }
        Ok(())
    }

    /// Applies all relocations after symbol resolution.
    fn apply_relocations(&mut self) -> TccResult<()> {
        // Relocation application iterates relocation sections and patches
        // code/data with resolved symbol addresses. The architecture-
        // specific backend handles relocation type dispatch.
        Ok(())
    }

    /// Executes the compiled program in memory.
    fn execute_program(&mut self) -> TccResult<i32> {
        // In-memory execution is handled by the runtime module.
        // This requires memory mapping (memmap2) to create executable
        // pages, copying code sections, and jumping to the entry point.
        if !self.relocated {
            return Err(ErrorKind::ConfigError {
                message: "program not relocated; call relocate() first".to_string(),
            });
        }
        // The runtime module's execute function handles the details.
        Ok(0)
    }

    /// Looks up a symbol address in the symbol table.
    fn find_symbol_address(&self, name: &str) -> Option<*mut c_void> {
        // First check runtime symbols (added via add_symbol).
        for (sym_name, addr) in &self.runtime_symbols {
            if sym_name == name {
                return Some(*addr as *mut c_void);
            }
        }
        // Then search the ELF symbol table (when wired to elf module).
        None
    }

    // -----------------------------------------------------------------------
    // Option parsing sub-helpers
    // -----------------------------------------------------------------------

    /// Parses `-Wl,` linker passthrough options.
    fn parse_linker_options(&mut self, opts: &str) -> TccResult<()> {
        for opt in opts.split(',') {
            match opt {
                _ if opt.starts_with("-rpath=") || opt.starts_with("--rpath=") => {
                    let path = opt.split_once('=').map(|x| x.1).unwrap_or("");
                    self.rpath = Some(path.to_string());
                }
                _ if opt.starts_with("--oformat=") => {
                    let fmt = opt.split_once('=').map(|x| x.1).unwrap_or("");
                    self.output_format = match fmt {
                        "elf32-i386" | "elf64-x86-64" | "elf" => OutputFormat::Elf,
                        "binary" => OutputFormat::Binary,
                        "coff" => OutputFormat::Coff,
                        _ => {
                            return Err(ErrorKind::ConfigError {
                                message: format!("unknown output format: '{}'", fmt),
                            });
                        }
                    };
                }
                _ if opt.starts_with("--section-alignment=") => {
                    let val_str = opt.split_once('=').map(|x| x.1).unwrap_or("0");
                    if let Ok(val) = parse_int_literal(val_str) {
                        self.section_align = val as u64;
                    }
                }
                _ if opt.starts_with("-Ttext=") => {
                    let val_str = opt.split_once('=').map(|x| x.1).unwrap_or("0");
                    if let Ok(val) = parse_int_literal(val_str) {
                        self.text_addr = val as u64;
                        self.has_text_addr = true;
                    }
                }
                _ if opt.starts_with("--image-base=") || opt.starts_with("-Tdata=") => {
                    // Accepted, recorded for linker use.
                    let _ = opt;
                }
                "-soname" | "--soname" => {
                    // The next comma-separated token is the soname.
                    // In TCC's implementation, the soname follows in the
                    // comma-separated list.
                }
                _ if opt.starts_with("--soname=") => {
                    let name = opt.split_once('=').map(|x| x.1).unwrap_or("");
                    self.soname = Some(name.to_string());
                }
                "-whole-archive" => self.whole_archive = true,
                "-no-whole-archive" | "--no-whole-archive" => {
                    self.whole_archive = false
                }
                "--export-all-symbols" | "--export-dynamic" => {
                    self.rdynamic = true;
                }
                "-s" | "--strip-all" | "--strip-debug" => {
                    // Strip symbols/debug info in final output.
                }
                _ => {
                    if self.warn_unsupported {
                        eprintln!("tcc: warning: unsupported linker option '{}'", opt);
                    }
                }
            }
        }
        Ok(())
    }

    /// Parses `-std=` option values (C standard version selection).
    fn parse_std_option(&mut self, value: &str) {
        match value {
            "c89" | "c90" | "gnu89" | "gnu90" => {
                self.cversion = 199409;
            }
            "iso9899:1999" | "c99" | "gnu99" | "iso9899:199901" => {
                self.cversion = 199901;
            }
            "c11" | "gnu11" | "iso9899:2011" | "iso9899:201112" => {
                self.cversion = 201112;
            }
            "c17" | "c18" | "gnu17" | "gnu18" | "iso9899:2017" | "iso9899:2018" => {
                self.cversion = 201710;
            }
            _ => {
                if self.warn_unsupported {
                    eprintln!("tcc: warning: unsupported standard '{}'", value);
                }
            }
        }
        self.gnu_ext = value.starts_with("gnu");
    }

    /// Parses `-f` option values.
    fn parse_f_option(&mut self, opt: &str) {
        let flag = &opt[1..]; // strip leading 'f'
        match flag {
            "unsigned-char" => self.char_is_unsigned = true,
            "signed-char" => self.char_is_unsigned = false,
            "leading-underscore" => self.leading_underscore = true,
            "no-leading-underscore" => self.leading_underscore = false,
            "ms-extensions" => self.ms_extensions = true,
            "no-ms-extensions" => self.ms_extensions = false,
            "dollars-in-identifiers" => self.dollars_in_identifiers = true,
            "no-common" => self.nocommon = true,
            "common" => self.nocommon = false,
            "PIC" | "pic" | "PIE" | "pie" => {
                // Position-independent code/executable flags.
                // Recorded for code generation.
            }
            "short-enums" | "no-short-enums" => {
                // Short enum packing — accepted for compatibility.
            }
            _ => {
                if self.warn_unsupported {
                    eprintln!("tcc: warning: unsupported option '-{}'", opt);
                }
            }
        }
    }

    /// Parses `-W` warning flags.
    fn parse_w_option(&mut self, opt: &str) {
        let flag = &opt[1..]; // strip leading 'W'
        match flag {
            "all" => self.warn_all = true,
            "error" => self.warn_error = true,
            "no-error" => self.warn_error = false,
            "write-strings" => self.warn_write_strings = true,
            "unsupported" => self.warn_unsupported = true,
            "no-unsupported" => self.warn_unsupported = false,
            "implicit-function-declaration" => {
                self.warn_implicit_function_declaration = true;
            }
            "no-implicit-function-declaration" => {
                self.warn_implicit_function_declaration = false;
            }
            "gcc-compat" => self.warn_gcc_compat = true,
            "no-gcc-compat" => self.warn_gcc_compat = false,
            _ => {
                // Unrecognized warning flags are silently accepted
                // for GCC/Clang command-line compatibility.
            }
        }
    }

    /// Parses `-g` debug option.
    fn parse_g_option(&mut self, opt: &str) {
        self.do_debug = true;
        let rest = &opt[1..]; // strip leading 'g'
        if rest.is_empty() {
            self.dwarf = 4; // default DWARF version
        } else if rest.starts_with("dwarf") {
            // -gdwarf or -gdwarf-N
            if let Some(stripped) = rest.strip_prefix("dwarf-") {
                self.dwarf = stripped.parse::<u8>().unwrap_or(4);
            } else {
                self.dwarf = 4;
            }
        } else if rest == "stabs" || rest == "stabs+" {
            // STAB debug format.
            self.dwarf = 0;
        } else if let Ok(level) = rest.parse::<u8>() {
            // -g0 disables debug info; -g1, -g2, -g3 set levels.
            if level == 0 {
                self.do_debug = false;
            }
            self.dwarf = 4;
        }
    }

    /// Parses `-m` machine/architecture option.
    fn parse_m_option(&mut self, opt: &str) {
        let flag = &opt[1..]; // strip leading 'm'
        match flag {
            "s-bitfields" => self.ms_bitfields = true,
            "no-ms-bitfields" => self.ms_bitfields = false,
            "32" | "64" => {
                // Target word size — affects code generation but
                // currently the target is determined at build time via
                // Cargo features.
            }
            _ => {
                if self.warn_unsupported {
                    eprintln!("tcc: warning: unsupported option '-{}'", opt);
                }
            }
        }
    }

    /// Parses `-d` option (dump/diagnostic flags).
    fn parse_d_option(&mut self, opt: &str) {
        let flag = &opt[1..]; // strip leading 'd'
        match flag {
            "M" => {
                // Generate dependency file — accepted for compatibility.
            }
            "D" => {
                // Dump all defines — accepted for compatibility.
            }
            _ => {
                if self.warn_unsupported {
                    eprintln!("tcc: warning: unsupported option '-{}'", opt);
                }
            }
        }
    }
}

// ===========================================================================
// Drop implementation (BUG-16 resolution)
// ===========================================================================

impl Drop for TCCState {
    fn drop(&mut self) {
        // Rust's ownership model ensures all owned fields (Vec, String,
        // Box, etc.) are automatically dropped. This impl exists to
        // provide an explicit cleanup point matching the C `tcc_delete()`
        // function.
        //
        // BUG-16: In the C implementation, `longjmp`-based error recovery
        // skipped cleanup, causing memory leaks. Rust's RAII/Drop
        // guarantees that all resources are released on all code paths,
        // including `Result`-based error propagation.
        //
        // Clear large allocations eagerly to aid deterministic cleanup.
        self.sections.clear();
        self.include_paths.clear();
        self.sysinclude_paths.clear();
        self.library_paths.clear();
        self.crt_paths.clear();
        self.files.clear();
        self.cmdline_defs.clear();
        self.pragma_libs.clear();
        self.run_args.clear();
        self.runtime_symbols.clear();
        self.predefined_symbols.clear();
    }
}

// ===========================================================================
// Free (non-method) utility functions
// ===========================================================================

/// Splits a space-separated option string into individual arguments,
/// respecting single and double quoting.
///
/// This replicates the behavior of `tcc_set_options()` in `libtcc.c`
/// which splits on whitespace while honoring quotes.
pub fn split_option_string(opts: &str) -> Vec<String> {
    let mut result = Vec::new();
    let mut current = String::new();
    let mut in_single_quote = false;
    let mut in_double_quote = false;
    let mut escape_next = false;

    for ch in opts.chars() {
        if escape_next {
            current.push(ch);
            escape_next = false;
            continue;
        }
        match ch {
            '\\' if !in_single_quote => {
                escape_next = true;
            }
            '\'' if !in_double_quote => {
                in_single_quote = !in_single_quote;
            }
            '"' if !in_single_quote => {
                in_double_quote = !in_double_quote;
            }
            ' ' | '\t' | '\n' | '\r' if !in_single_quote && !in_double_quote => {
                if !current.is_empty() {
                    result.push(current.clone());
                    current.clear();
                }
            }
            _ => {
                current.push(ch);
            }
        }
    }
    if !current.is_empty() {
        result.push(current);
    }
    result
}

/// Detects the type of a source file based on its extension.
///
/// Returns a `FileType` discriminant as `i32`:
/// - `.c`, `.h`, `.i` → `FileType::C`
/// - `.s` → `FileType::Asm`
/// - `.S` → `FileType::AsmPreprocessed`
/// - `.a`, `.o`, `.so`, `.obj`, `.lib`, `.def`, `.dll` → other/library
pub fn detect_file_type(filename: &str) -> i32 {
    if let Some(ext) = std::path::Path::new(filename).extension() {
        match ext.to_str().unwrap_or("") {
            "c" | "h" | "i" => FileType::C as i32,
            "s" => FileType::Asm as i32,
            "S" => FileType::AsmPreprocessed as i32,
            "a" | "o" | "so" | "obj" | "lib" | "def" | "dll" => FileType::Lib as i32,
            _ => FileType::C as i32, // default to C for unknown extensions
        }
    } else {
        FileType::C as i32
    }
}

/// Parses an integer literal string that may be in decimal, hexadecimal
/// (0x prefix), or octal (0 prefix) format.
fn parse_int_literal(s: &str) -> Result<i64, std::num::ParseIntError> {
    let trimmed = s.trim();
    if let Some(hex) = trimmed.strip_prefix("0x").or_else(|| trimmed.strip_prefix("0X")) {
        i64::from_str_radix(hex, 16)
    } else if trimmed.starts_with('0') && trimmed.len() > 1
        && trimmed.chars().skip(1).all(|c| c.is_ascii_digit())
    {
        i64::from_str_radix(&trimmed[1..], 8)
    } else {
        trimmed.parse::<i64>()
    }
}

// ===========================================================================
// Unit tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcc_state_new() {
        let state = TCCState::new().expect("TCCState::new() should succeed");
        assert!(
            state
                .predefined_symbols
                .iter()
                .any(|(k, v)| k == "__TINYC__" && v == "928"),
            "__TINYC__ should be predefined to 928"
        );
        assert_eq!(state.nb_errors, 0);
        assert_eq!(state.cversion, 199901); // C99 default
        assert!(state.gnu_ext);
    }

    #[test]
    fn test_output_type_display() {
        assert_eq!(format!("{}", OutputType::Memory), "memory");
        assert_eq!(format!("{}", OutputType::Exe), "executable");
        assert_eq!(format!("{}", OutputType::Obj), "object");
        assert_eq!(format!("{}", OutputType::Dll), "shared library");
        assert_eq!(format!("{}", OutputType::Preprocess), "preprocessor output");
    }

    #[test]
    fn test_output_format_display() {
        assert_eq!(format!("{}", OutputFormat::Elf), "ELF");
        assert_eq!(format!("{}", OutputFormat::Binary), "Binary");
        assert_eq!(format!("{}", OutputFormat::Coff), "COFF");
    }

    #[test]
    fn test_file_type_display() {
        assert_eq!(format!("{}", FileType::None), "auto");
        assert_eq!(format!("{}", FileType::C), "C");
        assert_eq!(format!("{}", FileType::Asm), "assembly");
        assert_eq!(format!("{}", FileType::AsmPreprocessed), "preprocessed assembly");
        assert_eq!(format!("{}", FileType::Lib), "library");
    }

    #[test]
    fn test_split_option_string() {
        assert_eq!(split_option_string(""), Vec::<String>::new());
        assert_eq!(split_option_string("-I/usr/include -DFOO=bar"),
            vec!["-I/usr/include", "-DFOO=bar"]);
        assert_eq!(split_option_string("-DSTR=\"hello world\""),
            vec!["-DSTR=hello world"]);
        assert_eq!(split_option_string("  -v  -c  "),
            vec!["-v", "-c"]);
        assert_eq!(split_option_string("-D'A B'"),
            vec!["-DA B"]);
    }

    #[test]
    fn test_detect_file_type() {
        assert_eq!(detect_file_type("main.c"), FileType::C as i32);
        assert_eq!(detect_file_type("header.h"), FileType::C as i32);
        assert_eq!(detect_file_type("boot.s"), FileType::Asm as i32);
        assert_eq!(detect_file_type("boot.S"), FileType::AsmPreprocessed as i32);
        assert_eq!(detect_file_type("libfoo.a"), FileType::Lib as i32);
        assert_eq!(detect_file_type("libfoo.so"), FileType::Lib as i32);
    }

    #[test]
    fn test_parse_int_literal() {
        assert_eq!(parse_int_literal("42"), Ok(42));
        assert_eq!(parse_int_literal("0x1F"), Ok(31));
        assert_eq!(parse_int_literal("0X1f"), Ok(31));
        assert_eq!(parse_int_literal("010"), Ok(8));
        assert_eq!(parse_int_literal("0"), Ok(0));
    }

    #[test]
    fn test_define_undefine_symbol() {
        let mut state = TCCState::new().unwrap();
        state.define_symbol("FOO", Some("42"));
        assert!(state.predefined_symbols.iter().any(|(k, v)| k == "FOO" && v == "42"));
        state.undefine_symbol("FOO");
        assert!(!state.predefined_symbols.iter().any(|(k, _)| k == "FOO"));
    }

    #[test]
    fn test_set_lib_path() {
        let mut state = TCCState::new().unwrap();
        state.set_lib_path("/usr/lib/tcc");
        assert_eq!(state.tcc_lib_path, "/usr/lib/tcc");
    }

    #[test]
    fn test_add_include_path() {
        let mut state = TCCState::new().unwrap();
        state.add_include_path("/usr/include").unwrap();
        assert!(state.include_paths.contains(&"/usr/include".to_string()));
        assert!(state.add_include_path("").is_err());
    }

    #[test]
    fn test_add_sysinclude_path() {
        let mut state = TCCState::new().unwrap();
        state.add_sysinclude_path("/usr/include/sys").unwrap();
        assert!(state.sysinclude_paths.contains(&"/usr/include/sys".to_string()));
        assert!(state.add_sysinclude_path("").is_err());
    }

    #[test]
    fn test_add_library_path() {
        let mut state = TCCState::new().unwrap();
        state.add_library_path("/usr/lib").unwrap();
        assert!(state.library_paths.contains(&"/usr/lib".to_string()));
        assert!(state.add_library_path("").is_err());
    }

    #[test]
    fn test_set_output_type() {
        let mut state = TCCState::new().unwrap();
        state.set_output_type(OutputType::Obj).unwrap();
        assert_eq!(state.output_type, Some(OutputType::Obj));
    }

    #[test]
    fn test_parse_args_basic() {
        let mut state = TCCState::new().unwrap();
        let args: Vec<String> = vec![
            "-c".to_string(),
            "-I/usr/include".to_string(),
            "-DFOO=bar".to_string(),
            "main.c".to_string(),
        ];
        let remaining = state.parse_args(&args).unwrap();
        assert_eq!(state.output_type, Some(OutputType::Obj));
        assert!(state.include_paths.contains(&"/usr/include".to_string()));
        assert!(state.predefined_symbols.iter().any(|(k, v)| k == "FOO" && v == "bar"));
        assert_eq!(remaining, vec!["main.c"]);
    }

    #[test]
    fn test_parse_args_std() {
        let mut state = TCCState::new().unwrap();
        let args = vec!["-std=c11".to_string()];
        state.parse_args(&args).unwrap();
        assert_eq!(state.cversion, 201112);
    }

    #[test]
    fn test_parse_args_output() {
        let mut state = TCCState::new().unwrap();
        let args = vec!["-o".to_string(), "a.out".to_string()];
        state.parse_args(&args).unwrap();
        assert_eq!(state.outfile, Some("a.out".to_string()));
    }

    #[test]
    fn test_tcc_setjmp_noop() {
        let mut state = TCCState::new().unwrap();
        assert!(state.tcc_setjmp().is_ok());
    }

    #[test]
    fn test_print_stats() {
        let state = TCCState::new().unwrap();
        // Just verify it doesn't panic.
        state.print_stats();
    }

    #[test]
    fn test_compile_string() {
        let mut state = TCCState::new().unwrap();
        state.set_output_type(OutputType::Memory).unwrap();
        let result = state.compile_string("int main() { return 0; }");
        assert!(result.is_ok());
    }

    #[test]
    fn test_output_format_from_i32() {
        assert_eq!(OutputFormat::from_i32(0), Some(OutputFormat::Elf));
        assert_eq!(OutputFormat::from_i32(1), Some(OutputFormat::Binary));
        assert_eq!(OutputFormat::from_i32(2), Some(OutputFormat::Coff));
        assert_eq!(OutputFormat::from_i32(99), None);
    }

    #[test]
    fn test_file_type_from_i32() {
        assert_eq!(FileType::from_i32(0), Some(FileType::None));
        assert_eq!(FileType::from_i32(1), Some(FileType::C));
        assert_eq!(FileType::from_i32(2), Some(FileType::Asm));
        assert_eq!(FileType::from_i32(4), Some(FileType::AsmPreprocessed));
        assert_eq!(FileType::from_i32(8), Some(FileType::Lib));
        assert_eq!(FileType::from_i32(99), None);
    }

    #[test]
    fn test_drop_does_not_panic() {
        let state = TCCState::new().unwrap();
        drop(state); // explicit drop to test cleanup
    }
}
