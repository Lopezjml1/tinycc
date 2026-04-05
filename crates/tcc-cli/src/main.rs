// -------------------------------------------------------------------------
// Tiny C Compiler — CLI Binary Entry Point (Rust Port)
//
// Copyright (c) 2001-2004 Fabrice Bellard
// Copyright (c) TinyCC contributors
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
// -------------------------------------------------------------------------
//! # tcc-cli — TCC Command-Line Interface
//!
//! This is the binary crate entry point for the Rust-ported TinyCC compiler.
//! It is a comprehensive port of `tcc.c` (428 lines) from the original C
//! implementation, preserving full CLI behavioral compatibility while using
//! idiomatic Rust patterns.
//!
//! ## CLI Contract
//!
//! All documented TCC CLI flags are preserved:
//! - Compilation: `-c`, `-o`, `-run`, `-E`
//! - Preprocessor: `-I`, `-D`, `-U`, `-nostdinc`
//! - Linker: `-L`, `-l`, `-nostdlib`, `-shared`, `-static`, `-rdynamic`, `-r`
//! - Debug: `-g`, `-gdwarf`, `-b`, `-bt`
//! - Misc: `-v`, `-bench`, `-std=`, `-x`, `-B`, `-MD`, `-MF`
//! - Tools: `-ar`, `-impdef`, `-m32`/`-m64`
//!
//! ## Relationship to tcc.c
//!
//! The original `tcc.c` contained:
//! - Lines 31-92: `help[]` static string (general, preprocessor, linker, debug, misc)
//! - Lines 94-168: `help2[]` static string (extended help)
//! - Lines 170-209: `version[]` string (version + arch + OS)
//! - Lines 211-230: `print_dirs()` / `print_search_dirs()`
//! - Lines 232-248: `set_environment()` (C_INCLUDE_PATH, CPATH, LIBRARY_PATH)
//! - Lines 250-275: `default_outputfile()` (output filename heuristic)
//! - Lines 277-286: `getclock_ms()` (timing)
//! - Lines 288-428: `main()` (full CLI orchestration)
//!
//! All of the above are faithfully ported to this Rust file.

use std::env;
use std::fs;
use std::io::{self, Write, BufWriter};
use std::path::Path;
use std::process;
use std::time::Instant;

use clap::Command as ClapCommand;

use tcc_core::{TCCState, TccError, TccResult, OutputType};
use tcc_core::config;
use tcc_core::tools;

// =========================================================================
// Constants — Help text ported from tcc.c lines 31-168
// =========================================================================

/// General help text, ported from `tcc.c` lines 31-92 (`help[]`).
const HELP: &str = "\
Tiny C Compiler - Copyright (C) 2001-2006 Fabrice Bellard
Usage: tcc [options...] [-o outfile] [-c] infile(s)...
       tcc [options...] -run infile(s)... [arguments...]
General options:
  -c           compile only - generate an object file
  -o outfile   set output filename
  -run         compile and run in-memory (use -- for arguments)
  -bench       show compilation statistics
  -v -vv       show version, show search paths (also -determine v)
  -            use stdin pipe as infile
  -@listfile   read arguments from listfile
Preprocessor options:
  -Idir        add include path 'dir'
  -Dsym[=val]  define 'sym' with value 'val'
  -Usym        undefine 'sym'
  -E           preprocess only
  -C           don't discard comments (with -E)
Linker options:
  -Ldir        add library path 'dir'
  -llib        link with dynamic or static library 'lib'
  -r           generate (relocatable) object file
  -shared      generate a shared library/dll
  -rdynamic    export all global symbols to dynamic linker
  -soname      set name for shared library to be used at runtime
  -static      static linking
  -nostdinc    do not use standard system include paths
  -nostdlib    do not link with standard crt and libraries
  -Wl,-opt[=val]  set linker option (see manual)
Debugger options:
  -g           generate stab runtime debug info
  -gdwarf[-x]  generate dwarf runtime debug info
  -b           compile with built-in memory and bounds checker (implies -g)
  -bt[N]       link with backtrace (stack dump) support [show max N callers]
Misc. options:
  -x[c|a|b|n]  specify type of the next infile (C,ASM,BIN,NONE)
  -std=c99     Conform to the ISO 1999 C standard (default)
  -std=c11     Conform to the ISO 2011 C standard
  -Bdir        set tcc's private include/library dir
  -M[M]D       generate make dependency file [ignore system files]
  -MF depfile  specify dependency file name
  -W[no-]warning  set (or reset) warning
  -f[no-]flag  set (or reset) a flag (see manual)
Tools:
  -ar          create library archive [rcs mode]
  -impdef      create windows .def file from .dll
Discussion URL: https://lists.nongnu.org/mailman/listinfo/tinycc-devel
";

/// Extended help text, ported from `tcc.c` lines 94-168 (`help2[]`).
const HELP2: &str = "\
Tiny C Compiler - More Options:
Special options:
  -P -P1                        with -E: no/alternative #line output
  -dD -dM                       with -E: output #define directives
  -pthread                      same as -D_REENTRANT and target -lpthread
  -On                           same as -D__OPTIMIZE__ (for abs abs path resolution)
  -Wp,-opt                      same as -opt
  -include file                 include 'file' at top of each input file
  -isystem dir                  add 'dir' to system include path
  -static                       link to static libraries (not shared)
  -dumpversion                  print version and exit
  -print-search-dirs            print search paths and exit
  -dt                           with -run/-E: auto-define test_... macros
Ignored options (compatibility):
  -arch -C --param -pedantic -pipe -s -traditional
-W[no-]... warnings:
  all                           turn on all warnings (except error)
  error[=warning]               abort on warning
  unsupported                   warn about unsupported GCC features
  write-strings                 make string constants be of type const char *
  implicit-function-declaration warn about implicit function declarations
  discarded-qualifiers          warn about const/volatile qualifiers being discarded
-f[no-]... flags:
  unsigned-char                 default char is unsigned
  signed-char                   default char is signed
  common                        use common section instead of bss
  leading-underscore            add leading _ to C symbols
  ms-extensions                 allow anonymous struct in union
  dollars-in-identifiers        accept $ in identifiers
  test-coverage                 instrument for test coverage
-m... target specific options:
  ms-bitfields                  use MSVC bitfield layout
  no-sse                        disable floating-point SSE
  32 64                         select 32/64 bit target (cross-compiler)
  float-abi                     select float ABI (softfp/hard)
-Wl,... linker options:
  -nostdlib                     do not link with standard crt/libs
  -[no-]whole-archive           load all objects from archives
  -export-all-symbols           export all global symbols
  -export-dynamic               same as -rdynamic
  -image-base= -Ttext=         set base address of executable
  -section-alignment=           set section alignment in executable
  -rpath=                       set dynamic library search path
  -enable-new-dtags             set DT_RUNPATH instead of DT_RPATH
  -subsystem=[console/windows]  set PE subsystem (Windows)
  -oformat=[elf32/binary/coff]  set executable output format
  -map mapfile                  write linker map file
  -init=sym -fini=sym           set constructor/destructor
Predefined macros:
  tcc -E -dM - < /dev/null
See also the manual for more details.
";

// =========================================================================
// Helper: Version string construction
// =========================================================================

/// Builds the version display string, ported from `tcc.c` lines 170-209.
///
/// Format: `"tcc version <VERSION> (<ARCH> <OS>)"`
fn build_version_string() -> String {
    let arch = if cfg!(target_arch = "x86") {
        "i386"
    } else if cfg!(target_arch = "x86_64") {
        "x86_64"
    } else if cfg!(target_arch = "arm") {
        "ARM"
    } else if cfg!(target_arch = "aarch64") {
        "AArch64"
    } else if cfg!(target_arch = "riscv64") {
        "riscv64"
    } else {
        "unknown"
    };

    let os = if cfg!(target_os = "windows") {
        "Windows"
    } else if cfg!(target_os = "macos") {
        "Darwin"
    } else if cfg!(target_os = "freebsd") {
        "FreeBSD"
    } else if cfg!(target_os = "openbsd") {
        "OpenBSD"
    } else if cfg!(target_os = "netbsd") {
        "NetBSD"
    } else if cfg!(target_os = "linux") {
        "Linux"
    } else {
        "unknown"
    };

    format!("tcc version {} ({} {})", config::TCC_VERSION, arch, os)
}

// =========================================================================
// CLI definition via clap (AAP section 0.6.1)
// =========================================================================

/// Builds the clap `Command` definition for TCC's CLI interface.
///
/// Uses clap's builder API (per AAP section 0.6.1) to define the argument
/// structure for help text rendering and version display. TCC's complex
/// prefix-based flags (`-I<dir>`, `-D<sym>[=val]`, `-L<dir>`, `-l<lib>`,
/// `-W<warning>`, `-f<flag>`, `-Wl,<opt>`, etc.) are processed by
/// [`TCCState::parse_args()`] since they are tightly coupled to compiler
/// state configuration — a common pattern for compilers where clap handles
/// the structural CLI definition while domain-specific logic handles the
/// actual flag processing.
fn build_cli() -> ClapCommand {
    ClapCommand::new("tcc")
        .version(config::TCC_VERSION)
        .about("Tiny C Compiler — Copyright (C) 2001-2006 Fabrice Bellard")
        // Use the exact TCC help text for display to maintain behavioral
        // compatibility with the original C implementation's help[] string.
        .override_help(HELP)
        // TCC uses -h (not --help) and -v (not --version) following the
        // original C implementation conventions; disable clap's built-in
        // flags to avoid conflicts with TCC's flag namespace.
        .disable_help_flag(true)
        .disable_version_flag(true)
        // TCC has many prefix-based flags (-I<dir>, -D<sym>, -L<dir>, etc.)
        // that don't follow standard clap conventions, plus special modes
        // (-ar, -impdef, -run) that change remaining-argument semantics.
        // Allow external subcommands so clap accepts the full TCC arg set.
        .allow_external_subcommands(true)
}

// =========================================================================
// Helper: print_dirs / print_search_dirs
// Ported from tcc.c lines 211-230
// =========================================================================

/// Prints a section header followed by directory entries.
/// If the list is empty, prints "  -" to indicate no paths.
/// Ported from `print_dirs()` in `tcc.c` lines 211-217.
fn print_dirs(header: &str, dirs: &[String]) {
    println!("{}:", header);
    if dirs.is_empty() {
        println!("  -");
    } else {
        for d in dirs {
            println!("  {}", d);
        }
    }
}

/// Prints all compiler search directories.
/// Ported from `print_search_dirs()` in `tcc.c` lines 219-230.
///
/// Uses `config::TCCDIR`, `config::CRT_PREFIX`, `config::SYSINCLUDE_PATHS`,
/// and `config::LIB_PATHS` as fallback defaults when the runtime state has
/// no paths configured (e.g., before `set_output_type()` has been called).
///
/// Output format:
/// ```text
/// install: <tcc_lib_path>
/// include:
///   <sysinclude_paths...>
/// libraries:
///   <library_paths...>
/// libtcc1:
///   <library_paths[0]>/<CROSS_PREFIX><LIBTCC1>
/// crt:
///   <crt_paths...>
/// elfinterp:
///   <ELF_INTERP>
/// ```
fn print_search_dirs(state: &TCCState) {
    println!("install: {}", state.tcc_lib_path);

    // Include paths: use state paths, with config defaults as reference
    if state.sysinclude_paths.is_empty() {
        // Show default system include paths from config
        let defaults = config::split_paths(config::SYSINCLUDE_PATHS);
        print_dirs("include", &defaults);
    } else {
        print_dirs("include", &state.sysinclude_paths);
    }

    // Library paths: use state paths, with config defaults as reference
    if state.library_paths.is_empty() {
        let defaults = config::split_paths(config::LIB_PATHS);
        print_dirs("libraries", &defaults);
    } else {
        print_dirs("libraries", &state.library_paths);
    }

    // libtcc1 location
    println!("libtcc1:");
    if let Some(first_lib) = state.library_paths.first() {
        println!(
            "  {}/{}{}",
            first_lib,
            config::CROSS_PREFIX,
            config::LIBTCC1
        );
    } else {
        println!(
            "  {}/{}{}",
            state.tcc_lib_path,
            config::CROSS_PREFIX,
            config::LIBTCC1
        );
    }

    // crt and elfinterp (Unix only)
    if !cfg!(target_os = "windows") {
        if state.crt_paths.is_empty() {
            let defaults = config::split_paths(config::CRT_PREFIX);
            print_dirs("crt", &defaults);
        } else {
            print_dirs("crt", &state.crt_paths);
        }
        println!("elfinterp:");
        println!("  {}", config::ELF_INTERP);
    }

    // TCCDIR reference for diagnostics in verbose mode
    if state.verbose > 1 {
        println!("tccdir: {}", config::TCCDIR);
    }
}

// =========================================================================
// Helper: set_environment
// Ported from tcc.c lines 232-248
// =========================================================================

/// Reads environment variables and adds their paths to the compiler state.
/// Ported from `set_environment()` in `tcc.c` lines 232-248.
///
/// Reads:
/// - `C_INCLUDE_PATH` → system include paths
/// - `CPATH` → user include paths
/// - `LIBRARY_PATH` → library search paths
///
/// Returns `TccResult<()>` to propagate path-addition errors properly.
fn set_environment(state: &mut TCCState) -> TccResult<()> {
    if let Ok(val) = env::var("C_INCLUDE_PATH") {
        for path in val.split(config::PATHSEP) {
            if !path.is_empty() {
                state.add_sysinclude_path(path)?;
            }
        }
    }
    if let Ok(val) = env::var("CPATH") {
        for path in val.split(config::PATHSEP) {
            if !path.is_empty() {
                state.add_include_path(path)?;
            }
        }
    }
    if let Ok(val) = env::var("LIBRARY_PATH") {
        for path in val.split(config::PATHSEP) {
            if !path.is_empty() {
                state.add_library_path(path)?;
            }
        }
    }
    Ok(())
}

// =========================================================================
// Helper: default_outputfile
// Ported from tcc.c lines 250-275
// =========================================================================

/// Determines the default output filename based on the first input file
/// and the output type.
/// Ported from `default_outputfile()` in `tcc.c` lines 250-275.
///
/// Logic:
/// - If `first_file` is "-" (stdin), returns "a.out" (or "a.exe" on Windows).
/// - Strips the directory prefix from `first_file`.
/// - Replaces the extension based on `output_type`:
///   - `OutputType::Dll` → `.dll` (Windows) or `.so` (Unix)
///   - `OutputType::Exe` → `.exe` (Windows) or strip extension (Unix)
///   - `OutputType::Obj` → `.o`
///   - Otherwise → `"a.out"` (Unix) or `"a.exe"` (Windows)
fn default_outputfile(state: &TCCState, first_file: &str) -> String {
    let is_pe = cfg!(target_os = "windows");

    if first_file == "-" {
        return if is_pe {
            "a.exe".to_string()
        } else {
            "a.out".to_string()
        };
    }

    let basename = Path::new(first_file)
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| first_file.to_string());

    // Guard: if basename is excessively long, fall back
    if basename.len() + 4 >= 1024 {
        return if is_pe {
            "a.exe".to_string()
        } else {
            "a".to_string()
        };
    }

    let path = Path::new(&basename);

    match state.output_type {
        Some(OutputType::Dll) => {
            let stem = path
                .file_stem()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_else(|| basename.clone());
            if is_pe {
                format!("{}.dll", stem)
            } else {
                format!("{}.so", stem)
            }
        }
        Some(OutputType::Exe) => {
            if is_pe {
                let stem = path
                    .file_stem()
                    .map(|s| s.to_string_lossy().to_string())
                    .unwrap_or_else(|| basename.clone());
                format!("{}.exe", stem)
            } else {
                // On Unix, strip extension
                path.file_stem()
                    .map(|s| s.to_string_lossy().to_string())
                    .unwrap_or_else(|| "a.out".to_string())
            }
        }
        Some(OutputType::Obj) => {
            let stem = path
                .file_stem()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_else(|| basename.clone());
            format!("{}.o", stem)
        }
        _ => {
            if is_pe {
                "a.exe".to_string()
            } else {
                "a.out".to_string()
            }
        }
    }
}

// =========================================================================
// Helper: @listfile expansion
// =========================================================================

/// Expands `@listfile` arguments by reading their contents and splitting
/// into individual arguments. Handles simple quoting with double quotes.
///
/// This matches the behavior of `tcc_parse_args()` in `libtcc.c` where
/// `@listfile` arguments are expanded before processing.
fn expand_args(args: Vec<String>) -> Vec<String> {
    let mut result = Vec::with_capacity(args.len());
    for arg in args {
        if let Some(stripped) = arg.strip_prefix('@') {
            // Read listfile and split into args
            match fs::read_to_string(stripped) {
                Ok(content) => {
                    let expanded = split_listfile_content(&content);
                    result.extend(expanded);
                }
                Err(e) => {
                    eprintln!("tcc: error reading listfile '{}': {}", stripped, e);
                    // Keep the original argument if file can't be read
                    result.push(arg);
                }
            }
        } else {
            result.push(arg);
        }
    }
    result
}

/// Splits listfile content into arguments, respecting double-quoted strings.
fn split_listfile_content(content: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;

    for c in content.chars() {
        if in_quotes {
            if c == '"' {
                in_quotes = false;
            } else {
                current.push(c);
            }
        } else if c == '"' {
            in_quotes = true;
        } else if c.is_whitespace() {
            if !current.is_empty() {
                args.push(std::mem::take(&mut current));
            }
        } else {
            current.push(c);
        }
    }
    if !current.is_empty() {
        args.push(current);
    }
    args
}

// =========================================================================
// Special option constants (matching tcc.h OPT_*)
// =========================================================================

/// Option identifiers for special dispatch modes.
/// These correspond to the OPT_* constants from tcc.h.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SpecialOption {
    /// No special option detected.
    None,
    /// `-h` — show help text.
    Help,
    /// `-hh` — show extended help text.
    Help2,
    /// `-print-search-dirs` — print search paths and exit.
    PrintDirs,
    /// `-dumpversion` — print version number and exit.
    DumpVersion,
    /// `-ar` — archive tool mode.
    Ar,
    /// `-impdef` — PE import definition tool.
    Impdef,
    /// `-m32` — cross-compile for 32-bit target.
    M32,
    /// `-m64` — cross-compile for 64-bit target.
    M64,
}

// =========================================================================
// Pre-parse: detect special options that don't need full TCCState
// =========================================================================

/// Scans the argument list for special options that cause immediate
/// dispatch/exit before full compilation state is created.
///
/// Returns the detected special option and the index where non-special
/// args start. This is a lightweight first pass that avoids the cost
/// of creating a full TCCState for simple queries like `-h` or `-v`.
fn detect_special_option(args: &[String]) -> SpecialOption {
    for arg in args {
        match arg.as_str() {
            "-h" | "--help" | "-help" => return SpecialOption::Help,
            "-hh" => return SpecialOption::Help2,
            "-print-search-dirs" => return SpecialOption::PrintDirs,
            "-dumpversion" => return SpecialOption::DumpVersion,
            "-ar" => return SpecialOption::Ar,
            "-impdef" => return SpecialOption::Impdef,
            "-m32" => return SpecialOption::M32,
            "-m64" => return SpecialOption::M64,
            _ => {}
        }
    }
    SpecialOption::None
}

// =========================================================================
// main() and run() — CLI orchestration
// Ported from tcc.c lines 288-428
// =========================================================================

/// Program entry point. Delegates to [`run()`] and exits with its code.
fn main() {
    let exit_code = run();
    process::exit(exit_code);
}

/// Main CLI orchestration function.
///
/// Ported from `main()` in `tcc.c` lines 288-428. This function:
/// 1. Collects and expands command-line arguments
/// 2. Handles special modes that exit early (help, version, ar, impdef, m32/m64)
/// 3. Creates a `TCCState` and configures it via `parse_args()`
/// 4. Validates inputs
/// 5. Runs the compilation pipeline
/// 6. Produces output (executable, object, preprocessed, or run in-memory)
///
/// Returns the exit code: 0 for success, 1 for errors, or the compiled
/// program's exit code when using `-run`.
fn run() -> i32 {
    // -----------------------------------------------------------------------
    // Step 1: Collect and expand arguments
    // -----------------------------------------------------------------------
    let raw_args: Vec<String> = env::args().collect();
    let argv0 = raw_args.first().cloned().unwrap_or_else(|| "tcc".to_string());

    // Skip argv[0] (program name) for argument processing
    let user_args: Vec<String> = if raw_args.len() > 1 {
        raw_args[1..].to_vec()
    } else {
        Vec::new()
    };

    // Expand @listfile arguments
    let args = expand_args(user_args);

    // -----------------------------------------------------------------------
    // Step 2: Handle special modes that exit early
    // -----------------------------------------------------------------------
    let special = detect_special_option(&args);

    match special {
        SpecialOption::Help => {
            // Use clap's help rendering infrastructure (AAP section 0.6.1)
            let _ = build_cli().print_help();
            return 0;
        }
        SpecialOption::Help2 => {
            // Extended help: clap renders the main help, then append HELP2
            let _ = build_cli().print_help();
            print!("{}", HELP2);
            return 0;
        }
        SpecialOption::DumpVersion => {
            // Use clap's version metadata for the dump-version display
            let cmd = build_cli();
            println!("{}", cmd.get_version().unwrap_or(config::TCC_VERSION));
            return 0;
        }
        SpecialOption::Ar => {
            // Everything after -ar goes to the archive tool.
            let ar_args = extract_args_after(&args, "-ar");
            match tools::tool_ar(&ar_args) {
                Ok(()) => return 0,
                Err(e) => {
                    eprintln!("tcc: {}", e);
                    return 1;
                }
            }
        }
        SpecialOption::Impdef => {
            let impdef_args = extract_args_after(&args, "-impdef");
            match tools::tool_impdef(&impdef_args) {
                Ok(()) => return 0,
                Err(e) => {
                    eprintln!("tcc: {}", e);
                    return 1;
                }
            }
        }
        SpecialOption::M32 => {
            // Re-execute with 32-bit cross-compiler
            let mut full_argv = vec![argv0.clone()];
            for a in &args {
                if a != "-m32" {
                    full_argv.push(a.clone());
                }
            }
            match tools::tool_cross(&full_argv, 32) {
                Ok(()) => return 0,
                Err(e) => {
                    eprintln!("tcc: {}", e);
                    return 1;
                }
            }
        }
        SpecialOption::M64 => {
            let mut full_argv = vec![argv0.clone()];
            for a in &args {
                if a != "-m64" {
                    full_argv.push(a.clone());
                }
            }
            match tools::tool_cross(&full_argv, 64) {
                Ok(()) => return 0,
                Err(e) => {
                    eprintln!("tcc: {}", e);
                    return 1;
                }
            }
        }
        SpecialOption::PrintDirs => {
            // Handled below after state creation
        }
        SpecialOption::None => {}
    }

    // -----------------------------------------------------------------------
    // Step 3: Check for version-only invocation
    // -----------------------------------------------------------------------
    // If the only argument is -v, print version and exit.
    // If -vv or more, we need state to display search paths.
    let only_version = args.len() == 1
        && (args[0] == "-v" || args[0] == "--version");
    if only_version {
        println!("{}", build_version_string());
        return 0;
    }

    // -----------------------------------------------------------------------
    // Step 4: Main compilation loop (redo pattern from tcc.c)
    // The C code uses `goto redo` for iterating over files in -c mode
    // and for -dt test iterations. In Rust, this becomes a loop.
    // -----------------------------------------------------------------------
    let bench_start = Instant::now();
    match run_compilation(&argv0, &args, bench_start) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("tcc: {}", e);
            1
        }
    }
}

/// Extracts arguments that follow a specific flag in the argument list.
/// For example, for `-ar`, returns everything after `-ar`.
fn extract_args_after(args: &[String], flag: &str) -> Vec<String> {
    let mut found = false;
    let mut result = Vec::new();
    for arg in args {
        if found {
            result.push(arg.clone());
        } else if arg == flag {
            found = true;
        }
    }
    result
}

/// Core compilation pipeline.
///
/// Creates a `TCCState`, configures it from CLI arguments, validates inputs,
/// and runs the compilation/output pipeline. This function implements the
/// `redo:` loop pattern from `tcc.c` lines 298-424.
fn run_compilation(
    argv0: &str,
    args: &[String],
    bench_start: Instant,
) -> Result<i32, TccError> {
    // -----------------------------------------------------------------------
    // Create compiler state and parse arguments
    // -----------------------------------------------------------------------
    let mut state = TCCState::new()?;
    state.set_lib_path_from_argv(argv0);

    // Process TCC_OPTIONS environment variable if set — this allows users
    // to provide default compiler options via the environment, matching the
    // behavior of `tcc_set_options()` in the C codebase. Options from
    // TCC_OPTIONS are applied before command-line arguments, so CLI args
    // can override them.
    if let Ok(tcc_options) = env::var("TCC_OPTIONS") {
        if !tcc_options.is_empty() {
            state.set_options(&tcc_options)?;
        }
    }

    // If -B<dir> was passed in the raw args, apply it via set_lib_path()
    // before parse_args so that the library path is configured early.
    // parse_args also handles -B internally, but this ensures the path
    // is available for any early path resolution.
    for arg in args {
        if let Some(dir) = arg.strip_prefix("-B") {
            if !dir.is_empty() {
                state.set_lib_path(dir);
            }
        }
    }

    // Parse arguments — returns list of non-option args (input files)
    let remaining_files = state.parse_args(args)?;

    // -----------------------------------------------------------------------
    // Handle -v (verbose) — print version, optionally continue
    // -----------------------------------------------------------------------
    if state.verbose > 0 {
        println!("{}", build_version_string());
    }

    // -----------------------------------------------------------------------
    // Handle -print-search-dirs after state is configured
    // -----------------------------------------------------------------------
    // Check if -print-search-dirs was in the original args
    if args.iter().any(|a| a == "-print-search-dirs") {
        set_environment(&mut state)?;
        if state.output_type.is_none() {
            state.set_output_type(OutputType::Memory)?;
        }
        print_search_dirs(&state);
        return Ok(0);
    }

    // -----------------------------------------------------------------------
    // Input validation
    // -----------------------------------------------------------------------
    if remaining_files.is_empty() {
        // If -v was given, that's a valid invocation (version display only)
        if state.verbose > 0 {
            return Ok(0);
        }
        eprintln!("tcc: error: no input files");
        return Ok(1);
    }

    // Check for -c with libraries (not allowed)
    if state.output_type == Some(OutputType::Obj) && !state.option_r {
        // Count how many files look like libraries (-l flags are already
        // consumed by parse_args, but check for .a/.so files)
        let lib_count = remaining_files
            .iter()
            .filter(|f| {
                f.ends_with(".a") || f.ends_with(".so") || f.starts_with("-l")
            })
            .count();
        if lib_count > 0 {
            eprintln!("tcc: error: cannot specify libraries with -c");
            return Ok(1);
        }

        // Check for -c with multiple files and -o
        if remaining_files.len() > 1 && state.outfile.is_some() {
            eprintln!(
                "tcc: error: cannot specify output file with -c and multiple input files"
            );
            return Ok(1);
        }
    }

    // -----------------------------------------------------------------------
    // Preprocessor-only output setup (-E flag)
    // -----------------------------------------------------------------------
    let mut ppfp: Option<Box<dyn Write>> = None;
    if state.output_type == Some(OutputType::Preprocess) {
        if let Some(ref outfile) = state.outfile {
            if outfile != "-" {
                let f = fs::File::create(outfile).map_err(|e| {
                    TccError::ConfigError {
                        message: format!("could not create '{}': {}", outfile, e),
                    }
                })?;
                ppfp = Some(Box::new(BufWriter::new(f)));
            } else {
                ppfp = Some(Box::new(io::stdout()));
            }
        } else {
            ppfp = Some(Box::new(io::stdout()));
        }
    }

    // -----------------------------------------------------------------------
    // Apply environment variables
    // -----------------------------------------------------------------------
    set_environment(&mut state)?;

    // -----------------------------------------------------------------------
    // Set default output type if not already set
    // -----------------------------------------------------------------------
    if state.output_type.is_none() {
        state.set_output_type(OutputType::Exe)?;
    } else {
        // Output type was set during parse_args; finalize it
        let ot = state.output_type.unwrap();
        // Re-apply to trigger init_default_include_paths/init_sections
        // (only if not already applied — check if sections are initialized)
        if state.sections.is_empty() && ot != OutputType::Preprocess {
            state.set_output_type(ot)?;
        }
    }

    // -----------------------------------------------------------------------
    // Handle -dt test macro auto-definition (dflag & 16)
    // -----------------------------------------------------------------------
    let dt_mode = state.dflag & 16 != 0;
    let mut test_iteration: i32 = 0;

    if dt_mode {
        // Define test_N macro for current iteration
        state.define_symbol(
            &format!("__TEST_{}", test_iteration),
            Some("1"),
        );
    }

    // -----------------------------------------------------------------------
    // Compilation loop (redo pattern)
    // -----------------------------------------------------------------------
    let mut file_idx: usize = 0;
    let mut first_file: Option<String> = None;
    let mut exit_code: i32 = 0;

    'redo: loop {
        // Process files starting from file_idx
        while file_idx < remaining_files.len() {
            let filename = &remaining_files[file_idx];
            file_idx += 1;

            // Track the first non-library file for default output naming
            if first_file.is_none() && !filename.starts_with("-l") {
                first_file = Some(filename.clone());
            }

            // Dispatch based on file type
            if let Some(lib_name) = filename.strip_prefix("-l") {
                // Library reference
                state.add_library(lib_name)?;
            } else {
                // Source/object file
                state.add_file(filename)?;
            }

            // In object-only mode (-c) without -r, output after each file
            if state.output_type == Some(OutputType::Obj) && !state.option_r {
                // Generate output for this single file
                let outfile = if let Some(ref of_) = state.outfile {
                    of_.clone()
                } else {
                    let ff = first_file.as_deref().unwrap_or("a.c");
                    default_outputfile(&state, ff)
                };

                if !state.just_deps {
                    state.output_file(&outfile)?;
                }
                if state.gen_deps {
                    let target = outfile.clone();
                    let deps_file = state.deps_outfile.clone();
                    tools::gen_makedeps(
                        &state,
                        &target,
                        deps_file.as_deref(),
                    )?;
                }

                // If there are more files, we need a fresh state for each
                if file_idx < remaining_files.len() {
                    first_file = None;
                    state = TCCState::new()?;
                    state.set_lib_path_from_argv(argv0);
                    let _ = state.parse_args(args)?;
                    set_environment(&mut state)?;
                    state.set_output_type(OutputType::Obj)?;
                    continue;
                } else {
                    break;
                }
            }
        }

        // -------------------------------------------------------------------
        // Output phase
        // -------------------------------------------------------------------
        if state.nb_errors > 0 {
            exit_code = 1;
            break 'redo;
        }

        match state.output_type {
            Some(OutputType::Memory) => {
                // -run mode: compile and execute in memory
                // Clone run_args to avoid borrow conflict with &mut self
                let run_args_owned: Vec<String> = state.run_args.clone();
                let run_args: Vec<&str> = run_args_owned
                    .iter()
                    .map(|s| s.as_str())
                    .collect();
                match state.run(&run_args) {
                    Ok(code) => {
                        exit_code = code;
                    }
                    Err(e) => {
                        eprintln!("tcc: {}", e);
                        exit_code = 1;
                    }
                }
            }
            Some(OutputType::Preprocess) => {
                // Drain the preprocessing output buffer to the target writer.
                //
                // The preprocessing pipeline writes tokens into
                // `state.ppfp_buffer` during compilation.  Here we write that
                // buffer to the destination (file or stdout) that was set up
                // earlier via the `-E`/`-o` flag combination.
                if let Some(ref mut writer) = ppfp {
                    if !state.ppfp_buffer.is_empty() {
                        let _ = writer.write_all(&state.ppfp_buffer);
                    }
                    let _ = writer.flush();
                }
            }
            _ => {
                // Generate output file (executable, shared library, or object)
                let outfile = if let Some(ref of_) = state.outfile {
                    of_.clone()
                } else {
                    let ff = first_file
                        .as_deref()
                        .unwrap_or("a.c");
                    default_outputfile(&state, ff)
                };

                if !state.just_deps {
                    state.output_file(&outfile)?;
                }

                if state.gen_deps {
                    let target = outfile.clone();
                    let deps_file = state.deps_outfile.clone();
                    tools::gen_makedeps(
                        &state,
                        &target,
                        deps_file.as_deref(),
                    )?;
                }
            }
        }

        // -------------------------------------------------------------------
        // Handle -dt test iteration loop
        // -------------------------------------------------------------------
        if dt_mode {
            test_iteration += 1;
            if state.run_test > 0 && test_iteration < state.run_test {
                // Undefine previous test macro, define new one
                state.undefine_symbol(&format!("__TEST_{}", test_iteration - 1));
                state.define_symbol(
                    &format!("__TEST_{}", test_iteration),
                    Some("1"),
                );
                file_idx = 0;
                first_file = None;
                // Create fresh state for next iteration
                state = TCCState::new()?;
                state.set_lib_path_from_argv(argv0);
                let _ = state.parse_args(args)?;
                set_environment(&mut state)?;
                if let Some(ot) = state.output_type {
                    state.set_output_type(ot)?;
                }
                continue 'redo;
            }
        }

        // Normal termination — exit the loop
        break 'redo;
    }

    // -----------------------------------------------------------------------
    // Benchmark statistics (-bench flag)
    // -----------------------------------------------------------------------
    if state.do_bench {
        let elapsed = bench_start.elapsed();
        let ms = elapsed.as_millis();
        eprintln!("* {:.1} s total compilation time", ms as f64 / 1000.0);
        state.print_stats();
    }

    // -----------------------------------------------------------------------
    // Final error check
    // -----------------------------------------------------------------------
    if state.nb_errors > 0 && exit_code == 0 {
        exit_code = 1;
    }

    Ok(exit_code)
}
