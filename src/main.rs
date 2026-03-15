//! CLI driver for tinycc-rs — the Rust port of Tiny C Compiler.
//!
//! This module translates `tcc.c` (428 lines) — the original TCC command-line
//! driver — into an idiomatic Rust CLI application using the `clap` derive API
//! per AAP §0.3.1 and §0.6.1.
//!
//! # Architecture
//!
//! The driver follows the same flow as the original C `main()` function
//! (tcc.c lines 288–428):
//!
//! 1. Parse command-line arguments (via `clap` derive)
//! 2. Dispatch tool modes (`-ar`, `-impdef`, `-m32`/`-m64`)
//! 3. Create a [`TccContext`] compilation handle
//! 4. Apply CLI arguments to the context
//! 5. Set environment variables (`C_INCLUDE_PATH`, `CPATH`, `LIBRARY_PATH`)
//! 6. Compile or add each input file
//! 7. Output result (file, in-memory execution, or preprocess)
//! 8. Report benchmark statistics if requested
//!
//! # CLI Compatibility
//!
//! All GCC-compatible flags from the original TCC are preserved:
//! `-c`, `-o`, `-I`, `-D`, `-U`, `-L`, `-l`, `-run`, `-b`, `-g`, `-gdwarf`,
//! `-O`, `-W`, `-f*`, `-m*`, and more. Single-dash long flags (TCC/GCC
//! convention) are normalized to double-dash before passing to `clap`.
//!
//! # Safety
//!
//! This module contains zero `unsafe` blocks — all operations are safe.
//! Error handling uses [`TccResult<T>`] with the `?` operator throughout.

use std::env;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process;
use std::time::Instant;

use clap::{ArgAction, Parser};
use tcc::tools::{tool_ar, tool_cross, tool_impdef};
use tcc::{OutputType, TccContext, TccError, TccResult};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// TCC version string, matching the original C `TCC_VERSION` macro.
const TCC_VERSION: &str = "0.9.28rc";

// ---------------------------------------------------------------------------
// CLI Argument Structure
// ---------------------------------------------------------------------------

/// Command-line argument structure for the TCC compiler driver.
///
/// Translates all GCC-compatible flags from `tcc.c` help\[\] and help2\[\]
/// strings (lines 31–168) into a type-safe Rust CLI interface using clap's
/// derive API.
///
/// C equivalent: `tcc_parse_args()` in `libtcc.c` and `main()` in `tcc.c`.
#[derive(Parser, Debug)]
#[command(
    name = "tcc",
    version = TCC_VERSION,
    about = "Tiny C Compiler - Copyright (C) 2001-2006 Fabrice Bellard",
    long_about = "Tiny C Compiler - Copyright (C) 2001-2006 Fabrice Bellard\n\
                  Usage: tcc [options...] [-o outfile] [-c] infile(s)...\n\
                  Usage: tcc [options...] -run infile [arguments...]",
    after_help = "Discussion & bug reports:\n  \
                  https://lists.nongnu.org/mailman/listinfo/tinycc-devel",
    disable_help_subcommand = true,
)]
struct CliArgs {
    // ===================================================================
    // General options (tcc.c help[] lines 35–47)
    // ===================================================================
    /// Compile only — generate an object file.
    /// C equivalent: `-c` flag (tcc.c:36).
    #[arg(short = 'c', help = "Compile only - generate an object file")]
    compile_only: bool,

    /// Set output filename.
    /// C equivalent: `-o outfile` (tcc.c:37).
    #[arg(short = 'o', value_name = "OUTFILE", help = "Set output filename")]
    output: Option<String>,

    /// Run compiled source in memory.
    /// C equivalent: `-run` flag (tcc.c:38).
    #[arg(long = "run", help = "Run compiled source")]
    run_mode: bool,

    /// Verbosity level (-v shows version, -vv shows search paths).
    /// C equivalent: `-v` / `-vv` (tcc.c:42–43).
    #[arg(short = 'v', action = ArgAction::Count, help = "Show version / verbose")]
    verbose: u8,

    /// Show compilation statistics (benchmark timing).
    /// C equivalent: `-bench` flag (tcc.c:45).
    #[arg(long = "bench", help = "Show compilation statistics")]
    bench: bool,

    /// Disable all warnings.
    /// C equivalent: `-w` flag (tcc.c:41).
    #[arg(short = 'w', help = "Disable all warnings")]
    no_warnings: bool,

    // ===================================================================
    // Preprocessor options (tcc.c help[] lines 48–53)
    // ===================================================================
    /// Add include search path (-Idir).
    /// C equivalent: `-Idir` (tcc.c:49).
    #[arg(short = 'I', action = ArgAction::Append, value_name = "DIR",
          help = "Add include path")]
    include_paths: Vec<String>,

    /// Define preprocessor symbol (-Dsym\[=val\]).
    /// C equivalent: `-Dsym[=val]` (tcc.c:50).
    #[arg(short = 'D', action = ArgAction::Append, value_name = "SYM[=VAL]",
          help = "Define preprocessor symbol with optional value")]
    defines: Vec<String>,

    /// Undefine preprocessor symbol (-Usym).
    /// C equivalent: `-Usym` (tcc.c:51).
    #[arg(short = 'U', action = ArgAction::Append, value_name = "SYM",
          help = "Undefine preprocessor symbol")]
    undefines: Vec<String>,

    /// Preprocess only — output preprocessed source to stdout.
    /// C equivalent: `-E` flag (tcc.c:52).
    #[arg(short = 'E', help = "Preprocess only")]
    preprocess_only: bool,

    /// Do not use standard system include paths.
    /// C equivalent: `-nostdinc` (tcc.c:53).
    #[arg(long = "nostdinc", help = "Do not use standard system include paths")]
    no_std_include: bool,

    // ===================================================================
    // Linker options (tcc.c help[] lines 54–62)
    // ===================================================================
    /// Add library search path (-Ldir).
    /// C equivalent: `-Ldir` (tcc.c:55).
    #[arg(short = 'L', action = ArgAction::Append, value_name = "DIR",
          help = "Add library path")]
    library_paths: Vec<String>,

    /// Link with dynamic or static library (-llib).
    /// C equivalent: `-llib` (tcc.c:56).
    #[arg(short = 'l', action = ArgAction::Append, value_name = "LIB",
          help = "Link with dynamic or static library")]
    libraries: Vec<String>,

    /// Do not link with standard crt and libraries.
    /// C equivalent: `-nostdlib` (tcc.c:57).
    #[arg(long = "nostdlib", help = "Do not link with standard crt and libraries")]
    no_std_lib: bool,

    /// Generate relocatable object file.
    /// C equivalent: `-r` flag (tcc.c:58).
    #[arg(short = 'r', help = "Generate (relocatable) object file")]
    relocatable: bool,

    /// Export all global symbols to dynamic linker.
    /// C equivalent: `-rdynamic` (tcc.c:59).
    #[arg(long = "rdynamic", help = "Export all global symbols to dynamic linker")]
    rdynamic: bool,

    /// Generate a shared library / DLL.
    /// C equivalent: `-shared` (tcc.c:60).
    #[arg(long = "shared", help = "Generate a shared library / DLL")]
    shared: bool,

    /// Set name for shared library to be used at runtime.
    /// C equivalent: `-soname name` (tcc.c:61).
    #[arg(long = "soname", value_name = "NAME",
          help = "Set name for shared library to be used at runtime")]
    soname: Option<String>,

    /// Link to static libraries.
    /// C equivalent: `-static` (help2:105).
    #[arg(long = "static", help = "Link to static libraries")]
    static_link: bool,

    // ===================================================================
    // Debugger options (tcc.c help[] lines 63–74)
    // ===================================================================
    /// Generate STABS runtime debug info.
    /// C equivalent: `-g` flag (tcc.c:64).
    #[arg(short = 'g', help = "Generate STABS runtime debug info")]
    debug: bool,

    /// Generate DWARF runtime debug info (optional version level).
    /// C equivalent: `-gdwarf[-x]` (tcc.c:65).
    #[arg(long = "gdwarf", value_name = "LEVEL", num_args = 0..=1,
          default_missing_value = "0",
          help = "Generate DWARF runtime debug info")]
    gdwarf: Option<String>,

    /// Compile with built-in memory and bounds checker (implies -g).
    /// C equivalent: `-b` flag (tcc.c:70).
    #[arg(short = 'b', help = "Compile with built-in memory and bounds checker (implies -g)")]
    bounds_check: bool,

    /// Link with backtrace (stack dump) support.
    /// C equivalent: `-bt[N]` (tcc.c:73).
    #[arg(long = "bt", value_name = "N", num_args = 0..=1,
          default_missing_value = "0",
          help = "Link with backtrace (stack dump) support")]
    backtrace: Option<String>,

    // ===================================================================
    // Misc options (tcc.c help[] lines 75–88 + help2)
    // ===================================================================
    /// Define `__STDC_VERSION__` according to version (c11/gnu11).
    /// C equivalent: `-std=version` (tcc.c:76).
    #[arg(long = "std", value_name = "VERSION",
          help = "Define __STDC_VERSION__ according to version")]
    std_version: Option<String>,

    /// Specify type of the next infile (C, ASM, BIN, NONE).
    /// C equivalent: `-x[c|a|b|n]` (tcc.c:77).
    #[arg(short = 'x', value_name = "TYPE",
          help = "Specify type of the next infile (C, ASM, BIN, NONE)")]
    file_type: Option<String>,

    /// Set tcc's private include/library dir.
    /// C equivalent: `-Bdir` (tcc.c:78).
    #[arg(short = 'B', value_name = "DIR",
          help = "Set tcc's private include/library dir")]
    tcc_lib_path: Option<String>,

    /// Generate make dependency file (as sole output).
    /// C equivalent: `-M` (tcc.c:80).
    #[arg(short = 'M', help = "Generate make dependency file")]
    gen_deps: bool,

    /// Generate make dependency file as a side effect of compilation.
    /// C equivalent: `-MD` (tcc.c:79).
    #[arg(long = "MD", help = "Generate make dependency file (side effect)")]
    gen_deps_side: bool,

    /// Specify dependency output file name.
    /// C equivalent: `-MF file` (tcc.c:81).
    #[arg(long = "MF", value_name = "FILE",
          help = "Specify dependency output file name")]
    deps_file: Option<String>,

    /// Warning flags (-W<warning>).
    /// C equivalent: `-Wwarning` (tcc.c:40).
    #[arg(short = 'W', action = ArgAction::Append, value_name = "WARNING",
          help = "Set or reset (with 'no-' prefix) warning")]
    warnings: Vec<String>,

    /// Compiler flags (-f<flag>).
    /// C equivalent: `-fflag` (tcc.c:39).
    #[arg(short = 'f', action = ArgAction::Append, value_name = "FLAG",
          help = "Set or reset (with 'no-' prefix) compiler flag")]
    flags: Vec<String>,

    /// Target/machine options (-m<option>).
    /// Handles `-m32`, `-m64`, `-mms-bitfields`, `-mfloat-abi`, etc.
    /// C equivalent: various -m flags (tcc.c help2).
    #[arg(short = 'm', action = ArgAction::Append, value_name = "OPTION",
          help = "Target-specific option")]
    machine_opts: Vec<String>,

    /// Optimization level (-O<n>).
    /// C equivalent: `-On` (help2:100).
    #[arg(short = 'O', value_name = "LEVEL", num_args = 0..=1,
          default_missing_value = "0",
          help = "Same as -D__OPTIMIZE__ for n > 0")]
    optimize: Option<String>,

    /// Print search directories and exit.
    /// C equivalent: `-print-search-dirs` (help2:107).
    #[arg(long = "print-search-dirs", help = "Print search paths")]
    print_search_dirs: bool,

    /// Print version string and exit.
    /// C equivalent: `-dumpversion` (help2:106).
    #[arg(long = "dumpversion", help = "Print version")]
    dumpversion: bool,

    /// Same as `-D_REENTRANT` and `-lpthread`.
    /// C equivalent: `-pthread` (help2:99).
    #[arg(long = "pthread", help = "Same as -D_REENTRANT and -lpthread")]
    pthread: bool,

    /// Force-include a file before each input (like `#include "file"`).
    /// C equivalent: `-include file` (help2:102).
    #[arg(long = "include", action = ArgAction::Append, value_name = "FILE",
          help = "Include file above each input file")]
    force_includes: Vec<String>,

    /// Add system include path.
    /// C equivalent: `-isystem dir` (help2:104).
    #[arg(long = "isystem", action = ArgAction::Append, value_name = "DIR",
          help = "Add dir to system include path")]
    sys_include_paths: Vec<String>,

    // ===================================================================
    // Tool dispatch (tcc.c help[] lines 85–89)
    // ===================================================================
    /// Archiver mode: create library (`tcc -ar [crstvx] lib [files]`).
    /// C equivalent: `-ar` tool mode (tcc.c:86).
    #[arg(long = "ar", help = "Create library: tcc --ar [crstvx] lib [files]")]
    tool_ar: bool,

    /// Windows import definition extraction mode.
    /// C equivalent: `-impdef` tool mode (tcc.c:88).
    #[arg(long = "impdef",
          help = "Create .def file: tcc --impdef lib.dll [-v] [-o lib.def]")]
    tool_impdef: bool,

    // ===================================================================
    // Extended options from help2 (tcc.c lines 94–168)
    // ===================================================================
    /// Suppress `#line` output with `-E`.
    /// C equivalent: `-P` (help2:97).
    #[arg(short = 'P', help = "With -E: no/alternative #line output")]
    no_line_output: bool,

    /// Auto-define `test_...` macros with `-run`/`-E`.
    /// C equivalent: `-dt` (help2:108).
    #[arg(long = "dt", help = "With -run/-E: auto-define test macros")]
    test_define: bool,

    /// Redirect stdin from FILE in `-run` mode.
    /// C equivalent: not in original TCC — extension for testing.
    #[arg(long = "rstdin", value_name = "FILE",
          help = "With -run: redirect stdin from FILE")]
    rstdin: Option<String>,

    /// Pass-through option strings for `TccContext::set_options()`.
    #[arg(long = "tcc-option", action = ArgAction::Append, value_name = "OPT",
          help = "Pass option directly to compiler internals", hide = true)]
    extra_options: Vec<String>,

    // ===================================================================
    // Positional arguments
    // ===================================================================
    /// Input files and (in `--run` mode) program arguments.
    ///
    /// In normal mode, all positional arguments are input files (.c, .S, .o,
    /// .a, etc.). In `--run` mode, the first positional is the source file
    /// and the rest are passed to the compiled program.
    #[arg(value_name = "FILES")]
    files: Vec<String>,
}

// ---------------------------------------------------------------------------
// Entry Point
// ---------------------------------------------------------------------------

/// CLI entry point — parses arguments, runs compilation, and exits.
///
/// Follows the `main() → run() → process::exit()` pattern from tcc.c:288–428.
/// Exit code 0 on success, 1 on error — matching original C behavior
/// (tcc.c lines 415–421 `return ret`).
///
/// TCC uses single-dash long flags (e.g. `-run`, `-bench`, `-nostdinc`) which
/// are normalized to double-dash format before clap parsing. In `-run` mode,
/// program arguments after the source file are split out before parsing so
/// they are not misinterpreted as TCC flags.
fn main() {
    let raw_args: Vec<String> = env::args().collect();

    // Split program arguments from TCC arguments for -run mode (tcc.c:298)
    let (tcc_raw, run_program_args) = split_run_args(raw_args);

    // Normalize TCC single-dash long flags to clap-compatible double-dash
    let normalized = normalize_args(tcc_raw);

    let args = match CliArgs::try_parse_from(&normalized) {
        Ok(a) => a,
        Err(e) => {
            // Let clap handle --help and --version display
            let _ = e.print();
            process::exit(if e.use_stderr() { 1 } else { 0 });
        }
    };

    let result = run(args, &run_program_args);
    process::exit(match result {
        Ok(code) => code,
        Err(e) => {
            eprintln!("tcc: error: {e}");
            1
        }
    });
}

// ---------------------------------------------------------------------------
// Argument Pre-processing
// ---------------------------------------------------------------------------

/// Split raw arguments at the `-run` flag to separate TCC flags from program
/// arguments.
///
/// In the original TCC (tcc.c:298), `-run` means: compile the next argument
/// as a source file and pass all remaining arguments to the compiled program.
/// These program arguments must not be parsed by the compiler driver.
///
/// # Returns
///
/// A tuple of `(tcc_args, program_args)`:
/// - `tcc_args`: Arguments for the TCC compiler (including `-run` and source)
/// - `program_args`: Arguments passed to the compiled program (may be empty)
///
/// # Example
///
/// ```text
/// Input:  ["tcc", "-DFOO", "-run", "source.c", "arg1", "arg2"]
/// Output: (["tcc", "-DFOO", "-run", "source.c"], ["arg1", "arg2"])
/// ```
fn split_run_args(raw_args: Vec<String>) -> (Vec<String>, Vec<String>) {
    let run_pos = raw_args
        .iter()
        .position(|a| a == "-run" || a == "--run");

    match run_pos {
        Some(idx) => {
            // Everything up to and including -run
            let mut tcc_args: Vec<String> = raw_args[..=idx].to_vec();

            let after_run = &raw_args[idx + 1..];

            // First element after -run is the source file — add to TCC args
            if let Some(source) = after_run.first() {
                tcc_args.push(source.clone());
            }

            // Remaining elements are program arguments
            let program_args = if after_run.len() > 1 {
                after_run[1..].to_vec()
            } else {
                Vec::new()
            };

            (tcc_args, program_args)
        }
        None => (raw_args, Vec::new()),
    }
}

/// Normalize TCC-style single-dash long flags to clap-compatible double-dash.
///
/// TCC (and GCC) use single-dash for flags like `-run`, `-bench`, `-nostdinc`,
/// while clap expects double-dash for long flags. This function converts known
/// single-dash long flags to their double-dash equivalents, preserving backward
/// compatibility with the original TCC CLI.
///
/// Also handles compound flags:
/// - `-MD` → `--MD`
/// - `-MF file` → `--MF file`
/// - `-gdwarf-2` → `--gdwarf=2`
/// - `-bt5` → `--bt=5`
/// - `-std=c99` → `--std=c99`
/// - `-soname name` → `--soname name`
/// - `-include file` → `--include file`
/// - `-isystem dir` → `--isystem dir`
/// - `@listfile` → expanded arguments from file
/// - `-Wp,-opt` → `-opt` (pass-through to preprocessor)
///
/// C equivalent: Argument processing logic embedded in `tcc.c` main() and
/// `tcc_parse_args()` in `libtcc.c`.
fn normalize_args(raw_args: Vec<String>) -> Vec<String> {
    let mut result = Vec::with_capacity(raw_args.len());
    let mut iter = raw_args.into_iter();

    // First element is the program name — pass through unchanged
    if let Some(prog) = iter.next() {
        result.push(prog);
    }

    while let Some(arg) = iter.next() {
        match arg.as_str() {
            // =============================================================
            // Single-dash long flags → double-dash
            // =============================================================
            "-run" => result.push("--run".to_string()),
            "-bench" => result.push("--bench".to_string()),
            "-nostdinc" => result.push("--nostdinc".to_string()),
            "-nostdlib" => result.push("--nostdlib".to_string()),
            "-rdynamic" => result.push("--rdynamic".to_string()),
            "-shared" => result.push("--shared".to_string()),
            "-static" => result.push("--static".to_string()),
            "-pthread" => result.push("--pthread".to_string()),
            "-print-search-dirs" => result.push("--print-search-dirs".to_string()),
            "-dumpversion" => result.push("--dumpversion".to_string()),
            "-ar" => result.push("--ar".to_string()),
            "-impdef" => result.push("--impdef".to_string()),
            "-dt" => result.push("--dt".to_string()),

            // =============================================================
            // Compound / special flag normalization
            // =============================================================

            // -MD / -MMD → --MD (dependency generation side-effect)
            "-MD" | "-MMD" => result.push("--MD".to_string()),

            // -MM → equivalent to -M (dependency only)
            "-MM" => result.push("-M".to_string()),

            // -MF<file> or -MF <file>
            s if s.starts_with("-MF") && s.len() > 3 => {
                result.push("--MF".to_string());
                result.push(s[3..].to_string());
            }
            "-MF" => result.push("--MF".to_string()),

            // -gdwarf or -gdwarf-<level>
            s if s.starts_with("-gdwarf") => {
                if let Some(level) = s.strip_prefix("-gdwarf-") {
                    result.push(format!("--gdwarf={level}"));
                } else {
                    result.push("--gdwarf".to_string());
                }
            }

            // -bt or -bt<N>
            "-bt" => result.push("--bt".to_string()),
            s if s.starts_with("-bt") && s.len() > 3 => {
                let n = &s[3..];
                result.push(format!("--bt={n}"));
            }

            // -std=<version>
            s if s.starts_with("-std=") => {
                result.push(format!("--std={}", &s[5..]));
            }

            // -soname <name> or -soname=<name>
            "-soname" => result.push("--soname".to_string()),
            s if s.starts_with("-soname=") => {
                result.push(format!("--soname={}", &s[8..]));
            }

            // -include <file>
            "-include" => result.push("--include".to_string()),

            // -isystem <dir> or -isystem<dir>
            "-isystem" => result.push("--isystem".to_string()),
            s if s.starts_with("-isystem") && s.len() > 8 => {
                result.push("--isystem".to_string());
                result.push(s[8..].to_string());
            }

            // -rstdin <file>
            "-rstdin" => result.push("--rstdin".to_string()),

            // -Wp,-opt → strip -Wp, prefix (pass through to preprocessor)
            s if s.starts_with("-Wp,") => {
                let inner = &s[4..];
                for part in inner.split(',') {
                    if !part.is_empty() {
                        result.push(part.to_string());
                    }
                }
            }

            // @listfile → expand arguments from file (tcc.c:47)
            s if s.starts_with('@') && s.len() > 1 => {
                let filename = &s[1..];
                match std::fs::read_to_string(filename) {
                    Ok(content) => {
                        for line in content.lines() {
                            for word in line.split_whitespace() {
                                result.push(word.to_string());
                            }
                        }
                    }
                    Err(_) => {
                        // If file cannot be read, pass through as-is
                        result.push(arg);
                    }
                }
            }

            // =============================================================
            // Ignored options (help2:110 — silently ignored for GCC compat)
            // =============================================================
            "-C" | "-pipe" | "-s" | "-traditional" | "-pedantic" => {
                // Silently ignore GCC-compatible flags that TCC does not use
            }
            "-arch" => {
                // -arch <name> — ignore flag and skip the next argument
                let _ = iter.next();
            }
            "--param" => {
                // --param <name>=<value> — ignore flag and skip value
                let _ = iter.next();
            }

            // =============================================================
            // Everything else passes through unchanged
            // =============================================================
            _ => result.push(arg),
        }
    }

    result
}

// ---------------------------------------------------------------------------
// Core Driver Logic
// ---------------------------------------------------------------------------

/// Core compilation driver — translates tcc.c main() lines 288–428.
///
/// This function implements the complete TCC compilation workflow:
/// 1. Tool dispatch (`-ar`, `-impdef`, `-m32`/`-m64`)
/// 2. Context creation and configuration
/// 3. Input file compilation
/// 4. Output generation (file, memory execution, or preprocess)
/// 5. Benchmark reporting
///
/// # Arguments
///
/// * `args` — Parsed CLI arguments from clap
/// * `run_program_args` — Arguments to pass to the compiled program in `-run`
///   mode (extracted before clap parsing by [`split_run_args()`])
///
/// # Returns
///
/// `Ok(exit_code)` on success where exit_code is 0 for compiler operations
/// or the program's exit code in `-run` mode. `Err(TccError)` on failure.
fn run(args: CliArgs, run_program_args: &[String]) -> TccResult<i32> {
    // -------------------------------------------------------------------
    // 1. Tool dispatch — handle before creating compilation context
    //    (tcc.c lines 316–321)
    // -------------------------------------------------------------------
    if args.tool_ar {
        return tool_ar(&args.files);
    }

    if args.tool_impdef {
        // tool_impdef is PE target only (tcc.c:88 — Windows only)
        return tool_impdef(&args.files);
    }

    // Cross-compilation dispatch for -m32/-m64 (tcc.c lines 311–312)
    for opt in &args.machine_opts {
        match opt.as_str() {
            "32" => {
                let all_args: Vec<String> = env::args().collect();
                return tool_cross(&all_args, 32);
            }
            "64" => {
                let all_args: Vec<String> = env::args().collect();
                return tool_cross(&all_args, 64);
            }
            _ => {} // Other -m flags handled in apply_cli_args
        }
    }

    // -------------------------------------------------------------------
    // 2. Handle version / dumpversion (tcc.c lines 313–314)
    // -------------------------------------------------------------------
    if args.dumpversion {
        println!("{TCC_VERSION}");
        return Ok(0);
    }

    // Verbose-only invocation shows version and exits (tcc.c:42)
    if args.verbose > 0 && args.files.is_empty() && !args.preprocess_only {
        println!("{}", version_string());
        return Ok(0);
    }

    // -------------------------------------------------------------------
    // 3. Create compilation context (tcc.c line 300)
    // -------------------------------------------------------------------
    let mut ctx = TccContext::new()?;

    // -------------------------------------------------------------------
    // 4. Apply CLI arguments to context (tcc.c line 301)
    // -------------------------------------------------------------------
    apply_cli_args(&mut ctx, &args)?;

    // -------------------------------------------------------------------
    // 5. Handle print-search-dirs mode (tcc.c lines 322–327)
    // -------------------------------------------------------------------
    if args.print_search_dirs {
        set_environment(&mut ctx);
        ctx.set_output_type(OutputType::Memory)?;
        println!(
            "install: {}",
            args.tcc_lib_path.as_deref().unwrap_or(".")
        );
        print_dirs("include", &args.include_paths);
        print_dirs("libraries", &args.library_paths);
        return Ok(0);
    }

    // -------------------------------------------------------------------
    // 6. Validate inputs (tcc.c lines 334–349)
    // -------------------------------------------------------------------
    if args.files.is_empty() {
        return Err(TccError::Parse {
            msg: "no input files".to_string(),
            line: 0,
            file: String::new(),
        });
    }

    // Check for invalid flag combinations (tcc.c lines 342–347)
    if args.compile_only {
        if !args.libraries.is_empty() {
            return Err(TccError::Parse {
                msg: "cannot specify libraries with -c".to_string(),
                line: 0,
                file: String::new(),
            });
        }
        if args.files.len() > 1 && args.output.is_some() {
            return Err(TccError::Parse {
                msg: "cannot specify -o with -c and multiple files".to_string(),
                line: 0,
                file: String::new(),
            });
        }
    }

    // -------------------------------------------------------------------
    // 7. Set environment (tcc.c line 354)
    // -------------------------------------------------------------------
    set_environment(&mut ctx);

    // -------------------------------------------------------------------
    // 8. Determine and set output type (tcc.c lines 355–358)
    // -------------------------------------------------------------------
    let output_type = determine_output_type(&args);
    ctx.set_output_type(output_type)?;

    // -------------------------------------------------------------------
    // 9. Start benchmark timer (tcc.c lines 350–351)
    //    Replaces C getclock_ms() at tcc.c:277 with Instant::now()
    // -------------------------------------------------------------------
    let start_time = if args.bench {
        Some(Instant::now())
    } else {
        None
    };

    // -------------------------------------------------------------------
    // 10. Compile or add each file/library (tcc.c lines 370–386)
    // -------------------------------------------------------------------
    let first_file: Option<&str> = args.files.first().map(String::as_str);

    for file_arg in &args.files {
        if args.verbose >= 1 {
            eprintln!("-> {file_arg}");
        }

        if file_arg == "-" {
            // Read source from stdin (tcc.c stdin handling)
            let mut source = String::new();
            std::io::stdin().read_to_string(&mut source)?;
            ctx.compile_string(&source)?;
        } else {
            ctx.add_file(file_arg)?;
        }
    }

    // Add libraries (tcc.c lines 375–376)
    for lib in &args.libraries {
        ctx.add_library(lib)?;
    }

    // -------------------------------------------------------------------
    // 11. Handle output (tcc.c lines 391–408)
    // -------------------------------------------------------------------
    let ret = match output_type {
        OutputType::Memory => {
            // Run mode — execute compiled code in memory (tcc.c:396–399)
            // Explicit relocate before run for symbol resolution
            ctx.relocate()?;
            let run_args: Vec<&str> =
                run_program_args.iter().map(String::as_str).collect();
            ctx.run(&run_args)?
        }
        OutputType::Preprocess => {
            // Preprocess only — already handled by compiler (tcc.c:393)
            0
        }
        _ => {
            // Output to file (tcc.c lines 400–407)
            let outfile = match &args.output {
                Some(f) => f.clone(),
                None => default_outputfile(
                    output_type,
                    first_file.unwrap_or("a"),
                ),
            };
            ctx.output_file(&outfile)?;
            0
        }
    };

    // -------------------------------------------------------------------
    // 12. Report benchmark statistics (tcc.c lines 419–420)
    //     Uses Instant::elapsed() instead of C getclock_ms() subtraction
    // -------------------------------------------------------------------
    if let Some(start) = start_time {
        let elapsed = start.elapsed();
        let total_ms = elapsed.as_millis();
        eprintln!("{total_ms} ms total compilation time");
    }

    Ok(ret)
}

// ---------------------------------------------------------------------------
// CLI Argument Application
// ---------------------------------------------------------------------------

/// Apply parsed CLI arguments to the compilation context.
///
/// Translates clap-parsed fields into [`TccContext`] method calls. Each field
/// maps to a specific API method following the libtcc API contract defined
/// in AAP §0.8.5.
///
/// C equivalent: Individual flag handling within `tcc_parse_args()` at
/// `libtcc.c` and option processing in `tcc.c` main().
fn apply_cli_args(ctx: &mut TccContext, args: &CliArgs) -> TccResult<()> {
    // -B<dir> — set tcc's private library path (tcc.c:78)
    if let Some(ref path) = args.tcc_lib_path {
        ctx.set_lib_path(path);
    }

    // -I<dir> — add include search paths (tcc.c:49)
    for path in &args.include_paths {
        ctx.add_include_path(path)?;
    }

    // -isystem <dir> — add system include paths (help2:104)
    for path in &args.sys_include_paths {
        ctx.add_sysinclude_path(path)?;
    }

    // -L<dir> — add library search paths (tcc.c:55)
    for path in &args.library_paths {
        ctx.add_library_path(path)?;
    }

    // -D<sym>[=<val>] — define preprocessor symbols (tcc.c:50)
    for def in &args.defines {
        if let Some((sym, val)) = def.split_once('=') {
            ctx.define_symbol(sym, Some(val));
        } else {
            ctx.define_symbol(def, None);
        }
    }

    // -U<sym> — undefine preprocessor symbols (tcc.c:51)
    for sym in &args.undefines {
        ctx.undefine_symbol(sym);
    }

    // -pthread → define _REENTRANT (help2:99)
    if args.pthread {
        ctx.define_symbol("_REENTRANT", None);
    }

    // -g — STABS debug info (tcc.c:64)
    if args.debug {
        ctx.set_options("-g")?;
    }

    // -gdwarf[-<level>] — DWARF debug info (tcc.c:65)
    if let Some(ref level) = args.gdwarf {
        if level == "0" || level.is_empty() {
            ctx.set_options("-gdwarf")?;
        } else {
            ctx.set_options(&format!("-gdwarf-{level}"))?;
        }
    }

    // -b — bounds checker (implies -g) (tcc.c:70)
    if args.bounds_check {
        ctx.set_options("-b")?;
    }

    // -bt[N] — backtrace support (tcc.c:73)
    if let Some(ref bt) = args.backtrace {
        if bt == "0" || bt.is_empty() {
            ctx.set_options("-bt")?;
        } else {
            ctx.set_options(&format!("-bt{bt}"))?;
        }
    }

    // -O<n> — optimization level (help2:100)
    if let Some(ref level) = args.optimize {
        ctx.set_options(&format!("-O{level}"))?;
    }

    // -w — disable all warnings (tcc.c:41)
    if args.no_warnings {
        ctx.set_options("-w")?;
    }

    // -W<warning> — warning flags (tcc.c:40)
    for warning in &args.warnings {
        ctx.set_options(&format!("-W{warning}"))?;
    }

    // -f<flag> — compiler flags (tcc.c:39)
    for flag in &args.flags {
        ctx.set_options(&format!("-f{flag}"))?;
    }

    // -m<option> — target-specific flags (non-m32/m64 dispatched above)
    for opt in &args.machine_opts {
        if opt != "32" && opt != "64" {
            ctx.set_options(&format!("-m{opt}"))?;
        }
    }

    // -std=<version> — C standard version (tcc.c:76)
    if let Some(ref ver) = args.std_version {
        ctx.set_options(&format!("-std={ver}"))?;
    }

    // -x <type> — input file type (tcc.c:77)
    if let Some(ref ft) = args.file_type {
        ctx.set_options(&format!("-x{ft}"))?;
    }

    // -nostdinc — no standard includes (tcc.c:53)
    if args.no_std_include {
        ctx.set_options("-nostdinc")?;
    }

    // -nostdlib — no standard libraries (tcc.c:57)
    if args.no_std_lib {
        ctx.set_options("-nostdlib")?;
    }

    // -rdynamic — export dynamic symbols (tcc.c:59)
    if args.rdynamic {
        ctx.set_options("-rdynamic")?;
    }

    // -static — static linking (help2:105)
    if args.static_link {
        ctx.set_options("-static")?;
    }

    // -soname <name> — shared library name (tcc.c:61)
    if let Some(ref name) = args.soname {
        ctx.set_options(&format!("-soname {name}"))?;
    }

    // -include <file> — force includes (help2:102)
    for inc in &args.force_includes {
        ctx.set_options(&format!("-include {inc}"))?;
    }

    // -M — dependency generation (tcc.c:80)
    if args.gen_deps {
        ctx.set_options("-M")?;
    }

    // -MD — dependency generation side effect (tcc.c:79)
    if args.gen_deps_side {
        ctx.set_options("-MD")?;
    }

    // -MF <file> — dependency output file (tcc.c:81)
    if let Some(ref f) = args.deps_file {
        ctx.set_options(&format!("-MF {f}"))?;
    }

    // -P — no #line output with -E (help2:97)
    if args.no_line_output {
        ctx.set_options("-P")?;
    }

    // -dt — test macro defines (help2:108)
    if args.test_define {
        ctx.set_options("-dt")?;
    }

    // Pass-through extra options (--tcc-option)
    for opt in &args.extra_options {
        ctx.set_options(opt)?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Environment Configuration
// ---------------------------------------------------------------------------

/// Read environment variables and apply them to the compilation context.
///
/// Reads `C_INCLUDE_PATH`, `CPATH`, and `LIBRARY_PATH` environment variables
/// and adds them as search paths, matching the C `set_environment()` function
/// at tcc.c lines 232–248 which uses `getenv()` to split colon-separated
/// (or semicolon-separated on Windows) paths.
///
/// Errors from individual path additions are silently ignored, matching the
/// C behavior where `getenv()`-derived paths that fail to register do not
/// abort compilation.
///
/// C equivalent: `set_environment()` at tcc.c:232–248.
fn set_environment(ctx: &mut TccContext) {
    let separator = if cfg!(target_os = "windows") {
        ';'
    } else {
        ':'
    };

    // C_INCLUDE_PATH → system include paths (tcc.c:236–239)
    if let Ok(path) = env::var("C_INCLUDE_PATH") {
        for p in path.split(separator) {
            if !p.is_empty() {
                let _ = ctx.add_sysinclude_path(p);
            }
        }
    }

    // CPATH → user include paths (tcc.c:240–243)
    if let Ok(path) = env::var("CPATH") {
        for p in path.split(separator) {
            if !p.is_empty() {
                let _ = ctx.add_include_path(p);
            }
        }
    }

    // LIBRARY_PATH → library search paths (tcc.c:244–247)
    if let Ok(path) = env::var("LIBRARY_PATH") {
        for p in path.split(separator) {
            if !p.is_empty() {
                let _ = ctx.add_library_path(p);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Output Type Determination
// ---------------------------------------------------------------------------

/// Determine the output type from CLI arguments.
///
/// Maps CLI flags to [`OutputType`] variants following the priority order
/// from tcc.c lines 355–357:
///
/// | Flag | OutputType |
/// |------|-----------|
/// | `-E` | `Preprocess` |
/// | `--run` | `Memory` |
/// | `-c` / `-r` | `Object` |
/// | `--shared` | `DynamicLibrary` |
/// | (default) | `Executable` |
///
/// C equivalent: `tcc_set_output_type()` logic at tcc.c:355–357.
fn determine_output_type(args: &CliArgs) -> OutputType {
    if args.preprocess_only {
        OutputType::Preprocess
    } else if args.run_mode {
        OutputType::Memory
    } else if args.compile_only || args.relocatable {
        OutputType::Object
    } else if args.shared {
        OutputType::DynamicLibrary
    } else {
        OutputType::Executable
    }
}

// ---------------------------------------------------------------------------
// Default Output Filename
// ---------------------------------------------------------------------------

/// Compute the default output filename based on output type and input file.
///
/// Uses [`Path`] and [`PathBuf`] for safe cross-platform path manipulation,
/// replacing the C `tcc_basename()` / `tcc_fileextension()` string operations
/// at tcc.c:250–275.
///
/// | OutputType | Platform | Default Name |
/// |-----------|----------|-------------|
/// | `Object` | all | `<stem>.o` |
/// | `DynamicLibrary` | Windows | `<stem>.dll` |
/// | `DynamicLibrary` | Unix | `<stem>.so` |
/// | `Executable` | Windows | `<stem>.exe` |
/// | `Executable` | Unix | `a.out` |
/// | other | all | `a.out` |
///
/// C equivalent: `default_outputfile()` at tcc.c:250–275.
fn default_outputfile(output_type: OutputType, first_file: &str) -> String {
    let input = Path::new(first_file);

    // Use Path::file_stem() for safe stem extraction
    let stem = input
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("a");

    // Use Path::extension() for input type detection (may be useful later)
    let _ext = input.extension().and_then(|e| e.to_str());

    match output_type {
        OutputType::Object => {
            // <stem>.o
            let mut out = PathBuf::from(stem);
            out.set_extension("o");
            out.file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("a.o")
                .to_string()
        }
        OutputType::DynamicLibrary => {
            // <stem>.dll (Windows) or <stem>.so (Unix)
            let mut out = PathBuf::from(stem);
            if cfg!(target_os = "windows") {
                out.set_extension("dll");
            } else {
                out.set_extension("so");
            }
            out.file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("a.out")
                .to_string()
        }
        OutputType::Executable => {
            // <stem>.exe (Windows) or a.out (Unix)
            if cfg!(target_os = "windows") {
                let mut out = PathBuf::from(stem);
                out.set_extension("exe");
                out.file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("a.exe")
                    .to_string()
            } else {
                "a.out".to_string()
            }
        }
        OutputType::Memory | OutputType::Preprocess => {
            // These output types don't produce files
            "a.out".to_string()
        }
    }
}

// ---------------------------------------------------------------------------
// Utility Functions
// ---------------------------------------------------------------------------

/// Print a labeled list of directories.
///
/// C equivalent: `print_dirs()` at tcc.c:211–217.
fn print_dirs(msg: &str, paths: &[String]) {
    println!("{msg}:");
    if paths.is_empty() {
        println!("  -");
    } else {
        for path in paths {
            println!("  {path}");
        }
    }
}

/// Build the version string matching the C version\[\] format.
///
/// Format: `tcc version {VERSION} ({TARGET} {OS})`
///
/// C equivalent: `version[]` array at tcc.c:170–209.
fn version_string() -> String {
    let target = if cfg!(target_arch = "x86_64") {
        "x86_64"
    } else if cfg!(target_arch = "x86") {
        "i386"
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
    } else {
        "Linux"
    };

    format!("tcc version {TCC_VERSION} ({target} {os})")
}
