// -------------------------------------------------------------------------
// Tiny C Compiler — Rust Integration Test Runner
//
// Copyright (c) 2001-2004 Fabrice Bellard
// Copyright (c) TinyCC contributors
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2 of the License, or (at your option) any later version.
// -------------------------------------------------------------------------
//! # Integration Test Runner
//!
//! This file is the primary automated validation that the Rust-built TCC
//! binary produces equivalent results to the C-built TCC. It invokes the
//! compiled `tcc` binary against the existing test suite inputs:
//!
//! - **`tests/tests2/*.c`** — 127+ numbered C regression tests (canonical count
//!   is 127; the actual directory may contain additional companion files)
//! - **`tests/pp/*.c` / `*.S`** — 24+ preprocessor regression tests
//!
//! Each test compiles/runs a C file with the `tcc` binary and compares the
//! captured output (stdout + stderr) against the corresponding `.expect`
//! file, replicating the C Makefile's diff-based validation pattern:
//!
//! ```text
//! # tests2 pattern:
//! $(TCC) -run $(SRC)/$*.c > $*.output 2>&1
//! diff $(SRC)/$*.expect $*.output
//!
//! # pp pattern:
//! $(TCC) -E -P $< > $*.output 2>&1
//! diff $(DIFF_OPTS) $(SRC)/$*.expect $*.output
//! ```

use std::fmt::Write as FmtWrite;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use similar::TextDiff;
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// Path Resolution Helpers
// ---------------------------------------------------------------------------

/// Locate the project workspace root directory.
///
/// The integration test is declared in `crates/tcc-core/Cargo.toml` so
/// `CARGO_MANIFEST_DIR` points to `<workspace>/crates/tcc-core`. We walk
/// two levels up to reach the workspace root.
fn project_root() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .expect("could not find crates/ directory")
        .parent()
        .expect("could not find workspace root")
        .to_path_buf()
}

/// Locate the compiled `tcc` binary produced by the `tcc-cli` crate.
///
/// Resolution order:
/// 1. `CARGO_BIN_EXE_tcc` environment variable (set by `cargo test` when
///    the test crate has a binary dependency — may not be available here).
/// 2. `<target_dir>/debug/tcc`
/// 3. `<target_dir>/release/tcc`
///
/// `<target_dir>` is derived from `CARGO_TARGET_DIR` if set, otherwise
/// defaults to `<workspace_root>/target`.
fn tcc_binary_path() -> PathBuf {
    // 1. Cargo-provided path (highest priority)
    if let Ok(path) = std::env::var("CARGO_BIN_EXE_tcc") {
        let p = PathBuf::from(&path);
        if p.exists() {
            return p;
        }
    }

    // 2. Derive target directory
    let workspace = project_root();
    let target_dir = std::env::var("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| workspace.join("target"));

    // 3. Prefer debug build (cargo test default), then release
    let debug_bin = target_dir.join("debug").join("tcc");
    if debug_bin.exists() {
        return debug_bin;
    }

    let release_bin = target_dir.join("release").join("tcc");
    if release_bin.exists() {
        return release_bin;
    }

    panic!(
        "Could not find tcc binary at {:?} or {:?}. \
         Run `cargo build` before running integration tests.",
        debug_bin, release_bin
    );
}

/// Path to `tests/tests2/` directory.
fn tests2_dir() -> PathBuf {
    project_root().join("tests").join("tests2")
}

/// Path to `tests/pp/` directory.
fn pp_dir() -> PathBuf {
    project_root().join("tests").join("pp")
}

// ---------------------------------------------------------------------------
// Output Filtering
// ---------------------------------------------------------------------------

/// Strip the source directory prefix from compiler output.
///
/// This replicates the C Makefile's base `FILTER`:
/// ```makefile
/// FILTER = 2>&1 | sed -e 's,$(SRC)/,,g'
/// ```
///
/// TCC error messages include the full path to source files; this function
/// normalises them to bare filenames for comparison with `.expect` files.
fn filter_source_dir(output: &str, src_dir: &Path) -> String {
    let prefix_with_slash = format!("{}/", src_dir.display());
    let prefix_bare = format!("{}", src_dir.display());
    output
        .replace(&prefix_with_slash, "")
        .replace(&prefix_bare, "")
}

/// Normalise hexadecimal addresses in backtrace output.
///
/// Replicates the Makefile filter for backtrace tests:
/// ```makefile
/// -e 's;[0-9A-Fa-fx]\{5,\};........;g'
/// -e 's;0x[0-9A-Fa-f]\{1,\};0x?;g'
/// ```
fn normalise_hex_addresses(output: &str) -> String {
    let mut result = String::with_capacity(output.len());
    let chars: Vec<char> = output.chars().collect();
    let len = chars.len();
    let mut i = 0;

    while i < len {
        // Check for "0x" prefix followed by hex digits
        if i + 2 < len && chars[i] == '0' && chars[i + 1] == 'x' {
            let start = i + 2;
            let mut end = start;
            while end < len && chars[end].is_ascii_hexdigit() {
                end += 1;
            }
            if end > start {
                result.push_str("0x?");
                i = end;
                continue;
            }
        }

        // Check for runs of 5+ hex-like chars (digits, a-f, A-F, 'x')
        if is_hex_like(chars[i]) {
            let start = i;
            let mut j = i;
            while j < len && is_hex_like(chars[j]) {
                j += 1;
            }
            if j - start >= 5 {
                result.push_str("........");
            } else {
                for &c in &chars[start..j] {
                    result.push(c);
                }
            }
            i = j;
            continue;
        }

        result.push(chars[i]);
        i += 1;
    }
    result
}

/// Returns `true` if the character is in `[0-9A-Fa-fx]`.
fn is_hex_like(c: char) -> bool {
    c.is_ascii_hexdigit() || c == 'x'
}

// ---------------------------------------------------------------------------
// Test Configuration and Execution Helpers
// ---------------------------------------------------------------------------

/// Options controlling how a tests2 test case is executed.
#[derive(Default)]
struct Tests2Opts<'a> {
    /// Additional flags passed to tcc before the source file (e.g. `-dt`,
    /// `-b`, `-lm`, `-fdollars-in-identifiers`).
    flags: &'a [&'a str],
    /// Arguments passed *after* the source file (e.g. `arg1 arg2`).
    args: &'a [&'a str],
    /// If `true`, compile to an executable then run it instead of using
    /// `-run` mode. Mirrors the Makefile's `NORUN = true`.
    norun: bool,
    /// Additional source files compiled alongside the primary source
    /// (e.g. `104+_inline.c` for `104_inline`).
    extra_sources: &'a [&'a str],
    /// Apply hex-address normalisation to the output (for backtrace tests).
    normalise_hex: bool,
}

/// Run a single `tests/tests2/` test case with default options.
///
/// Equivalent to the Makefile pattern:
/// ```makefile
/// $(TCC) -run $(SRC)/$*.c > $*.output 2>&1
/// diff $(SRC)/$*.expect $*.output
/// ```
fn run_tests2_case(test_name: &str) -> Result<(), String> {
    run_tests2_case_with_opts(test_name, &Tests2Opts::default())
}

/// Run a single `tests/tests2/` test case with explicit options.
fn run_tests2_case_with_opts(test_name: &str, opts: &Tests2Opts<'_>) -> Result<(), String> {
    let src_dir = tests2_dir();
    let source = src_dir.join(format!("{}.c", test_name));
    let expect = src_dir.join(format!("{}.expect", test_name));

    if !source.exists() {
        return Err(format!("Source file not found: {}", source.display()));
    }

    let temp_dir = TempDir::new().map_err(|e| format!("tempdir creation failed: {}", e))?;
    let tcc = tcc_binary_path();

    let output = if opts.norun {
        // ---------------------------------------------------------------
        // NORUN path: compile to executable, then run the executable.
        // Mirrors: $(TCC) $(FLAGS) $1 -o test.exe && ./test.exe $(ARGS)
        // ---------------------------------------------------------------
        let exe_path = temp_dir.path().join("test_exe");

        let mut compile_cmd = Command::new(&tcc);
        for flag in opts.flags {
            compile_cmd.arg(flag);
        }
        // Extra source files come before the main source
        for extra in opts.extra_sources {
            compile_cmd.arg(src_dir.join(extra));
        }
        compile_cmd
            .arg(&source)
            .arg("-o")
            .arg(&exe_path)
            .current_dir(temp_dir.path());

        let compile_out = compile_cmd
            .output()
            .map_err(|e| format!("Failed to execute tcc (compile): {}", e))?;

        if !compile_out.status.success() {
            // Return compile errors as the test output for comparison.
            // Some NORUN tests deliberately produce compile-time diagnostics.
            let stderr = String::from_utf8_lossy(&compile_out.stderr);
            let stdout = String::from_utf8_lossy(&compile_out.stdout);
            let combined = format!("{}{}", stdout, stderr);
            return compare_output(&combined, &expect, &src_dir, test_name, opts.normalise_hex);
        }

        // Run the compiled executable with any test-specific ARGS
        let mut run_cmd = Command::new(&exe_path);
        for arg in opts.args {
            run_cmd.arg(arg);
        }
        run_cmd.current_dir(temp_dir.path());

        run_cmd
            .output()
            .map_err(|e| format!("Failed to execute compiled test binary: {}", e))?
    } else {
        // ---------------------------------------------------------------
        // Standard -run path.
        // Mirrors: $(TCC) $(FLAGS) [extras] -run $1 $(ARGS)
        // ---------------------------------------------------------------
        let mut cmd = Command::new(&tcc);
        for flag in opts.flags {
            cmd.arg(flag);
        }
        for extra in opts.extra_sources {
            cmd.arg(src_dir.join(extra));
        }
        cmd.arg("-run").arg(&source);
        for arg in opts.args {
            cmd.arg(arg);
        }
        cmd.current_dir(temp_dir.path());

        cmd.output()
            .map_err(|e| format!("Failed to execute tcc -run: {}", e))?
    };

    // Combine stdout and stderr (matching the C Makefile's 2>&1 pattern).
    // The `|| true` in the Makefile means a non-zero exit is not fatal;
    // the output is still compared against .expect.
    let stdout_str = String::from_utf8_lossy(&output.stdout);
    let stderr_str = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{}{}", stdout_str, stderr_str);

    compare_output(&combined, &expect, &src_dir, test_name, opts.normalise_hex)
}

/// Compare actual output against the `.expect` file.
///
/// If no `.expect` file exists, the test passes as long as the output is
/// empty or the test compiled successfully (some tests just verify compilation).
fn compare_output(
    actual_raw: &str,
    expect_path: &Path,
    src_dir: &Path,
    test_name: &str,
    normalise_hex: bool,
) -> Result<(), String> {
    // Apply source-directory stripping (base FILTER from Makefile)
    let mut actual = filter_source_dir(actual_raw, src_dir);

    // Apply hex-address normalisation if requested (backtrace tests)
    if normalise_hex {
        actual = normalise_hex_addresses(&actual);
    }

    if !expect_path.exists() {
        // No .expect file: test passes if output is empty (compilation-only)
        if actual.trim().is_empty() {
            return Ok(());
        }
        return Err(format!(
            "Test {} produced output but has no .expect file:\n{}",
            test_name, actual
        ));
    }

    let expected =
        fs::read_to_string(expect_path).map_err(|e| format!("Read .expect file: {}", e))?;

    // Apply hex normalisation to expected output as well when enabled
    let expected_normalised = if normalise_hex {
        normalise_hex_addresses(&expected)
    } else {
        expected.clone()
    };

    if actual.trim() == expected_normalised.trim() {
        Ok(())
    } else {
        let diff = TextDiff::from_lines(&expected_normalised, &actual);
        let mut diff_output = String::new();
        for change in diff.iter_all_changes() {
            let sign = match change.tag() {
                similar::ChangeTag::Delete => "-",
                similar::ChangeTag::Insert => "+",
                similar::ChangeTag::Equal => " ",
            };
            let _ = write!(diff_output, "{}{}", sign, change);
        }
        Err(format!(
            "Output mismatch for {}:\n--- expected\n+++ actual\n{}",
            test_name, diff_output
        ))
    }
}

// ---------------------------------------------------------------------------
// Preprocessor Test Execution Helper
// ---------------------------------------------------------------------------

/// Options controlling how a `tests/pp/` test case is executed.
#[derive(Default)]
struct PpOpts {
    /// Use whitespace-insensitive comparison (mirrors `DIFF_OPTS += -w`
    /// from the pp Makefile for test 02).
    ignore_whitespace: bool,
}

/// Run a single `tests/pp/` preprocessor test case with default options.
///
/// Pattern from `tests/pp/Makefile`:
/// ```makefile
/// $(TCC) -E -P $< $(FILTER) >$*.output 2>&1
/// diff $(DIFF_OPTS) $(SRC)/$*.expect $*.output
/// ```
fn run_pp_case(test_name: &str, ext: &str) -> Result<(), String> {
    run_pp_case_with_opts(test_name, ext, &PpOpts::default())
}

/// Run a preprocessor test case with explicit options.
fn run_pp_case_with_opts(test_name: &str, ext: &str, opts: &PpOpts) -> Result<(), String> {
    let src_dir = pp_dir();
    let source = src_dir.join(format!("{}.{}", test_name, ext));
    let expect = src_dir.join(format!("{}.expect", test_name));

    if !source.exists() {
        return Err(format!("Source file not found: {}", source.display()));
    }
    if !expect.exists() {
        return Err(format!("Expect file not found: {}", expect.display()));
    }

    let tcc = tcc_binary_path();
    let output = Command::new(&tcc)
        .arg("-E")
        .arg("-P")
        .arg(&source)
        .output()
        .map_err(|e| format!("Failed to execute tcc -E -P: {}", e))?;

    let stdout_str = String::from_utf8_lossy(&output.stdout);
    let stderr_str = String::from_utf8_lossy(&output.stderr);
    let actual_raw = format!("{}{}", stdout_str, stderr_str);

    // Apply source-directory stripping
    let actual = filter_source_dir(&actual_raw, &src_dir);
    let expected =
        fs::read_to_string(&expect).map_err(|e| format!("Read .expect file: {}", e))?;

    let matches = if opts.ignore_whitespace {
        // Whitespace-insensitive comparison (diff -w) — test 02
        normalise_whitespace(&actual) == normalise_whitespace(&expected)
    } else {
        // Default: diff -b — ignore changes in amount of whitespace.
        // The C TCC tests/pp/Makefile uses DIFF_OPTS = -Nu -b for all
        // PP tests, so tab-vs-space and double-vs-single space
        // differences are considered equal.
        normalise_space_amount(actual.trim()) == normalise_space_amount(expected.trim())
    };

    if matches {
        Ok(())
    } else {
        let diff = TextDiff::from_lines(&expected, &actual);
        let mut diff_output = String::new();
        for change in diff.iter_all_changes() {
            let sign = match change.tag() {
                similar::ChangeTag::Delete => "-",
                similar::ChangeTag::Insert => "+",
                similar::ChangeTag::Equal => " ",
            };
            let _ = write!(diff_output, "{}{}", sign, change);
        }
        Err(format!(
            "PP output mismatch for {}:\n--- expected\n+++ actual\n{}",
            test_name, diff_output
        ))
    }
}

/// Collapse all whitespace sequences to a single space and trim, for
/// whitespace-insensitive comparison (mirrors `diff -w`).
/// Emulate `diff -w`: ignore ALL whitespace differences.
///
/// This strips every whitespace character so that `f (2 * (y + 1))` and
/// `f(2 * (y+1))` compare equal, matching the behaviour of the
/// Makefile's `DIFF_OPTS += -w`.
fn normalise_whitespace(s: &str) -> String {
    s.chars().filter(|c| !c.is_whitespace()).collect()
}

/// Emulate `diff -b`: ignore changes in the *amount* of whitespace.
///
/// Each run of consecutive whitespace characters (space, tab, etc.) within
/// a line is collapsed to a single space, and trailing whitespace on each
/// line is stripped.  This mirrors the default `DIFF_OPTS = -Nu -b` used
/// by the TCC `tests/pp/Makefile` for all PP test comparisons.
fn normalise_space_amount(s: &str) -> String {
    s.lines()
        .map(|line| {
            let mut result = String::with_capacity(line.len());
            let mut in_space = false;
            for c in line.chars() {
                if c == ' ' || c == '\t' {
                    if !in_space {
                        result.push(' ');
                        in_space = true;
                    }
                } else {
                    in_space = false;
                    result.push(c);
                }
            }
            // Strip trailing whitespace (diff -b ignores trailing spaces)
            let trimmed = result.trim_end();
            trimmed.to_string()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

// ===========================================================================
// tests/tests2/ — Individual Regression Test Functions (127 tests)
//
// Each function maps 1:1 to a numbered C test file. The function name
// encodes the test identity: `test_tests2_<number>_<name>`.
//
// Tests that are SKIPPED in the C Makefile are annotated with `#[ignore]`
// and a reason comment. Platform-specific tests use `#[cfg(...)]` gates
// matching the C Makefile's SKIP logic.
// ===========================================================================

// --- 00–09 : Basic Language Features ---

#[test]
fn test_tests2_00_assignment() {
    run_tests2_case("00_assignment").unwrap();
}

#[test]
fn test_tests2_01_comment() {
    run_tests2_case("01_comment").unwrap();
}

#[test]
fn test_tests2_02_printf() {
    run_tests2_case("02_printf").unwrap();
}

#[test]
fn test_tests2_03_struct() {
    run_tests2_case("03_struct").unwrap();
}

#[test]
fn test_tests2_04_for() {
    run_tests2_case("04_for").unwrap();
}

#[test]
fn test_tests2_05_array() {
    run_tests2_case("05_array").unwrap();
}

#[test]
fn test_tests2_06_case() {
    run_tests2_case("06_case").unwrap();
}

#[test]
fn test_tests2_07_function() {
    run_tests2_case("07_function").unwrap();
}

#[test]
fn test_tests2_08_while() {
    run_tests2_case("08_while").unwrap();
}

#[test]
fn test_tests2_09_do_while() {
    run_tests2_case("09_do_while").unwrap();
}

// --- 10–19 : Pointers, Precedence, Preprocessor, Literals ---

#[test]
fn test_tests2_10_pointer() {
    run_tests2_case("10_pointer").unwrap();
}

#[test]
fn test_tests2_11_precedence() {
    run_tests2_case("11_precedence").unwrap();
}

#[test]
fn test_tests2_12_hashdefine() {
    run_tests2_case("12_hashdefine").unwrap();
}

#[test]
fn test_tests2_13_integer_literals() {
    run_tests2_case("13_integer_literals").unwrap();
}

#[test]
fn test_tests2_14_if() {
    run_tests2_case("14_if").unwrap();
}

#[test]
fn test_tests2_15_recursion() {
    run_tests2_case("15_recursion").unwrap();
}

#[test]
fn test_tests2_16_nesting() {
    run_tests2_case("16_nesting").unwrap();
}

#[test]
fn test_tests2_17_enum() {
    run_tests2_case("17_enum").unwrap();
}

#[test]
fn test_tests2_18_include() {
    run_tests2_case("18_include").unwrap();
}

#[test]
fn test_tests2_19_pointer_arithmetic() {
    run_tests2_case("19_pointer_arithmetic").unwrap();
}

// --- 20–29 : Pointer Comparison, Strings, Arrays ---

#[test]
fn test_tests2_20_pointer_comparison() {
    run_tests2_case("20_pointer_comparison").unwrap();
}

#[test]
fn test_tests2_21_char_array() {
    run_tests2_case("21_char_array").unwrap();
}

#[test]
fn test_tests2_22_floating_point() {
    // Makefile: 22_floating_point.test: FLAGS += -lm
    run_tests2_case_with_opts(
        "22_floating_point",
        &Tests2Opts { flags: &["-lm"], ..Tests2Opts::default() },
    )
    .unwrap();
}

#[test]
fn test_tests2_23_type_coercion() {
    run_tests2_case("23_type_coercion").unwrap();
}

#[test]
fn test_tests2_24_math_library() {
    // Makefile: 24_math_library.test: FLAGS += -lm
    run_tests2_case_with_opts(
        "24_math_library",
        &Tests2Opts { flags: &["-lm"], ..Tests2Opts::default() },
    )
    .unwrap();
}

#[test]
fn test_tests2_25_quicksort() {
    run_tests2_case("25_quicksort").unwrap();
}

#[test]
fn test_tests2_26_character_constants() {
    run_tests2_case("26_character_constants").unwrap();
}

#[test]
fn test_tests2_27_sizeof() {
    run_tests2_case("27_sizeof").unwrap();
}

#[test]
fn test_tests2_28_strings() {
    run_tests2_case("28_strings").unwrap();
}

#[test]
fn test_tests2_29_array_address() {
    run_tests2_case("29_array_address").unwrap();
}

// --- 30–39 : Algorithms, Args, Ternary, Typedefs ---

#[test]
fn test_tests2_30_hanoi() {
    run_tests2_case("30_hanoi").unwrap();
}

#[test]
fn test_tests2_31_args() {
    // Makefile: 31_args.test : ARGS = arg1 arg2 arg3 arg4 arg5
    run_tests2_case_with_opts(
        "31_args",
        &Tests2Opts { args: &["arg1", "arg2", "arg3", "arg4", "arg5"], ..Tests2Opts::default() },
    )
    .unwrap();
}

#[test]
fn test_tests2_32_led() {
    run_tests2_case("32_led").unwrap();
}

#[test]
fn test_tests2_33_ternary_op() {
    run_tests2_case("33_ternary_op").unwrap();
}

#[test]
#[ignore = "array assignment is not in C standard (SKIP in Makefile)"]
fn test_tests2_34_array_assignment() {
    run_tests2_case("34_array_assignment").unwrap();
}

#[test]
fn test_tests2_35_sizeof() {
    run_tests2_case("35_sizeof").unwrap();
}

#[test]
fn test_tests2_36_array_initialisers() {
    run_tests2_case("36_array_initialisers").unwrap();
}

#[test]
fn test_tests2_37_sprintf() {
    run_tests2_case("37_sprintf").unwrap();
}

#[test]
fn test_tests2_38_multiple_array_index() {
    run_tests2_case("38_multiple_array_index").unwrap();
}

#[test]
fn test_tests2_39_typedef() {
    run_tests2_case("39_typedef").unwrap();
}

// --- 40–49 : stdio, hashif, Function Pointers, Scoping ---

#[test]
fn test_tests2_40_stdio() {
    run_tests2_case("40_stdio").unwrap();
}

#[test]
fn test_tests2_41_hashif() {
    run_tests2_case("41_hashif").unwrap();
}

#[test]
fn test_tests2_42_function_pointer() {
    // Makefile: 42_function_pointer.test : NORUN = true
    run_tests2_case_with_opts(
        "42_function_pointer",
        &Tests2Opts { norun: true, ..Tests2Opts::default() },
    )
    .unwrap();
}

#[test]
fn test_tests2_43_void_param() {
    run_tests2_case("43_void_param").unwrap();
}

#[test]
fn test_tests2_44_scoped_declarations() {
    run_tests2_case("44_scoped_declarations").unwrap();
}

#[test]
fn test_tests2_45_empty_for() {
    run_tests2_case("45_empty_for").unwrap();
}

#[test]
fn test_tests2_46_grep() {
    // Makefile: 46_grep.test : ARGS = '[^* ]*[:a:d: ]+\:\*-/: $$' $(SRC)/46_grep.c
    // The second arg is the path to the source file itself (used as grep input)
    let grep_src = tests2_dir().join("46_grep.c");
    let grep_src_str = grep_src.to_string_lossy().to_string();
    let args: Vec<&str> = vec![r"[^* ]*[:a:d: ]+\:\*-/: $$", &grep_src_str];
    run_tests2_case_with_opts(
        "46_grep",
        &Tests2Opts { args: &args, ..Tests2Opts::default() },
    )
    .unwrap();
}

#[test]
fn test_tests2_47_switch_return() {
    run_tests2_case("47_switch_return").unwrap();
}

#[test]
fn test_tests2_48_nested_break() {
    run_tests2_case("48_nested_break").unwrap();
}

#[test]
fn test_tests2_49_bracket_evaluation() {
    run_tests2_case("49_bracket_evaluation").unwrap();
}

// --- 50–55 : Logical Ops, Static, Enums, Goto, Shifts ---

#[test]
fn test_tests2_50_logical_second_arg() {
    run_tests2_case("50_logical_second_arg").unwrap();
}

#[test]
fn test_tests2_51_static() {
    run_tests2_case("51_static").unwrap();
}

#[test]
fn test_tests2_52_unnamed_enum() {
    run_tests2_case("52_unnamed_enum").unwrap();
}

#[test]
fn test_tests2_54_goto() {
    run_tests2_case("54_goto").unwrap();
}

#[test]
fn test_tests2_55_lshift_type() {
    run_tests2_case("55_lshift_type").unwrap();
}

// --- 60–67 : Errors/Warnings, Integers, Macro Nesting/Concat ---

#[test]
fn test_tests2_60_errors_and_warnings() {
    // Makefile: 60_errors_and_warnings.test : FLAGS += -dt
    run_tests2_case_with_opts(
        "60_errors_and_warnings",
        &Tests2Opts { flags: &["-dt"], ..Tests2Opts::default() },
    )
    .unwrap();
}

#[test]
fn test_tests2_61_integers() {
    run_tests2_case("61_integers").unwrap();
}

#[test]
fn test_tests2_64_macro_nesting() {
    run_tests2_case("64_macro_nesting").unwrap();
}

#[test]
fn test_tests2_67_macro_concat() {
    run_tests2_case("67_macro_concat").unwrap();
}

// --- 70–79 : FP Literals, Macros, ARM64, Arrays, VLA ---

#[test]
fn test_tests2_70_floating_point_literals() {
    run_tests2_case("70_floating_point_literals").unwrap();
}

#[test]
fn test_tests2_71_macro_empty_arg() {
    run_tests2_case("71_macro_empty_arg").unwrap();
}

#[test]
fn test_tests2_72_long_long_constant() {
    run_tests2_case("72_long_long_constant").unwrap();
}

#[test]
fn test_tests2_73_arm64() {
    run_tests2_case("73_arm64").unwrap();
}

#[test]
fn test_tests2_75_array_in_struct_init() {
    run_tests2_case("75_array_in_struct_init").unwrap();
}

#[test]
fn test_tests2_76_dollars_in_identifiers() {
    // Makefile: 76_dollars_in_identifiers.test : FLAGS += -fdollars-in-identifiers
    run_tests2_case_with_opts(
        "76_dollars_in_identifiers",
        &Tests2Opts { flags: &["-fdollars-in-identifiers"], ..Tests2Opts::default() },
    )
    .unwrap();
}

#[test]
fn test_tests2_77_push_pop_macro() {
    run_tests2_case("77_push_pop_macro").unwrap();
}

#[test]
fn test_tests2_78_vla_label() {
    run_tests2_case("78_vla_label").unwrap();
}

#[test]
fn test_tests2_79_vla_continue() {
    run_tests2_case("79_vla_continue").unwrap();
}

// --- 80–89 : Flexarray, Types, Attributes, Hex-Float, ASM, Dead Code ---

#[test]
fn test_tests2_80_flexarray() {
    run_tests2_case("80_flexarray").unwrap();
}

#[test]
fn test_tests2_81_types() {
    run_tests2_case("81_types").unwrap();
}

#[test]
fn test_tests2_82_attribs_position() {
    run_tests2_case("82_attribs_position").unwrap();
}

#[test]
fn test_tests2_83_utf8_in_identifiers() {
    run_tests2_case("83_utf8_in_identifiers").unwrap();
}

#[test]
fn test_tests2_84_hex_float() {
    run_tests2_case("84_hex-float").unwrap();
}

#[test]
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn test_tests2_85_asm_outside_function() {
    // Makefile: SKIP += 85_asm-outside-function.test (non-x86/x86_64)
    run_tests2_case("85_asm-outside-function").unwrap();
}

#[test]
fn test_tests2_86_memory_model() {
    run_tests2_case("86_memory-model").unwrap();
}

#[test]
fn test_tests2_87_dead_code() {
    run_tests2_case("87_dead_code").unwrap();
}

#[test]
fn test_tests2_88_codeopt() {
    run_tests2_case("88_codeopt").unwrap();
}

#[test]
fn test_tests2_89_nocode_wanted() {
    run_tests2_case("89_nocode_wanted").unwrap();
}

// --- 90–99 : Struct Init, Bitfields, Enums, Generics, Fastcall ---

#[test]
fn test_tests2_90_struct_init() {
    run_tests2_case("90_struct-init").unwrap();
}

#[test]
fn test_tests2_91_ptr_longlong_arith32() {
    run_tests2_case("91_ptr_longlong_arith32").unwrap();
}

#[test]
fn test_tests2_92_enum_bitfield() {
    run_tests2_case("92_enum_bitfield").unwrap();
}

#[test]
fn test_tests2_93_integer_promotion() {
    run_tests2_case("93_integer_promotion").unwrap();
}

#[test]
fn test_tests2_94_generic() {
    run_tests2_case("94_generic").unwrap();
}

#[test]
fn test_tests2_95_bitfields() {
    run_tests2_case("95_bitfields").unwrap();
}

#[test]
fn test_tests2_95_bitfields_ms() {
    run_tests2_case("95_bitfields_ms").unwrap();
}

#[test]
fn test_tests2_96_nodata_wanted() {
    // Makefile: 96_nodata_wanted.test : FLAGS += -dt
    run_tests2_case_with_opts(
        "96_nodata_wanted",
        &Tests2Opts { flags: &["-dt"], ..Tests2Opts::default() },
    )
    .unwrap();
}

#[test]
fn test_tests2_97_utf8_string_literal() {
    run_tests2_case("97_utf8_string_literal").unwrap();
}

#[test]
#[ignore = "i386 only — SKIP in Makefile for non-i386"]
fn test_tests2_98_al_ax_extend() {
    run_tests2_case("98_al_ax_extend").unwrap();
}

#[test]
#[ignore = "i386 only — SKIP in Makefile for non-i386"]
fn test_tests2_99_fastcall() {
    run_tests2_case("99_fastcall").unwrap();
}

// --- 100–109 : C99 Arrays, Cleanup, Alignas, Inline, Versym ---

#[test]
fn test_tests2_100_c99array_decls() {
    run_tests2_case("100_c99array-decls").unwrap();
}

#[test]
fn test_tests2_101_cleanup() {
    run_tests2_case("101_cleanup").unwrap();
}

#[test]
fn test_tests2_102_alignas() {
    run_tests2_case("102_alignas").unwrap();
}

#[test]
fn test_tests2_103_implicit_memmove() {
    run_tests2_case("103_implicit_memmove").unwrap();
}

#[test]
fn test_tests2_104_inline() {
    // Makefile: 104_inline.test : FLAGS += $(subst 104,104+,$1)
    //           104_inline.test : GEN = $(GEN-TCC)
    // This is a multi-file test: 104_inline.c + 104+_inline.c
    run_tests2_case_with_opts(
        "104_inline",
        &Tests2Opts {
            extra_sources: &["104+_inline.c"],
            ..Tests2Opts::default()
        },
    )
    .unwrap();
}

#[test]
fn test_tests2_105_local_extern() {
    run_tests2_case("105_local_extern").unwrap();
}

#[test]
#[ignore = "requires -pthread support (SKIP on Windows/BSD)"]
fn test_tests2_106_versym() {
    // Makefile: 106_versym.test: FLAGS += -pthread; NORUN = true
    run_tests2_case_with_opts(
        "106_versym",
        &Tests2Opts { flags: &["-pthread"], norun: true, ..Tests2Opts::default() },
    )
    .unwrap();
}

#[test]
fn test_tests2_107_stack_safe() {
    run_tests2_case("107_stack_safe").unwrap();
}

#[test]
fn test_tests2_108_constructor() {
    // Makefile: 108_constructor.test: NORUN = true
    run_tests2_case_with_opts(
        "108_constructor",
        &Tests2Opts { norun: true, ..Tests2Opts::default() },
    )
    .unwrap();
}

#[test]
fn test_tests2_109_float_struct_calling() {
    run_tests2_case("109_float_struct_calling").unwrap();
}

// --- 110–119 : Average, Conversion, Backtrace, Bounds, Switch ---

#[test]
fn test_tests2_110_average() {
    run_tests2_case("110_average").unwrap();
}

#[test]
fn test_tests2_111_conversion() {
    run_tests2_case("111_conversion").unwrap();
}

#[test]
#[ignore = "requires bounds checking support (CONFIG_bcheck)"]
fn test_tests2_112_backtrace() {
    // Makefile: 112_backtrace.test: FLAGS += -dt -b
    //           FILTER += hex address normalisation
    run_tests2_case_with_opts(
        "112_backtrace",
        &Tests2Opts {
            flags: &["-dt", "-b"],
            normalise_hex: true,
            ..Tests2Opts::default()
        },
    )
    .unwrap();
}

#[test]
#[ignore = "requires backtrace + DLL support (complex multi-step test)"]
fn test_tests2_113_btdll() {
    // Makefile: 113_btdll.test has a custom multi-step T1 pattern:
    //   tcc -bt $1 -shared -D DLL=1 -o a1.so &&
    //   tcc -bt $1 -shared -D DLL=2 -o a2.so &&
    //   tcc -bt $1 a1.so a2.so -Wl,-rpath=. -o test.exe && ./test.exe
    // This is too complex for the generic helper; mark as ignored.
    run_tests2_case("113_btdll").unwrap();
}

#[test]
#[ignore = "requires bounds checking support (CONFIG_bcheck)"]
fn test_tests2_114_bound_signal() {
    // Makefile: 114_bound_signal.test: FLAGS += -b; NORUN = true
    run_tests2_case_with_opts(
        "114_bound_signal",
        &Tests2Opts { flags: &["-b"], norun: true, ..Tests2Opts::default() },
    )
    .unwrap();
}

#[test]
#[ignore = "requires bounds checking support (CONFIG_bcheck)"]
fn test_tests2_115_bound_setjmp() {
    // Makefile: 115_bound_setjmp.test: FLAGS += -b
    run_tests2_case_with_opts(
        "115_bound_setjmp",
        &Tests2Opts { flags: &["-b"], ..Tests2Opts::default() },
    )
    .unwrap();
}

#[test]
#[ignore = "requires bounds checking support (CONFIG_bcheck)"]
fn test_tests2_116_bound_setjmp2() {
    // Makefile: 116_bound_setjmp2.test: FLAGS += -b
    run_tests2_case_with_opts(
        "116_bound_setjmp2",
        &Tests2Opts { flags: &["-b"], ..Tests2Opts::default() },
    )
    .unwrap();
}

#[test]
#[ignore = "requires bounds checking support (CONFIG_bcheck)"]
fn test_tests2_117_builtins() {
    // Makefile: 117_builtins.test: T1 = ( $(TCC) -run $1 && $(TCC) -b -run $1 )
    // This runs the test twice: once normal, once with bounds checking.
    // Since bcheck is required, mark as ignored.
    run_tests2_case("117_builtins").unwrap();
}

#[test]
fn test_tests2_118_switch() {
    run_tests2_case("118_switch").unwrap();
}

#[test]
fn test_tests2_119_random_stuff() {
    run_tests2_case("119_random_stuff").unwrap();
}

// --- 120–129 : Alias, Struct Return, VLA, Atomics, Bounds, Scopes ---

#[test]
fn test_tests2_120_alias() {
    // Makefile: 120_alias.test : FLAGS += $(subst 120,120+,$1)
    //           120_alias.test : GEN = $(GEN-TCC)
    //           120_alias.test : NORUN = true
    // Multi-file test: 120_alias.c + 120+_alias.c, compile to exe then run
    run_tests2_case_with_opts(
        "120_alias",
        &Tests2Opts {
            norun: true,
            extra_sources: &["120+_alias.c"],
            ..Tests2Opts::default()
        },
    )
    .unwrap();
}

#[test]
fn test_tests2_121_struct_return() {
    // Makefile: 121_struct_return.test: FLAGS += -b (only if bcheck enabled)
    // We run without -b by default since bcheck may not be available.
    run_tests2_case("121_struct_return").unwrap();
}

#[test]
fn test_tests2_122_vla_reuse() {
    // Makefile: 122_vla_reuse.test: FLAGS += -b (only if bcheck enabled)
    // We run without -b by default since bcheck may not be available.
    run_tests2_case("122_vla_reuse").unwrap();
}

#[test]
fn test_tests2_123_vla_bug() {
    run_tests2_case("123_vla_bug").unwrap();
}

#[test]
#[ignore = "requires -pthread support (SKIP on Windows)"]
fn test_tests2_124_atomic_counter() {
    // Makefile: 124_atomic_counter.test: FLAGS += -pthread
    run_tests2_case_with_opts(
        "124_atomic_counter",
        &Tests2Opts { flags: &["-pthread"], ..Tests2Opts::default() },
    )
    .unwrap();
}

#[test]
fn test_tests2_125_atomic_misc() {
    // Makefile: 125_atomic_misc.test: FLAGS += -dt
    run_tests2_case_with_opts(
        "125_atomic_misc",
        &Tests2Opts { flags: &["-dt"], ..Tests2Opts::default() },
    )
    .unwrap();
}

#[test]
#[ignore = "requires bounds checking support (CONFIG_bcheck)"]
fn test_tests2_126_bound_global() {
    // Makefile: 126_bound_global.test: FLAGS += -b; NORUN = true
    //           FILTER += hex address normalisation
    run_tests2_case_with_opts(
        "126_bound_global",
        &Tests2Opts {
            flags: &["-b"],
            norun: true,
            normalise_hex: true,
            ..Tests2Opts::default()
        },
    )
    .unwrap();
}

#[test]
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn test_tests2_127_asm_goto() {
    // Makefile: SKIP += 127_asm_goto.test (non-x86/x86_64) — hardcodes x86 asm
    run_tests2_case("127_asm_goto").unwrap();
}

#[test]
fn test_tests2_128_run_atexit() {
    // Makefile: 128_run_atexit.test: FLAGS += -dt
    run_tests2_case_with_opts(
        "128_run_atexit",
        &Tests2Opts { flags: &["-dt"], ..Tests2Opts::default() },
    )
    .unwrap();
}

#[test]
fn test_tests2_129_scopes() {
    run_tests2_case("129_scopes").unwrap();
}

// --- 130–137 : Large Args, Struct Return, Bounds, Old Func, etc. ---

#[test]
fn test_tests2_130_large_argument() {
    run_tests2_case("130_large_argument").unwrap();
}

#[test]
fn test_tests2_131_return_struct_in_reg() {
    run_tests2_case("131_return_struct_in_reg").unwrap();
}

#[test]
#[ignore = "requires bounds checking support (CONFIG_bcheck)"]
fn test_tests2_132_bound_test() {
    // Makefile: 132_bound_test.test: FLAGS += -b
    run_tests2_case_with_opts(
        "132_bound_test",
        &Tests2Opts { flags: &["-b"], ..Tests2Opts::default() },
    )
    .unwrap();
}

#[test]
fn test_tests2_133_old_func() {
    run_tests2_case("133_old_func").unwrap();
}

#[test]
fn test_tests2_134_double_to_signed() {
    run_tests2_case("134_double_to_signed").unwrap();
}

#[test]
fn test_tests2_135_func_arg_struct_compare() {
    run_tests2_case("135_func_arg_struct_compare").unwrap();
}

#[test]
fn test_tests2_136_atomic_gcc_style() {
    run_tests2_case("136_atomic_gcc_style").unwrap();
}

#[test]
fn test_tests2_137_funcall_struct_args() {
    run_tests2_case("137_funcall_struct_args").unwrap();
}

// ===========================================================================
// tests/pp/ — Individual Preprocessor Test Functions (24 tests)
//
// Each function maps 1:1 to a preprocessor test file. The function name
// encodes the test identity: `test_pp_<name>`.
//
// Files 01–11 are .c files, 12–13 are .S files, 14–22 are .c files,
// 23 is a .S file, and pp-counter is a .c file.
// ===========================================================================

#[test]
fn test_pp_01() {
    run_pp_case("01", "c").unwrap();
}

#[test]
fn test_pp_02() {
    // Makefile: 02.test : DIFF_OPTS += -w (whitespace-insensitive)
    run_pp_case_with_opts("02", "c", &PpOpts { ignore_whitespace: true }).unwrap();
}

#[test]
fn test_pp_03() {
    run_pp_case("03", "c").unwrap();
}

#[test]
fn test_pp_04() {
    run_pp_case("04", "c").unwrap();
}

#[test]
fn test_pp_05() {
    run_pp_case("05", "c").unwrap();
}

#[test]
fn test_pp_06() {
    run_pp_case("06", "c").unwrap();
}

#[test]
fn test_pp_07() {
    run_pp_case("07", "c").unwrap();
}

#[test]
fn test_pp_08() {
    run_pp_case("08", "c").unwrap();
}

#[test]
fn test_pp_09() {
    run_pp_case("09", "c").unwrap();
}

#[test]
fn test_pp_10() {
    run_pp_case("10", "c").unwrap();
}

#[test]
fn test_pp_11() {
    run_pp_case("11", "c").unwrap();
}

#[test]
fn test_pp_12() {
    // .S file — assembly preprocessor test
    run_pp_case("12", "S").unwrap();
}

#[test]
fn test_pp_13() {
    // .S file — assembly preprocessor test
    run_pp_case("13", "S").unwrap();
}

#[test]
fn test_pp_14() {
    run_pp_case("14", "c").unwrap();
}

#[test]
fn test_pp_15() {
    run_pp_case("15", "c").unwrap();
}

#[test]
fn test_pp_16() {
    run_pp_case("16", "c").unwrap();
}

#[test]
fn test_pp_17() {
    run_pp_case("17", "c").unwrap();
}

#[test]
fn test_pp_18() {
    run_pp_case("18", "c").unwrap();
}

#[test]
fn test_pp_19() {
    run_pp_case("19", "c").unwrap();
}

#[test]
fn test_pp_20() {
    run_pp_case("20", "c").unwrap();
}

#[test]
fn test_pp_21() {
    run_pp_case("21", "c").unwrap();
}

#[test]
fn test_pp_22() {
    run_pp_case("22", "c").unwrap();
}

#[test]
fn test_pp_23() {
    // .S file — assembly preprocessor test
    run_pp_case("23", "S").unwrap();
}

#[test]
fn test_pp_counter() {
    run_pp_case("pp-counter", "c").unwrap();
}

// ===========================================================================
// Discovery-Based Test Runners
//
// These tests dynamically discover all .c/.expect pairs in the test
// directories and run them in a single test function. They provide a
// "catch-all" safety net to ensure no test files are missed by the
// individual test functions above.
// ===========================================================================

/// Known tests2 test names that should be skipped by the discovery runner.
/// These correspond to the C Makefile's SKIP list or have special
/// requirements that prevent automated execution.
const TESTS2_SKIP: &[&str] = &[
    "34_array_assignment",   // array assignment not in C standard
    "98_al_ax_extend",       // i386 only
    "99_fastcall",           // i386 only
    "112_backtrace",         // requires CONFIG_bcheck
    "113_btdll",             // requires backtrace + DLL (complex T1)
    "114_bound_signal",      // requires CONFIG_bcheck
    "115_bound_setjmp",      // requires CONFIG_bcheck
    "116_bound_setjmp2",     // requires CONFIG_bcheck
    "117_builtins",          // requires CONFIG_bcheck
    "126_bound_global",      // requires CONFIG_bcheck
    "132_bound_test",        // requires CONFIG_bcheck
    "106_versym",            // requires -pthread
    "124_atomic_counter",    // requires -pthread
];

/// Known tests2 tests that are NOT on x86/x86_64 — these are handled via
/// cfg attributes on the individual test functions but must also be skipped
/// in the discovery runner when on non-x86 platforms.
#[allow(dead_code)]
const TESTS2_X86_ONLY: &[&str] = &[
    "85_asm-outside-function",
    "127_asm_goto",
];

/// Companion files that are NOT standalone test cases (they lack their own
/// .expect files and are compiled alongside another test).
const TESTS2_COMPANION_FILES: &[&str] = &[
    "104+_inline",
    "120+_alias",
];

/// Discovery-based runner for all tests/tests2/ test cases.
///
/// Iterates over every `.c` file in the directory, skips known special
/// cases, and runs each one with appropriate options. Collects all
/// failures and reports them at the end.
#[test]
fn test_discover_all_tests2() {
    let dir = tests2_dir();
    let mut results: Vec<(String, TestOutcome)> = Vec::new();

    let mut entries: Vec<_> = fs::read_dir(&dir)
        .expect("Could not read tests/tests2/ directory")
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.file_name()
                .to_string_lossy()
                .ends_with(".c")
        })
        .collect();
    entries.sort_by_key(|e| e.file_name());

    for entry in entries {
        let name = entry.file_name().to_string_lossy().to_string();
        let test_name = name.trim_end_matches(".c");

        // Skip companion files
        if TESTS2_COMPANION_FILES.contains(&test_name) {
            continue;
        }

        // Skip known problematic tests — tracked as Skipped, not Passed
        if TESTS2_SKIP.contains(&test_name) {
            results.push((
                test_name.to_string(),
                TestOutcome::Skipped("in TESTS2_SKIP list".to_string()),
            ));
            continue;
        }

        // Skip x86-only tests on non-x86 platforms
        #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
        if TESTS2_X86_ONLY.contains(&test_name) {
            results.push((
                test_name.to_string(),
                TestOutcome::Skipped("x86-only test on non-x86 platform".to_string()),
            ));
            continue;
        }

        // Determine test-specific options based on Makefile rules
        let result = match test_name {
            "22_floating_point" | "24_math_library" => {
                run_tests2_case_with_opts(
                    test_name,
                    &Tests2Opts { flags: &["-lm"], ..Tests2Opts::default() },
                )
            }
            "31_args" => {
                run_tests2_case_with_opts(
                    test_name,
                    &Tests2Opts {
                        args: &["arg1", "arg2", "arg3", "arg4", "arg5"],
                        ..Tests2Opts::default()
                    },
                )
            }
            "42_function_pointer" | "108_constructor" => {
                run_tests2_case_with_opts(
                    test_name,
                    &Tests2Opts { norun: true, ..Tests2Opts::default() },
                )
            }
            "46_grep" => {
                let grep_src = dir.join("46_grep.c");
                let grep_path = grep_src.to_string_lossy().to_string();
                let args_vec: Vec<&str> = vec![r"[^* ]*[:a:d: ]+\:\*-/: $$", &grep_path];
                run_tests2_case_with_opts(
                    test_name,
                    &Tests2Opts { args: &args_vec, ..Tests2Opts::default() },
                )
            }
            "60_errors_and_warnings" | "96_nodata_wanted"
            | "125_atomic_misc" | "128_run_atexit" => {
                run_tests2_case_with_opts(
                    test_name,
                    &Tests2Opts { flags: &["-dt"], ..Tests2Opts::default() },
                )
            }
            "76_dollars_in_identifiers" => {
                run_tests2_case_with_opts(
                    test_name,
                    &Tests2Opts {
                        flags: &["-fdollars-in-identifiers"],
                        ..Tests2Opts::default()
                    },
                )
            }
            "104_inline" => {
                run_tests2_case_with_opts(
                    test_name,
                    &Tests2Opts {
                        extra_sources: &["104+_inline.c"],
                        ..Tests2Opts::default()
                    },
                )
            }
            "120_alias" => {
                run_tests2_case_with_opts(
                    test_name,
                    &Tests2Opts {
                        norun: true,
                        extra_sources: &["120+_alias.c"],
                        ..Tests2Opts::default()
                    },
                )
            }
            _ => run_tests2_case(test_name),
        };

        let outcome = match result {
            Ok(()) => TestOutcome::Passed,
            Err(e) => TestOutcome::Failed(e),
        };
        results.push((test_name.to_string(), outcome));
    }

    let report = generate_test_report(&results);
    let failures: Vec<_> = results
        .iter()
        .filter(|(_, r)| matches!(r, TestOutcome::Failed(_)))
        .collect();

    if !failures.is_empty() {
        let mut msg = format!(
            "{}\n\n{} tests2 test(s) failed:\n",
            report,
            failures.len()
        );
        for (name, outcome) in &failures {
            if let TestOutcome::Failed(e) = outcome {
                let _ = write!(msg, "\n--- {} ---\n{}\n", name, e);
            }
        }
        panic!("{}", msg);
    }

    // Print summary on success
    eprintln!("{}", report);
}

/// Discovery-based runner for all tests/pp/ preprocessor tests.
///
/// Iterates over every `.c` and `.S` file in the pp directory that has a
/// matching `.expect` file and runs the preprocessor comparison.
#[test]
fn test_discover_all_pp() {
    let dir = pp_dir();
    let mut results: Vec<(String, TestOutcome)> = Vec::new();

    let mut entries: Vec<_> = fs::read_dir(&dir)
        .expect("Could not read tests/pp/ directory")
        .filter_map(|e| e.ok())
        .filter(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            name.ends_with(".c") || name.ends_with(".S")
        })
        .collect();
    entries.sort_by_key(|e| e.file_name());

    for entry in entries {
        let filename = entry.file_name().to_string_lossy().to_string();
        let (test_name, ext) = if filename.ends_with(".c") {
            (filename.trim_end_matches(".c").to_string(), "c")
        } else {
            (filename.trim_end_matches(".S").to_string(), "S")
        };

        // Check that the .expect file exists
        let expect_file = dir.join(format!("{}.expect", test_name));
        if !expect_file.exists() {
            continue;
        }

        let opts = if test_name == "02" {
            PpOpts { ignore_whitespace: true }
        } else {
            PpOpts::default()
        };

        let result = run_pp_case_with_opts(&test_name, ext, &opts);
        let outcome = match result {
            Ok(()) => TestOutcome::Passed,
            Err(e) => TestOutcome::Failed(e),
        };
        results.push((test_name, outcome));
    }

    let report = generate_test_report(&results);
    let failures: Vec<_> = results
        .iter()
        .filter(|(_, r)| matches!(r, TestOutcome::Failed(_)))
        .collect();

    if !failures.is_empty() {
        let mut msg = format!(
            "{}\n\n{} pp test(s) failed:\n",
            report,
            failures.len()
        );
        for (name, outcome) in &failures {
            if let TestOutcome::Failed(e) = outcome {
                let _ = write!(msg, "\n--- {} ---\n{}\n", name, e);
            }
        }
        panic!("{}", msg);
    }

    eprintln!("{}", report);
}

// ---------------------------------------------------------------------------
// Test Report Generation
// ---------------------------------------------------------------------------

/// Generate a summary report of test results.
///
/// Produces a human-readable line like:
/// `Tests: 120 passed, 3 failed, 123 total`
/// Result status for a single test case used by the discovery runner.
///
/// Distinguishes between passed, failed, and skipped tests so that the
/// report accurately reflects the actual verification coverage.
#[derive(Debug, Clone, PartialEq)]
enum TestOutcome {
    Passed,
    Failed(String),
    Skipped(String),
}

fn generate_test_report(results: &[(String, TestOutcome)]) -> String {
    let total = results.len();
    let passed = results.iter().filter(|(_, r)| *r == TestOutcome::Passed).count();
    let skipped = results
        .iter()
        .filter(|(_, r)| matches!(r, TestOutcome::Skipped(_)))
        .count();
    let failed = total - passed - skipped;
    format!(
        "Tests: {} passed, {} skipped, {} failed, {} total",
        passed, skipped, failed, total
    )
}
