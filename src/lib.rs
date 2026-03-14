//! # tinycc-rs
//!
//! A memory-safe Rust port of Tiny C Compiler (TCC) v0.9.28rc.
//!
//! This crate provides a complete C99 compiler as both a library and CLI tool.
//! The 22-function libtcc API is preserved as methods on [`TccContext`].
//!
//! ## Overview
//!
//! The original `TinyCC` is a fast, lightweight C compiler written in C. This crate
//! is a ground-up translation into idiomatic, memory-safe Rust (2021 edition) that
//! preserves behavioral equivalence while eliminating four known CVEs
//! (CVE-2018-20376, CVE-2018-20374, CVE-2019-9754, CVE-2006-0635) by construction
//! through Rust's type system and ownership model.
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use tcc::{TccContext, OutputType, TccResult};
//!
//! fn compile_hello() -> TccResult<()> {
//!     let mut ctx = TccContext::new()?;
//!     ctx.set_output_type(OutputType::Executable)?;
//!     ctx.compile_string(r#"
//!         #include <stdio.h>
//!         int main() { printf("Hello from TCC!\n"); return 0; }
//!     "#)?;
//!     ctx.output_file("hello")?;
//!     Ok(())
//! }
//! ```
//!
//! ## Public API
//!
//! The public API consists of:
//! - [`TccContext`] — The primary compilation handle (replaces C `TCCState*`)
//! - [`TccError`] — Error types for all compiler operations
//! - [`TccResult`] — Result type alias used by all fallible methods
//! - [`OutputType`] — Enum specifying compilation output format
//!
//! ## Safety
//!
//! This crate contains `unsafe` code **only** in [`runtime`] for platform syscalls
//! (`mprotect`, `VirtualProtect`, `mmap`). All other modules are 100% safe Rust.
//! Each `unsafe` block includes a `// SAFETY:` justification comment.

// =============================================================================
// Crate-Level Lint Configuration
// =============================================================================
//
// Integer safety lints — MANDATORY per AAP §0.8.1 "Integer Safety"
// These prevent implicit integer coercions that caused CVE-2006-0635
// in the original C codebase.
#![deny(clippy::cast_sign_loss)]
#![deny(clippy::cast_possible_truncation)]
#![deny(clippy::cast_possible_wrap)]
// General quality lints — MANDATORY per AAP §0.6.2 "Clippy Lints"
#![warn(clippy::all)]
#![warn(clippy::pedantic)]
// Allow dead code during incremental module development — types, structs, and
// functions are defined ahead of their callers across multiple build phases.
// This will be removed once all modules are fully connected.
#![allow(dead_code)]
// Allow module name repetitions for public re-exports (e.g., error::TccError)
#![allow(clippy::module_name_repetitions)]

// =============================================================================
// Module Declarations
// =============================================================================
//
// All modules are declared per the target architecture in AAP §0.4.1.
// Module visibility follows AAP §0.4.3: public API modules are `pub`,
// internal implementation modules are `pub(crate)`.

/// Error types for the `TinyCC` compiler.
///
/// Defines [`TccError`] enum and [`TccResult`] type alias used throughout
/// the crate for structured error propagation replacing C `setjmp`/`longjmp`.
///
/// C equivalent: Error paths through `tcc_error()`, `tcc_error_noabort()`,
/// and `tcc_warning()` in `libtcc.c`.
pub mod error;

/// Compiler context and public API handle.
///
/// Contains [`TccContext`] (public API) wrapping [`TccState`](context::TccState)
/// (internal state). Provides the 22-method libtcc-compatible API.
///
/// C equivalent: `TCCState` struct in `tcc.h` lines 738–1020 and the
/// 22 public API functions in `libtcc.c`.
pub mod context;

/// Token definitions for the TCC lexer.
///
/// Defines the [`Token`](tokens::Token) enum covering all TCC token types
/// and associated constants (`TOK_*`, `VT_*`).
///
/// C equivalent: `tcctok.h` (430 lines) and token definitions in `tcc.h`.
pub(crate) mod tokens;

/// Shared type definitions from the monolithic `tcc.h` header.
///
/// Contains Rust equivalents of C types: `CType`, `CValue`, `SValue`,
/// `Section`, `Symbol`, `SourceFile`, `TokenString`, `CachedInclude`, etc.
///
/// C equivalent: Struct definitions in `tcc.h`.
pub(crate) mod types;

/// Preprocessor — tokenizer, macro expansion, include caching, directives.
///
/// Implements the C preprocessor with CVE-2019-9754 remediation: the macro
/// expansion stack uses `Vec<MacroEntry>` with checked `pop()` instead of
/// a raw pointer linked list.
///
/// C equivalent: `tccpp.c` (4,005 lines).
pub(crate) mod preprocessor;

/// Recursive-descent parser (single-pass architecture).
///
/// Preserves `TinyCC`'s fundamental design: parser emits code directly to the
/// backend via codegen functions — no intermediate AST. Includes CVE-2006-0635
/// remediation through explicit `TryInto` conversions for all signed/unsigned
/// comparisons.
///
/// C equivalent: Parser functions from `tccgen.c` (8,920 lines).
pub(crate) mod parser;

/// Value stack, code emission, and constant folding.
///
/// Manages the value stack as `Vec<SValue>` (replacing C fixed-size array)
/// and emits code through the `CodegenBackend` trait.
///
/// C equivalent: Codegen functions from `tccgen.c` (8,920 lines).
pub(crate) mod codegen;

/// GAS-style assembler and inline assembly support.
///
/// Includes CVE-2018-20376 remediation (directive buffer as `Vec<u8>`) and
/// CVE-2018-20374 remediation (section array as `Vec<Section>` with checked
/// indexing).
///
/// C equivalent: `tccasm.c` (1,466 lines).
pub(crate) mod assembler;

/// STABS and DWARF debug information generation, code coverage hooks.
///
/// Uses the `gimli` crate (v0.28 with `write` feature) for DWARF generation
/// and implements STABS generation for legacy debug info support.
///
/// C equivalent: `tccdbg.c` (2,676 lines).
pub(crate) mod debug;

/// Runtime engine — W^X enforcement, in-memory execution, signal handlers.
///
/// This is the **only** module permitted to contain `unsafe` blocks, used
/// exclusively for platform syscalls (`mprotect`, `VirtualProtect`, `mmap`).
/// Each `unsafe` block includes a `// SAFETY:` justification comment.
///
/// C equivalent: `tccrun.c` (1,556 lines).
pub(crate) mod runtime;

/// Utility tools — archiver, dependency generator, impdef.
///
/// Provides `tcc -ar` (archiver), `-MD`/`-MF` (dependency generation),
/// and `-impdef` (Windows import definition extraction) tool implementations.
///
/// C equivalent: `tcctools.c` (651 lines).
pub mod tools;

/// Linker backends — ELF, PE/COFF, Mach-O, and COFF output.
///
/// Contains submodules for each output format:
/// - `elf` — ELF object/executable/shared library
/// - `pe` — Windows PE/COFF DLL and EXE
/// - `macho` — macOS Mach-O executable/dylib
/// - `coff` — COFF output for C67 target
///
/// C equivalent: `tccelf.c`, `tccpe.c`, `tccmacho.c`, `tcccoff.c`.
pub(crate) mod linker;

/// Architecture-specific code generation backends.
///
/// Defines the `CodegenBackend` trait and provides implementations for
/// i386, x86_64, ARM, AArch64, RISC-V 64, and TMS320C67 architectures.
///
/// C equivalent: `{arch}-gen.c`, `{arch}-asm.c`, `{arch}-link.c` files.
pub(crate) mod targets;

/// Runtime library components — bounds checking, builtins, coverage, etc.
///
/// Contains Rust implementations of TCC's runtime library (`lib/` directory):
/// bounds checking, 64-bit arithmetic helpers, code coverage, backtrace,
/// compiler builtins, constructor/destructor handling, and more.
///
/// C equivalent: `lib/*.c` and `lib/*.S` (18 files, 8,319 lines).
pub(crate) mod runtime_lib;

/// Binary format structure definitions — ELF, DWARF, COFF, STABS.
///
/// Contains `#[repr(C)]` struct definitions and constants for binary
/// format headers used by the linker backends.
///
/// C equivalent: `elf.h`, `dwarf.h`, `coff.h`, `stab.h`/`stab.def`.
pub(crate) mod formats;

// =============================================================================
// Public API Re-exports
// =============================================================================
//
// The crate's public surface re-exports the primary types from their
// defining modules. Users access these via `use tcc::{TccContext, ...}`.
// This matches the C pattern where `libtcc.h` is the single public header.

/// Re-export the primary compilation context handle.
///
/// [`TccContext`] is the main entry point for library users, providing
/// the 22-method API equivalent to the C `libtcc.h` functions.
///
/// C equivalent: `TCCState*` opaque pointer returned by `tcc_new()`.
pub use context::TccContext;

/// Re-export the output type enum for compilation mode selection.
///
/// [`OutputType`] specifies whether to compile to memory, executable,
/// object file, dynamic library, or preprocessor-only output.
///
/// C equivalent: `TCC_OUTPUT_MEMORY`, `TCC_OUTPUT_EXE`, `TCC_OUTPUT_OBJ`,
/// `TCC_OUTPUT_DLL`, `TCC_OUTPUT_PREPROCESS` constants in `libtcc.h`
/// lines 68–72.
pub use context::OutputType;

/// Re-export the error types for the compiler.
///
/// [`TccError`] provides structured error variants (`Parse`, `Link`, `Io`,
/// `UnsupportedTarget`) replacing the C `setjmp`/`longjmp` error handling.
///
/// [`TccResult`] is the `Result<T, TccError>` type alias used by all
/// fallible public API methods.
pub use error::{TccError, TccResult};
