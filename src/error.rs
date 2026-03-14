// Copyright (c) 2024 tinycc-rs contributors
// SPDX-License-Identifier: MIT OR LGPL-2.1-or-later
//
// Error types for the TinyCC Rust compiler.
//
// This module defines the crate-wide error enum (`TccError`) and result type
// alias (`TccResult<T>`), replacing the C error-handling pattern of
// `setjmp`/`longjmp` (used in `error1()` at libtcc.c:621-690) with
// structured error propagation via `Result` + the `?` operator.
//
// The four error variants cover every failure mode in the compiler:
//   - `Parse`  — lexer, preprocessor, parser, and code-generation errors
//   - `Link`   — linker, relocation, and symbol-resolution errors
//   - `Io`     — file-system and I/O errors (wraps `std::io::Error`)
//   - `UnsupportedTarget` — missing or feature-gated architecture backends
//
// C equivalents replaced:
//   - `tcc_error()` / `_tcc_error()` (libtcc.c:711)         → `Err(TccError::*)`
//   - `tcc_error_noabort()` / `_tcc_error_noabort()` (libtcc.c:701) → `Err(TccError::*)`
//   - `tcc_warning()` / `_tcc_warning()` (libtcc.c:720)     → diagnostic callback (not an error)
//   - `longjmp(s1->error_jmp_buf, 1)` (libtcc.c:690)        → `?` operator propagation

use std::num::TryFromIntError;
use thiserror::Error;

/// Error types produced by the `TinyCC` Rust compiler.
///
/// Every fallible operation in the compiler returns [`TccResult<T>`], which
/// uses this enum as its error type.  The variants are designed so that each
/// C error path maps to exactly one variant:
///
/// | C call-site pattern              | Rust variant              |
/// |----------------------------------|---------------------------|
/// | `tcc_error("parse …")`           | [`TccError::Parse`]       |
/// | `tcc_error("undefined symbol …")`| [`TccError::Link`]        |
/// | `fopen` failure / errno          | [`TccError::Io`]          |
/// | unsupported `-m` flag            | [`TccError::UnsupportedTarget`] |
///
/// # CVE Remediation
///
/// The `From<TryFromIntError>` implementation on this type is part of the
/// **CVE-2006-0635** remediation.  In the original C code, implicit
/// signed-to-unsigned integer promotion caused incorrect comparisons
/// (e.g. `i > sizeof(int)` when `i == -1`).  In Rust, all such comparisons
/// use explicit `TryInto` conversions, and integer-overflow errors are
/// captured as [`TccError::Parse`] via the blanket `From` impl below.
///
/// # Examples
///
/// ```rust,ignore
/// use tcc::{TccContext, TccResult};
///
/// fn compile(src: &str) -> TccResult<()> {
///     let mut ctx = TccContext::new()?;
///     ctx.compile_string(src)?;   // returns TccError::Parse on syntax error
///     ctx.relocate()?;            // returns TccError::Link on unresolved symbol
///     Ok(())
/// }
/// ```
#[derive(Debug, Error)]
pub enum TccError {
    /// Parse or compilation error — syntax errors, type mismatches,
    /// macro-expansion failures, code-generation errors, etc.
    ///
    /// The `file` and `line` fields reproduce the `"file:line: error: msg"`
    /// diagnostic format used by the original C `error1()` function
    /// (libtcc.c:621).
    ///
    /// C equivalent: calls to `tcc_error()` and `tcc_error_noabort()` from
    /// `tccpp.c`, `tccgen.c`, and `tccasm.c`.
    #[error("parse error in {file}:{line}: {msg}")]
    Parse {
        /// Human-readable error message.
        msg: String,
        /// Source line number where the error was detected (0 if unknown).
        line: u32,
        /// Source file path where the error was detected (empty if unknown).
        file: String,
    },

    /// Linker error — unresolved symbols, duplicate definitions, relocation
    /// failures, section format errors, archive corruption, etc.
    ///
    /// C equivalent: calls to `tcc_error()` from `tccelf.c`, `tccpe.c`,
    /// `tccmacho.c`, and `tcccoff.c`.
    #[error("link error: {0}")]
    Link(String),

    /// I/O error — file not found, permission denied, disk full, etc.
    ///
    /// This variant wraps [`std::io::Error`] and supports seamless conversion
    /// via the `?` operator thanks to the `#[from]` attribute.
    ///
    /// C equivalent: `fopen` / `fread` / `fwrite` failure paths that called
    /// `tcc_error("could not read '%s'", filename)`.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Unsupported target architecture or feature.
    ///
    /// Returned when a Cargo feature gate prevents a backend from being
    /// compiled in (e.g. requesting ARM code generation when only the
    /// `x86_64` feature is enabled), or when a platform-specific operation
    /// is attempted on an unsupported host.
    ///
    /// C equivalent: compile-time `#ifdef TCC_TARGET_*` exclusions that
    /// become runtime checks in the Rust port.
    #[error("unsupported target: {0}")]
    UnsupportedTarget(String),
}

// ---------------------------------------------------------------------------
// Blanket conversions
// ---------------------------------------------------------------------------

/// Convert integer-conversion errors into [`TccError::Parse`].
///
/// This implementation is a direct consequence of the **CVE-2006-0635**
/// remediation strategy.  In the original C code, comparisons like
/// `i > sizeof(int)` silently promoted the signed `int` value to `unsigned`,
/// making `-1` compare as a very large positive number.  In the Rust port,
/// every such comparison uses an explicit `TryInto` conversion; if the
/// conversion fails (e.g. a negative value cannot be represented as `usize`),
/// the resulting `TryFromIntError` is automatically converted into a parse
/// error via this `From` impl.
///
/// # CVE-2006-0635
///
/// The crate-level `#![deny(clippy::cast_sign_loss)]` lint gate (in
/// `src/lib.rs`) prevents any future code from reintroducing implicit
/// signed-to-unsigned casts, and this conversion catches the remaining
/// runtime edge cases.
// CVE-2006-0635: Explicit TryFrom prevents implicit signed/unsigned coercion
impl From<TryFromIntError> for TccError {
    fn from(err: TryFromIntError) -> Self {
        TccError::Parse {
            msg: format!("integer conversion error: {err}"),
            line: 0,
            file: String::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Result type alias
// ---------------------------------------------------------------------------

/// Result type alias for TCC operations.
///
/// All public API functions on [`crate::context::TccContext`] and most
/// internal helpers return `TccResult<T>`.  The `#[must_use]` attribute
/// ensures that callers never silently ignore a compilation or linking error.
///
/// C equivalent: replaces all `setjmp` / `longjmp` error-recovery paths
/// and the `-1` return-value convention used by `tcc_error_noabort()`.
///
/// # Examples
///
/// ```rust,ignore
/// fn add_files(ctx: &mut TccContext, paths: &[&str]) -> TccResult<()> {
///     for p in paths {
///         ctx.add_file(p)?;   // ? propagates TccError automatically
///     }
///     Ok(())
/// }
/// ```
///
/// # Note
///
/// `Result<T, E>` is already `#[must_use]` in the standard library, so
/// callers that ignore a `TccResult` value will receive a compiler warning
/// automatically.  Individual functions may add their own `#[must_use]`
/// annotations for extra emphasis.
pub type TccResult<T> = Result<T, TccError>;

// ---------------------------------------------------------------------------
// Convenience constructors (crate-internal helpers)
// ---------------------------------------------------------------------------

// Allow dead_code on convenience constructors — these are pub(crate) helpers
// consumed by context.rs, preprocessor.rs, parser.rs, assembler.rs, linker/,
// and other crate modules that are created by concurrent agents.
#[allow(dead_code)]
impl TccError {
    /// Create a [`TccError::Parse`] with only a message (unknown location).
    ///
    /// This is a convenience helper used throughout the crate when a parse
    /// error is detected but the exact file/line context is not immediately
    /// available.  Callers that *do* have location information should
    /// construct the variant directly.
    #[inline]
    pub(crate) fn parse(msg: impl Into<String>) -> Self {
        TccError::Parse {
            msg: msg.into(),
            line: 0,
            file: String::new(),
        }
    }

    /// Create a [`TccError::Parse`] with full location context.
    ///
    /// Mirrors the `"file:line: error: msg"` format produced by the
    /// original C `error1()` function (libtcc.c:621).
    #[inline]
    pub(crate) fn parse_at(msg: impl Into<String>, line: u32, file: impl Into<String>) -> Self {
        TccError::Parse {
            msg: msg.into(),
            line,
            file: file.into(),
        }
    }

    /// Create a [`TccError::Link`] from any string-like value.
    #[inline]
    pub(crate) fn link(msg: impl Into<String>) -> Self {
        TccError::Link(msg.into())
    }

    /// Create a [`TccError::UnsupportedTarget`] from any string-like value.
    #[inline]
    pub(crate) fn unsupported(target: impl Into<String>) -> Self {
        TccError::UnsupportedTarget(target.into())
    }
}
