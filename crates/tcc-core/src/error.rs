//! Error types module for the TCC Rust compiler pipeline.
//!
//! This module defines the [`TccError`] enum, [`TccResult`] type alias, and diagnostic
//! support types that replace TCC's C-based `setjmp`/`longjmp` error recovery mechanism
//! (see BUG-16 in the TODO file). By leveraging Rust's `Result<T, E>` with the `?` operator
//! and RAII-based resource cleanup, all memory leak risks on error paths are eliminated.
//!
//! # C-to-Rust Error Pattern Mapping
//!
//! | C Pattern | Rust Equivalent |
//! |-----------|-----------------|
//! | `tcc_error(fmt, ...)` | `return Err(TccError::parse(file, line, format!(...)))` |
//! | `tcc_warning(fmt, ...)` | Push [`Diagnostic`] to warning list, continue |
//! | `tcc_error_noabort(fmt, ...)` | Increment error count, accumulate into [`TccError::MultipleErrors`] |
//! | `expect(msg)` | `return Err(TccError::parse(file, line, format!("'{}' expected", msg)))` |
//! | `longjmp(s1->error_jmp_buf, 1)` | Eliminated — `?` operator propagates `Err` up the call stack |
//!
//! # Error Categories
//!
//! The [`TccError`] enum covers every phase of the compiler pipeline:
//! - **Lexer**: Invalid characters, unterminated strings/comments, malformed numeric literals
//! - **Preprocessor**: Missing include files, macro expansion failures, `#error` directives
//! - **Parser**: Syntax errors, type mismatches, declaration errors, semantic violations
//! - **Code Generator**: Register allocation failures, unsupported target operations
//! - **Assembler**: Invalid instructions, bad operands, undefined labels
//! - **Linker**: Undefined symbols, relocation overflows, format errors
//! - **I/O**: File not found, permission denied, read/write failures
//! - **Configuration**: Invalid CLI options, incompatible settings
//! - **Internal**: Compiler bugs that should never occur in correct usage
//! - **Multiple**: Accumulated errors during a single compilation pass

use thiserror::Error;

/// Comprehensive error type for the TCC compiler pipeline.
///
/// Each variant carries structured context (file name, line number, message) to produce
/// diagnostics that match the original C compiler's error output format:
/// `<file>:<line>: error: <message>`.
///
/// The `#[from]` attribute on [`IoError`](TccError::IoError) enables automatic conversion
/// from [`std::io::Error`] via the `?` operator, so all file I/O operations propagate
/// errors ergonomically without manual mapping.
///
/// # Examples
///
/// ```
/// use tcc_core::error::{TccError, TccResult};
///
/// fn compile_file(path: &str) -> TccResult<()> {
///     // I/O errors are automatically converted via From<std::io::Error>
///     let _contents = std::fs::read_to_string(path)?;
///
///     // Pipeline errors use the ergonomic constructor helpers
///     if path.is_empty() {
///         return Err(TccError::config("empty source file path"));
///     }
///     Ok(())
/// }
/// ```
#[derive(Error, Debug)]
pub enum TccError {
    /// Lexer errors: invalid characters, unterminated strings/comments, malformed numbers.
    ///
    /// Produced during the character-scanning phase when the input cannot be tokenized.
    /// Carries the source file name and line number where the error was detected.
    #[error("{file}:{line}: error: {message}")]
    LexerError {
        /// Source file path where the error occurred.
        file: String,
        /// Line number (1-based) where the error was detected.
        line: u32,
        /// Human-readable description of the lexer error.
        message: String,
    },

    /// Preprocessor errors: include not found, macro errors, `#error` directive.
    ///
    /// Produced during macro expansion, include resolution, and conditional compilation.
    /// Maps to the C `tcc_error()` calls within `tccpp.c`.
    #[error("{file}:{line}: error: {message}")]
    PreprocessorError {
        /// Source file path where the error occurred.
        file: String,
        /// Line number (1-based) where the error was detected.
        line: u32,
        /// Human-readable description of the preprocessor error.
        message: String,
    },

    /// Parse errors: syntax errors, type errors, declaration errors.
    ///
    /// Produced during expression parsing, statement parsing, declaration parsing,
    /// and type checking. This is the most common error type, corresponding to the
    /// majority of `tcc_error()` calls in the original `tccgen.c`.
    #[error("{file}:{line}: error: {message}")]
    ParseError {
        /// Source file path where the error occurred.
        file: String,
        /// Line number (1-based) where the error was detected.
        line: u32,
        /// Human-readable description of the parse error.
        message: String,
    },

    /// Code generation errors: register allocation failure, unsupported operation.
    ///
    /// Produced when the code generator encounters a construct it cannot translate
    /// to target machine code. Unlike lexer/parser errors, codegen errors typically
    /// do not carry a specific file/line since the code generator works on an
    /// intermediate representation level.
    #[error("error: {message}")]
    CodegenError {
        /// Human-readable description of the code generation error.
        message: String,
    },

    /// Linker errors: undefined symbols, relocation failures, format errors.
    ///
    /// Produced during symbol resolution, relocation processing, and output file
    /// generation. Maps to error paths in the original `tccelf.c`, `tccpe.c`,
    /// and `tccmacho.c`.
    #[error("error: {message}")]
    LinkerError {
        /// Human-readable description of the linker error.
        message: String,
    },

    /// Assembler errors: invalid instruction, bad operand, undefined label.
    ///
    /// Produced during inline assembly processing or standalone assembler mode.
    /// Maps to error paths in `tccasm.c` and the architecture-specific `*-asm.c` files.
    #[error("{file}:{line}: error: {message}")]
    AsmError {
        /// Source file path where the error occurred.
        file: String,
        /// Line number (1-based) where the error was detected.
        line: u32,
        /// Human-readable description of the assembler error.
        message: String,
    },

    /// I/O errors: file not found, permission denied, read/write failures.
    ///
    /// Wraps [`std::io::Error`] with automatic conversion via the `#[from]` attribute.
    /// This enables the `?` operator to propagate I/O errors from any file operation
    /// (open, read, write, seek) directly into the TCC error pipeline.
    #[error("error: {0}")]
    IoError(#[from] std::io::Error),

    /// Configuration errors: invalid options, incompatible settings.
    ///
    /// Produced when CLI option parsing or compiler configuration detects invalid
    /// or contradictory settings (e.g., incompatible target/output combinations,
    /// invalid `-std` values, or missing required paths).
    #[error("error: {message}")]
    ConfigError {
        /// Human-readable description of the configuration error.
        message: String,
    },

    /// Internal compiler error: should not happen in correct usage.
    ///
    /// Indicates a bug in the compiler itself rather than an error in user code.
    /// These errors should be reported to the TCC developers. In the original C
    /// codebase, these correspond to `tcc_error("internal compiler error")` calls.
    #[error("internal compiler error: {message}")]
    InternalError {
        /// Human-readable description of the internal error.
        message: String,
    },

    /// Multiple errors accumulated during compilation.
    ///
    /// Maps to the C pattern of incrementing `nb_errors` via `_tcc_error_noabort()`
    /// and continuing compilation to report as many errors as possible in a single
    /// pass. The collected errors are stored for post-compilation reporting.
    #[error("{count} error(s) during compilation")]
    MultipleErrors {
        /// Total number of errors detected.
        count: u32,
        /// Individual errors accumulated during compilation.
        errors: Vec<TccError>,
    },
}

/// Standard `Result` type alias for all TCC operations.
///
/// Every fallible function in the compiler pipeline returns `TccResult<T>` instead
/// of raw integer return codes or `setjmp`/`longjmp` error recovery. This enables
/// idiomatic Rust error propagation with the `?` operator.
///
/// # Examples
///
/// ```
/// use tcc_core::error::{TccError, TccResult};
///
/// fn add_include_path(path: &str) -> TccResult<()> {
///     if path.is_empty() {
///         return Err(TccError::config("include path cannot be empty"));
///     }
///     Ok(())
/// }
/// ```
pub type TccResult<T> = Result<T, TccError>;

/// Warning level for compiler diagnostics.
///
/// Controls how individual warning categories are handled. Maps to the C codebase's
/// `WARN_ON`, `WARN_ERR`, and `WARN_NOE` bit flags (see `libtcc.c` line 614-616).
///
/// - `Off` — Warning is suppressed (e.g., `-Wno-<option>`)
/// - `On` — Warning is emitted as a warning (e.g., `-W<option>`)
/// - `Error` — Warning is promoted to an error (e.g., `-Werror=<option>`)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WarningLevel {
    /// Warning is disabled — no diagnostic is emitted.
    /// Corresponds to the absence of `WARN_ON` in the C flags.
    Off,
    /// Warning is enabled — a warning diagnostic is emitted but compilation continues.
    /// Corresponds to `WARN_ON` (bit 0x1) in the C flags.
    On,
    /// Warning is promoted to an error — compilation is halted.
    /// Corresponds to `WARN_ERR` (bit 0x2) in the C flags, or the global `-Werror` flag.
    Error,
}

impl WarningLevel {
    /// Returns `true` if this warning level will produce a diagnostic (either warning or error).
    ///
    /// # Examples
    ///
    /// ```
    /// use tcc_core::error::WarningLevel;
    ///
    /// assert!(!WarningLevel::Off.is_active());
    /// assert!(WarningLevel::On.is_active());
    /// assert!(WarningLevel::Error.is_active());
    /// ```
    #[inline]
    pub fn is_active(self) -> bool {
        !matches!(self, WarningLevel::Off)
    }

    /// Returns `true` if this warning level will cause compilation failure.
    ///
    /// # Examples
    ///
    /// ```
    /// use tcc_core::error::WarningLevel;
    ///
    /// assert!(!WarningLevel::Off.is_error());
    /// assert!(!WarningLevel::On.is_error());
    /// assert!(WarningLevel::Error.is_error());
    /// ```
    #[inline]
    pub fn is_error(self) -> bool {
        matches!(self, WarningLevel::Error)
    }
}

impl Default for WarningLevel {
    /// The default warning level is [`WarningLevel::Off`].
    #[inline]
    fn default() -> Self {
        WarningLevel::Off
    }
}

/// Severity level for a compiler diagnostic.
///
/// Used by [`Diagnostic`] to classify messages. Maps to the C codebase's
/// `ERROR_WARN`, `ERROR_NOABORT`, and `ERROR_ERROR` modes in `error1()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DiagnosticLevel {
    /// Informational note — provides additional context for an error or warning.
    Note,
    /// Warning — potential issue that does not prevent compilation.
    Warning,
    /// Error — compilation failure.
    Error,
}

impl DiagnosticLevel {
    /// Returns the display prefix string for this diagnostic level.
    ///
    /// Matches the C codebase's format: `"warning: "` for warnings, `"error: "` for errors,
    /// and `"note: "` for notes (see `error1()` in `libtcc.c` line 669).
    #[inline]
    pub fn as_prefix(&self) -> &'static str {
        match self {
            DiagnosticLevel::Note => "note: ",
            DiagnosticLevel::Warning => "warning: ",
            DiagnosticLevel::Error => "error: ",
        }
    }
}

impl std::fmt::Display for DiagnosticLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DiagnosticLevel::Note => f.write_str("note"),
            DiagnosticLevel::Warning => f.write_str("warning"),
            DiagnosticLevel::Error => f.write_str("error"),
        }
    }
}

/// A compiler diagnostic message (warning, error, or note).
///
/// Captures the complete context needed to format a diagnostic in the standard
/// compiler output format: `<file>:<line>:<column>: <level>: <message>`.
///
/// In the C codebase, diagnostics are formatted inline by `error1()` (see `libtcc.c`
/// line 621). The Rust port separates collection from formatting, allowing diagnostics
/// to be accumulated, filtered, and displayed after compilation.
///
/// # Examples
///
/// ```
/// use tcc_core::error::{Diagnostic, DiagnosticLevel};
///
/// let diag = Diagnostic::warning("test.c", 42, 10, "unused variable 'x'");
/// assert_eq!(diag.level, DiagnosticLevel::Warning);
/// assert_eq!(format!("{}", diag), "test.c:42:10: warning: unused variable 'x'");
/// ```
#[derive(Debug, Clone)]
pub struct Diagnostic {
    /// Severity level of this diagnostic.
    pub level: DiagnosticLevel,
    /// Source file path where the diagnostic was generated.
    pub file: String,
    /// Line number (1-based) in the source file.
    pub line: u32,
    /// Column number (1-based) in the source line. Set to 0 when column is unknown.
    pub column: u32,
    /// Human-readable diagnostic message.
    pub message: String,
}

impl Diagnostic {
    /// Create a new diagnostic with the specified level and location.
    ///
    /// This is the general-purpose constructor. For common cases, prefer the
    /// convenience constructors [`warning()`](Self::warning), [`error()`](Self::error),
    /// or [`note()`](Self::note).
    pub fn new(
        level: DiagnosticLevel,
        file: impl Into<String>,
        line: u32,
        column: u32,
        message: impl Into<String>,
    ) -> Self {
        Diagnostic {
            level,
            file: file.into(),
            line,
            column,
            message: message.into(),
        }
    }

    /// Create a warning diagnostic at the specified location.
    ///
    /// Maps to `tcc_warning()` calls in the C codebase.
    pub fn warning(
        file: impl Into<String>,
        line: u32,
        column: u32,
        message: impl Into<String>,
    ) -> Self {
        Self::new(DiagnosticLevel::Warning, file, line, column, message)
    }

    /// Create an error diagnostic at the specified location.
    ///
    /// Maps to `tcc_error_noabort()` calls in the C codebase (errors that
    /// increment `nb_errors` but allow continued compilation for multi-error reporting).
    pub fn error(
        file: impl Into<String>,
        line: u32,
        column: u32,
        message: impl Into<String>,
    ) -> Self {
        Self::new(DiagnosticLevel::Error, file, line, column, message)
    }

    /// Create a note diagnostic at the specified location.
    ///
    /// Notes provide supplementary context for a preceding error or warning
    /// (e.g., "in expansion of macro 'FOO'" or "previous definition was here").
    pub fn note(
        file: impl Into<String>,
        line: u32,
        column: u32,
        message: impl Into<String>,
    ) -> Self {
        Self::new(DiagnosticLevel::Note, file, line, column, message)
    }

    /// Returns `true` if this diagnostic represents an error.
    #[inline]
    pub fn is_error(&self) -> bool {
        self.level == DiagnosticLevel::Error
    }

    /// Returns `true` if this diagnostic represents a warning.
    #[inline]
    pub fn is_warning(&self) -> bool {
        self.level == DiagnosticLevel::Warning
    }
}

impl std::fmt::Display for Diagnostic {
    /// Formats the diagnostic in the standard compiler output format:
    /// `<file>:<line>:<column>: <level>: <message>`
    ///
    /// When the column is 0 (unknown), the column component is omitted:
    /// `<file>:<line>: <level>: <message>`
    ///
    /// This matches the output format of the original C `error1()` function.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.column > 0 {
            write!(
                f,
                "{}:{}:{}: {}: {}",
                self.file, self.line, self.column, self.level, self.message
            )
        } else {
            write!(
                f,
                "{}:{}: {}: {}",
                self.file, self.line, self.level, self.message
            )
        }
    }
}

// ---------------------------------------------------------------------------
// Ergonomic helper constructors for TccError
// ---------------------------------------------------------------------------

impl TccError {
    /// Create a lexer error at the specified source location.
    ///
    /// # Arguments
    /// * `file` — Source file path
    /// * `line` — Line number (1-based)
    /// * `msg` — Error description (accepts `&str`, `String`, or anything `Into<String>`)
    ///
    /// # Examples
    ///
    /// ```
    /// use tcc_core::error::TccError;
    ///
    /// let err = TccError::lexer("input.c", 10, "unterminated string literal");
    /// assert!(format!("{}", err).contains("unterminated string literal"));
    /// ```
    pub fn lexer(file: impl Into<String>, line: u32, msg: impl Into<String>) -> Self {
        TccError::LexerError {
            file: file.into(),
            line,
            message: msg.into(),
        }
    }

    /// Create a preprocessor error at the specified source location.
    ///
    /// # Arguments
    /// * `file` — Source file path
    /// * `line` — Line number (1-based)
    /// * `msg` — Error description
    ///
    /// # Examples
    ///
    /// ```
    /// use tcc_core::error::TccError;
    ///
    /// let err = TccError::preprocessor("input.c", 5, "include file 'missing.h' not found");
    /// assert!(format!("{}", err).contains("missing.h"));
    /// ```
    pub fn preprocessor(file: impl Into<String>, line: u32, msg: impl Into<String>) -> Self {
        TccError::PreprocessorError {
            file: file.into(),
            line,
            message: msg.into(),
        }
    }

    /// Create a parse error at the specified source location.
    ///
    /// This is the most commonly used error constructor, corresponding to the
    /// majority of `tcc_error()` calls in the original `tccgen.c`.
    ///
    /// # Arguments
    /// * `file` — Source file path
    /// * `line` — Line number (1-based)
    /// * `msg` — Error description
    ///
    /// # Examples
    ///
    /// ```
    /// use tcc_core::error::TccError;
    ///
    /// let err = TccError::parse("input.c", 42, "';' expected");
    /// assert!(format!("{}", err).contains("';' expected"));
    /// ```
    pub fn parse(file: impl Into<String>, line: u32, msg: impl Into<String>) -> Self {
        TccError::ParseError {
            file: file.into(),
            line,
            message: msg.into(),
        }
    }

    /// Create a linker error.
    ///
    /// Linker errors typically do not carry file/line information since they occur
    /// after source parsing, during symbol resolution and relocation processing.
    ///
    /// # Arguments
    /// * `msg` — Error description
    ///
    /// # Examples
    ///
    /// ```
    /// use tcc_core::error::TccError;
    ///
    /// let err = TccError::linker("undefined symbol: 'main'");
    /// assert!(format!("{}", err).contains("undefined symbol"));
    /// ```
    pub fn linker(msg: impl Into<String>) -> Self {
        TccError::LinkerError {
            message: msg.into(),
        }
    }

    /// Create a code generation error.
    ///
    /// Code generation errors occur when the backend encounters a construct it
    /// cannot translate to target machine code (e.g., unsupported operation on
    /// the target architecture).
    ///
    /// # Arguments
    /// * `msg` — Error description
    ///
    /// # Examples
    ///
    /// ```
    /// use tcc_core::error::TccError;
    ///
    /// let err = TccError::codegen("register allocation failed: no free registers");
    /// assert!(format!("{}", err).contains("register allocation"));
    /// ```
    pub fn codegen(msg: impl Into<String>) -> Self {
        TccError::CodegenError {
            message: msg.into(),
        }
    }

    /// Create an assembler error at the specified source location.
    ///
    /// # Arguments
    /// * `file` — Source file path
    /// * `line` — Line number (1-based)
    /// * `msg` — Error description
    ///
    /// # Examples
    ///
    /// ```
    /// use tcc_core::error::TccError;
    ///
    /// let err = TccError::asm("input.S", 20, "invalid instruction: 'movzx'");
    /// assert!(format!("{}", err).contains("invalid instruction"));
    /// ```
    pub fn asm(file: impl Into<String>, line: u32, msg: impl Into<String>) -> Self {
        TccError::AsmError {
            file: file.into(),
            line,
            message: msg.into(),
        }
    }

    /// Create a configuration error.
    ///
    /// Configuration errors occur during CLI option processing or when compiler
    /// settings are incompatible.
    ///
    /// # Arguments
    /// * `msg` — Error description
    ///
    /// # Examples
    ///
    /// ```
    /// use tcc_core::error::TccError;
    ///
    /// let err = TccError::config("unsupported output type for this target");
    /// assert!(format!("{}", err).contains("unsupported output type"));
    /// ```
    pub fn config(msg: impl Into<String>) -> Self {
        TccError::ConfigError {
            message: msg.into(),
        }
    }

    /// Create an internal compiler error.
    ///
    /// Internal errors indicate a bug in the compiler itself. They should never
    /// occur during normal usage and should be reported to the developers.
    ///
    /// # Arguments
    /// * `msg` — Error description
    ///
    /// # Examples
    ///
    /// ```
    /// use tcc_core::error::TccError;
    ///
    /// let err = TccError::internal("unexpected empty value stack");
    /// assert!(format!("{}", err).contains("internal compiler error"));
    /// ```
    pub fn internal(msg: impl Into<String>) -> Self {
        TccError::InternalError {
            message: msg.into(),
        }
    }

    /// Create a multiple-errors container from a collection of errors.
    ///
    /// Used when compilation continues past the first error to accumulate all
    /// discovered issues for a comprehensive error report. Maps to the C pattern
    /// of `_tcc_error_noabort()` incrementing `nb_errors` and continuing.
    ///
    /// # Arguments
    /// * `errors` — Vector of individual errors
    ///
    /// # Panics
    /// Debug-asserts that the errors vector is non-empty.
    pub fn multiple(errors: Vec<TccError>) -> Self {
        debug_assert!(!errors.is_empty(), "MultipleErrors should contain at least one error");
        let count = errors.len() as u32;
        TccError::MultipleErrors { count, errors }
    }

    /// Returns `true` if this error is an internal compiler error.
    ///
    /// Internal errors indicate bugs in the compiler rather than user code errors.
    #[inline]
    pub fn is_internal(&self) -> bool {
        matches!(self, TccError::InternalError { .. })
    }

    /// Returns `true` if this error is an I/O error.
    #[inline]
    pub fn is_io(&self) -> bool {
        matches!(self, TccError::IoError(_))
    }

    /// Returns the source file associated with this error, if any.
    ///
    /// Not all error variants carry source location information (e.g., [`CodegenError`],
    /// [`LinkerError`], [`ConfigError`], [`InternalError`], and [`IoError`] do not).
    pub fn file(&self) -> Option<&str> {
        match self {
            TccError::LexerError { file, .. }
            | TccError::PreprocessorError { file, .. }
            | TccError::ParseError { file, .. }
            | TccError::AsmError { file, .. } => Some(file.as_str()),
            _ => None,
        }
    }

    /// Returns the line number associated with this error, if any.
    ///
    /// Only errors with source location information carry a line number.
    pub fn line(&self) -> Option<u32> {
        match self {
            TccError::LexerError { line, .. }
            | TccError::PreprocessorError { line, .. }
            | TccError::ParseError { line, .. }
            | TccError::AsmError { line, .. } => Some(*line),
            _ => None,
        }
    }

    /// Returns the error message for any variant.
    ///
    /// For [`IoError`], returns the underlying I/O error's display string.
    /// For [`MultipleErrors`], returns the summary string.
    pub fn message(&self) -> String {
        match self {
            TccError::LexerError { message, .. }
            | TccError::PreprocessorError { message, .. }
            | TccError::ParseError { message, .. }
            | TccError::CodegenError { message, .. }
            | TccError::LinkerError { message, .. }
            | TccError::AsmError { message, .. }
            | TccError::ConfigError { message, .. }
            | TccError::InternalError { message, .. } => message.clone(),
            TccError::IoError(e) => e.to_string(),
            TccError::MultipleErrors { count, .. } => {
                format!("{} error(s) during compilation", count)
            }
        }
    }

    /// Returns the total number of individual errors represented.
    ///
    /// For [`MultipleErrors`], returns the count field.
    /// For all other variants, returns 1.
    pub fn error_count(&self) -> u32 {
        match self {
            TccError::MultipleErrors { count, .. } => *count,
            _ => 1,
        }
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ---- TccError variant construction ----

    #[test]
    fn test_lexer_error_creation() {
        let err = TccError::lexer("test.c", 10, "unterminated string");
        match &err {
            TccError::LexerError { file, line, message } => {
                assert_eq!(file, "test.c");
                assert_eq!(*line, 10);
                assert_eq!(message, "unterminated string");
            }
            _ => panic!("expected LexerError"),
        }
        assert_eq!(format!("{}", err), "test.c:10: error: unterminated string");
    }

    #[test]
    fn test_preprocessor_error_creation() {
        let err = TccError::preprocessor("header.h", 5, "#error stop");
        match &err {
            TccError::PreprocessorError { file, line, message } => {
                assert_eq!(file, "header.h");
                assert_eq!(*line, 5);
                assert_eq!(message, "#error stop");
            }
            _ => panic!("expected PreprocessorError"),
        }
        assert_eq!(format!("{}", err), "header.h:5: error: #error stop");
    }

    #[test]
    fn test_parse_error_creation() {
        let err = TccError::parse("main.c", 42, "';' expected");
        match &err {
            TccError::ParseError { file, line, message } => {
                assert_eq!(file, "main.c");
                assert_eq!(*line, 42);
                assert_eq!(message, "';' expected");
            }
            _ => panic!("expected ParseError"),
        }
        assert_eq!(format!("{}", err), "main.c:42: error: ';' expected");
    }

    #[test]
    fn test_codegen_error_creation() {
        let err = TccError::codegen("register allocation failed");
        match &err {
            TccError::CodegenError { message } => {
                assert_eq!(message, "register allocation failed");
            }
            _ => panic!("expected CodegenError"),
        }
        assert_eq!(format!("{}", err), "error: register allocation failed");
    }

    #[test]
    fn test_linker_error_creation() {
        let err = TccError::linker("undefined symbol: 'main'");
        match &err {
            TccError::LinkerError { message } => {
                assert_eq!(message, "undefined symbol: 'main'");
            }
            _ => panic!("expected LinkerError"),
        }
        assert_eq!(format!("{}", err), "error: undefined symbol: 'main'");
    }

    #[test]
    fn test_asm_error_creation() {
        let err = TccError::asm("input.S", 15, "invalid opcode");
        match &err {
            TccError::AsmError { file, line, message } => {
                assert_eq!(file, "input.S");
                assert_eq!(*line, 15);
                assert_eq!(message, "invalid opcode");
            }
            _ => panic!("expected AsmError"),
        }
        assert_eq!(format!("{}", err), "input.S:15: error: invalid opcode");
    }

    #[test]
    fn test_config_error_creation() {
        let err = TccError::config("invalid output type");
        match &err {
            TccError::ConfigError { message } => {
                assert_eq!(message, "invalid output type");
            }
            _ => panic!("expected ConfigError"),
        }
        assert_eq!(format!("{}", err), "error: invalid output type");
    }

    #[test]
    fn test_internal_error_creation() {
        let err = TccError::internal("empty value stack");
        match &err {
            TccError::InternalError { message } => {
                assert_eq!(message, "empty value stack");
            }
            _ => panic!("expected InternalError"),
        }
        assert_eq!(
            format!("{}", err),
            "internal compiler error: empty value stack"
        );
    }

    #[test]
    fn test_io_error_from_conversion() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let tcc_err: TccError = io_err.into();
        assert!(tcc_err.is_io());
        assert!(format!("{}", tcc_err).contains("file not found"));
    }

    #[test]
    fn test_multiple_errors_creation() {
        let errors = vec![
            TccError::parse("a.c", 1, "error one"),
            TccError::parse("b.c", 2, "error two"),
            TccError::linker("undefined symbol"),
        ];
        let err = TccError::multiple(errors);
        match &err {
            TccError::MultipleErrors { count, errors } => {
                assert_eq!(*count, 3);
                assert_eq!(errors.len(), 3);
            }
            _ => panic!("expected MultipleErrors"),
        }
        assert_eq!(format!("{}", err), "3 error(s) during compilation");
    }

    // ---- TccError accessor methods ----

    #[test]
    fn test_error_file_accessor() {
        assert_eq!(TccError::lexer("a.c", 1, "x").file(), Some("a.c"));
        assert_eq!(TccError::preprocessor("b.h", 2, "y").file(), Some("b.h"));
        assert_eq!(TccError::parse("c.c", 3, "z").file(), Some("c.c"));
        assert_eq!(TccError::asm("d.S", 4, "w").file(), Some("d.S"));
        assert_eq!(TccError::codegen("x").file(), None);
        assert_eq!(TccError::linker("x").file(), None);
        assert_eq!(TccError::config("x").file(), None);
        assert_eq!(TccError::internal("x").file(), None);
    }

    #[test]
    fn test_error_line_accessor() {
        assert_eq!(TccError::lexer("a.c", 10, "x").line(), Some(10));
        assert_eq!(TccError::preprocessor("b.h", 20, "y").line(), Some(20));
        assert_eq!(TccError::parse("c.c", 30, "z").line(), Some(30));
        assert_eq!(TccError::asm("d.S", 40, "w").line(), Some(40));
        assert_eq!(TccError::codegen("x").line(), None);
        assert_eq!(TccError::linker("x").line(), None);
    }

    #[test]
    fn test_error_message_accessor() {
        assert_eq!(TccError::lexer("a.c", 1, "msg1").message(), "msg1");
        assert_eq!(TccError::codegen("msg2").message(), "msg2");
        assert_eq!(TccError::linker("msg3").message(), "msg3");
        assert_eq!(TccError::config("msg4").message(), "msg4");
        assert_eq!(TccError::internal("msg5").message(), "msg5");
    }

    #[test]
    fn test_error_count() {
        assert_eq!(TccError::parse("a.c", 1, "x").error_count(), 1);
        assert_eq!(TccError::codegen("x").error_count(), 1);
        let multi = TccError::multiple(vec![
            TccError::parse("a.c", 1, "x"),
            TccError::parse("b.c", 2, "y"),
        ]);
        assert_eq!(multi.error_count(), 2);
    }

    #[test]
    fn test_is_internal() {
        assert!(TccError::internal("bug").is_internal());
        assert!(!TccError::parse("a.c", 1, "x").is_internal());
    }

    #[test]
    fn test_is_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::Other, "test");
        let tcc_err: TccError = io_err.into();
        assert!(tcc_err.is_io());
        assert!(!TccError::config("x").is_io());
    }

    // ---- TccResult usage ----

    #[test]
    fn test_tcc_result_ok() {
        let result: TccResult<i32> = Ok(42);
        assert_eq!(result.unwrap(), 42);
    }

    #[test]
    fn test_tcc_result_err() {
        let result: TccResult<i32> = Err(TccError::parse("test.c", 1, "error"));
        assert!(result.is_err());
    }

    #[test]
    fn test_tcc_result_question_mark_operator() {
        fn inner() -> TccResult<()> {
            let _data = std::fs::read("/nonexistent/path/that/does/not/exist")?;
            Ok(())
        }
        let result = inner();
        assert!(result.is_err());
        assert!(result.unwrap_err().is_io());
    }

    // ---- WarningLevel ----

    #[test]
    fn test_warning_level_is_active() {
        assert!(!WarningLevel::Off.is_active());
        assert!(WarningLevel::On.is_active());
        assert!(WarningLevel::Error.is_active());
    }

    #[test]
    fn test_warning_level_is_error() {
        assert!(!WarningLevel::Off.is_error());
        assert!(!WarningLevel::On.is_error());
        assert!(WarningLevel::Error.is_error());
    }

    #[test]
    fn test_warning_level_default() {
        assert_eq!(WarningLevel::default(), WarningLevel::Off);
    }

    #[test]
    fn test_warning_level_equality() {
        assert_eq!(WarningLevel::On, WarningLevel::On);
        assert_ne!(WarningLevel::On, WarningLevel::Off);
        assert_ne!(WarningLevel::On, WarningLevel::Error);
    }

    #[test]
    fn test_warning_level_clone_copy() {
        let level = WarningLevel::Error;
        let cloned = level;
        assert_eq!(level, cloned);
    }

    // ---- DiagnosticLevel ----

    #[test]
    fn test_diagnostic_level_display() {
        assert_eq!(format!("{}", DiagnosticLevel::Warning), "warning");
        assert_eq!(format!("{}", DiagnosticLevel::Error), "error");
        assert_eq!(format!("{}", DiagnosticLevel::Note), "note");
    }

    #[test]
    fn test_diagnostic_level_prefix() {
        assert_eq!(DiagnosticLevel::Warning.as_prefix(), "warning: ");
        assert_eq!(DiagnosticLevel::Error.as_prefix(), "error: ");
        assert_eq!(DiagnosticLevel::Note.as_prefix(), "note: ");
    }

    // ---- Diagnostic ----

    #[test]
    fn test_diagnostic_warning_constructor() {
        let diag = Diagnostic::warning("test.c", 10, 5, "unused variable");
        assert_eq!(diag.level, DiagnosticLevel::Warning);
        assert_eq!(diag.file, "test.c");
        assert_eq!(diag.line, 10);
        assert_eq!(diag.column, 5);
        assert_eq!(diag.message, "unused variable");
    }

    #[test]
    fn test_diagnostic_error_constructor() {
        let diag = Diagnostic::error("test.c", 20, 1, "type mismatch");
        assert_eq!(diag.level, DiagnosticLevel::Error);
        assert!(diag.is_error());
        assert!(!diag.is_warning());
    }

    #[test]
    fn test_diagnostic_note_constructor() {
        let diag = Diagnostic::note("test.c", 15, 0, "previous definition here");
        assert_eq!(diag.level, DiagnosticLevel::Note);
        assert!(!diag.is_error());
        assert!(!diag.is_warning());
    }

    #[test]
    fn test_diagnostic_display_with_column() {
        let diag = Diagnostic::warning("test.c", 42, 10, "implicit conversion");
        assert_eq!(
            format!("{}", diag),
            "test.c:42:10: warning: implicit conversion"
        );
    }

    #[test]
    fn test_diagnostic_display_without_column() {
        let diag = Diagnostic::error("test.c", 42, 0, "syntax error");
        assert_eq!(format!("{}", diag), "test.c:42: error: syntax error");
    }

    #[test]
    fn test_diagnostic_clone() {
        let diag = Diagnostic::warning("test.c", 1, 1, "msg");
        let cloned = diag.clone();
        assert_eq!(cloned.file, "test.c");
        assert_eq!(cloned.message, "msg");
    }

    // ---- Error trait implementation ----

    #[test]
    fn test_error_trait_source_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "not found");
        let tcc_err: TccError = io_err.into();
        // Verify the error source chain works via std::error::Error
        let source = std::error::Error::source(&tcc_err);
        assert!(source.is_some());
    }

    #[test]
    fn test_error_trait_source_non_io() {
        let err = TccError::parse("a.c", 1, "test");
        let source = std::error::Error::source(&err);
        assert!(source.is_none());
    }

    #[test]
    fn test_debug_format() {
        let err = TccError::lexer("test.c", 1, "bad char");
        let debug_str = format!("{:?}", err);
        assert!(debug_str.contains("LexerError"));
        assert!(debug_str.contains("test.c"));
        assert!(debug_str.contains("bad char"));
    }
}
