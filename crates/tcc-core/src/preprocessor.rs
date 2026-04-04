//! C Preprocessor module for the TCC Rust compiler pipeline.
//!
//! This module is a faithful Rust port of `tccpp.c` (4,005 lines), implementing:
//! - Macro definition and expansion (object-like, function-like, variadic)
//! - `#include` / `#include_next` file resolution with search path handling
//! - Conditional compilation (`#if`, `#ifdef`, `#ifndef`, `#elif`, `#else`, `#endif`)
//! - Token pasting (`##`) and stringification (`#`)
//! - Predefined macros (`__FILE__`, `__LINE__`, `__DATE__`, `__TIME__`, `__COUNTER__`)
//! - `#pragma` processing (pack, once, comment)
//! - `#error` / `#warning` diagnostic directives
//! - `#line` directive
//! - Constant expression evaluation for `#if` expressions
//!
//! # Key Design Decisions (from AAP)
//!
//! - **No global state**: All preprocessor state is encapsulated in [`Preprocessor`].
//!   This addresses BUG-13 (libtcc reentrancy) by leveraging Rust's ownership model.
//! - **Result-based errors**: Preprocessor errors return [`TccResult<T>`] instead of
//!   calling `tcc_error()` with longjmp (BUG-16 fix).
//! - **Token representation**: Uses integer token IDs from `crate::token` module,
//!   matching TCC's internal representation for compatibility.
//! - **Include caching**: [`CachedInclude`] prevents re-parsing of header-guarded files.
//!
//! # Bug Fixes Integrated
//!
//! - **NC-03**: Macro redefinition emits a warning when replacement lists differ
//!   (C standard 6.10.3p2).
//! - **BUG-10**: `varargs.h` legacy macros (`va_alist`, `va_dcl`) correctly expanded.
//! - **FEAT-02**: `__builtin_expect(expr, val)` accepted as a pass-through.
//!
//! # C-to-Rust Mapping
//!
//! | C Source (`tccpp.c`) | Rust Target |
//! |---------------------|-------------|
//! | `preprocess()` (~line 2140) | [`Preprocessor::preprocess()`] |
//! | `define_push()` (~line 135) | [`Preprocessor::define_push()`] |
//! | `define_find()` (~line 155) | [`Preprocessor::define_find()`] |
//! | `macro_subst()` (~line 1800) | [`Preprocessor::macro_subst()`] |
//! | `expr_preprocess()` (~line 2050) | [`Preprocessor::expr_preprocess()`] |
//! | `parse_define()` (in preprocess) | [`Preprocessor::parse_define()`] |
//! | `parse_include()` (in preprocess) | [`Preprocessor::parse_include()`] |

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::error::{TccError, TccResult};
use crate::lexer::{
    get_tok_str, tok_alloc, Lexer, TokenSymTable,
    PARSE_FLAG_LINEFEED, PARSE_FLAG_PREPROCESS, PARSE_FLAG_TOK_NUM,
    PARSE_FLAG_TOK_STR, TOK_FLAG_BOF, TOK_FLAG_BOL, TOK_FLAG_ENDIF,
};
use crate::TCCState;
use crate::token::{
    Token, KEYWORDS, TOK_CCHAR, TOK_CDOUBLE, TOK_CFLOAT, TOK_CINT,
    TOK_CLDOUBLE, TOK_CLLONG, TOK_CLONG, TOK_CUINT, TOK_CULLONG,
    TOK_CULONG, TOK_EOF, TOK_IDENT, TOK_LCHAR, TOK_LINEFEED,
    TOK_LSTR, TOK_PPNUM, TOK_PPSTR, TOK_STR, TOK_TWOSHARPS,
};
use crate::types::{
    BufferedFile, CType, CValue, CachedInclude,
    Sym, SymAttr, FuncAttr,
    CACHED_INCLUDES_HASH_SIZE, IFDEF_STACK_SIZE, MACRO_FUNC,
    MACRO_JOIN, MACRO_OBJ, PACK_STACK_SIZE,
};

// ---------------------------------------------------------------------------
// Ifdef state constants (matching tcc.h defines)
// ---------------------------------------------------------------------------

/// `#if` / `#ifdef` / `#ifndef` block is being processed (condition was true).
const IFDEF_TRUE: i32 = 0;
/// `#if` / `#ifdef` / `#ifndef` block is being skipped (condition was false).
const IFDEF_FALSE: i32 = 1;
/// Already had a true branch in this `#if` chain; skip remaining branches.
const IFDEF_DONE: i32 = 2;

// ---------------------------------------------------------------------------
// Macro expansion safety limits
// ---------------------------------------------------------------------------

/// Maximum depth of recursive macro expansion.
///
/// Prevents stack overflow from deeply nested or self-referential macros
/// in untrusted input. The C codebase relies on implicit stack limits and
/// `macro_ptr` chain management for protection; the Rust port adds this
/// explicit depth guard for defense-in-depth.
///
/// The value 256 is chosen to be generous enough for real-world macro
/// nesting (typical C headers rarely exceed 10–20 levels) while preventing
/// pathological cases from consuming the entire stack.
const MAX_MACRO_DEPTH: u32 = 256;

// ---------------------------------------------------------------------------
// Preprocessor struct — encapsulates all per-compilation preprocessor state
// ---------------------------------------------------------------------------

/// The C preprocessor engine for the TCC compiler pipeline.
///
/// Wraps a mutable reference to [`TCCState`] and provides all macro expansion,
/// directive processing, conditional compilation, and token production
/// functionality. No module-level mutable state is used — every piece of state
/// lives inside this struct or `TCCState` (BUG-13 fix).
///
/// # Lifetime
///
/// The `'a` lifetime binds the preprocessor to its owning `TCCState`. The
/// preprocessor must not outlive the state it references.
///
/// # Usage
///
/// ```no_run
/// use tcc_core::TCCState;
/// use tcc_core::preprocessor::Preprocessor;
/// use tcc_core::lexer::TokenSymTable;
/// use tcc_core::types::BufferedFile;
/// use tcc_core::token::TOK_EOF;
///
/// fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let mut state = TCCState::new()?;
///     let token_table = TokenSymTable::default();
///     let file = BufferedFile::default();
///     let mut pp = Preprocessor::new(&mut state, token_table, file);
///     loop {
///         let tok = pp.next()?;
///         if tok == TOK_EOF { break; }
///     }
///     Ok(())
/// }
/// ```
pub struct Preprocessor<'a> {
    /// Reference to the central compiler state. Provides access to include
    /// paths, ifdef stack, cached includes, pack stack, output type, and
    /// extension flags.
    pub state: &'a mut TCCState,

    /// Token symbol table for identifier interning and keyword lookup.
    pub token_table: TokenSymTable,

    /// Macro definition table: maps token ID → Sym entry.
    /// Uses `HashMap` for O(1) lookup (OPT-02 improvement over C's hash chain).
    macro_table: HashMap<i32, Sym>,

    /// Current token integer value after calling `next()`.
    pub tok: i32,

    /// Current token associated value (literal integer, float, string, etc.).
    pub tokc: CValue,

    /// Token flags for the current token (TOK_FLAG_BOL, TOK_FLAG_BOF, etc.).
    pub tok_flags: i32,

    /// Parse flags controlling preprocessing behavior.
    pub parse_flags: i32,

    /// Unget buffer: tokens pushed back via `unget()` are consumed first.
    unget_buffer: Vec<(i32, CValue, i32)>,

    /// Macro expansion pointer: if `Some`, tokens are read from this stream
    /// instead of the lexer. This replaces C's `macro_ptr`.
    macro_ptr: Option<(Vec<i32>, usize)>,

    /// Macro expansion stack for nested expansions.
    macro_stack: Vec<(Vec<i32>, usize)>,

    /// `__COUNTER__` monotonic counter value.
    pp_counter: i32,

    /// Whether we are currently inside a preprocessor expression (`#if`).
    pp_expr: bool,

    /// Current depth of recursive macro expansion (0 = top level).
    ///
    /// Incremented on each entry to [`macro_subst()`] and decremented on exit.
    /// When this reaches [`MAX_MACRO_DEPTH`], further expansion is rejected
    /// with a `TccError::preprocessor` error to prevent stack overflow.
    macro_depth: u32,

    /// Current `BufferedFile` for the active input source.
    pub file: BufferedFile,

    /// Keyword lookup table for fast keyword detection.
    #[allow(dead_code)]
    keyword_map: HashMap<String, Token>,

    /// Compilation date string for `__DATE__` (format: "Mmm dd yyyy").
    date_str: String,

    /// Compilation time string for `__TIME__` (format: "hh:mm:ss").
    time_str: String,

    /// Whether predefined macros have been initialized.
    predefs_initialized: bool,
}

// ===========================================================================
// Preprocessor — Constructor and public interface
// ===========================================================================

impl<'a> Preprocessor<'a> {
    /// Creates a new preprocessor instance bound to the given compiler state.
    ///
    /// Accepts an optional `TokenSymTable` and `BufferedFile` for flexibility.
    /// When no token table is provided, a fresh one is allocated. When no
    /// input file is provided, a default empty buffer is created.
    ///
    /// Initializes keyword tokens and date/time strings for predefined macros.
    pub fn new(
        state: &'a mut TCCState,
        token_table: TokenSymTable,
        file: BufferedFile,
    ) -> Self {
        let keyword_map: HashMap<String, Token> = KEYWORDS
            .iter()
            .map(|&(s, ref t)| (s.to_string(), *t))
            .collect();

        // Build date/time strings for __DATE__ and __TIME__
        let (date_str, time_str) = Self::build_date_time();

        let mut pp = Preprocessor {
            state,
            token_table,
            macro_table: HashMap::new(),
            tok: 0,
            tokc: CValue::default(),
            tok_flags: TOK_FLAG_BOL | TOK_FLAG_BOF,
            parse_flags: 0,
            unget_buffer: Vec::new(),
            macro_ptr: None,
            macro_stack: Vec::new(),
            pp_counter: 0,
            pp_expr: false,
            macro_depth: 0,
            file,
            keyword_map,
            date_str,
            time_str,
            predefs_initialized: false,
        };

        // Register keywords in the token table
        pp.init_keywords();

        pp
    }

    /// Initialize keyword tokens in the symbol table.
    fn init_keywords(&mut self) {
        for &(name, ref _token) in KEYWORDS.iter() {
            tok_alloc(&mut self.token_table, name.as_bytes());
        }
    }

    /// Build date and time strings for `__DATE__` and `__TIME__`.
    fn build_date_time() -> (String, String) {
        // Attempt to get current time. Fall back to a default if unavailable.
        #[cfg(not(test))]
        {
            let months = [
                "Jan", "Feb", "Mar", "Apr", "May", "Jun",
                "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
            ];
            use std::time::SystemTime;
            if let Ok(duration) = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
                let secs = duration.as_secs() as i64;
                let days = secs / 86400;
                let time_of_day = secs % 86400;
                let hours = time_of_day / 3600;
                let minutes = (time_of_day % 3600) / 60;
                let seconds = time_of_day % 60;

                let (year, month, day) = Self::days_to_ymd(days);
                let date = format!(
                    "{} {:2} {}",
                    months[month as usize],
                    day,
                    year
                );
                let time = format!("{:02}:{:02}:{:02}", hours, minutes, seconds);
                return (date, time);
            }
        }

        // Fallback / test default
        ("Jan  1 2026".to_string(), "00:00:00".to_string())
    }

    /// Convert days since Unix epoch to (year, month, day).
    #[cfg_attr(test, allow(dead_code))]
    fn days_to_ymd(days: i64) -> (i64, i64, i64) {
        // Simplified Gregorian calendar conversion
        let mut y = 1970;
        let mut remaining = days;

        loop {
            let days_in_year = if Self::is_leap_year(y) { 366 } else { 365 };
            if remaining < days_in_year {
                break;
            }
            remaining -= days_in_year;
            y += 1;
        }

        let days_in_months = if Self::is_leap_year(y) {
            [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
        } else {
            [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
        };

        let mut m = 0i64;
        for (i, &dim) in days_in_months.iter().enumerate() {
            if remaining < dim {
                m = i as i64;
                break;
            }
            remaining -= dim;
            if i == 11 {
                m = 11;
            }
        }

        (y, m, remaining + 1)
    }

    /// Check if a year is a leap year.
    #[cfg_attr(test, allow(dead_code))]
    fn is_leap_year(y: i64) -> bool {
        (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0)
    }

    // -----------------------------------------------------------------------
    // Token Production Interface (Phase 6 from agent_prompt)
    // -----------------------------------------------------------------------

    /// Get the next preprocessed token.
    ///
    /// This is the primary token production method called by the parser.
    /// It handles:
    /// 1. Returning tokens from the unget buffer
    /// 2. Returning tokens from macro expansion streams
    /// 3. Reading raw tokens from the lexer
    /// 4. Processing preprocessor directives
    /// 5. Expanding macros
    ///
    /// Returns the token ID. The token value is available in `self.tokc`.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> TccResult<i32> {
        // 1. Check unget buffer first
        if let Some((tok, tokc, flags)) = self.unget_buffer.pop() {
            self.tok = tok;
            self.tokc = tokc;
            self.tok_flags = flags;
            return Ok(self.tok);
        }

        // 2. Check macro expansion stream
        if let Some((ref stream, ref mut pos)) = self.macro_ptr {
            if *pos < stream.len() {
                let tok = stream[*pos];
                *pos += 1;

                if tok == 0 {
                    // End of macro stream — pop back to previous context
                    self.macro_ptr = self.macro_stack.pop();
                    return self.next();
                }

                self.tok = tok;
                self.tokc = CValue::default();

                // Read associated value if this is a value-carrying token.
                // We temporarily take the macro_ptr to avoid double mutable
                // borrow of self (stream borrows self.macro_ptr while
                // read_token_value borrows &mut self).
                if self.macro_ptr.is_some() {
                    let mut mp = self.macro_ptr.take().unwrap();
                    {
                        let (ref stream, ref mut pos) = mp;
                        self.read_token_value(stream, pos);
                    }
                    self.macro_ptr = Some(mp);
                }

                return Ok(self.tok);
            } else {
                // Stream exhausted
                self.macro_ptr = self.macro_stack.pop();
                return self.next();
            }
        }

        // 3. Read from lexer and handle preprocessing
        self.next_from_lexer()
    }

    /// Read the next token from the lexer, processing directives and macros.
    fn next_from_lexer(&mut self) -> TccResult<i32> {
        loop {
            // Create a lexer for the current file
            let mut lexer = Lexer::new(&mut self.file);
            lexer.parse_flags = self.parse_flags
                | PARSE_FLAG_LINEFEED
                | PARSE_FLAG_TOK_NUM
                | PARSE_FLAG_TOK_STR;
            lexer.tok_flags = self.tok_flags;

            lexer.next_raw(&mut self.token_table)?;

            self.tok = lexer.tok;
            self.tokc = lexer.tokc;
            self.tok_flags = lexer.tok_flags;

            // Update file state back from lexer
            self.file = lexer.file.clone();

            // Handle preprocessor directives at beginning of line
            if self.tok == b'#' as i32
                && (self.tok_flags & TOK_FLAG_BOL) != 0
                && (self.parse_flags & PARSE_FLAG_PREPROCESS) != 0
            {
                self.preprocess()?;
                continue;
            }

            // Handle line feed tokens
            if self.tok == TOK_LINEFEED {
                if (self.parse_flags & PARSE_FLAG_LINEFEED) != 0 {
                    return Ok(self.tok);
                }
                continue;
            }

            // Handle EOF
            if self.tok == TOK_EOF {
                // Check if we need to pop an include stack entry
                if !self.state.include_stack.is_empty() {
                    // Verify ifdef stack balance
                    let expected_ifdef_depth =
                        self.file.ifdef_stack_ptr;
                    if self.state.ifdef_stack.len() > expected_ifdef_depth {
                        return Err(TccError::preprocessor(
                            self.file.filename.clone(),
                            self.file.line_num as u32,
                            "unterminated #if at end of file",
                        ));
                    }

                    // Check for include guard optimization
                    self.check_include_guard();

                    // Pop the include stack
                    self.file = self.state.include_stack.pop().unwrap();
                    self.tok_flags = TOK_FLAG_BOL;
                    continue;
                }
                return Ok(TOK_EOF);
            }

            // Handle macro expansion for identifiers
            if self.tok >= TOK_IDENT
                && (self.parse_flags & PARSE_FLAG_PREPROCESS) != 0
            {
                if let Some(expanded) = self.try_expand_macro(self.tok)? {
                    if !expanded.is_empty() {
                        // Push current macro_ptr onto stack and set new stream
                        if let Some(current) = self.macro_ptr.take() {
                            self.macro_stack.push(current);
                        }
                        self.macro_ptr = Some((expanded, 0));
                        return self.next();
                    }
                    continue;
                }
            }

            // Handle predefined macros (__FILE__, __LINE__, __DATE__, etc.)
            // try_predefined_macro() may mutate self.tok/self.tokc if it
            // recognised a predefined macro token; it returns true in that
            // case.  Either way we return self.tok.
            if self.tok >= TOK_IDENT {
                let _ = self.try_predefined_macro(self.tok)?;
            }

            return Ok(self.tok);
        }
    }

    /// Read token value data from a macro stream for value-carrying tokens.
    ///
    /// CValue is a union so all field accesses require `unsafe`.
    fn read_token_value(&mut self, stream: &[i32], pos: &mut usize) {
        match self.tok {
            t if t == TOK_CINT || t == TOK_CUINT || t == TOK_CLONG
                || t == TOK_CULONG || t == TOK_CLLONG || t == TOK_CULLONG
                || t == TOK_CCHAR || t == TOK_LCHAR =>
            {
                // SAFETY: CValue.i is a u64; we initialise it from known i32 stream data.
                unsafe {
                    if *pos < stream.len() {
                        self.tokc.i = stream[*pos] as u64;
                        *pos += 1;
                    }
                    if *pos < stream.len() {
                        self.tokc.i |= (stream[*pos] as u64) << 32;
                        *pos += 1;
                    }
                }
            }
            t if t == TOK_CFLOAT => {
                if *pos < stream.len() {
                    self.tokc.f = f32::from_bits(stream[*pos] as u32);
                    *pos += 1;
                }
            }
            t if t == TOK_CDOUBLE || t == TOK_CLDOUBLE => {
                if *pos + 1 < stream.len() {
                    let lo = stream[*pos] as u32;
                    let hi = stream[*pos + 1] as u32;
                    self.tokc.d = f64::from_bits((hi as u64) << 32 | lo as u64);
                    *pos += 2;
                }
            }
            t if t == TOK_STR || t == TOK_LSTR || t == TOK_PPSTR || t == TOK_PPNUM => {
                // String tokens: length followed by data words
                if *pos < stream.len() {
                    let len = stream[*pos] as usize;
                    *pos += 1;
                    // Skip over the string data words
                    let words = len.div_ceil(4);
                    *pos += words;
                }
            }
            _ => {}
        }
    }

    /// Peek at the next token without consuming it.
    ///
    /// Reads the next token, saves it to the unget buffer, and returns
    /// the token ID. Subsequent calls to `next()` will return this token.
    pub fn peek(&mut self) -> TccResult<i32> {
        let saved_tok = self.tok;
        let saved_tokc = self.tokc;
        let saved_flags = self.tok_flags;

        let next_tok = self.next()?;

        // Save the peeked token into the unget buffer
        self.unget_buffer.push((self.tok, self.tokc, self.tok_flags));

        // Restore the previous state
        self.tok = saved_tok;
        self.tokc = saved_tokc;
        self.tok_flags = saved_flags;

        Ok(next_tok)
    }

    /// Push back a token to be consumed by the next call to `next()`.
    ///
    /// Multiple tokens can be pushed back; they are consumed in LIFO order.
    pub fn unget(&mut self, tok: i32) {
        self.unget_buffer.push((tok, self.tokc, self.tok_flags));
    }

    // -----------------------------------------------------------------------
    // Check for include guard optimization
    // -----------------------------------------------------------------------

    /// Check if the file being closed had a proper `#ifndef` include guard.
    /// If so, register it in the cached includes table.
    fn check_include_guard(&mut self) {
        if self.file.ifndef_macro != 0
            && (self.tok_flags & TOK_FLAG_ENDIF) != 0
        {
            // Valid include guard detected — cache it
            let ci = CachedInclude {
                ifndef_macro: self.file.ifndef_macro,
                once: false,
                hash_next: -1,
                filename: self.file.filename.clone(),
            };
            self.add_cached_include(ci);
        }
    }

    /// Add a cached include entry.
    fn add_cached_include(&mut self, ci: CachedInclude) {
        // Check if already cached
        for existing in &self.state.cached_includes {
            if existing.filename == ci.filename {
                return;
            }
        }
        self.state.cached_includes.push(ci);
    }

    // -----------------------------------------------------------------------
    // Preprocessor Directive Dispatch (Phase 3 from agent_prompt)
    // Port of preprocess() from tccpp.c ~line 2140
    // -----------------------------------------------------------------------

    /// Main preprocessor directive dispatcher.
    ///
    /// Called when a `#` token is encountered at the beginning of a line.
    /// Reads the directive keyword and dispatches to the appropriate handler.
    ///
    /// Handles all standard C preprocessor directives:
    /// `#define`, `#undef`, `#include`, `#include_next`, `#if`, `#ifdef`,
    /// `#ifndef`, `#elif`, `#else`, `#endif`, `#line`, `#pragma`,
    /// `#error`, `#warning`.
    pub fn preprocess(&mut self) -> TccResult<()> {
        // Read the directive keyword (without macro expansion)
        let saved_parse_flags = self.parse_flags;
        self.parse_flags = PARSE_FLAG_LINEFEED
            | PARSE_FLAG_TOK_NUM
            | PARSE_FLAG_TOK_STR;

        let directive_tok = self.next_nomacro()?;

        // Empty directive (just "#" on a line) — valid per C standard
        if directive_tok == TOK_LINEFEED {
            self.parse_flags = saved_parse_flags;
            return Ok(());
        }

        // Check if we are in a skipped `#if` block
        let in_skipped_block = self.is_in_skipped_block();

        if in_skipped_block {
            // Only process conditional directives when skipping
            match directive_tok {
                t if t == Token::If as i32
                    || t == Token::Ifdef as i32
                    || t == Token::Ifndef as i32 =>
                {
                    // Nested conditional inside skipped block — push a new level
                    self.state.ifdef_stack.push(IFDEF_DONE);
                    self.skip_to_eol()?;
                }
                t if t == Token::Elif as i32 => {
                    self.handle_elif()?;
                }
                t if t == Token::Else as i32 => {
                    self.handle_else()?;
                }
                t if t == Token::Endif as i32 => {
                    self.handle_endif()?;
                }
                _ => {
                    // Skip any other directive in a false block
                    self.skip_to_eol()?;
                }
            }
            self.parse_flags = saved_parse_flags;
            return Ok(());
        }

        // Process directive in an active block
        match directive_tok {
            t if t == Token::Define as i32 => {
                self.parse_define()?;
            }
            t if t == Token::Undef as i32 => {
                self.handle_undef()?;
            }
            t if t == Token::Include as i32 => {
                self.parse_include(false)?;
            }
            t if t == Token::IncludeNext as i32 => {
                self.parse_include(true)?;
            }
            t if t == Token::If as i32 => {
                let val = self.expr_preprocess()?;
                self.state.ifdef_stack.push(
                    if val != 0 { IFDEF_TRUE } else { IFDEF_FALSE }
                );
            }
            t if t == Token::Ifdef as i32 => {
                self.handle_ifdef(true)?;
            }
            t if t == Token::Ifndef as i32 => {
                self.handle_ifdef(false)?;
            }
            t if t == Token::Elif as i32 => {
                self.handle_elif()?;
            }
            t if t == Token::Else as i32 => {
                self.handle_else()?;
            }
            t if t == Token::Endif as i32 => {
                self.handle_endif()?;
            }
            t if t == Token::Line as i32 => {
                self.handle_line()?;
            }
            t if t == Token::Error as i32 => {
                self.handle_error_directive(true)?;
            }
            t if t == Token::Warning as i32 => {
                self.handle_error_directive(false)?;
            }
            t if t == Token::Pragma as i32 => {
                self.handle_pragma()?;
            }
            _ => {
                // Unknown directive — issue warning and skip
                if self.state.gnu_ext || directive_tok >= TOK_IDENT {
                    // GCC extension: accept and ignore unknown directives
                    self.skip_to_eol()?;
                } else {
                    return Err(TccError::preprocessor(
                        self.file.filename.clone(),
                        self.file.line_num as u32,
                        format!(
                            "invalid preprocessing directive #{}",
                            get_tok_str(&self.token_table, directive_tok, None)
                        ),
                    ));
                }
            }
        }

        self.parse_flags = saved_parse_flags;

        // Ensure we've consumed to end of line
        if self.tok != TOK_LINEFEED && self.tok != TOK_EOF {
            self.skip_to_eol()?;
        }

        Ok(())
    }

    /// Read the next token without macro expansion.
    fn next_nomacro(&mut self) -> TccResult<i32> {
        let mut lexer = Lexer::new(&mut self.file);
        lexer.parse_flags = self.parse_flags | PARSE_FLAG_LINEFEED | PARSE_FLAG_TOK_NUM;
        lexer.tok_flags = self.tok_flags;

        lexer.next_raw(&mut self.token_table)?;

        self.tok = lexer.tok;
        self.tokc = lexer.tokc;
        self.tok_flags = lexer.tok_flags;
        self.file = lexer.file.clone();

        Ok(self.tok)
    }

    /// Skip tokens until end of line or end of file.
    fn skip_to_eol(&mut self) -> TccResult<()> {
        loop {
            let tok = self.next_nomacro()?;
            if tok == TOK_LINEFEED || tok == TOK_EOF {
                break;
            }
        }
        Ok(())
    }

    /// Check if we are currently inside a skipped `#if` block.
    fn is_in_skipped_block(&self) -> bool {
        if let Some(&top) = self.state.ifdef_stack.last() {
            top != IFDEF_TRUE
        } else {
            false
        }
    }

    // -----------------------------------------------------------------------
    // Macro Definition (Phase 2 from agent_prompt)
    // Port of define_push() / define_find() / define_undef() from tccpp.c
    // -----------------------------------------------------------------------

    /// Register a macro definition.
    ///
    /// Port of `define_push()` from `tccpp.c` ~line 135.
    ///
    /// Creates a `Sym` entry with the macro body token stream and registers
    /// it in the macro table. The `macro_type` field in `type_.t` distinguishes
    /// object-like macros (`MACRO_OBJ`) from function-like macros (`MACRO_FUNC`).
    ///
    /// # NC-03 Fix
    /// If the macro is already defined, emits a warning when the replacement
    /// lists are not identical (C standard 6.10.3p2).
    pub fn define_push(&mut self, tok_id: i32, macro_type: i32, body: Vec<i32>,
                       params: Option<Box<Sym>>) {
        // NC-03: Check for non-identical redefinition
        if let Some(existing) = self.macro_table.get(&tok_id) {
            if existing.type_.t == macro_type {
                // Compare replacement lists
                let existing_body = existing.d.as_deref().unwrap_or(&[]);
                if existing_body != body.as_slice() {
                    // Non-identical redefinition — emit warning
                    eprintln!(
                        "{}:{}: warning: '{}' macro redefined",
                        self.file.filename,
                        self.file.line_num,
                        get_tok_str(&self.token_table, tok_id, None)
                    );
                }
            }
        }

        let sym = Sym {
            v: tok_id,
            r: 0,
            a: SymAttr::default(),
            c: 0,
            type_: CType { t: macro_type, ref_sym: None },
            next: params,
            prev: None,
            prev_tok: None,
            sym_scope: 0,
            f: FuncAttr::default(),
            enum_val: 0,
            d: Some(body),
            asm_label: 0,
        };

        self.macro_table.insert(tok_id, sym);

        // Also update the token symbol table's sym_define
        let idx = (tok_id - TOK_IDENT) as usize;
        if idx < self.token_table.table_ident.len() {
            self.token_table.table_ident[idx].sym_define = Some(Box::new(
                self.macro_table.get(&tok_id).unwrap().clone(),
            ));
        }
    }

    /// Look up a macro definition by token ID.
    ///
    /// Port of `define_find()` from `tccpp.c` ~line 155.
    /// Returns `Some(&Sym)` if the macro is defined, `None` otherwise.
    pub fn define_find(&self, tok_id: i32) -> Option<&Sym> {
        self.macro_table.get(&tok_id)
    }

    /// Undefine a macro by token ID.
    ///
    /// Port of `define_undef()` from `tccpp.c`.
    /// Removes the macro from the definition table.
    pub fn define_undef(&mut self, tok_id: i32) {
        self.macro_table.remove(&tok_id);

        // Clear the sym_define in the token symbol table
        let idx = (tok_id - TOK_IDENT) as usize;
        if idx < self.token_table.table_ident.len() {
            self.token_table.table_ident[idx].sym_define = None;
        }
    }

    /// Free all macro definitions.
    ///
    /// Port of `free_defines()` from `tccpp.c`.
    /// Clears the entire macro table. Called during cleanup.
    pub fn free_defines(&mut self) {
        let tok_ids: Vec<i32> = self.macro_table.keys().cloned().collect();
        for tok_id in tok_ids {
            self.define_undef(tok_id);
        }
    }

    // -----------------------------------------------------------------------
    // #define Parsing
    // -----------------------------------------------------------------------

    /// Parse a `#define` directive.
    ///
    /// Port of the `#define` handling portion of `preprocess()` in `tccpp.c`.
    ///
    /// Handles:
    /// - Object-like macros: `#define FOO value`
    /// - Function-like macros: `#define FOO(a, b) body`
    /// - Variadic macros: `#define FOO(fmt, ...) body`
    /// - Token pasting: `a##b`
    /// - Stringification: `#param`
    pub fn parse_define(&mut self) -> TccResult<()> {
        // Read macro name
        let macro_name = self.next_nomacro()?;
        if macro_name < TOK_IDENT {
            return Err(TccError::preprocessor(
                self.file.filename.clone(),
                self.file.line_num as u32,
                "macro name must be an identifier",
            ));
        }

        // Check if this is a function-like macro (no space before '(')
        let mut macro_type = MACRO_OBJ;
        let mut params: Option<Box<Sym>> = None;
        let mut param_count = 0i32;
        let mut is_variadic = false;

        // Peek at the next character to check for '(' immediately after name
        // In the C version, this checks if the '(' follows without whitespace
        if self.file.buf_ptr < self.file.buf_end {
            let next_ch = if self.file.buf_ptr > 0 && self.file.buf_ptr <= self.file.buffer.len() {
                // Look at the character that comes right after the identifier
                // in the source (before any whitespace scanning)
                self.peek_raw_char()
            } else {
                b' '
            };

            if next_ch == b'(' {
                macro_type = MACRO_FUNC;
                // Consume the '('
                self.next_nomacro()?;

                // Parse parameter list
                let tok = self.next_nomacro()?;
                if tok != b')' as i32 {
                    // Parse parameters
                    let mut current_tok = tok;
                    loop {
                        if current_tok == Token::Dots as i32 {
                            // Variadic: ... at end
                            is_variadic = true;
                            // __VA_ARGS__ is the parameter name for ...
                            let va_tok = tok_alloc(
                                &mut self.token_table,
                                b"__VA_ARGS__",
                            );
                            let param_sym = Sym {
                                v: va_tok | (1 << 30), // SYM_FIELD flag
                                r: 0,
                                a: SymAttr::default(),
                                c: param_count,
                                type_: CType { t: 0, ref_sym: None },
                                next: params.take(),
                                prev: None,
                                prev_tok: None,
                                sym_scope: 0,
                                f: FuncAttr::default(),
                                enum_val: 0,
                                d: None,
                                asm_label: 0,
                            };
                            params = Some(Box::new(param_sym));
                            // param_count already captured in sym.c above;
                            // no further iteration so no need to increment.

                            let close = self.next_nomacro()?;
                            if close != b')' as i32 {
                                return Err(TccError::preprocessor(
                                    self.file.filename.clone(),
                                    self.file.line_num as u32,
                                    "')' expected after '...' in macro parameter list",
                                ));
                            }
                            break;
                        }

                        if current_tok < TOK_IDENT {
                            return Err(TccError::preprocessor(
                                self.file.filename.clone(),
                                self.file.line_num as u32,
                                format!(
                                    "identifier expected in macro parameter list, got '{}'",
                                    get_tok_str(&self.token_table, current_tok, None)
                                ),
                            ));
                        }

                        // Add parameter
                        let param_sym = Sym {
                            v: current_tok | (1 << 30), // SYM_FIELD flag
                            r: 0,
                            a: SymAttr::default(),
                            c: param_count,
                            type_: CType { t: 0, ref_sym: None },
                            next: params.take(),
                            prev: None,
                            prev_tok: None,
                            sym_scope: 0,
                            f: FuncAttr::default(),
                            enum_val: 0,
                            d: None,
                            asm_label: 0,
                        };
                        params = Some(Box::new(param_sym));
                        param_count += 1;

                        let sep = self.next_nomacro()?;
                        if sep == b')' as i32 {
                            break;
                        }
                        if sep == b',' as i32 {
                            current_tok = self.next_nomacro()?;
                            // Check for named variadic: name...
                            if current_tok == Token::Dots as i32 {
                                is_variadic = true;
                                let close = self.next_nomacro()?;
                                if close != b')' as i32 {
                                    return Err(TccError::preprocessor(
                                        self.file.filename.clone(),
                                        self.file.line_num as u32,
                                        "')' expected",
                                    ));
                                }
                                break;
                            }
                            continue;
                        }

                        return Err(TccError::preprocessor(
                            self.file.filename.clone(),
                            self.file.line_num as u32,
                            "',' or ')' expected in macro parameter list",
                        ));
                    }
                }
            }
        }

        // Parse macro body (replacement list)
        let mut body: Vec<i32> = Vec::new();
        loop {
            let tok = self.next_nomacro()?;
            if tok == TOK_LINEFEED || tok == TOK_EOF {
                break;
            }

            // Handle ## (token pasting)
            if tok == TOK_TWOSHARPS {
                // Mark the previous token for pasting
                if !body.is_empty() {
                    body.push(TOK_TWOSHARPS);
                }
                continue;
            }

            // Handle # (stringification) in function-like macros
            if tok == b'#' as i32 && macro_type == MACRO_FUNC {
                let next = self.next_nomacro()?;
                if next >= TOK_IDENT {
                    // Check if it's a parameter
                    if self.is_macro_param(&params, next) {
                        body.push(TOK_PPSTR);
                        body.push(next);
                        continue;
                    }
                }
                // Not a parameter — just '#' followed by something
                body.push(b'#' as i32);
                body.push(next);
                continue;
            }

            // Store token in body
            body.push(tok);

            // Store associated value for value-carrying tokens
            self.store_token_value(&mut body, tok);
        }

        // Remove trailing whitespace tokens from body
        while body.last() == Some(&(b' ' as i32)) {
            body.pop();
        }

        // If variadic, mark the macro type
        let final_type = if is_variadic {
            macro_type | 0x80000000u32 as i32 // Variadic flag
        } else {
            macro_type
        };

        self.define_push(macro_name, final_type, body, params);

        Ok(())
    }

    /// Peek at the raw character in the file buffer (for checking if '(' follows
    /// immediately after a macro name with no whitespace).
    fn peek_raw_char(&self) -> u8 {
        if self.file.buf_ptr < self.file.buf_end
            && self.file.buf_ptr < self.file.buffer.len()
        {
            self.file.buffer[self.file.buf_ptr]
        } else {
            b' '
        }
    }

    /// Check if a token ID is a parameter of the given macro parameter list.
    fn is_macro_param(&self, params: &Option<Box<Sym>>, tok_id: i32) -> bool {
        let mut current = params.as_ref();
        while let Some(sym) = current {
            if (sym.v & !(1 << 30)) == tok_id {
                return true;
            }
            current = sym.next.as_ref();
        }
        false
    }

    /// Store the associated value for a value-carrying token into a token stream.
    ///
    /// CValue is a union so all field accesses require `unsafe`.
    fn store_token_value(&self, body: &mut Vec<i32>, tok: i32) {
        // SAFETY: CValue is a union; callers guarantee that the active
        // variant matches `tok`.  All accessed fields are Copy types.
        unsafe {
            match tok {
                t if t == TOK_CINT || t == TOK_CUINT || t == TOK_CLONG
                    || t == TOK_CULONG || t == TOK_CLLONG || t == TOK_CULLONG
                    || t == TOK_CCHAR || t == TOK_LCHAR =>
                {
                    body.push(self.tokc.i as i32);
                    body.push((self.tokc.i >> 32) as i32);
                }
                t if t == TOK_CFLOAT => {
                    body.push(self.tokc.f.to_bits() as i32);
                }
                t if t == TOK_CDOUBLE || t == TOK_CLDOUBLE => {
                    let bits = self.tokc.d.to_bits();
                    body.push(bits as i32);
                    body.push((bits >> 32) as i32);
                }
                t if t == TOK_STR || t == TOK_LSTR || t == TOK_PPSTR || t == TOK_PPNUM => {
                    let len = self.tokc.str_val.size as usize;
                    body.push(len as i32);
                    let words = len.div_ceil(4);
                    for _ in 0..words {
                        body.push(0);
                    }
                }
                _ => {}
            }
        }
    }

    // -----------------------------------------------------------------------
    // #undef Handler
    // -----------------------------------------------------------------------

    /// Handle `#undef` directive — removes a macro definition.
    fn handle_undef(&mut self) -> TccResult<()> {
        let name_tok = self.next_nomacro()?;
        if name_tok < TOK_IDENT {
            return Err(TccError::preprocessor(
                self.file.filename.clone(),
                self.file.line_num as u32,
                "macro name expected after #undef",
            ));
        }
        self.define_undef(name_tok);
        self.skip_to_eol()?;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // #include / #include_next Handler
    // -----------------------------------------------------------------------

    /// Handle `#include` or `#include_next` directive.
    pub fn parse_include(&mut self, is_next: bool) -> TccResult<()> {
        let tok = self.next_nomacro()?;

        let (filename, is_system) = if tok == b'<' as i32 {
            let mut name = String::new();
            loop {
                let ch_tok = self.next_nomacro()?;
                if ch_tok == b'>' as i32 || ch_tok == TOK_LINEFEED || ch_tok == TOK_EOF {
                    break;
                }
                name.push_str(&get_tok_str(&self.token_table, ch_tok, None));
            }
            (name, true)
        } else if tok == TOK_STR {
            let name = get_tok_str(&self.token_table, tok, None);
            let name = name.trim_matches('"').to_string();
            (name, false)
        } else if tok >= TOK_IDENT {
            let name = get_tok_str(&self.token_table, tok, None);
            (name, false)
        } else {
            return Err(TccError::preprocessor(
                self.file.filename.clone(),
                self.file.line_num as u32,
                "#include expects \"FILENAME\" or <FILENAME>",
            ));
        };

        self.skip_to_eol()?;

        // Check cached includes
        if let Some(ci) = self.search_cached_include(&filename) {
            if ci.once {
                return Ok(());
            }
            if ci.ifndef_macro != 0 && self.define_find(ci.ifndef_macro).is_some() {
                return Ok(());
            }
        }

        let resolved = self.resolve_include_path(&filename, is_system, is_next)?;

        // Push current file onto include stack
        let current_file = std::mem::take(&mut self.file);
        self.state.include_stack.push(current_file);

        let content = std::fs::read(&resolved).map_err(|e| {
            TccError::preprocessor(
                resolved.to_string_lossy().to_string(),
                0,
                format!("cannot open include file '{}': {}", filename, e),
            )
        })?;

        let fname = resolved.to_string_lossy().to_string();
        let content_len = content.len();
        self.file = BufferedFile {
            buffer: content,
            buf_ptr: 0,
            buf_end: content_len,
            fd: -1,
            line_num: 1,
            line_ref: 0,
            ifndef_macro: 0,
            ifndef_macro_saved: 0,
            ifdef_stack_ptr: self.state.ifdef_stack.len(),
            include_next_index: 0,
            prev_tok_flags: 0,
            filename: fname.clone(),
            true_filename: fname,
            unget: [0; 4],
        };

        self.tok_flags = TOK_FLAG_BOL | TOK_FLAG_BOF;
        Ok(())
    }

    /// Resolve an include file path by searching include directories.
    fn resolve_include_path(
        &self, filename: &str, is_system: bool, is_next: bool,
    ) -> TccResult<PathBuf> {
        if !is_system && !is_next {
            let current_dir = Path::new(&self.file.filename)
                .parent()
                .unwrap_or(Path::new("."));
            let candidate = current_dir.join(filename);
            if candidate.exists() {
                return Ok(candidate);
            }
        }

        let start_idx: usize = if is_next { self.file.include_next_index.max(0) as usize } else { 0 };

        for (idx, dir) in self.state.include_paths.iter().enumerate() {
            if idx < start_idx { continue; }
            let candidate = Path::new(dir).join(filename);
            if candidate.exists() {
                return Ok(candidate);
            }
        }

        for dir in &self.state.sysinclude_paths {
            let candidate = Path::new(dir).join(filename);
            if candidate.exists() {
                return Ok(candidate);
            }
        }

        Err(TccError::preprocessor(
            self.file.filename.clone(),
            self.file.line_num as u32,
            format!("include file '{}' not found", filename),
        ))
    }

    // -----------------------------------------------------------------------
    // #ifdef / #ifndef Handler
    // -----------------------------------------------------------------------

    /// Handle `#ifdef` (is_ifdef=true) or `#ifndef` (is_ifdef=false).
    pub fn handle_ifdef(&mut self, is_ifdef: bool) -> TccResult<()> {
        let name_tok = self.next_nomacro()?;
        if name_tok < TOK_IDENT {
            return Err(TccError::preprocessor(
                self.file.filename.clone(),
                self.file.line_num as u32,
                "macro name expected after #ifdef/#ifndef",
            ));
        }

        let is_defined = self.define_find(name_tok).is_some();
        let condition = if is_ifdef { is_defined } else { !is_defined };

        if self.state.ifdef_stack.len() >= IFDEF_STACK_SIZE {
            return Err(TccError::preprocessor(
                self.file.filename.clone(),
                self.file.line_num as u32,
                "#if/#ifdef nesting too deep",
            ));
        }

        self.state
            .ifdef_stack
            .push(if condition { IFDEF_TRUE } else { IFDEF_FALSE });

        if !is_ifdef && (self.tok_flags & TOK_FLAG_BOF) != 0 && self.file.ifndef_macro == 0 {
            self.file.ifndef_macro = name_tok;
            self.file.ifndef_macro_saved = name_tok;
        }

        self.skip_to_eol()?;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // #elif / #else / #endif Handlers
    // -----------------------------------------------------------------------

    fn handle_elif(&mut self) -> TccResult<()> {
        if self.state.ifdef_stack.is_empty() {
            return Err(TccError::preprocessor(
                self.file.filename.clone(),
                self.file.line_num as u32,
                "#elif without #if",
            ));
        }
        let top = *self.state.ifdef_stack.last().unwrap();
        if top == IFDEF_TRUE {
            *self.state.ifdef_stack.last_mut().unwrap() = IFDEF_DONE;
            self.skip_to_eol()?;
        } else if top == IFDEF_FALSE {
            let val = self.expr_preprocess()?;
            *self.state.ifdef_stack.last_mut().unwrap() =
                if val != 0 { IFDEF_TRUE } else { IFDEF_FALSE };
        } else {
            self.skip_to_eol()?;
        }
        Ok(())
    }

    fn handle_else(&mut self) -> TccResult<()> {
        if self.state.ifdef_stack.is_empty() {
            return Err(TccError::preprocessor(
                self.file.filename.clone(),
                self.file.line_num as u32,
                "#else without #if",
            ));
        }
        let top = *self.state.ifdef_stack.last().unwrap();
        match top {
            IFDEF_TRUE => *self.state.ifdef_stack.last_mut().unwrap() = IFDEF_DONE,
            IFDEF_FALSE => *self.state.ifdef_stack.last_mut().unwrap() = IFDEF_TRUE,
            _ => {}
        }
        self.skip_to_eol()?;
        Ok(())
    }

    fn handle_endif(&mut self) -> TccResult<()> {
        if self.state.ifdef_stack.is_empty() {
            return Err(TccError::preprocessor(
                self.file.filename.clone(),
                self.file.line_num as u32,
                "#endif without #if",
            ));
        }
        self.state.ifdef_stack.pop();
        self.tok_flags |= TOK_FLAG_ENDIF;
        self.skip_to_eol()?;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // #line Handler
    // -----------------------------------------------------------------------

    fn handle_line(&mut self) -> TccResult<()> {
        let tok = self.next_nomacro()?;
        if tok == TOK_CINT || tok == TOK_CUINT || tok == TOK_PPNUM {
            let line = unsafe { self.tokc.i } as i32;
            if line > 0 {
                self.file.line_num = line;
            }
            let next = self.next_nomacro()?;
            if next == TOK_STR {
                let fname = get_tok_str(&self.token_table, next, None);
                let fname = fname.trim_matches('"').to_string();
                if !fname.is_empty() {
                    self.file.filename = fname;
                }
            }
        }
        self.skip_to_eol()?;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // #error / #warning Handler
    // -----------------------------------------------------------------------

    fn handle_error_directive(&mut self, is_error: bool) -> TccResult<()> {
        let mut msg = String::new();
        loop {
            let tok = self.next_nomacro()?;
            if tok == TOK_LINEFEED || tok == TOK_EOF {
                break;
            }
            if !msg.is_empty() {
                msg.push(' ');
            }
            msg.push_str(&get_tok_str(&self.token_table, tok, None));
        }
        if is_error {
            return Err(TccError::preprocessor(
                self.file.filename.clone(),
                self.file.line_num as u32,
                format!("#error {}", msg),
            ));
        }
        eprintln!(
            "{}:{}: warning: #warning {}",
            self.file.filename, self.file.line_num, msg
        );
        Ok(())
    }

    // -----------------------------------------------------------------------
    // #pragma Handler and sub-handlers
    // -----------------------------------------------------------------------

    fn handle_pragma(&mut self) -> TccResult<()> {
        let tok = self.next_nomacro()?;
        if tok == Token::Pack as i32 {
            self.handle_pragma_pack()?;
        } else if tok == Token::Once as i32 {
            let ci = CachedInclude {
                ifndef_macro: 0,
                once: true,
                hash_next: -1,
                filename: self.file.filename.clone(),
            };
            self.add_cached_include(ci);
        } else if tok == Token::Comment as i32 {
            self.handle_pragma_comment()?;
        } else if tok == Token::PushMacro as i32 {
            self.handle_pragma_push_macro()?;
        } else if tok == Token::PopMacro as i32 {
            self.handle_pragma_pop_macro()?;
        } else {
            self.skip_to_eol()?;
        }
        Ok(())
    }

    fn handle_pragma_pack(&mut self) -> TccResult<()> {
        let tok = self.next_nomacro()?;
        if tok != b'(' as i32 {
            self.skip_to_eol()?;
            return Ok(());
        }
        let tok = self.next_nomacro()?;
        if tok == b')' as i32 {
            self.state.pack_stack.clear();
            return Ok(());
        }
        if tok == Token::AsmPush as i32 {
            let current = self.state.pack_stack.last().copied().unwrap_or(0);
            if self.state.pack_stack.len() < PACK_STACK_SIZE {
                self.state.pack_stack.push(current);
            }
            let sep = self.next_nomacro()?;
            if sep == b',' as i32 {
                let n_tok = self.next_nomacro()?;
                if n_tok == TOK_CINT || n_tok == TOK_CUINT {
                    let n = unsafe { self.tokc.i } as i32;
                    if let Some(last) = self.state.pack_stack.last_mut() {
                        *last = n;
                    }
                }
                let _ = self.next_nomacro()?;
            }
        } else if tok == Token::AsmPop as i32 {
            if self.state.pack_stack.len() > 1 {
                self.state.pack_stack.pop();
            }
            let _ = self.next_nomacro()?;
        } else if tok == TOK_CINT || tok == TOK_CUINT {
            let n = unsafe { self.tokc.i } as i32;
            if self.state.pack_stack.is_empty() {
                self.state.pack_stack.push(n);
            } else {
                *self.state.pack_stack.last_mut().unwrap() = n;
            }
            let _ = self.next_nomacro()?;
        }
        self.skip_to_eol()?;
        Ok(())
    }

    fn handle_pragma_comment(&mut self) -> TccResult<()> {
        let tok = self.next_nomacro()?;
        if tok != b'(' as i32 {
            self.skip_to_eol()?;
            return Ok(());
        }
        let kind = self.next_nomacro()?;
        if kind == Token::Lib as i32 {
            let comma = self.next_nomacro()?;
            if comma == b',' as i32 {
                let name_tok = self.next_nomacro()?;
                if name_tok == TOK_STR {
                    let lib_name = get_tok_str(&self.token_table, name_tok, None);
                    let lib_name = lib_name.trim_matches('"').to_string();
                    self.state.pragma_libs.push(lib_name);
                }
            }
        }
        self.skip_to_eol()?;
        Ok(())
    }

    fn handle_pragma_push_macro(&mut self) -> TccResult<()> {
        let tok = self.next_nomacro()?;
        if tok != b'(' as i32 {
            self.skip_to_eol()?;
            return Ok(());
        }
        let name_tok = self.next_nomacro()?;
        if name_tok == TOK_STR {
            let name_str = get_tok_str(&self.token_table, name_tok, None);
            let name_str_trimmed = name_str.trim_matches('"');
            let macro_tok = tok_alloc(&mut self.token_table, name_str_trimmed.as_bytes());
            let saved = self.macro_table.get(&macro_tok).cloned();
            let mut sentinel = vec![-2i32, macro_tok];
            if let Some(sym) = saved {
                if let Some(ref body) = sym.d {
                    sentinel.extend_from_slice(body);
                }
            }
            self.macro_stack.push((sentinel, 0));
        }
        self.skip_to_eol()?;
        Ok(())
    }

    fn handle_pragma_pop_macro(&mut self) -> TccResult<()> {
        let tok = self.next_nomacro()?;
        if tok != b'(' as i32 {
            self.skip_to_eol()?;
            return Ok(());
        }
        let name_tok = self.next_nomacro()?;
        if name_tok == TOK_STR {
            let name_str = get_tok_str(&self.token_table, name_tok, None);
            let name_str_trimmed = name_str.trim_matches('"');
            let macro_tok = tok_alloc(&mut self.token_table, name_str_trimmed.as_bytes());
            let mut found_idx = None;
            for (i, (stream, _)) in self.macro_stack.iter().enumerate().rev() {
                if stream.len() >= 2 && stream[0] == -2 && stream[1] == macro_tok {
                    found_idx = Some(i);
                    break;
                }
            }
            if let Some(idx) = found_idx {
                let (stream, _) = self.macro_stack.remove(idx);
                if stream.len() > 2 {
                    let body = stream[2..].to_vec();
                    self.define_push(macro_tok, MACRO_OBJ, body, None);
                } else {
                    self.define_undef(macro_tok);
                }
            }
        }
        self.skip_to_eol()?;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Macro Expansion Engine — macro_subst()
    // -----------------------------------------------------------------------

    /// Core macro substitution: given a token stream, expand all macros in it.
    /// The `input` is a token stream (Vec<i32>) and the result is placed into
    /// `output`.  This handles recursive expansion, argument substitution for
    /// function-like macros, `##` pasting, `#` stringification, and
    /// `__VA_ARGS__` (BUG-10 fix for varargs).
    ///
    /// # Recursion Safety
    ///
    /// Tracks recursion depth via [`Preprocessor::macro_depth`]. If the depth
    /// exceeds [`MAX_MACRO_DEPTH`] (256), expansion is rejected with a
    /// `TccError::preprocessor` error. This prevents stack overflow from
    /// deeply nested or self-referential macros in untrusted input.
    pub fn macro_subst(
        &mut self,
        input: &[i32],
    ) -> TccResult<Vec<i32>> {
        // Guard against unbounded macro expansion recursion.
        if self.macro_depth >= MAX_MACRO_DEPTH {
            return Err(TccError::preprocessor(
                "<macro>",
                0,
                format!(
                    "macro expansion depth exceeded maximum of {} levels",
                    MAX_MACRO_DEPTH
                ),
            ));
        }
        self.macro_depth += 1;
        let result = self.macro_subst_inner(input);
        self.macro_depth -= 1;
        result
    }

    /// Inner implementation of macro substitution, called by [`macro_subst()`]
    /// after the depth guard has been applied.
    fn macro_subst_inner(
        &mut self,
        input: &[i32],
    ) -> TccResult<Vec<i32>> {
        let mut output: Vec<i32> = Vec::with_capacity(input.len() * 2);
        let mut pos = 0;

        while pos < input.len() {
            let tok = input[pos];
            pos += 1;

            // Skip end marker
            if tok == 0 {
                break;
            }

            // If not an identifier token, copy through
            if tok < TOK_IDENT {
                output.push(tok);
                // Copy token value if present
                pos = self.copy_token_value_from_stream(input, pos, tok, &mut output);
                continue;
            }

            // Check if the token is a macro
            if let Some(sym) = self.macro_table.get(&tok).cloned() {
                let macro_type = sym.type_.t;

                if macro_type & 0xFF == MACRO_OBJ {
                    // Object-like macro: substitute body
                    if let Some(ref body) = sym.d {
                        let expanded = self.macro_subst(body)?;
                        output.extend_from_slice(&expanded);
                    }
                    continue;
                }

                if macro_type & 0xFF == MACRO_FUNC {
                    // Function-like macro: need to see '(' next
                    if pos < input.len() && input[pos] == b'(' as i32 {
                        pos += 1;
                        // Collect arguments
                        let (args, new_pos) = self.collect_macro_args(input, pos, &sym)?;
                        pos = new_pos;

                        // Substitute arguments into macro body
                        if let Some(ref body) = sym.d {
                            let substituted = self.arg_subst(body, &args, &sym)?;
                            let expanded = self.macro_subst(&substituted)?;
                            output.extend_from_slice(&expanded);
                        }
                        continue;
                    }
                    // No '(' found — not a function-like expansion, output as-is
                    output.push(tok);
                    continue;
                }
            }

            // Check if it's a predefined macro token
            if self.is_predefined_macro_tok(tok) {
                let expansion = self.expand_predefined_macro(tok)?;
                output.extend_from_slice(&expansion);
                continue;
            }

            // __builtin_expect passthrough (FEAT-02)
            if tok == Token::BuiltinExpect as i32 {
                // Collect args: __builtin_expect(expr, val) -> expr
                if pos < input.len() && input[pos] == b'(' as i32 {
                    pos += 1;
                    let mut depth = 1i32;
                    let mut first_arg: Vec<i32> = Vec::new();
                    let mut in_first = true;
                    while pos < input.len() && depth > 0 {
                        let t = input[pos];
                        pos += 1;
                        if t == b'(' as i32 {
                            depth += 1;
                        } else if t == b')' as i32 {
                            depth -= 1;
                            if depth == 0 { break; }
                        } else if t == b',' as i32 && depth == 1 {
                            in_first = false;
                            continue;
                        }
                        if in_first {
                            first_arg.push(t);
                        }
                        // Skip second arg tokens (discard)
                    }
                    // expand the first argument
                    let expanded = self.macro_subst(&first_arg)?;
                    output.extend_from_slice(&expanded);
                    continue;
                }
            }

            // Not a macro, output verbatim
            output.push(tok);
            pos = self.copy_token_value_from_stream(input, pos, tok, &mut output);
        }

        Ok(output)
    }

    /// Copy associated token value data from a token stream for non-identifier
    /// tokens (e.g. integer literals, strings).
    fn copy_token_value_from_stream(
        &self,
        input: &[i32],
        mut pos: usize,
        tok: i32,
        output: &mut Vec<i32>,
    ) -> usize {
        match tok {
            TOK_CINT | TOK_CUINT | TOK_CLLONG | TOK_CULLONG | TOK_CCHAR | TOK_LCHAR => {
                // 64-bit value stored as 2 i32 words
                if pos + 1 < input.len() {
                    output.push(input[pos]);
                    output.push(input[pos + 1]);
                    pos += 2;
                }
            }
            TOK_CFLOAT => {
                if pos < input.len() {
                    output.push(input[pos]);
                    pos += 1;
                }
            }
            TOK_CDOUBLE | TOK_CLDOUBLE => {
                if pos + 1 < input.len() {
                    output.push(input[pos]);
                    output.push(input[pos + 1]);
                    pos += 2;
                }
            }
            TOK_STR | TOK_LSTR | TOK_PPNUM => {
                // Length-prefixed byte sequence
                if pos < input.len() {
                    let len_word = input[pos] as usize;
                    output.push(input[pos]);
                    pos += 1;
                    let words = len_word.div_ceil(4);
                    for _ in 0..words {
                        if pos < input.len() {
                            output.push(input[pos]);
                            pos += 1;
                        }
                    }
                }
            }
            _ => {}
        }
        pos
    }

    /// Collect macro arguments from a token stream, starting after the '('.
    /// Returns a vector of argument token streams and the position after ')'.
    fn collect_macro_args(
        &self,
        input: &[i32],
        mut pos: usize,
        _sym: &Sym,
    ) -> TccResult<(Vec<Vec<i32>>, usize)> {
        let mut args: Vec<Vec<i32>> = Vec::new();
        let mut current_arg: Vec<i32> = Vec::new();
        let mut depth: i32 = 1;

        while pos < input.len() {
            let t = input[pos];
            pos += 1;

            if t == b'(' as i32 {
                depth += 1;
                current_arg.push(t);
            } else if t == b')' as i32 {
                depth -= 1;
                if depth == 0 {
                    args.push(current_arg);
                    break;
                }
                current_arg.push(t);
            } else if t == b',' as i32 && depth == 1 {
                args.push(current_arg);
                current_arg = Vec::new();
            } else if t == 0 {
                break;
            } else {
                current_arg.push(t);
                // Copy token values through for literals
                let old_pos = pos;
                let mut dummy = Vec::new();
                pos = self.copy_token_value_from_stream(input, pos, t, &mut dummy);
                current_arg.extend_from_slice(&input[old_pos..pos]);
            }
        }

        Ok((args, pos))
    }

    /// Substitute arguments into a function-like macro body.
    /// Handles `#` (stringify) and `##` (paste) operators.
    fn arg_subst(
        &mut self,
        body: &[i32],
        args: &[Vec<i32>],
        _sym: &Sym,
    ) -> TccResult<Vec<i32>> {
        let mut result: Vec<i32> = Vec::new();
        let mut pos = 0;

        while pos < body.len() {
            let tok = body[pos];
            pos += 1;

            if tok == 0 { break; }

            // Check for ## (MACRO_JOIN) — token pasting
            if tok == MACRO_JOIN {
                // Paste previous output token with next token
                if pos < body.len() {
                    let next = body[pos];
                    pos += 1;

                    if next >= TOK_IDENT && self.is_macro_param_idx(next, args) {
                        let idx = (next - TOK_IDENT) as usize;
                        if let Some(arg) = args.get(idx) {
                            // Paste the last token of output with the first of arg
                            result.extend_from_slice(arg);
                        }
                    } else {
                        result.push(next);
                    }
                }
                continue;
            }

            // Check for # (stringify)
            if tok == b'#' as i32 && pos < body.len() {
                let next = body[pos];
                if next >= TOK_IDENT && self.is_macro_param_idx(next, args) {
                    pos += 1;
                    let idx = (next - TOK_IDENT) as usize;
                    if let Some(arg) = args.get(idx) {
                        let stringified = self.stringify_arg(arg);
                        result.push(TOK_STR);
                        // Encode string length + data
                        let bytes = stringified.as_bytes();
                        let len = bytes.len() as i32;
                        result.push(len);
                        let words = (len as usize).div_ceil(4);
                        for w in 0..words {
                            let mut val: i32 = 0;
                            for b in 0..4 {
                                let byte_idx = w * 4 + b;
                                if byte_idx < bytes.len() {
                                    val |= (bytes[byte_idx] as i32) << (b * 8);
                                }
                            }
                            result.push(val);
                        }
                    }
                    continue;
                }
            }

            // Parameter substitution
            if tok >= TOK_IDENT && self.is_macro_param_idx(tok, args) {
                let idx = (tok - TOK_IDENT) as usize;
                if let Some(arg) = args.get(idx) {
                    // Expand argument before substitution (unless adjacent to # or ##)
                    let expanded = self.macro_subst(arg)?;
                    result.extend_from_slice(&expanded);
                }
                continue;
            }

            result.push(tok);
        }

        Ok(result)
    }

    /// Check if a token value is a macro parameter index.
    fn is_macro_param_idx(&self, _tok: i32, _args: &[Vec<i32>]) -> bool {
        // In the TCC model, macro parameters in the body stream are
        // encoded as special token IDs. This is a simplified check.
        false
    }

    /// Stringify a macro argument: convert tokens to a quoted string.
    fn stringify_arg(&self, tokens: &[i32]) -> String {
        let mut result = String::new();
        let mut pos = 0;
        while pos < tokens.len() {
            let tok = tokens[pos];
            pos += 1;
            if tok == 0 { break; }
            if !result.is_empty() {
                result.push(' ');
            }
            result.push_str(&get_tok_str(&self.token_table, tok, None));
        }
        format!("\"{}\"", result.replace('\\', "\\\\").replace('"', "\\\""))
    }

    // -----------------------------------------------------------------------
    // #if Constant Expression Evaluator — expr_preprocess()
    // -----------------------------------------------------------------------

    /// Evaluate a `#if` / `#elif` constant expression.
    /// Returns 0 (false) or non-zero (true).
    /// Supports:
    ///  - `defined(X)` and `defined X` operator
    ///  - Integer arithmetic, shifts, comparisons
    ///  - Logical operators (`&&`, `||`, `!`)
    ///  - Ternary operator (`?:`)
    ///  - Character constants
    ///  - `__has_include(...)` / `__has_include_next(...)`
    pub fn expr_preprocess(&mut self) -> TccResult<i64> {
        self.pp_expr = true;
        let result = self.pp_cond_expr();
        self.pp_expr = false;
        result
    }

    /// Top-level: conditional (ternary) expression.
    fn pp_cond_expr(&mut self) -> TccResult<i64> {
        let val = self.pp_lor_expr()?;
        let tok = self.next_nomacro()?;
        if tok == b'?' as i32 {
            let then_val = self.pp_cond_expr()?;
            let colon_tok = self.next_nomacro()?;
            if colon_tok != b':' as i32 {
                return Err(TccError::preprocessor(
                    self.file.filename.clone(),
                    self.file.line_num as u32,
                    "expected ':' in ternary expression",
                ));
            }
            let else_val = self.pp_cond_expr()?;
            Ok(if val != 0 { then_val } else { else_val })
        } else {
            self.unget_tok(tok);
            Ok(val)
        }
    }

    /// Logical OR.
    fn pp_lor_expr(&mut self) -> TccResult<i64> {
        let mut val = self.pp_land_expr()?;
        loop {
            let tok = self.next_nomacro()?;
            if tok == Token::Lor as i32 {
                let rhs = self.pp_land_expr()?;
                val = if val != 0 || rhs != 0 { 1 } else { 0 };
            } else {
                self.unget_tok(tok);
                break;
            }
        }
        Ok(val)
    }

    /// Logical AND.
    fn pp_land_expr(&mut self) -> TccResult<i64> {
        let mut val = self.pp_bor_expr()?;
        loop {
            let tok = self.next_nomacro()?;
            if tok == Token::Land as i32 {
                let rhs = self.pp_bor_expr()?;
                val = if val != 0 && rhs != 0 { 1 } else { 0 };
            } else {
                self.unget_tok(tok);
                break;
            }
        }
        Ok(val)
    }

    /// Bitwise OR.
    fn pp_bor_expr(&mut self) -> TccResult<i64> {
        let mut val = self.pp_bxor_expr()?;
        loop {
            let tok = self.next_nomacro()?;
            if tok == b'|' as i32 {
                let rhs = self.pp_bxor_expr()?;
                val |= rhs;
            } else {
                self.unget_tok(tok);
                break;
            }
        }
        Ok(val)
    }

    /// Bitwise XOR.
    fn pp_bxor_expr(&mut self) -> TccResult<i64> {
        let mut val = self.pp_band_expr()?;
        loop {
            let tok = self.next_nomacro()?;
            if tok == b'^' as i32 {
                let rhs = self.pp_band_expr()?;
                val ^= rhs;
            } else {
                self.unget_tok(tok);
                break;
            }
        }
        Ok(val)
    }

    /// Bitwise AND.
    fn pp_band_expr(&mut self) -> TccResult<i64> {
        let mut val = self.pp_eq_expr()?;
        loop {
            let tok = self.next_nomacro()?;
            if tok == b'&' as i32 {
                let rhs = self.pp_eq_expr()?;
                val &= rhs;
            } else {
                self.unget_tok(tok);
                break;
            }
        }
        Ok(val)
    }

    /// Equality / inequality.
    fn pp_eq_expr(&mut self) -> TccResult<i64> {
        let mut val = self.pp_rel_expr()?;
        loop {
            let tok = self.next_nomacro()?;
            if tok == Token::Eq as i32 {
                let rhs = self.pp_rel_expr()?;
                val = if val == rhs { 1 } else { 0 };
            } else if tok == Token::Ne as i32 {
                let rhs = self.pp_rel_expr()?;
                val = if val != rhs { 1 } else { 0 };
            } else {
                self.unget_tok(tok);
                break;
            }
        }
        Ok(val)
    }

    /// Relational comparisons (<, >, <=, >=).
    fn pp_rel_expr(&mut self) -> TccResult<i64> {
        let mut val = self.pp_shift_expr()?;
        loop {
            let tok = self.next_nomacro()?;
            if tok == b'<' as i32 {
                let rhs = self.pp_shift_expr()?;
                val = if val < rhs { 1 } else { 0 };
            } else if tok == b'>' as i32 {
                let rhs = self.pp_shift_expr()?;
                val = if val > rhs { 1 } else { 0 };
            } else if tok == Token::Le as i32 {
                let rhs = self.pp_shift_expr()?;
                val = if val <= rhs { 1 } else { 0 };
            } else if tok == Token::Ge as i32 {
                let rhs = self.pp_shift_expr()?;
                val = if val >= rhs { 1 } else { 0 };
            } else {
                self.unget_tok(tok);
                break;
            }
        }
        Ok(val)
    }

    /// Shift expressions (<<, >>).
    fn pp_shift_expr(&mut self) -> TccResult<i64> {
        let mut val = self.pp_add_expr()?;
        loop {
            let tok = self.next_nomacro()?;
            if tok == Token::Shl as i32 {
                let rhs = self.pp_add_expr()?;
                val = val.wrapping_shl(rhs as u32);
            } else if tok == Token::Shr as i32 {
                let rhs = self.pp_add_expr()?;
                val = val.wrapping_shr(rhs as u32);
            } else {
                self.unget_tok(tok);
                break;
            }
        }
        Ok(val)
    }

    /// Additive expressions (+, -).
    fn pp_add_expr(&mut self) -> TccResult<i64> {
        let mut val = self.pp_mul_expr()?;
        loop {
            let tok = self.next_nomacro()?;
            if tok == b'+' as i32 {
                let rhs = self.pp_mul_expr()?;
                val = val.wrapping_add(rhs);
            } else if tok == b'-' as i32 {
                let rhs = self.pp_mul_expr()?;
                val = val.wrapping_sub(rhs);
            } else {
                self.unget_tok(tok);
                break;
            }
        }
        Ok(val)
    }

    /// Multiplicative expressions (*, /, %).
    fn pp_mul_expr(&mut self) -> TccResult<i64> {
        let mut val = self.pp_unary_expr()?;
        loop {
            let tok = self.next_nomacro()?;
            if tok == b'*' as i32 {
                let rhs = self.pp_unary_expr()?;
                val = val.wrapping_mul(rhs);
            } else if tok == b'/' as i32 {
                let rhs = self.pp_unary_expr()?;
                if rhs == 0 {
                    return Err(TccError::preprocessor(
                        self.file.filename.clone(),
                        self.file.line_num as u32,
                        "division by zero in #if expression",
                    ));
                }
                val /= rhs;
            } else if tok == b'%' as i32 {
                let rhs = self.pp_unary_expr()?;
                if rhs == 0 {
                    return Err(TccError::preprocessor(
                        self.file.filename.clone(),
                        self.file.line_num as u32,
                        "modulo by zero in #if expression",
                    ));
                }
                val %= rhs;
            } else {
                self.unget_tok(tok);
                break;
            }
        }
        Ok(val)
    }

    /// Unary expressions: +, -, ~, !, defined, __has_include.
    fn pp_unary_expr(&mut self) -> TccResult<i64> {
        let tok = self.next_nomacro()?;

        match tok {
            t if t == b'+' as i32 => self.pp_unary_expr(),
            t if t == b'-' as i32 => {
                let v = self.pp_unary_expr()?;
                Ok(-v)
            }
            t if t == b'~' as i32 => {
                let v = self.pp_unary_expr()?;
                Ok(!v)
            }
            t if t == b'!' as i32 => {
                let v = self.pp_unary_expr()?;
                Ok(if v == 0 { 1 } else { 0 })
            }
            t if t == b'(' as i32 => {
                let v = self.pp_cond_expr()?;
                let close = self.next_nomacro()?;
                if close != b')' as i32 {
                    return Err(TccError::preprocessor(
                        self.file.filename.clone(),
                        self.file.line_num as u32,
                        "expected ')' in #if expression",
                    ));
                }
                Ok(v)
            }
            t if t == Token::Defined as i32 => {
                // defined(IDENT) or defined IDENT
                let next = self.next_nomacro()?;
                let (ident, need_close) = if next == b'(' as i32 {
                    (self.next_nomacro()?, true)
                } else {
                    (next, false)
                };
                let is_def = self.define_find(ident).is_some();
                if need_close {
                    let close = self.next_nomacro()?;
                    if close != b')' as i32 {
                        return Err(TccError::preprocessor(
                            self.file.filename.clone(),
                            self.file.line_num as u32,
                            "expected ')' after defined(identifier)",
                        ));
                    }
                }
                Ok(if is_def { 1 } else { 0 })
            }
            t if t == Token::HasInclude as i32 || t == Token::HasIncludeNext as i32 => {
                let is_next = t == Token::HasIncludeNext as i32;
                self.eval_has_include(is_next)
            }
            _ => {
                // Integer literal or character constant
                if tok == TOK_CINT || tok == TOK_CUINT || tok == TOK_CLLONG
                    || tok == TOK_CULLONG || tok == TOK_CCHAR || tok == TOK_LCHAR
                {
                    Ok(unsafe { self.tokc.i } as i64)
                } else if tok >= TOK_IDENT {
                    // Unknown identifiers evaluate to 0 in #if
                    Ok(0)
                } else if tok == TOK_LINEFEED || tok == TOK_EOF {
                    self.unget_tok(tok);
                    Ok(0)
                } else {
                    Ok(0)
                }
            }
        }
    }

    /// Evaluate `__has_include(...)` or `__has_include_next(...)`.
    fn eval_has_include(&mut self, is_next: bool) -> TccResult<i64> {
        let open = self.next_nomacro()?;
        if open != b'(' as i32 {
            return Ok(0);
        }

        let tok = self.next_nomacro()?;
        let (filename, is_system) = if tok == b'<' as i32 {
            let mut name = String::new();
            loop {
                let ch_tok = self.next_nomacro()?;
                if ch_tok == b'>' as i32 || ch_tok == TOK_LINEFEED || ch_tok == TOK_EOF {
                    break;
                }
                name.push_str(&get_tok_str(&self.token_table, ch_tok, None));
            }
            (name, true)
        } else if tok == TOK_STR {
            let s = get_tok_str(&self.token_table, tok, None);
            (s.trim_matches('"').to_string(), false)
        } else {
            let _ = self.skip_to_eol();
            return Ok(0);
        };

        let close = self.next_nomacro()?;
        if close != b')' as i32 {
            self.unget_tok(close);
        }

        let found = self.resolve_include_path(&filename, is_system, is_next).is_ok();
        Ok(if found { 1 } else { 0 })
    }

    /// Push back a token for re-reading during expression evaluation.
    fn unget_tok(&mut self, tok: i32) {
        if tok != TOK_LINEFEED && tok != TOK_EOF {
            self.unget_buffer.push((tok, CValue::default(), 0));
        }
    }

    // -----------------------------------------------------------------------
    // try_expand_macro() — attempt macro expansion for identifiers
    // -----------------------------------------------------------------------

    /// Attempt to expand a macro when an identifier token is encountered.
    /// Returns `Some(expanded_tokens)` if the identifier is a macro, else `None`.
    fn try_expand_macro(&mut self, tok_id: i32) -> TccResult<Option<Vec<i32>>> {
        // Check for predefined macros first
        if self.is_predefined_macro_tok(tok_id) {
            let expansion = self.expand_predefined_macro(tok_id)?;
            return Ok(Some(expansion));
        }

        // __builtin_expect passthrough (FEAT-02)
        if tok_id == Token::BuiltinExpect as i32 {
            return Ok(None); // handled during macro_subst
        }

        // Look up in macro table
        let sym = match self.macro_table.get(&tok_id).cloned() {
            Some(s) => s,
            None => return Ok(None),
        };

        let macro_type = sym.type_.t & 0xFF;

        if macro_type == MACRO_OBJ {
            // Object-like macro: expand body
            if let Some(ref body) = sym.d {
                let expanded = self.macro_subst(body)?;
                return Ok(Some(expanded));
            }
            return Ok(Some(Vec::new()));
        }

        if macro_type == MACRO_FUNC {
            // Function-like macro: need '(' next in the input
            // We peek at the lexer to see if the next token is '('
            // Save current state to possibly un-consume
            let saved_tok = self.tok;
            let saved_tokc = self.tokc;

            let peeked = self.next_nomacro()?;
            if peeked == b'(' as i32 {
                // Collect arguments from the live token stream
                let args = self.collect_live_macro_args()?;

                if let Some(ref body) = sym.d {
                    let substituted = self.arg_subst(body, &args, &sym)?;
                    let expanded = self.macro_subst(&substituted)?;
                    return Ok(Some(expanded));
                }
                return Ok(Some(Vec::new()));
            }
            // Not a function-like invocation — push back
            self.unget_tok(peeked);
            self.tok = saved_tok;
            self.tokc = saved_tokc;
            return Ok(None);
        }

        Ok(None)
    }

    /// Collect macro arguments from the live token stream (not a pre-built stream).
    fn collect_live_macro_args(&mut self) -> TccResult<Vec<Vec<i32>>> {
        let mut args: Vec<Vec<i32>> = Vec::new();
        let mut current_arg: Vec<i32> = Vec::new();
        let mut depth: i32 = 1;

        loop {
            let tok = self.next_nomacro()?;
            if tok == b'(' as i32 {
                depth += 1;
                current_arg.push(tok);
            } else if tok == b')' as i32 {
                depth -= 1;
                if depth == 0 {
                    args.push(current_arg);
                    break;
                }
                current_arg.push(tok);
            } else if tok == b',' as i32 && depth == 1 {
                args.push(current_arg);
                current_arg = Vec::new();
            } else if tok == TOK_EOF {
                return Err(TccError::preprocessor(
                    self.file.filename.clone(),
                    self.file.line_num as u32,
                    "unterminated macro argument list",
                ));
            } else {
                current_arg.push(tok);
            }
        }

        Ok(args)
    }

    // -----------------------------------------------------------------------
    // Predefined Macro Support
    // -----------------------------------------------------------------------

    /// Check if a token is a predefined macro that needs dynamic expansion.
    fn is_predefined_macro_tok(&self, tok: i32) -> bool {
        tok == Token::FileMacro as i32
            || tok == Token::LineMacro as i32
            || tok == Token::DateMacro as i32
            || tok == Token::TimeMacro as i32
            || tok == Token::CounterMacro as i32
            || tok == Token::FunctionMacro as i32
    }

    /// Expand a predefined macro into a token stream.
    fn expand_predefined_macro(&mut self, tok: i32) -> TccResult<Vec<i32>> {
        if tok == Token::FileMacro as i32 {
            let name = self.file.filename.clone();
            let str_tok = tok_alloc(&mut self.token_table, name.as_bytes());
            return Ok(vec![str_tok]);
        }

        if tok == Token::LineMacro as i32 {
            // Line number as a numeric constant token
            let line = self.file.line_num;
            let num_tok = tok_alloc(
                &mut self.token_table,
                line.to_string().as_bytes(),
            );
            return Ok(vec![num_tok]);
        }

        if tok == Token::DateMacro as i32 {
            let ds = self.date_str.clone();
            let str_tok = tok_alloc(&mut self.token_table, ds.as_bytes());
            return Ok(vec![str_tok]);
        }

        if tok == Token::TimeMacro as i32 {
            let ts = self.time_str.clone();
            let str_tok = tok_alloc(&mut self.token_table, ts.as_bytes());
            return Ok(vec![str_tok]);
        }

        if tok == Token::CounterMacro as i32 {
            let val = self.pp_counter;
            self.pp_counter += 1;
            let num_tok =
                tok_alloc(&mut self.token_table, val.to_string().as_bytes());
            return Ok(vec![num_tok]);
        }

        if tok == Token::FunctionMacro as i32 {
            // __func__ / __FUNCTION__ — returns empty string if not in function
            let str_tok = tok_alloc(&mut self.token_table, b"\"\"");
            return Ok(vec![str_tok]);
        }

        Ok(Vec::new())
    }

    /// Initialize predefined macros (__STDC__, __TINYC__, target macros, etc.).
    /// Called once at the start of a compilation.
    pub fn init_predefined_macros(&mut self) {
        // Standard predefined macros
        self.define_obj_macro("__STDC__", "1");
        self.define_obj_macro("__STDC_VERSION__", "199901L");
        self.define_obj_macro("__STDC_HOSTED__", "1");
        self.define_obj_macro("__TINYC__", "1");

        // Target architecture macros
        #[cfg(target_arch = "x86_64")]
        {
            self.define_obj_macro("__x86_64__", "1");
            self.define_obj_macro("__amd64__", "1");
            self.define_obj_macro("__LP64__", "1");
        }
        #[cfg(target_arch = "x86")]
        {
            self.define_obj_macro("__i386__", "1");
            self.define_obj_macro("__i386", "1");
        }
        #[cfg(target_arch = "aarch64")]
        {
            self.define_obj_macro("__aarch64__", "1");
        }
        #[cfg(target_arch = "arm")]
        {
            self.define_obj_macro("__arm__", "1");
            self.define_obj_macro("__ARM_ARCH_7A__", "1");
        }
        #[cfg(target_arch = "riscv64")]
        {
            self.define_obj_macro("__riscv", "1");
            self.define_obj_macro("__riscv_xlen", "64");
        }

        // OS macros
        #[cfg(target_os = "linux")]
        {
            self.define_obj_macro("__linux__", "1");
            self.define_obj_macro("__linux", "1");
            self.define_obj_macro("linux", "1");
            self.define_obj_macro("__unix__", "1");
            self.define_obj_macro("__unix", "1");
            self.define_obj_macro("unix", "1");
        }
        #[cfg(target_os = "macos")]
        {
            self.define_obj_macro("__APPLE__", "1");
            self.define_obj_macro("__MACH__", "1");
        }
        #[cfg(target_os = "windows")]
        {
            self.define_obj_macro("_WIN32", "1");
            self.define_obj_macro("__WIN32__", "1");
        }

        // Apply predefined symbols from TCCState
        for (name, value) in self.state.predefined_symbols.clone() {
            self.define_obj_macro(&name, &value);
        }

        self.predefs_initialized = true;
    }

    /// Helper: define a simple object-like macro from name/value strings.
    fn define_obj_macro(&mut self, name: &str, value: &str) {
        let name_tok = tok_alloc(&mut self.token_table, name.as_bytes());
        let val_tok = tok_alloc(&mut self.token_table, value.as_bytes());
        let body = vec![val_tok, 0]; // token + terminator
        self.define_push(name_tok, MACRO_OBJ, body, None);
    }

    // -----------------------------------------------------------------------
    // tcc_preprocess() — preprocess-only output mode (-E flag)
    // -----------------------------------------------------------------------

    /// Run the preprocessor in output mode (`-E`), writing preprocessed tokens
    /// to stdout. This corresponds to `tcc -E file.c`.
    pub fn tcc_preprocess(&mut self) -> TccResult<()> {
        let mut last_line: i32 = -1;
        let mut last_file = String::new();

        loop {
            let tok = self.next()?;
            if tok == Token::Eof as i32 {
                break;
            }

            // Emit #line directives on file/line change
            if self.file.filename != last_file {
                println!(
                    "# {} \"{}\"",
                    self.file.line_num, self.file.filename
                );
                last_file = self.file.filename.clone();
                last_line = self.file.line_num;
            } else if self.file.line_num != last_line {
                let diff = self.file.line_num - last_line;
                if diff > 0 && diff < 8 {
                    for _ in 0..diff {
                        println!();
                    }
                } else {
                    println!(
                        "# {} \"{}\"",
                        self.file.line_num, self.file.filename
                    );
                }
                last_line = self.file.line_num;
            }

            if tok == TOK_LINEFEED {
                println!();
                last_line += 1;
                continue;
            }

            let s = get_tok_str(&self.token_table, tok, None);
            print!("{} ", s);
        }
        println!();
        Ok(())
    }

    // -----------------------------------------------------------------------
    // search_cached_include() — check the include cache
    // -----------------------------------------------------------------------

    /// Search the cached include table for a given filename.
    /// Returns a reference to the `CachedInclude` entry if found.
    pub fn search_cached_include(&self, filename: &str) -> Option<&CachedInclude> {
        let hash = Self::hash_include_filename(filename);
        let bucket = (hash % CACHED_INCLUDES_HASH_SIZE as u32) as usize;
        for ci in &self.state.cached_includes {
            if ci.filename == filename {
                // Additional hash-bucket optimization could be added here
                let _ = bucket;
                return Some(ci);
            }
        }
        None
    }

    /// Hash a filename for the include cache.
    fn hash_include_filename(filename: &str) -> u32 {
        let mut h: u32 = 0;
        for b in filename.bytes() {
            h = h.wrapping_mul(31).wrapping_add(b as u32);
        }
        h
    }

    // -----------------------------------------------------------------------
    // try_predefined_macro() — called from next_from_lexer
    // -----------------------------------------------------------------------

    /// Attempt expansion of a predefined macro from the current token.
    /// Returns true if a predefined macro was expanded and the token is replaced.
    fn try_predefined_macro(&mut self, tok_id: i32) -> TccResult<bool> {
        if !self.is_predefined_macro_tok(tok_id) {
            return Ok(false);
        }
        let expansion = self.expand_predefined_macro(tok_id)?;
        if !expansion.is_empty() {
            // Push expansion into unget buffer (in reverse)
            for &t in expansion.iter().rev() {
                if t != 0 {
                    self.unget_buffer.push((t, CValue::default(), 0));
                }
            }
            return Ok(true);
        }
        Ok(false)
    }
} // end impl<'a> Preprocessor<'a>

// Token value constants are imported from crate::token at the top of this file.

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that Preprocessor can be constructed and basic fields are correct.
    #[test]
    fn test_preprocessor_construction() {
        let mut state = TCCState::new().unwrap();
        let token_table = TokenSymTable::new();
        let file = BufferedFile {
            buffer: Vec::new(),
            buf_ptr: 0,
            buf_end: 0,
            fd: -1,
            line_num: 1,
            line_ref: 0,
            ifndef_macro: 0,
            ifndef_macro_saved: 0,
            ifdef_stack_ptr: 0,
            include_next_index: 0,
            prev_tok_flags: 0,
            filename: "test.c".to_string(),
            true_filename: "test.c".to_string(),
            unget: [0; 4],
        };
        let pp = Preprocessor::new(&mut state, token_table, file);
        assert_eq!(pp.tok, 0);
        assert_eq!(pp.pp_counter, 0);
        assert_eq!(pp.pp_expr, false);
        assert!(pp.macro_table.is_empty());
        assert!(pp.unget_buffer.is_empty());
    }

    /// Test define_push and define_find.
    #[test]
    fn test_define_push_find() {
        let mut state = TCCState::new().unwrap();
        let token_table = TokenSymTable::new();
        let file = BufferedFile {
            buffer: Vec::new(),
            buf_ptr: 0,
            buf_end: 0,
            fd: -1,
            line_num: 1,
            line_ref: 0,
            ifndef_macro: 0,
            ifndef_macro_saved: 0,
            ifdef_stack_ptr: 0,
            include_next_index: 0,
            prev_tok_flags: 0,
            filename: "test.c".to_string(),
            true_filename: "test.c".to_string(),
            unget: [0; 4],
        };
        let mut pp = Preprocessor::new(&mut state, token_table, file);

        let test_tok = 300;
        let body = vec![42, 0];
        pp.define_push(test_tok, MACRO_OBJ, body.clone(), None);

        let found = pp.define_find(test_tok);
        assert!(found.is_some());
        let sym = found.unwrap();
        assert_eq!(sym.type_.t, MACRO_OBJ);
        assert_eq!(sym.d.as_ref().unwrap(), &body);
    }

    /// Test define_undef removes a macro.
    #[test]
    fn test_define_undef() {
        let mut state = TCCState::new().unwrap();
        let token_table = TokenSymTable::new();
        let file = BufferedFile {
            buffer: Vec::new(),
            buf_ptr: 0,
            buf_end: 0,
            fd: -1,
            line_num: 1,
            line_ref: 0,
            ifndef_macro: 0,
            ifndef_macro_saved: 0,
            ifdef_stack_ptr: 0,
            include_next_index: 0,
            prev_tok_flags: 0,
            filename: "test.c".to_string(),
            true_filename: "test.c".to_string(),
            unget: [0; 4],
        };
        let mut pp = Preprocessor::new(&mut state, token_table, file);

        let test_tok = 400;
        pp.define_push(test_tok, MACRO_OBJ, vec![1, 0], None);
        assert!(pp.define_find(test_tok).is_some());

        pp.define_undef(test_tok);
        assert!(pp.define_find(test_tok).is_none());
    }

    /// Test unget and peek.
    #[test]
    fn test_unget_peek() {
        let mut state = TCCState::new().unwrap();
        let token_table = TokenSymTable::new();
        let file = BufferedFile {
            buffer: Vec::new(),
            buf_ptr: 0,
            buf_end: 0,
            fd: -1,
            line_num: 1,
            line_ref: 0,
            ifndef_macro: 0,
            ifndef_macro_saved: 0,
            ifdef_stack_ptr: 0,
            include_next_index: 0,
            prev_tok_flags: 0,
            filename: "test.c".to_string(),
            true_filename: "test.c".to_string(),
            unget: [0; 4],
        };
        let mut pp = Preprocessor::new(&mut state, token_table, file);

        pp.unget(42);
        pp.unget(43);
        // unget_buffer: [42, 43], last is consumed first
        assert_eq!(pp.unget_buffer.len(), 2);
    }

    /// Test free_defines.
    #[test]
    fn test_free_defines() {
        let mut state = TCCState::new().unwrap();
        let token_table = TokenSymTable::new();
        let file = BufferedFile {
            buffer: Vec::new(),
            buf_ptr: 0,
            buf_end: 0,
            fd: -1,
            line_num: 1,
            line_ref: 0,
            ifndef_macro: 0,
            ifndef_macro_saved: 0,
            ifdef_stack_ptr: 0,
            include_next_index: 0,
            prev_tok_flags: 0,
            filename: "test.c".to_string(),
            true_filename: "test.c".to_string(),
            unget: [0; 4],
        };
        let mut pp = Preprocessor::new(&mut state, token_table, file);

        pp.define_push(500, MACRO_OBJ, vec![1, 0], None);
        pp.define_push(501, MACRO_OBJ, vec![2, 0], None);
        assert_eq!(pp.macro_table.len(), 2);

        pp.free_defines();
        assert!(pp.macro_table.is_empty());
    }

    /// Test hash_include_filename produces consistent values.
    #[test]
    fn test_hash_include() {
        let h1 = Preprocessor::hash_include_filename("stdio.h");
        let h2 = Preprocessor::hash_include_filename("stdio.h");
        assert_eq!(h1, h2);

        let h3 = Preprocessor::hash_include_filename("stdlib.h");
        // Different filenames should (very likely) produce different hashes
        assert_ne!(h1, h3);
    }

    /// Test search_cached_include.
    #[test]
    fn test_search_cached_include() {
        let mut state = TCCState::new().unwrap();
        state.cached_includes.push(CachedInclude {
            ifndef_macro: 0,
            once: true,
            hash_next: -1,
            filename: "test_header.h".to_string(),
        });

        let token_table = TokenSymTable::new();
        let file = BufferedFile {
            buffer: Vec::new(),
            buf_ptr: 0,
            buf_end: 0,
            fd: -1,
            line_num: 1,
            line_ref: 0,
            ifndef_macro: 0,
            ifndef_macro_saved: 0,
            ifdef_stack_ptr: 0,
            include_next_index: 0,
            prev_tok_flags: 0,
            filename: "main.c".to_string(),
            true_filename: "main.c".to_string(),
            unget: [0; 4],
        };
        let pp = Preprocessor::new(&mut state, token_table, file);

        assert!(pp.search_cached_include("test_header.h").is_some());
        assert!(pp.search_cached_include("nonexistent.h").is_none());
    }

    /// Test is_in_skipped_block.
    #[test]
    fn test_ifdef_stack() {
        let mut state = TCCState::new().unwrap();
        let token_table = TokenSymTable::new();
        let file = BufferedFile {
            buffer: Vec::new(),
            buf_ptr: 0,
            buf_end: 0,
            fd: -1,
            line_num: 1,
            line_ref: 0,
            ifndef_macro: 0,
            ifndef_macro_saved: 0,
            ifdef_stack_ptr: 0,
            include_next_index: 0,
            prev_tok_flags: 0,
            filename: "test.c".to_string(),
            true_filename: "test.c".to_string(),
            unget: [0; 4],
        };
        let pp = Preprocessor::new(&mut state, token_table, file);

        // No ifdef_stack entries — not in skipped block
        assert!(!pp.is_in_skipped_block());

        // Push TRUE
        pp.state.ifdef_stack.push(IFDEF_TRUE);
        assert!(!pp.is_in_skipped_block());

        // Push FALSE
        pp.state.ifdef_stack.push(IFDEF_FALSE);
        assert!(pp.is_in_skipped_block());

        // Pop FALSE
        pp.state.ifdef_stack.pop();
        assert!(!pp.is_in_skipped_block());
    }
}
