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
    get_tok_str, tok_alloc, tok_register_alias, Lexer, TokenSymTable,
    PARSE_FLAG_ASM_FILE, PARSE_FLAG_LINEFEED, PARSE_FLAG_PREPROCESS,
    PARSE_FLAG_TOK_NUM, PARSE_FLAG_TOK_STR, TOK_FLAG_BOF, TOK_FLAG_BOL,
    TOK_FLAG_ENDIF, TOK_FLAG_SPC,
};
use crate::TCCState;
use crate::token::{
    Token, KEYWORDS, TOK_CCHAR, TOK_CDOUBLE, TOK_CFLOAT, TOK_CINT,
    TOK_CLDOUBLE, TOK_CLLONG, TOK_CLONG, TOK_CUINT, TOK_CULLONG,
    TOK_CULONG, TOK_DOTS, TOK_EOF, TOK_IDENT, TOK_LCHAR, TOK_LINEFEED,
    TOK_EQ, TOK_GE, TOK_GT, TOK_LAND, TOK_LE, TOK_LOR, TOK_LT, TOK_NE,
    TOK_SAR, TOK_SHL,
    TOK_LSTR, TOK_NOSUBST, TOK_PPNUM, TOK_PPSTR, TOK_STR, TOK_TWOSHARPS,
};
use crate::types::{
    BufferedFile, CType, CValue, CachedInclude,
    Sym, SymAttr, FuncAttr,
    CACHED_INCLUDES_HASH_SIZE, IFDEF_STACK_SIZE, MACRO_FUNC,
    MACRO_OBJ, PACK_STACK_SIZE,
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

/// Base value for encoding macro parameter references in a macro body.
///
/// During `parse_define()`, when a token in the macro replacement list
/// matches a formal parameter, it is stored as `MACRO_PARAM_BASE + param_index`
/// instead of the raw token ID.  During `arg_subst()`, tokens in the range
/// `[MACRO_PARAM_BASE, MACRO_PARAM_BASE + 256)` are recognised as parameter
/// placeholders and substituted with the corresponding actual argument.
///
/// The value `0x4000_0000` (bit 30 only) is chosen to be far above any
/// valid token ID (real token IDs are `< 0x10000` in practice) and
/// below `i32::MAX` to avoid sign issues.  Crucially, it does NOT
/// overlap with `STREAM_SPC_BIT` (bit 29), so both can coexist in the
/// same `i32` stream entry without interference.
const MACRO_PARAM_BASE: i32 = 0x4000_0000;

/// Bit flag packed into token-stream entries to indicate that the token
/// was preceded by whitespace in the source.  The preprocessor `-E`
/// output uses this to reproduce the original spacing.  Bit 29
/// (`0x2000_0000`) is chosen so that it does NOT conflict with
/// `MACRO_PARAM_BASE` (bit 30, `0x4000_0000`) or normal token IDs
/// (`< 0x10000`).
const STREAM_SPC_BIT: i32 = 0x2000_0000;

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
/// Value produced by `#if` expression evaluation.  Carries both the
/// computed `i64` value and a flag indicating whether the value
/// originated from an unsigned context (e.g. `U`-suffixed literal,
/// hex literal exceeding `i64::MAX`, or propagated through arithmetic
/// with an unsigned operand).  This matches the C preprocessor's
/// "usual arithmetic conversions" for `#if` expressions.
#[derive(Copy, Clone, Debug)]
struct PPVal {
    val: i64,
    unsigned: bool,
}

impl PPVal {
    /// Create a signed (default) PPVal.
    #[inline]
    fn signed(val: i64) -> Self {
        PPVal { val, unsigned: false }
    }
    /// Create a PPVal with an explicit unsigned flag.
    #[inline]
    fn new(val: i64, unsigned: bool) -> Self {
        PPVal { val, unsigned }
    }
}

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

    /// Set to `true` by the number parser when the most recently scanned
    /// integer literal had an explicit `U`/`u` suffix.  Used by the
    /// `#if` expression evaluator to determine unsigned semantics.
    pub tok_explicit_unsigned: bool,

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

    /// Scratch buffer used by `read_token_value` to hold string data
    /// (for `TOK_PPNUM`, `TOK_STR`, etc.) read back from a token stream.
    /// The data is valid until the next call to `read_token_value`.
    pp_str_buf: Vec<u8>,

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

    /// Lookahead character carried over from the previous `Lexer` instance.
    /// `None` means the very first token read should use `Lexer::new()` (which
    /// primes the first character).  `Some(ch)` means the previous lexer left
    /// this character un-consumed; the next lexer should be created with
    /// `Lexer::resume(file, ch)` to avoid losing it.
    lexer_ch: Option<i32>,

    /// Set of macro token IDs currently being expanded (the "painted blue"
    /// set per C99 6.10.3.4).  A macro whose ID is in this set must NOT be
    /// recursively expanded — it is output verbatim instead.  Entries are
    /// pushed when expansion of a macro begins and popped when it completes.
    noexpand_set: std::collections::HashSet<i32>,

    /// Spelling-preserving tok_alloc ID for the most recent identifier/keyword
    /// read directly from the lexer.  For regular identifiers this equals
    /// `self.tok`.  For keyword aliases (e.g. `__noreturn__` vs `_Noreturn`),
    /// this is the alias entry's position-based ID, which preserves the
    /// original spelling for `##` token pasting.  Set in `next_nomacro()`,
    /// consumed by `tok_to_stream_id()`.
    last_ident_alloc_id: i32,

    /// Extra spaces to emit before the next token in `-E` output mode.
    ///
    /// When a macro invocation that had whitespace before it (SPC flag)
    /// expands to nothing (empty expansion), the SPC would normally be
    /// lost because there is no expansion token to carry it.  C TCC handles
    /// this via `PARSE_FLAG_SPACES` which returns space characters as actual
    /// tokens accumulated in a `white[]` buffer.  Our implementation instead
    /// uses a single-bit SPC flag per token, so we track "consumed but
    /// undelivered" spaces here.  `run_preprocess_only()` reads this counter
    /// and emits the additional spaces.
    pub extra_spaces: u8,
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
            tok_explicit_unsigned: false,
            tok_flags: TOK_FLAG_BOL | TOK_FLAG_BOF,
            parse_flags: 0,
            unget_buffer: Vec::new(),
            macro_ptr: None,
            macro_stack: Vec::new(),
            pp_counter: 0,
            pp_expr: false,
            pp_str_buf: Vec::new(),
            macro_depth: 0,
            file,
            keyword_map,
            date_str,
            time_str,
            predefs_initialized: false,
            lexer_ch: None,
            noexpand_set: std::collections::HashSet::new(),
            last_ident_alloc_id: 0,
            extra_spaces: 0,
        };

        // Register keywords in the token table
        pp.init_keywords();

        pp
    }

    /// Initialize keyword tokens in the symbol table.
    ///
    /// Primary keywords (one per `Token` variant) are registered first, in
    /// enum-discriminant order, so that `tok_alloc` auto-assigns IDs that
    /// match the `Token` enum values exactly.  Aliases (e.g. `__asm__` for
    /// `asm`) are then registered via `tok_register_alias` so hash lookups
    /// return the same token ID as the primary.
    fn init_keywords(&mut self) {
        use std::collections::HashSet;

        let mut registered = HashSet::<i32>::new();
        let mut primaries: Vec<(&str, i32)> = Vec::new();
        let mut aliases: Vec<(&str, i32)> = Vec::new();

        for &(name, token) in KEYWORDS.iter() {
            let tok_val = token as i32;
            if registered.insert(tok_val) {
                // First occurrence of this Token variant → primary keyword
                primaries.push((name, tok_val));
            } else {
                // Subsequent occurrence → alias
                aliases.push((name, tok_val));
            }
        }

        // Sort primaries by token value so tok_alloc assigns sequential IDs
        // that exactly match the Token enum discriminants.
        primaries.sort_by_key(|&(_, v)| v);

        for (name, _) in &primaries {
            tok_alloc(&mut self.token_table, name.as_bytes());
        }

        // Register aliases that resolve to the same token ID as their primary.
        for (name, primary_tok) in &aliases {
            tok_register_alias(&mut self.token_table, name.as_bytes(), *primary_tok);
        }

        // Sync tok_ident with table_ident length so that future tok_alloc
        // calls for user identifiers get IDs whose index into table_ident
        // matches (tok - TOK_IDENT).
        self.token_table.tok_ident =
            crate::token::TOK_IDENT + self.token_table.table_ident.len() as i32;
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
        // 1. Check unget buffer first.
        //
        // In C TCC, unget_tok() pushes the token as a tiny macro stream
        // via begin_macro(), so that subsequent next() calls re-enter the
        // full macro-expansion path.  Our Rust port uses a simple Vec
        // buffer instead.  To match the C behaviour we must still run the
        // macro expansion / rescan check for identifier tokens popped from
        // the unget buffer (otherwise tokens pushed back by
        // try_expand_macro()'s "no '(' found" path are returned as-is,
        // preventing proper rescanning — this broke pp/07).
        if let Some((tok, tokc, flags)) = self.unget_buffer.pop() {
            self.tok = tok;
            self.tokc = tokc;
            self.tok_flags = flags;

            // Rescan for macro expansion on the popped token, matching
            // the same logic applied to tokens read from macro_ptr.
            if self.tok >= TOK_IDENT
                && (self.parse_flags & PARSE_FLAG_PREPROCESS) != 0
            {
                let call_site_spc = (self.tok_flags & TOK_FLAG_SPC) != 0;
                if let Some(mut expanded) = self.try_expand_macro(self.tok)? {
                    if !expanded.is_empty() {
                        // REPLACE the first token's SPC with the
                        // call-site SPC so invocation spacing overrides
                        // internal expansion spacing.
                        let spc_bit = if call_site_spc { STREAM_SPC_BIT } else { 0 };
                        expanded[0] = (expanded[0] & !STREAM_SPC_BIT) | spc_bit;
                        if let Some(current) = self.macro_ptr.take() {
                            self.macro_stack.push(current);
                        }
                        self.macro_ptr = Some((expanded, 0));
                        return self.next();
                    }
                    // Empty expansion from unget buffer rescan —
                    // don't accumulate extra_spaces here; same
                    // reasoning as the macro_ptr rescan path.
                    return self.next();
                }
            }

            return Ok(self.tok);
        }

        // 2. Check macro expansion stream
        if let Some((ref stream, ref mut pos)) = self.macro_ptr {
            if *pos < stream.len() {
                let raw = stream[*pos];
                *pos += 1;

                // Unpack the space flag from the stream entry.
                let has_spc = (raw & STREAM_SPC_BIT) != 0;
                let tok = raw & !STREAM_SPC_BIT;

                if tok == 0 {
                    // End of macro stream — pop back to previous context
                    self.macro_ptr = self.macro_stack.pop();
                    return self.next();
                }

                // TOK_NOSUBST: consume the marker silently, read the next
                // token, and set a flag preventing macro expansion of it.
                if tok == TOK_NOSUBST {
                    if *pos < stream.len() {
                        let raw2 = stream[*pos];
                        *pos += 1;
                        let has_spc2 = (raw2 & STREAM_SPC_BIT) != 0;
                        let real_tok = raw2 & !STREAM_SPC_BIT;
                        self.tok = real_tok;
                        self.tokc = CValue::default();
                        self.tok_flags = if has_spc2 { TOK_FLAG_SPC } else { 0 };
                        // Read associated value if needed
                        if self.macro_ptr.is_some() {
                            let mut mp = self.macro_ptr.take().unwrap();
                            {
                                let (ref stream, ref mut pos) = mp;
                                self.read_token_value(stream, pos);
                            }
                            self.macro_ptr = Some(mp);
                        }
                        // Return directly — skip macro expansion check in
                        // next_from_lexer() because this token is "painted blue".
                        return Ok(self.tok);
                    }
                    // No token after marker — stream exhausted
                    self.macro_ptr = self.macro_stack.pop();
                    return self.next();
                }

                self.tok = tok;
                self.tokc = CValue::default();
                // Set tok_flags from the packed stream SPC bit.
                self.tok_flags = if has_spc { TOK_FLAG_SPC } else { 0 };

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

                // --- Rescan for macro expansion (C99 6.10.3.4) ---
                // Tokens produced by macro_ptr may themselves be macros.
                // For example, `#define g f` followed by `g(1)` produces
                // `f` in macro_ptr; `f` must be re-checked and, if it is
                // a function-like macro, combined with the subsequent `(`
                // from the lexer (or another macro_ptr frame).
                if self.tok >= TOK_IDENT
                    && (self.parse_flags & PARSE_FLAG_PREPROCESS) != 0
                {
                    let call_site_spc = (self.tok_flags & TOK_FLAG_SPC) != 0;
                    if let Some(mut expanded) = self.try_expand_macro(self.tok)? {
                        if !expanded.is_empty() {
                            // REPLACE the first token's SPC with the
                            // call-site SPC (same logic as in next_from_lexer).
                            let spc_bit = if call_site_spc { STREAM_SPC_BIT } else { 0 };
                            expanded[0] = (expanded[0] & !STREAM_SPC_BIT) | spc_bit;
                            // Push current macro_ptr (if any) and install
                            // the new expansion.
                            if let Some(current) = self.macro_ptr.take() {
                                self.macro_stack.push(current);
                            }
                            self.macro_ptr = Some((expanded, 0));
                            return self.next();
                        }
                        // Empty expansion during macro_ptr rescan —
                        // don't accumulate extra_spaces here because the
                        // whitespace model inside expansion streams is
                        // handled by SPC flags, not accumulated spaces.
                        // (extra_spaces is only for top-level source
                        // empty expansions, handled in next_from_lexer.)
                        return self.next();
                    }
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
            // Save tok_flags BEFORE reading the next token.  The lexer
            // clears tok_flags after producing a token, but the
            // preprocessor needs to know whether the PREVIOUS position
            // was beginning-of-line (BOL) in order to recognise `#`
            // directives.  This matches the C implementation's
            // `saved_tok_flags` pattern in `next()`.
            let saved_tok_flags = self.tok_flags;

            // Create a lexer for the current file.
            // On the very first call `lexer_ch` is `None`, so we use
            // `Lexer::new()` which primes the first character via
            // `next_char()`.  On subsequent calls we use
            // `Lexer::resume()` which accepts the lookahead character
            // left over from the previous lexer instance, avoiding the
            // character-eating bug where `next_char()` would skip the
            // character the previous lexer already read but did not
            // consume.
            let mut lexer = match self.lexer_ch {
                Some(ch) => {
                    let mut l = Lexer::resume(&mut self.file, ch);
                    // Inherit the preprocessor's parse_flags (including
                    // or excluding TOK_NUM/TOK_STR as set by the caller).
                    // Always ensure LINEFEED is set for directive detection.
                    l.parse_flags = self.parse_flags | PARSE_FLAG_LINEFEED;
                    l.tok_flags = self.tok_flags;
                    l
                }
                None => {
                    let mut l = Lexer::new(&mut self.file);
                    l.parse_flags = self.parse_flags | PARSE_FLAG_LINEFEED;
                    l.tok_flags = self.tok_flags;
                    l
                }
            };

            lexer.next_raw(&mut self.token_table)?;

            self.tok = lexer.tok;
            self.tokc = lexer.tokc;
            self.tok_flags = lexer.tok_flags;
            self.tok_explicit_unsigned = lexer.tok_explicit_unsigned;

            // Save the spelling-preserving tok_alloc ID from the lexer.
            // For keyword aliases (e.g. `__noreturn__` → Token::Noreturn),
            // this ID preserves the original spelling so `tok_to_stream_id()`
            // can store the alias entry in macro body/arg streams, making
            // `##` token pasting use the correct text.
            self.last_ident_alloc_id = lexer.ident_alloc_id;

            // For tokens with string data (TOK_PPNUM, TOK_PPSTR,
            // TOK_STR, TOK_LSTR), the tokc.str_val pointer targets
            // the lexer's tok_buf which will be freed when the lexer
            // is dropped.  Copy the data to our persistent pp_str_buf
            // and update the pointer.
            match self.tok {
                t if t == TOK_PPNUM || t == TOK_PPSTR
                    || t == TOK_STR || t == TOK_LSTR =>
                {
                    self.pp_str_buf = lexer.tok_buf.data.clone();
                    self.tokc.str_val.data = self.pp_str_buf.as_ptr();
                    self.tokc.str_val.size = self.pp_str_buf.len() as i32;
                }
                _ => {}
            }

            // Save the lexer's lookahead character so the next
            // iteration can resume without losing it.
            self.lexer_ch = Some(lexer.ch);
            self.file = lexer.file.clone();

            // Handle preprocessor directives at beginning of line.
            // Use `saved_tok_flags` (the state BEFORE the lexer consumed
            // the token) to check BOL, because the lexer zeroes
            // tok_flags after producing the `#` token.
            if self.tok == b'#' as i32
                && (saved_tok_flags & TOK_FLAG_BOL) != 0
                && (self.parse_flags & PARSE_FLAG_PREPROCESS) != 0
            {
                self.preprocess()?;
                continue;
            }

            // Skip tokens inside inactive `#if`/`#else` blocks.
            if (self.parse_flags & PARSE_FLAG_PREPROCESS) != 0
                && self.is_in_skipped_block()
            {
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
                // Capture the call-site SPC BEFORE try_expand_macro()
                // may alter tok_flags (e.g. by reading ahead for `(`).
                let call_site_spc = (self.tok_flags & TOK_FLAG_SPC) != 0;

                let _try_tok = self.tok;
                if let Some(mut expanded) = self.try_expand_macro(self.tok)? {
                    
                    if !expanded.is_empty() {
                        // REPLACE the first expansion token's SPC with
                        // the call-site SPC so that invocation-site spacing
                        // overrides internal expansion spacing.
                        let spc_bit = if call_site_spc { STREAM_SPC_BIT } else { 0 };
                        expanded[0] = (expanded[0] & !STREAM_SPC_BIT) | spc_bit;
                        // Push current macro_ptr onto stack and set new stream
                        if let Some(current) = self.macro_ptr.take() {
                            self.macro_stack.push(current);
                        }
                        self.macro_ptr = Some((expanded, 0));
                        return self.next();
                    }
                    // Macro expanded to empty — the macro invocation is
                    // consumed without producing any token.  If there was
                    // whitespace before the macro name (call_site_spc), that
                    // space would normally be lost because there is no
                    // expansion token to carry it.  Record it so that
                    // `run_preprocess_only()` can emit the extra space.
                    if call_site_spc {
                        self.extra_spaces = self.extra_spaces.saturating_add(1);
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
                // String tokens: length followed by data words.
                // Reconstruct the string into `pp_str_buf` so that
                // callers (especially the `#if` expression evaluator)
                // can access the text content.
                if *pos < stream.len() {
                    let len = stream[*pos] as usize;
                    *pos += 1;
                    let words = len.div_ceil(4);
                    self.pp_str_buf.clear();
                    for w in 0..words {
                        if *pos < stream.len() {
                            let word = stream[*pos] as u32;
                            *pos += 1;
                            for b in 0..4 {
                                let idx = w * 4 + b;
                                if idx < len {
                                    self.pp_str_buf.push(((word >> (b * 8)) & 0xFF) as u8);
                                }
                            }
                        }
                    }
                    // Also set str_val to point to the buffer so
                    // get_tok_str can access it.
                    self.tokc.str_val.size = self.pp_str_buf.len() as i32;
                    self.tokc.str_val.data = self.pp_str_buf.as_ptr();
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
        // In assembly file mode (.S), a `#` at the start of a line that is
        // NOT followed by an identifier or number is a line comment (GAS
        // syntax).  We detect this cheaply by peeking at the next
        // non-whitespace character in the buffer and skipping to EOL if it
        // cannot begin a preprocessor directive.
        if (self.parse_flags & PARSE_FLAG_ASM_FILE) != 0 {
            // Peek past horizontal whitespace after the `#`.
            let buf = &self.file.buffer;
            let mut pos = self.file.buf_ptr;
            while pos < self.file.buf_end {
                let ch = buf[pos];
                if ch == b' ' || ch == b'\t' {
                    pos += 1;
                } else {
                    break;
                }
            }
            let peek_ch = if pos < self.file.buf_end { buf[pos] } else { 0 };
            // A valid directive starts with a letter (keyword) or digit
            // (line marker like `# 10`).  Anything else (backtick, single
            // quote, etc.) is a GAS-style comment — skip to EOL.
            if !(peek_ch.is_ascii_alphabetic() || peek_ch == b'_' || peek_ch.is_ascii_digit()) {
                // Skip rest of the line using raw char scan
                self.skip_to_eol_raw();
                return Ok(());
            }
        }

        // Read the directive keyword (without macro expansion)
        let saved_parse_flags = self.parse_flags;
        self.parse_flags = PARSE_FLAG_LINEFEED
            | PARSE_FLAG_TOK_NUM
            | PARSE_FLAG_TOK_STR;
        if (saved_parse_flags & PARSE_FLAG_ASM_FILE) != 0 {
            self.parse_flags |= PARSE_FLAG_ASM_FILE;
        }

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
                    // Skip any other directive in a false block.
                    // In ASM_FILE mode, use raw skip because the line may
                    // contain characters the C lexer cannot tokenise.
                    if (saved_parse_flags & PARSE_FLAG_ASM_FILE) != 0 {
                        self.skip_to_eol_raw();
                    } else {
                        self.skip_to_eol()?;
                    }
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
                // Unknown directive.
                // In ASM_FILE mode (`.S`), `#` at start of line followed
                // by a non-directive identifier is a GAS line comment —
                // silently skip to end of line using raw char scan.
                if (saved_parse_flags & PARSE_FLAG_ASM_FILE) != 0 {
                    self.skip_to_eol_raw();
                } else if self.state.gnu_ext || directive_tok >= TOK_IDENT {
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
        // Check unget buffer first so that tokens pushed back by the
        // expression evaluator (e.g. TOK_LINEFEED at end of `#if`
        // expression) are re-consumed before reading from the lexer.
        if let Some((tok, tokc, flags)) = self.unget_buffer.pop() {
            self.tok = tok;
            self.tokc = tokc;
            self.tok_flags = flags;
            return Ok(self.tok);
        }

        // Loop to handle directives transparently.  In C TCC,
        // `next_nomacro1()` processes `#if`/`#else`/`#endif` when `#`
        // appears at beginning-of-line (BOL) with PARSE_FLAG_PREPROCESS
        // set — even during macro argument collection.  We replicate
        // that behaviour here so that constructs like
        //   TRACE( ARG_1,  #if 1  ARG_2,  #else  wrong,  #endif  ARG_3 )
        // work correctly: the `#if`/`#else`/`#endif` are evaluated
        // inline and only the active branch's tokens are returned to
        // the argument collector.
        loop {
            // Save tok_flags BEFORE reading so we can check BOL.
            // The lexer clears BOL after producing the `#` token.
            let saved_tok_flags = self.tok_flags;

            let mut lexer = match self.lexer_ch {
                Some(ch) => {
                    let mut l = Lexer::resume(&mut self.file, ch);
                    // Inherit parse_flags; always ensure LINEFEED for
                    // directive detection.
                    l.parse_flags = self.parse_flags | PARSE_FLAG_LINEFEED;
                    l.tok_flags = self.tok_flags;
                    l
                }
                None => {
                    let mut l = Lexer::new(&mut self.file);
                    l.parse_flags = self.parse_flags | PARSE_FLAG_LINEFEED;
                    l.tok_flags = self.tok_flags;
                    l
                }
            };

            lexer.next_raw(&mut self.token_table)?;

            self.tok = lexer.tok;
            self.tokc = lexer.tokc;
            self.tok_flags = lexer.tok_flags;
            self.tok_explicit_unsigned = lexer.tok_explicit_unsigned;

            // Propagate the spelling-preserving alias ID from the lexer.
            self.last_ident_alloc_id = lexer.ident_alloc_id;

            // Copy string data from the lexer's tok_buf into our
            // persistent pp_str_buf so that tokc.str_val stays valid.
            match self.tok {
                t if t == TOK_PPNUM || t == TOK_PPSTR
                    || t == TOK_STR || t == TOK_LSTR =>
                {
                    self.pp_str_buf = lexer.tok_buf.data.clone();
                    self.tokc.str_val.data = self.pp_str_buf.as_ptr();
                    self.tokc.str_val.size = self.pp_str_buf.len() as i32;
                }
                _ => {}
            }

            // Save the lexer's lookahead character for the next call.
            self.lexer_ch = Some(lexer.ch);
            self.file = lexer.file.clone();

            // Handle preprocessor directives at beginning of line.
            // This matches C TCC's next_nomacro1() which calls
            // preprocess() when `#` is at BOL with PREPROCESS flag.
            if self.tok == b'#' as i32
                && (saved_tok_flags & TOK_FLAG_BOL) != 0
                && (self.parse_flags & PARSE_FLAG_PREPROCESS) != 0
            {
                self.preprocess()?;
                continue;
            }

            // Skip tokens inside inactive `#if`/`#else` blocks.
            if (self.parse_flags & PARSE_FLAG_PREPROCESS) != 0
                && self.is_in_skipped_block()
            {
                continue;
            }

            return Ok(self.tok);
        }
    }

    /// Read the next raw token from any available source — unget buffer,
    /// macro_ptr, or lexer — WITHOUT performing macro expansion.
    ///
    /// This is the "unified reader" used by `try_expand_macro()` (to peek
    /// for `(` after a function-like macro name) and by
    /// `collect_live_macro_args()` (to consume arguments).  It honours the
    /// same priority order as `next()`:
    ///   1. unget_buffer  2. macro_ptr  3. lexer
    ///
    /// `TOK_NOSUBST` markers in macro_ptr are consumed transparently (the
    /// guarded token is returned, but we deliberately do NOT set a "no
    /// expand" flag because the caller is `_nomacro` — expansion is already
    /// suppressed).
    fn next_nomacro_any(&mut self) -> TccResult<i32> {
        // 1. unget buffer
        if let Some((tok, tokc, flags)) = self.unget_buffer.pop() {
            self.tok = tok;
            self.tokc = tokc;
            self.tok_flags = flags;
            return Ok(self.tok);
        }

        // 2. macro_ptr (if present and not exhausted)
        let from_macro = if let Some((ref stream, ref mut pos)) = self.macro_ptr {
            if *pos < stream.len() {
                let tok = stream[*pos];
                *pos += 1;
                Some(tok)
            } else {
                None
            }
        } else {
            None
        };

        if let Some(raw) = from_macro {
            if raw == 0 {
                // End-of-stream sentinel — pop stack and retry
                self.macro_ptr = self.macro_stack.pop();
                return self.next_nomacro_any();
            }

            if raw == TOK_NOSUBST {
                // Skip the marker, read the guarded token
                let guarded = if let Some((ref stream, ref mut pos)) = self.macro_ptr {
                    if *pos < stream.len() {
                        let t = stream[*pos];
                        *pos += 1;
                        Some(t)
                    } else {
                        None
                    }
                } else {
                    None
                };

                if let Some(t) = guarded {
                    self.tok = t & !STREAM_SPC_BIT;
                    if (t & STREAM_SPC_BIT) != 0 {
                        self.tok_flags |= TOK_FLAG_SPC;
                    }
                    self.tokc = CValue::default();
                    // Read value payload if any
                    if self.macro_ptr.is_some() {
                        let mut mp = self.macro_ptr.take().unwrap();
                        {
                            let (ref stream, ref mut pos) = mp;
                            self.read_token_value(stream, pos);
                        }
                        self.macro_ptr = Some(mp);
                    }
                    // Convert keyword-alias stream IDs to primary values
                    if self.tok >= TOK_IDENT {
                        let idx = (self.tok - TOK_IDENT) as usize;
                        if idx < self.token_table.table_ident.len() {
                            let primary = self.token_table.table_ident[idx].tok;
                            if primary != self.tok {
                                self.last_ident_alloc_id = self.tok;
                                self.tok = primary;
                            }
                        }
                    }
                    return Ok(self.tok);
                }
                // Marker at end of stream — pop and retry
                self.macro_ptr = self.macro_stack.pop();
                return self.next_nomacro_any();
            }

            // Strip SPC bit so self.tok is the clean token value;
            // callers compare against raw ASCII or TOK_* constants.
            let spc = raw & STREAM_SPC_BIT;
            self.tok = raw & !STREAM_SPC_BIT;
            if spc != 0 {
                self.tok_flags |= TOK_FLAG_SPC;
            }
            self.tokc = CValue::default();
            // Read value payload
            if self.macro_ptr.is_some() {
                let mut mp = self.macro_ptr.take().unwrap();
                {
                    let (ref stream, ref mut pos) = mp;
                    self.read_token_value(stream, pos);
                }
                self.macro_ptr = Some(mp);
            }
            // Convert keyword-alias stream IDs back to primary keyword
            // values.  Alias entries have ts.tok != (entry_index+TOK_IDENT),
            // so table_ident[idx].tok gives the canonical keyword value
            // that the parser / expansion logic checks against.
            if self.tok >= TOK_IDENT {
                let idx = (self.tok - TOK_IDENT) as usize;
                if idx < self.token_table.table_ident.len() {
                    let primary = self.token_table.table_ident[idx].tok;
                    if primary != self.tok {
                        // Save the alias ID so tok_to_stream_id can re-use
                        // it if this token is stored into another stream.
                        self.last_ident_alloc_id = self.tok;
                        self.tok = primary;
                    }
                }
            }
            return Ok(self.tok);
        }

        // macro_ptr exhausted — pop stack and check again before falling to lexer
        if self.macro_ptr.is_some() {
            self.macro_ptr = self.macro_stack.pop();
            // Re-check: the popped frame might have more tokens
            return self.next_nomacro_any();
        }

        // 3. Fall through to lexer
        self.next_nomacro()
    }

    /// Skip tokens until end of line or end of file.
    fn skip_to_eol(&mut self) -> TccResult<()> {
        // Match C TCC's preprocess_skip(): while-do, NOT do-while.
        // When self.tok is already TOK_LINEFEED we must NOT call
        // next_nomacro() again — doing so would consume the next line.
        while self.tok != TOK_LINEFEED && self.tok != TOK_EOF {
            self.next_nomacro()?;
        }
        Ok(())
    }

    /// Skip to end of line at the raw character level, without tokenising.
    /// Used for assembly-mode lines that contain characters the C lexer
    /// cannot handle (backticks, unmatched single-quotes, etc.).
    fn skip_to_eol_raw(&mut self) {
        // The lexer reads one character ahead into self.lexer_ch,
        // leaving self.file.buf_ptr one position PAST that look-ahead
        // character.  If the look-ahead is already the newline at the
        // end of the current line (or EOF), we must NOT scan the
        // buffer from buf_ptr — doing so would consume content from
        // the NEXT line, causing the "each # comment eats the next
        // line" bug in .S assembly preprocessing.
        if let Some(ch) = self.lexer_ch {
            if ch == b'\n' as i32 {
                // The newline ending this line is in lexer_ch.
                // Just consume it — buf_ptr already points to the
                // start of the next line.
                self.file.line_num += 1;
                self.tok = TOK_LINEFEED;
                self.tokc = CValue::default();
                self.tok_flags = TOK_FLAG_BOL;
                self.lexer_ch = None;
                return;
            }
            if ch < 0 {
                // EOF in look-ahead — treat as end of line.
                self.tok = TOK_LINEFEED;
                self.tokc = CValue::default();
                self.tok_flags = TOK_FLAG_BOL;
                self.lexer_ch = None;
                return;
            }
            // The look-ahead character is NOT a newline — it sits on
            // the same line, between the last consumed token and the
            // real newline.  Discard it (the buffer has already been
            // advanced past it) and continue scanning from buf_ptr.
            self.lexer_ch = None;
        }

        while self.file.buf_ptr < self.file.buf_end {
            let ch = self.file.buffer[self.file.buf_ptr];
            self.file.buf_ptr += 1;
            if ch == b'\n' {
                self.file.line_num += 1;
                break;
            }
        }
        self.tok = TOK_LINEFEED;
        self.tokc = CValue::default();
        // Signal beginning-of-line so the next `#` is treated as a
        // directive, and reset the lexer look-ahead character.
        self.tok_flags = TOK_FLAG_BOL;
        self.lexer_ch = None;
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
        self.define_push_at(tok_id, macro_type, body, params, None);
    }

    /// Like `define_push`, but accepts an explicit `line_num` for the
    /// redefinition warning so that the diagnostic refers to the `#define`
    /// line rather than whatever line the lexer has advanced to by the time
    /// the body has been fully scanned.
    pub fn define_push_at(&mut self, tok_id: i32, macro_type: i32, body: Vec<i32>,
                          params: Option<Box<Sym>>, line_num: Option<i32>) {
        // NC-03: Check for non-identical redefinition
        if let Some(existing) = self.macro_table.get(&tok_id) {
            if existing.type_.t == macro_type {
                // Compare replacement lists
                let existing_body = existing.d.as_deref().unwrap_or(&[]);
                if existing_body != body.as_slice() {
                    // Non-identical redefinition — emit warning (NC-03).
                    let fname = std::path::Path::new(&self.file.filename)
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or(&self.file.filename);
                    let ln = line_num.unwrap_or(self.file.line_num);
                    eprintln!(
                        "{}:{}: warning: {} redefined",
                        fname,
                        ln,
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
        // Save the line number of the #define directive for diagnostics.
        // The line counter advances as we scan the macro body, so capture
        // it before reading tokens.
        let define_line = self.file.line_num;

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

        // The lexer leaves the first non-identifier character as the
        // lookahead (`lexer_ch`).  If that lookahead is '(' with no
        // intervening whitespace, this is a function-like macro.
        {
            let next_ch = self.lexer_ch.unwrap_or(b' ' as i32) as u8;

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
                        if current_tok == TOK_DOTS {
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
                        // GCC extension: `name...` makes the LAST parameter
                        // variadic (used instead of __VA_ARGS__).
                        // E.g. `#define M(X,Y...) ...` — Y captures varargs.
                        if sep == TOK_DOTS {
                            is_variadic = true;
                            let close = self.next_nomacro()?;
                            if close != b')' as i32 {
                                return Err(TccError::preprocessor(
                                    self.file.filename.clone(),
                                    self.file.line_num as u32,
                                    "')' expected after '...'",
                                ));
                            }
                            break;
                        }
                        if sep == b',' as i32 {
                            current_tok = self.next_nomacro()?;
                            // Check for C99 variadic: , ...
                            if current_tok == TOK_DOTS {
                                is_variadic = true;
                                // __VA_ARGS__ is the parameter name for ...
                                let va_tok = tok_alloc(
                                    &mut self.token_table,
                                    b"__VA_ARGS__",
                                );
                                let param_sym = Sym {
                                    v: va_tok | (1 << 30),
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
                                let close = self.next_nomacro()?;
                                if close != b')' as i32 {
                                    return Err(TccError::preprocessor(
                                        self.file.filename.clone(),
                                        self.file.line_num as u32,
                                        "')' expected after '...'",
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

        // Parse macro body (replacement list).
        // For function-like macros, parameter references are encoded as
        // `MACRO_PARAM_BASE + param_index` so that `arg_subst()` can
        // recognise and substitute them without needing the param list.
        //
        // Each token entry in the body stream may have `STREAM_SPC_BIT`
        // OR-ed in to indicate that whitespace preceded it in the source.
        // The preprocessor `-E` output uses this to reproduce spacing.
        //
        // CRITICAL: Strip PARSE_FLAG_TOK_NUM and PARSE_FLAG_TOK_STR
        // during body reading.  In C TCC, next_nomacro() never converts
        // TOK_PPNUM → TOK_CINT (conversion only happens in next() at the
        // "convert:" label).  Our lexer performs the conversion inside
        // next_raw() when the flags are set, so we must strip them here
        // to preserve raw pp-number text (e.g. "9999b" in asm macros).
        let saved_define_parse_flags = self.parse_flags;
        self.parse_flags &= !(PARSE_FLAG_TOK_NUM | PARSE_FLAG_TOK_STR);
        let mut body: Vec<i32> = Vec::new();
        loop {
            let tok = self.next_nomacro()?;
            if tok == TOK_LINEFEED || tok == TOK_EOF {
                break;
            }

            // Capture the whitespace flag BEFORE any transformation.
            // The first body token ALWAYS has SPC cleared — the space
            // between the macro name / parameter list and the body text
            // is structural, not part of the replacement list.  The
            // expansion logic in `macro_subst_inner()` will transplant
            // the SPC from the *call-site* macro name instead.
            let spc_bit = if body.is_empty() {
                0
            } else if (self.tok_flags & TOK_FLAG_SPC) != 0 {
                STREAM_SPC_BIT
            } else {
                0
            };

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
                    if let Some(idx) = self.get_macro_param_index(&params, next) {
                        body.push(TOK_PPSTR | spc_bit);
                        body.push(MACRO_PARAM_BASE + idx);
                        continue;
                    }
                }
                // Not a parameter — just '#' followed by something
                body.push(b'#' as i32 | spc_bit);
                body.push(next);
                continue;
            }

            // For function-like macros, replace parameter tokens with
            // encoded parameter markers.
            if macro_type == MACRO_FUNC && tok >= TOK_IDENT {
                if let Some(idx) = self.get_macro_param_index(&params, tok) {
                    body.push((MACRO_PARAM_BASE + idx) | spc_bit);
                    continue;
                }
            }

            // Convert value-carrying tokens to tok_alloc identifiers
            // so the body stream is self-describing (no inline values
            // needed).  This simplifies macro_subst_inner() and
            // arg_subst() considerably.
            let stored = self.tok_to_stream_id(tok);
            body.push(stored | spc_bit);
        }

        // Restore parse_flags after body reading.
        self.parse_flags = saved_define_parse_flags;

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

        self.define_push_at(macro_name, final_type, body, params, Some(define_line));

        Ok(())
    }

    /// Peek at the raw character in the file buffer (for checking if '(' follows
    /// immediately after a macro name with no whitespace).
    #[allow(dead_code)]
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
    #[allow(dead_code)]
    fn is_macro_param(&self, params: &Option<Box<Sym>>, tok_id: i32) -> bool {
        self.get_macro_param_index(params, tok_id).is_some()
    }

    /// Look up a token in the macro parameter list and return its parameter
    /// index (0-based) if found.  Parameters are stored with
    /// `sym.v = token_id | SYM_FIELD_FLAG` and `sym.c = param_index`.
    fn get_macro_param_index(&self, params: &Option<Box<Sym>>, tok_id: i32) -> Option<i32> {
        let mut current = params.as_ref();
        while let Some(sym) = current {
            if (sym.v & !(1 << 30)) == tok_id {
                return Some(sym.c);
            }
            current = sym.next.as_ref();
        }
        None
    }

    /// Store the associated value for a value-carrying token into a token stream.
    ///
    /// CValue is a union so all field accesses require `unsafe`.
    #[allow(dead_code)]
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
                    // Copy the actual string data bytes into the body
                    // words, 4 bytes per i32 word (little-endian packing).
                    let data_ptr = self.tokc.str_val.data;
                    for w in 0..words {
                        let mut word: u32 = 0;
                        for b in 0..4 {
                            let idx = w * 4 + b;
                            if idx < len && !data_ptr.is_null() {
                                word |= (*data_ptr.add(idx) as u32) << (b * 8);
                            }
                        }
                        body.push(word as i32);
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

        let (filename, is_system) = if tok == TOK_LT {
            let mut name = String::new();
            loop {
                let ch_tok = self.next_nomacro()?;
                if ch_tok == TOK_GT || ch_tok == TOK_LINEFEED || ch_tok == TOK_EOF {
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

    /// Read next token with macro expansion for directive arguments.
    ///
    /// C TCC uses `next()` (with full expansion) inside `preprocess()`
    /// for reading `#line` arguments, so macros like `#define LINE1 40`
    /// followed by `# line LINE1` work correctly.  Our architecture
    /// separates directive and macro handling, so we temporarily enable
    /// `PARSE_FLAG_PREPROCESS` to allow the `next()` pipeline to expand
    /// macros.  This is safe because tokens within a directive line are
    /// never at beginning-of-line (BOL), preventing recursive re-entry
    /// into `preprocess()`.
    fn next_directive_expanded(&mut self) -> TccResult<i32> {
        let saved = self.parse_flags;
        self.parse_flags |= PARSE_FLAG_PREPROCESS;
        let tok = self.next()?;
        self.parse_flags = saved;
        Ok(tok)
    }

    fn handle_line(&mut self) -> TccResult<()> {
        let tok = self.next_directive_expanded()?;
        let mut new_line_num: Option<i32> = None;
        let mut new_filename: Option<String> = None;

        // Extract line number from the token.  After macro expansion
        // the token may be TOK_CINT/CUINT (from PARSE_FLAG_TOK_NUM),
        // TOK_PPNUM, or a tok_alloc identifier whose string is digits
        // (macro bodies store numbers as allocated identifiers).
        let line = if tok == TOK_CINT || tok == TOK_CUINT {
            Some((unsafe { self.tokc.i }) as i32)
        } else if tok == TOK_PPNUM {
            let s = get_tok_str(&self.token_table, tok, Some(&self.tokc));
            s.parse::<i32>().ok()
        } else if tok >= TOK_IDENT {
            // Macro-expanded token — check if its string is numeric.
            let s = get_tok_str(&self.token_table, tok, None);
            s.parse::<i32>().ok()
        } else {
            None
        };

        if let Some(line) = line {
            if line > 0 {
                new_line_num = Some(line);
            }
            let next = self.next_directive_expanded()?;
            // Extract optional filename.  May be TOK_STR, or an
            // allocated identifier whose string starts with `"` (from
            // macro expansion of `#define FILE "path"`).
            if next == TOK_STR {
                let fname = get_tok_str(&self.token_table, next, Some(&self.tokc));
                let fname = fname.trim_matches('"').to_string();
                if !fname.is_empty() {
                    new_filename = Some(fname);
                }
            } else if next >= TOK_IDENT && next != TOK_LINEFEED {
                let fname = get_tok_str(&self.token_table, next, None);
                if fname.starts_with('"') {
                    let trimmed = fname.trim_matches('"').to_string();
                    if !trimmed.is_empty() {
                        new_filename = Some(trimmed);
                    }
                }
            }
        }
        self.skip_to_eol()?;
        // Apply line number and filename AFTER consuming all directive
        // tokens (including the terminating LINEFEED).  C TCC sets
        // file->line_num after preprocess_skip(), so the LINEFEED's
        // line_num++ is overwritten by the directive's target value.
        if let Some(line) = new_line_num {
            self.file.line_num = line;
        }
        if let Some(fname) = new_filename {
            self.file.filename = fname;
        }
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

    /// Expand `input` token stream via [`macro_subst()`], but with `macro_id`
    /// in the noexpand set.  After expansion, any occurrence of `macro_id` in
    /// the result that is NOT already preceded by `TOK_NOSUBST` gets a
    /// `TOK_NOSUBST` marker inserted before it (C99 6.10.3.4 "painting blue").
    /// Insert `TOK_NOSUBST` markers before every occurrence of `macro_id`
    /// in `tokens` that is not already guarded, implementing the C99 6.10.3.4
    /// "painted blue" semantics.
    /// Process `##` (token pasting) operators in a token stream.
    ///
    /// C99 6.10.3.3: "each instance of a ## preprocessing token in the
    /// replacement list is deleted and the preceding preprocessing token is
    /// concatenated with the following preprocessing token."
    ///
    /// This is used for object-like macro bodies (which are not processed
    /// by `arg_subst`).  For function-like macros, `arg_subst()` handles
    /// `##` during argument substitution.
    fn paste_tokens(&mut self, input: &[i32]) -> Vec<i32> {
        let mut out: Vec<i32> = Vec::with_capacity(input.len());
        let mut i = 0;
        while i < input.len() {
            let raw = input[i];
            i += 1;
            let tok = raw & !STREAM_SPC_BIT;
            if tok == 0 {
                break;
            }
            // Skip TOK_NOSUBST markers in paste_tokens input — they are
            // bookkeeping for rescan suppression and must not participate
            // in ## concatenation.
            if tok == TOK_NOSUBST {
                if i < input.len() {
                    out.push(input[i]); // push guarded token
                    i += 1;
                }
                continue;
            }
            if tok == TOK_TWOSHARPS && i < input.len() {
                let mut rhs_raw = input[i];
                i += 1;
                let mut rhs = rhs_raw & !STREAM_SPC_BIT;
                // Skip NOSUBST on the RHS of ##.
                if rhs == TOK_NOSUBST && i < input.len() {
                    rhs_raw = input[i];
                    i += 1;
                    rhs = rhs_raw & !STREAM_SPC_BIT;
                }
                // If the LHS was NOSUBST-guarded, pop the marker and the
                // guarded token.
                let lhs_entry = out.pop();
                let (left, left_nosubst_marker) = if let Some(l) = lhs_entry {
                    if (l & !STREAM_SPC_BIT) == TOK_NOSUBST {
                        // This shouldn't happen since we skip NOSUBST above,
                        // but handle it defensively.
                        (out.pop(), true)
                    } else {
                        (Some(l), false)
                    }
                } else {
                    (None, false)
                };
                let _ = left_nosubst_marker;
                if let Some(left) = left {
                    let left_clean = left & !STREAM_SPC_BIT;
                    let left_spc = left & STREAM_SPC_BIT;
                    if rhs == 0 {
                        out.push(left);
                    } else {
                        let left_str = get_tok_str(&self.token_table, left_clean, None);
                        let right_str = get_tok_str(&self.token_table, rhs, None);
                        let pasted_text = format!("{}{}", left_str, right_str);
                        if pasted_text.is_empty() {
                            // Both sides empty — produce nothing.
                        } else {
                            let pasted_tok =
                                tok_alloc(&mut self.token_table, pasted_text.as_bytes());
                            out.push(pasted_tok | left_spc);
                        }
                    }
                } else if rhs != 0 {
                    out.push(rhs_raw);
                }
            } else {
                out.push(raw);
            }
        }
        out
    }

    /// Strip all `TOK_NOSUBST` markers from a token stream, returning only
    /// the "real" tokens.  NOSUBST markers are internal bookkeeping for
    /// preventing recursive macro expansion; they must be stripped before
    /// `##` token pasting because `get_tok_str(TOK_NOSUBST)` would produce
    /// `<token 0xf1>` instead of the guarded token's text.
    fn strip_nosubst(tokens: &[i32]) -> Vec<i32> {
        let mut out = Vec::with_capacity(tokens.len());
        let mut i = 0;
        while i < tokens.len() {
            let raw = tokens[i];
            let tok = raw & !STREAM_SPC_BIT;
            if tok == TOK_NOSUBST {
                // Skip the marker; the guarded token follows.
                i += 1;
                if i < tokens.len() {
                    // Preserve the guarded token (including its SPC bit).
                    out.push(tokens[i]);
                }
            } else {
                out.push(raw);
            }
            i += 1;
        }
        out
    }

    fn tag_nosubst(&self, tokens: &[i32], macro_id: i32) -> Vec<i32> {
        let mut out: Vec<i32> = Vec::with_capacity(tokens.len() + 8);
        let mut i = 0;
        while i < tokens.len() {
            let raw = tokens[i];
            let tok = raw & !STREAM_SPC_BIT;
            if tok == TOK_NOSUBST {
                // Already guarded — copy marker + guarded token.
                out.push(raw);
                i += 1;
                if i < tokens.len() {
                    out.push(tokens[i]);
                    i += 1;
                }
                continue;
            }
            if tok == macro_id {
                out.push(TOK_NOSUBST);
            }
            out.push(raw); // preserve SPC bit
            i += 1;
        }
        out
    }

    /// Inner implementation of macro substitution, called by [`macro_subst()`]
    /// after the depth guard has been applied.
    fn macro_subst_inner(
        &mut self,
        input: &[i32],
    ) -> TccResult<Vec<i32>> {
        let mut output: Vec<i32> = Vec::with_capacity(input.len() * 2);
        // Use a mutable work buffer so expansion results can be spliced
        // into the unscanned portion, allowing rescanning to see
        // subsequent tokens (e.g. `g` expands to `f`, and `(...)` follows
        // in the original stream, so `f(...)` is properly recognised).
        let mut work: Vec<i32> = input.to_vec();
        let mut pos: usize = 0;

        while pos < work.len() {
            let raw = work[pos];
            pos += 1;

            // Separate the STREAM_SPC_BIT from the actual token so that
            // all comparisons and macro-table lookups use the clean value,
            // while the spacing information is preserved on output tokens.
            let spc = raw & STREAM_SPC_BIT;
            let tok = raw & !STREAM_SPC_BIT;

            // Skip end marker
            if tok == 0 {
                break;
            }

            // Handle TOK_NOSUBST: the next token must NOT be expanded.
            // Preserve the marker in output so it survives through all
            // rescanning levels; it will be stripped at the final output stage.
            if tok == TOK_NOSUBST {
                output.push(TOK_NOSUBST);
                if pos < work.len() {
                    output.push(work[pos]); // keep SPC bit on guarded tok
                    pos += 1;
                }
                continue;
            }

            // If not an identifier token, copy through with SPC intact.
            if tok < TOK_IDENT {
                output.push(raw);
                continue;
            }

            // In #if expressions, 'defined' operator's argument must NOT be
            // expanded (C99 6.10.1p1).  Emit 'defined' and its argument
            // verbatim so the expression evaluator can check define_find()
            // on the original macro name, not an expanded replacement.
            if self.pp_expr && tok == Token::Defined as i32 {
                output.push(raw);
                // Read the argument: either (IDENT) or IDENT
                if pos < work.len() {
                    let nxt_raw = work[pos];
                    let nxt = nxt_raw & !STREAM_SPC_BIT;
                    if nxt == b'(' as i32 {
                        // defined(IDENT) — copy '(', IDENT, ')'
                        output.push(nxt_raw);
                        pos += 1;
                        if pos < work.len() {
                            output.push(work[pos]); // IDENT
                            pos += 1;
                        }
                        if pos < work.len() {
                            let close = work[pos] & !STREAM_SPC_BIT;
                            if close == b')' as i32 {
                                output.push(work[pos]);
                                pos += 1;
                            }
                        }
                    } else if nxt >= TOK_IDENT {
                        // defined IDENT (without parens)
                        output.push(nxt_raw);
                        pos += 1;
                    }
                }
                continue;
            }

            // "Painted blue" check — if the macro is in the noexpand set
            // (currently being expanded at an outer level), emit verbatim
            // with a TOK_NOSUBST guard so downstream rescans won't touch it.
            if self.noexpand_set.contains(&tok) {
                output.push(raw); // preserve SPC
                continue;
            }

            // Check if the token is a macro
            if let Some(sym) = self.macro_table.get(&tok).cloned() {
                let macro_type = sym.type_.t;

                if macro_type & 0xFF == MACRO_OBJ {
                    // Object-like macro: process ## paste operators in the
                    // body first (C99 6.10.3.3), then recursively expand.
                    if let Some(ref body) = sym.d {
                        let pasted = self.paste_tokens(body);
                        // Mark this macro as noexpand during rescanning.
                        self.noexpand_set.insert(tok);
                        let expanded = self.macro_subst(&pasted)?;
                        self.noexpand_set.remove(&tok);
                        // Tag self-references
                        let tagged = self.tag_nosubst(&expanded, tok);
                        // Transfer SPC from the macro invocation token to
                        // the first token of the expansion result.  The
                        // invocation-site spacing REPLACES whatever SPC
                        // the expansion tokens carried internally (e.g.
                        // arg tokens that had SPC from source).
                        let mut splice = tagged;
                        if !splice.is_empty() {
                            splice[0] = (splice[0] & !STREAM_SPC_BIT) | spc;
                        }
                        // Splice expansion into work at current pos
                        let tail: Vec<i32> = work[pos..].to_vec();
                        work.truncate(pos);
                        work.extend_from_slice(&splice);
                        work.extend_from_slice(&tail);
                        // Don't advance pos — rescan from here.
                    }
                    continue;
                }

                if macro_type & 0xFF == MACRO_FUNC {
                    // Function-like macro: need to see '(' next (strip SPC
                    // from the peeked token before comparing).
                    if pos < work.len()
                        && (work[pos] & !STREAM_SPC_BIT) == b'(' as i32
                    {
                        let saved_pos = pos; // position of '('
                        pos += 1;
                        // Collect arguments from the work buffer
                        let (args, new_pos, complete) =
                            self.collect_macro_args(&work, pos, &sym)?;

                        if !complete {
                            // The closing ')' was NOT found inside the
                            // work buffer.  This happens when a macro
                            // expansion produces an INCOMPLETE invocation.
                            // Output the tokens verbatim and let the
                            // live-stream rescanning handle the invocation.
                            pos = saved_pos; // rewind past '('
                            output.push(raw); // preserve SPC
                            continue;
                        }

                        pos = new_pos;

                        // Substitute arguments into macro body
                        if let Some(ref body) = sym.d {
                            let substituted = self.arg_subst(body, &args, &sym)?;
                            // Mark this macro as noexpand during rescanning.
                            self.noexpand_set.insert(tok);
                            let expanded = self.macro_subst(&substituted)?;
                            self.noexpand_set.remove(&tok);
                            // Tag self-references
                            let tagged = self.tag_nosubst(&expanded, tok);
                            // Transfer SPC: REPLACE (not OR) so that
                            // invocation-site spacing overrides internal
                            // expansion spacing.
                            let mut splice = tagged;
                            if !splice.is_empty() {
                                splice[0] = (splice[0] & !STREAM_SPC_BIT) | spc;
                            }
                            // Splice expansion into work at current pos
                            let tail: Vec<i32> = work[pos..].to_vec();
                            work.truncate(pos);
                            work.extend_from_slice(&splice);
                            work.extend_from_slice(&tail);
                        }
                        continue;
                    }
                    // No '(' found — not a function-like expansion, output as-is
                    output.push(raw); // preserve SPC
                    continue;
                }
            }

            // Check if it's a predefined macro token — only use built-in
            // expansion when there is NO user `#define` for this name.
            if !self.macro_table.contains_key(&tok)
                && self.is_predefined_macro_tok(tok)
            {
                let mut expansion = self.expand_predefined_macro(tok)?;
                // Transfer SPC to first expansion token.
                if !expansion.is_empty() {
                    expansion[0] = (expansion[0] & !STREAM_SPC_BIT) | spc;
                }
                output.extend_from_slice(&expansion);
                continue;
            }

            // __builtin_expect passthrough (FEAT-02)
            if tok == Token::BuiltinExpect as i32 {
                // Collect args: __builtin_expect(expr, val) -> expr
                if pos < work.len()
                    && (work[pos] & !STREAM_SPC_BIT) == b'(' as i32
                {
                    pos += 1;
                    let mut depth = 1i32;
                    let mut first_arg: Vec<i32> = Vec::new();
                    let mut in_first = true;
                    while pos < work.len() && depth > 0 {
                        let t_raw = work[pos];
                        let t = t_raw & !STREAM_SPC_BIT;
                        pos += 1;
                        if t == b'(' as i32 {
                            depth += 1;
                        } else if t == b')' as i32 {
                            depth -= 1;
                            if depth == 0 {
                                break;
                            }
                        } else if t == b',' as i32 && depth == 1 {
                            in_first = false;
                            continue;
                        }
                        if in_first {
                            first_arg.push(t_raw);
                        }
                    }
                    // expand the first argument
                    let expanded = self.macro_subst(&first_arg)?;
                    output.extend_from_slice(&expanded);
                    continue;
                }
            }

            // Not a macro, output verbatim (preserve SPC).
            output.push(raw);
            pos = self.copy_token_value_from_stream(&work, pos, tok, &mut output);
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
    /// Collect macro arguments from a flat token buffer.
    ///
    /// Returns `(args, new_pos, complete)` where `complete` is `true` when a
    /// matching `)` was found, `false` when the buffer ran out first.
    fn collect_macro_args(
        &self,
        input: &[i32],
        mut pos: usize,
        sym: &Sym,
    ) -> TccResult<(Vec<Vec<i32>>, usize, bool)> {
        let mut args: Vec<Vec<i32>> = Vec::new();
        let mut current_arg: Vec<i32> = Vec::new();
        let mut depth: i32 = 1;
        let mut complete = false;

        // Determine variadic status and param count so we can stop splitting
        // commas once all named parameters have been filled — remaining
        // tokens (including commas) become the variadic argument.
        let is_variadic = (sym.type_.t & 0x80000000u32 as i32) != 0;
        let total_params = {
            let mut count = 0usize;
            let mut p = sym.next.as_ref();
            while let Some(s) = p {
                count += 1;
                p = s.next.as_ref();
            }
            count
        };
        let stop_split_at = if is_variadic && total_params > 0 {
            total_params - 1
        } else {
            usize::MAX
        };

        while pos < input.len() {
            let raw = input[pos];
            pos += 1;
            // Strip STREAM_SPC_BIT for structural comparisons (parentheses,
            // comma), but keep the original `raw` value when pushing tokens
            // into argument lists so spacing information is preserved.
            let t = raw & !STREAM_SPC_BIT;

            if t == b'(' as i32 {
                depth += 1;
                current_arg.push(raw); // preserve SPC
            } else if t == b')' as i32 {
                depth -= 1;
                if depth == 0 {
                    args.push(current_arg);
                    complete = true;
                    break;
                }
                current_arg.push(raw); // preserve SPC
            } else if t == b',' as i32 && depth == 1 && args.len() < stop_split_at {
                // Normal comma split (for named params)
                args.push(current_arg);
                current_arg = Vec::new();
            } else if t == b',' as i32 && depth == 1 {
                // Variadic region: keep comma as part of the current arg
                current_arg.push(raw); // preserve SPC
            } else if t == 0 {
                break;
            } else {
                current_arg.push(raw); // preserve SPC
                // Copy token values through for literals
                let old_pos = pos;
                let mut dummy = Vec::new();
                pos = self.copy_token_value_from_stream(input, pos, t, &mut dummy);
                current_arg.extend_from_slice(&input[old_pos..pos]);
            }
        }

        // Pad with empty Vecs when fewer args than params were supplied,
        // so arg_subst() can always index every parameter slot.
        if complete {
            while args.len() < total_params {
                args.push(Vec::new());
            }
        }

        Ok((args, pos, complete))
    }

    /// Substitute arguments into a function-like macro body.
    /// Handles `#` (stringify) and `##` (paste) operators.
    ///
    /// **Argument Pre-expansion Caching**: When a parameter appears in the
    /// body WITHOUT `#` or `##`, the argument is macro-expanded once via
    /// [`macro_subst()`] and the result is cached.  Subsequent occurrences
    /// of the same parameter reuse the cached expansion.  This matches the
    /// C standard (6.10.3.1) and is critical for `__COUNTER__` correctness
    /// — see C TCC's `s->e` caching in `macro_subst_tok()`.
    fn arg_subst(
        &mut self,
        body: &[i32],
        args: &[Vec<i32>],
        sym: &Sym,
    ) -> TccResult<Vec<i32>> {
        let mut result: Vec<i32> = Vec::new();
        let mut pos = 0;

        // Cache for pre-expanded arguments.  `None` means not yet expanded;
        // `Some(tokens)` holds the cached expansion.  C TCC stores this in
        // `s->e` on the `Sym` — we use a local vec since our `Sym` is
        // borrowed immutably.
        let mut expanded_cache: Vec<Option<Vec<i32>>> = vec![None; args.len()];

        // Determine the index of the variadic parameter (last param) so we
        // can implement GCC's `, ## __VA_ARGS__` comma elision extension.
        let is_variadic_macro = (sym.type_.t & 0x80000000u32 as i32) != 0;
        let variadic_param_idx: usize = if is_variadic_macro {
            let mut count = 0usize;
            let mut p = sym.next.as_ref();
            while let Some(s) = p {
                count += 1;
                p = s.next.as_ref();
            }
            if count > 0 { count - 1 } else { usize::MAX }
        } else {
            usize::MAX
        };

        while pos < body.len() {
            let raw = body[pos];
            pos += 1;

            // Separate spacing bit from the real token value.
            let spc = raw & STREAM_SPC_BIT;
            let tok = raw & !STREAM_SPC_BIT;

            if tok == 0 {
                break;
            }

            // ── ## (token pasting / TOK_TWOSHARPS) ──────────────────────
            if tok == TOK_TWOSHARPS {
                // Paste previous output token with next token
                if pos < body.len() {
                    let next_raw = body[pos];
                    pos += 1;
                    let next = next_raw & !STREAM_SPC_BIT;

                    if (MACRO_PARAM_BASE..MACRO_PARAM_BASE + 256).contains(&next) {
                        let idx = (next - MACRO_PARAM_BASE) as usize;
                        if let Some(arg) = args.get(idx) {
                            if arg.is_empty() {
                                // GCC comma elision extension: when the
                                // variadic parameter is empty and the last
                                // output token is a comma, remove the comma.
                                if idx == variadic_param_idx {
                                    if let Some(&last) = result.last() {
                                        if (last & !STREAM_SPC_BIT) == b',' as i32 {
                                            result.pop();
                                        }
                                    }
                                }
                                // For non-variadic empty args with ##, the
                                // left side remains as-is (paste with nothing).
                            } else {
                                // Check if this is the GNU `, ## __VA_ARGS__`
                                // comma elision extension: only applies when
                                // the variadic arg is non-empty AND the left
                                // side is a comma.  Otherwise, do real pasting.
                                let is_comma_elision = idx == variadic_param_idx
                                    && result.last().is_some_and(|&last| {
                                        (last & !STREAM_SPC_BIT) == b',' as i32
                                    });
                                if is_comma_elision {
                                    // Keep existing result (comma stays),
                                    // append expanded variadic args with
                                    // no SPC on the first token (adjacent).
                                    let clean_arg = Self::strip_nosubst(arg);
                                    if !clean_arg.is_empty() {
                                        // Strip SPC from first variadic
                                        // token so it appears immediately
                                        // after the comma.
                                        result.push(clean_arg[0] & !STREAM_SPC_BIT);
                                        result.extend_from_slice(&clean_arg[1..]);
                                    }
                                } else {
                                    // Non-variadic param: real token paste.
                                    // Strip TOK_NOSUBST markers from the arg
                                    // before pasting — NOSUBST is for rescan
                                    // suppression, not for concatenation text.
                                    let clean_arg = Self::strip_nosubst(arg);
                                    let last_out = result.pop();
                                    let first_arg = if !clean_arg.is_empty() {
                                        clean_arg[0] & !STREAM_SPC_BIT
                                    } else {
                                        0
                                    };
                                    if let Some(left) = last_out {
                                        let left_clean = left & !STREAM_SPC_BIT;
                                        let left_spc = left & STREAM_SPC_BIT;
                                        let left_str =
                                            get_tok_str(&self.token_table, left_clean, None);
                                        let right_str =
                                            get_tok_str(&self.token_table, first_arg, None);
                                        let pasted = format!("{}{}", left_str, right_str);
                                        let pasted_tok =
                                            tok_alloc(&mut self.token_table, pasted.as_bytes());
                                        result.push(pasted_tok | left_spc);
                                        if clean_arg.len() > 1 {
                                            result.extend_from_slice(&clean_arg[1..]);
                                        }
                                    } else {
                                        result.extend_from_slice(arg);
                                    }
                                }
                            }
                        }
                    } else {
                        // Paste with a literal token
                        let last_out = result.pop();
                        if let Some(left) = last_out {
                            let left_clean = left & !STREAM_SPC_BIT;
                            let left_spc = left & STREAM_SPC_BIT;
                            let left_str =
                                get_tok_str(&self.token_table, left_clean, None);
                            let right_str =
                                get_tok_str(&self.token_table, next, None);
                            let pasted = format!("{}{}", left_str, right_str);
                            let pasted_tok =
                                tok_alloc(&mut self.token_table, pasted.as_bytes());
                            result.push(pasted_tok | left_spc);
                        } else {
                            result.push(next_raw); // preserve SPC
                        }
                    }
                }
                continue;
            }

            // ── # (stringification followed by param marker) ────────────
            if tok == TOK_PPSTR && pos < body.len() {
                let next_raw = body[pos];
                let next = next_raw & !STREAM_SPC_BIT;
                if (MACRO_PARAM_BASE..MACRO_PARAM_BASE + 256).contains(&next) {
                    pos += 1;
                    let idx = (next - MACRO_PARAM_BASE) as usize;
                    if let Some(arg) = args.get(idx) {
                        let stringified = self.stringify_arg(arg);
                        let str_tok =
                            tok_alloc(&mut self.token_table, stringified.as_bytes());
                        // Transfer SPC from the `#` token.
                        result.push(str_tok | spc);
                    }
                    continue;
                }
            }

            // ── Parameter substitution (MACRO_PARAM_BASE + index) ───────
            if (MACRO_PARAM_BASE..MACRO_PARAM_BASE + 256).contains(&tok) {
                let idx = (tok - MACRO_PARAM_BASE) as usize;
                if let Some(arg) = args.get(idx) {
                    // Check if the next body token is ## — if so, paste as-is.
                    let next_is_paste = pos < body.len()
                        && (body[pos] & !STREAM_SPC_BIT) == TOK_TWOSHARPS;

                    if next_is_paste {
                        // Don't macro-expand the argument — paste as-is.
                        // Strip TOK_NOSUBST markers so they don't leak into
                        // the result buffer where result.pop() will pick them
                        // up as the left-side token for ## concatenation.
                        let clean = Self::strip_nosubst(arg);
                        // Transfer SPC to first arg token.
                        if spc != 0 && !clean.is_empty() {
                            result.push(clean[0] | spc);
                            result.extend_from_slice(&clean[1..]);
                        } else {
                            result.extend_from_slice(&clean);
                        }
                    } else {
                        // Expand argument, using the cache.  This ensures
                        // `__COUNTER__` (and all side-effectful macros) is
                        // evaluated exactly once per argument, matching C
                        // TCC's `s->e` cache in `macro_subst_tok()`.
                        if expanded_cache[idx].is_none() {
                            let exp = self.macro_subst(arg)?;
                            expanded_cache[idx] = Some(exp);
                        }
                        let expanded = expanded_cache[idx].as_ref().unwrap();
                        // Transfer SPC to first expansion token.
                        if spc != 0 && !expanded.is_empty() {
                            result.push(expanded[0] | spc);
                            result.extend_from_slice(&expanded[1..]);
                        } else {
                            result.extend_from_slice(expanded);
                        }
                    }
                }
                continue;
            }

            // ── Ordinary token — copy through with SPC intact. ──────────
            result.push(raw);
        }

        Ok(result)
    }

    /// Stringify a macro argument: convert tokens to a quoted string.
    ///
    /// C99 6.10.3.2: "Each occurrence of white space between the argument's
    /// preprocessing tokens becomes a single space character."  We honour
    /// the `STREAM_SPC_BIT` embedded in each token entry to decide spacing.
    fn stringify_arg(&self, tokens: &[i32]) -> String {
        let mut result = String::new();
        let mut pos = 0;
        let mut first = true;
        while pos < tokens.len() {
            let raw = tokens[pos];
            pos += 1;

            let has_spc = (raw & STREAM_SPC_BIT) != 0;
            let tok = raw & !STREAM_SPC_BIT;

            if tok == 0 {
                break;
            }
            // Skip TOK_NOSUBST markers — they are internal bookkeeping
            // and should not appear in the stringified output.
            if tok == TOK_NOSUBST {
                continue;
            }

            // Insert a space between tokens when the SPC bit is set
            // (but never before the very first token).
            if !first && has_spc {
                result.push(' ');
            }
            first = false;

            let spelling = get_tok_str(&self.token_table, tok, None);

            // C99 6.10.3.2p2: Escape `\` and `"` ONLY when they appear
            // inside string literals or character constants — not for
            // standalone `\` or `"` tokens.
            //
            // Note: in our stream encoding, value-carrying tokens
            // (TOK_PPSTR, TOK_CCHAR, etc.) are converted into
            // tok_alloc identifier IDs by `tok_to_stream_id()`, so
            // we cannot check the raw token type.  Instead, detect
            // string/char literals by their text representation.
            let is_string_or_char = tok == TOK_STR
                || tok == TOK_PPSTR
                || tok == TOK_CCHAR
                || tok == TOK_LCHAR
                || spelling.starts_with('"')
                || spelling.starts_with('\'')
                || spelling.starts_with("L\"")
                || spelling.starts_with("L'");

            if is_string_or_char {
                // Escape every `\` and `"` within the token's spelling
                // (which already includes the delimiters).
                for ch in spelling.chars() {
                    if ch == '\\' || ch == '"' {
                        result.push('\\');
                    }
                    result.push(ch);
                }
            } else {
                result.push_str(&spelling);
            }
        }
        format!("\"{}\"", result)
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
        // Enable macro expansion during `#if` expression evaluation so
        // that `#if CCC` (where CCC is a macro) gets expanded first.
        let saved_flags = self.parse_flags;
        self.parse_flags |= PARSE_FLAG_PREPROCESS;
        let result = self.pp_cond_expr();
        self.parse_flags = saved_flags;
        self.pp_expr = false;
        // Drain any tokens left in the unget buffer by the expression
        // evaluator (typically a TOK_LINEFEED that was read one level
        // deeper than needed and then pushed back).  We also drain the
        // rest of the physical line so `preprocess()` returns cleanly.
        self.unget_buffer.clear();
        result.map(|ppv| ppv.val)
    }

    /// Read the next token for `#if` expression evaluation, WITH macro
    /// expansion.  This simply delegates to `self.next()` which already
    /// handles macro expansion via `macro_ptr`.  Unknown identifiers
    /// (after expansion attempts) evaluate to 0 in the caller.
    fn pp_next(&mut self) -> TccResult<i32> {
        self.next()
    }

    /// Top-level: conditional (ternary) expression.
    fn pp_cond_expr(&mut self) -> TccResult<PPVal> {
        let v = self.pp_lor_expr()?;
        let tok = self.pp_next()?;
        if tok == b'?' as i32 {
            let then_v = self.pp_cond_expr()?;
            let colon_tok = self.pp_next()?;
            if colon_tok != b':' as i32 {
                return Err(TccError::preprocessor(
                    self.file.filename.clone(),
                    self.file.line_num as u32,
                    "expected ':' in ternary expression",
                ));
            }
            let else_v = self.pp_cond_expr()?;
            let chosen = if v.val != 0 { then_v } else { else_v };
            Ok(PPVal { val: chosen.val, unsigned: then_v.unsigned || else_v.unsigned })
        } else {
            self.unget_tok(tok);
            Ok(v)
        }
    }

    /// Logical OR.
    fn pp_lor_expr(&mut self) -> TccResult<PPVal> {
        let mut v = self.pp_land_expr()?;
        loop {
            let tok = self.pp_next()?;
            if tok == TOK_LOR {
                let rhs = self.pp_land_expr()?;
                v = PPVal { val: if v.val != 0 || rhs.val != 0 { 1 } else { 0 }, unsigned: false };
            } else {
                self.unget_tok(tok);
                break;
            }
        }
        Ok(v)
    }

    /// Logical AND.
    fn pp_land_expr(&mut self) -> TccResult<PPVal> {
        let mut v = self.pp_bor_expr()?;
        loop {
            let tok = self.pp_next()?;
            if tok == TOK_LAND {
                let rhs = self.pp_bor_expr()?;
                v = PPVal { val: if v.val != 0 && rhs.val != 0 { 1 } else { 0 }, unsigned: false };
            } else {
                self.unget_tok(tok);
                break;
            }
        }
        Ok(v)
    }

    /// Bitwise OR.
    fn pp_bor_expr(&mut self) -> TccResult<PPVal> {
        let mut v = self.pp_bxor_expr()?;
        loop {
            let tok = self.pp_next()?;
            if tok == b'|' as i32 {
                let rhs = self.pp_bxor_expr()?;
                v = PPVal::new(v.val | rhs.val, v.unsigned || rhs.unsigned);
            } else {
                self.unget_tok(tok);
                break;
            }
        }
        Ok(v)
    }

    /// Bitwise XOR.
    fn pp_bxor_expr(&mut self) -> TccResult<PPVal> {
        let mut v = self.pp_band_expr()?;
        loop {
            let tok = self.pp_next()?;
            if tok == b'^' as i32 {
                let rhs = self.pp_band_expr()?;
                v = PPVal::new(v.val ^ rhs.val, v.unsigned || rhs.unsigned);
            } else {
                self.unget_tok(tok);
                break;
            }
        }
        Ok(v)
    }

    /// Bitwise AND.
    fn pp_band_expr(&mut self) -> TccResult<PPVal> {
        let mut v = self.pp_eq_expr()?;
        loop {
            let tok = self.pp_next()?;
            if tok == b'&' as i32 {
                let rhs = self.pp_eq_expr()?;
                v = PPVal::new(v.val & rhs.val, v.unsigned || rhs.unsigned);
            } else {
                self.unget_tok(tok);
                break;
            }
        }
        Ok(v)
    }

    /// Equality / inequality.
    fn pp_eq_expr(&mut self) -> TccResult<PPVal> {
        let mut v = self.pp_rel_expr()?;
        loop {
            let tok = self.pp_next()?;
            if tok == TOK_EQ {
                let rhs = self.pp_rel_expr()?;
                let r = if v.unsigned || rhs.unsigned {
                    (v.val as u64) == (rhs.val as u64)
                } else {
                    v.val == rhs.val
                };
                v = PPVal::signed(if r { 1 } else { 0 });
            } else if tok == TOK_NE {
                let rhs = self.pp_rel_expr()?;
                let r = if v.unsigned || rhs.unsigned {
                    (v.val as u64) != (rhs.val as u64)
                } else {
                    v.val != rhs.val
                };
                v = PPVal::signed(if r { 1 } else { 0 });
            } else {
                self.unget_tok(tok);
                break;
            }
        }
        Ok(v)
    }

    /// Relational comparisons (<, >, <=, >=).
    /// When either operand is unsigned, comparison is performed as u64
    /// (matching C usual arithmetic conversions for preprocessor).
    fn pp_rel_expr(&mut self) -> TccResult<PPVal> {
        let mut v = self.pp_shift_expr()?;
        loop {
            let tok = self.pp_next()?;
            if tok == TOK_LT {
                let rhs = self.pp_shift_expr()?;
                let uns = v.unsigned || rhs.unsigned;
                let r = if uns { (v.val as u64) < (rhs.val as u64) } else { v.val < rhs.val };
                v = PPVal::signed(if r { 1 } else { 0 });
            } else if tok == TOK_GT {
                let rhs = self.pp_shift_expr()?;
                let uns = v.unsigned || rhs.unsigned;
                let r = if uns { (v.val as u64) > (rhs.val as u64) } else { v.val > rhs.val };
                v = PPVal::signed(if r { 1 } else { 0 });
            } else if tok == TOK_LE {
                let rhs = self.pp_shift_expr()?;
                let uns = v.unsigned || rhs.unsigned;
                let r = if uns { (v.val as u64) <= (rhs.val as u64) } else { v.val <= rhs.val };
                v = PPVal::signed(if r { 1 } else { 0 });
            } else if tok == TOK_GE {
                let rhs = self.pp_shift_expr()?;
                let uns = v.unsigned || rhs.unsigned;
                let r = if uns { (v.val as u64) >= (rhs.val as u64) } else { v.val >= rhs.val };
                v = PPVal::signed(if r { 1 } else { 0 });
            } else {
                self.unget_tok(tok);
                break;
            }
        }
        Ok(v)
    }

    /// Shift expressions (<<, >>).
    /// The result type is determined by the left operand's signedness.
    /// For unsigned left operand, right-shift is logical (unsigned);
    /// for signed, right-shift is arithmetic (signed).
    fn pp_shift_expr(&mut self) -> TccResult<PPVal> {
        let mut v = self.pp_add_expr()?;
        loop {
            let tok = self.pp_next()?;
            if tok == TOK_SHL {
                let rhs = self.pp_add_expr()?;
                let shifted = (v.val as u64).wrapping_shl(rhs.val as u32);
                v = PPVal::new(shifted as i64, v.unsigned);
            } else if tok == TOK_SAR {
                let rhs = self.pp_add_expr()?;
                if v.unsigned {
                    let shifted = (v.val as u64).wrapping_shr(rhs.val as u32);
                    v = PPVal::new(shifted as i64, true);
                } else {
                    v = PPVal::new(v.val.wrapping_shr(rhs.val as u32), false);
                }
            } else {
                self.unget_tok(tok);
                break;
            }
        }
        Ok(v)
    }

    /// Additive expressions (+, -).
    fn pp_add_expr(&mut self) -> TccResult<PPVal> {
        let mut v = self.pp_mul_expr()?;
        loop {
            let tok = self.pp_next()?;
            if tok == b'+' as i32 {
                let rhs = self.pp_mul_expr()?;
                v = PPVal::new(v.val.wrapping_add(rhs.val), v.unsigned || rhs.unsigned);
            } else if tok == b'-' as i32 {
                let rhs = self.pp_mul_expr()?;
                v = PPVal::new(v.val.wrapping_sub(rhs.val), v.unsigned || rhs.unsigned);
            } else {
                self.unget_tok(tok);
                break;
            }
        }
        Ok(v)
    }

    /// Multiplicative expressions (*, /, %).
    fn pp_mul_expr(&mut self) -> TccResult<PPVal> {
        let mut v = self.pp_unary_expr()?;
        loop {
            let tok = self.pp_next()?;
            if tok == b'*' as i32 {
                let rhs = self.pp_unary_expr()?;
                v = PPVal::new(v.val.wrapping_mul(rhs.val), v.unsigned || rhs.unsigned);
            } else if tok == b'/' as i32 {
                let rhs = self.pp_unary_expr()?;
                if rhs.val == 0 {
                    return Err(TccError::preprocessor(
                        self.file.filename.clone(),
                        self.file.line_num as u32,
                        "division by zero in #if expression",
                    ));
                }
                let uns = v.unsigned || rhs.unsigned;
                let result = if uns {
                    ((v.val as u64).wrapping_div(rhs.val as u64)) as i64
                } else {
                    v.val.wrapping_div(rhs.val)
                };
                v = PPVal::new(result, uns);
            } else if tok == b'%' as i32 {
                let rhs = self.pp_unary_expr()?;
                if rhs.val == 0 {
                    return Err(TccError::preprocessor(
                        self.file.filename.clone(),
                        self.file.line_num as u32,
                        "modulo by zero in #if expression",
                    ));
                }
                let uns = v.unsigned || rhs.unsigned;
                let result = if uns {
                    ((v.val as u64).wrapping_rem(rhs.val as u64)) as i64
                } else {
                    v.val.wrapping_rem(rhs.val)
                };
                v = PPVal::new(result, uns);
            } else {
                self.unget_tok(tok);
                break;
            }
        }
        Ok(v)
    }

    /// Unary expressions: +, -, ~, !, defined, __has_include.
    fn pp_unary_expr(&mut self) -> TccResult<PPVal> {
        let tok = self.pp_next()?;

        match tok {
            t if t == b'+' as i32 => self.pp_unary_expr(),
            t if t == b'-' as i32 => {
                let v = self.pp_unary_expr()?;
                Ok(PPVal::new(v.val.wrapping_neg(), v.unsigned))
            }
            t if t == b'~' as i32 => {
                let v = self.pp_unary_expr()?;
                Ok(PPVal::new(!v.val, v.unsigned))
            }
            t if t == b'!' as i32 => {
                let v = self.pp_unary_expr()?;
                Ok(PPVal::signed(if v.val == 0 { 1 } else { 0 }))
            }
            t if t == b'(' as i32 => {
                let v = self.pp_cond_expr()?;
                let close = self.pp_next()?;
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
                // Must NOT expand macros for the identifier argument of
                // defined — use next_nomacro_any() so it reads from
                // macro_ptr if one is active.
                let next = self.next_nomacro_any()?;
                let (ident, need_close) = if next == b'(' as i32 {
                    (self.next_nomacro_any()?, true)
                } else {
                    (next, false)
                };
                let is_def = self.define_find(ident).is_some();
                if need_close {
                    let close = self.next_nomacro_any()?;
                    if close != b')' as i32 {
                        return Err(TccError::preprocessor(
                            self.file.filename.clone(),
                            self.file.line_num as u32,
                            "expected ')' after defined(identifier)",
                        ));
                    }
                }
                Ok(PPVal::signed(if is_def { 1 } else { 0 }))
            }
            t if t == Token::HasInclude as i32 || t == Token::HasIncludeNext as i32 => {
                let is_next = t == Token::HasIncludeNext as i32;
                let r = self.eval_has_include(is_next)?;
                Ok(PPVal::signed(r))
            }
            _ => {
                // Integer literal or character constant
                if tok == TOK_CINT || tok == TOK_CUINT || tok == TOK_CLONG
                    || tok == TOK_CULONG || tok == TOK_CLLONG
                    || tok == TOK_CULLONG || tok == TOK_CCHAR || tok == TOK_LCHAR
                {
                    let raw = unsafe { self.tokc.i } as i64;
                    // In #if expressions, all values are intmax_t (i64) or
                    // uintmax_t (u64).  A value is unsigned only when the
                    // source literal had an explicit U/u suffix, OR the
                    // value itself exceeds i64::MAX (TOK_CULLONG without
                    // explicit U means the value overflows signed 64-bit).
                    let uns = self.tok_explicit_unsigned
                        || (tok == TOK_CULLONG
                            && (unsafe { self.tokc.i } > i64::MAX as u64));
                    Ok(PPVal::new(raw, uns))
                } else if tok == TOK_PPNUM {
                    // PP-number from macro expansion — parse the string
                    // representation in pp_str_buf as an integer.
                    let s = String::from_utf8_lossy(&self.pp_str_buf).to_string();
                    let s = s.trim_end_matches('\0');
                    let ppv = self.parse_pp_number_as_ppval(s);
                    Ok(ppv)
                } else if tok >= TOK_IDENT {
                    // If the token string starts with a digit, it's a PP-number
                    // from macro expansion that wasn't converted to TOK_CINT.
                    // Parse it as an integer.
                    let ts = get_tok_str(&self.token_table, tok, None);
                    let first = ts.as_bytes().first().copied().unwrap_or(0);
                    if first.is_ascii_digit() {
                        let ppv = self.parse_pp_number_as_ppval(&ts);
                        Ok(ppv)
                    } else {
                        // Unknown identifiers evaluate to 0 in #if
                        Ok(PPVal::signed(0))
                    }
                } else if tok == TOK_LINEFEED || tok == TOK_EOF {
                    self.unget_tok(tok);
                    Ok(PPVal::signed(0))
                } else {
                    Ok(PPVal::signed(0))
                }
            }
        }
    }

    /// Evaluate `__has_include(...)` or `__has_include_next(...)`.
    /// Parse a PP-number string (like "42", "0xFF", "123U", "0x8000000000000000")
    /// as an integer value for `#if` expression evaluation.
    fn parse_pp_number_as_int(&self, s: &str) -> i64 {
        let s = s.trim();
        if s.is_empty() {
            return 0;
        }
        // Strip trailing suffixes: U, L, LL, ULL, etc.
        let mut num_str = s;
        while num_str.ends_with('U') || num_str.ends_with('u')
            || num_str.ends_with('L') || num_str.ends_with('l')
        {
            num_str = &num_str[..num_str.len() - 1];
        }
        if num_str.is_empty() {
            return 0;
        }
        // Character constants
        if num_str.starts_with('\'') {
            let inner = num_str.trim_matches('\'');
            if inner.starts_with('\\') {
                // Escape sequences
                return match inner.chars().nth(1) {
                    Some('n') => b'\n' as i64,
                    Some('t') => b'\t' as i64,
                    Some('r') => b'\r' as i64,
                    Some('0') => 0,
                    Some('\\') => b'\\' as i64,
                    Some('\'') => b'\'' as i64,
                    Some('x') | Some('X') => {
                        let hex = &inner[2..];
                        u64::from_str_radix(hex, 16).unwrap_or(0) as i64
                    }
                    _ => 0,
                };
            }
            return inner.bytes().next().unwrap_or(0) as i64;
        }
        // Hex
        if num_str.starts_with("0x") || num_str.starts_with("0X") {
            return u64::from_str_radix(&num_str[2..], 16).unwrap_or(0) as i64;
        }
        // Octal
        if num_str.starts_with('0') && num_str.len() > 1 && !num_str.contains('.') {
            return u64::from_str_radix(&num_str[1..], 8).unwrap_or(0) as i64;
        }
        // Decimal (use u64 parse to handle large unsigned values)
        num_str.parse::<u64>().map(|v| v as i64).unwrap_or(
            num_str.parse::<i64>().unwrap_or(0)
        )
    }

    /// Parse a PP-number string as a PPVal, detecting the `U` suffix and
    /// hex values that overflow i64 to set the unsigned flag, matching
    /// the C preprocessor's usual arithmetic conversions.
    fn parse_pp_number_as_ppval(&self, s: &str) -> PPVal {
        let s = s.trim();
        if s.is_empty() {
            return PPVal::signed(0);
        }
        // Detect U/u suffix → unsigned
        let upper = s.to_ascii_uppercase();
        let has_u = upper.ends_with('U')
            || upper.ends_with("UL")
            || upper.ends_with("ULL")
            || upper.ends_with("LU")
            || upper.ends_with("LLU");
        let val = self.parse_pp_number_as_int(s);
        // Also mark unsigned if hex/octal value exceeds i64::MAX
        let mut unsigned = has_u;
        if !unsigned {
            let mut num_str = s;
            while num_str.ends_with(['U', 'u', 'L', 'l']) {
                num_str = &num_str[..num_str.len() - 1];
            }
            if num_str.starts_with("0x") || num_str.starts_with("0X") {
                if let Ok(uval) = u64::from_str_radix(&num_str[2..], 16) {
                    if uval > i64::MAX as u64 {
                        unsigned = true;
                    }
                }
            } else if num_str.starts_with('0') && num_str.len() > 1 && !num_str.contains('.') {
                if let Ok(uval) = u64::from_str_radix(&num_str[1..], 8) {
                    if uval > i64::MAX as u64 {
                        unsigned = true;
                    }
                }
            }
        }
        PPVal::new(val, unsigned)
    }

    fn eval_has_include(&mut self, is_next: bool) -> TccResult<i64> {
        let open = self.next_nomacro()?;
        if open != b'(' as i32 {
            return Ok(0);
        }

        let tok = self.next_nomacro()?;
        let (filename, is_system) = if tok == TOK_LT {
            let mut name = String::new();
            loop {
                let ch_tok = self.next_nomacro()?;
                if ch_tok == TOK_GT || ch_tok == TOK_LINEFEED || ch_tok == TOK_EOF {
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
        if tok != TOK_EOF {
            self.unget_buffer.push((tok, CValue::default(), 0));
        }
    }

    // -----------------------------------------------------------------------
    // try_expand_macro() — attempt macro expansion for identifiers
    // -----------------------------------------------------------------------

    /// Attempt to expand a macro when an identifier token is encountered.
    /// Returns `Some(expanded_tokens)` if the identifier is a macro, else `None`.
    fn try_expand_macro(&mut self, tok_id: i32) -> TccResult<Option<Vec<i32>>> {
        // --- "Painted blue" check (C99 6.10.3.4) ---
        if self.noexpand_set.contains(&tok_id) {
            return Ok(None);
        }

        // __builtin_expect passthrough (FEAT-02)
        if tok_id == Token::BuiltinExpect as i32 {
            return Ok(None); // handled during macro_subst
        }

        // Check user macro table FIRST — user `#define __LINE__` overrides
        // the predefined expansion.  Only fall through to predefined macros
        // when the user has NOT defined the identifier.
        // (We peek at the macro_table; if found, the normal code below
        //  handles the expansion.  If NOT found AND this is a predefined
        //  macro token, use the built-in expansion.)
        if !self.macro_table.contains_key(&tok_id)
            && self.is_predefined_macro_tok(tok_id)
        {
            let expansion = self.expand_predefined_macro(tok_id)?;
            return Ok(Some(expansion));
        }

        // Look up in macro table
        let sym = match self.macro_table.get(&tok_id).cloned() {
            Some(s) => s,
            None => return Ok(None),
        };

        let macro_type = sym.type_.t & 0xFF;

        if macro_type == MACRO_OBJ {
            // Object-like macro: process ## paste operators in the body
            // first (C99 6.10.3.3), then recursively expand.
            if let Some(ref body) = sym.d {
                let pasted = self.paste_tokens(body);
                self.noexpand_set.insert(tok_id);
                let expanded = self.macro_subst(&pasted)?;
                self.noexpand_set.remove(&tok_id);
                let tagged = self.tag_nosubst(&expanded, tok_id);
                return Ok(Some(tagged));
            }
            return Ok(Some(Vec::new()));
        }

        if macro_type == MACRO_FUNC {
            // Function-like macro: need '(' next in the input.
            // We must skip whitespace/linefeeds between the macro name
            // and `(`, because the invocation may span lines
            // (e.g. `m\n(f)`).
            let saved_tok = self.tok;
            let saved_tokc = self.tokc;
            let mut pushed_back: Vec<i32> = Vec::new();

            let mut peeked = self.next_nomacro_any()?;
            while peeked == TOK_LINEFEED {
                pushed_back.push(peeked);
                peeked = self.next_nomacro_any()?;
            }

            if peeked == b'(' as i32 {
                // Determine the number of named parameters and variadic status.
                let is_variadic = (sym.type_.t & 0x80000000u32 as i32) != 0;
                let total_params = {
                    let mut count = 0i32;
                    let mut p = sym.next.as_ref();
                    while let Some(s) = p {
                        count += 1;
                        p = s.next.as_ref();
                    }
                    count
                };
                // Collect arguments from the live token stream
                let args = self.collect_live_macro_args_variadic(
                    total_params, is_variadic,
                )?;

                if let Some(ref body) = sym.d {
                    let substituted = self.arg_subst(body, &args, &sym)?;
                    self.noexpand_set.insert(tok_id);
                    let expanded = self.macro_subst(&substituted)?;
                    self.noexpand_set.remove(&tok_id);
                    let tagged = self.tag_nosubst(&expanded, tok_id);
                    return Ok(Some(tagged));
                }
                return Ok(Some(Vec::new()));
            }
            // Not a function-like invocation — push back all tokens
            self.unget_tok(peeked);
            for t in pushed_back.into_iter().rev() {
                self.unget_tok(t);
            }
            self.tok = saved_tok;
            self.tokc = saved_tokc;
            return Ok(None);
        }

        Ok(None)
    }

    /// Collect macro arguments from the live token stream (not a pre-built stream).
    ///
    /// Value-carrying tokens (numeric/string literals) are converted to their
    /// text representation via `tok_alloc` so that the returned token streams
    /// are entirely self-describing — every element is either a simple ASCII
    /// character token (`< TOK_IDENT`) or a tok_alloc identifier whose text
    /// can be retrieved by `get_tok_str()`.
    #[allow(dead_code)]
    fn collect_live_macro_args(&mut self) -> TccResult<Vec<Vec<i32>>> {
        let mut args: Vec<Vec<i32>> = Vec::new();
        let mut current_arg: Vec<i32> = Vec::new();
        let mut depth: i32 = 1;

        loop {
            let tok = self.next_nomacro_any()?;
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
                let stored = self.tok_to_stream_id(tok);
                current_arg.push(stored);
            }
        }

        Ok(args)
    }

    /// Like `collect_live_macro_args()` but aware of variadic parameters.
    ///
    /// When `is_variadic` is true and we have collected `total_params - 1`
    /// complete arguments (i.e. the named non-variadic ones), all remaining
    /// tokens — including commas — are folded into the last argument.  This
    /// means the variadic parameter gets a single `Vec<i32>` whose tokens
    /// include the separating commas, matching C99 §6.10.3 semantics.
    ///
    /// If fewer arguments are provided than the macro declares, the missing
    /// slots are filled with empty `Vec`s so that `arg_subst()` always finds
    /// an entry for every parameter index.
    fn collect_live_macro_args_variadic(
        &mut self,
        total_params: i32,
        is_variadic: bool,
    ) -> TccResult<Vec<Vec<i32>>> {
        let mut args: Vec<Vec<i32>> = Vec::new();
        let mut current_arg: Vec<i32> = Vec::new();
        let mut depth: i32 = 1;
        // For variadic macros, stop splitting at commas once we've collected
        // enough named-parameter args.  The "stop" count is (total_params - 1)
        // because the variadic parameter itself occupies the last slot.
        let stop_split_at = if is_variadic && total_params > 0 {
            (total_params - 1) as usize
        } else {
            usize::MAX // never stop splitting for non-variadic
        };

        loop {
            let tok = self.next_nomacro_any()?;
            // Capture SPC flag once — used for ALL token types.
            let spc = if (self.tok_flags & TOK_FLAG_SPC) != 0 {
                STREAM_SPC_BIT
            } else {
                0
            };
            if tok == b'(' as i32 {
                depth += 1;
                current_arg.push(tok | spc);
            } else if tok == b')' as i32 {
                depth -= 1;
                if depth == 0 {
                    args.push(current_arg);
                    break;
                }
                current_arg.push(tok | spc);
            } else if tok == b',' as i32 && depth == 1 && args.len() < stop_split_at {
                // Normal comma split (for named params)
                args.push(current_arg);
                current_arg = Vec::new();
            } else if tok == b',' as i32 && depth == 1 {
                // Variadic region: keep comma as a token in the arg
                current_arg.push(b',' as i32 | spc);
            } else if tok == TOK_EOF {
                return Err(TccError::preprocessor(
                    self.file.filename.clone(),
                    self.file.line_num as u32,
                    "unterminated macro argument list",
                ));
            } else if tok == TOK_LINEFEED {
                // Skip linefeeds in args (they're whitespace)
                continue;
            } else {
                let stored = self.tok_to_stream_id(tok);
                current_arg.push(stored | spc);
            }
        }

        // Pad with empty Vecs when fewer args than params were supplied,
        // so arg_subst can always index every parameter slot.
        let tp = total_params as usize;
        while args.len() < tp {
            args.push(Vec::new());
        }

        Ok(args)
    }

    /// Convert a token (possibly value-carrying) into a stream-safe token ID.
    ///
    /// For value-carrying tokens (`TOK_CINT`, `TOK_CFLOAT`, `TOK_STR`,
    /// `TOK_PPNUM`, etc.) this converts the token+value into a `tok_alloc`
    /// identifier whose text representation matches the original source text.
    /// For identifier tokens (`>= TOK_IDENT`) and simple character tokens,
    /// the token is returned as-is.
    fn tok_to_stream_id(&mut self, tok: i32) -> i32 {
        if tok >= TOK_IDENT {
            // For keyword aliases (e.g. `__noreturn__` mapped to
            // `Token::Noreturn`), `last_ident_alloc_id` holds the
            // spelling-preserving entry ID.  Use it so that `##`
            // pasting and `-E` output produce the original text.
            //
            // Safety: validate that the alias entry's `ts.tok` matches
            // the current keyword value, confirming this really is an
            // alias for `tok` and not a stale/coincidental value.
            let aid = self.last_ident_alloc_id;
            if aid != 0 && aid != tok && aid >= TOK_IDENT {
                let aidx = (aid - TOK_IDENT) as usize;
                if aidx < self.token_table.table_ident.len()
                    && self.token_table.table_ident[aidx].tok == tok
                {
                    self.last_ident_alloc_id = 0; // consume
                    return aid;
                }
            }
            // Reset unconditionally — the sideband was either consumed
            // above or is invalid for this token.
            self.last_ident_alloc_id = 0;
            return tok; // regular identifier or primary keyword
        }
        // Check if this is a value-carrying token
        match tok {
            TOK_CINT | TOK_CUINT | TOK_CLONG | TOK_CULONG
            | TOK_CLLONG | TOK_CULLONG | TOK_CCHAR | TOK_LCHAR
            | TOK_CFLOAT | TOK_CDOUBLE | TOK_CLDOUBLE
            | TOK_PPNUM | TOK_STR | TOK_LSTR | TOK_PPSTR => {
                let text = get_tok_str(&self.token_table, tok, Some(&self.tokc));
                if text.is_empty() {
                    tok
                } else {
                    tok_alloc(&mut self.token_table, text.as_bytes())
                }
            }
            _ => tok, // Simple character tokens pass through
        }
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
            // __FILE__ expands to a string literal with double quotes,
            // e.g. `"tests/pp/23.S"` — matching the C standard 6.10.8.
            let name = self.file.filename.clone();
            let quoted = format!("\"{}\"", name);
            let str_tok = tok_alloc(&mut self.token_table, quoted.as_bytes());
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
    /// Only fires when there is NO user `#define` overriding the built-in.
    fn try_predefined_macro(&mut self, tok_id: i32) -> TccResult<bool> {
        if !self.is_predefined_macro_tok(tok_id) {
            return Ok(false);
        }
        // User `#define __LINE__` (etc.) overrides the built-in.
        if self.macro_table.contains_key(&tok_id) {
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
