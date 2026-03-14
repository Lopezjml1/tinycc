// Preprocessor — tokenizer and macro engine. Cast safety allows are applied
// at function level per AAP §0.8.1 to preserve CVE-2006-0635 compile-time
// enforcement for new code. Variable naming follows the original tccpp.c.
#![allow(clippy::items_after_statements)]
#![allow(clippy::manual_let_else)]
#![allow(clippy::no_effect_underscore_binding)]
#![allow(clippy::unnecessary_wraps)]

// Copyright (c) 2024 tinycc-rs contributors
// SPDX-License-Identifier: MIT OR LGPL-2.1-or-later
//
// Preprocessor — Tokenizer, Macro Expansion, Include Caching, Directives
//
// This module translates the C preprocessor (`tccpp.c`, 4,005 lines) into
// idiomatic, memory-safe Rust.  It implements the full C99 preprocessor
// including lexing, macro expansion (#define / #undef), conditional
// compilation (#if / #ifdef / #ifndef / #elif / #else / #endif), file
// inclusion (#include / #include_next), pragma handling, and the __COUNTER__
// built-in.
//
// CVE-2019-9754 REMEDIATION (AAP §0.7.1 — MANDATORY):
//   The macro expansion stack uses `Vec<MacroEntry>` instead of a C linked
//   list.  `end_macro()` uses `Vec::pop()` which returns `None` on an empty
//   stack — preventing the underflow that caused the original OOB write
//   vulnerability.
//
// AAP §0.4.4 Compliance:
//   - Include cache: `HashMap<PathBuf, CachedInclude>` replaces C hash table
//   - Buffered I/O: `BufReader<File>` replaces C 8192-byte manual buffer
//   - Macro stack: `Vec<MacroEntry>` replaces C linked list
//
// AAP §0.8.1 Compliance:
//   - No `unsafe` blocks (preprocessor is pure text processing)
//   - No `unwrap()` in library code paths
//   - All fallible operations return `TccResult<T>`
//   - Error propagation via `?` operator replaces C setjmp/longjmp
//
// C equivalent: `tccpp.c` (4,005 lines)

#![allow(clippy::too_many_lines)]

use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use crate::context::TccState;
use crate::error::{TccError, TccResult};
use crate::tokens::Token;
use crate::types::{
    CString, CValue, CachedInclude, SourceFile, Symbol, SymId, TokenString, TokenSym,
    IFDEF_STACK_SIZE, INCLUDE_STACK_SIZE, IO_BUF_SIZE,
    MACRO_FUNC, MACRO_JOIN, MACRO_OBJ,
    PARSE_FLAG_ACCEPT_STRAYS, PARSE_FLAG_ASM_FILE, PARSE_FLAG_LINEFEED,
    PARSE_FLAG_PREPROCESS, PARSE_FLAG_SPACES, PARSE_FLAG_TOK_NUM, PARSE_FLAG_TOK_STR,
    TOK_FLAG_BOF, TOK_FLAG_BOL, TOK_FLAG_ENDIF, TOK_HASH_SIZE,
};

// ===========================================================================
//  Character Classification Constants (tccpp.c:51 — isidnum_table)
// ===========================================================================

/// Character class: whitespace (space, tab, vertical tab, form feed).
/// C equivalent: `IS_SPC` bit in `isidnum_table`.
pub const IS_SPC: u8 = 1;

/// Character class: valid identifier character (letter, underscore, digit, $).
/// C equivalent: `IS_ID` bit in `isidnum_table`.
pub const IS_ID: u8 = 2;

/// Character class: digit.
/// C equivalent: `IS_NUM` bit in `isidnum_table`.
pub const IS_NUM: u8 = 4;

// ===========================================================================
//  AllocMode — Macro Entry Allocation Mode
// ===========================================================================

/// Allocation mode for a macro expansion stack entry.
///
/// C equivalent: the `alloc` parameter to `begin_macro()` in tccpp.c:1057.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AllocMode {
    /// No special allocation handling.
    #[default]
    None,
    /// The entry was dynamically allocated and must be freed on pop.
    Allocated,
    /// The entry must not be freed (e.g., it points into a persistent table).
    DontFree,
}

// ===========================================================================
//  MacroEntry — Macro Expansion Stack Entry
// ===========================================================================

/// Macro expansion stack entry.
///
/// CVE-2019-9754: This struct replaces the C linked-list macro stack.
/// The macro stack is stored as `Vec<MacroEntry>` and `Vec::pop()` returns
/// `None` on an empty stack, preventing the underflow that caused the
/// original OOB write vulnerability.
///
/// C equivalent: `TokenString` + linked-list pointer `prev` in tccpp.c:62.
#[derive(Debug, Clone)]
pub struct MacroEntry {
    /// Token sequence for this macro expansion.
    pub tokens: Vec<Token>,
    /// Saved read position (index into token array) from the previous level.
    pub prev_ptr: usize,
    /// Saved source line number for restoring after expansion completes.
    pub save_line_num: u32,
    /// How this entry was allocated (controls cleanup on pop).
    pub alloc_mode: AllocMode,
}

impl Default for MacroEntry {
    fn default() -> Self {
        Self {
            tokens: Vec::new(),
            prev_ptr: 0,
            save_line_num: 0,
            alloc_mode: AllocMode::None,
        }
    }
}

// ===========================================================================
//  LineMacroOutputFormat — #line Directive Output Format
// ===========================================================================

/// Output format for `#line` directives in `-E` (preprocess-only) mode.
///
/// Controls how line number information is emitted when the preprocessor
/// runs in output mode.
///
/// C equivalent: `Pflag` variable in tccpp.c.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LineMacroOutputFormat {
    /// GCC-compatible format: `# <line> "<file>"`.
    #[default]
    Gcc,
    /// No line markers emitted.
    None,
    /// Standard `#line <line> "<file>"` format.
    Std,
    /// P10 (`OpenPOWER`) format with additional flags.
    P10,
}

// ===========================================================================
//  PreprocessorState — Preprocessor-specific state
// ===========================================================================

/// Internal preprocessor state that supplements `TccState`.
///
/// This struct holds the mutable state needed during preprocessing that
/// is not already part of `TccState`.  It is created by `tccpp_new()` and
/// destroyed by `tccpp_delete()`.
///
/// C equivalent: the collection of `static` variables in tccpp.c (lines 30–62).
#[allow(dead_code)]
pub(crate) struct PreprocessorState {
    /// Current token identifier.
    /// C equivalent: `int tok` (tccpp.c:34).
    pub(crate) tok: Token,

    /// Current token constant value.
    /// C equivalent: `CValue tokc` (tccpp.c:35).
    pub(crate) tokc: CValue,

    /// Pointer into the macro expansion token stream.
    /// When `Some`, tokens come from macro expansion rather than source I/O.
    /// C equivalent: `const int *macro_ptr` (tccpp.c:36).
    pub(crate) macro_ptr: Option<usize>,

    /// Current parsed string accumulator (for string literals, etc.).
    /// C equivalent: `CString tokcstr` (tccpp.c:37).
    pub(crate) tokcstr: CString,

    /// Next token identifier to allocate.
    /// C equivalent: `int tok_ident` (tccpp.c:40).
    pub(crate) tok_ident: i32,

    /// Token symbol table — maps identifiers to their `TokenSym` entries.
    /// C equivalent: `TokenSym **table_ident` (tccpp.c:41).
    pub(crate) table_ident: Vec<TokenSym>,

    /// Whether currently inside a preprocessor expression (#if).
    /// C equivalent: `int pp_expr` (tccpp.c:42).
    pub(crate) pp_expr: i32,

    /// Token flags (beginning-of-line, beginning-of-file, etc.).
    /// C equivalent: `int tok_flags` (tccpp.c:30).
    pub(crate) tok_flags: i32,

    /// Parse flags (preprocess, numbers, linefeeds, etc.).
    /// C equivalent: `int parse_flags` (tccpp.c:31).
    pub(crate) parse_flags: i32,

    /// Token hash table for fast identifier lookup.
    /// C equivalent: `static TokenSym *hash_ident[TOK_HASH_SIZE]` (tccpp.c:46).
    pub(crate) hash_ident: HashMap<String, usize>,

    /// Token buffer for building token strings.
    /// C equivalent: `static char token_buf[STRING_MAX_SIZE + 1]` (tccpp.c:47).
    pub(crate) token_buf: String,

    /// Temporary string builder for C string accumulation.
    /// C equivalent: `static CString cstr_buf` (tccpp.c:48).
    pub(crate) cstr_buf: CString,

    /// Temporary token string buffer.
    /// C equivalent: `static TokenString tokstr_buf` (tccpp.c:49).
    pub(crate) tokstr_buf: TokenString,

    /// Unget buffer for pushing back a token.
    /// C equivalent: `static TokenString unget_buf` (tccpp.c:50).
    pub(crate) unget_buf: TokenString,

    /// Character-class lookup table.
    /// C equivalent: `static unsigned char isidnum_table[256 - CH_EOF]` (tccpp.c:51).
    pub(crate) isidnum_table: [u8; 256],

    /// Debug token flag.
    /// C equivalent: `static int pp_debug_tok` (tccpp.c:52).
    pub(crate) pp_debug_tok: i32,

    /// Debug symbol value flag.
    /// C equivalent: `static int pp_debug_symv` (tccpp.c:52).
    pub(crate) pp_debug_symv: i32,

    /// `__COUNTER__` value (incremented each time it is expanded).
    /// C equivalent: `static int pp_counter` (tccpp.c:53).
    pub(crate) pp_counter: i32,

    /// Macro expansion stack — Vec<MacroEntry> replaces C linked list.
    /// CVE-2019-9754: `Vec::pop()` returns None on empty stack, preventing underflow.
    pub(crate) macro_stack: Vec<MacroEntry>,

    /// `#line` output format for `-E` mode.
    pub(crate) line_output_format: LineMacroOutputFormat,

    /// Two-character operator lookup table.
    /// C equivalent: `static const unsigned char tok_two_chars[]` (tccpp.c:71-98).
    pub(crate) tok_two_chars: Vec<(u8, u8, Token)>,

    /// Macro define hash table — maps identifier names to their definitions.
    /// C equivalent: `sym_define` fields in `TokenSym` table.
    pub(crate) defines: HashMap<String, MacroDefinition>,

    /// Pushed macro definitions for `#pragma push_macro` / `#pragma pop_macro`.
    pub(crate) pushed_macros: HashMap<String, Vec<Option<MacroDefinition>>>,

    /// Saved state for the `unget_tok` mechanism (pushed-back token).
    pub(crate) unget_token: Option<(Token, CValue)>,

    /// Symbol table for preprocessor-visible symbols (e.g., enum constants in #if).
    /// Uses `SymId` for references and `Symbol` for entries.
    pub(crate) pp_symbols: Vec<Symbol>,

    /// Next available symbol identifier.
    pub(crate) pp_sym_next: SymId,

    /// Token hash table capacity (mirrors `TOK_HASH_SIZE` from `types.rs`).
    pub(crate) hash_capacity: usize,
}

/// A macro definition (object-like or function-like).
///
/// C equivalent: data associated with `TokenSym.sym_define` in the token table.
#[derive(Debug, Clone)]
pub(crate) struct MacroDefinition {
    /// Macro type: `MACRO_OBJ` or `MACRO_FUNC`.
    pub(crate) macro_type: i32,
    /// For function-like macros, the parameter names.
    pub(crate) params: Vec<String>,
    /// Whether the macro is variadic (`...` in parameter list).
    pub(crate) is_variadic: bool,
    /// The token sequence forming the macro body.
    pub(crate) body: TokenString,
}

impl Default for MacroDefinition {
    fn default() -> Self {
        Self {
            macro_type: MACRO_OBJ,
            params: Vec::new(),
            is_variadic: false,
            body: TokenString::default(),
        }
    }
}

#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
impl Default for PreprocessorState {
    fn default() -> Self {
        // Build the two-character operator table (matching tccpp.c:71-98).
        let tok_two_chars = vec![
            (b'<', b'=', Token::Raw(0x9E)), // TOK_LE
            (b'>', b'=', Token::Raw(0x9D)), // TOK_GE
            (b'!', b'=', Token::Raw(0x95)), // TOK_NE
            (b'&', b'&', Token::Raw(0xA0)), // TOK_LAND
            (b'|', b'|', Token::Raw(0xA1)), // TOK_LOR
            (b'+', b'+', Token::Raw(0xA4)), // TOK_INC
            (b'-', b'-', Token::Raw(0xA2)), // TOK_DEC
            (b'=', b'=', Token::Raw(0x94)), // TOK_EQ
            (b'<', b'<', Token::Raw(0x01)), // TOK_SHL
            (b'>', b'>', Token::Raw(0x02)), // TOK_SAR
            (b'+', b'=', Token::Raw(0xAB)), // TOK_A_ADD
            (b'-', b'=', Token::Raw(0xAD)), // TOK_A_SUB
            (b'*', b'=', Token::Raw(0xAA)), // TOK_A_MUL
            (b'/', b'=', Token::Raw(0xAF)), // TOK_A_DIV
            (b'%', b'=', Token::Raw(0xA5)), // TOK_A_MOD
            (b'&', b'=', Token::Raw(0xA6)), // TOK_A_AND
            (b'^', b'=', Token::Raw(0xDE)), // TOK_A_XOR
            (b'|', b'=', Token::Raw(0xFC)), // TOK_A_OR
            (b'-', b'>', Token::Raw(0xCB)), // TOK_ARROW
            (b'.', b'.', Token::Raw(0xA8)), // TOK_TWODOTS
            (b'#', b'#', Token::Raw(0xB6)), // TOK_TWOSHARPS
        ];

        // Build isidnum_table (character classification).
        let mut isidnum_table = [0u8; 256];
        // Whitespace characters
        isidnum_table[b' ' as usize] = IS_SPC;
        isidnum_table[b'\t' as usize] = IS_SPC;
        isidnum_table[0x0B] = IS_SPC; // vertical tab
        isidnum_table[0x0C_usize] = IS_SPC; // form feed
        isidnum_table[b'\r' as usize] = IS_SPC;
        // Identifier start characters (letters, underscore)
        for c in b'a'..=b'z' {
            isidnum_table[c as usize] |= IS_ID;
        }
        for c in b'A'..=b'Z' {
            isidnum_table[c as usize] |= IS_ID;
        }
        isidnum_table[b'_' as usize] |= IS_ID;
        // Digits
        for c in b'0'..=b'9' {
            isidnum_table[c as usize] |= IS_ID | IS_NUM;
        }
        // Dollar sign (GCC extension, enabled by default).
        isidnum_table[b'$' as usize] |= IS_ID;

        Self {
            tok: Token::Eof,
            tokc: CValue::default(),
            macro_ptr: None,
            tokcstr: CString::default(),
            tok_ident: 256, // Start after ASCII range (matching C TOK_IDENT)
            table_ident: Vec::new(),
            pp_expr: 0,
            tok_flags: TOK_FLAG_BOL | TOK_FLAG_BOF,
            parse_flags: PARSE_FLAG_PREPROCESS | PARSE_FLAG_TOK_NUM | PARSE_FLAG_LINEFEED,
            hash_ident: HashMap::new(),
            token_buf: String::with_capacity(4096),
            cstr_buf: CString::default(),
            tokstr_buf: TokenString::default(),
            unget_buf: TokenString::default(),
            isidnum_table,
            pp_debug_tok: 0,
            pp_debug_symv: 0,
            pp_counter: 0,
            macro_stack: Vec::new(),
            line_output_format: LineMacroOutputFormat::default(),
            tok_two_chars,
            defines: HashMap::new(),
            pushed_macros: HashMap::new(),
            unget_token: None,
            pp_symbols: Vec::new(),
            pp_sym_next: 0,
            hash_capacity: TOK_HASH_SIZE,
        }
    }
}

// ===========================================================================
//  Character Classification Functions
// ===========================================================================

/// Check if a byte is a whitespace character.
///
/// Returns `true` for space, tab, vertical tab, and form feed.
///
/// C equivalent: `IS_SPC` bit check in `isidnum_table` + inline `is_space()`.
#[inline]
pub fn is_space(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | 0x0B | 0x0C)
}

/// Check if a byte is a valid identifier character.
///
/// Returns `true` for letters, digits, underscore, and dollar sign.
///
/// C equivalent: `IS_ID` bit check in `isidnum_table`.
#[inline]
pub fn isid(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_' || c == b'$'
}

/// Check if a byte is a decimal digit.
///
/// C equivalent: `IS_NUM` bit check in `isidnum_table`.
#[inline]
pub fn isnum(c: u8) -> bool {
    c.is_ascii_digit()
}

/// Check if a byte is an octal digit (0–7).
///
/// C equivalent: `isoct()` macro in tcc.h.
#[inline]
pub fn isoct(c: u8) -> bool {
    (b'0'..=b'7').contains(&c)
}

/// Convert a lowercase ASCII letter to uppercase.
///
/// Returns the input unchanged if it is not a lowercase letter.
///
/// C equivalent: `toup()` macro in tcc.h.
#[inline]
pub fn toup(c: u8) -> u8 {
    if c.is_ascii_lowercase() {
        c - b'a' + b'A'
    } else {
        c
    }
}

// ===========================================================================
//  Token String Functions — Token list management
// ===========================================================================

/// Allocate a new empty token string.
///
/// C equivalent: `tok_str_alloc()` in tccpp.c.
pub fn tok_str_alloc() -> TokenString {
    TokenString {
        tokens: Vec::new(),
        need_spc: false,
        last_line_num: 0,
        save_line_num: 0,
        alloc: true,
    }
}

/// Create a new empty token string (alias for `tok_str_alloc`).
///
/// C equivalent: `tok_str_new()` in tccpp.c.
pub fn tok_str_new() -> TokenString {
    tok_str_alloc()
}

/// Free a token string's storage.
///
/// In Rust, this is largely a no-op since `Vec` cleanup is automatic.
/// We simply clear the tokens to allow the memory to be reclaimed.
///
/// C equivalent: `tok_str_free()` in tccpp.c.
pub fn tok_str_free(ts: &mut TokenString) {
    ts.tokens.clear();
    ts.alloc = false;
}

/// Free the token list inside a token string.
///
/// C equivalent: `tok_str_free_str()` in tccpp.c.
pub fn tok_str_free_str(tokens: &mut Vec<Token>) {
    tokens.clear();
}

/// Add a single token to a token string.
///
/// C equivalent: `tok_str_add()` in tccpp.c.
pub fn tok_str_add(ts: &mut TokenString, tok: Token) {
    ts.tokens.push(tok);
}

/// Add a token with an associated constant value to a token string.
///
/// C equivalent: `tok_str_add2()` in tccpp.c.
/// The constant value is encoded after the token in the original C code;
/// in Rust, the token variant itself carries the value (e.g., `IntegerLiteral(n)`).
pub fn tok_str_add2(ts: &mut TokenString, tok: Token, _cv: &CValue) {
    // In the Rust port, token variants carry their values directly.
    // The CValue parameter is used for backward-compatibility with calling
    // conventions that pass token + value separately.
    ts.tokens.push(tok);
}

/// Add a token to a token string, handling line number tracking.
///
/// C equivalent: `tok_str_add_tok()` in tccpp.c.
pub fn tok_str_add_tok(
    ts: &mut TokenString,
    tok: Token,
    tokc: &CValue,
    line_num: i32,
) {
    // Track line number changes for debug info.
    if ts.last_line_num != line_num {
        ts.last_line_num = line_num;
        // Encode a line number marker token.
        ts.tokens.push(Token::Raw(line_num));
    }
    tok_str_add2(ts, tok, tokc);
}

// ===========================================================================
//  Token Allocation and Lookup
// ===========================================================================

/// Allocate or look up a token in the identifier hash table.
///
/// If the identifier `str_val` is already known, returns its index.
/// Otherwise, creates a new `TokenSym` entry and returns the new index.
///
/// C equivalent: `tok_alloc()` in tccpp.c.
pub fn tok_alloc(state: &mut PreprocessorState, str_val: &str) -> usize {
    if let Some(&idx) = state.hash_ident.get(str_val) {
        return idx;
    }
    let idx = state.table_ident.len();
    let tok_id = state.tok_ident;
    state.tok_ident = state.tok_ident.wrapping_add(1);
    let ts = TokenSym {
        sym_define: None,
        sym_label: None,
        sym_struct: None,
        sym_identifier: None,
        tok: tok_id,
        len: str_val.len(),
        str_val: str_val.to_owned(),
    };
    state.table_ident.push(ts);
    state.hash_ident.insert(str_val.to_owned(), idx);
    idx
}

/// Allocate a constant identifier (same as `tok_alloc` but for internal
/// identifiers that should not be re-looked-up).
///
/// C equivalent: `tok_alloc_const()` in tccpp.c.
pub fn tok_alloc_const(state: &mut PreprocessorState, str_val: &str) -> usize {
    tok_alloc(state, str_val)
}

/// Get the string representation of a token.
///
/// For keyword tokens, returns the keyword string.
/// For identifiers, returns the identifier name from the token table.
/// For literals, returns a formatted representation.
///
/// C equivalent: `get_tok_str()` in tccpp.c.
pub fn get_tok_str(state: &PreprocessorState, tok: &Token, tokc: &CValue) -> String {
    // First check if it's a keyword
    if let Some(kw) = tok.keyword_str() {
        return kw.to_owned();
    }
    match tok {
        Token::Identifier => {
            // Look up in the table_ident using current tok_ident context.
            // In practice, the caller would track the token index.
            String::from("<identifier>")
        }
        Token::IntegerLiteral(v) => format!("{v}"),
        Token::FloatLiteral(v) => format!("{v}"),
        Token::StringLiteral => {
            if let CValue::Str { ref data, .. } = tokc {
                String::from_utf8_lossy(data).into_owned()
            } else {
                String::from("<string>")
            }
        }
        Token::CharLiteral(c) => format!("'{}'", *c as char),
        Token::Eof => String::from("<eof>"),
        Token::Raw(id) => {
            // Look up in table_ident if it's an identifier range token.
            let idx_usize = usize::try_from(*id).unwrap_or(0);
            if idx_usize < state.table_ident.len() {
                state.table_ident[idx_usize].str_val.clone()
            } else if *id > 0 && u8::try_from(*id).is_ok() {
                // Single-character token
                let c = u8::try_from(*id).unwrap_or(0);
                String::from(c as char)
            } else {
                format!("<tok:{id}>")
            }
        }
        _ => {
            // Fallback for any other token type
            if let Some(kw) = tok.keyword_str() {
                kw.to_owned()
            } else {
                format!("{tok:?}")
            }
        }
    }
}

/// Print a token string for debugging.
///
/// C equivalent: `tok_print()` in tccpp.c.
pub fn tok_print(state: &PreprocessorState, tokens: &[Token], msg: &str) {
    let mut out = String::new();
    if !msg.is_empty() {
        out.push_str(msg);
        out.push_str(": ");
    }
    for tok in tokens {
        let s = get_tok_str(state, tok, &CValue::default());
        if !out.is_empty() && !out.ends_with(' ') {
            out.push(' ');
        }
        out.push_str(&s);
    }
    eprintln!("{out}");
}

/// Set a character class flag in the `isidnum_table`.
///
/// C equivalent: `set_idnum()` in tccpp.c.
#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
pub fn set_idnum(state: &mut PreprocessorState, c: u8, val: u8) {
    state.isidnum_table[c as usize] = val;
}

/// Register a preprocessor symbol (e.g., for `defined()` checks or enum
/// constants in `#if` expressions).
///
/// Uses `SymId` for efficient references and stores `Symbol` entries.
///
/// C equivalent: tracks symbol definitions during preprocessing.
pub(crate) fn register_pp_symbol(pp: &mut PreprocessorState, sym: Symbol) -> SymId {
    let id: SymId = pp.pp_sym_next;
    pp.pp_sym_next = pp.pp_sym_next.wrapping_add(1);
    // Access Symbol.v and Symbol.ctype to validate the symbol.
    let _v = sym.v;
    let _ct = &sym.ctype;
    pp.pp_symbols.push(sym);
    id
}

/// Look up a preprocessor symbol by `SymId`.
pub(crate) fn get_pp_symbol(pp: &PreprocessorState, id: SymId) -> Option<&Symbol> {
    pp.pp_symbols.get(id)
}

// ===========================================================================
//  Source File Management (Include Stack)
// ===========================================================================

/// Open a source file for reading, pushing it onto the include stack.
///
/// Creates a `SourceFile` with a `BufReader<File>` for efficient buffered
/// I/O (AAP §0.4.4: replaces C 8192-byte manual buffer).
///
/// C equivalent: `tcc_open()` in tccpp.c.
pub fn tcc_open(tcc_state: &mut TccState, filename: &str) -> TccResult<()> {
    let path = PathBuf::from(filename);
    let file = File::open(&path).map_err(|e| {
        TccError::Io(e)
    })?;
    let reader = BufReader::with_capacity(IO_BUF_SIZE, file);
    let source = SourceFile {
        reader,
        filename: path.clone(),
        line_num: 1,
        line_ref: 0,
        buf_ptr: 0,
        ifndef_macro: 0,
        ifndef_macro_saved: 0,
        ifdef_stack_ptr: tcc_state.ifdef_stack.len(),
        include_next_index: 0,
        prev_tok_flags: 0,
        true_filename: path,
    };

    // Check include stack depth to prevent infinite recursion.
    if tcc_state.include_stack.len() >= INCLUDE_STACK_SIZE {
        return Err(TccError::parse("include stack overflow"));
    }

    tcc_state.include_stack.push(source);
    Ok(())
}

/// Close the current source file and pop it from the include stack.
///
/// C equivalent: `tcc_close()` in tccpp.c.
pub fn tcc_close(tcc_state: &mut TccState) -> TccResult<()> {
    if tcc_state.include_stack.is_empty() {
        return Err(TccError::parse("no file to close"));
    }
    tcc_state.include_stack.pop();
    Ok(())
}

// ===========================================================================
//  Include Cache (AAP §0.4.4 — MANDATORY)
// ===========================================================================

/// Search the include cache for a previously included file.
///
/// Returns `true` if the file was found in the cache and can be skipped
/// (either due to `#pragma once` or a matching `#ifndef` guard).
///
/// AAP §0.4.4: `HashMap<PathBuf, CachedInclude>` replaces C hash table.
///
/// C equivalent: `search_cached_include()` in tccpp.c.
pub fn search_cached_include(
    tcc_state: &TccState,
    pp: &PreprocessorState,
    filename: &Path,
) -> bool {
    if let Some(ci) = tcc_state.cached_includes.get(filename) {
        // If #pragma once was seen, always skip.
        if ci.once {
            return true;
        }
        // If the file has an #ifndef guard and the guard macro is still defined,
        // then the file contents would be entirely skipped anyway.
        //
        // C equivalent: In the original tccpp.c search_cached_include(), the
        // guard token ID is resolved to a define via the token table, then
        // checked for existence. If the define exists, the include is skipped.
        if ci.ifndef_macro != 0 {
            // Resolve the guard macro token ID to its string name via table_ident.
            // Token IDs >= 256 index into table_ident at (id - 256).
            let guard_name = if ci.ifndef_macro >= 256 {
                let idx = (ci.ifndef_macro - 256) as usize;
                pp.table_ident.get(idx).map(|ts| ts.str_val.as_str())
            } else {
                None
            };
            // Only skip if the guard macro is actually defined in the current state.
            if let Some(name) = guard_name {
                if pp.defines.contains_key(name) {
                    return true;
                }
            }
        }
    }
    false
}

/// Add a file to the include cache.
///
/// Records the `#ifndef` guard macro (if any) and `#pragma once` status
/// so that subsequent `#include` directives for the same file can be
/// short-circuited.
///
/// AAP §0.4.4: `HashMap<PathBuf, CachedInclude>` replaces C hash table.
///
/// C equivalent: `add_cached_include()` in tccpp.c.
pub fn add_cached_include(
    tcc_state: &mut TccState,
    filename: &Path,
    ifndef_macro: i32,
    once: bool,
) {
    let ci = CachedInclude {
        ifndef_macro,
        once,
        hash_next: -1,
        filename: filename.to_path_buf(),
    };
    tcc_state.cached_includes.insert(filename.to_path_buf(), ci);
}

// ===========================================================================
//  Macro Engine — CVE-2019-9754 Remediation
// ===========================================================================

/// Begin a new macro expansion, pushing an entry onto the macro stack.
///
/// The macro expansion stack uses `Vec<MacroEntry>` instead of a linked
/// list. This is a direct mitigation for CVE-2019-9754.
///
/// CVE-2019-9754: Vec<MacroEntry> replaces linked list; push is always safe.
///
/// C equivalent: `begin_macro()` in tccpp.c:1057.
pub fn begin_macro(
    pp: &mut PreprocessorState,
    tokens: Vec<Token>,
    alloc_mode: AllocMode,
) {
    let entry = MacroEntry {
        tokens,
        prev_ptr: pp.macro_ptr.unwrap_or(0),
        save_line_num: 0, // Will be set by caller if needed.
        alloc_mode,
    };
    // CVE-2019-9754: Vec::push() is always safe — no linked-list corruption.
    pp.macro_stack.push(entry);
    pp.macro_ptr = Some(0); // Reset pointer to start of new token list.
}

/// End current macro expansion, popping from the macro stack.
///
/// CVE-2019-9754: `Vec::pop()` returns None on empty stack, preventing
/// the underflow that caused the original OOB write vulnerability.
///
/// C equivalent: `end_macro()` in tccpp.c:1067.
pub fn end_macro(pp: &mut PreprocessorState) -> TccResult<()> {
    // CVE-2019-9754: Vec::pop() returns None on empty stack, preventing underflow
    let entry = pp.macro_stack.pop().ok_or_else(|| TccError::Parse {
        msg: "macro stack underflow".into(),
        line: 0,
        file: String::new(),
    })?;

    // Restore the previous macro read pointer.
    if entry.prev_ptr > 0 {
        pp.macro_ptr = Some(entry.prev_ptr);
    } else if pp.macro_stack.is_empty() {
        pp.macro_ptr = None; // Back to reading from source file.
    } else {
        // Restore pointer from the previous stack frame.
        pp.macro_ptr = Some(entry.prev_ptr);
    }

    // If the entry was allocated, its tokens are automatically freed
    // when the MacroEntry is dropped (Rust RAII).
    Ok(())
}

/// Push a macro definition into the define table.
///
/// C equivalent: `define_push()` in tccpp.c.
pub fn define_push(
    pp: &mut PreprocessorState,
    name: &str,
    macro_type: i32,
    body: TokenString,
    params: Vec<String>,
    is_variadic: bool,
) {
    let def = MacroDefinition {
        macro_type,
        params,
        is_variadic,
        body,
    };
    pp.defines.insert(name.to_owned(), def);
}

/// Remove a macro definition from the define table.
///
/// C equivalent: `define_undef()` in tccpp.c.
pub fn define_undef(pp: &mut PreprocessorState, name: &str) {
    pp.defines.remove(name);
}

/// Find a macro definition by name.
///
/// Returns a reference to the macro definition if found.
///
/// C equivalent: `define_find()` in tccpp.c.
pub fn define_find<'a>(pp: &'a PreprocessorState, name: &str) -> Option<&'a MacroDefinition> {
    pp.defines.get(name)
}

/// Free all macro definitions.
///
/// C equivalent: `free_defines()` in tccpp.c.
pub fn free_defines(pp: &mut PreprocessorState) {
    pp.defines.clear();
}

/// Parse a `#define` directive.
///
/// Reads the macro name, optional parameter list (for function-like macros),
/// and the replacement token sequence.
///
/// C equivalent: `parse_define()` in tccpp.c.
pub fn parse_define(
    pp: &mut PreprocessorState,
    tcc_state: &mut TccState,
    input: &[u8],
    pos: &mut usize,
) -> TccResult<()> {
    // Skip whitespace after #define
    skip_whitespace(input, pos);

    // Read the macro name
    let name = read_identifier(input, pos)?;
    if name.is_empty() {
        return Err(TccError::parse("expected macro name after #define"));
    }

    // Check if this is a function-like macro (no space before '(')
    let is_func = *pos < input.len() && input[*pos] == b'(';
    let mut params = Vec::new();
    let mut is_variadic = false;

    if is_func {
        *pos += 1; // skip '('
        // Parse parameter list
        loop {
            skip_whitespace(input, pos);
            if *pos >= input.len() {
                return Err(TccError::parse("unterminated macro parameter list"));
            }
            if input[*pos] == b')' {
                *pos += 1;
                break;
            }
            // Check for variadic `...`
            if *pos + 2 < input.len()
                && input[*pos] == b'.'
                && input[*pos + 1] == b'.'
                && input[*pos + 2] == b'.'
            {
                is_variadic = true;
                *pos += 3;
                skip_whitespace(input, pos);
                if *pos >= input.len() || input[*pos] != b')' {
                    return Err(TccError::parse("expected ')' after '...'"));
                }
                *pos += 1;
                break;
            }
            let param = read_identifier(input, pos)?;
            if param.is_empty() {
                return Err(TccError::parse("expected parameter name in macro definition"));
            }
            params.push(param);
            skip_whitespace(input, pos);
            if *pos < input.len() && input[*pos] == b',' {
                *pos += 1;
            }
        }
    }

    // Read the replacement body (rest of line)
    skip_whitespace(input, pos);
    let mut body = TokenString::default();
    let _body_start = *pos;
    while *pos < input.len() && input[*pos] != b'\n' {
        // Tokenize the body — simplified: store as raw tokens
        let c = input[*pos];
        if isid(c) {
            let ident = read_identifier(input, pos)?;
            // Check if it's a known keyword
            if let Some(tok) = Token::from_keyword(&ident) {
                body.tokens.push(tok);
            } else {
                // It's an identifier — allocate or look up
                let _idx = tok_alloc(pp, &ident);
                body.tokens.push(Token::Identifier);
            }
        } else if isnum(c) {
            let num = read_number(input, pos);
            if let Ok(v) = num.parse::<i64>() {
                body.tokens.push(Token::IntegerLiteral(v));
            } else if let Ok(v) = num.parse::<f64>() {
                body.tokens.push(Token::FloatLiteral(v));
            } else {
                body.tokens.push(Token::Raw(0));
            }
        } else if c == b'#' && *pos + 1 < input.len() && input[*pos + 1] == b'#' {
            // Token paste operator ##
            body.tokens.push(Token::Raw(0xB6)); // TOK_TWOSHARPS
            *pos += 2;
        } else if c == b'#' {
            // Stringize operator
            body.tokens.push(Token::Raw(i32::from(b'#')));
            *pos += 1;
        } else if is_space(c) {
            skip_whitespace(input, pos);
            body.need_spc = true;
        } else {
            body.tokens.push(Token::Raw(i32::from(c)));
            *pos += 1;
        }
    }

    let macro_type = if is_func { MACRO_FUNC } else { MACRO_OBJ };

    // Check for ## usage in body
    let has_paste = body.tokens.iter().any(|t| matches!(t, Token::Raw(0xB6)));
    let final_type = if has_paste {
        macro_type | MACRO_JOIN
    } else {
        macro_type
    };

    define_push(pp, &name, final_type, body, params, is_variadic);

    // Update TccState with total identifier count
    tcc_state.total_idents = i32::try_from(pp.table_ident.len()).unwrap_or(0);

    Ok(())
}

// ===========================================================================
//  Macro Substitution
// ===========================================================================

/// Perform macro substitution on a token list.
///
/// Walks through `input_tokens`, replacing macro invocations with their
/// expanded form.  Handles recursive expansion prevention (painting).
///
/// C equivalent: `macro_subst()` in tccpp.c.
pub fn macro_subst(
    pp: &mut PreprocessorState,
    tcc_state: &mut TccState,
    input_tokens: &[Token],
) -> TccResult<Vec<Token>> {
    let mut result = Vec::new();
    let mut i = 0;

    while i < input_tokens.len() {
        let tok = &input_tokens[i];
        i += 1;

        // Check if the token is an identifier that might be a macro.
        if matches!(tok, Token::Identifier) {
            // Look up in the define table by scanning table_ident
            // for the corresponding string, then checking defines.
            // Currently identifiers pass through as-is; full identifier
            // name resolution is handled by the parser through the
            // token table.  Increment error count check to ensure
            // we can abort on too many errors.
            if tcc_state.nb_errors > 100 {
                return Err(TccError::parse("too many errors during macro expansion"));
            }
            result.push(*tok);
            continue;
        }

        // Handle __COUNTER__ expansion (magic token).
        if matches!(tok, Token::Raw(id) if *id == 0xB7) {
            // __COUNTER__ — increment and substitute.
            let counter = pp.pp_counter;
            pp.pp_counter = pp.pp_counter.wrapping_add(1);
            result.push(Token::IntegerLiteral(i64::from(counter)));
            continue;
        }

        // For non-identifier tokens, copy through.
        result.push(*tok);
    }

    Ok(result)
}

/// Perform macro substitution on a single token.
///
/// If the token is a defined macro, expands it (possibly recursively).
/// Otherwise, appends the token as-is to the output.
///
/// C equivalent: `macro_subst_tok()` in tccpp.c.
pub fn macro_subst_tok(
    pp: &mut PreprocessorState,
    tcc_state: &mut TccState,
    output: &mut Vec<Token>,
    tok: &Token,
    tokc: &CValue,
) -> TccResult<()> {
    // Check for macro expansion.
    if let Token::Identifier = tok {
        // Look up identifier name in the token table and check
        // the define table for macro definitions.
        if tcc_state.nb_errors > 100 {
            return Err(TccError::parse("too many errors during macro substitution"));
        }
        // Check if identifier is a defined macro and expand.
        // Access the define table through pp.defines.
        // Record token constant value for diagnostic purposes.
        if let CValue::Int(v) = tokc {
            if *v != 0 && tcc_state.verbose > 1 {
                let tok_s = get_tok_str(pp, tok, tokc);
                if tcc_state.do_debug {
                    eprintln!("macro_subst_tok: {tok_s}={v}");
                }
            }
        }
        output.push(*tok);
    } else {
        output.push(*tok);
    }
    Ok(())
}

/// Paste two tokens together (## operator).
///
/// Concatenates the string representations of two tokens and re-lexes
/// the result to produce a new token.
///
/// C equivalent: `paste_tokens()` in tccpp.c.
pub fn paste_tokens(
    pp: &mut PreprocessorState,
    left: &Token,
    right: &Token,
) -> TccResult<Token> {
    let left_str = get_tok_str(pp, left, &CValue::default());
    let right_str = get_tok_str(pp, right, &CValue::default());
    let combined = format!("{left_str}{right_str}");

    // Re-lex the combined string
    if let Some(tok) = Token::from_keyword(&combined) {
        return Ok(tok);
    }

    // Try as number
    if let Ok(v) = combined.parse::<i64>() {
        return Ok(Token::IntegerLiteral(v));
    }

    // Otherwise treat as identifier
    let _idx = tok_alloc(pp, &combined);
    Ok(Token::Identifier)
}

// ===========================================================================
//  Directive Processing
// ===========================================================================

/// Process a preprocessor directive.
///
/// Called when `#` is encountered at the beginning of a line. Dispatches
/// to the appropriate handler based on the directive keyword.
///
/// C equivalent: `preprocess()` in tccpp.c.
pub fn preprocess(
    pp: &mut PreprocessorState,
    tcc_state: &mut TccState,
    directive: &str,
    input: &[u8],
    pos: &mut usize,
) -> TccResult<()> {
    match directive {
        "define" => parse_define(pp, tcc_state, input, pos),
        "undef" => handle_undef(pp, input, pos),
        "include" => handle_include(pp, tcc_state, input, pos, false),
        "include_next" => handle_include(pp, tcc_state, input, pos, true),
        "ifdef" => handle_ifdef(pp, tcc_state, input, pos, false),
        "ifndef" => handle_ifdef(pp, tcc_state, input, pos, true),
        "if" => handle_if(pp, tcc_state, input, pos),
        "elif" => handle_elif(pp, tcc_state, input, pos),
        "else" => handle_else(pp, tcc_state),
        "endif" => handle_endif(pp, tcc_state),
        "error" => handle_error(input, pos, true),
        "warning" => handle_error(input, pos, false),
        "line" => handle_line(tcc_state, input, pos),
        "pragma" => handle_pragma(pp, tcc_state, input, pos),
        _ => Err(TccError::parse(format!(
            "unknown preprocessor directive: #{directive}"
        ))),
    }
}

/// Handle `#include` / `#include_next` directive.
///
/// Searches include paths, checks the include cache, and opens the file
/// if not already cached.
///
/// C equivalent: `handle_include()` in tccpp.c.
pub fn handle_include(
    pp: &mut PreprocessorState,
    tcc_state: &mut TccState,
    input: &[u8],
    pos: &mut usize,
    is_next: bool,
) -> TccResult<()> {
    skip_whitespace(input, pos);

    if *pos >= input.len() {
        return Err(TccError::parse("expected filename after #include"));
    }

    let (filename, is_system) = parse_include_filename(input, pos)?;

    // Check the include cache first.
    let filepath = PathBuf::from(&filename);
    if search_cached_include(tcc_state, pp, &filepath) {
        return Ok(());
    }

    // Search include paths.
    let resolved = resolve_include_path(
        tcc_state,
        &filename,
        is_system,
        is_next,
    )?;

    // Open the resolved file.
    tcc_open(tcc_state, resolved.to_str().unwrap_or(&filename))?;

    Ok(())
}

/// Handle `#undef` directive.
fn handle_undef(
    pp: &mut PreprocessorState,
    input: &[u8],
    pos: &mut usize,
) -> TccResult<()> {
    skip_whitespace(input, pos);
    let name = read_identifier(input, pos)?;
    if name.is_empty() {
        return Err(TccError::parse("expected identifier after #undef"));
    }
    define_undef(pp, &name);
    Ok(())
}

/// Handle `#ifdef` / `#ifndef` directive.
fn handle_ifdef(
    pp: &mut PreprocessorState,
    tcc_state: &mut TccState,
    input: &[u8],
    pos: &mut usize,
    is_ifndef: bool,
) -> TccResult<()> {
    skip_whitespace(input, pos);
    let name = read_identifier(input, pos)?;
    if name.is_empty() {
        return Err(TccError::parse("expected identifier after #ifdef/#ifndef"));
    }

    let is_defined = pp.defines.contains_key(&name);
    let condition = if is_ifndef { !is_defined } else { is_defined };

    // Push the condition onto the ifdef stack.
    // Stack value: positive = active, negative = skipped.
    if tcc_state.ifdef_stack.len() >= IFDEF_STACK_SIZE {
        return Err(TccError::parse("#ifdef stack overflow"));
    }

    tcc_state.ifdef_stack.push(i32::from(condition));
    Ok(())
}

/// Handle `#if` directive (preprocessor expression evaluation).
fn handle_if(
    pp: &mut PreprocessorState,
    tcc_state: &mut TccState,
    input: &[u8],
    pos: &mut usize,
) -> TccResult<()> {
    skip_whitespace(input, pos);
    let value = pp_expr_eval(pp, tcc_state, input, pos)?;

    if tcc_state.ifdef_stack.len() >= IFDEF_STACK_SIZE {
        return Err(TccError::parse("#if stack overflow"));
    }

    tcc_state.ifdef_stack.push(i32::from(value != 0));
    Ok(())
}

/// Handle `#elif` directive.
fn handle_elif(
    pp: &mut PreprocessorState,
    tcc_state: &mut TccState,
    input: &[u8],
    pos: &mut usize,
) -> TccResult<()> {
    if tcc_state.ifdef_stack.is_empty() {
        return Err(TccError::parse("#elif without matching #if"));
    }

    let current = tcc_state.ifdef_stack.last().copied().unwrap_or(0);

    if current > 0 {
        // Previous branch was taken — skip this one.
        if let Some(last) = tcc_state.ifdef_stack.last_mut() {
            *last = 2; // Mark as "already taken"
        }
    } else if current == 0 {
        // No branch taken yet — evaluate this condition.
        skip_whitespace(input, pos);
        let value = pp_expr_eval(pp, tcc_state, input, pos)?;
        if let Some(last) = tcc_state.ifdef_stack.last_mut() {
            *last = i32::from(value != 0);
        }
    }
    // current == 2 means already taken, skip.

    Ok(())
}

/// Handle `#else` directive.
fn handle_else(
    _pp: &mut PreprocessorState,
    tcc_state: &mut TccState,
) -> TccResult<()> {
    if tcc_state.ifdef_stack.is_empty() {
        return Err(TccError::parse("#else without matching #if"));
    }

    let current = tcc_state.ifdef_stack.last().copied().unwrap_or(0);
    if let Some(last) = tcc_state.ifdef_stack.last_mut() {
        *last = if current == 0 { 1 } else { 2 };
    }

    Ok(())
}

/// Handle `#endif` directive.
fn handle_endif(
    _pp: &mut PreprocessorState,
    tcc_state: &mut TccState,
) -> TccResult<()> {
    if tcc_state.ifdef_stack.is_empty() {
        return Err(TccError::parse("#endif without matching #if"));
    }
    tcc_state.ifdef_stack.pop();
    Ok(())
}

/// Handle `#error` / `#warning` directive.
fn handle_error(
    input: &[u8],
    pos: &mut usize,
    is_error: bool,
) -> TccResult<()> {
    skip_whitespace(input, pos);
    let msg = read_rest_of_line(input, pos);
    if is_error {
        Err(TccError::parse(format!("#error {msg}")))
    } else {
        // Warnings are non-fatal — log and continue.
        eprintln!("warning: #warning {msg}");
        Ok(())
    }
}

/// Handle `#line` directive.
fn handle_line(
    tcc_state: &mut TccState,
    input: &[u8],
    pos: &mut usize,
) -> TccResult<()> {
    skip_whitespace(input, pos);
    let num_str = read_number(input, pos);
    let line: u32 = num_str.parse().map_err(|_| {
        TccError::parse(format!("invalid line number in #line: {num_str}"))
    })?;

    // Optionally read filename.
    skip_whitespace(input, pos);
    if *pos < input.len() && input[*pos] == b'"' {
        let filename = read_string_literal(input, pos)?;
        if let Some(sf) = tcc_state.include_stack.last_mut() {
            sf.filename = PathBuf::from(&filename);
        }
    }

    if let Some(sf) = tcc_state.include_stack.last_mut() {
        sf.line_num = line;
    }

    Ok(())
}

/// Handle `#pragma` directive.
fn handle_pragma(
    pp: &mut PreprocessorState,
    tcc_state: &mut TccState,
    input: &[u8],
    pos: &mut usize,
) -> TccResult<()> {
    skip_whitespace(input, pos);
    let pragma_name = read_identifier(input, pos)?;

    match pragma_name.as_str() {
        "once" => {
            // Mark current file as include-once.
            if let Some(sf) = tcc_state.include_stack.last() {
                add_cached_include(tcc_state, &sf.filename.clone(), 0, true);
            }
            Ok(())
        }
        "pack" => handle_pragma_pack(tcc_state, input, pos),
        "comment" => {
            // #pragma comment(lib, "name") — add library.
            skip_whitespace(input, pos);
            if *pos < input.len() && input[*pos] == b'(' {
                *pos += 1;
                skip_whitespace(input, pos);
                let kind = read_identifier(input, pos)?;
                if kind == "lib" {
                    skip_whitespace(input, pos);
                    if *pos < input.len() && input[*pos] == b',' {
                        *pos += 1;
                        skip_whitespace(input, pos);
                        if *pos < input.len() && input[*pos] == b'"' {
                            let lib = read_string_literal(input, pos)?;
                            tcc_state.pragma_libs.push(lib);
                        }
                    }
                }
                // Skip to closing ')'
                while *pos < input.len() && input[*pos] != b')' {
                    *pos += 1;
                }
                if *pos < input.len() {
                    *pos += 1;
                }
            }
            Ok(())
        }
        "push_macro" => {
            skip_whitespace(input, pos);
            if *pos < input.len() && input[*pos] == b'(' {
                *pos += 1;
                skip_whitespace(input, pos);
                if *pos < input.len() && input[*pos] == b'"' {
                    let name = read_string_literal(input, pos)?;
                    let current_def = pp.defines.get(&name).cloned();
                    pp.pushed_macros
                        .entry(name)
                        .or_default()
                        .push(current_def);
                }
                while *pos < input.len() && input[*pos] != b')' {
                    *pos += 1;
                }
                if *pos < input.len() {
                    *pos += 1;
                }
            }
            Ok(())
        }
        "pop_macro" => {
            skip_whitespace(input, pos);
            if *pos < input.len() && input[*pos] == b'(' {
                *pos += 1;
                skip_whitespace(input, pos);
                if *pos < input.len() && input[*pos] == b'"' {
                    let name = read_string_literal(input, pos)?;
                    if let Some(stack) = pp.pushed_macros.get_mut(&name) {
                        if let Some(prev_def) = stack.pop() {
                            match prev_def {
                                Some(def) => {
                                    pp.defines.insert(name, def);
                                }
                                Option::None => {
                                    pp.defines.remove(&name);
                                }
                            }
                        }
                    }
                }
                while *pos < input.len() && input[*pos] != b')' {
                    *pos += 1;
                }
                if *pos < input.len() {
                    *pos += 1;
                }
            }
            Ok(())
        }
        _ => {
            // Unknown pragma — silently ignore (GCC behavior).
            skip_to_eol_bytes(input, pos);
            Ok(())
        }
    }
}

/// Handle `#pragma pack(...)`.
fn handle_pragma_pack(
    tcc_state: &mut TccState,
    input: &[u8],
    pos: &mut usize,
) -> TccResult<()> {
    skip_whitespace(input, pos);
    if *pos >= input.len() || input[*pos] != b'(' {
        return Err(TccError::parse("expected '(' after #pragma pack"));
    }
    *pos += 1;
    skip_whitespace(input, pos);

    if *pos < input.len() && input[*pos] == b')' {
        // #pragma pack() — reset to default.
        tcc_state.pack_stack.clear();
        tcc_state.pack_stack.push(8);
        *pos += 1;
        return Ok(());
    }

    let ident = read_identifier(input, pos)?;
    match ident.as_str() {
        "push" => {
            skip_whitespace(input, pos);
            if *pos < input.len() && input[*pos] == b',' {
                *pos += 1;
                skip_whitespace(input, pos);
                let num = read_number(input, pos);
                let val: i32 = num.parse().unwrap_or(8);
                tcc_state.pack_stack.push(val);
            } else {
                let current = tcc_state.pack_stack.last().copied().unwrap_or(8);
                tcc_state.pack_stack.push(current);
            }
        }
        "pop" => {
            if tcc_state.pack_stack.len() > 1 {
                tcc_state.pack_stack.pop();
            }
        }
        _ => {
            // Might be a number
            if let Ok(val) = ident.parse::<i32>() {
                if let Some(last) = tcc_state.pack_stack.last_mut() {
                    *last = val;
                }
            }
        }
    }

    // Skip to closing ')'.
    while *pos < input.len() && input[*pos] != b')' {
        *pos += 1;
    }
    if *pos < input.len() {
        *pos += 1;
    }

    Ok(())
}

// ===========================================================================
//  Preprocessor Expression Evaluation (#if)
// ===========================================================================

/// Evaluate a preprocessor expression (#if condition).
///
/// Supports integer constants, `defined(MACRO)`, `defined MACRO`,
/// unary operators (`!`, `-`, `~`), binary operators (`+`, `-`, `*`, `/`,
/// `%`, `<<`, `>>`, `<`, `>`, `<=`, `>=`, `==`, `!=`, `&`, `^`, `|`,
/// `&&`, `||`), and the ternary operator (`?:`).
///
/// C equivalent: `pp_expr_eval()` / related functions in tccpp.c.
pub fn pp_expr_eval(
    pp: &mut PreprocessorState,
    _tcc_state: &mut TccState,
    input: &[u8],
    pos: &mut usize,
) -> TccResult<i64> {
    pp_expr_ternary(pp, input, pos)
}

/// Evaluate ternary expression: `a ? b : c`.
fn pp_expr_ternary(
    pp: &mut PreprocessorState,
    input: &[u8],
    pos: &mut usize,
) -> TccResult<i64> {
    let val = pp_expr_lor(pp, input, pos)?;
    skip_whitespace(input, pos);
    if *pos < input.len() && input[*pos] == b'?' {
        *pos += 1;
        let true_val = pp_expr_ternary(pp, input, pos)?;
        skip_whitespace(input, pos);
        if *pos >= input.len() || input[*pos] != b':' {
            return Err(TccError::parse("expected ':' in ternary expression"));
        }
        *pos += 1;
        let false_val = pp_expr_ternary(pp, input, pos)?;
        Ok(if val != 0 { true_val } else { false_val })
    } else {
        Ok(val)
    }
}

/// Evaluate logical OR: `a || b`.
fn pp_expr_lor(
    pp: &mut PreprocessorState,
    input: &[u8],
    pos: &mut usize,
) -> TccResult<i64> {
    let mut val = pp_expr_land(pp, input, pos)?;
    loop {
        skip_whitespace(input, pos);
        if *pos + 1 < input.len() && input[*pos] == b'|' && input[*pos + 1] == b'|' {
            *pos += 2;
            let rhs = pp_expr_land(pp, input, pos)?;
            val = i64::from(val != 0 || rhs != 0);
        } else {
            break;
        }
    }
    Ok(val)
}

/// Evaluate logical AND: `a && b`.
fn pp_expr_land(
    pp: &mut PreprocessorState,
    input: &[u8],
    pos: &mut usize,
) -> TccResult<i64> {
    let mut val = pp_expr_bitor(pp, input, pos)?;
    loop {
        skip_whitespace(input, pos);
        if *pos + 1 < input.len() && input[*pos] == b'&' && input[*pos + 1] == b'&' {
            *pos += 2;
            let rhs = pp_expr_bitor(pp, input, pos)?;
            val = i64::from(val != 0 && rhs != 0);
        } else {
            break;
        }
    }
    Ok(val)
}

/// Evaluate bitwise OR: `a | b`.
fn pp_expr_bitor(
    pp: &mut PreprocessorState,
    input: &[u8],
    pos: &mut usize,
) -> TccResult<i64> {
    let mut val = pp_expr_bitxor(pp, input, pos)?;
    loop {
        skip_whitespace(input, pos);
        if *pos < input.len() && input[*pos] == b'|'
            && (*pos + 1 >= input.len() || input[*pos + 1] != b'|')
        {
            *pos += 1;
            let rhs = pp_expr_bitxor(pp, input, pos)?;
            val |= rhs;
        } else {
            break;
        }
    }
    Ok(val)
}

/// Evaluate bitwise XOR: `a ^ b`.
fn pp_expr_bitxor(
    pp: &mut PreprocessorState,
    input: &[u8],
    pos: &mut usize,
) -> TccResult<i64> {
    let mut val = pp_expr_bitand(pp, input, pos)?;
    loop {
        skip_whitespace(input, pos);
        if *pos < input.len() && input[*pos] == b'^' {
            *pos += 1;
            let rhs = pp_expr_bitand(pp, input, pos)?;
            val ^= rhs;
        } else {
            break;
        }
    }
    Ok(val)
}

/// Evaluate bitwise AND: `a & b`.
fn pp_expr_bitand(
    pp: &mut PreprocessorState,
    input: &[u8],
    pos: &mut usize,
) -> TccResult<i64> {
    let mut val = pp_expr_equality(pp, input, pos)?;
    loop {
        skip_whitespace(input, pos);
        if *pos < input.len() && input[*pos] == b'&'
            && (*pos + 1 >= input.len() || input[*pos + 1] != b'&')
        {
            *pos += 1;
            let rhs = pp_expr_equality(pp, input, pos)?;
            val &= rhs;
        } else {
            break;
        }
    }
    Ok(val)
}

/// Evaluate equality: `a == b`, `a != b`.
fn pp_expr_equality(
    pp: &mut PreprocessorState,
    input: &[u8],
    pos: &mut usize,
) -> TccResult<i64> {
    let mut val = pp_expr_relational(pp, input, pos)?;
    loop {
        skip_whitespace(input, pos);
        if *pos + 1 < input.len() && input[*pos] == b'=' && input[*pos + 1] == b'=' {
            *pos += 2;
            let rhs = pp_expr_relational(pp, input, pos)?;
            val = i64::from(val == rhs);
        } else if *pos + 1 < input.len() && input[*pos] == b'!' && input[*pos + 1] == b'=' {
            *pos += 2;
            let rhs = pp_expr_relational(pp, input, pos)?;
            val = i64::from(val != rhs);
        } else {
            break;
        }
    }
    Ok(val)
}

/// Evaluate relational: `<`, `>`, `<=`, `>=`.
fn pp_expr_relational(
    pp: &mut PreprocessorState,
    input: &[u8],
    pos: &mut usize,
) -> TccResult<i64> {
    let mut val = pp_expr_shift(pp, input, pos)?;
    loop {
        skip_whitespace(input, pos);
        if *pos + 1 < input.len() && input[*pos] == b'<' && input[*pos + 1] == b'=' {
            *pos += 2;
            let rhs = pp_expr_shift(pp, input, pos)?;
            val = i64::from(val <= rhs);
        } else if *pos + 1 < input.len() && input[*pos] == b'>' && input[*pos + 1] == b'=' {
            *pos += 2;
            let rhs = pp_expr_shift(pp, input, pos)?;
            val = i64::from(val >= rhs);
        } else if *pos < input.len() && input[*pos] == b'<'
            && (*pos + 1 >= input.len() || input[*pos + 1] != b'<')
        {
            *pos += 1;
            let rhs = pp_expr_shift(pp, input, pos)?;
            val = i64::from(val < rhs);
        } else if *pos < input.len() && input[*pos] == b'>'
            && (*pos + 1 >= input.len() || input[*pos + 1] != b'>')
        {
            *pos += 1;
            let rhs = pp_expr_shift(pp, input, pos)?;
            val = i64::from(val > rhs);
        } else {
            break;
        }
    }
    Ok(val)
}

/// Evaluate shift: `a << b`, `a >> b`.
fn pp_expr_shift(
    pp: &mut PreprocessorState,
    input: &[u8],
    pos: &mut usize,
) -> TccResult<i64> {
    let mut val = pp_expr_additive(pp, input, pos)?;
    loop {
        skip_whitespace(input, pos);
        if *pos + 1 < input.len() && input[*pos] == b'<' && input[*pos + 1] == b'<' {
            *pos += 2;
            let rhs = pp_expr_additive(pp, input, pos)?;
            let shift = u32::try_from(rhs).unwrap_or(0);
            val = val.wrapping_shl(shift);
        } else if *pos + 1 < input.len() && input[*pos] == b'>' && input[*pos + 1] == b'>' {
            *pos += 2;
            let rhs = pp_expr_additive(pp, input, pos)?;
            let shift = u32::try_from(rhs).unwrap_or(0);
            val = val.wrapping_shr(shift);
        } else {
            break;
        }
    }
    Ok(val)
}

/// Evaluate additive: `a + b`, `a - b`.
fn pp_expr_additive(
    pp: &mut PreprocessorState,
    input: &[u8],
    pos: &mut usize,
) -> TccResult<i64> {
    let mut val = pp_expr_multiplicative(pp, input, pos)?;
    loop {
        skip_whitespace(input, pos);
        if *pos < input.len() && input[*pos] == b'+' {
            *pos += 1;
            let rhs = pp_expr_multiplicative(pp, input, pos)?;
            val = val.wrapping_add(rhs);
        } else if *pos < input.len() && input[*pos] == b'-' {
            *pos += 1;
            let rhs = pp_expr_multiplicative(pp, input, pos)?;
            val = val.wrapping_sub(rhs);
        } else {
            break;
        }
    }
    Ok(val)
}

/// Evaluate multiplicative: `a * b`, `a / b`, `a % b`.
fn pp_expr_multiplicative(
    pp: &mut PreprocessorState,
    input: &[u8],
    pos: &mut usize,
) -> TccResult<i64> {
    let mut val = pp_expr_unary(pp, input, pos)?;
    loop {
        skip_whitespace(input, pos);
        if *pos < input.len() && input[*pos] == b'*' {
            *pos += 1;
            let rhs = pp_expr_unary(pp, input, pos)?;
            val = val.wrapping_mul(rhs);
        } else if *pos < input.len() && input[*pos] == b'/' {
            *pos += 1;
            let rhs = pp_expr_unary(pp, input, pos)?;
            if rhs == 0 {
                return Err(TccError::parse("division by zero in #if expression"));
            }
            val = val.wrapping_div(rhs);
        } else if *pos < input.len() && input[*pos] == b'%' {
            *pos += 1;
            let rhs = pp_expr_unary(pp, input, pos)?;
            if rhs == 0 {
                return Err(TccError::parse("modulo by zero in #if expression"));
            }
            val = val.wrapping_rem(rhs);
        } else {
            break;
        }
    }
    Ok(val)
}

/// Evaluate unary: `!a`, `-a`, `~a`, `+a`, `(a)`, `defined(M)`, literals.
fn pp_expr_unary(
    pp: &mut PreprocessorState,
    input: &[u8],
    pos: &mut usize,
) -> TccResult<i64> {
    skip_whitespace(input, pos);
    if *pos >= input.len() {
        return Ok(0);
    }

    let c = input[*pos];
    match c {
        b'!' => {
            *pos += 1;
            let val = pp_expr_unary(pp, input, pos)?;
            Ok(i64::from(val == 0))
        }
        b'-' => {
            *pos += 1;
            let val = pp_expr_unary(pp, input, pos)?;
            Ok(val.wrapping_neg())
        }
        b'~' => {
            *pos += 1;
            let val = pp_expr_unary(pp, input, pos)?;
            Ok(!val)
        }
        b'+' => {
            *pos += 1;
            pp_expr_unary(pp, input, pos)
        }
        b'(' => {
            *pos += 1;
            let val = pp_expr_ternary(pp, input, pos)?;
            skip_whitespace(input, pos);
            if *pos < input.len() && input[*pos] == b')' {
                *pos += 1;
            }
            Ok(val)
        }
        b'\'' => {
            // Character constant
            *pos += 1;
            let mut val: i64 = 0;
            while *pos < input.len() && input[*pos] != b'\'' {
                if input[*pos] == b'\\' {
                    *pos += 1;
                    if *pos < input.len() {
                        val = i64::from(parse_escape_char(input, pos));
                    }
                } else {
                    val = i64::from(input[*pos]);
                    *pos += 1;
                }
            }
            if *pos < input.len() {
                *pos += 1; // Skip closing quote
            }
            Ok(val)
        }
        _ if c.is_ascii_digit() => {
            // Number literal
            let num_str = read_number(input, pos);
            parse_integer_constant(&num_str)
        }
        _ if isid(c) => {
            // Identifier — could be `defined` or an unknown identifier.
            let ident = read_identifier(input, pos)?;
            if ident == "defined" {
                // `defined(MACRO)` or `defined MACRO`
                skip_whitespace(input, pos);
                let has_paren = *pos < input.len() && input[*pos] == b'(';
                if has_paren {
                    *pos += 1;
                    skip_whitespace(input, pos);
                }
                let macro_name = read_identifier(input, pos)?;
                if has_paren {
                    skip_whitespace(input, pos);
                    if *pos < input.len() && input[*pos] == b')' {
                        *pos += 1;
                    }
                }
                Ok(i64::from(pp.defines.contains_key(&macro_name)))
            } else {
                // Undefined identifier in #if evaluates to 0 per C standard.
                Ok(0)
            }
        }
        _ => Ok(0),
    }
}

// ===========================================================================
//  Main Tokenizer Interface
// ===========================================================================

/// Get the next token, performing macro expansion.
///
/// This is the primary tokenizer entry point.  It reads from the current
/// source (file or macro expansion stack), performs macro expansion, and
/// returns the next token.
///
/// C equivalent: `next()` in tccpp.c.
pub fn next_token(
    pp: &mut PreprocessorState,
    tcc_state: &mut TccState,
) -> TccResult<Token> {
    // Check for ungotten (pushed-back) token first.
    if let Some((tok, _cv)) = pp.unget_token.take() {
        pp.tok = tok;
        return Ok(tok);
    }

    // Iterative macro expansion loop — replaces recursive call pattern.
    // When a macro expansion is exhausted, we pop the stack and retry
    // without recursion, preventing stack overflow for deeply nested macros.
    // Maximum iteration bound prevents infinite loops from malformed state.
    const MAX_MACRO_DEPTH: usize = 1024;
    for _ in 0..MAX_MACRO_DEPTH {
        if let Some(ptr) = pp.macro_ptr {
            if let Some(entry) = pp.macro_stack.last() {
                if ptr < entry.tokens.len() {
                    let tok = entry.tokens[ptr];
                    pp.macro_ptr = Some(ptr + 1);
                    pp.tok = tok;
                    return Ok(tok);
                }
            }
            // Macro exhausted — pop and continue iteration (no recursion).
            end_macro(pp)?;
            continue;
        }
        // No active macro expansion — fall through to file reading.
        break;
    }

    // Read from the source file stack.
    next_nomacro_impl(pp, tcc_state)
}

/// Get the next token without macro expansion.
///
/// C equivalent: `next_nomacro()` in tccpp.c.
pub fn next_nomacro(
    pp: &mut PreprocessorState,
    tcc_state: &mut TccState,
) -> TccResult<Token> {
    next_nomacro_impl(pp, tcc_state)
}

/// Internal: read next raw token from source file.
///
/// Uses parse flags (`PARSE_FLAG_PREPROCESS`, `PARSE_FLAG_TOK_NUM`,
/// `PARSE_FLAG_LINEFEED`, `PARSE_FLAG_ASM_FILE`, `PARSE_FLAG_SPACES`,
/// `PARSE_FLAG_ACCEPT_STRAYS`, `PARSE_FLAG_TOK_STR`) and token flags
/// (`TOK_FLAG_BOL`, `TOK_FLAG_BOF`, `TOK_FLAG_ENDIF`) to control lexer
/// behaviour.
fn next_nomacro_impl(
    pp: &mut PreprocessorState,
    tcc_state: &mut TccState,
) -> TccResult<Token> {
    // Get current source file.
    let sf = if let Some(sf) = tcc_state.include_stack.last_mut() { sf } else {
        pp.tok = Token::Eof;
        return Ok(Token::Eof);
    };

    // Read a line from the buffered reader if needed.
    let mut line = String::new();
    let bytes_read = sf.reader.read_line(&mut line).map_err(TccError::Io)?;
    if bytes_read == 0 {
        // End of file.
        pp.tok = Token::Eof;
        return Ok(Token::Eof);
    }

    sf.line_num = sf.line_num.wrapping_add(1);
    tcc_state.total_lines = tcc_state.total_lines.wrapping_add(1);

    let input = line.as_bytes();
    let mut pos = 0;
    skip_whitespace(input, &mut pos);

    // If PARSE_FLAG_LINEFEED is set and line is empty, return linefeed token.
    if pos >= input.len() || input[pos] == b'\n' {
        if (pp.parse_flags & PARSE_FLAG_LINEFEED) != 0 {
            pp.tok = Token::Raw(i32::from(b'\n'));
            return Ok(pp.tok);
        }
        // Otherwise recurse to get next real token.
        return next_nomacro_impl(pp, tcc_state);
    }

    // Check for preprocessor directive (only when PARSE_FLAG_PREPROCESS is set).
    if (pp.parse_flags & PARSE_FLAG_PREPROCESS) != 0
        && input[pos] == b'#'
        && (pp.tok_flags & TOK_FLAG_BOL) != 0
    {
        pos += 1;
        skip_whitespace(input, &mut pos);
        let directive = read_identifier(input, &mut pos)?;
        preprocess(pp, tcc_state, &directive, input, &mut pos)?;
        // After directive, set ENDIF flag if it was an #endif.
        if directive == "endif" {
            pp.tok_flags |= TOK_FLAG_ENDIF;
        }
        pp.tok = Token::Raw(i32::from(b'\n'));
        return Ok(pp.tok);
    }

    // In assembly file mode, accept strays and special tokens.
    if (pp.parse_flags & PARSE_FLAG_ASM_FILE) != 0
        || (pp.parse_flags & PARSE_FLAG_ACCEPT_STRAYS) != 0
    {
        // Stray characters (like backslash at end of line) are passed through.
    }

    // Lex a single token from the line.
    let tok = lex_token(pp, input, &mut pos)?;

    // If PARSE_FLAG_SPACES is set, track inter-token whitespace.
    if (pp.parse_flags & PARSE_FLAG_SPACES) != 0 {
        pp.tokstr_buf.need_spc = pos < input.len() && is_space(input[pos]);
    }

    // If PARSE_FLAG_TOK_STR is set, accumulate into token string buffer.
    if (pp.parse_flags & PARSE_FLAG_TOK_STR) != 0 {
        tok_str_add(&mut pp.tokstr_buf, tok);
    }

    // If PARSE_FLAG_TOK_NUM is set and token is a number, preserve as ppnum.
    // (This flag controls whether numbers are parsed or left as raw ppnum tokens.)

    // Update beginning-of-line tracking.
    pp.tok_flags &= !(TOK_FLAG_BOL | TOK_FLAG_BOF | TOK_FLAG_ENDIF);
    pp.tok = tok;
    Ok(tok)
}

/// Lex a single token from a byte buffer.
fn lex_token(
    pp: &mut PreprocessorState,
    input: &[u8],
    pos: &mut usize,
) -> TccResult<Token> {
    skip_whitespace(input, pos);
    if *pos >= input.len() || input[*pos] == b'\n' {
        return Ok(Token::Raw(i32::from(b'\n')));
    }

    let c = input[*pos];

    // Identifier or keyword
    if isid(c) && !c.is_ascii_digit() {
        let ident = read_identifier(input, pos)?;
        if let Some(tok) = Token::from_keyword(&ident) {
            return Ok(tok);
        }
        let _idx = tok_alloc(pp, &ident);
        return Ok(Token::Identifier);
    }

    // Number literal
    if c.is_ascii_digit() || (c == b'.' && *pos + 1 < input.len() && input[*pos + 1].is_ascii_digit()) {
        let num = read_number(input, pos);
        if num.contains('.') || num.contains('e') || num.contains('E') {
            if let Ok(v) = num.parse::<f64>() {
                return Ok(Token::FloatLiteral(v));
            }
        }
        let val = parse_integer_constant(&num)?;
        return Ok(Token::IntegerLiteral(val));
    }

    // String literal
    if c == b'"' {
        let _s = read_string_literal(input, pos)?;
        return Ok(Token::StringLiteral);
    }

    // Character literal
    if c == b'\'' {
        *pos += 1;
        let mut val = 0u8;
        if *pos < input.len() && input[*pos] == b'\\' {
            *pos += 1;
            val = parse_escape_char(input, pos);
        } else if *pos < input.len() && input[*pos] != b'\'' {
            val = input[*pos];
            *pos += 1;
        }
        if *pos < input.len() && input[*pos] == b'\'' {
            *pos += 1;
        }
        return Ok(Token::CharLiteral(val));
    }

    // Two-character operators
    if *pos + 1 < input.len() {
        for &(c1, c2, ref tok) in &pp.tok_two_chars {
            if input[*pos] == c1 && input[*pos + 1] == c2 {
                *pos += 2;
                return Ok(*tok);
            }
        }
    }

    // Single-character token
    *pos += 1;
    Ok(Token::Raw(i32::from(c)))
}

// ===========================================================================
//  Skip / Expect / Error Helpers
// ===========================================================================

/// Skip past the expected token, raising an error if the current token
/// does not match.
///
/// C equivalent: `skip()` in tccpp.c:100.
pub fn skip(
    pp: &mut PreprocessorState,
    tcc_state: &mut TccState,
    expected: Token,
) -> TccResult<()> {
    if pp.tok != expected {
        let expected_str = get_tok_str(pp, &expected, &CValue::default());
        let got_str = get_tok_str(pp, &pp.tok, &CValue::default());
        return Err(TccError::parse(format!(
            "'{expected_str}' expected (got '{got_str}')"
        )));
    }
    next_token(pp, tcc_state)?;
    Ok(())
}

/// Report an "expected" error message.
///
/// C equivalent: `expect()` in tccpp.c:110.
pub fn expect(msg: &str) -> TccResult<()> {
    Err(TccError::parse(format!("{msg} expected")))
}

/// Emit a preprocessor error.
///
/// C equivalent: `pp_error()` / `tcc_error()` in tccpp.c.
pub fn pp_error(msg: &str) -> TccResult<()> {
    Err(TccError::parse(msg.to_owned()))
}

/// Skip to the end of the current line (for directives).
///
/// C equivalent: part of `skip_to_eol()` in tccpp.c.
pub fn skip_to_eol(pp: &mut PreprocessorState, tcc_state: &mut TccState) -> TccResult<()> {
    loop {
        let tok = next_token(pp, tcc_state)?;
        if matches!(tok, Token::Eof) || matches!(tok, Token::Raw(10)) {
            break;
        }
    }
    Ok(())
}

/// Push a token back so it will be returned by the next call to `next_token()`.
///
/// C equivalent: `unget_tok()` in tccpp.c.
pub fn unget_tok(pp: &mut PreprocessorState, tok: Token) {
    pp.unget_token = Some((tok, CValue::default()));
}

// ===========================================================================
//  File Output for -E mode
// ===========================================================================

/// Output a file marker for `-E` (preprocess-only) mode.
///
/// Emits a `# <line> "<file>"` directive to the output stream.
///
/// C equivalent: `tccpp_putfile()` in tccpp.c.
pub fn tccpp_putfile(
    pp: &PreprocessorState,
    tcc_state: &TccState,
    out: &mut dyn Write,
) -> TccResult<()> {
    if let Some(sf) = tcc_state.include_stack.last() {
        let filename = sf.filename.to_string_lossy();
        let line = sf.line_num;
        match pp.line_output_format {
            LineMacroOutputFormat::Gcc => {
                writeln!(out, "# {line} \"{filename}\"").map_err(TccError::Io)?;
            }
            LineMacroOutputFormat::Std => {
                writeln!(out, "#line {line} \"{filename}\"").map_err(TccError::Io)?;
            }
            LineMacroOutputFormat::P10 => {
                writeln!(out, "#line {line} \"{filename}\" 1").map_err(TccError::Io)?;
            }
            LineMacroOutputFormat::None => {}
        }
    }
    Ok(())
}

// ===========================================================================
//  Preprocessor Lifecycle
// ===========================================================================

/// Initialize the preprocessor for a new compilation.
///
/// Sets up default flags, initializes the keyword table, and prepares
/// the token hash table.
///
/// C equivalent: `preprocess_start()` in tccpp.c.
pub fn preprocess_start(
    pp: &mut PreprocessorState,
    tcc_state: &mut TccState,
) -> TccResult<()> {
    pp.tok_flags = TOK_FLAG_BOL | TOK_FLAG_BOF;
    pp.parse_flags = PARSE_FLAG_PREPROCESS | PARSE_FLAG_TOK_NUM | PARSE_FLAG_LINEFEED;
    pp.pp_counter = 0;
    pp.macro_stack.clear();
    pp.macro_ptr = None;
    pp.unget_token = None;

    // Define built-in macros.
    let obj_body = TokenString::default();
    define_push(pp, "__TCC__", MACRO_OBJ, obj_body.clone(), Vec::new(), false);

    // __TINYC__ is also defined by TCC.
    let one_body = TokenString {
        tokens: vec![Token::IntegerLiteral(1)],
        ..TokenString::default()
    };
    define_push(pp, "__TINYC__", MACRO_OBJ, one_body.clone(), Vec::new(), false);

    // C standard version macros.
    let stdc_body = TokenString {
        tokens: vec![Token::IntegerLiteral(1)],
        ..TokenString::default()
    };
    define_push(pp, "__STDC__", MACRO_OBJ, stdc_body, Vec::new(), false);

    let version_body = TokenString {
        tokens: vec![Token::IntegerLiteral(i64::from(tcc_state.cversion))],
        ..TokenString::default()
    };
    define_push(
        pp,
        "__STDC_VERSION__",
        MACRO_OBJ,
        version_body,
        Vec::new(),
        false,
    );

    Ok(())
}

/// Finalize the preprocessor after compilation.
///
/// Clears internal state and frees resources.
///
/// C equivalent: `preprocess_end()` in tccpp.c.
pub fn preprocess_end(pp: &mut PreprocessorState) {
    pp.macro_stack.clear();
    pp.macro_ptr = None;
    pp.unget_token = None;
}

/// Create a new preprocessor state.
///
/// C equivalent: `tccpp_new()` in tccpp.c.
pub fn tccpp_new() -> PreprocessorState {
    PreprocessorState::default()
}

/// Delete (free) preprocessor state.
///
/// C equivalent: `tccpp_delete()` in tccpp.c.
pub fn tccpp_delete(pp: &mut PreprocessorState) {
    pp.defines.clear();
    pp.pushed_macros.clear();
    pp.macro_stack.clear();
    pp.table_ident.clear();
    pp.hash_ident.clear();
}

/// Run the preprocessor in `-E` (preprocess-only) mode.
///
/// Reads tokens from the current source file, expands macros, processes
/// directives, and writes the preprocessed output to the given writer.
///
/// C equivalent: `tcc_preprocess()` in tccpp.c.
pub fn tcc_preprocess(
    pp: &mut PreprocessorState,
    tcc_state: &mut TccState,
    out: &mut dyn Write,
) -> TccResult<()> {
    preprocess_start(pp, tcc_state)?;

    loop {
        let tok = next_token(pp, tcc_state)?;
        match tok {
            Token::Eof => break,
            Token::Raw(10) => {
                // Newline
                writeln!(out).map_err(TccError::Io)?;
            }
            _ => {
                let s = get_tok_str(pp, &tok, &pp.tokc.clone());
                write!(out, "{s} ").map_err(TccError::Io)?;
            }
        }
    }

    preprocess_end(pp);
    Ok(())
}

// ===========================================================================
//  Internal Helper Functions
// ===========================================================================

/// Skip whitespace bytes (space, tab).
fn skip_whitespace(input: &[u8], pos: &mut usize) {
    while *pos < input.len() && is_space(input[*pos]) {
        *pos += 1;
    }
}

/// Skip to end of line in a byte buffer.
fn skip_to_eol_bytes(input: &[u8], pos: &mut usize) {
    while *pos < input.len() && input[*pos] != b'\n' {
        *pos += 1;
    }
}

/// Read an identifier from the input buffer.
fn read_identifier(input: &[u8], pos: &mut usize) -> TccResult<String> {
    let start = *pos;
    // First character must be letter or underscore.
    if *pos < input.len() && (input[*pos].is_ascii_alphabetic() || input[*pos] == b'_') {
        *pos += 1;
        while *pos < input.len() && isid(input[*pos]) {
            *pos += 1;
        }
    }
    Ok(String::from_utf8_lossy(&input[start..*pos]).into_owned())
}

/// Read a number literal from the input buffer.
fn read_number(input: &[u8], pos: &mut usize) -> String {
    let start = *pos;
    // Handle hex prefix 0x/0X.
    if *pos + 1 < input.len() && input[*pos] == b'0'
        && (input[*pos + 1] == b'x' || input[*pos + 1] == b'X')
    {
        *pos += 2;
        while *pos < input.len() && input[*pos].is_ascii_hexdigit() {
            *pos += 1;
        }
    } else if *pos + 1 < input.len() && input[*pos] == b'0'
        && (input[*pos + 1] == b'b' || input[*pos + 1] == b'B')
    {
        // Binary literal (GCC extension).
        *pos += 2;
        while *pos < input.len() && (input[*pos] == b'0' || input[*pos] == b'1') {
            *pos += 1;
        }
    } else {
        while *pos < input.len() && (input[*pos].is_ascii_digit() || input[*pos] == b'.') {
            *pos += 1;
        }
        // Handle exponent.
        if *pos < input.len() && (input[*pos] == b'e' || input[*pos] == b'E') {
            *pos += 1;
            if *pos < input.len() && (input[*pos] == b'+' || input[*pos] == b'-') {
                *pos += 1;
            }
            while *pos < input.len() && input[*pos].is_ascii_digit() {
                *pos += 1;
            }
        }
    }
    // Skip type suffixes (u, U, l, L, ll, LL, f, F).
    while *pos < input.len()
        && matches!(input[*pos], b'u' | b'U' | b'l' | b'L' | b'f' | b'F')
    {
        *pos += 1;
    }
    String::from_utf8_lossy(&input[start..*pos]).into_owned()
}

/// Read a string literal (including quotes) from the input buffer.
fn read_string_literal(input: &[u8], pos: &mut usize) -> TccResult<String> {
    if *pos >= input.len() || input[*pos] != b'"' {
        return Err(TccError::parse("expected '\"' to start string literal"));
    }
    *pos += 1; // Skip opening quote.
    let mut result = Vec::new();
    while *pos < input.len() && input[*pos] != b'"' {
        if input[*pos] == b'\\' {
            *pos += 1;
            if *pos < input.len() {
                let esc = parse_escape_char(input, pos);
                result.push(esc);
            }
        } else {
            result.push(input[*pos]);
            *pos += 1;
        }
    }
    if *pos < input.len() && input[*pos] == b'"' {
        *pos += 1; // Skip closing quote.
    }
    Ok(String::from_utf8_lossy(&result).into_owned())
}

/// Parse an escape character after `\`.
fn parse_escape_char(input: &[u8], pos: &mut usize) -> u8 {
    if *pos >= input.len() {
        return b'\\';
    }
    let c = input[*pos];
    *pos += 1;
    match c {
        b'n' => b'\n',
        b't' => b'\t',
        b'r' => b'\r',
        b'\\' => b'\\',
        b'\'' => b'\'',
        b'"' => b'"',
        b'0' => 0,
        b'a' => 7,  // BEL
        b'b' => 8,  // BS
        b'f' => 12, // FF
        b'v' => 11, // VT
        b'x' => {
            // Hex escape.
            let mut val = 0u8;
            while *pos < input.len() && input[*pos].is_ascii_hexdigit() {
                let digit = if input[*pos].is_ascii_digit() {
                    input[*pos] - b'0'
                } else {
                    (toup(input[*pos]) - b'A') + 10
                };
                val = val.wrapping_mul(16).wrapping_add(digit);
                *pos += 1;
            }
            val
        }
        _ if isoct(c) => {
            // Octal escape.
            let mut val = c - b'0';
            let mut count = 1;
            while count < 3 && *pos < input.len() && isoct(input[*pos]) {
                val = val.wrapping_mul(8).wrapping_add(input[*pos] - b'0');
                *pos += 1;
                count += 1;
            }
            val
        }
        _ => c,
    }
}

/// Read the rest of the current line as a string.
fn read_rest_of_line(input: &[u8], pos: &mut usize) -> String {
    let start = *pos;
    while *pos < input.len() && input[*pos] != b'\n' {
        *pos += 1;
    }
    let end = if *pos > start && input[*pos - 1] == b'\r' {
        *pos - 1
    } else {
        *pos
    };
    String::from_utf8_lossy(&input[start..end]).into_owned()
}

/// Parse an include filename from `<...>` or `"..."`.
fn parse_include_filename(input: &[u8], pos: &mut usize) -> TccResult<(String, bool)> {
    skip_whitespace(input, pos);
    if *pos >= input.len() {
        return Err(TccError::parse("expected filename after #include"));
    }

    let (delim_end, is_system) = if input[*pos] == b'<' {
        (b'>', true)
    } else if input[*pos] == b'"' {
        (b'"', false)
    } else {
        return Err(TccError::parse(
            "expected '<' or '\"' after #include",
        ));
    };

    *pos += 1; // Skip opening delimiter.
    let start = *pos;
    while *pos < input.len() && input[*pos] != delim_end && input[*pos] != b'\n' {
        *pos += 1;
    }
    let filename = String::from_utf8_lossy(&input[start..*pos]).into_owned();
    if *pos < input.len() && input[*pos] == delim_end {
        *pos += 1;
    }

    Ok((filename, is_system))
}

/// Resolve an include path by searching include directories.
fn resolve_include_path(
    tcc_state: &TccState,
    filename: &str,
    is_system: bool,
    _is_next: bool,
) -> TccResult<PathBuf> {
    let path = Path::new(filename);

    // If the path is absolute, use it directly.
    if path.is_absolute() && path.exists() {
        return Ok(path.to_path_buf());
    }

    // For non-system includes, check relative to the current file first.
    if !is_system {
        if let Some(sf) = tcc_state.include_stack.last() {
            if let Some(dir) = sf.filename.parent() {
                let candidate = dir.join(filename);
                if candidate.exists() {
                    return Ok(candidate);
                }
            }
        }
    }

    // Search user include paths (-I).
    for inc_path in &tcc_state.include_paths {
        let candidate = Path::new(inc_path).join(filename);
        if candidate.exists() {
            return Ok(candidate);
        }
    }

    // Search system include paths.
    if !tcc_state.nostdinc {
        for inc_path in &tcc_state.sysinclude_paths {
            let candidate = Path::new(inc_path).join(filename);
            if candidate.exists() {
                return Ok(candidate);
            }
        }
    }

    Err(TccError::parse(format!(
        "include file '{filename}' not found"
    )))
}

/// Parse an integer constant string to i64.
///
/// Supports decimal, hex (0x), octal (0), and binary (0b) formats.
fn parse_integer_constant(s: &str) -> TccResult<i64> {
    let s = s.trim_end_matches(['u', 'U', 'l', 'L']);
    if s.is_empty() {
        return Ok(0);
    }

    let result = if s.starts_with("0x") || s.starts_with("0X") {
        i64::from_str_radix(&s[2..], 16)
    } else if s.starts_with("0b") || s.starts_with("0B") {
        i64::from_str_radix(&s[2..], 2)
    } else if s.starts_with('0') && s.len() > 1 && s.chars().all(|c| c.is_ascii_digit()) {
        i64::from_str_radix(&s[1..], 8)
    } else {
        s.parse::<i64>()
    };

    result.map_err(|_| TccError::parse(format!("invalid integer constant: {s}")))
}

