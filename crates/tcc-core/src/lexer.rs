//! Lexer / Character Scanner module for the TCC Rust compiler pipeline.
//!
//! This module handles raw character input, number literal parsing, string literal
//! parsing, character constant parsing, identifier recognition, and token production.
//! It is a faithful Rust port of the character-level scanning portions of `tccpp.c`
//! (approximately lines 1–800 and 2189–2994 of the original C source).
//!
//! # Architecture
//!
//! The lexer operates on a [`BufferedFile`] input source, reading characters from
//! a byte buffer and producing [`Token`] values. The preprocessor module
//! (`preprocessor.rs`) sits above this layer and handles macro expansion, `#include`
//! resolution, and conditional compilation directives.
//!
//! # Key Design Decisions
//!
//! - **Separation from preprocessor**: The lexer handles raw tokenization only;
//!   macro expansion and directive processing are handled at a higher level.
//! - **BufferedFile for input**: Matches the C codebase's file input model with
//!   indexed buffer access instead of raw pointers.
//! - **Fast identifier classification**: A 257-entry `ISIDNUM_TABLE` lookup table
//!   (indexed by `ch - CH_EOF`) provides O(1) character classification.
//! - **Error handling**: All fallible operations return [`TccResult<T>`] using the
//!   `TccError::lexer()` constructor for structured error reporting.
//!
//! # C-to-Rust Mapping
//!
//! | C Source | Rust Target |
//! |----------|-------------|
//! | `tccpp.c` global `tok`, `tokc`, `ch`, `tok_flags`, `parse_flags` | `Lexer` struct fields |
//! | `next_nomacro()` (tccpp.c:2586) | `Lexer::next_raw()` |
//! | `parse_number()` (tccpp.c:2270) | `Lexer::parse_number()` |
//! | `parse_string()` (tccpp.c:2189) | `Lexer::parse_string()` |
//! | `parse_escape_string()` (tccpp.c:2009) | `Lexer::parse_escape_string()` |
//! | `handle_eob()` (tccpp.c:519) | `Lexer::handle_eob()` |
//! | `skip_spaces()` (tccpp.c:575) | `Lexer::skip_spaces()` |
//! | `parse_comment()` / `parse_line_comment()` | `Lexer::parse_comment()` / `parse_line_comment()` |
//! | `isidnum_table[]` (tccpp.c:13) | `ISIDNUM_TABLE` constant |
//! | `tok_alloc()` (tccpp.c:469) | `tok_alloc()` function |
//! | `get_tok_str()` (tccpp.c:487) | `get_tok_str()` function |

use std::collections::HashMap;

use crate::error::{TccError, TccResult};
use crate::token::{
    build_keyword_table, tok_hash, Token, TOK_HASH_SIZE, TOK_IDENT,
    // Value-carrying token constants
    TOK_CCHAR, TOK_CFLOAT, TOK_CDOUBLE, TOK_CLDOUBLE, TOK_CINT, TOK_CUINT,
    TOK_CLLONG, TOK_CULLONG, TOK_CLONG, TOK_CULONG, TOK_LCHAR, TOK_STR, TOK_LSTR,
    TOK_PPNUM, TOK_PPSTR, TOK_EOF, TOK_LINEFEED,
    // Operator token constants
    TOK_LE, TOK_GE, TOK_EQ, TOK_NE, TOK_LAND, TOK_LOR, TOK_INC, TOK_DEC,
    TOK_SHL, TOK_SAR, TOK_ARROW, TOK_DOTS, TOK_TWOSHARPS,
    // Assignment operator token constants
    TOK_A_ADD, TOK_A_SUB, TOK_A_MUL, TOK_A_DIV, TOK_A_MOD, TOK_A_AND,
    TOK_A_OR, TOK_A_XOR, TOK_A_SHL, TOK_A_SAR,
    TOK_LT, TOK_GT,
};
use crate::types::{
    BufferedFile, CString as TccCString, CValue, CStringValue, TokenSym,
    CH_EOF, TOK_ALLOC_INCR,
};

// ===========================================================================
// Parse Flag Constants
// (Also defined in token.rs; re-exported here as the lexer's public interface)
// ===========================================================================

/// Activate preprocessing (macro expansion, `#include`, etc.).
pub const PARSE_FLAG_PREPROCESS: i32 = 0x0001;
/// Return numbers as fully parsed constants instead of `TOK_PPNUM`.
pub const PARSE_FLAG_TOK_NUM: i32 = 0x0002;
/// Return line feed as a token; also return it at EOF.
pub const PARSE_FLAG_LINEFEED: i32 = 0x0004;
/// Processing an assembly file: `#` can be used for line comments.
pub const PARSE_FLAG_ASM_FILE: i32 = 0x0008;
/// Return space tokens (used in `-E` preprocess-only mode).
pub const PARSE_FLAG_SPACES: i32 = 0x0010;
/// Return `\` stray tokens instead of producing errors.
pub const PARSE_FLAG_ACCEPT_STRAYS: i32 = 0x0020;
/// Return parsed strings instead of `TOK_PPSTR`.
pub const PARSE_FLAG_TOK_STR: i32 = 0x0040;

// ===========================================================================
// Token Flag Constants
// ===========================================================================

/// Beginning of line before this token (for `#` directive detection).
pub const TOK_FLAG_BOL: i32 = 0x0001;
/// Beginning of file before this token (for `#ifndef` guard detection).
pub const TOK_FLAG_BOF: i32 = 0x0002;
/// An `#endif` was found matching the starting `#ifdef` guard.
pub const TOK_FLAG_ENDIF: i32 = 0x0004;
/// Whitespace (space/tab) preceded this token in the source text.
/// Used by the `-E` preprocessor output to reproduce original spacing.
pub const TOK_FLAG_SPC: i32 = 0x0008;

// ===========================================================================
// Character Classification Constants and Table
// From tccpp.c lines 13-20 (isidnum_table)
// ===========================================================================

/// Character is a whitespace character (space, tab, form-feed, vertical-tab, carriage-return).
pub const IS_SPC: u8 = 1;
/// Character is a valid identifier start or continuation character (a-z, A-Z, _, $).
pub const IS_ID: u8 = 2;
/// Character is a decimal digit (0-9).
pub const IS_NUM: u8 = 4;

/// Character classification table for fast identifier/number/space detection.
///
/// Indexed by `(byte_value as i32 - CH_EOF) as usize`, where `CH_EOF = -1`.
/// This gives a 258-entry table covering values from -1 (CH_EOF = index 0)
/// through 256 (index 257).
///
/// Bit flags: `IS_SPC` (1) for whitespace, `IS_ID` (2) for identifier chars,
/// `IS_NUM` (4) for digit chars. Digits also have `IS_ID` set so they can
/// appear in identifier continuations.
///
/// Port of the C `isidnum_table[256 - CH_EOF]` array.
pub static ISIDNUM_TABLE: [u8; 258] = {
    let mut table = [0u8; 258];
    // Index 0 = CH_EOF (-1), index 1 = 0x00, index 2 = 0x01, ...
    // index N+1 = byte value N

    // Space characters: \t=9, \n=10 (NOT marked as SPC here; handled separately),
    // \v=11, \f=12, \r=13, space=32
    table[9 + 1] = IS_SPC;   // \t
    table[11 + 1] = IS_SPC;  // \v
    table[12 + 1] = IS_SPC;  // \f
    table[13 + 1] = IS_SPC;  // \r
    table[32 + 1] = IS_SPC;  // space

    // Digits: '0'..'9' — both IS_ID and IS_NUM
    let mut d = b'0' as usize;
    while d <= b'9' as usize {
        table[d + 1] = IS_ID | IS_NUM;
        d += 1;
    }

    // Uppercase letters: 'A'..'Z' — IS_ID
    let mut c = b'A' as usize;
    while c <= b'Z' as usize {
        table[c + 1] = IS_ID;
        c += 1;
    }

    // Lowercase letters: 'a'..'z' — IS_ID
    c = b'a' as usize;
    while c <= b'z' as usize {
        table[c + 1] = IS_ID;
        c += 1;
    }

    // Underscore '_' — IS_ID
    table[b'_' as usize + 1] = IS_ID;

    // High bytes 0x80-0xFF — IS_ID (UTF-8 continuation bytes, used for identifiers)
    c = 0x80;
    while c <= 0xFF {
        table[c + 1] = IS_ID;
        c += 1;
    }

    table
};

/// Index into `ISIDNUM_TABLE` from a character value.
///
/// The table is indexed by `(ch - CH_EOF)` where `CH_EOF = -1`, so for a byte
/// value `b`, the index is `b + 1`. For `CH_EOF` itself, the index is `0`.
#[inline]
fn isidnum_index(ch: i32) -> usize {
    (ch - CH_EOF) as usize
}

/// Check if a character is a whitespace character using the classification table.
#[inline]
pub fn is_space(ch: i32) -> bool {
    let idx = isidnum_index(ch);
    idx < ISIDNUM_TABLE.len() && (ISIDNUM_TABLE[idx] & IS_SPC) != 0
}

/// Check if a character is a valid identifier character.
#[inline]
pub fn is_id(ch: i32) -> bool {
    let idx = isidnum_index(ch);
    idx < ISIDNUM_TABLE.len() && (ISIDNUM_TABLE[idx] & IS_ID) != 0
}

/// Check if a character is a decimal digit.
#[inline]
pub fn is_num(ch: i32) -> bool {
    ch >= b'0' as i32 && ch <= b'9' as i32
}

/// Check if a character is a valid identifier start or continuation character.
#[inline]
fn is_idnum(ch: i32) -> bool {
    let idx = isidnum_index(ch);
    idx < ISIDNUM_TABLE.len() && (ISIDNUM_TABLE[idx] & (IS_ID | IS_NUM)) != 0
}

/// Check if a character is an octal digit.
#[inline]
fn is_oct(ch: i32) -> bool {
    ch >= b'0' as i32 && ch <= b'7' as i32
}

/// Convert a character to uppercase.
#[inline]
fn toup(ch: i32) -> i32 {
    if ch >= b'a' as i32 && ch <= b'z' as i32 {
        ch - 32
    } else {
        ch
    }
}

// ===========================================================================
// LineMacroOutputFormat — Line directive output format
// ===========================================================================

/// Format for `#line` directive output in `-E` (preprocess-only) mode.
///
/// Controls how source location tracking information is emitted when
/// the preprocessor output is being written.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum LineMacroOutputFormat {
    /// GCC-compatible `# linenum "filename"` format (default).
    #[default]
    Gcc,
    /// No line directives emitted.
    None,
    /// Standard C `#line linenum "filename"` format.
    Std,
    /// P10 (Plan 9) format.
    P10,
}

// Default implementation derived via #[default] on Gcc variant above.

// ===========================================================================
// Mutable ISIDNUM table for set_idnum
// ===========================================================================

/// A mutable copy of the ISIDNUM table that can be modified at runtime
/// (e.g., to enable `$` in identifiers).
///
/// Initialized from `ISIDNUM_TABLE` at lexer construction time.
pub type IsIdnumTableMut = [u8; 258];

/// Modify the character classification for a given byte value in a mutable table.
///
/// Used to enable/disable `$` in identifiers (`dollars_in_identifiers` option).
///
/// # Arguments
/// * `table` — Mutable classification table to modify
/// * `c` — Byte value to modify classification for
/// * `val` — New classification flags (combination of `IS_SPC`, `IS_ID`, `IS_NUM`)
///
/// # Returns
/// The previous classification flags for the character.
pub fn set_idnum(table: &mut IsIdnumTableMut, c: u8, val: u8) -> u8 {
    let idx = c as usize + 1; // +1 because index 0 = CH_EOF (-1)
    let old = table[idx];
    table[idx] = val;
    old
}

// ===========================================================================
// Token Allocation — Symbol Hash Table
// From tccpp.c lines 440-475 (tok_alloc, tok_alloc_new)
// ===========================================================================

/// Token symbol hash table — maps identifier strings to `TokenSym` entries.
///
/// This is the central data structure for identifier interning. Each unique
/// identifier string gets exactly one `TokenSym` entry, assigned a unique
/// token integer value starting from `TOK_IDENT`.
#[derive(Clone)]
pub struct TokenSymTable {
    /// Hash buckets: each entry is an index into `table_ident` or -1 (empty).
    pub hash_ident: Vec<i32>,
    /// All allocated `TokenSym` entries, indexed by `(tok - TOK_IDENT)`.
    pub table_ident: Vec<TokenSym>,
    /// Next available token value to assign.
    pub tok_ident: i32,
}

impl TokenSymTable {
    /// Create a new empty token symbol table.
    pub fn new() -> Self {
        TokenSymTable {
            hash_ident: vec![-1; TOK_HASH_SIZE],
            table_ident: Vec::with_capacity(TOK_ALLOC_INCR),
            tok_ident: TOK_IDENT,
        }
    }
}

impl Default for TokenSymTable {
    fn default() -> Self {
        Self::new()
    }
}

/// Allocate or look up a token symbol in the hash table.
///
/// If the identifier string `str_data` already exists in the table, returns its
/// `TokenSym` token value. Otherwise, allocates a new entry with the next
/// available token integer.
///
/// Port of `tok_alloc()` from `tccpp.c` lines 469-475.
///
/// # Arguments
/// * `table` — The token symbol table to search/insert into
/// * `str_data` — The identifier string bytes
///
/// # Returns
/// The `TokenSym`'s integer token value.
pub fn tok_alloc(table: &mut TokenSymTable, str_data: &[u8]) -> i32 {
    let h = tok_hash(str_data) & (TOK_HASH_SIZE - 1);

    // Walk the hash chain looking for a match
    let mut idx = table.hash_ident[h];
    while idx >= 0 {
        let ts = &table.table_ident[idx as usize];
        if ts.len == str_data.len() as i32 && ts.str_data.as_bytes() == str_data {
            return ts.tok;
        }
        idx = ts.hash_next;
    }

    // Not found — allocate a new entry
    tok_alloc_new(table, str_data, h)
}

/// Find (or create) a token entry by text, returning the **position-based**
/// ID (`entry_index + TOK_IDENT`) instead of `ts.tok`.
///
/// For regular identifiers the result equals `tok_alloc()`.  For keyword
/// alias entries (e.g. `__noreturn__` whose `ts.tok = Token::Noreturn`),
/// `tok_alloc()` returns the primary keyword value whereas this function
/// returns the alias entry's own position — preserving the original
/// spelling so that `get_tok_str(result)` produces `"__noreturn__"`.
pub fn tok_find_entry_id(table: &mut TokenSymTable, str_data: &[u8]) -> i32 {
    let h = tok_hash(str_data) & (TOK_HASH_SIZE - 1);
    let mut idx = table.hash_ident[h];
    while idx >= 0 {
        let ts = &table.table_ident[idx as usize];
        if ts.len == str_data.len() as i32 && ts.str_data.as_bytes() == str_data {
            return idx + TOK_IDENT; // position-based ID (NOT ts.tok)
        }
        idx = ts.hash_next;
    }
    // Not found — create a new entry (returns position-based ID naturally)
    tok_alloc_new(table, str_data, h)
}

/// Allocate a new token symbol entry in the hash table (internal helper).
///
/// Port of `tok_alloc_new()` from `tccpp.c` lines 440-467.
fn tok_alloc_new(table: &mut TokenSymTable, str_data: &[u8], hash_bucket: usize) -> i32 {
    let tok = table.tok_ident;
    table.tok_ident += 1;

    let str_string = String::from_utf8_lossy(str_data).into_owned();

    let ts = TokenSym {
        tok,
        len: str_data.len() as i32,
        str_data: str_string,
        hash_next: table.hash_ident[hash_bucket],
        sym_define: None,
        sym_label: None,
        sym_struct: None,
        sym_identifier: None,
    };

    table.hash_ident[hash_bucket] = table.table_ident.len() as i32;
    table.table_ident.push(ts);

    tok
}

/// Allocate a token for a constant (known-at-compile-time) identifier string.
///
/// Same as `tok_alloc`, but takes a `&str` for convenience when inserting
/// keywords and built-in identifiers.
///
/// Port of constant-string token allocation patterns in `tccpp.c`.
///
/// # Arguments
/// * `table` — The token symbol table
/// * `s` — The identifier string
///
/// # Returns
/// The token integer value for the identifier.
pub fn tok_alloc_const(table: &mut TokenSymTable, s: &str) -> i32 {
    tok_alloc(table, s.as_bytes())
}

/// Register a keyword alias in the token table.
///
/// Adds a hash entry for `str_data` that returns `target_tok` when looked up.
/// This allows multiple spellings (e.g. `__asm__`, `__asm`, `asm`) to resolve
/// to the same `Token` enum value.
///
/// The entry is appended to `table_ident` with `tok = target_tok`, so hash
/// lookups find it and return the correct keyword token.  `get_tok_str` is
/// unaffected because it indexes by `(tok - TOK_IDENT)` which still points
/// to the primary keyword entry.
pub fn tok_register_alias(table: &mut TokenSymTable, str_data: &[u8], target_tok: i32) {
    let h = tok_hash(str_data) & (TOK_HASH_SIZE - 1);

    // Check if this string is already registered in the hash chain.
    let mut idx = table.hash_ident[h];
    while idx >= 0 {
        let ts = &table.table_ident[idx as usize];
        if ts.len == str_data.len() as i32 && ts.str_data.as_bytes() == str_data {
            return; // Already exists — nothing to do.
        }
        idx = ts.hash_next;
    }

    // Create a new entry that carries the PRIMARY keyword's tok value.
    let new_idx = table.table_ident.len() as i32;
    let str_string = String::from_utf8_lossy(str_data).into_owned();
    table.table_ident.push(TokenSym {
        tok: target_tok,
        len: str_data.len() as i32,
        str_data: str_string,
        hash_next: table.hash_ident[h],
        sym_define: None,
        sym_label: None,
        sym_struct: None,
        sym_identifier: None,
    });
    table.hash_ident[h] = new_idx;
}

/// Get the string representation of a token value.
///
/// For identifiers and keywords (tok >= TOK_IDENT), returns the interned string.
/// For single-character tokens (0 < tok < 128), returns the character as a string.
/// For special multi-character tokens, returns the operator/keyword text.
///
/// Port of `get_tok_str()` from `tccpp.c` lines 487-518.
///
/// # Arguments
/// * `table` — The token symbol table for identifier lookup
/// * `tok` — The token integer value
/// * `cv` — Optional `CValue` for literal tokens (numbers, strings)
///
/// # Returns
/// A string representation of the token.
pub fn get_tok_str(table: &TokenSymTable, tok: i32, cv: Option<&CValue>) -> String {
    // Identifier or keyword
    if tok >= TOK_IDENT {
        let idx = (tok - TOK_IDENT) as usize;
        if idx < table.table_ident.len() {
            return table.table_ident[idx].str_data.clone();
        }
        return format!("<unknown token {}>", tok);
    }

    // Value-carrying tokens
    match tok {
        t if t == TOK_CINT || t == TOK_CUINT => {
            if let Some(cv) = cv {
                return format!("{}", unsafe { cv.i });
            }
            return "<int>".to_string();
        }
        t if t == TOK_CLLONG || t == TOK_CULLONG => {
            if let Some(cv) = cv {
                return format!("{}LL", unsafe { cv.i });
            }
            return "<llong>".to_string();
        }
        t if t == TOK_CLONG || t == TOK_CULONG => {
            if let Some(cv) = cv {
                return format!("{}L", unsafe { cv.i });
            }
            return "<long>".to_string();
        }
        t if t == TOK_CFLOAT => {
            if let Some(cv) = cv {
                return format!("{}f", unsafe { cv.f });
            }
            return "<float>".to_string();
        }
        t if t == TOK_CDOUBLE => {
            if let Some(cv) = cv {
                return format!("{}", unsafe { cv.d });
            }
            return "<double>".to_string();
        }
        t if t == TOK_CLDOUBLE => {
            if let Some(cv) = cv {
                return format!("{}L", unsafe { cv.ld });
            }
            return "<ldouble>".to_string();
        }
        t if t == TOK_CCHAR || t == TOK_LCHAR => {
            if let Some(cv) = cv {
                let ch_val = unsafe { cv.i } as u8;
                if (32..127).contains(&ch_val) {
                    return format!("'{}'", ch_val as char);
                }
                return format!("'\\x{:02x}'", ch_val);
            }
            return "<char>".to_string();
        }
        t if t == TOK_PPNUM || t == TOK_PPSTR => {
            // Return the raw text stored in cv.str_val — for pp-numbers
            // this preserves hex/octal notation (e.g. "0x1E"), for
            // pp-strings this preserves the quoted form ("pipapo").
            if let Some(cv) = cv {
                unsafe {
                    let ptr = cv.str_val.data;
                    let size = cv.str_val.size as usize;
                    if !ptr.is_null() && size > 0 {
                        let data = std::slice::from_raw_parts(ptr, size);
                        // Exclude the null terminator if present
                        let end = data.iter().position(|&b| b == 0).unwrap_or(size);
                        if let Ok(s) = std::str::from_utf8(&data[..end]) {
                            return s.to_string();
                        }
                    }
                }
            }
            return "<ppnum>".to_string();
        }
        t if t == TOK_STR || t == TOK_LSTR => {
            // Re-escape the parsed string data back into a C string literal.
            // Mirrors the C TCC's add_char()-based reconstruction.
            if let Some(cv) = cv {
                unsafe {
                    let ptr = cv.str_val.data;
                    let size = cv.str_val.size as usize;
                    if !ptr.is_null() && size > 0 {
                        let data = std::slice::from_raw_parts(ptr, size);
                        // Exclude the null terminator
                        let end = data.iter().position(|&b| b == 0).unwrap_or(size);
                        let prefix = if tok == TOK_LSTR { "L" } else { "" };
                        let mut result = format!("{}\"", prefix);
                        for &byte in &data[..end] {
                            match byte {
                                b'\\' => result.push_str("\\\\"),
                                b'"'  => result.push_str("\\\""),
                                b'\n' => result.push_str("\\n"),
                                b'\r' => result.push_str("\\r"),
                                b'\t' => result.push_str("\\t"),
                                b'\0' => result.push_str("\\0"),
                                0x20..=0x7e => result.push(byte as char),
                                _ => {
                                    use std::fmt::Write;
                                    let _ = write!(result, "\\{:03o}", byte);
                                }
                            }
                        }
                        result.push('"');
                        return result;
                    }
                }
            }
            return "<string>".to_string();
        }

        // Multi-character operators
        t if t == TOK_LE => return "<=".to_string(),
        t if t == TOK_GE => return ">=".to_string(),
        t if t == TOK_EQ => return "==".to_string(),
        t if t == TOK_NE => return "!=".to_string(),
        t if t == TOK_LAND => return "&&".to_string(),
        t if t == TOK_LOR => return "||".to_string(),
        t if t == TOK_INC => return "++".to_string(),
        t if t == TOK_DEC => return "--".to_string(),
        t if t == TOK_LT => return "<".to_string(),
        t if t == TOK_GT => return ">".to_string(),
        t if t == TOK_SHL => return "<<".to_string(),
        t if t == TOK_SAR => return ">>".to_string(),
        t if t == TOK_ARROW => return "->".to_string(),
        t if t == TOK_DOTS => return "...".to_string(),
        t if t == TOK_TWOSHARPS => return "##".to_string(),
        t if t == TOK_A_ADD => return "+=".to_string(),
        t if t == TOK_A_SUB => return "-=".to_string(),
        t if t == TOK_A_MUL => return "*=".to_string(),
        t if t == TOK_A_DIV => return "/=".to_string(),
        t if t == TOK_A_MOD => return "%=".to_string(),
        t if t == TOK_A_AND => return "&=".to_string(),
        t if t == TOK_A_OR => return "|=".to_string(),
        t if t == TOK_A_XOR => return "^=".to_string(),
        t if t == TOK_A_SHL => return "<<=".to_string(),
        t if t == TOK_A_SAR => return ">>=".to_string(),
        t if t == TOK_EOF => return "<eof>".to_string(),
        t if t == TOK_LINEFEED => return "<linefeed>".to_string(),

        _ => {}
    }

    // Single ASCII character token
    if tok > 0 && tok < 128 {
        return String::from(tok as u8 as char);
    }

    format!("<token {:#x}>", tok)
}

/// Two-character operator table mapping `(first_char, second_char)` to a token constant.
///
/// Port of `tok_two_chars[]` from `tccpp.c` lines 23-36.
/// Used by the preprocessor for token pasting verification.
pub const TOK_TWO_CHARS: &[(u8, u8, i32)] = &[
    (b'<', b'=', TOK_LE),
    (b'>', b'=', TOK_GE),
    (b'!', b'=', TOK_NE),
    (b'=', b'=', TOK_EQ),
    (b'&', b'&', TOK_LAND),
    (b'|', b'|', TOK_LOR),
    (b'+', b'+', TOK_INC),
    (b'-', b'-', TOK_DEC),
    (b'-', b'>', TOK_ARROW),
    (b'<', b'<', TOK_SHL),
    (b'>', b'>', TOK_SAR),
    (b'+', b'=', TOK_A_ADD),
    (b'-', b'=', TOK_A_SUB),
    (b'*', b'=', TOK_A_MUL),
    (b'/', b'=', TOK_A_DIV),
    (b'%', b'=', TOK_A_MOD),
    (b'&', b'=', TOK_A_AND),
    (b'|', b'=', TOK_A_OR),
    (b'^', b'=', TOK_A_XOR),
];

// ===========================================================================
// Lexer Struct — Main token scanner
// ===========================================================================

/// The lexer / character scanner for the TCC compiler pipeline.
///
/// Reads characters from a [`BufferedFile`] and produces raw tokens (before
/// preprocessing). The preprocessor module wraps this to add macro expansion,
/// `#include` processing, and conditional compilation.
///
/// # Fields
///
/// * `tok` — Current token integer value
/// * `tokc` — Current token associated value (integer, float, string, etc.)
/// * `ch` — Current look-ahead character (as `i32`; `CH_EOF` for end-of-file)
/// * `parse_flags` — Parser-controlled flags (`PARSE_FLAG_*`)
/// * `tok_flags` — Token-level flags (`TOK_FLAG_*`, cleared after each token)
/// * `tok_buf` — Growable byte buffer for accumulating token text
/// * `file` — The current buffered file input source
pub struct Lexer<'a> {
    /// Current buffered file (input source). Owned mutably for reading.
    pub file: &'a mut BufferedFile,
    /// Current look-ahead character (`CH_EOF` if at end of file).
    pub ch: i32,
    /// Current token integer value (e.g., `TOK_IDENT`, `'+'`, `TOK_CINT`).
    pub tok: i32,
    /// Associated value for the current token (literal integer, float, string, etc.).
    pub tokc: CValue,
    /// Growable byte buffer for accumulating token text (identifiers, numbers, strings).
    pub tok_buf: TccCString,
    /// Parser-controlled flags that affect tokenization behavior.
    pub parse_flags: i32,
    /// Token-level flags (BOL, BOF, ENDIF) — cleared after each call to `next_raw()`.
    pub tok_flags: i32,
    /// Position-based tok_alloc ID for the last identifier/keyword scanned.
    /// For regular identifiers this equals `self.tok`.  For keyword aliases
    /// (e.g. `__noreturn__` mapping to `Token::Noreturn`), this preserves the
    /// spelling-specific entry index so that `##` token pasting uses the
    /// original text, not the canonical keyword spelling.
    pub ident_alloc_id: i32,

    /// Set to `true` when `parse_number()` encounters an integer literal
    /// with an explicit `U`/`u` suffix.  The `#if` expression evaluator
    /// uses this to distinguish explicit unsigned (e.g. `42U`) from
    /// implicit unsigned token types (e.g. hex `0x80000000` → `TOK_CUINT`).
    pub tok_explicit_unsigned: bool,

    // ---- Private state ----

    /// Mutable copy of the character classification table.
    isidnum_table: IsIdnumTableMut,
    /// Keyword lookup map: identifier string → Token enum value.
    keyword_map: HashMap<&'static str, Token>,
}

impl<'a> Lexer<'a> {
    /// Create a new lexer reading from the given buffered file.
    ///
    /// Initializes the character classification table, keyword lookup map,
    /// and reads the first look-ahead character from the input.
    ///
    /// # Arguments
    /// * `file` — Mutable reference to the buffered file input source.
    ///
    /// # Returns
    /// A new `Lexer` instance ready to produce tokens via `next_raw()`.
    pub fn new(file: &'a mut BufferedFile) -> Self {
        let keyword_map = build_keyword_table();
        let isidnum_table: IsIdnumTableMut = ISIDNUM_TABLE;

        let mut lexer = Lexer {
            file,
            ch: b' ' as i32, // will be overwritten by initial next_char()
            tok: 0,
            tokc: CValue::default(),
            tok_buf: TccCString::new(),
            parse_flags: 0,
            tok_flags: TOK_FLAG_BOL | TOK_FLAG_BOF,
            ident_alloc_id: 0,
            tok_explicit_unsigned: false,
            isidnum_table,
            keyword_map,
        };

        // Read the first character
        lexer.next_char();
        lexer
    }

    /// Create a lexer that resumes scanning with a pre-loaded lookahead
    /// character.  Use this instead of `new()` when the caller already
    /// has the next unprocessed character (e.g. from a previous Lexer
    /// instance), avoiding the `next_char()` that `new()` performs.
    pub fn resume(file: &'a mut BufferedFile, lookahead_ch: i32) -> Self {
        let keyword_map = build_keyword_table();
        let isidnum_table: IsIdnumTableMut = ISIDNUM_TABLE;

        Lexer {
            file,
            ch: lookahead_ch,
            tok: 0,
            tokc: CValue::default(),
            tok_buf: TccCString::new(),
            parse_flags: 0,
            tok_flags: TOK_FLAG_BOL | TOK_FLAG_BOF,
            ident_alloc_id: 0,
            tok_explicit_unsigned: false,
            isidnum_table,
            keyword_map,
        }
    }

    // ---------------------------------------------------------------
    // Character Input — Low-Level Buffered Reading
    // From tccpp.c handle_eob(), next_c(), handle_stray_noerror()
    // ---------------------------------------------------------------

    /// Read the next character from the buffer without any special handling.
    ///
    /// If the buffer is exhausted, calls `handle_eob()` to refill or detect EOF.
    #[inline]
    fn next_char(&mut self) {
        if self.file.buf_ptr < self.file.buf_end {
            self.ch = self.file.buffer[self.file.buf_ptr] as i32;
            self.file.buf_ptr += 1;
        } else {
            self.handle_eob_internal();
        }
    }

    /// Peek at the current character without advancing the buffer pointer.
    #[inline]
    fn peek_char(&self) -> i32 {
        if self.file.buf_ptr < self.file.buf_end {
            self.file.buffer[self.file.buf_ptr] as i32
        } else {
            CH_EOF
        }
    }

    /// Peek at the character at the current buffer position (one ahead of ch).
    #[inline]
    fn peek_char_at(&self, offset: usize) -> i32 {
        let pos = self.file.buf_ptr + offset;
        if pos < self.file.buf_end {
            self.file.buffer[pos] as i32
        } else {
            CH_EOF
        }
    }

    /// Handle end-of-buffer condition: refill the buffer from file or signal EOF.
    ///
    /// Port of `handle_eob()` from `tccpp.c` lines 519-565.
    ///
    /// When the buffer pointer reaches the end:
    /// - If the file descriptor is valid (`fd >= 0`), refill the buffer
    /// - Otherwise, signal `CH_EOF`
    pub fn handle_eob(&mut self) {
        self.handle_eob_internal();
    }

    /// Internal implementation of handle_eob.
    ///
    /// Signals `CH_EOF` when the buffer is exhausted, regardless of whether
    /// the input came from a file descriptor or an in-memory buffer.
    ///
    /// In the original C codebase (`tccpp.c` lines 519–565), the `fd >= 0`
    /// branch would issue a `read()` syscall to refill the buffer. In the
    /// Rust port, file contents are pre-loaded into [`BufferedFile::buffer`]
    /// by the preprocessor/file-loader before lexing begins, so both code
    /// paths converge to the same `CH_EOF` signal. No syscall-based buffer
    /// refill is needed.
    fn handle_eob_internal(&mut self) {
        self.ch = CH_EOF;
    }

    /// Handle a stray backslash (line continuation or actual stray).
    ///
    /// Port of `handle_stray_noerror()` from `tccpp.c` lines 552-574.
    ///
    /// If `ch` is `\`, checks if the next character is a newline (line continuation).
    /// If so, skips the `\<newline>` pair and returns `true`.
    /// Otherwise, returns `false` (it's a stray backslash).
    fn handle_stray(&mut self) -> bool {
        if self.ch == b'\\' as i32 {
            let next = self.peek_char();
            if next == b'\n' as i32 {
                // Line continuation: skip backslash + newline
                self.next_char(); // consume '\'
                self.file.line_num += 1;
                self.next_char(); // consume '\n', read next char
                return true;
            }
            if next == b'\r' as i32 {
                // Handle \r\n line continuation
                self.next_char(); // consume '\'
                self.next_char(); // consume '\r'
                if self.ch == b'\n' as i32 {
                    self.next_char(); // consume '\n'
                }
                self.file.line_num += 1;
                return true;
            }
        }
        false
    }

    /// Read the next character, handling line continuations and CH_EOB.
    ///
    /// Port of `minp()` / `next_c()` combined from `tccpp.c`.
    /// Skips backslash-newline line continuations transparently.
    pub fn minp(&mut self) {
        self.next_char();
        // Loop to handle consecutive line continuations
        while self.ch == b'\\' as i32 {
            let next = self.peek_char();
            if next == b'\n' as i32 {
                self.next_char(); // skip the newline
                self.file.line_num += 1;
                self.next_char(); // read next real char
            } else if next == b'\r' as i32 {
                self.next_char(); // skip \r
                if self.ch == b'\n' as i32 {
                    self.next_char(); // skip \n
                }
                self.file.line_num += 1;
                self.next_char(); // read next real char
            } else {
                break; // Not a line continuation
            }
        }
    }

    // ---------------------------------------------------------------
    // Whitespace and Comment Handling
    // ---------------------------------------------------------------

    /// Skip whitespace characters (space, tab, form-feed, vertical-tab, carriage-return).
    ///
    /// Port of `skip_spaces()` from `tccpp.c` line 575.
    /// Does NOT skip newlines (those are significant for preprocessor directives).
    pub fn skip_spaces(&mut self) {
        loop {
            let idx = isidnum_index(self.ch);
            if idx < self.isidnum_table.len() && (self.isidnum_table[idx] & IS_SPC) != 0 {
                self.next_char();
            } else {
                break;
            }
        }
    }

    /// Parse and skip a line comment (`// ...`).
    ///
    /// Port of `parse_line_comment()` from `tccpp.c` lines 584-595.
    /// Consumes characters until end of line or end of file.
    pub fn parse_line_comment(&mut self) {
        // The initial `//` has already been consumed; ch is the char after `//`
        loop {
            if self.ch == b'\n' as i32 || self.ch == CH_EOF {
                break;
            }
            // Handle line continuation inside line comments
            if self.ch == b'\\' as i32 {
                let next = self.peek_char();
                if next == b'\n' as i32 {
                    self.next_char(); // skip backslash
                    self.file.line_num += 1;
                    self.next_char(); // skip newline
                    continue;
                }
                if next == b'\r' as i32 {
                    self.next_char(); // skip backslash
                    self.next_char(); // skip \r
                    if self.ch == b'\n' as i32 {
                        self.next_char(); // skip \n
                    }
                    self.file.line_num += 1;
                    continue;
                }
            }
            self.next_char();
        }
    }

    /// Parse and skip a block comment (`/* ... */`).
    ///
    /// Port of `parse_comment()` from `tccpp.c` lines 597-625.
    /// Consumes characters until the closing `*/` is found.
    /// Returns an error if the comment is unterminated (hits EOF).
    pub fn parse_comment(&mut self) -> TccResult<()> {
        // The initial `/*` has already been consumed; ch is the char after `/*`
        loop {
            match self.ch {
                c if c == b'*' as i32 => {
                    self.next_char();
                    if self.ch == b'/' as i32 {
                        self.next_char(); // consume closing '/'
                        return Ok(());
                    }
                    // Not end of comment, continue
                }
                c if c == b'\n' as i32 => {
                    self.file.line_num += 1;
                    self.next_char();
                }
                c if c == CH_EOF => {
                    return Err(TccError::lexer(
                        self.file.filename.clone(),
                        self.file.line_num as u32,
                        "unterminated block comment",
                    ));
                }
                _ => {
                    self.next_char();
                }
            }
        }
    }

    // ---------------------------------------------------------------
    // Escape Sequence Parsing
    // From tccpp.c parse_escape_string() lines 2009-2188
    // ---------------------------------------------------------------

    /// Parse a C escape sequence and return the resulting character value.
    ///
    /// Handles: `\a`, `\b`, `\f`, `\n`, `\r`, `\t`, `\v`, `\e` (GNU), `\\`,
    /// `\'`, `\"`, `\?`, octal (`\0` – `\377`), hex (`\xFF`),
    /// and universal character names (`\uXXXX`, `\UXXXXXXXX`).
    ///
    /// # Returns
    /// The character value (as u32) and whether it's a wide character.
    fn parse_escape_char(&mut self) -> TccResult<u32> {
        self.next_char(); // skip the backslash
        let c = self.ch;
        match c {
            // Standard C escape sequences
            c if c == b'a' as i32 => { self.next_char(); Ok(7) }    // BEL
            c if c == b'b' as i32 => { self.next_char(); Ok(8) }    // BS
            c if c == b'f' as i32 => { self.next_char(); Ok(12) }   // FF
            c if c == b'n' as i32 => { self.next_char(); Ok(10) }   // LF
            c if c == b'r' as i32 => { self.next_char(); Ok(13) }   // CR
            c if c == b't' as i32 => { self.next_char(); Ok(9) }    // HT
            c if c == b'v' as i32 => { self.next_char(); Ok(11) }   // VT
            c if c == b'e' as i32 || c == b'E' as i32 => {
                // GNU extension: \e = ESC
                self.next_char();
                Ok(27)
            }
            c if c == b'\'' as i32 || c == b'"' as i32
                || c == b'\\' as i32 || c == b'?' as i32 => {
                let val = c as u32;
                self.next_char();
                Ok(val)
            }

            // Octal escape: \0 – \377
            c if is_oct(c) => {
                let mut val: u32 = (c - b'0' as i32) as u32;
                self.next_char();
                if is_oct(self.ch) {
                    val = val * 8 + (self.ch - b'0' as i32) as u32;
                    self.next_char();
                    if is_oct(self.ch) {
                        val = val * 8 + (self.ch - b'0' as i32) as u32;
                        self.next_char();
                    }
                }
                Ok(val)
            }

            // Hex escape: \xNN (unlimited digits per C standard)
            c if c == b'x' as i32 => {
                self.next_char();
                let mut val: u32 = 0;
                let mut has_digit = false;
                loop {
                    let d = hex_digit(self.ch);
                    if d < 0 {
                        break;
                    }
                    has_digit = true;
                    val = val.wrapping_mul(16).wrapping_add(d as u32);
                    self.next_char();
                }
                if !has_digit {
                    return Err(TccError::lexer(
                        self.file.filename.clone(),
                        self.file.line_num as u32,
                        "\\x used with no following hex digits",
                    ));
                }
                Ok(val)
            }

            // Universal character name: \uXXXX
            c if c == b'u' as i32 => {
                self.next_char();
                self.parse_ucn(4)
            }

            // Universal character name: \UXXXXXXXX
            c if c == b'U' as i32 => {
                self.next_char();
                self.parse_ucn(8)
            }

            // Unknown escape — return char as-is with warning potential
            _ => {
                let val = c as u32;
                self.next_char();
                Ok(val)
            }
        }
    }

    /// Parse a universal character name (\uXXXX or \UXXXXXXXX).
    fn parse_ucn(&mut self, n_digits: usize) -> TccResult<u32> {
        let mut val: u32 = 0;
        for i in 0..n_digits {
            let d = hex_digit(self.ch);
            if d < 0 {
                return Err(TccError::lexer(
                    self.file.filename.clone(),
                    self.file.line_num as u32,
                    format!(
                        "incomplete universal character name (expected {} hex digits, got {})",
                        n_digits, i
                    ),
                ));
            }
            val = val * 16 + d as u32;
            self.next_char();
        }
        Ok(val)
    }

    // ---------------------------------------------------------------
    // String Literal Parsing
    // From tccpp.c parse_string(), parse_escape_string()
    // ---------------------------------------------------------------

    /// Parse a string literal (including escape sequences).
    ///
    /// Port of `parse_string()` from `tccpp.c` lines 2189-2235.
    ///
    /// On entry, `ch` is the opening quote character (`"` or `'`).
    /// The `is_long` flag indicates whether this is a wide string/char (L, u, U prefix).
    ///
    /// Sets `self.tok` to the appropriate token type:
    /// - `TOK_STR` / `TOK_LSTR` for string literals
    /// - `TOK_CCHAR` / `TOK_LCHAR` for character constants
    pub fn parse_string(&mut self, separator: u8, is_long: bool) -> TccResult<()> {
        self.tok_buf = TccCString::new();

        // Skip the opening quote
        self.next_char();

        loop {
            if self.ch == separator as i32 {
                // End of string/char
                self.next_char(); // consume closing quote
                break;
            }
            if self.ch == b'\n' as i32 || self.ch == CH_EOF {
                return Err(TccError::lexer(
                    self.file.filename.clone(),
                    self.file.line_num as u32,
                    if separator == b'"' {
                        "unterminated string literal"
                    } else {
                        "unterminated character constant"
                    },
                ));
            }
            if self.ch == b'\\' as i32 {
                let c = self.parse_escape_char()?;
                // Encode the character as UTF-8 bytes into tok_buf
                if c <= 0x7F {
                    self.tok_buf.data.push(c as u8);
                } else if c <= 0x7FF {
                    self.tok_buf.data.push((0xC0 | (c >> 6)) as u8);
                    self.tok_buf.data.push((0x80 | (c & 0x3F)) as u8);
                } else if c <= 0xFFFF {
                    self.tok_buf.data.push((0xE0 | (c >> 12)) as u8);
                    self.tok_buf.data.push((0x80 | ((c >> 6) & 0x3F)) as u8);
                    self.tok_buf.data.push((0x80 | (c & 0x3F)) as u8);
                } else {
                    self.tok_buf.data.push((0xF0 | (c >> 18)) as u8);
                    self.tok_buf.data.push((0x80 | ((c >> 12) & 0x3F)) as u8);
                    self.tok_buf.data.push((0x80 | ((c >> 6) & 0x3F)) as u8);
                    self.tok_buf.data.push((0x80 | (c & 0x3F)) as u8);
                }
            } else {
                self.tok_buf.data.push(self.ch as u8);
                self.next_char();
            }
        }

        // Add null terminator
        self.tok_buf.data.push(0);

        if separator == b'\'' {
            // Character constant
            self.tok = if is_long { TOK_LCHAR } else { TOK_CCHAR };
            // For character constants, store the value in tokc.i
            let val = if self.tok_buf.data.len() == 2 {
                // Single-byte char (plus null terminator)
                self.tok_buf.data[0] as u64
            } else {
                // Multi-byte character constant — use first byte
                self.tok_buf.data[0] as u64
            };
            self.tokc = CValue::default();
            self.tokc.i = val;
        } else {
            // String literal
            self.tok = if is_long { TOK_LSTR } else { TOK_STR };
            // Store the string data in tokc.str_val
            self.tokc = CValue::default();
            let data_ptr = self.tok_buf.data.as_ptr();
            let data_size = self.tok_buf.data.len() as i32;
            self.tokc.str_val = CStringValue {
                data: data_ptr,
                size: data_size,
            };
        }

        Ok(())
    }

    /// Parse a character constant (`'x'`, `L'x'`, etc.).
    ///
    /// Delegates to `parse_string()` with `separator = '\''`.
    pub fn parse_char(&mut self, is_long: bool) -> TccResult<()> {
        self.parse_string(b'\'', is_long)
    }

    // ---------------------------------------------------------------
    // Number Literal Parsing
    // From tccpp.c parse_number() lines 2270-2571
    // ---------------------------------------------------------------

    /// Parse a number literal (integer or floating-point).
    ///
    /// Port of `parse_number()` from `tccpp.c` lines 2270-2571.
    ///
    /// On entry, the number's digits have been accumulated in `tok_buf`
    /// (as a `TOK_PPNUM` token). This function re-parses the digit string
    /// to determine the actual numeric type and value.
    ///
    /// Sets `self.tok` to the appropriate token type (`TOK_CINT`, `TOK_CFLOAT`,
    /// `TOK_CDOUBLE`, `TOK_CLDOUBLE`, `TOK_CUINT`, `TOK_CLLONG`, `TOK_CULLONG`)
    /// and `self.tokc` to the parsed value.
    pub fn parse_number(&mut self) -> TccResult<()> {
        let buf = self.tok_buf.data.clone();
        let buf = if buf.last() == Some(&0) { &buf[..buf.len() - 1] } else { &buf };
        if buf.is_empty() {
            return Err(TccError::lexer(
                self.file.filename.clone(),
                self.file.line_num as u32,
                "empty number literal",
            ));
        }

        let mut pos: usize = 0;
        let mut base: u32 = 10;
        let mut is_unsigned = false;
        let mut is_long = 0u32; // 0=normal, 1=long, 2=long long

        // Detect base prefix
        if buf[pos] == b'0' && pos + 1 < buf.len() {
            let next = toup(buf[pos + 1] as i32);
            if next == b'X' as i32 {
                base = 16;
                pos += 2;
            } else if next == b'B' as i32 {
                base = 2;
                pos += 2;
            } else {
                base = 8;
            }
        }

        // Scan digits and check for float indicators
        let digit_start = pos;
        let mut has_dot = false;
        let mut has_exp = false;
        let mut scan = pos;

        while scan < buf.len() {
            let c = buf[scan];
            let cu = toup(c as i32);

            if c == b'.' {
                has_dot = true;
                scan += 1;
                continue;
            }
            if (base == 10 && (cu == b'E' as i32))
                || (base == 16 && (cu == b'P' as i32))
            {
                has_exp = true;
                scan += 1;
                // Skip sign after exponent
                if scan < buf.len() && (buf[scan] == b'+' || buf[scan] == b'-') {
                    scan += 1;
                }
                continue;
            }
            if is_hex_digit_char(c) || c == b'_' {
                scan += 1;
                continue;
            }
            // Suffix character or end
            break;
        }

        let is_float = has_dot || has_exp;

        // Also handle case where base is 8 but digits include 8/9 → decimal
        if base == 8 && !is_float {
            let mut i = digit_start;
            while i < scan {
                if buf[i] == b'8' || buf[i] == b'9' {
                    base = 10;
                    break;
                }
                i += 1;
            }
        }

        if is_float {
            // ---- Float parsing ----
            // Get the digit portion as a string for parsing
            let float_str: String = buf[..scan]
                .iter()
                .filter(|&&c| c != b'_')
                .map(|&c| c as char)
                .collect();

            // Check for float suffix
            let mut float_tok = TOK_CDOUBLE;
            if scan < buf.len() {
                let suffix = toup(buf[scan] as i32);
                if suffix == b'F' as i32 {
                    float_tok = TOK_CFLOAT;
                    // scan += 1; // not needed, just to acknowledge suffix
                } else if suffix == b'L' as i32 {
                    float_tok = TOK_CLDOUBLE;
                }
            }

            self.tok = float_tok;
            self.tokc = CValue::default();

            match float_tok {
                t if t == TOK_CFLOAT => {
                    let val: f32 = float_str.parse().unwrap_or(0.0);
                    self.tokc.f = val;
                }
                t if t == TOK_CLDOUBLE => {
                    let val: f64 = float_str.parse().unwrap_or(0.0);
                    self.tokc.ld = val;
                }
                _ => {
                    // TOK_CDOUBLE
                    let val: f64 = float_str.parse().unwrap_or(0.0);
                    self.tokc.d = val;
                }
            }
        } else {
            // ---- Integer parsing ----
            let mut val: u64 = 0;
            let mut _overflow = false;
            let mut i = digit_start;

            while i < scan {
                let c = buf[i];
                i += 1;
                if c == b'_' {
                    continue; // Skip digit separators (extension)
                }
                let d = digit_value(c);
                if d >= base as i32 {
                    // For octal base 8, treat as decimal if we see 8/9
                    // (already handled above)
                    break;
                }
                let new_val = val.wrapping_mul(base as u64).wrapping_add(d as u64);
                if new_val / (base as u64) != val || (d as u64 > 0 && new_val < val) {
                    _overflow = true;
                }
                val = new_val;
            }

            // Parse integer suffix
            let _suffix_start = scan;
            while scan < buf.len() {
                let sc = toup(buf[scan] as i32);
                if sc == b'U' as i32 {
                    is_unsigned = true;
                    scan += 1;
                } else if sc == b'L' as i32 {
                    is_long += 1;
                    scan += 1;
                } else {
                    break;
                }
            }

            // Determine token type based on value and suffix
            // Port of tccpp.c lines 2530-2571
            self.tokc = CValue::default();
            // Record whether the source literal had an explicit U/u suffix.
            // The #if expression evaluator needs this to distinguish
            // e.g. `42U` (unsigned) from `0x80000000` (TOK_CUINT by C type
            // rules but signed in 64-bit #if evaluation context).
            self.tok_explicit_unsigned = is_unsigned;

            if is_long >= 2 {
                // Explicit long long
                self.tok = if is_unsigned { TOK_CULLONG } else { TOK_CLLONG };
            } else if is_long == 1 {
                // Explicit long
                self.tok = if is_unsigned { TOK_CULONG } else { TOK_CLONG };
            } else if is_unsigned {
                self.tok = TOK_CUINT;
            } else {
                // No suffix — determine by value
                if val <= i32::MAX as u64 {
                    self.tok = TOK_CINT;
                } else if val <= u32::MAX as u64 {
                    self.tok = if base != 10 { TOK_CUINT } else { TOK_CLONG };
                } else if val <= i64::MAX as u64 {
                    self.tok = TOK_CLLONG;
                } else {
                    self.tok = TOK_CULLONG;
                }
            }

            self.tokc.i = val;
        }

        Ok(())
    }

    // ---------------------------------------------------------------
    // Identifier Parsing
    // From tccpp.c next_nomacro() identifier scanning
    // ---------------------------------------------------------------

    /// Parse an identifier token and look up keywords.
    ///
    /// On entry, `ch` is the first character of the identifier (already validated
    /// as IS_ID). Scans the rest of the identifier, computes its hash, and looks
    /// it up in the keyword table.
    ///
    /// Sets `self.tok` to either the keyword token value or `TOK_IDENT + offset`.
    pub fn parse_ident(&mut self, token_table: &mut TokenSymTable) -> TccResult<()> {
        self.tok_buf = TccCString::new();

        // Collect identifier characters
        while is_idnum(self.ch) || self.ch == b'\\' as i32 {
            if self.ch == b'\\' as i32 {
                // Might be a line continuation inside an identifier
                if !self.handle_stray() {
                    break; // Actual backslash, not part of identifier
                }
                continue;
            }
            self.tok_buf.data.push(self.ch as u8);
            self.next_char();
        }

        // Add null terminator for C compatibility
        self.tok_buf.data.push(0);

        let ident_bytes = &self.tok_buf.data[..self.tok_buf.data.len() - 1]; // exclude null

        // Always obtain the spelling-preserving entry ID so that keyword
        // aliases (e.g. `__noreturn__` vs `_Noreturn`) keep their original
        // text through `##` token pasting.  tok_find_entry_id returns the
        // entry's POSITION-based ID (index + TOK_IDENT), not ts.tok.
        let entry_id = tok_find_entry_id(token_table, ident_bytes);
        self.ident_alloc_id = entry_id;

        // Check if this is a keyword
        if let Ok(ident_str) = std::str::from_utf8(ident_bytes) {
            if let Some(kw_token) = self.keyword_map.get(ident_str) {
                // This is a keyword — convert Token enum to its integer discriminant
                self.tok = *kw_token as i32;
                self.tokc = CValue::default();
                return Ok(());
            }
        }

        // Not a keyword — tok and entry_id are the same
        self.tok = entry_id;
        self.tokc = CValue::default();

        Ok(())
    }

    // ---------------------------------------------------------------
    // Set Parse Flags
    // ---------------------------------------------------------------

    /// Set the parse flags that control lexer behavior.
    ///
    /// # Arguments
    /// * `flags` — Combination of `PARSE_FLAG_*` constants.
    pub fn set_parse_flags(&mut self, flags: i32) {
        self.parse_flags = flags;
    }

    /// Get the current token value.
    pub fn current_value(&self) -> &CValue {
        &self.tokc
    }

    // ---------------------------------------------------------------
    // Main Token Scanning — next_raw()
    // Port of next_nomacro() from tccpp.c lines 2586-2994
    // ---------------------------------------------------------------

    /// Scan the next raw token from the input (before preprocessing).
    ///
    /// This is the core tokenization loop, ported from `next_nomacro()` in
    /// `tccpp.c` lines 2586-2994. It reads characters from the buffered file
    /// and produces a single token, setting `self.tok` and `self.tokc`.
    ///
    /// The preprocessor module calls this method to obtain raw tokens, which
    /// it then processes for macro expansion, directive handling, etc.
    ///
    /// # Token Types Produced
    ///
    /// - Identifiers: `tok >= TOK_IDENT`
    /// - Keywords: their dedicated `Token::*` integer values
    /// - Integer constants: `TOK_CINT`, `TOK_CUINT`, `TOK_CLLONG`, `TOK_CULLONG`
    /// - Float constants: `TOK_CFLOAT`, `TOK_CDOUBLE`, `TOK_CLDOUBLE`
    /// - String literals: `TOK_STR`, `TOK_LSTR` (or `TOK_PPSTR` if not `PARSE_FLAG_TOK_STR`)
    /// - Character constants: `TOK_CCHAR`, `TOK_LCHAR`
    /// - Operators: their single/multi-char token values
    /// - `TOK_EOF` at end of file
    pub fn next_raw(&mut self, token_table: &mut TokenSymTable) -> TccResult<()> {
        loop {
            // Clear SPC from the previous token — each token must have its
            // own fresh whitespace detection.  `tok_flags` may carry BOL
            // and BOF across tokens (intentional), but SPC is per-token.
            self.tok_flags &= !TOK_FLAG_SPC;

            // Reset the spelling-preserving alias ID.  Only `parse_ident()`
            // sets this to a non-zero value; for every other token kind it
            // must be zero so that `tok_to_stream_id()` does not consume a
            // stale value from the previous identifier.
            self.ident_alloc_id = 0;

            // Skip whitespace, recording if any was seen so the
            // preprocessor `-E` output can reproduce spacing.
            let mut saw_space = false;
            loop {
                let idx = isidnum_index(self.ch);
                if idx < self.isidnum_table.len() && (self.isidnum_table[idx] & IS_SPC) != 0 {
                    saw_space = true;
                    self.next_char();
                } else {
                    break;
                }
            }
            if saw_space {
                self.tok_flags |= TOK_FLAG_SPC;
            }

            match self.ch {
                // ---- End of file ----
                c if c == CH_EOF => {
                    self.tok = TOK_EOF;
                    self.tokc = CValue::default();
                    self.tok_flags &= TOK_FLAG_SPC;
                    return Ok(());
                }

                // ---- Newline ----
                c if c == b'\n' as i32 => {
                    self.file.line_num += 1;
                    self.tok_flags |= TOK_FLAG_BOL;
                    self.next_char();

                    if (self.parse_flags & PARSE_FLAG_LINEFEED) != 0 {
                        self.tok = TOK_LINEFEED;
                        self.tokc = CValue::default();
                        // PRESERVE tok_flags (including BOL) — matches the C
                        // code's `goto keep_tok_flags` which skips the
                        // `tok_flags = 0` assignment.  The BOL flag must
                        // survive so the preprocessor can detect `#` at the
                        // start of the NEXT line.
                        return Ok(());
                    }
                    // Otherwise, skip and continue scanning
                    continue;
                }

                // ---- Backslash (line continuation or stray) ----
                c if c == b'\\' as i32 => {
                    if self.handle_stray() {
                        // Line continuation — continue scanning
                        continue;
                    }
                    if (self.parse_flags & PARSE_FLAG_ACCEPT_STRAYS) != 0 {
                        self.tok = b'\\' as i32;
                        self.tokc = CValue::default();
                        self.next_char();
                        self.tok_flags &= TOK_FLAG_SPC;
                        return Ok(());
                    }
                    // Stray backslash error
                    self.next_char();
                    continue;
                }

                // ---- Hash: preprocessor directive or ## ----
                c if c == b'#' as i32 => {
                    self.next_char();
                    if self.ch == b'#' as i32 {
                        // Token pasting operator ##
                        self.next_char();
                        self.tok = TOK_TWOSHARPS;
                    } else {
                        // Single # — stringification or preprocessor directive
                        self.tok = b'#' as i32;
                    }
                    self.tokc = CValue::default();
                    self.tok_flags &= TOK_FLAG_SPC;
                    return Ok(());
                }

                // ---- Identifiers (a-z, A-Z, _) ----
                c if (c >= b'a' as i32 && c <= b'z' as i32)
                    || (c >= b'A' as i32 && c <= b'Z' as i32)
                    || c == b'_' as i32 => {
                    // Check for L prefix (wide string/char)
                    if c == b'L' as i32 {
                        let next = self.peek_char();
                        if next == b'\'' as i32 {
                            self.next_char(); // skip 'L'
                            self.parse_char(true)?;
                            self.tok_flags &= TOK_FLAG_SPC;
                            return Ok(());
                        }
                        if next == b'"' as i32 {
                            self.next_char(); // skip 'L'
                            self.parse_string(b'"', true)?;
                            self.tok_flags &= TOK_FLAG_SPC;
                            return Ok(());
                        }
                    }

                    self.parse_ident(token_table)?;
                    self.tok_flags &= TOK_FLAG_SPC;
                    return Ok(());
                }

                // ---- Dollar sign (GCC extension: $ in identifiers) ----
                c if c == b'$' as i32 => {
                    let idx = isidnum_index(c);
                    if idx < self.isidnum_table.len() && (self.isidnum_table[idx] & IS_ID) != 0 {
                        self.parse_ident(token_table)?;
                        self.tok_flags &= TOK_FLAG_SPC;
                        return Ok(());
                    }
                    // Not allowed in identifiers — treat as single-char token
                    self.tok = c;
                    self.tokc = CValue::default();
                    self.next_char();
                    self.tok_flags &= TOK_FLAG_SPC;
                    return Ok(());
                }

                // ---- High bytes (0x80+: UTF-8 identifier starts) ----
                c if c >= 0x80 => {
                    self.parse_ident(token_table)?;
                    self.tok_flags &= TOK_FLAG_SPC;
                    return Ok(());
                }

                // ---- Number literals ----
                c if c >= b'0' as i32 && c <= b'9' as i32 => {
                    self.scan_number()?;
                    if (self.parse_flags & PARSE_FLAG_TOK_NUM) != 0 {
                        self.parse_number()?;
                    }
                    self.tok_flags &= TOK_FLAG_SPC;
                    return Ok(());
                }

                // ---- Dot: number, ..., or plain dot ----
                c if c == b'.' as i32 => {
                    let next = self.peek_char();
                    if next >= b'0' as i32 && next <= b'9' as i32 {
                        // Number starting with dot: .5, .123
                        self.scan_number()?;
                        if (self.parse_flags & PARSE_FLAG_TOK_NUM) != 0 {
                            self.parse_number()?;
                        }
                        self.tok_flags &= TOK_FLAG_SPC;
                        return Ok(());
                    }
                    if next == b'.' as i32 {
                        // Check for ...
                        let next2 = self.peek_char_at(1);
                        if next2 == b'.' as i32 {
                            self.next_char(); // skip first .
                            self.next_char(); // skip second .
                            self.next_char(); // skip third .
                            self.tok = TOK_DOTS;
                            self.tokc = CValue::default();
                            self.tok_flags &= TOK_FLAG_SPC;
                            return Ok(());
                        }
                    }
                    // Plain dot
                    self.tok = b'.' as i32;
                    self.tokc = CValue::default();
                    self.next_char();
                    self.tok_flags &= TOK_FLAG_SPC;
                    return Ok(());
                }

                // ---- String literal ----
                c if c == b'"' as i32 => {
                    if (self.parse_flags & PARSE_FLAG_TOK_STR) != 0 {
                        self.parse_string(b'"', false)?;
                    } else {
                        self.scan_pp_string(b'"')?;
                    }
                    self.tok_flags &= TOK_FLAG_SPC;
                    return Ok(());
                }

                // ---- Character constant ----
                c if c == b'\'' as i32 => {
                    if (self.parse_flags & PARSE_FLAG_TOK_STR) != 0 {
                        self.parse_char(false)?;
                    } else {
                        self.scan_pp_string(b'\'')?;
                    }
                    self.tok_flags &= TOK_FLAG_SPC;
                    return Ok(());
                }

                // ---- Operators ----

                // < <= << <<=
                c if c == b'<' as i32 => {
                    self.next_char();
                    if self.ch == b'=' as i32 {
                        self.next_char();
                        self.tok = TOK_LE;
                    } else if self.ch == b'<' as i32 {
                        self.next_char();
                        if self.ch == b'=' as i32 {
                            self.next_char();
                            self.tok = TOK_A_SHL;
                        } else {
                            self.tok = TOK_SHL;
                        }
                    } else {
                        self.tok = TOK_LT;
                    }
                    self.tokc = CValue::default();
                    self.tok_flags &= TOK_FLAG_SPC;
                    return Ok(());
                }

                // > >= >> >>=
                c if c == b'>' as i32 => {
                    self.next_char();
                    if self.ch == b'=' as i32 {
                        self.next_char();
                        self.tok = TOK_GE;
                    } else if self.ch == b'>' as i32 {
                        self.next_char();
                        if self.ch == b'=' as i32 {
                            self.next_char();
                            self.tok = TOK_A_SAR;
                        } else {
                            self.tok = TOK_SAR;
                        }
                    } else {
                        self.tok = TOK_GT;
                    }
                    self.tokc = CValue::default();
                    self.tok_flags &= TOK_FLAG_SPC;
                    return Ok(());
                }

                // & && &=
                c if c == b'&' as i32 => {
                    self.next_char();
                    if self.ch == b'&' as i32 {
                        self.next_char();
                        self.tok = TOK_LAND;
                    } else if self.ch == b'=' as i32 {
                        self.next_char();
                        self.tok = TOK_A_AND;
                    } else {
                        self.tok = b'&' as i32;
                    }
                    self.tokc = CValue::default();
                    self.tok_flags &= TOK_FLAG_SPC;
                    return Ok(());
                }

                // | || |=
                c if c == b'|' as i32 => {
                    self.next_char();
                    if self.ch == b'|' as i32 {
                        self.next_char();
                        self.tok = TOK_LOR;
                    } else if self.ch == b'=' as i32 {
                        self.next_char();
                        self.tok = TOK_A_OR;
                    } else {
                        self.tok = b'|' as i32;
                    }
                    self.tokc = CValue::default();
                    self.tok_flags &= TOK_FLAG_SPC;
                    return Ok(());
                }

                // + ++ +=
                c if c == b'+' as i32 => {
                    self.next_char();
                    if self.ch == b'+' as i32 {
                        self.next_char();
                        self.tok = TOK_INC;
                    } else if self.ch == b'=' as i32 {
                        self.next_char();
                        self.tok = TOK_A_ADD;
                    } else {
                        self.tok = b'+' as i32;
                    }
                    self.tokc = CValue::default();
                    self.tok_flags &= TOK_FLAG_SPC;
                    return Ok(());
                }

                // - -- -= ->
                c if c == b'-' as i32 => {
                    self.next_char();
                    if self.ch == b'-' as i32 {
                        self.next_char();
                        self.tok = TOK_DEC;
                    } else if self.ch == b'=' as i32 {
                        self.next_char();
                        self.tok = TOK_A_SUB;
                    } else if self.ch == b'>' as i32 {
                        self.next_char();
                        self.tok = TOK_ARROW;
                    } else {
                        self.tok = b'-' as i32;
                    }
                    self.tokc = CValue::default();
                    self.tok_flags &= TOK_FLAG_SPC;
                    return Ok(());
                }

                // ! !=
                c if c == b'!' as i32 => {
                    self.next_char();
                    if self.ch == b'=' as i32 {
                        self.next_char();
                        self.tok = TOK_NE;
                    } else {
                        self.tok = b'!' as i32;
                    }
                    self.tokc = CValue::default();
                    self.tok_flags &= TOK_FLAG_SPC;
                    return Ok(());
                }

                // = ==
                c if c == b'=' as i32 => {
                    self.next_char();
                    if self.ch == b'=' as i32 {
                        self.next_char();
                        self.tok = TOK_EQ;
                    } else {
                        self.tok = b'=' as i32;
                    }
                    self.tokc = CValue::default();
                    self.tok_flags &= TOK_FLAG_SPC;
                    return Ok(());
                }

                // * *=
                c if c == b'*' as i32 => {
                    self.next_char();
                    if self.ch == b'=' as i32 {
                        self.next_char();
                        self.tok = TOK_A_MUL;
                    } else {
                        self.tok = b'*' as i32;
                    }
                    self.tokc = CValue::default();
                    self.tok_flags &= TOK_FLAG_SPC;
                    return Ok(());
                }

                // % %=
                c if c == b'%' as i32 => {
                    self.next_char();
                    if self.ch == b'=' as i32 {
                        self.next_char();
                        self.tok = TOK_A_MOD;
                    } else {
                        self.tok = b'%' as i32;
                    }
                    self.tokc = CValue::default();
                    self.tok_flags &= TOK_FLAG_SPC;
                    return Ok(());
                }

                // ^ ^=
                c if c == b'^' as i32 => {
                    self.next_char();
                    if self.ch == b'=' as i32 {
                        self.next_char();
                        self.tok = TOK_A_XOR;
                    } else {
                        self.tok = b'^' as i32;
                    }
                    self.tokc = CValue::default();
                    self.tok_flags &= TOK_FLAG_SPC;
                    return Ok(());
                }

                // / /* // /=
                c if c == b'/' as i32 => {
                    self.next_char();
                    if self.ch == b'*' as i32 {
                        // Block comment — comments count as whitespace in C
                        self.next_char();
                        self.parse_comment()?;
                        self.tok_flags |= TOK_FLAG_SPC;
                        continue; // Comment consumed, scan next token
                    } else if self.ch == b'/' as i32 {
                        // Line comment — comments count as whitespace in C
                        self.next_char();
                        self.parse_line_comment();
                        self.tok_flags |= TOK_FLAG_SPC;
                        continue; // Comment consumed, scan next token
                    } else if self.ch == b'=' as i32 {
                        self.next_char();
                        self.tok = TOK_A_DIV;
                    } else {
                        self.tok = b'/' as i32;
                    }
                    self.tokc = CValue::default();
                    self.tok_flags &= TOK_FLAG_SPC;
                    return Ok(());
                }

                // ---- Simple single-character tokens ----
                c if c == b'(' as i32 || c == b')' as i32
                    || c == b'[' as i32 || c == b']' as i32
                    || c == b'{' as i32 || c == b'}' as i32
                    || c == b',' as i32 || c == b':' as i32
                    || c == b';' as i32 || c == b'?' as i32
                    || c == b'~' as i32 || c == b'@' as i32 => {
                    self.tok = c;
                    self.tokc = CValue::default();
                    self.next_char();
                    self.tok_flags &= TOK_FLAG_SPC;
                    return Ok(());
                }

                // ---- Unknown character ----
                _ => {
                    // Skip unrecognized characters
                    let ch = self.ch;
                    self.next_char();
                    // For printable ASCII, treat as single-char token
                    if ch > 0 && ch < 128 {
                        self.tok = ch;
                        self.tokc = CValue::default();
                        self.tok_flags &= TOK_FLAG_SPC;
                        return Ok(());
                    }
                    // Non-ASCII: might be a UTF-8 identifier start
                    if ch >= 0x80 {
                        // Push back and parse as identifier
                        // Since we already consumed the char, reconstruct
                        self.tok_buf = TccCString::new();
                        self.tok_buf.data.push(ch as u8);
                        while is_idnum(self.ch) {
                            self.tok_buf.data.push(self.ch as u8);
                            self.next_char();
                        }
                        self.tok_buf.data.push(0);
                        let ident_bytes = &self.tok_buf.data[..self.tok_buf.data.len() - 1];
                        let tok_val = tok_alloc(token_table, ident_bytes);
                        self.tok = tok_val;
                        self.tokc = CValue::default();
                        self.tok_flags &= TOK_FLAG_SPC;
                        return Ok(());
                    }
                    // Skip truly unrecognized chars
                    continue;
                }
            }
        }
    }

    // ---------------------------------------------------------------
    // Internal helpers for next_raw
    // ---------------------------------------------------------------

    /// Scan digits into tok_buf for a preprocessor number token (TOK_PPNUM).
    ///
    /// Port of the number scanning portion of `next_nomacro()` in `tccpp.c`.
    /// Collects all characters that could be part of a number (digits, letters,
    /// dots, exponent signs, etc.) into `tok_buf`.
    fn scan_number(&mut self) -> TccResult<()> {
        self.tok_buf = TccCString::new();

        // First character is already validated as a digit or '.'
        loop {
            self.tok_buf.data.push(self.ch as u8);
            self.next_char();

            // Continue scanning: digits, letters (hex, suffix), dots, underscores
            let c = self.ch;
            if (c >= b'0' as i32 && c <= b'9' as i32)
                || (c >= b'a' as i32 && c <= b'z' as i32)
                || (c >= b'A' as i32 && c <= b'Z' as i32)
                || c == b'_' as i32
                || c == b'.' as i32
            {
                continue;
            }

            // Exponent sign: e+, e-, E+, E-, p+, p-, P+, P-
            if (c == b'+' as i32 || c == b'-' as i32) && !self.tok_buf.data.is_empty() {
                let last = toup(self.tok_buf.data[self.tok_buf.data.len() - 1] as i32);
                if last == b'E' as i32 || last == b'P' as i32 {
                    continue;
                }
            }

            break;
        }

        // Null-terminate
        self.tok_buf.data.push(0);
        self.tok = TOK_PPNUM;
        // Point tokc.str_val at the raw text so that get_tok_str() and
        // store_token_value() can access the pp-number representation.
        self.tokc = CValue::default();
        self.tokc.str_val = CStringValue {
            data: self.tok_buf.data.as_ptr(),
            size: self.tok_buf.data.len() as i32,
        };
        Ok(())
    }

    /// Scan a preprocessor string/char token (TOK_PPSTR).
    ///
    /// Collects all characters between the opening and closing quote into `tok_buf`,
    /// handling escape sequences as opaque characters (no interpretation).
    fn scan_pp_string(&mut self, separator: u8) -> TccResult<()> {
        self.tok_buf = TccCString::new();

        // Skip opening quote
        self.tok_buf.data.push(self.ch as u8);
        self.next_char();

        loop {
            if self.ch == separator as i32 {
                self.tok_buf.data.push(self.ch as u8);
                self.next_char();
                break;
            }
            if self.ch == b'\\' as i32 {
                self.tok_buf.data.push(self.ch as u8);
                self.next_char();
                if self.ch == CH_EOF || self.ch == b'\n' as i32 {
                    return Err(TccError::lexer(
                        self.file.filename.clone(),
                        self.file.line_num as u32,
                        "unterminated string or character constant",
                    ));
                }
                self.tok_buf.data.push(self.ch as u8);
                self.next_char();
                continue;
            }
            if self.ch == b'\n' as i32 || self.ch == CH_EOF {
                return Err(TccError::lexer(
                    self.file.filename.clone(),
                    self.file.line_num as u32,
                    "unterminated string or character constant",
                ));
            }
            self.tok_buf.data.push(self.ch as u8);
            self.next_char();
        }

        // Null-terminate
        self.tok_buf.data.push(0);
        self.tok = TOK_PPSTR;
        // Point tokc.str_val at the raw text (including quotes) so
        // that get_tok_str() returns the original source representation.
        self.tokc = CValue::default();
        self.tokc.str_val = CStringValue {
            data: self.tok_buf.data.as_ptr(),
            size: self.tok_buf.data.len() as i32,
        };
        Ok(())
    }
}

// ===========================================================================
// Helper Functions
// ===========================================================================

/// Convert a hex digit character to its numeric value, or -1 if not a hex digit.
fn hex_digit(ch: i32) -> i32 {
    if ch >= b'0' as i32 && ch <= b'9' as i32 {
        ch - b'0' as i32
    } else if ch >= b'a' as i32 && ch <= b'f' as i32 {
        ch - b'a' as i32 + 10
    } else if ch >= b'A' as i32 && ch <= b'F' as i32 {
        ch - b'A' as i32 + 10
    } else {
        -1
    }
}

/// Check if a byte is a valid hex digit character.
fn is_hex_digit_char(c: u8) -> bool {
    c.is_ascii_hexdigit()
}

/// Convert a digit character to its numeric value.
fn digit_value(c: u8) -> i32 {
    if c.is_ascii_digit() {
        (c - b'0') as i32
    } else if c.is_ascii_lowercase() {
        (c - b'a') as i32 + 10
    } else if c.is_ascii_uppercase() {
        (c - b'A') as i32 + 10
    } else {
        -1
    }
}

// ===========================================================================
// Unit Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Create a test BufferedFile from a string.
    fn make_test_file(content: &str) -> BufferedFile {
        let mut bf = BufferedFile::default();
        bf.buffer = content.as_bytes().to_vec();
        bf.buf_end = bf.buffer.len();
        bf.buf_ptr = 0;
        bf.fd = -1;
        bf.line_num = 1;
        bf.filename = "<test>".to_string();
        bf
    }

    #[test]
    fn test_isidnum_table_basics() {
        // Space characters
        assert_ne!(ISIDNUM_TABLE[b' ' as usize + 1] & IS_SPC, 0);
        assert_ne!(ISIDNUM_TABLE[b'\t' as usize + 1] & IS_SPC, 0);

        // Digits
        assert_ne!(ISIDNUM_TABLE[b'0' as usize + 1] & IS_NUM, 0);
        assert_ne!(ISIDNUM_TABLE[b'9' as usize + 1] & IS_NUM, 0);
        // Digits are also ID
        assert_ne!(ISIDNUM_TABLE[b'5' as usize + 1] & IS_ID, 0);

        // Letters
        assert_ne!(ISIDNUM_TABLE[b'a' as usize + 1] & IS_ID, 0);
        assert_ne!(ISIDNUM_TABLE[b'Z' as usize + 1] & IS_ID, 0);
        assert_ne!(ISIDNUM_TABLE[b'_' as usize + 1] & IS_ID, 0);

        // Non-identifier/non-digit/non-space
        assert_eq!(ISIDNUM_TABLE[b'!' as usize + 1] & (IS_SPC | IS_ID | IS_NUM), 0);
        assert_eq!(ISIDNUM_TABLE[b'+' as usize + 1] & (IS_SPC | IS_ID | IS_NUM), 0);

        // High bytes (UTF-8)
        assert_ne!(ISIDNUM_TABLE[0x80 + 1] & IS_ID, 0);
        assert_ne!(ISIDNUM_TABLE[0xFF + 1] & IS_ID, 0);
    }

    #[test]
    fn test_set_idnum() {
        let mut table = ISIDNUM_TABLE;
        // $ is not an identifier char by default
        let old = set_idnum(&mut table, b'$', IS_ID);
        assert_eq!(old, 0);
        assert_ne!(table[b'$' as usize + 1] & IS_ID, 0);
        // Restore
        set_idnum(&mut table, b'$', 0);
        assert_eq!(table[b'$' as usize + 1] & IS_ID, 0);
    }

    #[test]
    fn test_tok_alloc_basic() {
        let mut table = TokenSymTable::new();
        let tok1 = tok_alloc(&mut table, b"hello");
        let tok2 = tok_alloc(&mut table, b"world");
        let tok3 = tok_alloc(&mut table, b"hello"); // same as tok1

        assert_eq!(tok1, tok3); // same string → same token
        assert_ne!(tok1, tok2); // different strings → different tokens
        assert!(tok1 >= TOK_IDENT as i32);
        assert!(tok2 >= TOK_IDENT as i32);
    }

    #[test]
    fn test_tok_alloc_const_func() {
        let mut table = TokenSymTable::new();
        let tok1 = tok_alloc_const(&mut table, "test_ident");
        let tok2 = tok_alloc_const(&mut table, "test_ident");
        assert_eq!(tok1, tok2);
    }

    #[test]
    fn test_get_tok_str_single_char() {
        let table = TokenSymTable::new();
        assert_eq!(get_tok_str(&table, b'+' as i32, None), "+");
        assert_eq!(get_tok_str(&table, b';' as i32, None), ";");
    }

    #[test]
    fn test_get_tok_str_operators() {
        let table = TokenSymTable::new();
        assert_eq!(get_tok_str(&table, TOK_LE, None), "<=");
        assert_eq!(get_tok_str(&table, TOK_GE, None), ">=");
        assert_eq!(get_tok_str(&table, TOK_EQ, None), "==");
        assert_eq!(get_tok_str(&table, TOK_NE, None), "!=");
        assert_eq!(get_tok_str(&table, TOK_LAND, None), "&&");
        assert_eq!(get_tok_str(&table, TOK_LOR, None), "||");
        assert_eq!(get_tok_str(&table, TOK_INC, None), "++");
        assert_eq!(get_tok_str(&table, TOK_DEC, None), "--");
        assert_eq!(get_tok_str(&table, TOK_ARROW, None), "->");
        assert_eq!(get_tok_str(&table, TOK_DOTS, None), "...");
    }

    #[test]
    fn test_get_tok_str_identifier() {
        let mut table = TokenSymTable::new();
        let tok = tok_alloc(&mut table, b"my_var");
        assert_eq!(get_tok_str(&table, tok, None), "my_var");
    }

    #[test]
    fn test_lexer_simple_tokens() {
        let mut file = make_test_file("+ - * ;");
        let mut lexer = Lexer::new(&mut file);
        let mut table = TokenSymTable::new();

        lexer.set_parse_flags(0);

        lexer.next_raw(&mut table).unwrap();
        assert_eq!(lexer.tok, b'+' as i32);

        lexer.next_raw(&mut table).unwrap();
        assert_eq!(lexer.tok, b'-' as i32);

        lexer.next_raw(&mut table).unwrap();
        assert_eq!(lexer.tok, b'*' as i32);

        lexer.next_raw(&mut table).unwrap();
        assert_eq!(lexer.tok, b';' as i32);

        lexer.next_raw(&mut table).unwrap();
        assert_eq!(lexer.tok, TOK_EOF);
    }

    #[test]
    fn test_lexer_multi_char_operators() {
        let mut file = make_test_file("++ -- <= >= == != && ||");
        let mut lexer = Lexer::new(&mut file);
        let mut table = TokenSymTable::new();

        lexer.next_raw(&mut table).unwrap();
        assert_eq!(lexer.tok, TOK_INC);

        lexer.next_raw(&mut table).unwrap();
        assert_eq!(lexer.tok, TOK_DEC);

        lexer.next_raw(&mut table).unwrap();
        assert_eq!(lexer.tok, TOK_LE);

        lexer.next_raw(&mut table).unwrap();
        assert_eq!(lexer.tok, TOK_GE);

        lexer.next_raw(&mut table).unwrap();
        assert_eq!(lexer.tok, TOK_EQ);

        lexer.next_raw(&mut table).unwrap();
        assert_eq!(lexer.tok, TOK_NE);

        lexer.next_raw(&mut table).unwrap();
        assert_eq!(lexer.tok, TOK_LAND);

        lexer.next_raw(&mut table).unwrap();
        assert_eq!(lexer.tok, TOK_LOR);
    }

    #[test]
    fn test_lexer_identifiers() {
        let mut file = make_test_file("hello world _test x123");
        let mut lexer = Lexer::new(&mut file);
        let mut table = TokenSymTable::new();

        lexer.next_raw(&mut table).unwrap();
        assert!(lexer.tok >= TOK_IDENT as i32);
        assert_eq!(
            get_tok_str(&table, lexer.tok, None),
            "hello"
        );

        lexer.next_raw(&mut table).unwrap();
        assert!(lexer.tok >= TOK_IDENT as i32);
        assert_eq!(
            get_tok_str(&table, lexer.tok, None),
            "world"
        );

        lexer.next_raw(&mut table).unwrap();
        assert!(lexer.tok >= TOK_IDENT as i32);
        assert_eq!(
            get_tok_str(&table, lexer.tok, None),
            "_test"
        );

        lexer.next_raw(&mut table).unwrap();
        assert!(lexer.tok >= TOK_IDENT as i32);
        assert_eq!(
            get_tok_str(&table, lexer.tok, None),
            "x123"
        );
    }

    #[test]
    fn test_lexer_comments() {
        let mut file = make_test_file("a /* comment */ b // line\nc");
        let mut lexer = Lexer::new(&mut file);
        let mut table = TokenSymTable::new();

        lexer.next_raw(&mut table).unwrap();
        assert_eq!(get_tok_str(&table, lexer.tok, None), "a");

        lexer.next_raw(&mut table).unwrap();
        assert_eq!(get_tok_str(&table, lexer.tok, None), "b");

        lexer.set_parse_flags(0); // no LINEFEED
        lexer.next_raw(&mut table).unwrap();
        assert_eq!(get_tok_str(&table, lexer.tok, None), "c");
    }

    #[test]
    fn test_lexer_number() {
        let mut file = make_test_file("123");
        let mut lexer = Lexer::new(&mut file);
        let mut table = TokenSymTable::new();

        lexer.set_parse_flags(PARSE_FLAG_TOK_NUM);
        lexer.next_raw(&mut table).unwrap();
        assert_eq!(lexer.tok, TOK_CINT);
        assert_eq!(unsafe { lexer.tokc.i }, 123);
    }

    #[test]
    fn test_lexer_hex_number() {
        let mut file = make_test_file("0xFF");
        let mut lexer = Lexer::new(&mut file);
        let mut table = TokenSymTable::new();

        lexer.set_parse_flags(PARSE_FLAG_TOK_NUM);
        lexer.next_raw(&mut table).unwrap();
        assert_eq!(lexer.tok, TOK_CINT);
        assert_eq!(unsafe { lexer.tokc.i }, 255);
    }

    #[test]
    fn test_lexer_string() {
        let mut file = make_test_file(r#""hello""#);
        let mut lexer = Lexer::new(&mut file);
        let mut table = TokenSymTable::new();

        lexer.set_parse_flags(PARSE_FLAG_TOK_STR);
        lexer.next_raw(&mut table).unwrap();
        assert_eq!(lexer.tok, TOK_STR);
        // Check string content (excluding null terminator)
        let content = &lexer.tok_buf.data[..lexer.tok_buf.data.len() - 1];
        assert_eq!(content, b"hello");
    }

    #[test]
    fn test_lexer_char_const() {
        let mut file = make_test_file("'a'");
        let mut lexer = Lexer::new(&mut file);
        let mut table = TokenSymTable::new();

        lexer.set_parse_flags(PARSE_FLAG_TOK_STR);
        lexer.next_raw(&mut table).unwrap();
        assert_eq!(lexer.tok, TOK_CCHAR);
        assert_eq!(unsafe { lexer.tokc.i }, b'a' as u64);
    }

    #[test]
    fn test_lexer_escape_sequences() {
        let mut file = make_test_file(r#""\n\t\\""#);
        let mut lexer = Lexer::new(&mut file);
        let mut table = TokenSymTable::new();

        lexer.set_parse_flags(PARSE_FLAG_TOK_STR);
        lexer.next_raw(&mut table).unwrap();
        assert_eq!(lexer.tok, TOK_STR);
        let content = &lexer.tok_buf.data[..lexer.tok_buf.data.len() - 1];
        assert_eq!(content, &[b'\n', b'\t', b'\\']);
    }

    #[test]
    fn test_lexer_arrow_and_dots() {
        let mut file = make_test_file("-> ...");
        let mut lexer = Lexer::new(&mut file);
        let mut table = TokenSymTable::new();

        lexer.next_raw(&mut table).unwrap();
        assert_eq!(lexer.tok, TOK_ARROW);

        lexer.next_raw(&mut table).unwrap();
        assert_eq!(lexer.tok, TOK_DOTS);
    }

    #[test]
    fn test_lexer_assignment_operators() {
        let mut file = make_test_file("+= -= *= /= %= &= |= ^= <<= >>=");
        let mut lexer = Lexer::new(&mut file);
        let mut table = TokenSymTable::new();

        let expected = [
            TOK_A_ADD, TOK_A_SUB, TOK_A_MUL, TOK_A_DIV, TOK_A_MOD,
            TOK_A_AND, TOK_A_OR, TOK_A_XOR, TOK_A_SHL, TOK_A_SAR,
        ];
        for &exp in &expected {
            lexer.next_raw(&mut table).unwrap();
            assert_eq!(lexer.tok, exp, "expected {} got {}", exp, lexer.tok);
        }
    }

    #[test]
    fn test_lexer_eof() {
        let mut file = make_test_file("");
        let mut lexer = Lexer::new(&mut file);
        let mut table = TokenSymTable::new();

        lexer.next_raw(&mut table).unwrap();
        assert_eq!(lexer.tok, TOK_EOF);
    }

    #[test]
    fn test_lexer_linefeed() {
        let mut file = make_test_file("a\nb");
        let mut lexer = Lexer::new(&mut file);
        let mut table = TokenSymTable::new();

        lexer.set_parse_flags(PARSE_FLAG_LINEFEED);

        lexer.next_raw(&mut table).unwrap();
        // First token is 'a'
        assert_eq!(get_tok_str(&table, lexer.tok, None), "a");

        lexer.next_raw(&mut table).unwrap();
        assert_eq!(lexer.tok, TOK_LINEFEED);

        lexer.next_raw(&mut table).unwrap();
        assert_eq!(get_tok_str(&table, lexer.tok, None), "b");
    }

    #[test]
    fn test_lexer_hash() {
        let mut file = make_test_file("# ##");
        let mut lexer = Lexer::new(&mut file);
        let mut table = TokenSymTable::new();

        lexer.next_raw(&mut table).unwrap();
        assert_eq!(lexer.tok, b'#' as i32);

        lexer.next_raw(&mut table).unwrap();
        assert_eq!(lexer.tok, TOK_TWOSHARPS);
    }

    #[test]
    fn test_lexer_unterminated_block_comment() {
        let mut file = make_test_file("/* never ends");
        let mut lexer = Lexer::new(&mut file);
        let mut table = TokenSymTable::new();

        let result = lexer.next_raw(&mut table);
        assert!(result.is_err());
    }

    #[test]
    fn test_lexer_octal_number() {
        let mut file = make_test_file("0777");
        let mut lexer = Lexer::new(&mut file);
        let mut table = TokenSymTable::new();

        lexer.set_parse_flags(PARSE_FLAG_TOK_NUM);
        lexer.next_raw(&mut table).unwrap();
        assert_eq!(unsafe { lexer.tokc.i }, 0o777);
    }

    #[test]
    fn test_lexer_ppnum_without_flag() {
        let mut file = make_test_file("42");
        let mut lexer = Lexer::new(&mut file);
        let mut table = TokenSymTable::new();

        lexer.set_parse_flags(0);
        lexer.next_raw(&mut table).unwrap();
        assert_eq!(lexer.tok, TOK_PPNUM);
    }

    #[test]
    fn test_line_macro_output_format() {
        assert_eq!(LineMacroOutputFormat::default(), LineMacroOutputFormat::Gcc);
        let f = LineMacroOutputFormat::Std;
        assert_ne!(f, LineMacroOutputFormat::None);
        assert_ne!(f, LineMacroOutputFormat::Gcc);
        assert_ne!(f, LineMacroOutputFormat::P10);
    }

    #[test]
    fn test_hex_digit_helper() {
        assert_eq!(hex_digit(b'0' as i32), 0);
        assert_eq!(hex_digit(b'9' as i32), 9);
        assert_eq!(hex_digit(b'a' as i32), 10);
        assert_eq!(hex_digit(b'f' as i32), 15);
        assert_eq!(hex_digit(b'A' as i32), 10);
        assert_eq!(hex_digit(b'F' as i32), 15);
        assert_eq!(hex_digit(b'g' as i32), -1);
        assert_eq!(hex_digit(b' ' as i32), -1);
    }

    #[test]
    fn test_digit_value_helper() {
        assert_eq!(digit_value(b'0'), 0);
        assert_eq!(digit_value(b'9'), 9);
        assert_eq!(digit_value(b'a'), 10);
        assert_eq!(digit_value(b'f'), 15);
        assert_eq!(digit_value(b'z'), 35);
    }
}
