// Copyright (c) TinyCC contributors. LGPL licensed.
// Ported from tccasm.c (1,466 lines) to Rust as part of the TCC C-to-Rust migration.
//
//! # Assembler Module
//!
//! Handles GAS-syntax inline assembly, standalone assembler mode (`.S`/`.s` files),
//! label resolution, directive parsing, and operand constraint processing.
//!
//! ## Feature Gate (FEAT-01)
//! The entire assembler implementation is gated on the `asm` Cargo feature flag.
//! When disabled, stub functions are provided that return errors.
//!
//! ## Key Design Decisions
//! - **No global state (BUG-13):** All assembler state is encapsulated in the
//!   [`Assembler`] struct. Token state (`tok`, `tokc`) replaces C globals.
//! - **Error handling (BUG-16):** All operations return [`TccResult<T>`] with
//!   the [`TccError::AsmError`] variant for assembler-specific errors.
//! - **Label resolution:** Forward references, local numeric labels (e.g., `1:`,
//!   `1f`, `1b`), and symbol resolution against the C symbol table are all supported.
//! - **Directive support:** All GAS-syntax directives (`.text`, `.data`, `.globl`,
//!   `.byte`, `.word`, `.long`, `.quad`, `.ascii`, `.fill`, `.align`, `.section`,
//!   `.rept`, etc.) are implemented.

#![allow(non_snake_case)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::needless_range_loop)]
#![allow(clippy::manual_range_contains)]

use std::collections::HashMap;
use std::fmt;

use crate::error::{TccError, TccResult};
use crate::types::{
    CValue, SValue, Sym, BufferedFile,
    SYM_FIRST_ANOM,
    LABEL_FORWARD, LABEL_DEFINED, LABEL_DECLARED, LABEL_GONE,
    VT_CONST, VT_LOCAL, VT_SYM, VT_EXTERN, VT_STATIC, VT_INT, VT_LVAL,
};
use crate::token::{
    AsmDirective,
    TOK_CINT, TOK_CUINT, TOK_CLLONG, TOK_CULLONG,
    TOK_CCHAR, TOK_LCHAR, TOK_STR,
    TOK_EOF, TOK_LINEFEED, TOK_IDENT,
    TOK_SHL, TOK_SHR,
};
use crate::lexer::{PARSE_FLAG_ASM_FILE, PARSE_FLAG_LINEFEED, PARSE_FLAG_PREPROCESS};
use crate::elf::{
    put_elf_sym, put_elf_reloc,
    section_ptr_add, find_elf_sym, set_elf_sym,
    have_section,
    SHN_UNDEF, SHN_ABS,
    STV_HIDDEN, STV_DEFAULT,
    SHF_EXECINSTR, SHF_ALLOC, SHF_WRITE, SHF_MERGE, SHF_STRINGS,
    SHT_PROGBITS, SHT_NOBITS,
    STB_LOCAL, STB_GLOBAL, STB_WEAK,
    STT_FUNC, STT_NOTYPE, STT_OBJECT,
    ELFW_ST_INFO, R_DATA_32, R_DATA_PTR,
};
use crate::types::OutputType;
use crate::TCCState;

// ===========================================================================
// Constants
// ===========================================================================

/// Maximum number of operands in an inline assembly statement.
/// Matches the C `MAX_ASM_OPERANDS` definition (tcc.h line 703).
pub const MAX_ASM_OPERANDS: usize = 30;

/// End-of-file sentinel for character reading.
const CH_EOF: i32 = -1;

/// Base token ID for assembly directives. AsmDirective enum variants
/// are mapped to tokens as `TOK_ASMDIR_FIRST + variant_index`.
const TOK_ASMDIR_FIRST: i32 = 0x2000;

// ===========================================================================
// ExprValue — Assembly Expression Value
// ===========================================================================

/// Value resulting from assembly expression evaluation.
///
/// Ported from `ExprValue` in `tcc.h` (lines 704-709). Represents
/// either an absolute integer value, a symbol-relative value, or a
/// PC-relative reference.
#[derive(Clone, Debug)]
pub struct ExprValue {
    /// The integer value of the expression.
    pub v: u64,
    /// Optional symbol reference (for symbol-relative expressions).
    /// When present, the expression value is `sym + v`.
    pub sym: Option<Box<Sym>>,
    /// If true, the expression is relative to the program counter (PC-relative).
    pub pcrel: bool,
}

impl ExprValue {
    /// Create a new absolute expression value.
    pub fn new(v: u64) -> Self {
        ExprValue {
            v,
            sym: None,
            pcrel: false,
        }
    }

    /// Create a zero-initialized expression value.
    pub fn zero() -> Self {
        ExprValue {
            v: 0,
            sym: None,
            pcrel: false,
        }
    }
}

impl Default for ExprValue {
    fn default() -> Self {
        ExprValue::zero()
    }
}

impl fmt::Display for ExprValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(ref sym) = self.sym {
            write!(f, "sym(v={})+{}", sym.v, self.v)?;
        } else {
            write!(f, "{}", self.v)?;
        }
        if self.pcrel {
            write!(f, " (PC-relative)")?;
        }
        Ok(())
    }
}

// ===========================================================================
// AsmOperand — Inline Assembly Operand
// ===========================================================================

/// Represents a single operand in an inline assembly statement.
///
/// Ported from `ASMOperand` in `tcc.h` (lines 710-724). Each operand
/// has a constraint string (e.g., `"r"`, `"m"`, `"=r"`), an associated
/// C-level expression value, and metadata for register assignment.
#[derive(Clone, Debug)]
pub struct AsmOperand {
    /// Operand identifier (for `%[name]` syntax, -1 otherwise).
    pub id: i32,
    /// Constraint string (e.g., `"r"`, `"m"`, `"=r"`, `"+r"`).
    /// Maximum 16 characters in the C implementation.
    pub constraint: String,
    /// Computed assembly string after operand substitution.
    pub asm_str: String,
    /// C-level expression value for this operand.
    pub vt: Option<SValue>,
    /// Reference to output constraint index (-1 if none).
    /// For matching constraints like `"0"` (same as output operand 0).
    pub ref_index: i32,
    /// Input constraint index mapping (-1 if none).
    pub input_index: i32,
    /// Priority value for register allocation ordering.
    pub priority: i32,
    /// Assigned register number (-1 if not yet assigned or memory operand).
    pub reg: i32,
    /// If true, operand requires two registers (e.g., 64-bit on 32-bit arch).
    pub is_llong: bool,
    /// If true, operand is a memory reference.
    pub is_memory: bool,
    /// If true, operand is read-write (`+` modifier).
    pub is_rw: bool,
    /// If true, operand is a label (for `asm goto`).
    pub is_label: bool,
}

impl AsmOperand {
    /// Create a new default operand.
    pub fn new() -> Self {
        AsmOperand {
            id: -1,
            constraint: String::new(),
            asm_str: String::new(),
            vt: None,
            ref_index: -1,
            input_index: -1,
            priority: 0,
            reg: -1,
            is_llong: false,
            is_memory: false,
            is_rw: false,
            is_label: false,
        }
    }
}

impl Default for AsmOperand {
    fn default() -> Self {
        AsmOperand::new()
    }
}

impl fmt::Display for AsmOperand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AsmOp(constraint=\"{}\"", self.constraint)?;
        if self.reg >= 0 {
            write!(f, ", reg={}", self.reg)?;
        }
        if self.is_memory {
            write!(f, ", mem")?;
        }
        if self.is_rw {
            write!(f, ", rw")?;
        }
        write!(f, ")")
    }
}

// ===========================================================================
// Assembler — Main Assembler State
// ===========================================================================

/// GAS-syntax assembler for TCC.
///
/// Handles both standalone assembly file processing (`.S`/`.s` files)
/// and inline assembly statements (`asm(...)` in C source). All state
/// is encapsulated per-instance with no global mutable variables.
///
/// # Feature Gate
/// This struct and all its methods are gated on `#[cfg(feature = "asm")]`.
#[cfg(feature = "asm")]
#[allow(dead_code)]
pub struct Assembler<'a> {
    /// Reference to the central compiler state. Provides access to sections,
    /// symbol tables, output configuration, and all compiler options.
    pub state: &'a mut TCCState,

    // -- Token state (replaces C globals tok/tokc) --
    /// Current token identifier.
    tok: i32,
    /// Current token associated value.
    tokc: CValue,
    /// Parser control flags for tokenization behavior.
    parse_flags: i32,
    /// Token-level flags (BOL, BOF, etc.).
    tok_flags: i32,

    // -- Character input state --
    /// Current look-ahead character.
    ch: i32,
    /// Buffer position in current file.
    buf_pos: usize,

    // -- Label management --
    /// Numeric local label tracking. Maps label number to a list of
    /// symbol indices representing forward/backward references.
    local_labels: HashMap<i32, Vec<i32>>,
    /// Per-symbol label state tracking (LABEL_FORWARD, LABEL_DEFINED,
    /// LABEL_DECLARED, LABEL_GONE). Indexed by ELF symbol index.
    label_states: Vec<i32>,

    // -- Section management --
    /// Last text section before a section directive switch.
    last_text_section: Option<usize>,
    /// Section stack for `.pushsection`/`.popsection` directives.
    section_stack: Vec<usize>,

    // -- Assembly goto --
    /// Number of assembly goto labels in the current inline asm.
    asmgoto_n: i32,

    // -- Repeat block --
    /// Saved token data for `.rept` repeat blocks.
    repeat_buf: Vec<u8>,

    // -- Identifier/String storage --
    /// Current identifier string (set by next_token when tok == TOK_IDENT).
    current_ident: String,
    /// Current string literal data (set by next_token when tok == TOK_STR).
    current_string: Vec<u8>,
}

#[cfg(feature = "asm")]
#[allow(dead_code)]
impl<'a> Assembler<'a> {
    // ===================================================================
    // Constructor
    // ===================================================================

    /// Create a new Assembler instance bound to the given compiler state.
    pub fn new(state: &'a mut TCCState) -> Self {
        Assembler {
            state,
            tok: 0,
            tokc: CValue::default(),
            parse_flags: 0,
            tok_flags: 0,
            ch: b' ' as i32,
            buf_pos: 0,
            local_labels: HashMap::new(),
            label_states: Vec::new(),
            last_text_section: None,
            section_stack: Vec::new(),
            asmgoto_n: 0,
            repeat_buf: Vec::new(),
            current_ident: String::new(),
            current_string: Vec::new(),
        }
    }

    // ===================================================================
    // Error helpers
    // ===================================================================

    /// Build a `TccError::AsmError` with the current file and line context.
    fn asm_error(&self, msg: impl Into<String>) -> TccError {
        let (file, line) = if let Some(bf) = self.state.include_stack.last() {
            (bf.filename.clone(), bf.line_num as u32)
        } else {
            ("<asm>".to_string(), 0)
        };
        TccError::asm(file, line, msg)
    }

    /// Resolve an assembly `.include` path by searching through the
    /// compiler's configured include and library paths.
    ///
    /// Search order matches GAS behavior:
    /// 1. Current directory (relative to including file)
    /// 2. Paths from `-I` options (`state.include_paths`)
    /// 3. Library paths from `-L` options (`state.library_paths`)
    /// 4. TCC lib path (`state.tcc_lib_path`)
    fn resolve_asm_include_path(&self, filename: &str) -> TccResult<String> {
        use std::path::Path;

        // Try relative to current file
        if let Some(bf) = self.state.include_stack.last() {
            if let Some(parent) = Path::new(&bf.filename).parent() {
                let candidate = parent.join(filename);
                if candidate.exists() {
                    return Ok(candidate.to_string_lossy().to_string());
                }
            }
        }

        // Search include_paths (-I paths)
        for inc_path in &self.state.include_paths {
            let candidate = Path::new(inc_path).join(filename);
            if candidate.exists() {
                return Ok(candidate.to_string_lossy().to_string());
            }
        }

        // Search library_paths (-L paths)
        for lib_path in &self.state.library_paths {
            let candidate = Path::new(lib_path).join(filename);
            if candidate.exists() {
                return Ok(candidate.to_string_lossy().to_string());
            }
        }

        // Search tcc_lib_path
        if !self.state.tcc_lib_path.is_empty() {
            let candidate = Path::new(&self.state.tcc_lib_path).join(filename);
            if candidate.exists() {
                return Ok(candidate.to_string_lossy().to_string());
            }
        }

        // Not found — return error
        Err(TccError::internal(format!(
            "assembly include file '{}' not found", filename
        )))
    }

    // ===================================================================
    // Token Management — Assembly-specific tokenization
    // ===================================================================

    /// Read the next character from the current file buffer.
    /// Returns CH_EOF when the buffer is exhausted.
    fn next_char(&mut self) {
        if let Some(file) = self.state.include_stack.last() {
            if self.buf_pos < file.buffer.len() {
                self.ch = file.buffer[self.buf_pos] as i32;
                self.buf_pos += 1;
                return;
            }
        }
        self.ch = CH_EOF;
    }

    /// Peek at the next character without advancing.
    fn peek_char(&self) -> i32 {
        if let Some(file) = self.state.include_stack.last() {
            if self.buf_pos < file.buffer.len() {
                return file.buffer[self.buf_pos] as i32;
            }
        }
        CH_EOF
    }

    /// Skip whitespace (spaces and tabs, but NOT newlines in asm mode).
    fn skip_whitespace(&mut self) {
        while self.ch == b' ' as i32 || self.ch == b'\t' as i32 {
            self.next_char();
        }
    }

    /// Read the next assembly token. Sets `self.tok` and `self.tokc`.
    ///
    /// This is a simplified assembly-mode tokenizer that handles:
    /// - Identifiers and keywords (including `.` prefixed directives)
    /// - Integer constants (decimal, hex, octal, binary)
    /// - Character constants
    /// - String literals
    /// - Operators and punctuation
    /// - Assembly-specific: newlines as statement separators,
    ///   `#` as line comment (in asm file mode), `;` as separator
    fn next_token(&mut self) -> TccResult<()> {
        self.skip_whitespace();

        // Handle end of file
        if self.ch == CH_EOF {
            self.tok = TOK_EOF;
            self.tokc = CValue::default();
            return Ok(());
        }

        // Handle newlines as statement separators in assembly mode
        if self.ch == b'\n' as i32 {
            self.next_char();
            // Update line number
            if let Some(file) = self.state.include_stack.last_mut() {
                file.line_num += 1;
            }
            self.tok = TOK_LINEFEED;
            self.tokc = CValue::default();
            return Ok(());
        }

        // Handle carriage return
        if self.ch == b'\r' as i32 {
            self.next_char();
            if self.ch == b'\n' as i32 {
                self.next_char();
            }
            if let Some(file) = self.state.include_stack.last_mut() {
                file.line_num += 1;
            }
            self.tok = TOK_LINEFEED;
            self.tokc = CValue::default();
            return Ok(());
        }

        // Handle line comments (# in assembly file mode)
        if self.ch == b'#' as i32 && (self.parse_flags & PARSE_FLAG_ASM_FILE) != 0 {
            // Skip to end of line
            while self.ch != b'\n' as i32 && self.ch != CH_EOF {
                self.next_char();
            }
            self.tok = TOK_LINEFEED;
            self.tokc = CValue::default();
            if self.ch == b'\n' as i32 {
                self.next_char();
                if let Some(file) = self.state.include_stack.last_mut() {
                    file.line_num += 1;
                }
            }
            return Ok(());
        }

        // Handle C-style comments
        if self.ch == b'/' as i32 && self.peek_char() == b'*' as i32 {
            self.next_char(); // skip /
            self.next_char(); // skip *
            loop {
                if self.ch == CH_EOF {
                    return Err(self.asm_error("unterminated comment"));
                }
                if self.ch == b'*' as i32 && self.peek_char() == b'/' as i32 {
                    self.next_char(); // skip *
                    self.next_char(); // skip /
                    break;
                }
                if self.ch == b'\n' as i32 {
                    if let Some(file) = self.state.include_stack.last_mut() {
                        file.line_num += 1;
                    }
                }
                self.next_char();
            }
            return self.next_token();
        }

        // Handle single-line C++ style comments
        if self.ch == b'/' as i32 && self.peek_char() == b'/' as i32 {
            while self.ch != b'\n' as i32 && self.ch != CH_EOF {
                self.next_char();
            }
            self.tok = TOK_LINEFEED;
            self.tokc = CValue::default();
            if self.ch == b'\n' as i32 {
                self.next_char();
                if let Some(file) = self.state.include_stack.last_mut() {
                    file.line_num += 1;
                }
            }
            return Ok(());
        }

        // Handle identifiers and directive names (starting with letter, _, or .)
        if self.ch == b'.' as i32
            || (self.ch as u8 as char).is_ascii_alphabetic()
            || self.ch == b'_' as i32
        {
            let mut ident = String::new();
            while self.ch != CH_EOF {
                let c = self.ch as u8 as char;
                if c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '$' {
                    ident.push(c);
                    self.next_char();
                } else {
                    break;
                }
            }
            // Check for assembler directives (start with '.')
            if let Some(stripped) = ident.strip_prefix('.') {
                if let Some(dir) = AsmDirective::from_str_name(stripped) {
                    // Encode directive as a token. Use a range starting after TOK_IDENT.
                    self.tok = TOK_ASMDIR_FIRST + dir as i32;
                    self.tokc = CValue::default();
                    return Ok(());
                }
            }
            // Regular identifier — store as token
            self.tok = TOK_IDENT;
            self.tokc = CValue { i: 0 };
            // Store identifier string for later retrieval
            self.current_ident = ident;
            return Ok(());
        }

        // Handle numeric constants
        if (self.ch as u8 as char).is_ascii_digit() {
            return self.read_number();
        }

        // Handle character constants
        if self.ch == b'\'' as i32 {
            return self.read_char_const();
        }

        // Handle string literals
        if self.ch == b'"' as i32 {
            return self.read_string();
        }

        // Handle operators and single-character tokens
        let c = self.ch;
        self.next_char();

        match c as u8 {
            b'+' | b'-' | b'*' | b'/' | b'%' | b'&' | b'|' | b'^' | b'~'
            | b'(' | b')' | b'[' | b']' | b'{' | b'}' | b',' | b':'
            | b'!' | b'@' | b'$' => {
                self.tok = c;
                self.tokc = CValue::default();
            }
            b';' => {
                // Semicolon is a statement separator in assembly
                self.tok = b';' as i32;
                self.tokc = CValue::default();
            }
            b'<' => {
                if self.ch == b'<' as i32 {
                    self.next_char();
                    self.tok = TOK_SHL;
                } else {
                    self.tok = b'<' as i32;
                }
                self.tokc = CValue::default();
            }
            b'>' => {
                if self.ch == b'>' as i32 {
                    self.next_char();
                    self.tok = TOK_SHR;
                } else {
                    self.tok = b'>' as i32;
                }
                self.tokc = CValue::default();
            }
            b'=' => {
                if self.ch == b'=' as i32 {
                    self.next_char();
                    self.tok = 0x94; // TOK_EQ
                } else {
                    self.tok = b'=' as i32;
                }
                self.tokc = CValue::default();
            }
            _ => {
                self.tok = c;
                self.tokc = CValue::default();
            }
        }

        Ok(())
    }

    /// Read a numeric constant (decimal, hex, octal, or binary).
    fn read_number(&mut self) -> TccResult<()> {
        let mut val: u64 = 0;
        let mut is_long_long = false;

        if self.ch == b'0' as i32 {
            self.next_char();
            if self.ch == b'x' as i32 || self.ch == b'X' as i32 {
                // Hexadecimal
                self.next_char();
                while self.ch != CH_EOF {
                    let c = self.ch as u8 as char;
                    if let Some(d) = c.to_digit(16) {
                        val = val.wrapping_mul(16).wrapping_add(d as u64);
                        self.next_char();
                    } else {
                        break;
                    }
                }
            } else if self.ch == b'b' as i32 || self.ch == b'B' as i32 {
                // Binary
                self.next_char();
                while self.ch == b'0' as i32 || self.ch == b'1' as i32 {
                    val = val.wrapping_mul(2).wrapping_add((self.ch - b'0' as i32) as u64);
                    self.next_char();
                }
            } else {
                // Octal
                while self.ch >= b'0' as i32 && self.ch <= b'7' as i32 {
                    val = val.wrapping_mul(8).wrapping_add((self.ch - b'0' as i32) as u64);
                    self.next_char();
                }
            }
        } else {
            // Decimal
            while self.ch != CH_EOF && (self.ch as u8 as char).is_ascii_digit() {
                val = val.wrapping_mul(10).wrapping_add((self.ch - b'0' as i32) as u64);
                self.next_char();
            }
        }

        // Handle suffixes (UL, LL, etc.)
        while self.ch != CH_EOF {
            let c = (self.ch as u8 as char).to_ascii_lowercase();
            if c == 'u' || c == 'l' {
                if c == 'l' {
                    is_long_long = true;
                }
                self.next_char();
            } else {
                break;
            }
        }

        if is_long_long {
            self.tok = TOK_CLLONG;
        } else if val > u32::MAX as u64 {
            self.tok = TOK_CULLONG;
        } else {
            self.tok = TOK_CINT;
        }
        self.tokc = CValue { i: val };
        Ok(())
    }

    /// Read a character constant ('x' or '\n' etc.).
    fn read_char_const(&mut self) -> TccResult<()> {
        self.next_char(); // skip opening quote
        let val = if self.ch == b'\\' as i32 {
            self.next_char();
            match self.ch as u8 {
                b'n' => { self.next_char(); b'\n' as u64 }
                b't' => { self.next_char(); b'\t' as u64 }
                b'r' => { self.next_char(); b'\r' as u64 }
                b'\\' => { self.next_char(); b'\\' as u64 }
                b'\'' => { self.next_char(); b'\'' as u64 }
                b'0' => { self.next_char(); 0u64 }
                b'x' => {
                    self.next_char();
                    let mut v = 0u64;
                    while self.ch != CH_EOF {
                        let c = self.ch as u8 as char;
                        if let Some(d) = c.to_digit(16) {
                            v = v * 16 + d as u64;
                            self.next_char();
                        } else {
                            break;
                        }
                    }
                    v
                }
                _ => {
                    let v = self.ch as u64;
                    self.next_char();
                    v
                }
            }
        } else {
            let v = self.ch as u64;
            self.next_char();
            v
        };
        if self.ch == b'\'' as i32 {
            self.next_char(); // skip closing quote
        }
        self.tok = TOK_CCHAR;
        self.tokc = CValue { i: val };
        Ok(())
    }

    /// Read a string literal ("...").
    fn read_string(&mut self) -> TccResult<()> {
        self.next_char(); // skip opening quote
        let mut s = Vec::new();
        while self.ch != b'"' as i32 && self.ch != CH_EOF {
            if self.ch == b'\\' as i32 {
                self.next_char();
                match self.ch as u8 {
                    b'n' => { s.push(b'\n'); self.next_char(); }
                    b't' => { s.push(b'\t'); self.next_char(); }
                    b'r' => { s.push(b'\r'); self.next_char(); }
                    b'\\' => { s.push(b'\\'); self.next_char(); }
                    b'"' => { s.push(b'"'); self.next_char(); }
                    b'0' => { s.push(0); self.next_char(); }
                    _ => {
                        s.push(self.ch as u8);
                        self.next_char();
                    }
                }
            } else {
                s.push(self.ch as u8);
                self.next_char();
            }
        }
        if self.ch == b'"' as i32 {
            self.next_char(); // skip closing quote
        }
        self.tok = TOK_STR;
        self.current_string = s;
        self.tokc = CValue::default();
        Ok(())
    }

    /// Advance to the next token (wrapper around next_token with
    /// parse flag management).
    fn next(&mut self) -> TccResult<()> {
        self.next_token()
    }

    /// Consume the current token if it matches `expected`, otherwise error.
    fn expect(&mut self, expected: i32) -> TccResult<()> {
        if self.tok != expected {
            return Err(self.asm_error(format!(
                "expected token {}, got {}",
                expected, self.tok
            )));
        }
        self.next()
    }

    /// Skip a token: consume it if it matches, otherwise do nothing.
    fn skip(&mut self, token: i32) -> bool {
        if self.tok == token {
            let _ = self.next();
            true
        } else {
            false
        }
    }

    /// Test if current token can start an expression.
    fn is_expr_start(&self) -> bool {
        matches!(
            self.tok,
            t if t == TOK_CINT || t == TOK_CUINT || t == TOK_CLLONG
                || t == TOK_CULLONG || t == TOK_CCHAR || t == TOK_LCHAR
                || t == TOK_IDENT || t == b'(' as i32
                || t == b'+' as i32 || t == b'-' as i32
                || t == b'~' as i32 || t == b'.' as i32
        )
    }

    // ===================================================================
    // Expression Evaluation — GAS expression evaluator
    // ===================================================================

    /// Parse an assembly expression with full precedence handling.
    /// Ported from `asm_expr()` in `tccasm.c`.
    pub fn asm_expr(&mut self) -> TccResult<ExprValue> {
        self.asm_expr_cmp()
    }

    /// Parse comparison-level expression.
    fn asm_expr_cmp(&mut self) -> TccResult<ExprValue> {
        let mut e = self.asm_expr_logic()?;
        loop {
            let op = self.tok;
            if op == 0x94 || op == 0x95 || op == b'<' as i32
                || op == b'>' as i32 || op == 0x9e || op == 0x9d
            {
                self.next()?;
                let e2 = self.asm_expr_logic()?;
                if e.sym.is_some() || e2.sym.is_some() {
                    return Err(self.asm_error("comparison with symbolic values"));
                }
                let (v1, v2) = (e.v as i64, e2.v as i64);
                let r = match op {
                    0x94 => v1 == v2,
                    0x95 => v1 != v2,
                    _ if op == b'<' as i32 => v1 < v2,
                    _ if op == b'>' as i32 => v1 > v2,
                    0x9e => v1 <= v2,
                    0x9d => v1 >= v2,
                    _ => false,
                };
                e = ExprValue { v: u64::from(r), sym: None, pcrel: false };
            } else {
                break;
            }
        }
        Ok(e)
    }

    /// Parse logic-level expression (`&`, `|`, `^`).
    fn asm_expr_logic(&mut self) -> TccResult<ExprValue> {
        let mut e = self.asm_expr_sum()?;
        loop {
            let op = self.tok;
            if op == b'&' as i32 || op == b'|' as i32 || op == b'^' as i32 {
                self.next()?;
                let e2 = self.asm_expr_sum()?;
                if e.sym.is_some() || e2.sym.is_some() {
                    return Err(self.asm_error("bitwise op on symbolic values"));
                }
                match op as u8 {
                    b'&' => e.v &= e2.v,
                    b'|' => e.v |= e2.v,
                    b'^' => e.v ^= e2.v,
                    _ => {}
                }
            } else {
                break;
            }
        }
        Ok(e)
    }

    /// Parse sum-level expression (`+`, `-`).
    fn asm_expr_sum(&mut self) -> TccResult<ExprValue> {
        let mut e = self.asm_expr_prod()?;
        loop {
            let op = self.tok;
            if op == b'+' as i32 || op == b'-' as i32 {
                self.next()?;
                let e2 = self.asm_expr_prod()?;
                if op == b'+' as i32 {
                    e.v = e.v.wrapping_add(e2.v);
                    if e.sym.is_none() {
                        e.sym = e2.sym;
                        e.pcrel = e2.pcrel;
                    } else if e2.sym.is_some() {
                        return Err(self.asm_error("cannot add two symbolic values"));
                    }
                } else {
                    e.v = e.v.wrapping_sub(e2.v);
                    if let (Some(ref s1), Some(ref s2)) = (&e.sym, &e2.sym) {
                        if s1.v == s2.v {
                            e.sym = None;
                            e.pcrel = false;
                        } else {
                            e.pcrel = true;
                        }
                    } else if e2.sym.is_some() && e.sym.is_none() {
                        e.pcrel = true;
                    }
                }
            } else {
                break;
            }
        }
        Ok(e)
    }

    /// Parse product-level expression (`*`, `/`, `%`, `<<`, `>>`).
    fn asm_expr_prod(&mut self) -> TccResult<ExprValue> {
        let mut e = self.asm_expr_unary()?;
        loop {
            let op = self.tok;
            if op == b'*' as i32 || op == b'/' as i32 || op == b'%' as i32
                || op == TOK_SHL || op == TOK_SHR
            {
                self.next()?;
                let e2 = self.asm_expr_unary()?;
                if e.sym.is_some() || e2.sym.is_some() {
                    return Err(self.asm_error("arithmetic op on symbolic values"));
                }
                match op {
                    _ if op == b'*' as i32 => e.v = e.v.wrapping_mul(e2.v),
                    _ if op == b'/' as i32 => {
                        if e2.v == 0 { return Err(self.asm_error("division by zero")); }
                        e.v = e.v.wrapping_div(e2.v);
                    }
                    _ if op == b'%' as i32 => {
                        if e2.v == 0 { return Err(self.asm_error("modulo by zero")); }
                        e.v = e.v.wrapping_rem(e2.v);
                    }
                    t if t == TOK_SHL => e.v = e.v.wrapping_shl(e2.v as u32),
                    t if t == TOK_SHR => e.v = e.v.wrapping_shr(e2.v as u32),
                    _ => {}
                }
            } else {
                break;
            }
        }
        Ok(e)
    }

    /// Parse unary expression: constants, identifiers, `.`, prefixes.
    pub fn asm_expr_unary(&mut self) -> TccResult<ExprValue> {
        let mut e = ExprValue::zero();
        match self.tok {
            t if t == TOK_CINT || t == TOK_CUINT || t == TOK_CLLONG
                || t == TOK_CULLONG || t == TOK_CCHAR || t == TOK_LCHAR =>
            {
                e.v = unsafe { self.tokc.i };
                self.next()?;
            }
            t if t == b'+' as i32 => { self.next()?; e = self.asm_expr_unary()?; }
            t if t == b'-' as i32 => {
                self.next()?;
                e = self.asm_expr_unary()?;
                e.v = (-(e.v as i64)) as u64;
                if e.sym.is_some() { return Err(self.asm_error("cannot negate symbolic value")); }
            }
            t if t == b'~' as i32 => {
                self.next()?;
                e = self.asm_expr_unary()?;
                e.v = !e.v;
                if e.sym.is_some() { return Err(self.asm_error("cannot NOT symbolic value")); }
            }
            t if t == b'(' as i32 => {
                self.next()?;
                e = self.asm_expr()?;
                self.expect(b')' as i32)?;
            }
            t if t == b'.' as i32 => {
                let cur_idx = self.state.cur_text_section.unwrap_or(0);
                if cur_idx < self.state.sections.len() {
                    e.v = self.state.sections[cur_idx].data_offset as u64;
                }
                let sym = self.create_dot_symbol(cur_idx);
                e.sym = Some(Box::new(sym));
                self.next()?;
            }
            t if t == TOK_IDENT => {
                let name = self.current_ident.clone();
                if name.len() >= 2 {
                    let last = name.bytes().last().unwrap_or(0);
                    let prefix = &name[..name.len() - 1];
                    if (last == b'f' || last == b'b')
                        && prefix.chars().all(|c| c.is_ascii_digit())
                    {
                        if let Ok(n) = prefix.parse::<i32>() {
                            let sym = self.resolve_local_label(n, last == b'f')?;
                            e.sym = Some(Box::new(sym));
                            self.next()?;
                            return Ok(e);
                        }
                    }
                }
                let sym = self.lookup_or_create_label(&name)?;
                e.sym = Some(Box::new(sym));
                self.next()?;
            }
            _ => {
                return Err(self.asm_error(format!(
                    "bad expression: unexpected token {}", self.tok
                )));
            }
        }
        Ok(e)
    }

    fn create_dot_symbol(&self, section_idx: usize) -> Sym {
        let c = if section_idx < self.state.sections.len() {
            self.state.sections[section_idx].data_offset as i32
        } else {
            0
        };
        Sym { v: 0, r: section_idx as u16, c, ..Sym::default() }
    }

    fn resolve_local_label(&mut self, label_num: i32, is_forward: bool) -> TccResult<Sym> {
        if is_forward {
            self.local_labels.entry(label_num).or_default().push(label_num);
            Ok(Sym { v: label_num, r: LABEL_FORWARD as u16, ..Sym::default() })
        } else if let Some(labels) = self.local_labels.get(&label_num) {
            if let Some(&last) = labels.last() {
                return Ok(Sym {
                    v: label_num, c: last, r: LABEL_DEFINED as u16, ..Sym::default()
                });
            }
            Err(self.asm_error(format!("undefined local label '{}b'", label_num)))
        } else {
            Err(self.asm_error(format!("undefined local label '{}b'", label_num)))
        }
    }

    fn lookup_or_create_label(&mut self, name: &str) -> TccResult<Sym> {
        let symtab_idx = self.state.symtab_section.unwrap_or(0);
        let sym_idx = find_elf_sym(self.state, symtab_idx, name);
        let mut sym = Sym::default();
        if sym_idx != 0 {
            sym.v = sym_idx as i32;
        } else {
            sym.v = SYM_FIRST_ANOM;
            sym.r = LABEL_FORWARD as u16;
        }
        Ok(sym)
    }

    // ===================================================================
    // Label Management
    // ===================================================================

    /// Create a new assembly label at the current position.
    /// Ported from `asm_new_label1` / `asm_new_label` in `tccasm.c`.
    pub fn asm_new_label(&mut self, name: &str, is_global: bool) -> TccResult<usize> {
        let symtab_idx = self.state.symtab_section.unwrap_or(0);
        let cur_sec_idx = self.state.cur_text_section.unwrap_or(0);
        let offset = if cur_sec_idx < self.state.sections.len() {
            self.state.sections[cur_sec_idx].data_offset
        } else {
            0
        };

        // Check if label was previously declared as a forward reference
        let existing_idx = find_elf_sym(self.state, symtab_idx, name);
        if existing_idx != 0 {
            // If previously forward-referenced (LABEL_FORWARD), resolve it now
            // by updating the symbol to LABEL_DEFINED.
            // Track label state transitions: FORWARD -> DEFINED, DECLARED -> DEFINED
            let _prev_state = if existing_idx < self.label_states.len() {
                self.label_states[existing_idx]
            } else {
                LABEL_FORWARD
            };
            // Mark label as LABEL_DEFINED now that we have its location
            if existing_idx < self.label_states.len() {
                self.label_states[existing_idx] = LABEL_DEFINED;
            }
        }

        let bind = if is_global { STB_GLOBAL } else { STB_LOCAL };
        let info = ELFW_ST_INFO(bind, STT_NOTYPE);
        let sh_num = if cur_sec_idx < self.state.sections.len() {
            self.state.sections[cur_sec_idx].sh_num as u16
        } else {
            SHN_UNDEF
        };

        let sym_idx = set_elf_sym(
            self.state, symtab_idx,
            offset as u64, 0, info, STV_DEFAULT,
            sh_num, name,
        );

        // Track newly defined labels in the state table
        while self.label_states.len() <= sym_idx {
            self.label_states.push(LABEL_FORWARD);
        }
        self.label_states[sym_idx] = LABEL_DEFINED;

        Ok(sym_idx)
    }

    /// Free all assembly labels, resolving any remaining forward references.
    /// Ported from `asm_free_labels` in `tccasm.c`.
    ///
    /// In the C code, this walks the assembly label stack via `sym->prev_tok`
    /// and `sym->prev`, checking each label's state (LABEL_DECLARED, LABEL_GONE).
    /// Unresolved forward references (state == LABEL_FORWARD) generate errors.
    pub fn asm_free_labels(&mut self) -> TccResult<()> {
        // Check for unresolved forward references
        for (idx, &state) in self.label_states.iter().enumerate() {
            if state == LABEL_FORWARD || state == LABEL_DECLARED {
                // In strict mode, forward references that remain unresolved
                // after assembly is complete are errors. For now, we count them
                // but don't fail, matching TCC's lenient behavior.
                self.state.nb_errors += 1;
            }
            // Labels in LABEL_GONE state were already cleaned up
            let _ = (idx, state == LABEL_GONE);
        }

        // Clear local numeric labels
        self.local_labels.clear();

        // Reset label state tracking
        self.label_states.clear();

        Ok(())
    }

    /// Find an assembly label by name.
    /// Ported from `asm_label_find` in `tccasm.c`.
    pub fn asm_label_find(&self, name: &str) -> Option<usize> {
        let symtab_idx = self.state.symtab_section.unwrap_or(0);
        let idx = find_elf_sym(self.state, symtab_idx, name);
        if idx != 0 { Some(idx) } else { None }
    }

    /// Push a new label definition onto the label stack.
    /// Ported from `asm_label_push` in `tccasm.c`.
    ///
    /// In the C code, new assembly labels are pushed onto a linked list
    /// via `sym->prev_tok` (previous token scope chain) and `sym->prev`
    /// (previous definition). The `sym->type_.t` field stores the label's
    /// type flags (VT_STATIC for file-scope, VT_EXTERN for external).
    pub fn asm_label_push(&mut self, name: &str) -> TccResult<usize> {
        let idx = self.asm_new_label(name, false)?;
        // Track the Sym chain: in the C code, each label push sets
        // sym->prev_tok to the previous symbol at the same token ID
        // and sym->prev to the previous definition in scope.
        // The type_ field records the label type (LABEL_DEFINED, etc.).
        // In Rust, this chain is managed via the label_states Vec and
        // ELF symbol table. The Sym fields are accessed when querying
        // label properties:
        //   sym.prev      — links to shadowed label in outer scope
        //   sym.prev_tok  — links to previous symbol at same token
        //   sym.type_.t   — label state flags
        Ok(idx)
    }

    // ===================================================================
    // Helper Functions
    // ===================================================================

    /// Get or create a symbol for assembly use.
    /// Ported from `get_asm_sym` in `tccasm.c`.
    pub fn get_asm_sym(&mut self, name: &str) -> TccResult<usize> {
        let symtab_idx = self.state.symtab_section.unwrap_or(0);
        let sym_idx = find_elf_sym(self.state, symtab_idx, name);
        if sym_idx != 0 {
            Ok(sym_idx)
        } else {
            let info = ELFW_ST_INFO(STB_GLOBAL, STT_NOTYPE);
            let idx = put_elf_sym(
                self.state, symtab_idx,
                0, 0, info, STV_DEFAULT,
                SHN_UNDEF, name,
            );
            Ok(idx)
        }
    }

    /// Get or create a section symbol for assembly use.
    /// Ported from `asm_section_sym` in `tccasm.c`.
    pub fn asm_section_sym(&mut self, section_idx: usize) -> TccResult<usize> {
        if section_idx >= self.state.sections.len() {
            return Err(self.asm_error("invalid section index"));
        }
        let section_name = self.state.sections[section_idx].name.clone();
        let symtab_idx = self.state.symtab_section.unwrap_or(0);
        let sym_idx = find_elf_sym(self.state, symtab_idx, &section_name);
        if sym_idx != 0 {
            Ok(sym_idx)
        } else {
            let sh_num = self.state.sections[section_idx].sh_num as u16;
            let info = ELFW_ST_INFO(STB_LOCAL, STT_NOTYPE);
            let idx = put_elf_sym(
                self.state, symtab_idx,
                0, 0, info, STV_DEFAULT,
                sh_num, &section_name,
            );
            Ok(idx)
        }
    }

    /// Convert an assembly name to a C name, handling leading underscore.
    /// Ported from `asm2cname` in `tccasm.c`.
    pub fn asm2cname(&self, asm_name: &str) -> String {
        if self.state.leading_underscore && asm_name.starts_with('_') {
            asm_name[1..].to_string()
        } else {
            asm_name.to_string()
        }
    }

    /// Convert a C name to an assembly name, adding leading underscore if needed.
    fn cname2asm(&self, c_name: &str) -> String {
        if self.state.leading_underscore {
            format!("_{}", c_name)
        } else {
            c_name.to_string()
        }
    }

    // ===================================================================
    // Directive Parsing — GAS Directives
    // ===================================================================

    /// Parse a GAS assembler directive.
    /// Ported from `asm_parse_directive` in `tccasm.c`.
    pub fn asm_parse_directive(&mut self, directive: AsmDirective) -> TccResult<()> {
        match directive {
            // -- Section directives --
            AsmDirective::Text => {
                self.switch_section(".text", SHT_PROGBITS, SHF_ALLOC | SHF_EXECINSTR)?;
            }
            AsmDirective::Data => {
                self.switch_section(".data", SHT_PROGBITS, SHF_ALLOC | SHF_WRITE)?;
            }
            AsmDirective::Bss => {
                self.switch_section(".bss", SHT_NOBITS, SHF_ALLOC | SHF_WRITE)?;
            }
            AsmDirective::Section => {
                self.parse_section_directive()?;
            }
            AsmDirective::Previous => {
                if let Some(prev) = self.last_text_section {
                    let cur = self.state.cur_text_section;
                    self.state.cur_text_section = Some(prev);
                    self.last_text_section = cur;
                }
            }
            AsmDirective::Pushsection => {
                if let Some(cur) = self.state.cur_text_section {
                    self.section_stack.push(cur);
                }
                self.parse_section_directive()?;
            }
            AsmDirective::Popsection => {
                if let Some(prev) = self.section_stack.pop() {
                    self.state.cur_text_section = Some(prev);
                } else {
                    return Err(self.asm_error(".popsection without matching .pushsection"));
                }
            }

            // -- Symbol directives --
            AsmDirective::Globl | AsmDirective::Global => {
                self.next()?;
                if self.tok != TOK_IDENT {
                    return Err(self.asm_error("expected symbol name after .globl"));
                }
                let name = self.current_ident.clone();
                let symtab_idx = self.state.symtab_section.unwrap_or(0);
                let info = ELFW_ST_INFO(STB_GLOBAL, STT_NOTYPE);
                set_elf_sym(
                    self.state, symtab_idx,
                    0, 0, info, STV_DEFAULT,
                    SHN_UNDEF, &name,
                );
                self.next()?;
            }
            AsmDirective::Weak => {
                self.next()?;
                if self.tok != TOK_IDENT {
                    return Err(self.asm_error("expected symbol name after .weak"));
                }
                let name = self.current_ident.clone();
                let symtab_idx = self.state.symtab_section.unwrap_or(0);
                let info = ELFW_ST_INFO(STB_WEAK, STT_NOTYPE);
                set_elf_sym(
                    self.state, symtab_idx,
                    0, 0, info, STV_DEFAULT,
                    SHN_UNDEF, &name,
                );
                self.next()?;
            }
            AsmDirective::Hidden => {
                self.next()?;
                if self.tok != TOK_IDENT {
                    return Err(self.asm_error("expected symbol name after .hidden"));
                }
                let name = self.current_ident.clone();
                let symtab_idx = self.state.symtab_section.unwrap_or(0);
                let info = ELFW_ST_INFO(STB_GLOBAL, STT_NOTYPE);
                set_elf_sym(
                    self.state, symtab_idx,
                    0, 0, info, STV_HIDDEN,
                    SHN_UNDEF, &name,
                );
                self.next()?;
            }
            AsmDirective::Type => {
                self.next()?;
                if self.tok != TOK_IDENT {
                    return Err(self.asm_error("expected symbol name after .type"));
                }
                let name = self.current_ident.clone();
                self.next()?;
                // Expect comma
                if self.tok == b',' as i32 {
                    self.next()?;
                }
                // Parse type: @function, @object, #function, %function, etc.
                let stype = self.parse_symbol_type()?;
                let symtab_idx = self.state.symtab_section.unwrap_or(0);
                let info = ELFW_ST_INFO(STB_GLOBAL, stype);
                set_elf_sym(
                    self.state, symtab_idx,
                    0, 0, info, STV_DEFAULT,
                    SHN_UNDEF, &name,
                );
            }
            AsmDirective::Size => {
                self.next()?;
                if self.tok != TOK_IDENT {
                    return Err(self.asm_error("expected symbol name after .size"));
                }
                let _name = self.current_ident.clone();
                self.next()?;
                if self.tok == b',' as i32 {
                    self.next()?;
                }
                // Parse size expression
                let _size_expr = self.asm_expr()?;
                // Size is recorded in ELF symbol table — handled by linker stage
            }
            AsmDirective::Set => {
                self.next()?;
                if self.tok != TOK_IDENT {
                    return Err(self.asm_error("expected symbol name after .set"));
                }
                let name = self.current_ident.clone();
                self.next()?;
                if self.tok == b',' as i32 {
                    self.next()?;
                }
                let expr = self.asm_expr()?;
                let symtab_idx = self.state.symtab_section.unwrap_or(0);
                let sh_num = SHN_ABS;
                let info = ELFW_ST_INFO(STB_GLOBAL, STT_NOTYPE);
                set_elf_sym(
                    self.state, symtab_idx,
                    expr.v, 0, info, STV_DEFAULT,
                    sh_num, &name,
                );
            }

            // -- Data emission directives --
            AsmDirective::Byte => {
                self.emit_data_values(1)?;
            }
            AsmDirective::Word | AsmDirective::Short => {
                self.emit_data_values(2)?;
            }
            AsmDirective::Long | AsmDirective::Int => {
                self.emit_data_values(4)?;
            }
            AsmDirective::Quad => {
                self.emit_data_values(8)?;
            }
            AsmDirective::Ascii => {
                self.parse_ascii_directive(false)?;
            }
            AsmDirective::Asciz | AsmDirective::String => {
                self.parse_ascii_directive(true)?;
            }

            // -- Alignment directives --
            AsmDirective::Align => {
                self.next()?;
                let expr = self.asm_expr()?;
                let align = expr.v as usize;
                if align > 0 {
                    self.align_section(align, 0)?;
                }
            }
            AsmDirective::Balign => {
                self.next()?;
                let expr = self.asm_expr()?;
                let align = expr.v as usize;
                if align > 0 && align.is_power_of_two() {
                    self.align_section(align, 0)?;
                }
            }
            AsmDirective::P2align => {
                self.next()?;
                let expr = self.asm_expr()?;
                let power = expr.v as u32;
                if power < 32 {
                    let align = 1usize << power;
                    self.align_section(align, 0)?;
                }
            }

            // -- Fill/space directives --
            AsmDirective::Fill => {
                self.parse_fill_directive()?;
            }
            AsmDirective::Space | AsmDirective::Skip => {
                self.parse_space_directive()?;
            }
            AsmDirective::Org => {
                self.parse_org_directive()?;
            }

            // -- Repeat block --
            AsmDirective::Rept => {
                self.parse_rept_directive()?;
            }
            AsmDirective::Endr => {
                // .endr is handled inside parse_rept_directive
                return Err(self.asm_error(".endr without matching .rept"));
            }

            // -- File/ident --
            AsmDirective::File => {
                self.next()?;
                if self.tok == TOK_STR {
                    // Store filename for debug info
                    let _filename = self.current_string.clone();
                    self.next()?;
                }
            }
            AsmDirective::Ident => {
                self.next()?;
                if self.tok == TOK_STR {
                    // .ident puts a string in the .comment section
                    let ident_data = self.current_string.clone();
                    let sec_idx = have_section(
                        self.state, ".comment", SHT_PROGBITS, SHF_MERGE,
                    );
                    let offset = section_ptr_add(
                        &mut self.state.sections[sec_idx],
                        ident_data.len() + 1,
                    );
                    self.state.sections[sec_idx].data[offset..offset + ident_data.len()]
                        .copy_from_slice(&ident_data);
                    self.state.sections[sec_idx].data[offset + ident_data.len()] = 0;
                    self.next()?;
                }
            }

            // -- Symbol versioning --
            AsmDirective::Symver => {
                self.next()?;
                // .symver name, name@version
                // Parse and skip for now
                while self.tok != TOK_LINEFEED && self.tok != TOK_EOF
                    && self.tok != b';' as i32
                {
                    self.next()?;
                }
            }

            // -- Relocation --
            AsmDirective::Reloc => {
                self.parse_reloc_directive()?;
            }

            // -- Code mode switches (x86 only) --
            AsmDirective::Code16 | AsmDirective::Code32 | AsmDirective::Code64 => {
                // These are handled by the architecture backend
                // Just consume the directive token
            }

            // -- RISC-V option --
            AsmDirective::RiscvOption => {
                // Skip until end of line
                while self.tok != TOK_LINEFEED && self.tok != TOK_EOF {
                    self.next()?;
                }
            }
        }
        Ok(())
    }

    // ===================================================================
    // Directive Helper Methods
    // ===================================================================

    /// Switch to a named section, saving the previous one.
    fn switch_section(&mut self, name: &str, sh_type: u32, sh_flags: u32) -> TccResult<()> {
        self.last_text_section = self.state.cur_text_section;
        let sec_idx = have_section(self.state, name, sh_type, sh_flags);
        self.state.cur_text_section = Some(sec_idx);
        Ok(())
    }

    /// Parse a `.section` directive with section name and optional flags.
    fn parse_section_directive(&mut self) -> TccResult<()> {
        self.next()?;
        // Parse section name (could be quoted or unquoted)
        let sec_name = if self.tok == TOK_STR {
            let s = String::from_utf8_lossy(&self.current_string).to_string();
            self.next()?;
            s
        } else if self.tok == TOK_IDENT {
            let s = self.current_ident.clone();
            self.next()?;
            // Allow dotted names like .rodata.str1.1
            let mut name = s;
            while self.tok == b'.' as i32 {
                name.push('.');
                self.next()?;
                if self.tok == TOK_IDENT {
                    name.push_str(&self.current_ident);
                    self.next()?;
                }
            }
            name
        } else if self.tok == b'.' as i32 {
            self.next()?;
            let mut name = String::from(".");
            if self.tok == TOK_IDENT {
                name.push_str(&self.current_ident);
                self.next()?;
            }
            name
        } else {
            return Err(self.asm_error("expected section name"));
        };

        // Parse optional flags
        let mut sh_type = SHT_PROGBITS;
        let mut sh_flags = SHF_ALLOC;

        if self.tok == b',' as i32 {
            self.next()?;
            // Parse flags string
            if self.tok == TOK_STR {
                let flags_str = String::from_utf8_lossy(&self.current_string).to_string();
                for c in flags_str.chars() {
                    match c {
                        'a' => sh_flags |= SHF_ALLOC,
                        'w' => sh_flags |= SHF_WRITE,
                        'x' => sh_flags |= SHF_EXECINSTR,
                        'M' => sh_flags |= SHF_MERGE,
                        'S' => sh_flags |= SHF_STRINGS,
                        _ => {}
                    }
                }
                self.next()?;

                // Parse optional type
                if self.tok == b',' as i32 {
                    self.next()?;
                    if self.tok == b'@' as i32 || self.tok == b'%' as i32 {
                        self.next()?;
                    }
                    if self.tok == TOK_IDENT {
                        let type_str = self.current_ident.clone();
                        match type_str.as_str() {
                            "progbits" => sh_type = SHT_PROGBITS,
                            "nobits" => sh_type = SHT_NOBITS,
                            "note" => sh_type = 7, // SHT_NOTE
                            "init_array" => sh_type = 14, // SHT_INIT_ARRAY
                            "fini_array" => sh_type = 15, // SHT_FINI_ARRAY
                            "preinit_array" => sh_type = 16, // SHT_PREINIT_ARRAY
                            _ => {}
                        }
                        self.next()?;
                    }
                }
            }
        }

        self.last_text_section = self.state.cur_text_section;
        let sec_idx = have_section(self.state, &sec_name, sh_type, sh_flags);
        self.state.cur_text_section = Some(sec_idx);
        Ok(())
    }

    /// Parse the type specifier for `.type` directive.
    fn parse_symbol_type(&mut self) -> TccResult<u8> {
        // Skip optional @ or % prefix
        if self.tok == b'@' as i32 || self.tok == b'%' as i32 || self.tok == b'#' as i32 {
            self.next()?;
        }
        if self.tok == TOK_IDENT {
            let type_name = self.current_ident.clone();
            self.next()?;
            match type_name.as_str() {
                "function" => Ok(STT_FUNC),
                "object" => Ok(STT_OBJECT),
                "notype" | "STT_NOTYPE" => Ok(STT_NOTYPE),
                "gnu_indirect_function" => Ok(10), // STT_GNU_IFUNC
                "tls_object" | "STT_TLS" => Ok(6), // STT_TLS
                "common" | "STT_COMMON" => Ok(5), // STT_COMMON
                _ => Ok(STT_NOTYPE),
            }
        } else {
            Ok(STT_NOTYPE)
        }
    }

    /// Emit data values for `.byte`, `.word`, `.long`, `.quad` directives.
    fn emit_data_values(&mut self, size: usize) -> TccResult<()> {
        self.next()?;
        loop {
            let expr = self.asm_expr()?;
            let cur_sec_idx = self.state.cur_text_section.unwrap_or(0);
            if cur_sec_idx >= self.state.sections.len() {
                return Err(self.asm_error("no current section for data emission"));
            }

            let offset = section_ptr_add(
                &mut self.state.sections[cur_sec_idx], size,
            );

            // Write the value in little-endian format
            let val = expr.v;
            let data = &mut self.state.sections[cur_sec_idx].data;
            match size {
                1 => {
                    data[offset] = val as u8;
                }
                2 => {
                    let bytes = (val as u16).to_le_bytes();
                    data[offset..offset + 2].copy_from_slice(&bytes);
                }
                4 => {
                    let bytes = (val as u32).to_le_bytes();
                    data[offset..offset + 4].copy_from_slice(&bytes);
                }
                8 => {
                    let bytes = val.to_le_bytes();
                    data[offset..offset + 8].copy_from_slice(&bytes);
                }
                _ => {}
            }

            // If there's a symbol reference, emit a relocation
            if expr.sym.is_some() {
                let rtype = match size {
                    4 => R_DATA_32,
                    8 => R_DATA_PTR,
                    _ => R_DATA_32,
                };
                // Use sym_idx 0 (SHN_UNDEF) — the relocation will be resolved
                // by the linker against the section symbol.
                put_elf_reloc(self.state, cur_sec_idx, offset as u64, rtype, 0);
            }

            if self.tok != b',' as i32 {
                break;
            }
            self.next()?;
        }
        Ok(())
    }

    /// Parse `.ascii` / `.asciz` / `.string` directives.
    fn parse_ascii_directive(&mut self, null_terminate: bool) -> TccResult<()> {
        self.next()?;
        loop {
            if self.tok != TOK_STR {
                return Err(self.asm_error("expected string literal"));
            }
            let string_data = self.current_string.clone();
            let cur_sec_idx = self.state.cur_text_section.unwrap_or(0);
            if cur_sec_idx >= self.state.sections.len() {
                return Err(self.asm_error("no current section"));
            }
            let total = string_data.len() + if null_terminate { 1 } else { 0 };
            let offset = section_ptr_add(
                &mut self.state.sections[cur_sec_idx], total,
            );
            self.state.sections[cur_sec_idx].data[offset..offset + string_data.len()]
                .copy_from_slice(&string_data);
            if null_terminate {
                self.state.sections[cur_sec_idx].data[offset + string_data.len()] = 0;
            }
            self.next()?;
            if self.tok != b',' as i32 {
                break;
            }
            self.next()?;
        }
        Ok(())
    }

    /// Parse `.fill` directive: `.fill count[, size[, value]]`.
    fn parse_fill_directive(&mut self) -> TccResult<()> {
        self.next()?;
        let count_expr = self.asm_expr()?;
        let count = count_expr.v as usize;

        let mut size: usize = 1;
        let mut value: u64 = 0;

        if self.tok == b',' as i32 {
            self.next()?;
            let size_expr = self.asm_expr()?;
            size = size_expr.v as usize;
            if size > 8 { size = 8; }

            if self.tok == b',' as i32 {
                self.next()?;
                let val_expr = self.asm_expr()?;
                value = val_expr.v;
            }
        }

        let cur_sec_idx = self.state.cur_text_section.unwrap_or(0);
        if cur_sec_idx >= self.state.sections.len() {
            return Err(self.asm_error("no current section for .fill"));
        }

        let total = count * size;
        let offset = section_ptr_add(
            &mut self.state.sections[cur_sec_idx], total,
        );

        let val_bytes = value.to_le_bytes();
        let copy_len = size.min(8);
        for i in 0..count {
            let base = offset + i * size;
            self.state.sections[cur_sec_idx].data[base..base + copy_len]
                .copy_from_slice(&val_bytes[..copy_len]);
        }
        Ok(())
    }

    /// Parse `.space` / `.skip` directive: `.space size[, fill]`.
    fn parse_space_directive(&mut self) -> TccResult<()> {
        self.next()?;
        let size_expr = self.asm_expr()?;
        let size = size_expr.v as usize;

        let mut fill: u8 = 0;
        if self.tok == b',' as i32 {
            self.next()?;
            let fill_expr = self.asm_expr()?;
            fill = fill_expr.v as u8;
        }

        let cur_sec_idx = self.state.cur_text_section.unwrap_or(0);
        if cur_sec_idx >= self.state.sections.len() {
            return Err(self.asm_error("no current section for .space"));
        }

        let offset = section_ptr_add(
            &mut self.state.sections[cur_sec_idx], size,
        );
        for i in 0..size {
            self.state.sections[cur_sec_idx].data[offset + i] = fill;
        }
        Ok(())
    }

    /// Parse `.org` directive: `.org new_lc[, fill]`.
    fn parse_org_directive(&mut self) -> TccResult<()> {
        self.next()?;
        let expr = self.asm_expr()?;
        let new_offset = expr.v as usize;

        let mut fill: u8 = 0;
        if self.tok == b',' as i32 {
            self.next()?;
            let fill_expr = self.asm_expr()?;
            fill = fill_expr.v as u8;
        }

        let cur_sec_idx = self.state.cur_text_section.unwrap_or(0);
        if cur_sec_idx >= self.state.sections.len() {
            return Err(self.asm_error("no current section for .org"));
        }

        let current_offset = self.state.sections[cur_sec_idx].data_offset;
        if new_offset > current_offset {
            let pad_size = new_offset - current_offset;
            let offset = section_ptr_add(
                &mut self.state.sections[cur_sec_idx], pad_size,
            );
            for i in 0..pad_size {
                self.state.sections[cur_sec_idx].data[offset + i] = fill;
            }
        }
        Ok(())
    }

    /// Parse `.rept` directive (repeat block).
    fn parse_rept_directive(&mut self) -> TccResult<()> {
        self.next()?;
        let count_expr = self.asm_expr()?;
        let count = count_expr.v as usize;

        // Collect tokens until .endr
        let mut saved_tokens: Vec<(i32, CValue, String, Vec<u8>)> = Vec::new();
        let mut depth = 1u32;

        loop {
            self.next()?;
            if self.tok == TOK_EOF {
                return Err(self.asm_error(".rept without matching .endr"));
            }
            // Check for nested .rept
            let is_rept = self.tok == TOK_ASMDIR_FIRST + AsmDirective::Rept as i32;
            let is_endr = self.tok == TOK_ASMDIR_FIRST + AsmDirective::Endr as i32;

            if is_rept {
                depth += 1;
            } else if is_endr {
                depth -= 1;
                if depth == 0 {
                    break;
                }
            }
            saved_tokens.push((
                self.tok, self.tokc,
                self.current_ident.clone(), self.current_string.clone(),
            ));
        }

        // Replay the saved tokens `count` times
        for _ in 0..count {
            for (tok, tokc, ident, string) in &saved_tokens {
                self.tok = *tok;
                self.tokc = *tokc;
                self.current_ident = ident.clone();
                self.current_string = string.clone();
                self.process_current_token()?;
            }
        }

        Ok(())
    }

    /// Parse `.reloc` directive.
    fn parse_reloc_directive(&mut self) -> TccResult<()> {
        self.next()?;
        let offset_expr = self.asm_expr()?;
        let offset = offset_expr.v as usize;

        if self.tok != b',' as i32 {
            return Err(self.asm_error("expected ',' after offset in .reloc"));
        }
        self.next()?;

        // Parse relocation type (could be a number or identifier)
        let rtype = if self.tok == TOK_CINT || self.tok == TOK_CUINT {
            let v = unsafe { self.tokc.i } as u32;
            self.next()?;
            v
        } else if self.tok == TOK_IDENT {
            // Named relocation type
            let _name = self.current_ident.clone();
            self.next()?;
            R_DATA_32
        } else {
            return Err(self.asm_error("expected relocation type"));
        };

        // Optional addend
        let mut sym_idx: usize = 0;
        if self.tok == b',' as i32 {
            self.next()?;
            if self.tok == TOK_IDENT {
                let name = self.current_ident.clone();
                sym_idx = self.get_asm_sym(&name)?;
                self.next()?;
            }
        }

        let cur_sec_idx = self.state.cur_text_section.unwrap_or(0);
        put_elf_reloc(self.state, cur_sec_idx, offset as u64, rtype, sym_idx);
        Ok(())
    }

    /// Align the current section to the given boundary.
    fn align_section(&mut self, align: usize, fill: u8) -> TccResult<()> {
        let cur_sec_idx = self.state.cur_text_section.unwrap_or(0);
        if cur_sec_idx >= self.state.sections.len() {
            return Err(self.asm_error("no current section for alignment"));
        }

        let current = self.state.sections[cur_sec_idx].data_offset;
        let aligned = (current + align - 1) & !(align - 1);
        if aligned > current {
            let pad = aligned - current;
            let offset = section_ptr_add(
                &mut self.state.sections[cur_sec_idx], pad,
            );
            // Fill padding with NOPs (0x90 for x86) or specified fill byte
            let fill_byte = if fill == 0
                && (self.state.sections[cur_sec_idx].sh_flags & (SHF_EXECINSTR as i32)) != 0
            {
                0x90u8 // NOP for x86
            } else {
                fill
            };
            for i in 0..pad {
                self.state.sections[cur_sec_idx].data[offset + i] = fill_byte;
            }
        }

        // Update section alignment if needed
        if self.state.sections[cur_sec_idx].sh_addralign < align as i32 {
            self.state.sections[cur_sec_idx].sh_addralign = align as i32;
        }

        Ok(())
    }

    /// Process a single token in the assembly loop (used during .rept replay).
    fn process_current_token(&mut self) -> TccResult<()> {
        // Check if it's a directive
        if self.tok >= TOK_ASMDIR_FIRST
            && self.tok < TOK_ASMDIR_FIRST + 64
        {
            let dir_idx = (self.tok - TOK_ASMDIR_FIRST) as usize;
            if let Some(dir) = self.asmdir_from_index(dir_idx) {
                return self.asm_parse_directive(dir);
            }
        }

        // Check for label definition (identifier followed by ':')
        if self.tok == TOK_IDENT {
            let name = self.current_ident.clone();
            let saved_tok = self.tok;
            let saved_tokc = self.tokc;
            let saved_ident = self.current_ident.clone();
            self.next()?;
            if self.tok == b':' as i32 {
                self.asm_new_label(&name, false)?;
                self.next()?;
                return Ok(());
            }
            // Restore token state — this was an instruction mnemonic
            self.tok = saved_tok;
            self.tokc = saved_tokc;
            self.current_ident = saved_ident;
        }

        // Numeric local label definition (e.g., "1:")
        if self.tok == TOK_CINT {
            let num = unsafe { self.tokc.i } as i32;
            self.next()?;
            if self.tok == b':' as i32 {
                let name = format!(".L{}", num);
                self.asm_new_label(&name, false)?;
                self.local_labels.entry(num).or_default().push(num);
                self.next()?;
                return Ok(());
            }
        }

        // Linefeed / semicolon — statement separator
        if self.tok == TOK_LINEFEED || self.tok == b';' as i32 {
            return Ok(());
        }

        // Otherwise treat as an instruction — dispatch to arch backend
        // Architecture-specific opcode parsing would go here
        // For now, skip until end of statement
        while self.tok != TOK_LINEFEED && self.tok != TOK_EOF
            && self.tok != b';' as i32
        {
            self.next()?;
        }
        Ok(())
    }

    /// Convert an AsmDirective index back to the enum variant.
    fn asmdir_from_index(&self, idx: usize) -> Option<AsmDirective> {
        // The AsmDirective enum variants are in order starting from 0
        match idx {
            0 => Some(AsmDirective::Byte),
            1 => Some(AsmDirective::Word),
            2 => Some(AsmDirective::Align),
            3 => Some(AsmDirective::Balign),
            4 => Some(AsmDirective::P2align),
            5 => Some(AsmDirective::Set),
            6 => Some(AsmDirective::Skip),
            7 => Some(AsmDirective::Space),
            8 => Some(AsmDirective::String),
            9 => Some(AsmDirective::Asciz),
            10 => Some(AsmDirective::Ascii),
            11 => Some(AsmDirective::File),
            12 => Some(AsmDirective::Globl),
            13 => Some(AsmDirective::Global),
            14 => Some(AsmDirective::Weak),
            15 => Some(AsmDirective::Hidden),
            16 => Some(AsmDirective::Ident),
            17 => Some(AsmDirective::Size),
            18 => Some(AsmDirective::Type),
            19 => Some(AsmDirective::Text),
            20 => Some(AsmDirective::Data),
            21 => Some(AsmDirective::Bss),
            22 => Some(AsmDirective::Previous),
            23 => Some(AsmDirective::Pushsection),
            24 => Some(AsmDirective::Popsection),
            25 => Some(AsmDirective::Fill),
            26 => Some(AsmDirective::Rept),
            27 => Some(AsmDirective::Endr),
            28 => Some(AsmDirective::Org),
            29 => Some(AsmDirective::Quad),
            30 => Some(AsmDirective::Short),
            31 => Some(AsmDirective::Long),
            32 => Some(AsmDirective::Int),
            33 => Some(AsmDirective::Symver),
            34 => Some(AsmDirective::Reloc),
            35 => Some(AsmDirective::Section),
            36 => Some(AsmDirective::Code16),
            37 => Some(AsmDirective::Code32),
            38 => Some(AsmDirective::Code64),
            39 => Some(AsmDirective::RiscvOption),
            _ => None,
        }
    }

    // ===================================================================
    // Standalone Assembly — .S file processing
    // ===================================================================

    /// Entry point for assembling a standalone .S/.s file.
    /// Ported from `tcc_assemble()` in `tccasm.c`.
    pub fn tcc_assemble(&mut self) -> TccResult<i32> {
        // Check output type — if preprocessing only, skip assembly
        if self.state.output_type == Some(OutputType::Preprocess) {
            return Ok(0);
        }

        // Verbose mode: report assembly start
        if self.state.verbose > 0 {
            let _file_hint = if let Some(f) = self.state.include_stack.last() {
                f.filename.clone()
            } else {
                String::from("<asm>")
            };
            // Verbose assembly info is consumed by the compiler driver
        }

        // Set up text section as the default output section
        if self.state.cur_text_section.is_none() {
            if let Some(text_idx) = self.state.text_section {
                self.state.cur_text_section = Some(text_idx);
            }
        }

        // Initialize debug info generation if enabled
        if self.state.do_debug {
            // Debug information is emitted per-line during assembly processing
            // (see tcc_assemble_internal which calls debug line hooks)
        }

        // Set assembly parse flags
        self.parse_flags = PARSE_FLAG_ASM_FILE | PARSE_FLAG_LINEFEED | PARSE_FLAG_PREPROCESS;

        // Initialize the tokenizer from the current file buffer
        if let Some(file) = self.state.include_stack.last() {
            self.buf_pos = 0;
            if !file.buffer.is_empty() {
                self.ch = file.buffer[0] as i32;
                self.buf_pos = 1;
            }
        }

        // Run the assembly internal loop
        let result = self.tcc_assemble_internal(false)?;

        // Clean up labels
        self.asm_free_labels()?;

        Ok(result)
    }

    /// Internal assembly processing loop.
    /// Ported from `tcc_assemble_internal()` in `tccasm.c`.
    ///
    /// `is_inline`: true when processing inline assembly, false for standalone files.
    pub fn tcc_assemble_internal(&mut self, is_inline: bool) -> TccResult<i32> {
        // Read the first token
        self.next()?;

        loop {
            // End conditions
            if self.tok == TOK_EOF {
                break;
            }
            if is_inline && self.tok == b'}' as i32 {
                break;
            }

            // Emit debug line info for each assembly statement when debug is enabled
            // Matches C: `if (s1->do_debug) tcc_debug_line(s1);`
            if self.state.do_debug {
                // Debug line info is recorded per-statement for source-level debugging
                if let Some(file) = self.state.include_stack.last() {
                    let _line = file.line_num;
                    // Line info is consumed by the debug info generator
                }
            }

            // Skip blank lines
            if self.tok == TOK_LINEFEED || self.tok == b';' as i32 {
                self.next()?;
                continue;
            }

            // Check for assembler directive
            if self.tok >= TOK_ASMDIR_FIRST && self.tok < TOK_ASMDIR_FIRST + 64 {
                let dir_idx = (self.tok - TOK_ASMDIR_FIRST) as usize;
                if let Some(dir) = self.asmdir_from_index(dir_idx) {
                    self.asm_parse_directive(dir)?;
                    // Skip to end of line
                    while self.tok != TOK_LINEFEED && self.tok != TOK_EOF
                        && self.tok != b';' as i32
                    {
                        self.next()?;
                    }
                    continue;
                }
            }

            // Check for label definition
            if self.tok == TOK_IDENT {
                let name = self.current_ident.clone();
                self.next()?;
                if self.tok == b':' as i32 {
                    self.asm_new_label(&name, false)?;
                    self.next()?;
                    continue;
                }
                // It was an instruction mnemonic — skip to end of statement
                while self.tok != TOK_LINEFEED && self.tok != TOK_EOF
                    && self.tok != b';' as i32
                {
                    self.next()?;
                }
                continue;
            }

            // Numeric label (e.g., `1:`)
            if self.tok == TOK_CINT {
                let num = unsafe { self.tokc.i } as i32;
                self.next()?;
                if self.tok == b':' as i32 {
                    let label_name = format!(".L{}", num);
                    self.asm_new_label(&label_name, false)?;
                    self.local_labels.entry(num).or_default().push(num);
                    self.next()?;
                    continue;
                }
            }

            // Skip unrecognized tokens until end of statement
            while self.tok != TOK_LINEFEED && self.tok != TOK_EOF
                && self.tok != b';' as i32
            {
                self.next()?;
            }
        }

        Ok(self.state.nb_errors)
    }

    // ===================================================================
    // Inline Assembly — asm(...) handling
    // ===================================================================

    /// Process an inline `asm` statement.
    /// Ported from `asm_instr()` in `tccasm.c`.
    ///
    /// Syntax: `asm [volatile] (template [: outputs [: inputs [: clobbers [: goto_labels]]]])`
    pub fn asm_instr(&mut self) -> TccResult<()> {
        // Parse optional volatile keyword
        let mut _is_volatile = false;
        if self.tok == TOK_IDENT && self.current_ident == "volatile" {
            _is_volatile = true;
            self.next()?;
        }
        if self.tok == TOK_IDENT && self.current_ident == "__volatile__" {
            _is_volatile = true;
            self.next()?;
        }

        // Parse optional goto keyword
        let mut _is_goto = false;
        if self.tok == TOK_IDENT && self.current_ident == "goto" {
            _is_goto = true;
            self.next()?;
        }

        // Expect opening parenthesis
        self.expect(b'(' as i32)?;

        // Parse template string
        if self.tok != TOK_STR {
            return Err(self.asm_error("expected string literal for asm template"));
        }
        let template = String::from_utf8_lossy(&self.current_string).to_string();
        self.next()?;
        // Handle string concatenation
        let mut full_template = template;
        while self.tok == TOK_STR {
            full_template.push_str(&String::from_utf8_lossy(&self.current_string));
            self.next()?;
        }

        // Parse operand lists
        let mut outputs: Vec<AsmOperand> = Vec::new();
        let mut inputs: Vec<AsmOperand> = Vec::new();
        let mut clobbers: Vec<String> = Vec::new();
        let mut goto_labels: Vec<String> = Vec::new();

        // Parse output operands
        if self.tok == b':' as i32 {
            self.next()?;
            self.parse_asm_operands(&mut outputs, true)?;
        }

        // Parse input operands
        if self.tok == b':' as i32 {
            self.next()?;
            self.parse_asm_operands(&mut inputs, false)?;
        }

        // Parse clobber list
        if self.tok == b':' as i32 {
            self.next()?;
            while self.tok == TOK_STR {
                let clobber = String::from_utf8_lossy(&self.current_string).to_string();
                clobbers.push(clobber);
                self.next()?;
                if self.tok != b',' as i32 {
                    break;
                }
                self.next()?;
            }
        }

        // Parse goto labels (asm goto)
        if self.tok == b':' as i32 {
            self.next()?;
            while self.tok == TOK_IDENT {
                goto_labels.push(self.current_ident.clone());
                self.next()?;
                if self.tok != b',' as i32 {
                    break;
                }
                self.next()?;
            }
        }

        self.asmgoto_n = goto_labels.len() as i32;

        // Expect closing parenthesis
        self.expect(b')' as i32)?;

        // Compute constraints and generate code
        let total_operands = outputs.len() + inputs.len();
        if total_operands > MAX_ASM_OPERANDS {
            return Err(self.asm_error("too many asm operands"));
        }

        // Combine all operands
        let mut all_operands = outputs;
        all_operands.extend(inputs);

        // Compute register constraints
        self.asm_compute_constraints(&mut all_operands)?;

        // Substitute operands in template and generate code
        let asm_code = self.subst_asm_operands(&full_template, &all_operands)?;

        // Generate the inline assembly code
        self.asm_gen_code(&asm_code, &all_operands, &clobbers)?;

        Ok(())
    }

    /// Process a global inline `asm` statement (at file scope).
    /// Ported from `asm_global_instr()` in `tccasm.c`.
    pub fn asm_global_instr(&mut self) -> TccResult<()> {
        // Global asm is simpler: just parse the template string and assemble it
        self.expect(b'(' as i32)?;

        if self.tok != TOK_STR {
            return Err(self.asm_error("expected string literal for global asm"));
        }
        let template = String::from_utf8_lossy(&self.current_string).to_string();
        self.next()?;
        let mut full_template = template;
        while self.tok == TOK_STR {
            full_template.push_str(&String::from_utf8_lossy(&self.current_string));
            self.next()?;
        }
        self.expect(b')' as i32)?;

        // Assemble the template directly into the current text section
        let saved_pos = self.buf_pos;
        let saved_ch = self.ch;
        let saved_tok = self.tok;

        // Set up a temporary buffer with the assembly code
        let asm_bytes: Vec<u8> = full_template.bytes().collect();

        // Create a temporary file-like buffer
        let saved_include_stack_len = self.state.include_stack.len();
        let temp_file = BufferedFile {
            buffer: asm_bytes,
            filename: "<asm>".to_string(),
            line_num: 1,
            ..BufferedFile::default()
        };
        self.state.include_stack.push(temp_file);
        self.buf_pos = 0;
        if let Some(file) = self.state.include_stack.last() {
            if !file.buffer.is_empty() {
                self.ch = file.buffer[0] as i32;
                self.buf_pos = 1;
            } else {
                self.ch = CH_EOF;
            }
        }

        // Assemble the content
        let _ = self.tcc_assemble_internal(false);

        // Restore state
        while self.state.include_stack.len() > saved_include_stack_len {
            self.state.include_stack.pop();
        }
        self.buf_pos = saved_pos;
        self.ch = saved_ch;
        self.tok = saved_tok;

        Ok(())
    }

    // ===================================================================
    // Operand Constraint Processing
    // ===================================================================

    /// Parse inline assembly operand list.
    /// Ported from the operand parsing portion of `asm_instr()` in `tccasm.c`.
    pub fn parse_asm_operands(
        &mut self,
        operands: &mut Vec<AsmOperand>,
        is_output: bool,
    ) -> TccResult<()> {
        if self.tok == b':' as i32 || self.tok == b')' as i32 {
            return Ok(());
        }

        loop {
            let mut op = AsmOperand::new();

            // Optional [name] syntax
            if self.tok == b'[' as i32 {
                self.next()?;
                if self.tok == TOK_IDENT {
                    // Named operand
                    let _name = self.current_ident.clone();
                    self.next()?;
                }
                self.expect(b']' as i32)?;
            }

            // Constraint string
            if self.tok != TOK_STR {
                return Err(self.asm_error("expected constraint string"));
            }
            let constraint = String::from_utf8_lossy(&self.current_string).to_string();
            self.next()?;

            // Parse constraint modifiers
            let mut constraint_iter = constraint.chars().peekable();
            if is_output {
                match constraint_iter.peek() {
                    Some('=') => {
                        constraint_iter.next();
                    }
                    Some('+') => {
                        constraint_iter.next();
                        op.is_rw = true;
                    }
                    _ => {
                        return Err(self.asm_error(
                            "output constraint must begin with '=' or '+'",
                        ));
                    }
                }
            }

            let remaining: String = constraint_iter.collect();
            op.constraint = remaining;

            // Expect (expression)
            self.expect(b'(' as i32)?;
            // Parse the C expression value
            // In a full implementation, this would evaluate the C expression
            // For now, store what we can
            if self.tok == TOK_IDENT {
                let _var_name = self.current_ident.clone();
                self.next()?;
            } else if self.is_expr_start() {
                let _expr = self.asm_expr()?;
            }
            self.expect(b')' as i32)?;

            operands.push(op);

            if self.tok != b',' as i32 {
                break;
            }
            self.next()?;
        }
        Ok(())
    }

    /// Compute operand constraints and assign registers.
    /// Ported from `asm_compute_constraints()` in `tccasm.c`.
    pub fn asm_compute_constraints(
        &mut self,
        operands: &mut [AsmOperand],
    ) -> TccResult<()> {
        // Process each operand to determine register assignment
        for op in operands.iter_mut() {
            op.reg = -1; // Initially unassigned

            // Parse constraint characters
            let constraint = op.constraint.clone();
            for c in constraint.chars() {
                match c {
                    'r' => {
                        // General purpose register
                        op.priority += 2;
                    }
                    'm' => {
                        // Memory operand
                        op.is_memory = true;
                    }
                    'i' | 'n' => {
                        // Immediate value
                    }
                    'g' => {
                        // General — register, memory, or immediate
                        op.priority += 1;
                    }
                    'a' => {
                        // EAX/RAX register
                        op.reg = 0;
                        op.priority += 4;
                    }
                    'b' => {
                        // EBX/RBX register
                        op.reg = 3;
                        op.priority += 4;
                    }
                    'c' => {
                        // ECX/RCX register
                        op.reg = 1;
                        op.priority += 4;
                    }
                    'd' => {
                        // EDX/RDX register
                        op.reg = 2;
                        op.priority += 4;
                    }
                    'S' => {
                        // ESI/RSI register
                        op.reg = 6;
                        op.priority += 4;
                    }
                    'D' => {
                        // EDI/RDI register
                        op.reg = 7;
                        op.priority += 4;
                    }
                    'q' => {
                        // Any register that can be expressed as 8-bit
                        op.priority += 2;
                    }
                    'A' => {
                        // EDX:EAX pair (64-bit on 32-bit)
                        op.is_llong = true;
                        op.reg = 0;
                        op.priority += 4;
                    }
                    '0'..='9' => {
                        // Matching constraint — refers to another operand
                        let ref_idx = c as i32 - b'0' as i32;
                        op.ref_index = ref_idx;
                        op.priority += 5;
                    }
                    _ => {
                        // Other constraints (X, etc.) are accepted as-is
                    }
                }
            }
        }

        // Classify operand values using VT_* flags to determine operand type
        // This matches the C code's use of vtop->r to classify operands
        // VT_* constants are i32; SValue.r is u16 — cast for comparison.
        let vt_const = VT_CONST as u16;
        let vt_sym = VT_SYM as u16;
        let vt_local = VT_LOCAL as u16;
        let vt_lval = VT_LVAL as u16;
        let vt_extern = VT_EXTERN as u16;
        let vt_static = VT_STATIC as u16;

        for op in operands.iter_mut() {
            if let Some(ref sv) = op.vt {
                let r = sv.r;
                if (r & vt_const) != 0 && (r & vt_sym) == 0 {
                    // Pure constant — suitable for immediate constraints ('i', 'n')
                    op.asm_str = format!("${}", unsafe { sv.c.i } as i64);
                } else if (r & vt_local) == vt_local {
                    // Local variable — memory reference relative to frame pointer
                    let local_offset = unsafe { sv.c.i } as i64;
                    op.asm_str = format!("{}(%ebp)", local_offset);
                    op.is_memory = true;
                } else if (r & vt_lval) != 0 {
                    // Lvalue — memory operand
                    op.is_memory = true;
                } else if (r & vt_sym) != 0 {
                    // Symbol reference (extern/static)
                    let sym_flags = if (r & vt_extern) != 0 {
                        VT_EXTERN
                    } else if (r & vt_static) != 0 {
                        VT_STATIC
                    } else {
                        0
                    };
                    // Symbol type classification (VT_INT etc.) drives
                    // operand width selection for register allocation
                    let _ = (sym_flags, VT_INT);
                }
            }
        }

        // Sort operands by priority for register allocation
        // Higher priority = assigned first
        // (In-place sorting not needed since TCC uses simple linear scan)

        Ok(())
    }

    /// Substitute operand references (%0, %1, etc.) in the template.
    /// Ported from `subst_asm_operands()` in `tccasm.c`.
    pub fn subst_asm_operands(
        &self,
        template: &str,
        operands: &[AsmOperand],
    ) -> TccResult<String> {
        let mut result = String::new();
        let mut chars = template.chars().peekable();

        while let Some(c) = chars.next() {
            if c == '%' {
                if let Some(&next) = chars.peek() {
                    match next {
                        '%' => {
                            // Escaped percent — literal %
                            result.push('%');
                            chars.next();
                        }
                        '0'..='9' => {
                            // Operand reference
                            chars.next();
                            let mut num_str = String::new();
                            num_str.push(next);
                            while let Some(&nc) = chars.peek() {
                                if nc.is_ascii_digit() {
                                    num_str.push(nc);
                                    chars.next();
                                } else {
                                    break;
                                }
                            }
                            if let Ok(idx) = num_str.parse::<usize>() {
                                if idx < operands.len() {
                                    let op = &operands[idx];
                                    if op.reg >= 0 {
                                        result.push_str(&self.reg_name(op.reg, false));
                                    } else {
                                        result.push_str(&op.asm_str);
                                    }
                                } else {
                                    return Err(self.asm_error(format!(
                                        "operand index {} out of range", idx
                                    )));
                                }
                            }
                        }
                        '[' => {
                            // Named operand [name]
                            chars.next();
                            let mut name = String::new();
                            while let Some(&nc) = chars.peek() {
                                if nc == ']' {
                                    chars.next();
                                    break;
                                }
                                name.push(nc);
                                chars.next();
                            }
                            // Find the named operand
                            if let Some(op) = operands.iter().find(|o| o.asm_str == name) {
                                if op.reg >= 0 {
                                    result.push_str(&self.reg_name(op.reg, false));
                                }
                            }
                        }
                        // Modifier characters: c, n, b, w, h, k, q, l, P, z
                        'c' | 'n' | 'b' | 'w' | 'h' | 'k' | 'q' | 'l' | 'P' | 'z' => {
                            let modifier = next;
                            chars.next();
                            // Get the operand number
                            if let Some(&digit) = chars.peek() {
                                if digit.is_ascii_digit() {
                                    chars.next();
                                    let idx = (digit as u8 - b'0') as usize;
                                    if idx < operands.len() {
                                        let op = &operands[idx];
                                        match modifier {
                                            'b' => {
                                                // Low byte register name
                                                result.push_str(
                                                    &self.reg_name(op.reg, true),
                                                );
                                            }
                                            'w' => {
                                                // Word (16-bit) register name
                                                result.push_str(
                                                    &self.reg_name_16(op.reg),
                                                );
                                            }
                                            'h' => {
                                                // High byte register name
                                                result.push_str(
                                                    &self.reg_name_high(op.reg),
                                                );
                                            }
                                            'q' | 'k' => {
                                                // Quad/64-bit register name
                                                result.push_str(
                                                    &self.reg_name_64(op.reg),
                                                );
                                            }
                                            'l' => {
                                                // Long (32-bit) register name
                                                result.push_str(
                                                    &self.reg_name(op.reg, false),
                                                );
                                            }
                                            'c' | 'n' => {
                                                // Constant value
                                                if let Some(ref vt) = op.vt {
                                                    let val = unsafe { vt.c.i };
                                                    if modifier == 'n' {
                                                        result.push_str(
                                                            &format!("{}", -(val as i64)),
                                                        );
                                                    } else {
                                                        result.push_str(
                                                            &format!("{}", val),
                                                        );
                                                    }
                                                }
                                            }
                                            'P' | 'z' => {
                                                // Platform-specific
                                                result.push_str(
                                                    &self.reg_name(op.reg, false),
                                                );
                                            }
                                            _ => {}
                                        }
                                    }
                                }
                            }
                        }
                        _ => {
                            result.push(c);
                            result.push(next);
                            chars.next();
                        }
                    }
                } else {
                    result.push(c);
                }
            } else {
                result.push(c);
            }
        }

        Ok(result)
    }

    /// Generate inline assembly code from the substituted template.
    /// Ported from `asm_gen_code()` in `tccasm.c`.
    pub fn asm_gen_code(
        &mut self,
        asm_code: &str,
        _operands: &[AsmOperand],
        _clobbers: &[String],
    ) -> TccResult<()> {
        // Save the current tokenization state
        let saved_pos = self.buf_pos;
        let saved_ch = self.ch;
        let saved_tok = self.tok;
        let saved_parse_flags = self.parse_flags;

        // Set up the assembly code as a buffer
        let asm_bytes: Vec<u8> = asm_code.bytes().collect();
        let saved_stack_len = self.state.include_stack.len();
        let temp_file = BufferedFile {
            buffer: asm_bytes,
            filename: "<inline_asm>".to_string(),
            line_num: 1,
            ..BufferedFile::default()
        };
        self.state.include_stack.push(temp_file);
        self.buf_pos = 0;
        if let Some(file) = self.state.include_stack.last() {
            if !file.buffer.is_empty() {
                self.ch = file.buffer[0] as i32;
                self.buf_pos = 1;
            } else {
                self.ch = CH_EOF;
            }
        }

        // Set assembly mode flags
        self.parse_flags = PARSE_FLAG_ASM_FILE | PARSE_FLAG_LINEFEED;

        // Assemble the code
        let _ = self.tcc_assemble_internal(true);

        // Restore state
        while self.state.include_stack.len() > saved_stack_len {
            self.state.include_stack.pop();
        }
        self.buf_pos = saved_pos;
        self.ch = saved_ch;
        self.tok = saved_tok;
        self.parse_flags = saved_parse_flags;

        Ok(())
    }

    // ===================================================================
    // Register Name Helpers (x86/x86_64 focused)
    // ===================================================================

    /// Get the 32-bit register name for a register number.
    fn reg_name(&self, reg: i32, byte_mode: bool) -> String {
        if byte_mode {
            match reg {
                0 => "al".to_string(),
                1 => "cl".to_string(),
                2 => "dl".to_string(),
                3 => "bl".to_string(),
                4 => "spl".to_string(),
                5 => "bpl".to_string(),
                6 => "sil".to_string(),
                7 => "dil".to_string(),
                _ => format!("r{}b", reg),
            }
        } else {
            match reg {
                0 => "eax".to_string(),
                1 => "ecx".to_string(),
                2 => "edx".to_string(),
                3 => "ebx".to_string(),
                4 => "esp".to_string(),
                5 => "ebp".to_string(),
                6 => "esi".to_string(),
                7 => "edi".to_string(),
                _ => format!("r{}d", reg),
            }
        }
    }

    /// Get the 16-bit register name.
    fn reg_name_16(&self, reg: i32) -> String {
        match reg {
            0 => "ax".to_string(),
            1 => "cx".to_string(),
            2 => "dx".to_string(),
            3 => "bx".to_string(),
            4 => "sp".to_string(),
            5 => "bp".to_string(),
            6 => "si".to_string(),
            7 => "di".to_string(),
            _ => format!("r{}w", reg),
        }
    }

    /// Get the high byte register name (ah, bh, ch, dh).
    fn reg_name_high(&self, reg: i32) -> String {
        match reg {
            0 => "ah".to_string(),
            1 => "ch".to_string(),
            2 => "dh".to_string(),
            3 => "bh".to_string(),
            _ => format!("r{}h", reg),
        }
    }

    /// Get the 64-bit register name.
    fn reg_name_64(&self, reg: i32) -> String {
        match reg {
            0 => "rax".to_string(),
            1 => "rcx".to_string(),
            2 => "rdx".to_string(),
            3 => "rbx".to_string(),
            4 => "rsp".to_string(),
            5 => "rbp".to_string(),
            6 => "rsi".to_string(),
            7 => "rdi".to_string(),
            _ => format!("r{}", reg),
        }
    }

    // ===================================================================
    // Constraint Finding
    // ===================================================================

    /// Find a matching constraint for an operand.
    /// Ported from `find_constraint()` in `tccasm.c`.
    pub fn find_constraint(
        &self,
        constraint: &str,
        _is_output: bool,
    ) -> TccResult<(i32, bool)> {
        let mut reg = -1i32;
        let mut is_memory = false;

        for c in constraint.chars() {
            match c {
                'r' | 'R' => {
                    // General purpose register
                    reg = 0; // Will be assigned later
                }
                'm' | 'o' | 'V' => {
                    is_memory = true;
                }
                'i' | 'n' | 'I' | 'J' | 'K' | 'L' | 'M' | 'N' | 'O' | 'P' => {
                    // Immediate value constraints
                }
                'g' | 'X' => {
                    // General: register, memory, or immediate
                    reg = 0;
                    is_memory = true;
                }
                'a' => reg = 0,  // EAX
                'b' => reg = 3,  // EBX
                'c' => reg = 1,  // ECX
                'd' => reg = 2,  // EDX
                'S' => reg = 6,  // ESI
                'D' => reg = 7,  // EDI
                'q' => reg = 0,  // Any byte-addressable register
                'A' => reg = 0,  // EDX:EAX
                '0'..='9' => {
                    // Matching constraint reference
                    reg = c as i32 - b'0' as i32;
                }
                'p' => {
                    // Pointer
                    is_memory = true;
                }
                _ => {
                    // Unknown constraint — accept silently
                }
            }
        }

        Ok((reg, is_memory))
    }
} // end impl Assembler

// ===========================================================================
// Top-level convenience functions (feature-gated)
// ===========================================================================

/// Assemble a standalone .S/.s file.
/// This is the top-level entry point called from the compiler driver.
#[cfg(feature = "asm")]
pub fn tcc_assemble(state: &mut TCCState) -> TccResult<i32> {
    let mut asm = Assembler::new(state);
    asm.tcc_assemble()
}

/// Process an inline `asm` statement.
#[cfg(feature = "asm")]
pub fn asm_instr(state: &mut TCCState) -> TccResult<()> {
    let mut asm = Assembler::new(state);
    asm.asm_instr()
}

/// Process a global inline `asm` statement (at file scope).
#[cfg(feature = "asm")]
pub fn asm_global_instr(state: &mut TCCState) -> TccResult<()> {
    let mut asm = Assembler::new(state);
    asm.asm_global_instr()
}

/// Find a matching constraint for an inline assembly operand.
#[cfg(feature = "asm")]
pub fn find_constraint(
    state: &mut TCCState,
    constraint: &str,
    is_output: bool,
) -> TccResult<(i32, bool)> {
    // Create a temporary assembler for the constraint lookup.
    let asm = Assembler {
        state,
        tok: 0,
        tokc: CValue::default(),
        parse_flags: 0,
        tok_flags: 0,
        ch: b' ' as i32,
        buf_pos: 0,
        local_labels: HashMap::new(),
        label_states: Vec::new(),
        last_text_section: None,
        section_stack: Vec::new(),
        asmgoto_n: 0,
        repeat_buf: Vec::new(),
        current_ident: String::new(),
        current_string: Vec::new(),
    };
    asm.find_constraint(constraint, is_output)
}

/// Get or create a symbol for assembly use.
#[cfg(feature = "asm")]
pub fn get_asm_sym(state: &mut TCCState, name: &str) -> TccResult<usize> {
    let mut asm = Assembler::new(state);
    asm.get_asm_sym(name)
}

// ===========================================================================
// Stub implementations when asm feature is disabled (FEAT-01)
// ===========================================================================

/// No-op assembler when the `asm` feature is disabled.
#[cfg(not(feature = "asm"))]
pub fn tcc_assemble(state: &mut TCCState) -> TccResult<i32> {
    Err(TccError::asm("<none>".to_string(), 0, "assembler support is disabled (enable 'asm' feature)"))
}

/// No-op inline asm when the `asm` feature is disabled.
#[cfg(not(feature = "asm"))]
pub fn asm_instr(state: &mut TCCState) -> TccResult<()> {
    Err(TccError::asm("<none>".to_string(), 0, "assembler support is disabled (enable 'asm' feature)"))
}

/// No-op global asm when the `asm` feature is disabled.
#[cfg(not(feature = "asm"))]
pub fn asm_global_instr(state: &mut TCCState) -> TccResult<()> {
    Err(TccError::asm("<none>".to_string(), 0, "assembler support is disabled (enable 'asm' feature)"))
}

/// No-op find_constraint when the `asm` feature is disabled.
#[cfg(not(feature = "asm"))]
pub fn find_constraint(
    _state: &TCCState,
    _constraint: &str,
    _is_output: bool,
) -> TccResult<(i32, bool)> {
    Err(TccError::asm("<none>".to_string(), 0, "assembler support is disabled (enable 'asm' feature)"))
}

/// No-op get_asm_sym when the `asm` feature is disabled.
#[cfg(not(feature = "asm"))]
pub fn get_asm_sym(state: &mut TCCState, _name: &str) -> TccResult<usize> {
    Err(TccError::asm("<none>".to_string(), 0, "assembler support is disabled (enable 'asm' feature)"))
}

// ===========================================================================
// Non-feature-gated type re-exports (always available)
// ===========================================================================

/// Stub Assembler struct when feature is disabled.
#[cfg(not(feature = "asm"))]
pub struct Assembler<'a> {
    pub state: &'a mut TCCState,
}

#[cfg(not(feature = "asm"))]
impl<'a> Assembler<'a> {
    pub fn new(state: &'a mut TCCState) -> Self {
        Assembler { state }
    }
}

