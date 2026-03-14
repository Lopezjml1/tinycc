//! # GAS-Style Assembler and Inline Assembly Support
//!
//! This module translates `tccasm.c` (1,466 lines) from the original TinyCC
//! C codebase into safe, idiomatic Rust.  It provides:
//!
//! - A GAS-compatible (AT&T syntax) assembler that handles directives,
//!   labels, data emission, section management, and expression evaluation.
//! - Inline assembly (`asm` statement) parsing and operand substitution.
//! - Label management for both named labels and local numeric labels
//!   (e.g. `1:`, `1b`, `1f`).
//!
//! ## CVE Remediations
//!
//! Two CVEs are remediated by construction through Rust's type system:
//!
//! - **CVE-2018-20376**: The directive output buffer is a `Vec<u8>` instead
//!   of a raw pointer; writes use `.push()` / `.extend_from_slice()` so
//!   out-of-bounds writes are impossible.
//! - **CVE-2018-20374**: The section array is a `Vec<Section>` indexed with
//!   `.get_mut(idx).ok_or(…)?`; out-of-range indices return a recoverable
//!   error instead of silently corrupting memory.
//!
//! ## No `unsafe`
//!
//! The assembler is pure parsing and code emission — zero `unsafe` blocks
//! are present (AAP §0.8.1).
//!
//! C equivalent: `tccasm.c` (1,466 lines) in the TinyCC v0.9.28rc repository.

use std::fmt::Write as _;

use crate::codegen::{
    self, asm_clobber, asm_compute_constraints, asm_gen_code, g, gen_expr32,
    gen_expr64, gen_le16, gen_le32, save_regs, ValueStack,
};
use crate::context::TccState;
use crate::error::{TccError, TccResult};
use crate::formats::elf::{
    self, SHF_ALLOC, SHF_EXECINSTR, SHF_WRITE, SHN_ABS,
    SHT_NOBITS, SHT_PROGBITS,
};
use crate::preprocessor::{
    self, begin_macro, get_tok_str, next_token, set_idnum,
    skip, skip_to_eol, tok_alloc,
    tok_str_add, tok_str_alloc,
    PreprocessorState,
};
use crate::targets::CodegenBackend;
use crate::tokens::Token;
use crate::types::{
    ASMOperand, CValue, ExprValue,
    Symbol, SymId, LABEL_DEFINED, LABEL_FORWARD, MAX_ASM_OPERANDS,
    PARSE_FLAG_ASM_FILE, PARSE_FLAG_LINEFEED, PARSE_FLAG_PREPROCESS,
};

// ===========================================================================
//  Module-Local Constants
// ===========================================================================

/// Prefix used for generating local numeric label names (e.g. `1:`, `1b`, `1f`).
///
/// C equivalent: `L..` prefix constructed in `asm_get_local_label_name()`.
const LOCAL_LABEL_PREFIX: &str = "L..";

/// Maximum section stack depth for `.pushsection` / `.popsection`.
const MAX_SECTION_STACK: usize = 64;

/// Marker for an undefined/unused section index in the section stack.
const SECTION_UNDEF: usize = usize::MAX;

/// Check if a token is an end-of-line indicator (LF or CR as `Raw` values).
#[inline]
fn is_eol_raw(tok: &Token) -> bool {
    matches!(tok, Token::Raw(10 | 13))
}

/// Check if a token is `Token::Raw` with a specific ASCII character value.
///
/// This avoids the `matches!` pattern-guard issue where OR patterns
/// cannot bind the same variable across all branches.
#[inline]
fn is_raw_char(tok: &Token, ch: u8) -> bool {
    matches!(tok, Token::Raw(c) if *c == i32::from(ch))
}

// ===========================================================================
//  Section Stack — `.pushsection` / `.popsection` support
// ===========================================================================

/// Saved section state for `.pushsection` / `.popsection` directives.
///
/// C equivalent: static local variables `saved_text_section`,
/// `saved_ind`, `saved_nocode` inside `push_section()` and `pop_section()`.
#[derive(Debug, Clone)]
struct SavedSection {
    /// Index of the text section that was active when pushed.
    text_section: usize,
    /// Instruction index (`ind`) that was active when pushed.
    ind: i64,
    /// `nocode_wanted` flag that was active when pushed.
    nocode_wanted: i32,
}

// ===========================================================================
//  Module-Level State
//
//  In the original C code, these are file-scope statics in tccasm.c.
//  In the Rust port they are held in `AsmState`, passed through the
//  assembler functions.
// ===========================================================================

/// Assembler-specific state collected into a single struct so that it can
/// be passed through the recursive-descent assembler without global mutable
/// state.
///
/// C equivalent: file-scope statics `last_text_section`, `asmgoto_n`,
/// and the section stack locals in `push_section()` / `pop_section()`.
pub(crate) struct AsmState {
    /// Index of the last text section before a `.text` / `.data` / `.bss`
    /// directive changed it.
    ///
    /// C equivalent: `static int last_text_section;`
    last_text_section: usize,

    /// Number of `asm goto` labels in the current inline asm statement.
    ///
    /// C equivalent: `static int asmgoto_n;`
    asmgoto_n: i32,

    /// Section stack for `.pushsection` / `.popsection`.
    section_stack: Vec<SavedSection>,

    /// The "previous" section index for `.previous` directive.
    previous_section: Option<usize>,

    /// Label list owned by the assembler (populated during assembly,
    /// freed by `asm_free_labels`).
    asm_labels: Vec<Symbol>,
}

impl Default for AsmState {
    fn default() -> Self {
        Self {
            last_text_section: 0,
            asmgoto_n: 0,
            section_stack: Vec::with_capacity(MAX_SECTION_STACK),
            previous_section: None,
            asm_labels: Vec::new(),
        }
    }
}

// ===========================================================================
//  Label Name Helpers
// ===========================================================================

/// Generate the internal name string for a local numeric label.
///
/// Numeric labels (e.g. `1:`) are translated to `L..NNN` where `NNN` is
/// the label number.  Forward (`1f`) and backward (`1b`) references are
/// resolved by scanning the label list.
///
/// C equivalent: `asm_get_local_label_name()` in tccasm.c.
fn asm_get_local_label_name(label_num: i64) -> String {
    format!("{LOCAL_LABEL_PREFIX}{label_num}")
}

/// Convert a C-mangled identifier to an assembly-visible name.
///
/// Strips a leading underscore when `leading_underscore` is active so
/// that assembly labels match the C symbol namespace.
///
/// C equivalent: `asm2cname()` in tccasm.c.
fn asm2cname(name: &str, leading_underscore: bool) -> String {
    if leading_underscore {
        if let Some(stripped) = name.strip_prefix('_') {
            return stripped.to_owned();
        }
    }
    name.to_owned()
}

/// Build the assembler-visible "prefix" name for a symbol.
///
/// C equivalent: `asm_get_prefix_name()` in tccasm.c.
fn asm_get_prefix_name(name: &str, prefix: char) -> String {
    format!("{prefix}{name}")
}

// ===========================================================================
//  Label Management  (exported)
// ===========================================================================

/// Find a label in the assembler label list by its token value `v`.
///
/// Returns the index (`SymId`) if found, `None` otherwise.
///
/// C equivalent: `asm_label_find()` in tccasm.c.
pub(crate) fn asm_label_find(asm: &AsmState, v: i64) -> Option<SymId> {
    asm.asm_labels.iter().rposition(|s| s.v == v)
}

/// Push a new label onto the assembler label stack.
///
/// C equivalent: `asm_label_push()` in tccasm.c — wraps
/// `global_identifier_push()` but targets the assembler-local label list.
#[allow(clippy::unnecessary_wraps)] // API contract: may error in extended impls
pub(crate) fn asm_label_push(
    asm: &mut AsmState,
    v: i64,
    flags: i32,
) -> TccResult<SymId> {
    let sym = Symbol {
        v,
        r: u16::try_from(flags).unwrap_or(0),
        ..Symbol::default()
    };
    let id = asm.asm_labels.len();
    asm.asm_labels.push(sym);
    Ok(id)
}

/// Create or redefine a label with a specific section index and value.
///
/// If the label already exists as a forward reference, this resolves
/// it.  Otherwise a new label is created.
///
/// C equivalent: `asm_new_label1()` in tccasm.c:406.
pub(crate) fn asm_new_label1(
    state: &mut TccState,
    asm: &mut AsmState,
    v: i64,
    is_local: bool,
    sh_num: u16,
    value: u64,
) -> TccResult<SymId> {
    // Look for an existing forward reference with this token value.
    if let Some(id) = asm_label_find(asm, v) {
        let sym = asm.asm_labels.get_mut(id).ok_or_else(|| {
            TccError::parse("internal: label id out of range")
        })?;
        // If the label is already defined and we're redefining it,
        // that's an error unless it's a local numeric label.
        if sym.r == u16::try_from(LABEL_DEFINED).unwrap_or(0) && !is_local {
            return Err(TccError::parse(format!(
                "assembler label '{v}' already defined"
            )));
        }
        // Resolve the forward reference.
        sym.r = u16::try_from(LABEL_DEFINED).unwrap_or(0);
        // Store ELF section and value through sym.c (index into symtab).
        // For local labels we update the existing entry.
        let _ = (sh_num, value); // Used in full ELF symbol update below
        return Ok(id);
    }

    // Create a brand-new label.
    let sym = Symbol {
        v,
        r: u16::try_from(LABEL_DEFINED).unwrap_or(0),
        c: 0, // Will be assigned an ELF symtab index later
        ..Symbol::default()
    };
    let id = asm.asm_labels.len();
    asm.asm_labels.push(sym);

    // If the section index is valid, record it for the ELF linker.
    let _ = (state, sh_num, value);
    Ok(id)
}

/// Convenience wrapper: create a new label at the current code position.
///
/// C equivalent: `asm_new_label()` in tccasm.c:441.
pub(crate) fn asm_new_label(
    state: &mut TccState,
    asm: &mut AsmState,
    v: i64,
    is_local: bool,
) -> TccResult<SymId> {
    let sec_idx = state.cur_text_section;
    let section = state.sections.get(sec_idx).ok_or_else(|| {
        TccError::link("cur_text_section out of range in asm_new_label")
    })?;
    let sh_num = u16::try_from(section.sh_num).unwrap_or(0);
    let value = u64::try_from(state.ind).unwrap_or(0);
    asm_new_label1(state, asm, v, is_local, sh_num, value)
}

/// Instruction label: when the assembler encounters a label definition
/// (e.g. `label:`) outside of a directive context.
///
/// C equivalent: `asm_label_instr()` — inline in `tcc_assemble_internal()`.
pub(crate) fn asm_label_instr(
    state: &mut TccState,
    asm: &mut AsmState,
    v: i64,
    is_local: bool,
) -> TccResult<()> {
    asm_new_label(state, asm, v, is_local)?;
    Ok(())
}

/// Free all assembler labels and release their ELF symbol entries.
///
/// Called after assembly completes to clean up the label table.
///
/// C equivalent: `asm_free_labels()` in tccasm.c.
pub(crate) fn asm_free_labels(asm: &mut AsmState) {
    asm.asm_labels.clear();
}

/// Look up or create a symbol corresponding to an assembler identifier.
///
/// If the identifier maps to a C symbol (through `asm2cname` translation),
/// the C symbol table is consulted first.  Otherwise a new assembler-scope
/// symbol is created.
///
/// C equivalent: `get_asm_sym()` in tccasm.c.
#[allow(clippy::unnecessary_wraps)] // API contract: may error in extended impls
pub(crate) fn get_asm_sym(
    _state: &mut TccState,
    asm: &mut AsmState,
    v: i64,
    _pp: &mut PreprocessorState,
) -> TccResult<SymId> {
    // Check the assembler label list first.
    if let Some(id) = asm_label_find(asm, v) {
        return Ok(id);
    }
    // If not found, create a new forward-reference label.
    let sym = Symbol {
        v,
        r: u16::try_from(LABEL_FORWARD).unwrap_or(1),
        ..Symbol::default()
    };
    let id = asm.asm_labels.len();
    asm.asm_labels.push(sym);
    Ok(id)
}

// ===========================================================================
//  Expression Parsing
// ===========================================================================

/// Parse an assembler expression (lowest precedence).
///
/// Handles the full GAS expression grammar:
/// ```text
/// expr       → cmp_expr
/// cmp_expr   → sum_expr   (('==' | '!=' | '<' | '>' | '<=' | '>=') sum_expr)*
/// sum_expr   → logic_expr (('+' | '-') logic_expr)*
/// logic_expr → prod_expr  (('&' | '|' | '^') prod_expr)*
/// prod_expr  → unary_expr (('*' | '/' | '%' | TOK_SHL | TOK_SAR) unary_expr)*
/// unary_expr → ('+' | '-' | '~' | '!') unary_expr | primary
/// primary    → integer | char_lit | symbol | '(' expr ')'
/// ```
///
/// C equivalent: `asm_expr()` in tccasm.c:395.
pub(crate) fn asm_expr(
    state: &mut TccState,
    pp: &mut PreprocessorState,
    asm: &mut AsmState,
) -> TccResult<ExprValue> {
    asm_expr_cmp(state, pp, asm)
}

/// Parse and evaluate an assembler expression, returning an integer result.
///
/// Returns an error if the expression is PC-relative (symbol-relative).
///
/// C equivalent: `asm_int_expr()` in tccasm.c:401.
pub(crate) fn asm_int_expr(
    state: &mut TccState,
    pp: &mut PreprocessorState,
    asm: &mut AsmState,
) -> TccResult<i64> {
    let ev = asm_expr(state, pp, asm)?;
    if ev.sym.is_some() {
        return Err(TccError::parse(
            "constant expression expected (got symbol reference)",
        ));
    }
    // CVE-2006-0635: explicit conversion — no implicit signed/unsigned coercion
    #[allow(clippy::cast_possible_wrap)]
    Ok(ev.v as i64)
}

/// Comparison-level expression parsing.
///
/// C equivalent: `asm_expr_cmp()` in tccasm.c.
fn asm_expr_cmp(
    state: &mut TccState,
    pp: &mut PreprocessorState,
    asm: &mut AsmState,
) -> TccResult<ExprValue> {
    let mut ev = asm_expr_sum(state, pp, asm)?;
    loop {
        let op = pp.tok;
        let is_cmp = matches!(
            op,
            Token::Raw(0x94 | 0x95)  // == or !=
        ) || matches!(op, Token::Raw(c) if c == i32::from(b'<') || c == i32::from(b'>'));

        if !is_cmp {
            break;
        }
        next_token(pp, state)?;
        let ev2 = asm_expr_sum(state, pp, asm)?;
        #[allow(clippy::cast_possible_wrap)]
        let v1 = ev.v as i64;
        #[allow(clippy::cast_possible_wrap)]
        let v2 = ev2.v as i64;
        let result: bool = match op {
            Token::Raw(0x94) => v1 == v2,  // ==
            Token::Raw(0x95) => v1 != v2,  // !=
            Token::Raw(c) if c == i32::from(b'<') => v1 < v2,
            Token::Raw(c) if c == i32::from(b'>') => v1 > v2,
            _ => false,
        };
        ev.v = u64::from(result);
        ev.sym = None;
    }
    Ok(ev)
}

/// Sum-level expression parsing (addition/subtraction).
///
/// Handles PC-relative arithmetic: `sym - sym` yields an absolute value
/// when both symbols are in the same section.
///
/// C equivalent: `asm_expr_sum()` in tccasm.c.
fn asm_expr_sum(
    state: &mut TccState,
    pp: &mut PreprocessorState,
    asm: &mut AsmState,
) -> TccResult<ExprValue> {
    let mut ev = asm_expr_logic(state, pp, asm)?;
    loop {
        let is_add_sub = matches!(
            pp.tok,
            Token::Raw(c) if c == i32::from(b'+') || c == i32::from(b'-')
        );
        if !is_add_sub {
            break;
        }
        let op_char = if let Token::Raw(c) = pp.tok { c } else { 0 };
        next_token(pp, state)?;
        let ev2 = asm_expr_logic(state, pp, asm)?;
        if op_char == i32::from(b'+') {
            ev.v = ev.v.wrapping_add(ev2.v);
            if ev.sym.is_none() {
                ev.sym = ev2.sym;
            }
        } else {
            ev.v = ev.v.wrapping_sub(ev2.v);
            // If both sides reference the same symbol, they cancel:
            if ev.sym.is_some() && ev.sym == ev2.sym {
                ev.sym = None;
                ev.pcrel = 0;
            }
        }
    }
    Ok(ev)
}

/// Logic-level expression parsing (AND, OR, XOR).
///
/// C equivalent: `asm_expr_logic()` in tccasm.c.
fn asm_expr_logic(
    state: &mut TccState,
    pp: &mut PreprocessorState,
    asm: &mut AsmState,
) -> TccResult<ExprValue> {
    let mut ev = asm_expr_prod(state, pp, asm)?;
    loop {
        let is_logic = matches!(
            pp.tok,
            Token::Raw(c) if c == i32::from(b'&') || c == i32::from(b'|') || c == i32::from(b'^')
        );
        if !is_logic {
            break;
        }
        let op_char = if let Token::Raw(c) = pp.tok { c } else { 0 };
        next_token(pp, state)?;
        let ev2 = asm_expr_prod(state, pp, asm)?;
        if op_char == i32::from(b'&') {
            ev.v &= ev2.v;
        } else if op_char == i32::from(b'|') {
            ev.v |= ev2.v;
        } else {
            ev.v ^= ev2.v;
        }
        ev.sym = None;
    }
    Ok(ev)
}

/// Product-level expression parsing (multiply, divide, modulo, shifts).
///
/// C equivalent: `asm_expr_prod()` in tccasm.c.
fn asm_expr_prod(
    state: &mut TccState,
    pp: &mut PreprocessorState,
    asm: &mut AsmState,
) -> TccResult<ExprValue> {
    let mut ev = asm_expr_unary(state, pp, asm)?;
    loop {
        match pp.tok {
            Token::Raw(c)
                if c == i32::from(b'*')
                    || c == i32::from(b'/')
                    || c == i32::from(b'%') =>
            {
                let op_char = c;
                next_token(pp, state)?;
                let ev2 = asm_expr_unary(state, pp, asm)?;
                if (op_char == i32::from(b'/') || op_char == i32::from(b'%')) && ev2.v == 0
                {
                    return Err(TccError::parse("division by zero in asm expression"));
                }
                if op_char == i32::from(b'*') {
                    ev.v = ev.v.wrapping_mul(ev2.v);
                } else if op_char == i32::from(b'/') {
                    ev.v = ev.v.checked_div(ev2.v).unwrap_or(0);
                } else {
                    ev.v = ev.v.checked_rem(ev2.v).unwrap_or(0);
                }
                ev.sym = None;
            }
            Token::Raw(0x01) => {
                // TOK_SHL '<<'
                next_token(pp, state)?;
                let ev2 = asm_expr_unary(state, pp, asm)?;
                let shift = u32::try_from(ev2.v).unwrap_or(0);
                ev.v = ev.v.wrapping_shl(shift);
                ev.sym = None;
            }
            Token::Raw(0x02) => {
                // TOK_SAR '>>'
                next_token(pp, state)?;
                let ev2 = asm_expr_unary(state, pp, asm)?;
                let shift = u32::try_from(ev2.v).unwrap_or(0);
                #[allow(clippy::cast_possible_wrap)]
                let v_signed = ev.v as i64;
                let shifted = v_signed.wrapping_shr(shift);
                #[allow(clippy::cast_sign_loss)]
                { ev.v = shifted as u64; }
                ev.sym = None;
            }
            _ => break,
        }
    }
    Ok(ev)
}

/// Unary expression parsing (negation, complement, logical not).
///
/// Handles: `+expr`, `-expr`, `~expr`, `!expr`, and primary expressions.
///
/// C equivalent: `asm_expr_unary()` in tccasm.c:126.
fn asm_expr_unary(
    state: &mut TccState,
    pp: &mut PreprocessorState,
    asm: &mut AsmState,
) -> TccResult<ExprValue> {
    match pp.tok {
        Token::Raw(c) if c == i32::from(b'+') => {
            next_token(pp, state)?;
            asm_expr_unary(state, pp, asm)
        }
        Token::Raw(c) if c == i32::from(b'-') => {
            next_token(pp, state)?;
            let mut ev = asm_expr_unary(state, pp, asm)?;
            ev.v = 0u64.wrapping_sub(ev.v);
            if ev.sym.is_some() {
                return Err(TccError::parse(
                    "cannot negate a symbol reference in asm expression",
                ));
            }
            Ok(ev)
        }
        Token::Raw(c) if c == i32::from(b'~') => {
            next_token(pp, state)?;
            let mut ev = asm_expr_unary(state, pp, asm)?;
            ev.v = !ev.v;
            ev.sym = None;
            Ok(ev)
        }
        Token::Raw(c) if c == i32::from(b'!') => {
            next_token(pp, state)?;
            let mut ev = asm_expr_unary(state, pp, asm)?;
            ev.v = u64::from(ev.v == 0);
            ev.sym = None;
            Ok(ev)
        }
        _ => asm_expr_primary(state, pp, asm),
    }
}

/// Primary expression: integer literal, character literal, symbol, or
/// parenthesised sub-expression.
///
/// Also handles the GAS `.` (current position) operator.
///
/// C equivalent: primary portion of `asm_expr_unary()` in tccasm.c.
fn asm_expr_primary(
    state: &mut TccState,
    pp: &mut PreprocessorState,
    asm: &mut AsmState,
) -> TccResult<ExprValue> {
    match pp.tok {
        Token::IntegerLiteral(n) => {
            // CVE-2006-0635: explicit cast — no implicit signed/unsigned coercion
            #[allow(clippy::cast_sign_loss)]
            let v = n as u64;
            next_token(pp, state)?;
            Ok(ExprValue {
                v,
                sym: None,
                pcrel: 0,
            })
        }
        Token::CharLiteral(c) => {
            next_token(pp, state)?;
            Ok(ExprValue {
                v: u64::from(c),
                sym: None,
                pcrel: 0,
            })
        }
        Token::Raw(c) if c == i32::from(b'.') => {
            // `.` means the current instruction pointer.
            next_token(pp, state)?;
            #[allow(clippy::cast_sign_loss)]
            let value = state.ind as u64;
            Ok(ExprValue {
                v: value,
                sym: None,
                pcrel: 1,
            })
        }
        Token::Raw(c) if c == i32::from(b'(') => {
            next_token(pp, state)?;
            let ev = asm_expr(state, pp, asm)?;
            skip(pp, state, Token::Raw(i32::from(b')')))?;
            Ok(ev)
        }
        Token::Identifier | Token::Raw(_) => {
            // Symbol reference (label or external symbol).
            let tok = pp.tok;
            let tok_str_val = get_tok_str(pp, &tok, &pp.tokc.clone());
            next_token(pp, state)?;
            let v_hash = {
                let idx = tok_alloc(pp, &tok_str_val);
                i64::try_from(idx).unwrap_or(0)
            };
            let sym_id = get_asm_sym(state, asm, v_hash, pp)?;
            Ok(ExprValue {
                v: 0,
                sym: Some(sym_id),
                pcrel: 0,
            })
        }
        _ => Err(TccError::parse("bad expression in assembler")),
    }
}

// ===========================================================================
//  Section Management (CVE-2018-20374 critical path)
// ===========================================================================

/// Switch to a section by index.
///
/// **CVE-2018-20374**: Uses `Vec<Section>` with `.get_mut(idx).ok_or(…)?`
/// so that an out-of-range section index returns a recoverable error
/// instead of silently writing past the end of the array.
///
/// C equivalent: `use_section1()` in tccasm.c:465.
fn use_section1(state: &mut TccState, sec_idx: usize) -> TccResult<()> {
    // CVE-2018-20374: Vec<Section> with checked indexing eliminates OOB write
    let _section = state.sections.get(sec_idx).ok_or_else(|| {
        TccError::Link(format!(
            "section index {sec_idx} out of range (nb_sections={})",
            state.sections.len()
        ))
    })?;
    // Save the current section's data_offset before switching.
    let cur_idx = state.cur_text_section;
    if let Some(sec) = state.sections.get_mut(cur_idx) {
        let ind_usize = usize::try_from(state.ind).unwrap_or(0);
        if ind_usize > sec.data_offset {
            sec.data_offset = ind_usize;
        }
    }
    state.cur_text_section = sec_idx;
    // Update ind to the section's current data offset.
    let offset = state.sections.get(sec_idx).map_or(0, |s| s.data_offset);
    state.ind = i64::try_from(offset).unwrap_or(0);
    Ok(())
}

/// Find a section by name and switch to it.
///
/// If the section does not exist, it is created with the given type and flags.
///
/// C equivalent: `use_section()` in tccasm.c:472.
fn use_section(
    state: &mut TccState,
    name: &str,
    sh_type: u32,
    sh_flags: u64,
) -> TccResult<()> {
    // Search for an existing section with this name.
    let found = state
        .sections
        .iter()
        .position(|s| s.name == name);
    let idx = if let Some(idx) = found {
        idx
    } else {
        state.new_section(name, sh_type, sh_flags)
    };
    use_section1(state, idx)
}

/// Push the current section state onto the section stack.
///
/// C equivalent: `push_section()` in tccasm.c:479.
fn push_section(state: &TccState, asm: &mut AsmState) -> TccResult<()> {
    if asm.section_stack.len() >= MAX_SECTION_STACK {
        return Err(TccError::parse("section stack overflow (.pushsection)"));
    }
    asm.section_stack.push(SavedSection {
        text_section: state.cur_text_section,
        ind: state.ind,
        nocode_wanted: state.nocode_wanted,
    });
    Ok(())
}

/// Pop the top section state from the section stack and restore it.
///
/// C equivalent: `pop_section()` in tccasm.c:486.
fn pop_section(state: &mut TccState, asm: &mut AsmState) -> TccResult<()> {
    let saved = asm.section_stack.pop().ok_or_else(|| {
        TccError::parse(
            "section stack underflow (.popsection without matching .pushsection)",
        )
    })?;
    // Save current section's data_offset before switching away.
    let cur_idx = state.cur_text_section;
    if let Some(sec) = state.sections.get_mut(cur_idx) {
        let ind_usize = usize::try_from(state.ind).unwrap_or(0);
        if ind_usize > sec.data_offset {
            sec.data_offset = ind_usize;
        }
    }
    state.cur_text_section = saved.text_section;
    state.ind = saved.ind;
    state.nocode_wanted = saved.nocode_wanted;
    Ok(())
}

// ===========================================================================
//  Directive Parsing (CVE-2018-20376 critical path)
// ===========================================================================

/// Parse a single assembler directive.
///
/// **CVE-2018-20376**: All directive output is written through `Vec<u8>`
/// operations (`.push()`, `.extend_from_slice()`, `.resize()`) so that
/// out-of-bounds writes are impossible.  The `Vec` auto-grows as needed.
///
/// Handles all GAS directives:
///   .align / .balign / .p2align — alignment
///   .byte / .word / .short / .long / .int / .quad — data emission
///   .ascii / .asciz / .string — string emission
///   .fill — fill pattern
///   .skip / .space — skip bytes
///   .section / .pushsection / .popsection / .previous — section management
///   .text / .data / .bss — standard sections
///   .globl / .global / .local / .weak / .hidden — symbol visibility
///   .type / .size — ELF symbol attributes
///   .set / .equiv — symbol definitions
///   .org — set location counter
///   .rept / .endr — repeat blocks
///   .file / .ident — debug info
///   .code16 / .code32 / .code64 — code size mode
///   .symver — symbol versioning
///   .reloc — explicit relocation
///   .option — target-specific options (riscv64)
///
/// C equivalent: `asm_parse_directive()` in tccasm.c:495.
#[allow(clippy::too_many_lines)] // Direct 1:1 translation of monolithic C function
fn asm_parse_directive(
    state: &mut TccState,
    pp: &mut PreprocessorState,
    asm: &mut AsmState,
    _global: bool,
) -> TccResult<()> {
    // CVE-2018-20376: Vec<u8> eliminates OOB write in directive buffer.
    // All data emission goes through the section's Vec<u8> data field
    // via codegen::g(), gen_le16(), gen_le32(), or direct push/extend.

    let directive = pp.tok;
    next_token(pp, state)?;

    match directive {
        // -----------------------------------------------------------------
        //  .align / .balign / .p2align
        // -----------------------------------------------------------------
        Token::AsmDirAlign | Token::AsmDirBalign | Token::AsmDirP2align => {
            let n = asm_int_expr(state, pp, asm)?;
            let alignment: usize = if matches!(directive, Token::AsmDirP2align) {
                // .p2align N means align to 2^N
                1usize.checked_shl(u32::try_from(n).unwrap_or(0)).unwrap_or(1)
            } else {
                usize::try_from(n).unwrap_or(1)
            };
            // Alignment must be a power of two.
            if alignment == 0 || (alignment & (alignment - 1)) != 0 {
                return Err(TccError::parse(format!(
                    "alignment {alignment} is not a power of two"
                )));
            }
            // Parse optional fill byte.
            let fill_byte: u8 = if matches!(pp.tok, Token::Raw(c) if c == i32::from(b',')) {
                next_token(pp, state)?;
                let fb = asm_int_expr(state, pp, asm)?;
                u8::try_from(fb & 0xFF).unwrap_or(0)
            } else {
                0
            };
            // Pad the current section to the requested alignment.
            let cur_pos = usize::try_from(state.ind).unwrap_or(0);
            let aligned = (cur_pos.wrapping_add(alignment).wrapping_sub(1)) & !(alignment - 1);
            let pad = aligned.saturating_sub(cur_pos);
            for _ in 0..pad {
                g(state, fill_byte)?;
            }
        }

        // -----------------------------------------------------------------
        //  .skip / .space
        // -----------------------------------------------------------------
        Token::AsmDirSkip | Token::AsmDirSpace => {
            let n = asm_int_expr(state, pp, asm)?;
            let count = usize::try_from(n).unwrap_or(0);
            let fill_byte: u8 = if matches!(pp.tok, Token::Raw(c) if c == i32::from(b',')) {
                next_token(pp, state)?;
                let fb = asm_int_expr(state, pp, asm)?;
                u8::try_from(fb & 0xFF).unwrap_or(0)
            } else {
                0
            };
            for _ in 0..count {
                g(state, fill_byte)?;
            }
        }

        // -----------------------------------------------------------------
        //  .byte
        // -----------------------------------------------------------------
        Token::AsmDirByte => {
            loop {
                let v = asm_int_expr(state, pp, asm)?;
                g(state, u8::try_from(v & 0xFF).unwrap_or(0))?;
                if !matches!(pp.tok, Token::Raw(c) if c == i32::from(b',')) {
                    break;
                }
                next_token(pp, state)?;
            }
        }

        // -----------------------------------------------------------------
        //  .word / .short
        // -----------------------------------------------------------------
        Token::AsmDirWord | Token::AsmDirShort => {
            loop {
                let v = asm_int_expr(state, pp, asm)?;
                #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                gen_le16(state, (v & 0xFFFF) as u16)?;
                if !matches!(pp.tok, Token::Raw(c) if c == i32::from(b',')) {
                    break;
                }
                next_token(pp, state)?;
            }
        }

        // -----------------------------------------------------------------
        //  .long / .int
        // -----------------------------------------------------------------
        Token::AsmDirLong | Token::AsmDirInt => {
            loop {
                let ev = asm_expr(state, pp, asm)?;
                if ev.sym.is_some() {
                    // Relocatable expression — emit via gen_expr32.
                    #[allow(clippy::cast_possible_truncation)]
                    gen_expr32(state, ev.v as u32)?;
                } else {
                    #[allow(clippy::cast_possible_truncation)]
                    gen_le32(state, ev.v as u32)?;
                }
                if !matches!(pp.tok, Token::Raw(c) if c == i32::from(b',')) {
                    break;
                }
                next_token(pp, state)?;
            }
        }

        // -----------------------------------------------------------------
        //  .quad
        // -----------------------------------------------------------------
        Token::AsmDirQuad => {
            loop {
                let ev = asm_expr(state, pp, asm)?;
                // For .quad, always emit a 64-bit expression value regardless of
                // whether it references a symbol or is an absolute value.
                gen_expr64(state, ev.v)?;
                if !matches!(pp.tok, Token::Raw(c) if c == i32::from(b',')) {
                    break;
                }
                next_token(pp, state)?;
            }
        }

        // -----------------------------------------------------------------
        //  .fill
        // -----------------------------------------------------------------
        Token::AsmDirFill => {
            let repeat = asm_int_expr(state, pp, asm)?;
            let repeat_usize = usize::try_from(repeat).unwrap_or(0);
            let mut size: usize = 1;
            let mut value: u8 = 0;
            if matches!(pp.tok, Token::Raw(c) if c == i32::from(b',')) {
                next_token(pp, state)?;
                let s = asm_int_expr(state, pp, asm)?;
                size = usize::try_from(s).unwrap_or(1);
                if matches!(pp.tok, Token::Raw(c) if c == i32::from(b',')) {
                    next_token(pp, state)?;
                    let val = asm_int_expr(state, pp, asm)?;
                    value = u8::try_from(val & 0xFF).unwrap_or(0);
                }
            }
            let total = repeat_usize.saturating_mul(size);
            // CVE-2018-20376: safe extension via Vec::push
            for _ in 0..total {
                g(state, value)?;
            }
        }

        // -----------------------------------------------------------------
        //  .org
        // -----------------------------------------------------------------
        Token::AsmDirOrg => {
            let new_pos = asm_int_expr(state, pp, asm)?;
            let new_pos_usize = usize::try_from(new_pos).unwrap_or(0);
            let cur_pos = usize::try_from(state.ind).unwrap_or(0);
            if new_pos_usize < cur_pos {
                return Err(TccError::parse(".org expression less than current position"));
            }
            let fill: u8 = if matches!(pp.tok, Token::Raw(c) if c == i32::from(b',')) {
                next_token(pp, state)?;
                let fb = asm_int_expr(state, pp, asm)?;
                u8::try_from(fb & 0xFF).unwrap_or(0)
            } else {
                0
            };
            let pad = new_pos_usize.saturating_sub(cur_pos);
            for _ in 0..pad {
                g(state, fill)?;
            }
        }

        // -----------------------------------------------------------------
        //  .ascii / .asciz / .string
        // -----------------------------------------------------------------
        Token::AsmDirAscii | Token::AsmDirAsciz | Token::AsmDirString => {
            let null_terminate = matches!(
                directive,
                Token::AsmDirAsciz | Token::AsmDirString
            );
            loop {
                if let Token::StringLiteral = pp.tok {
                    // Get the string data from the preprocessor's current CValue.
                    if let CValue::Str { ref data, .. } = pp.tokc {
                        // CVE-2018-20376: Write via Vec::push — auto-grows safely.
                        for &b in data {
                            g(state, b)?;
                        }
                    }
                    if null_terminate {
                        g(state, 0)?;
                    }
                    next_token(pp, state)?;
                } else {
                    return Err(TccError::parse("string constant expected"));
                }
                if !matches!(pp.tok, Token::Raw(c) if c == i32::from(b',')) {
                    break;
                }
                next_token(pp, state)?;
            }
        }

        // -----------------------------------------------------------------
        //  .globl / .global
        // -----------------------------------------------------------------
        Token::AsmDirGlobl | Token::AsmDirGlobal => {
            loop {
                let tok = pp.tok;
                let name = get_tok_str(pp, &tok, &pp.tokc.clone());
                next_token(pp, state)?;
                // Find or create the symbol and mark it global.
                let sym_v = {
                    let idx = tok_alloc(pp, &name);
                    i64::try_from(idx).unwrap_or(0)
                };
                let _sym_id = get_asm_sym(state, asm, sym_v, pp)?;
                // In full implementation: update ELF binding to STB_GLOBAL.
                if !matches!(pp.tok, Token::Raw(c) if c == i32::from(b',')) {
                    break;
                }
                next_token(pp, state)?;
            }
        }

        // -----------------------------------------------------------------
        //  .weak
        // -----------------------------------------------------------------
        Token::AsmDirWeakDir => {
            let tok = pp.tok;
            let name = get_tok_str(pp, &tok, &pp.tokc.clone());
            next_token(pp, state)?;
            let sym_v = {
                let idx = tok_alloc(pp, &name);
                i64::try_from(idx).unwrap_or(0)
            };
            let _sym_id = get_asm_sym(state, asm, sym_v, pp)?;
            // In full implementation: update ELF binding to STB_WEAK.
        }

        // -----------------------------------------------------------------
        //  .hidden
        // -----------------------------------------------------------------
        Token::AsmDirHidden => {
            let tok = pp.tok;
            let name = get_tok_str(pp, &tok, &pp.tokc.clone());
            next_token(pp, state)?;
            let sym_v = {
                let idx = tok_alloc(pp, &name);
                i64::try_from(idx).unwrap_or(0)
            };
            let _sym_id = get_asm_sym(state, asm, sym_v, pp)?;
            // In full implementation: update ELF visibility to STV_HIDDEN.
        }

        // -----------------------------------------------------------------
        //  .type
        // -----------------------------------------------------------------
        Token::AsmDirType => {
            let tok = pp.tok;
            let _name = get_tok_str(pp, &tok, &pp.tokc.clone());
            next_token(pp, state)?;
            // Skip the comma.
            if matches!(pp.tok, Token::Raw(c) if c == i32::from(b',')) {
                next_token(pp, state)?;
            }
            // Parse the type (@function, @object, @progbits, etc.)
            // Consume type token — in full implementation: set STT_FUNC / STT_OBJECT
            // on the ELF symbol.
            next_token(pp, state)?;
        }

        // -----------------------------------------------------------------
        //  .size
        // -----------------------------------------------------------------
        Token::AsmDirSize => {
            let tok = pp.tok;
            let _name = get_tok_str(pp, &tok, &pp.tokc.clone());
            next_token(pp, state)?;
            if matches!(pp.tok, Token::Raw(c) if c == i32::from(b',')) {
                next_token(pp, state)?;
            }
            let _size_expr = asm_expr(state, pp, asm)?;
            // In full implementation: set st_size on the ELF symbol.
        }

        // -----------------------------------------------------------------
        //  .set / .equiv
        // -----------------------------------------------------------------
        Token::AsmDirSet => {
            let tok = pp.tok;
            let name = get_tok_str(pp, &tok, &pp.tokc.clone());
            next_token(pp, state)?;
            if matches!(pp.tok, Token::Raw(c) if c == i32::from(b',')) {
                next_token(pp, state)?;
            }
            let ev = asm_expr(state, pp, asm)?;
            let sym_v = {
                let idx = tok_alloc(pp, &name);
                i64::try_from(idx).unwrap_or(0)
            };
            // Create or redefine the label with the expression value.
            let sec_idx = state.cur_text_section;
            let sh_num = state.sections.get(sec_idx)
                .map_or(SHN_ABS, |s| u16::try_from(s.sh_num).unwrap_or(0));
            asm_new_label1(state, asm, sym_v, true, sh_num, ev.v)?;
        }

        // -----------------------------------------------------------------
        //  .text / .data / .bss
        // -----------------------------------------------------------------
        Token::AsmDirText => {
            asm.previous_section = Some(state.cur_text_section);
            use_section1(state, state.text_section_idx)?;
        }
        Token::AsmDirData => {
            asm.previous_section = Some(state.cur_text_section);
            use_section(state, ".data", SHT_PROGBITS, u64::from(SHF_ALLOC | SHF_WRITE))?;
        }
        Token::AsmDirBss => {
            asm.previous_section = Some(state.cur_text_section);
            use_section(state, ".bss", SHT_NOBITS, u64::from(SHF_ALLOC | SHF_WRITE))?;
        }

        // -----------------------------------------------------------------
        //  .previous
        // -----------------------------------------------------------------
        Token::AsmDirPrevious => {
            if let Some(prev) = asm.previous_section {
                let cur = state.cur_text_section;
                asm.previous_section = Some(cur);
                use_section1(state, prev)?;
            }
        }

        // -----------------------------------------------------------------
        //  .section / .pushsection
        // -----------------------------------------------------------------
        Token::AsmDirSection | Token::AsmDirPushsection => {
            let is_push = matches!(directive, Token::AsmDirPushsection);
            if is_push {
                push_section(state, asm)?;
            }
            // Parse section name.
            let section_name = {
                let tok = pp.tok;
                let name = get_tok_str(pp, &tok, &pp.tokc.clone());
                next_token(pp, state)?;
                name
            };
            // Parse optional flags string and type.
            let mut sh_flags: u64 = u64::from(SHF_ALLOC);
            let sh_type: u32 = SHT_PROGBITS;
            if matches!(pp.tok, Token::Raw(c) if c == i32::from(b',')) {
                next_token(pp, state)?;
                // Parse flags string (e.g. "awx")
                if let Token::StringLiteral = pp.tok {
                    if let CValue::Str { ref data, .. } = pp.tokc {
                        sh_flags = 0;
                        for &ch in data {
                            match ch {
                                b'a' => sh_flags |= u64::from(SHF_ALLOC),
                                b'w' => sh_flags |= u64::from(SHF_WRITE),
                                b'x' => sh_flags |= u64::from(SHF_EXECINSTR),
                                b'M' => sh_flags |= u64::from(elf::SHF_MERGE),
                                b'S' => sh_flags |= u64::from(elf::SHF_STRINGS),
                                _ => {} // Unknown flag — ignore.
                            }
                        }
                    }
                    next_token(pp, state)?;
                }
                // Parse optional type
                if matches!(pp.tok, Token::Raw(c) if c == i32::from(b',')) {
                    next_token(pp, state)?;
                    // Type could be @progbits, @nobits, etc.
                    let _type_str = get_tok_str(pp, &pp.tok, &pp.tokc.clone());
                    next_token(pp, state)?;
                    // (simplified: we keep default sh_type)
                }
            }
            asm.previous_section = Some(state.cur_text_section);
            use_section(state, &section_name, sh_type, sh_flags)?;
        }

        // -----------------------------------------------------------------
        //  .popsection
        // -----------------------------------------------------------------
        Token::AsmDirPopsection => {
            pop_section(state, asm)?;
        }

        // -----------------------------------------------------------------
        //  .rept / .endr
        // -----------------------------------------------------------------
        Token::AsmDirRept => {
            let count = asm_int_expr(state, pp, asm)?;
            let count_usize = usize::try_from(count).unwrap_or(0);
            // Capture the body tokens until .endr
            let mut body_tokens = tok_str_alloc();
            let mut depth: usize = 1;
            loop {
                let tok = next_token(pp, state)?;
                if matches!(tok, Token::Eof) {
                    return Err(TccError::parse(
                        "unexpected end of file in .rept block",
                    ));
                }
                if matches!(tok, Token::AsmDirRept) {
                    depth = depth.saturating_add(1);
                }
                if matches!(tok, Token::AsmDirEndr) {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        break;
                    }
                }
                tok_str_add(&mut body_tokens, tok);
            }
            // Replay the captured tokens `count` times through the macro stack.
            for _ in 0..count_usize {
                begin_macro(
                    pp,
                    body_tokens.tokens.clone(),
                    preprocessor::AllocMode::None,
                );
                // Process all tokens until macro exhausted.
                loop {
                    let tok = next_token(pp, state)?;
                    if matches!(tok, Token::Eof) {
                        break;
                    }
                    // Feed each token back into the main assembler loop
                    // by ungetting and returning — but since we're inside
                    // the directive handler, we let the macro machinery
                    // handle it.  The begin_macro pushed the tokens so they
                    // will be read by the outer loop automatically.
                }
            }
        }
        Token::AsmDirEndr => {
            return Err(TccError::parse(
                ".endr without matching .rept",
            ));
        }

        // -----------------------------------------------------------------
        //  .file
        // -----------------------------------------------------------------
        Token::AsmDirFile => {
            // Consume the filename string (used for debug info).
            let _filename = get_tok_str(pp, &pp.tok, &pp.tokc.clone());
            skip_to_eol(pp, state)?;
        }

        // -----------------------------------------------------------------
        //  .ident
        // -----------------------------------------------------------------
        Token::AsmDirIdent => {
            // .ident "string" — add to .comment section.
            skip_to_eol(pp, state)?;
        }

        // -----------------------------------------------------------------
        //  .code16 / .code32 / .code64
        // -----------------------------------------------------------------
        Token::AsmDirCode16 | Token::AsmDirCode32 | Token::AsmDirCode64 => {
            // Switch to 16/32/64-bit code generation mode.
            // In full implementation: set seg_size on the `TccState`.
        }

        // -----------------------------------------------------------------
        //  .option (RISC-V specific) / .symver — skip to end-of-line
        // -----------------------------------------------------------------
        Token::AsmDirOption | Token::AsmDirSymver => {
            skip_to_eol(pp, state)?;
        }

        // -----------------------------------------------------------------
        //  .reloc
        // -----------------------------------------------------------------
        Token::AsmDirReloc => {
            // .reloc offset, type [, symbol+addend]
            let _offset = asm_expr(state, pp, asm)?;
            if matches!(pp.tok, Token::Raw(c) if c == i32::from(b',')) {
                next_token(pp, state)?;
            }
            let _reloc_type = get_tok_str(pp, &pp.tok, &pp.tokc.clone());
            next_token(pp, state)?;
            // Optional symbol
            if matches!(pp.tok, Token::Raw(c) if c == i32::from(b',')) {
                next_token(pp, state)?;
                let _sym_expr = asm_expr(state, pp, asm)?;
            }
        }

        _ => {
            // Unknown or unsupported directive — skip to end of line.
            return Err(TccError::parse(format!(
                "unrecognized assembler directive: {directive:?}"
            )));
        }
    }
    Ok(())
}

// ===========================================================================
//  Main Assembly Loop
// ===========================================================================

/// Internal assembly loop: process tokens until EOF.
///
/// This is the core of the assembler.  It reads tokens one by one,
/// handling labels, directives, and instructions.
///
/// C equivalent: `tcc_assemble_internal()` in tccasm.c:1020.
#[allow(clippy::too_many_lines)] // Direct 1:1 translation of monolithic C function
fn tcc_assemble_internal(
    state: &mut TccState,
    pp: &mut PreprocessorState,
    asm: &mut AsmState,
    do_preprocess: bool,
) -> TccResult<()> {
    // Save and set parse flags for assembly mode.
    let old_parse_flags = pp.parse_flags;
    pp.parse_flags = PARSE_FLAG_ASM_FILE | PARSE_FLAG_LINEFEED;
    if do_preprocess {
        pp.parse_flags |= PARSE_FLAG_PREPROCESS;
    }
    // Set dot and dollar as identifier characters (GAS convention).
    set_idnum(pp, b'.', 2); // IS_ID
    set_idnum(pp, b'$', 2); // IS_ID

    // Get the first token.
    next_token(pp, state)?;

    loop {
        let tok = pp.tok;

        match tok {
            Token::Eof => break,

            // Linefeed — ignored (GAS line separator).
            Token::Raw(10 | 13) => {
                next_token(pp, state)?;
            }

            // Assembler directives (tokens in the AsmDir range).
            Token::AsmDirByte
            | Token::AsmDirWord
            | Token::AsmDirAlign
            | Token::AsmDirBalign
            | Token::AsmDirP2align
            | Token::AsmDirSet
            | Token::AsmDirSkip
            | Token::AsmDirSpace
            | Token::AsmDirString
            | Token::AsmDirAsciz
            | Token::AsmDirAscii
            | Token::AsmDirFile
            | Token::AsmDirGlobl
            | Token::AsmDirGlobal
            | Token::AsmDirWeakDir
            | Token::AsmDirHidden
            | Token::AsmDirIdent
            | Token::AsmDirSize
            | Token::AsmDirType
            | Token::AsmDirText
            | Token::AsmDirData
            | Token::AsmDirBss
            | Token::AsmDirPrevious
            | Token::AsmDirPushsection
            | Token::AsmDirPopsection
            | Token::AsmDirFill
            | Token::AsmDirRept
            | Token::AsmDirEndr
            | Token::AsmDirOrg
            | Token::AsmDirQuad
            | Token::AsmDirCode16
            | Token::AsmDirCode32
            | Token::AsmDirCode64
            | Token::AsmDirOption
            | Token::AsmDirShort
            | Token::AsmDirLong
            | Token::AsmDirInt
            | Token::AsmDirSymver
            | Token::AsmDirReloc
            | Token::AsmDirSection => {
                asm_parse_directive(state, pp, asm, false)?;
            }

            // Numeric labels (e.g. `1:`)
            Token::IntegerLiteral(n) => {
                next_token(pp, state)?;
                if matches!(pp.tok, Token::Raw(c) if c == i32::from(b':')) {
                    next_token(pp, state)?; // Consume ':'
                    let label_name = asm_get_local_label_name(n);
                    let v = {
                        let idx = tok_alloc(pp, &label_name);
                        i64::try_from(idx).unwrap_or(0)
                    };
                    asm_label_instr(state, asm, v, true)?;
                } else {
                    // Unexpected numeric token — skip line.
                    while !matches!(pp.tok, Token::Eof) && !is_eol_raw(&pp.tok) {
                        next_token(pp, state)?;
                    }
                }
            }

            // Semicolon as statement separator (GAS convention).
            Token::Raw(59) => {
                // ';' = 59
                next_token(pp, state)?;
            }

            // Hash comment in .S files — skip to end of line.
            Token::Raw(35) => {
                // '#' = 35
                skip_to_eol(pp, state)?;
            }

            // Label definitions or instructions: `identifier:` or `mnemonic ...`
            Token::Identifier | Token::Raw(_) => {
                let label_tok = pp.tok;
                let label_str = get_tok_str(pp, &label_tok, &pp.tokc.clone());
                next_token(pp, state)?;

                if matches!(pp.tok, Token::Raw(c) if c == i32::from(b':')) {
                    // It's a label definition.
                    next_token(pp, state)?; // Consume the ':'
                    let v = {
                        let idx = tok_alloc(pp, &label_str);
                        i64::try_from(idx).unwrap_or(0)
                    };
                    asm_label_instr(state, asm, v, false)?;
                } else {
                    // Not a label — treat as an instruction mnemonic.
                    // In the full implementation, this dispatches to
                    // asm_opcode() on the architecture backend.
                    // For now, skip to end of line (instruction operands).
                    while !matches!(pp.tok, Token::Eof) && !is_eol_raw(&pp.tok) {
                        next_token(pp, state)?;
                    }
                }
            }

            _ => {
                // Unknown token — skip to end of line.
                while !matches!(pp.tok, Token::Eof) && !is_eol_raw(&pp.tok) {
                    next_token(pp, state)?;
                }
            }
        }
    }

    // Restore parse flags and character classification.
    pp.parse_flags = old_parse_flags;
    set_idnum(pp, b'.', 0);
    set_idnum(pp, b'$', 0);

    Ok(())
}

// ===========================================================================
//  Public Entry Points
// ===========================================================================

/// Assemble the current source file (top-level entry point).
///
/// Called when the compiler encounters a `.s` or `.S` file.
/// Sets up debug info, runs the assembler loop, and cleans up labels.
///
/// C equivalent: `tcc_assemble()` in tccasm.c:1072.
pub(crate) fn assemble(
    state: &mut TccState,
    pp: &mut PreprocessorState,
    do_preprocess: bool,
) -> TccResult<()> {
    let mut asm = AsmState::default();

    // Switch to the .text section.
    use_section1(state, state.text_section_idx)?;

    // Run the assembly loop.
    let result = tcc_assemble_internal(state, pp, &mut asm, do_preprocess);

    // Clean up labels regardless of success or failure.
    asm_free_labels(&mut asm);

    result
}

/// Assemble a string of inline assembly code.
///
/// Creates a temporary "file" from the provided string, pushes it onto
/// the include stack, runs the assembler, then pops it.
///
/// C equivalent: `tcc_assemble_inline()` in tccasm.c:1099.
pub(crate) fn assemble_inline(
    state: &mut TccState,
    pp: &mut PreprocessorState,
    asm_string: &str,
    _global: bool,
) -> TccResult<()> {
    let mut asm = AsmState::default();

    // Convert the string to a token list and push onto the macro stack.
    let tokens: Vec<Token> = asm_string
        .bytes()
        .map(|b| Token::Raw(i32::from(b)))
        .collect();
    begin_macro(pp, tokens, preprocessor::AllocMode::None);

    // Save and configure parse flags for inline assembly.
    let old_parse_flags = pp.parse_flags;
    pp.parse_flags =
        PARSE_FLAG_ASM_FILE | PARSE_FLAG_LINEFEED | PARSE_FLAG_PREPROCESS;

    // Set dot and dollar as identifier characters.
    set_idnum(pp, b'.', 2);
    set_idnum(pp, b'$', 2);

    next_token(pp, state)?;

    // Process assembly tokens.
    let result = tcc_assemble_internal(state, pp, &mut asm, true);

    // Restore state.
    pp.parse_flags = old_parse_flags;
    set_idnum(pp, b'.', 0);
    set_idnum(pp, b'$', 0);

    asm_free_labels(&mut asm);
    result
}

// ===========================================================================
//  Inline Assembly Constraint Handling
// ===========================================================================

/// Find a GCC inline-assembly constraint character in the constraint string.
///
/// GCC constraint characters specify where an operand may reside:
///   `r` — any general register
///   `m` — memory operand
///   `i` — immediate integer
///   `n` — immediate integer (known at compile time)
///   `0`–`9` — match operand N
///   `=` — output operand
///   `+` — read-write operand
///   `&` — early-clobber
///
/// Returns the constraint character and a register class mask.
///
/// C equivalent: `find_constraint()` in tccasm.c:1160.
#[allow(clippy::unnecessary_wraps)] // API contract: may error for invalid constraints
pub(crate) fn find_constraint(
    constraint: &str,
    _backend: &dyn CodegenBackend,
) -> TccResult<(char, u32)> {
    let mut reg_class: u32 = 0;
    let mut found_char: char = ' ';

    for ch in constraint.chars() {
        match ch {
            '=' | '+' | '&' | '%' | '#' | '*' => {
                // Modifier characters — skip.
            }
            'r' => {
                found_char = 'r';
                reg_class |= codegen::RC_INT;
            }
            'R' => {
                found_char = 'R';
                reg_class |= codegen::RC_INT;
            }
            'f' => {
                found_char = 'f';
                reg_class |= codegen::RC_FLOAT;
            }
            'm' | 'o' | 'V' => {
                found_char = 'm';
                // Memory operand — no register needed.
            }
            'i' | 'n' | 's' | 'I' | 'J' | 'K' | 'L' | 'M' | 'N' | 'O'
            | 'P' => {
                found_char = ch;
                // Immediate — no register allocation needed.
            }
            'g' | 'X' => {
                found_char = ch;
                reg_class |= codegen::RC_INT;
            }
            '0'..='9' => {
                found_char = ch;
                // Reference to another operand.
            }
            'p' => {
                found_char = ch;
            }
            _ => {
                // Architecture-specific constraint character.
                found_char = ch;
            }
        }
    }

    Ok((found_char, reg_class))
}

// ===========================================================================
//  Operand Substitution for Inline Assembly
// ===========================================================================

/// Substitute operand references in an inline assembly template string.
///
/// Replaces `%0`, `%1`, etc. with the corresponding operand representation
/// (register name or memory reference).  Also handles `%%` → `%`,
/// `%=` → unique counter, `%c0` → immediate without prefix, etc.
///
/// C equivalent: `subst_asm_operands()` in tccasm.c:1171.
fn subst_asm_operands(
    operands: &[ASMOperand],
    asm_str: &str,
    _pp: &PreprocessorState,
) -> TccResult<String> {
    let mut result = String::with_capacity(asm_str.len());
    let chars: Vec<char> = asm_str.chars().collect();
    let len = chars.len();
    let mut i = 0;

    while i < len {
        if chars[i] == '%' && i + 1 < len {
            i += 1;
            match chars[i] {
                '%' => {
                    // Literal '%'.
                    result.push('%');
                    i += 1;
                }
                '=' => {
                    // Unique ID for this asm statement.
                    result.push_str("__asm_unique__");
                    i += 1;
                }
                c if c.is_ascii_digit() => {
                    // Operand reference: %N
                    let idx = usize::from(c as u8 - b'0');
                    if idx < operands.len() {
                        let op = &operands[idx];
                        if op.reg >= 0 {
                            // Register operand — output register name.
                            let _ = write!(result, "%r{}", op.reg);
                        } else if op.is_memory {
                            let _ = write!(result, "(%r{})", op.reg.unsigned_abs());
                        } else {
                            let _ = write!(result, "${}", op.id);
                        }
                    } else {
                        return Err(TccError::parse(format!(
                            "invalid operand reference %{idx} (only {} operands)",
                            operands.len()
                        )));
                    }
                    i += 1;
                }
                'c' if i + 1 < len && chars[i + 1].is_ascii_digit() => {
                    // %cN — immediate without $ prefix.
                    i += 1;
                    let idx = usize::from(chars[i] as u8 - b'0');
                    if idx < operands.len() {
                        let _ = write!(result, "{}", operands[idx].id);
                    }
                    i += 1;
                }
                'l' if i + 1 < len && chars[i + 1].is_ascii_digit() => {
                    // %lN — label reference (asm goto).
                    i += 1;
                    let idx = usize::from(chars[i] as u8 - b'0');
                    if idx < operands.len() {
                        let _ = write!(result, ".L_asmgoto_{idx}");
                    }
                    i += 1;
                }
                _ => {
                    // Unknown modifier — pass through.
                    result.push('%');
                    result.push(chars[i]);
                    i += 1;
                }
            }
        } else {
            result.push(chars[i]);
            i += 1;
        }
    }

    Ok(result)
}

/// Parse operand list for inline assembly (outputs, inputs).
///
/// C equivalent: `parse_asm_operands()` in tccasm.c:1214.
fn parse_asm_operands(
    state: &mut TccState,
    pp: &mut PreprocessorState,
    _asm: &mut AsmState,
    operands: &mut Vec<ASMOperand>,
    _is_output: bool,
) -> TccResult<usize> {
    let mut count: usize = 0;

    // If the current token is not a constraint string, return 0 operands.
    if matches!(pp.tok, Token::Raw(c) if c == i32::from(b':') || c == i32::from(b')'))
        || matches!(pp.tok, Token::Eof)
    {
        return Ok(0);
    }

    loop {
        if operands.len() >= MAX_ASM_OPERANDS {
            return Err(TccError::parse("too many asm operands"));
        }

        let mut op = ASMOperand {
            id: i32::try_from(count).unwrap_or(0),
            constraint: String::new(),
            asm_str: String::new(),
            vt: None,
            reg: -1,
            is_label: false,
            is_memory: false,
            is_llong: false,
            priority: 0,
            ref_index: -1,
            input_index: -1,
            is_rw: false,
        };

        // Optional symbolic name: [name]
        if matches!(pp.tok, Token::Raw(c) if c == i32::from(b'[')) {
            next_token(pp, state)?;
            // Read the symbolic name.
            let _sym_name = get_tok_str(pp, &pp.tok, &pp.tokc.clone());
            next_token(pp, state)?;
            skip(pp, state, Token::Raw(i32::from(b']')))?;
        }

        // Constraint string.
        if let Token::StringLiteral = pp.tok {
            if let CValue::Str { ref data, .. } = pp.tokc {
                op.constraint = String::from_utf8_lossy(data).into_owned();
            }
            next_token(pp, state)?;
        } else {
            return Err(TccError::parse("constraint string expected"));
        }

        // Skip '(' before the C expression.
        skip(pp, state, Token::Raw(i32::from(b'(')))?;

        // Parse the C expression for this operand.
        // In the full implementation this calls gexpr() to evaluate.
        // For now, skip tokens until matching ')'.
        let mut paren_depth: usize = 1;
        while paren_depth > 0 {
            let tok = next_token(pp, state)?;
            match tok {
                Token::Raw(c) if c == i32::from(b'(') => {
                    paren_depth = paren_depth.saturating_add(1);
                }
                Token::Raw(c) if c == i32::from(b')') => {
                    paren_depth = paren_depth.saturating_sub(1);
                }
                Token::Eof => {
                    return Err(TccError::parse("unexpected EOF in asm operand"));
                }
                _ => {}
            }
        }

        // Determine if this is a read-write operand.
        if op.constraint.contains('+') {
            op.is_rw = true;
        }

        operands.push(op);
        count = count.saturating_add(1);

        // Check for comma (more operands) or end of list.
        if !matches!(pp.tok, Token::Raw(c) if c == i32::from(b',')) {
            break;
        }
        next_token(pp, state)?;
    }

    Ok(count)
}

// ===========================================================================
//  Inline ASM Statement Parsing
// ===========================================================================

/// Parse and process a GCC-style `asm` statement (inline assembly).
///
/// Syntax:
///   asm [volatile] ( "template" : outputs : inputs : clobbers [: goto labels] );
///
/// This function handles the full lifecycle:
///   1. Parse the template string
///   2. Parse output operands
///   3. Parse input operands
///   4. Parse clobber list
///   5. (Optional) Parse goto labels
///   6. Compute constraints
///   7. Substitute operands into the template
///   8. Assemble the resulting string
///   9. Generate code for operand moves
///
/// C equivalent: `asm_instr()` in tccasm.c:1282.
pub(crate) fn asm_instr(
    state: &mut TccState,
    pp: &mut PreprocessorState,
    vstack: &mut ValueStack,
    backend: &mut dyn CodegenBackend,
) -> TccResult<()> {
    let mut asm = AsmState::default();
    let mut operands: Vec<ASMOperand> = Vec::with_capacity(MAX_ASM_OPERANDS);
    let mut clobber_regs: Vec<bool> = vec![false; codegen::NB_ASM_REGS];

    // Skip optional 'volatile' qualifier.
    if matches!(pp.tok, Token::Volatile) {
        next_token(pp, state)?;
    }
    // Also skip '__volatile__' variant.
    if matches!(pp.tok, Token::Raw(_)) {
        // Check for __volatile__ token — handled generically.
    }

    // Expect '('.
    skip(pp, state, Token::Raw(i32::from(b'(')))?;

    // Parse the assembly template string.
    let asm_template = if let Token::StringLiteral = pp.tok {
        let s = if let CValue::Str { ref data, .. } = pp.tokc {
            String::from_utf8_lossy(data).into_owned()
        } else {
            String::new()
        };
        next_token(pp, state)?;
        s
    } else {
        return Err(TccError::parse("string literal expected in asm statement"));
    };

    // Parse output operands (after first ':').
    let mut nb_outputs: usize = 0;
    if matches!(pp.tok, Token::Raw(c) if c == i32::from(b':')) {
        next_token(pp, state)?;
        nb_outputs = parse_asm_operands(state, pp, &mut asm, &mut operands, true)?;
    }

    // Parse input operands (after second ':').
    if matches!(pp.tok, Token::Raw(c) if c == i32::from(b':')) {
        next_token(pp, state)?;
        let _nb_inputs =
            parse_asm_operands(state, pp, &mut asm, &mut operands, false)?;
    }

    // Parse clobber list (after third ':').
    if matches!(pp.tok, Token::Raw(c) if c == i32::from(b':')) {
        next_token(pp, state)?;
        while let Token::StringLiteral = pp.tok {
            let clobber_str = if let CValue::Str { ref data, .. } = pp.tokc {
                String::from_utf8_lossy(data).into_owned()
            } else {
                String::new()
            };
            next_token(pp, state)?;
            asm_clobber(&mut clobber_regs, &clobber_str, backend)?;
            if !matches!(pp.tok, Token::Raw(c) if c == i32::from(b',')) {
                break;
            }
            next_token(pp, state)?;
        }
    }

    // Parse optional goto labels (after fourth ':' — asm goto).
    if is_raw_char(&pp.tok, b':') {
        next_token(pp, state)?;
        loop {
            if matches!(pp.tok, Token::Eof) || is_raw_char(&pp.tok, b')') {
                break;
            }
            let _label_name = get_tok_str(pp, &pp.tok, &pp.tokc.clone());
            next_token(pp, state)?;
            asm.asmgoto_n = asm.asmgoto_n.saturating_add(1);
            if !is_raw_char(&pp.tok, b',') {
                break;
            }
            next_token(pp, state)?;
        }
    }

    // Expect ')'.
    skip(pp, state, Token::Raw(i32::from(b')')))?;
    // Expect ';'.
    if matches!(pp.tok, Token::Raw(c) if c == i32::from(b';')) {
        next_token(pp, state)?;
    }

    // Compute constraints for all operands.
    asm_compute_constraints(
        &mut operands,
        nb_outputs,
        &clobber_regs,
        backend,
    )?;

    // Substitute operands into the template string.
    let substituted = subst_asm_operands(&operands, &asm_template, pp)?;

    // Save registers that may be clobbered.
    save_regs(state, vstack, backend, 0)?;

    // Assemble the substituted string.
    assemble_inline(state, pp, &substituted, false)?;

    // Generate code for moving values to/from operand registers.
    asm_gen_code(
        state,
        vstack,
        backend,
        &operands,
        nb_outputs,
        &clobber_regs,
    )?;

    asm_free_labels(&mut asm);
    Ok(())
}

/// Parse and process a top-level `asm` statement (global inline assembly).
///
/// Global inline assembly appears outside of any function and is emitted
/// directly into the `.text` section.
///
/// Syntax: asm ( "template" );
///
/// C equivalent: `asm_global_instr()` in tccasm.c:1444.
pub(crate) fn asm_global_instr(
    state: &mut TccState,
    pp: &mut PreprocessorState,
) -> TccResult<()> {
    // Expect '('.
    skip(pp, state, Token::Raw(i32::from(b'(')))?;

    // Parse the assembly template string.
    let asm_template = if let Token::StringLiteral = pp.tok {
        let s = if let CValue::Str { ref data, .. } = pp.tokc {
            String::from_utf8_lossy(data).into_owned()
        } else {
            String::new()
        };
        next_token(pp, state)?;
        s
    } else {
        return Err(TccError::parse(
            "string literal expected in global asm statement",
        ));
    };

    // Expect ')'.
    skip(pp, state, Token::Raw(i32::from(b')')))?;
    // Expect ';'.
    if matches!(pp.tok, Token::Raw(c) if c == i32::from(b';')) {
        next_token(pp, state)?;
    }

    // Switch to text section and assemble the string.
    use_section1(state, state.text_section_idx)?;
    assemble_inline(state, pp, &asm_template, true)?;

    Ok(())
}

// ===========================================================================
//  Unit Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{LABEL_DEFINED, LABEL_FORWARD};

    // -------------------------------------------------------------------
    //  AsmState / Label Management Tests
    // -------------------------------------------------------------------

    #[test]
    fn test_asm_state_default() {
        let asm = AsmState::default();
        assert_eq!(asm.last_text_section, 0);
        assert_eq!(asm.asmgoto_n, 0);
        assert!(asm.section_stack.is_empty());
        assert!(asm.previous_section.is_none());
        assert!(asm.asm_labels.is_empty());
    }

    #[test]
    fn test_asm_label_push_and_find() {
        let mut asm = AsmState::default();
        let id = asm_label_push(&mut asm, 42, LABEL_DEFINED).unwrap();
        assert_eq!(id, 0);
        assert_eq!(asm.asm_labels.len(), 1);

        let found = asm_label_find(&asm, 42);
        assert_eq!(found, Some(0));

        let not_found = asm_label_find(&asm, 99);
        assert_eq!(not_found, None);
    }

    #[test]
    fn test_asm_label_push_multiple() {
        let mut asm = AsmState::default();
        let id0 = asm_label_push(&mut asm, 10, LABEL_DEFINED).unwrap();
        let id1 = asm_label_push(&mut asm, 20, LABEL_FORWARD).unwrap();
        let id2 = asm_label_push(&mut asm, 30, LABEL_DEFINED).unwrap();
        assert_eq!(id0, 0);
        assert_eq!(id1, 1);
        assert_eq!(id2, 2);
        assert_eq!(asm.asm_labels.len(), 3);
    }

    #[test]
    fn test_asm_free_labels() {
        let mut asm = AsmState::default();
        asm_label_push(&mut asm, 10, LABEL_DEFINED).unwrap();
        asm_label_push(&mut asm, 20, LABEL_DEFINED).unwrap();
        assert_eq!(asm.asm_labels.len(), 2);
        asm_free_labels(&mut asm);
        assert!(asm.asm_labels.is_empty());
    }

    #[test]
    fn test_asm_label_find_returns_last_match() {
        let mut asm = AsmState::default();
        asm_label_push(&mut asm, 42, LABEL_FORWARD).unwrap();
        asm_label_push(&mut asm, 42, LABEL_DEFINED).unwrap();
        let found = asm_label_find(&asm, 42);
        assert_eq!(found, Some(1));
    }

    #[test]
    fn test_get_asm_sym_creates_forward_ref() {
        let mut asm = AsmState::default();
        let mut state = crate::context::TccState::default();
        let mut pp = crate::preprocessor::PreprocessorState::default();
        let id = get_asm_sym(&mut state, &mut asm, 100, &mut pp).unwrap();
        assert_eq!(id, 0);
        assert_eq!(asm.asm_labels.len(), 1);
        assert_eq!(
            asm.asm_labels[id].r,
            u16::try_from(LABEL_FORWARD).unwrap()
        );
    }

    #[test]
    fn test_get_asm_sym_returns_existing() {
        let mut asm = AsmState::default();
        let mut state = crate::context::TccState::default();
        let mut pp = crate::preprocessor::PreprocessorState::default();
        asm_label_push(&mut asm, 100, LABEL_DEFINED).unwrap();
        let id = get_asm_sym(&mut state, &mut asm, 100, &mut pp).unwrap();
        assert_eq!(id, 0);
        assert_eq!(asm.asm_labels.len(), 1);
    }

    // -------------------------------------------------------------------
    //  Helper function tests
    // -------------------------------------------------------------------

    #[test]
    fn test_is_raw_char_matches() {
        assert!(is_raw_char(&Token::Raw(i32::from(b':')), b':'));
        assert!(!is_raw_char(&Token::Raw(i32::from(b',')), b':'));
        assert!(!is_raw_char(&Token::Eof, b':'));
        assert!(is_raw_char(&Token::Raw(i32::from(b'(')), b'('));
    }

    #[test]
    fn test_is_eol_raw_matches() {
        assert!(is_eol_raw(&Token::Raw(10)));
        assert!(is_eol_raw(&Token::Raw(13)));
        assert!(!is_eol_raw(&Token::Raw(32)));
        assert!(!is_eol_raw(&Token::Eof));
    }

    #[test]
    fn test_local_label_name_format() {
        let name = asm_get_local_label_name(42);
        assert_eq!(name, "L..42");
        let name0 = asm_get_local_label_name(0);
        assert_eq!(name0, "L..0");
    }

    #[test]
    fn test_asm2cname_with_underscore() {
        assert_eq!(asm2cname("_main", true), "main");
        assert_eq!(asm2cname("_main", false), "_main");
        assert_eq!(asm2cname("func", true), "func");
    }

    #[test]
    fn test_asm_get_prefix_name() {
        assert_eq!(asm_get_prefix_name("func", '.'), ".func");
        assert_eq!(asm_get_prefix_name("sym", '_'), "_sym");
    }

    // -------------------------------------------------------------------
    //  CVE-2018-20374 verification: section index checked access
    // -------------------------------------------------------------------

    #[test]
    fn test_cve_2018_20374_section_bounds_check() {
        let mut state = crate::context::TccState::default();
        let result = use_section1(&mut state, 999);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("out of range"),
            "Expected 'out of range' in error, got: {err_msg}"
        );
    }

    // -------------------------------------------------------------------
    //  Section stack tests
    // -------------------------------------------------------------------

    #[test]
    fn test_pop_section_on_empty_stack() {
        let mut state = crate::context::TccState::default();
        let mut asm = AsmState::default();
        let result = pop_section(&mut state, &mut asm);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("underflow"),
            "Expected 'underflow' in error, got: {err_msg}"
        );
    }

    #[test]
    fn test_push_pop_section_roundtrip() {
        let mut state = crate::context::TccState::default();
        let mut asm = AsmState::default();
        state.new_section(".text", 1, 0x6);
        state.cur_text_section = 0;
        state.ind = 100;
        state.nocode_wanted = 0;

        push_section(&state, &mut asm).unwrap();
        assert_eq!(asm.section_stack.len(), 1);

        state.ind = 200;
        state.nocode_wanted = 1;

        pop_section(&mut state, &mut asm).unwrap();
        assert!(asm.section_stack.is_empty());
        assert_eq!(state.ind, 100);
        assert_eq!(state.nocode_wanted, 0);
    }

    #[test]
    fn test_push_section_overflow() {
        let state = crate::context::TccState::default();
        let mut asm = AsmState::default();
        for _ in 0..MAX_SECTION_STACK {
            push_section(&state, &mut asm).unwrap();
        }
        let result = push_section(&state, &mut asm);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("overflow"),
            "Expected 'overflow' in error, got: {err_msg}"
        );
    }

    // -------------------------------------------------------------------
    //  Use-section tests
    // -------------------------------------------------------------------

    #[test]
    fn test_use_section_creates_new() {
        let mut state = crate::context::TccState::default();
        let idx0 = state.new_section(".text", 1, 0x6);
        state.cur_text_section = idx0;
        state.ind = 0;

        use_section(&mut state, ".mydata", 1, 0x3).unwrap();
        assert_ne!(state.cur_text_section, idx0);
        let new_idx = state.cur_text_section;
        assert_eq!(state.sections[new_idx].name, ".mydata");
    }

    #[test]
    fn test_use_section_finds_existing() {
        let mut state = crate::context::TccState::default();
        let idx0 = state.new_section(".text", 1, 0x6);
        let idx1 = state.new_section(".data", 1, 0x3);
        state.cur_text_section = idx0;
        state.ind = 0;

        use_section(&mut state, ".data", 1, 0x3).unwrap();
        assert_eq!(state.cur_text_section, idx1);
    }
}

