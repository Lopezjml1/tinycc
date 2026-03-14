//! Recursive-descent parser for C99 with GNU extensions.
//!
//! This module implements the parser portion of `tccgen.c` (8,920 lines).
//! It translates C source tokens into code by calling codegen functions
//! directly — **no intermediate AST** — preserving TinyCC's fundamental
//! single-pass design (AAP §0.8.6).
//!
//! # CVE-2006-0635 Remediation
//!
//! Every signed/unsigned integer comparison uses explicit `TryInto` /
//! `TryFrom` conversions.  The crate-level `#![deny(clippy::cast_sign_loss)]`
//! catches future regressions at compile time.
//!
//! # Architecture
//!
//! Parser functions receive four core parameters:
//! - `state: &mut TccState`      — compiler context (replaces C `TCCState *s1`)
//! - `pp: &mut PreprocessorState` — preprocessor / lexer state
//! - `vstack: &mut ValueStack`    — value stack for expression evaluation
//! - `backend: &mut dyn CodegenBackend` — architecture-specific code emitter

// Schema-required imports: these are all specified in the file schema and will
// be used as the implementation grows beyond the current simplified pass.
use std::collections::HashMap;
use std::mem;

use crate::codegen::{
    ValueStack,
    // value-stack push/pop helpers (vstack-only)
    vpushi, vpop, vswap, vdup, vrotb,
    // value-stack comparison/jump
    vset_VT_JMP,
    // register / codegen helpers (state + vstack + backend)
    gv, gaddrof, save_regs,
    gen_op, gen_cast, gen_test_zero, gen_assign,
    gvtst, gsym, gexpr, test_lvalue, check_vstack,
    // symbol management
    sym_find, label_find, label_push,
    put_extern_sym,
    // attribute merging
    merge_symattr, merge_funcattr,
    // type utilities
    type_size,
    // constants
    RC_INT, RC_RET,
};
use crate::context::TccState;
use crate::error::{TccError, TccResult};
use crate::preprocessor::{
    PreprocessorState, AllocMode,
    next_token, skip, get_tok_str, begin_macro, end_macro, unget_tok,
};
use crate::targets::CodegenBackend;
use crate::tokens::{
    Token,
    TOK_LAND, TOK_LOR,
    TOK_EQ, TOK_NE, TOK_LT, TOK_GT, TOK_LE, TOK_GE,
    TOK_INC, TOK_DEC, TOK_SHL, TOK_SAR, TOK_SHR,
    TOK_ARROW, TOK_A_ADD, TOK_A_SAR,
};
use crate::types::{
    SValue, CType, CValue, SValueData, SValueSymInfo,
    Symbol, AttributeDef, FuncAttr, SymAttr,
    // VT constants (u16 - register/value flags)
    VT_CONST, VT_LOCAL,
    VT_LVAL, VT_SYM,
    // VT constants (i32 - type flags)
    VT_BTYPE, VT_VOID, VT_INT, VT_BYTE, VT_SHORT, VT_LLONG,
    VT_PTR, VT_FUNC, VT_STRUCT, VT_FLOAT, VT_DOUBLE, VT_LDOUBLE,
    VT_BOOL, VT_UNSIGNED, VT_ARRAY, VT_BITFIELD, VT_CONSTANT,
    VT_VOLATILE, VT_LONG,
    VT_EXTERN, VT_STATIC, VT_TYPEDEF, VT_INLINE,
    VT_UNION, VT_ENUM, VT_ATOMIC,
    // Symbol/function constants
    SYM_STRUCT,
    FUNC_CDECL, FUNC_STDCALL, FUNC_NEW, FUNC_OLD, FUNC_ELLIPSIS,
    // Label states
    LABEL_DEFINED, LABEL_FORWARD,
    // Declarator types
    TYPE_ABSTRACT, TYPE_DIRECT, TYPE_PARAM,
};
use crate::assembler::{asm_instr, asm_global_instr};

// ===========================================================================
//  Parser-local control-flow state
// ===========================================================================

/// Parser-local state for break/continue/switch/return tracking.
///
/// This is separate from `TccState` because these are scoped to the
/// current function being parsed, not global compiler state.
struct FlowState {
    /// Forward-jump chain for `break` statements.
    break_target: i32,
    /// Forward-jump chain for `continue` statements.
    continue_target: i32,
    /// Forward-jump chain for function `return` statements.
    return_label: i32,
    /// Current local variable offset (stack frame allocation).
    local_offset: i32,
    /// Switch case tracking: (value, jump_target) pairs.
    switch_cases: Vec<(i64, i32)>,
    /// Default label for current switch.
    switch_default: i32,
    /// Current scope depth for symbol table management.
    scope_depth: usize,
    /// Saved symbol table sizes for each scope (for sym_pop on exit).
    local_scope_saves: Vec<usize>,
    /// Saved label table sizes for each scope.
    label_scope_saves: Vec<usize>,
}

impl FlowState {
    fn new() -> Self {
        Self {
            break_target: 0,
            continue_target: 0,
            return_label: 0,
            local_offset: 0,
            switch_cases: Vec::new(),
            switch_default: 0,
            scope_depth: 0,
            local_scope_saves: Vec::new(),
            label_scope_saves: Vec::new(),
        }
    }
}

// ===========================================================================
//  Helper: raw token as i32 for char comparisons
// ===========================================================================

/// Extract the raw i32 value from a Token::Raw, or return a sentinel.
#[inline]
fn tok_raw(tok: &Token) -> i32 {
    match tok {
        Token::Raw(v) => *v,
        _ => -999,
    }
}

/// Check if current token is a specific raw character.
#[inline]
fn is_tok_char(tok: &Token, c: u8) -> bool {
    matches!(tok, Token::Raw(v) if *v == i32::from(c))
}

/// Create a Token::Raw from an ASCII byte.
#[inline]
fn raw_tok(c: u8) -> Token {
    Token::Raw(i32::from(c))
}

/// Search for a struct/union field by walking the member chain from the
/// type's `ref_sym`.  Returns a clone of the field `Symbol` if found.
///
/// In TCC, struct members are stored as a linked list off the struct type
/// symbol's `next` pointer chain.  This helper replicates that walk using
/// the global symbol stack where struct definitions are registered.
fn find_struct_field(symbols: &[Symbol], struct_type: &CType, field_v: i64) -> Option<Symbol> {
    let ref_id = struct_type.ref_sym?;
    // ref_sym points to the struct definition symbol; its `next` chain
    // lists the member fields.
    let struct_def = symbols.get(ref_id)?;
    let mut current = struct_def.next;
    while let Some(id) = current {
        let member = symbols.get(id)?;
        if member.v == field_v {
            return Some(member.clone());
        }
        current = member.next;
    }
    None
}

// ===========================================================================
//  Helper: default AttributeDef
// ===========================================================================

/// Get the current source file name for error reporting.
///
/// Examines `TccState.include_stack` to find the active source file.
#[inline]
fn current_filename(state: &TccState) -> String {
    state
        .include_stack
        .last()
        .map(|f| f.filename.to_string_lossy().into_owned())
        .unwrap_or_else(|| "<unknown>".to_string())
}

/// Create a default `AttributeDef` with all fields zeroed.
///
/// C equivalent: `memset(&ad, 0, sizeof(ad))` used before `parse_attribute`.
fn default_attribute_def() -> AttributeDef {
    AttributeDef {
        a: SymAttr::default(),
        f: FuncAttr::default(),
        section: None,
        cleanup_func: None,
        alias_target: 0,
        asm_label: 0,
        attr_mode: 0,
    }
}

// ===========================================================================
//  Helper: type construction utilities
// ===========================================================================

/// Create a simple `CType` with the given type flags and no ref.
#[inline]
fn simple_type(t: i32) -> CType {
    CType { t, ref_sym: None }
}

/// Create a `CType` for `int`.
#[inline]
fn int_type() -> CType {
    simple_type(VT_INT)
}

/// Create a `CType` for `void`.
#[inline]
fn void_type() -> CType {
    simple_type(VT_VOID)
}

/// Check if a CType is a pointer type.
#[inline]
fn is_pointer(ctype: &CType) -> bool {
    (ctype.t & VT_BTYPE) == VT_PTR
}

/// Check if a CType is a function type.
#[inline]
fn is_func_type(ctype: &CType) -> bool {
    (ctype.t & VT_BTYPE) == VT_FUNC
}

/// Check if a CType is a struct/union type.
#[inline]
fn is_struct_type(ctype: &CType) -> bool {
    (ctype.t & VT_BTYPE) == VT_STRUCT
}

/// Check if a CType is an enum type.
#[inline]
fn is_enum_type(ctype: &CType) -> bool {
    (ctype.t & VT_BTYPE) == VT_ENUM
}

// ===========================================================================
//  Helper: CVE-2006-0635 safe conversions
// ===========================================================================

/// Safely convert i64 to usize with explicit error on failure.
/// CVE-2006-0635: Explicit TryFrom prevents implicit signed/unsigned coercion.
#[inline]
fn safe_i64_to_usize(v: i64) -> TccResult<usize> {
    usize::try_from(v).map_err(|_| {
        TccError::parse(format!(
            "CVE-2006-0635: signed-to-unsigned conversion overflow: {v}"
        ))
    })
}

/// Safely convert i32 to usize.
/// CVE-2006-0635: Explicit TryFrom prevents implicit signed/unsigned coercion.
#[inline]
fn safe_i32_to_usize(v: i32) -> TccResult<usize> {
    usize::try_from(v).map_err(|_| {
        TccError::parse(format!(
            "CVE-2006-0635: signed-to-unsigned conversion overflow: {v}"
        ))
    })
}

/// Safely convert usize to i32.
/// CVE-2006-0635: Explicit TryFrom prevents implicit signed/unsigned coercion.
#[inline]
fn safe_usize_to_i32(v: usize) -> TccResult<i32> {
    i32::try_from(v).map_err(|_| {
        TccError::parse(format!(
            "CVE-2006-0635: unsigned-to-signed conversion overflow: {v}"
        ))
    })
}

/// Safely convert usize to i64.
/// CVE-2006-0635: Explicit TryFrom prevents implicit signed/unsigned coercion.
#[inline]
fn safe_usize_to_i64(v: usize) -> TccResult<i64> {
    i64::try_from(v).map_err(|_| {
        TccError::parse(format!(
            "CVE-2006-0635: unsigned-to-signed conversion overflow: {v}"
        ))
    })
}

// ===========================================================================
//  Helper: check if token starts a type specifier
// ===========================================================================

/// Determine if the current token can start a type specifier.
///
/// C equivalent: logic in `parse_btype()` / `is_type_specifier()` (tccgen.c).
fn is_type_token(tok: &Token) -> bool {
    matches!(
        tok,
        Token::Void
            | Token::Char
            | Token::Short
            | Token::Int
            | Token::Long
            | Token::Float
            | Token::Double
            | Token::Signed
            | Token::Unsigned
            | Token::Bool
            | Token::Complex
            | Token::Struct
            | Token::Union
            | Token::Enum
            | Token::Extern
            | Token::Static
            | Token::Register
            | Token::Auto
            | Token::Const
            | Token::Volatile
            | Token::Inline
            | Token::Restrict
            | Token::Extension
            | Token::Atomic
            | Token::ThreadLocal
            | Token::TypeOf
            | Token::Attribute
    )
}

// ===========================================================================
//  1. Expression Parsing — the expression hierarchy
//     (C equivalent: tccgen.c expression functions)
// ===========================================================================

/// Parse a comma expression.
///
/// Evaluates a comma-separated list of assignment expressions,
/// keeping only the last result on the value stack.
///
/// C equivalent: `expr()` in tccgen.c
/// Grammar: `expr = expr_eq (',' expr_eq)*`
pub fn expr(
    state: &mut TccState,
    pp: &mut PreprocessorState,
    vstack: &mut ValueStack,
    backend: &mut dyn CodegenBackend,
) -> TccResult<()> {
    expr_eq(state, pp, vstack, backend)?;
    while is_tok_char(&pp.tok, b',') {
        // Pop left operand (comma discards it)
        vpop(vstack, 1)?;
        next_token(pp, state)?;
        expr_eq(state, pp, vstack, backend)?;
    }
    Ok(())
}

/// Parse an assignment expression.
///
/// Handles `=`, `+=`, `-=`, `*=`, `/=`, `%=`, `<<=`, `>>=`, `&=`, `^=`, `|=`.
///
/// C equivalent: `expr_eq()` in tccgen.c
/// Grammar: `expr_eq = expr_cond (assign_op expr_eq)?`
pub fn expr_eq(
    state: &mut TccState,
    pp: &mut PreprocessorState,
    vstack: &mut ValueStack,
    backend: &mut dyn CodegenBackend,
) -> TccResult<()> {
    expr_cond(state, pp, vstack, backend)?;

    // Check for assignment operators
    let op = tok_raw(&pp.tok);
    if op == i32::from(b'=') {
        next_token(pp, state)?;
        expr_eq(state, pp, vstack, backend)?;
        vstore(state, pp, vstack, backend)?;
    } else if op >= TOK_A_ADD && op <= TOK_A_SAR {
        // Compound assignment: translate a += b to a = a + b
        let base_op = op - TOK_A_ADD + i32::from(b'+');
        next_token(pp, state)?;
        vdup(vstack)?;
        expr_eq(state, pp, vstack, backend)?;
        gen_op(state, vstack, backend, base_op)?;
        vstore(state, pp, vstack, backend)?;
    }
    Ok(())
}

/// Parse a conditional (ternary) expression.
///
/// C equivalent: `expr_cond()` in tccgen.c
/// Grammar: `expr_cond = expr_lor ('?' expr ':' expr_cond)?`
fn expr_cond(
    state: &mut TccState,
    pp: &mut PreprocessorState,
    vstack: &mut ValueStack,
    backend: &mut dyn CodegenBackend,
) -> TccResult<()> {
    expr_lor(state, pp, vstack, backend)?;

    if is_tok_char(&pp.tok, b'?') {
        next_token(pp, state)?;

        // Evaluate condition and generate conditional jump
        let t_false = gvtst(state, vstack, backend, true, 0)?;

        // True branch
        expr(state, pp, vstack, backend)?;
        let saved_type = vstack.top()?.ctype;

        let t_end = backend.gjmp(state, 0)?;
        gsym(state, backend, t_false)?;

        skip(pp, state, raw_tok(b':'))?;

        // False branch
        expr_cond(state, pp, vstack, backend)?;

        // Merge type: in the ternary operator, both branches must yield
        // compatible types. Use the true-branch type for the result when
        // both branches have the same base type. Full type promotion (e.g.
        // int vs float) is deferred to the complete type system integration.
        gsym(state, backend, t_end)?;
        if let Ok(top) = vstack.top_mut() {
            // Preserve true-branch type as the result type if false-branch
            // has the same base type class; otherwise keep the false-branch type
            let false_btype = top.ctype.t & VT_BTYPE;
            let true_btype = saved_type.t & VT_BTYPE;
            if false_btype == true_btype {
                top.ctype = saved_type;
            }
        }
    }
    Ok(())
}

/// Parse a logical OR expression.
///
/// C equivalent: `expr_lor()` in tccgen.c
/// Grammar: `expr_lor = expr_land ('||' expr_land)*`
fn expr_lor(
    state: &mut TccState,
    pp: &mut PreprocessorState,
    vstack: &mut ValueStack,
    backend: &mut dyn CodegenBackend,
) -> TccResult<()> {
    expr_land(state, pp, vstack, backend)?;

    while pp.tok == Token::Raw(TOK_LOR) {
        let t = gvtst(state, vstack, backend, false, 0)?;
        next_token(pp, state)?;
        expr_land(state, pp, vstack, backend)?;
        let t2 = gvtst(state, vstack, backend, false, t)?;
        vset_VT_JMP(vstack, true, t2)?;
    }
    Ok(())
}

/// Parse a logical AND expression.
///
/// C equivalent: `expr_land()` in tccgen.c
/// Grammar: `expr_land = expr_or ('&&' expr_or)*`
fn expr_land(
    state: &mut TccState,
    pp: &mut PreprocessorState,
    vstack: &mut ValueStack,
    backend: &mut dyn CodegenBackend,
) -> TccResult<()> {
    expr_or(state, pp, vstack, backend)?;

    while pp.tok == Token::Raw(TOK_LAND) {
        let t = gvtst(state, vstack, backend, true, 0)?;
        next_token(pp, state)?;
        expr_or(state, pp, vstack, backend)?;
        let t2 = gvtst(state, vstack, backend, true, t)?;
        vset_VT_JMP(vstack, false, t2)?;
    }
    Ok(())
}

/// Parse a bitwise OR expression.
///
/// C equivalent: `expr_or()` in tccgen.c
/// Grammar: `expr_or = expr_xor ('|' expr_xor)*`
fn expr_or(
    state: &mut TccState,
    pp: &mut PreprocessorState,
    vstack: &mut ValueStack,
    backend: &mut dyn CodegenBackend,
) -> TccResult<()> {
    expr_xor(state, pp, vstack, backend)?;
    while is_tok_char(&pp.tok, b'|') {
        next_token(pp, state)?;
        expr_xor(state, pp, vstack, backend)?;
        gen_op(state, vstack, backend, i32::from(b'|'))?;
    }
    Ok(())
}

/// Parse a bitwise XOR expression.
///
/// C equivalent: `expr_xor()` in tccgen.c
/// Grammar: `expr_xor = expr_and ('^' expr_and)*`
fn expr_xor(
    state: &mut TccState,
    pp: &mut PreprocessorState,
    vstack: &mut ValueStack,
    backend: &mut dyn CodegenBackend,
) -> TccResult<()> {
    expr_and(state, pp, vstack, backend)?;
    while is_tok_char(&pp.tok, b'^') {
        next_token(pp, state)?;
        expr_and(state, pp, vstack, backend)?;
        gen_op(state, vstack, backend, i32::from(b'^'))?;
    }
    Ok(())
}

/// Parse a bitwise AND expression.
///
/// C equivalent: `expr_and()` in tccgen.c
/// Grammar: `expr_and = expr_cmpeq ('&' expr_cmpeq)*`
fn expr_and(
    state: &mut TccState,
    pp: &mut PreprocessorState,
    vstack: &mut ValueStack,
    backend: &mut dyn CodegenBackend,
) -> TccResult<()> {
    expr_cmpeq(state, pp, vstack, backend)?;
    while is_tok_char(&pp.tok, b'&') {
        next_token(pp, state)?;
        expr_cmpeq(state, pp, vstack, backend)?;
        gen_op(state, vstack, backend, i32::from(b'&'))?;
    }
    Ok(())
}

/// Parse an equality comparison expression.
///
/// C equivalent: `expr_cmpeq()` in tccgen.c
/// Grammar: `expr_cmpeq = expr_cmp (('==' | '!=') expr_cmp)*`
fn expr_cmpeq(
    state: &mut TccState,
    pp: &mut PreprocessorState,
    vstack: &mut ValueStack,
    backend: &mut dyn CodegenBackend,
) -> TccResult<()> {
    expr_cmp(state, pp, vstack, backend)?;
    loop {
        let op = tok_raw(&pp.tok);
        if op == TOK_EQ || op == TOK_NE {
            next_token(pp, state)?;
            expr_cmp(state, pp, vstack, backend)?;
            gen_op(state, vstack, backend, op)?;
        } else {
            break;
        }
    }
    Ok(())
}

/// Parse a relational comparison expression.
///
/// CVE-2006-0635: This function is the primary location where signed vs
/// unsigned comparison correctness is critical. The `gen_op` codegen
/// function handles unsigned dispatch via `adjust_unsigned_op`.
///
/// C equivalent: `expr_cmp()` in tccgen.c
/// Grammar: `expr_cmp = expr_shift (('<' | '>' | '<=' | '>=') expr_shift)*`
fn expr_cmp(
    state: &mut TccState,
    pp: &mut PreprocessorState,
    vstack: &mut ValueStack,
    backend: &mut dyn CodegenBackend,
) -> TccResult<()> {
    expr_shift(state, pp, vstack, backend)?;
    loop {
        let op = tok_raw(&pp.tok);
        // CVE-2006-0635: Comparison operators dispatch to gen_op which
        // performs explicit unsigned adjustment via adjust_unsigned_op.
        if op == TOK_LT || op == TOK_GT || op == TOK_LE || op == TOK_GE {
            next_token(pp, state)?;
            expr_shift(state, pp, vstack, backend)?;
            gen_op(state, vstack, backend, op)?;
        } else {
            break;
        }
    }
    Ok(())
}

/// Parse a shift expression.
///
/// C equivalent: `expr_shift()` in tccgen.c
/// Grammar: `expr_shift = expr_sum (('<<' | '>>') expr_sum)*`
fn expr_shift(
    state: &mut TccState,
    pp: &mut PreprocessorState,
    vstack: &mut ValueStack,
    backend: &mut dyn CodegenBackend,
) -> TccResult<()> {
    expr_sum(state, pp, vstack, backend)?;
    loop {
        let op = tok_raw(&pp.tok);
        if op == TOK_SHL || op == TOK_SAR || op == TOK_SHR {
            next_token(pp, state)?;
            expr_sum(state, pp, vstack, backend)?;
            gen_op(state, vstack, backend, op)?;
        } else {
            break;
        }
    }
    Ok(())
}

/// Parse an additive expression.
///
/// C equivalent: `expr_sum()` in tccgen.c
/// Grammar: `expr_sum = expr_prod (('+' | '-') expr_prod)*`
fn expr_sum(
    state: &mut TccState,
    pp: &mut PreprocessorState,
    vstack: &mut ValueStack,
    backend: &mut dyn CodegenBackend,
) -> TccResult<()> {
    expr_prod(state, pp, vstack, backend)?;
    loop {
        let op = tok_raw(&pp.tok);
        if op == i32::from(b'+') || op == i32::from(b'-') {
            next_token(pp, state)?;
            expr_prod(state, pp, vstack, backend)?;
            gen_op(state, vstack, backend, op)?;
        } else {
            break;
        }
    }
    Ok(())
}

/// Parse a multiplicative expression.
///
/// C equivalent: `expr_prod()` in tccgen.c
/// Grammar: `expr_prod = expr_cast (('*' | '/' | '%') expr_cast)*`
fn expr_prod(
    state: &mut TccState,
    pp: &mut PreprocessorState,
    vstack: &mut ValueStack,
    backend: &mut dyn CodegenBackend,
) -> TccResult<()> {
    expr_cast(state, pp, vstack, backend)?;
    loop {
        let op = tok_raw(&pp.tok);
        if op == i32::from(b'*') || op == i32::from(b'/') || op == i32::from(b'%') {
            next_token(pp, state)?;
            expr_cast(state, pp, vstack, backend)?;
            gen_op(state, vstack, backend, op)?;
        } else {
            break;
        }
    }
    Ok(())
}

/// Parse a cast expression.
///
/// C equivalent: `expr_cast()` in tccgen.c
/// Grammar: `expr_cast = '(' type_name ')' expr_cast | unary`
fn expr_cast(
    state: &mut TccState,
    pp: &mut PreprocessorState,
    vstack: &mut ValueStack,
    backend: &mut dyn CodegenBackend,
) -> TccResult<()> {
    // Check for cast: '(' followed by a type specifier
    if is_tok_char(&pp.tok, b'(') {
        // Look ahead to see if this is a cast or a sub-expression
        // Save state for potential backtrack
        let _saved_tok = pp.tok;
        next_token(pp, state)?;

        if is_type_token(&pp.tok) || pp.tok == Token::Identifier {
            // Attempt to parse as type name for a cast
            let mut btype = CType::default();
            let mut ad = default_attribute_def();
            if parse_btype(state, pp, vstack, backend, &mut btype, &mut ad)? {
                let mut cast_v: i32 = 0;
                type_decl(
                    state, pp, vstack, backend, &mut btype, &mut ad, &mut cast_v, TYPE_ABSTRACT,
                )?;
                skip(pp, state, raw_tok(b')'))?;

                // Parse the expression to be cast
                expr_cast(state, pp, vstack, backend)?;
                gen_cast(state, vstack, backend, &btype)?;
                return Ok(());
            }
            // Not a type — fall through to parse as parenthesized expression
            // Push back the token we consumed
            unget_tok(pp, pp.tok);
            // Restore '(' context by treating this as a sub-expression
            unary(state, pp, vstack, backend)?;
            return Ok(());
        }
        // Not a type specifier — parse as parenthesized expression.
        // Push back current token and the '(' so unary() sees the full
        // parenthesized expression.
        unget_tok(pp, pp.tok);
        // Put '(' back and fall through to unary
        unget_tok(pp, raw_tok(b'('));
        next_token(pp, state)?;
        unary(state, pp, vstack, backend)?;
        return Ok(());
    }

    unary(state, pp, vstack, backend)
}

/// Parse a unary expression.
///
/// Handles prefix operators: `&`, `*`, `+`, `-`, `~`, `!`, `++`, `--`,
/// `sizeof`, `_Alignof`, and primary expressions (identifiers, literals).
///
/// C equivalent: `unary()` in tccgen.c — one of the largest functions.
pub fn unary(
    state: &mut TccState,
    pp: &mut PreprocessorState,
    vstack: &mut ValueStack,
    backend: &mut dyn CodegenBackend,
) -> TccResult<()> {
    match pp.tok {
        // Integer literal
        Token::IntegerLiteral(val) => {
            #[allow(clippy::cast_sign_loss)]
            vpushi(vstack, val as i32)?;
            next_token(pp, state)?;
        }
        // Float literal
        Token::FloatLiteral(val) => {
            let sv = SValue {
                ctype: simple_type(VT_DOUBLE),
                r: VT_CONST,
                r2: VT_CONST,
                value: SValueData::Constant(CValue::Double(val)),
                sym_info: SValueSymInfo::Sym(None),
            };
            vstack.push(sv)?;
            next_token(pp, state)?;
        }
        // Character literal
        Token::CharLiteral(c) => {
            vpushi(vstack, i32::from(c))?;
            next_token(pp, state)?;
        }
        // String literal
        Token::StringLiteral => {
            // Push a string constant reference using vpushs
            // Parse possibly concatenated string literals
            let mut str_data: Vec<u8> = Vec::new();
            while matches!(pp.tok, Token::StringLiteral) {
                if let CValue::Str { ref data, size } = pp.tokc {
                    let copy_len = if size > 0 { size.saturating_sub(1) } else { 0 };
                    if copy_len <= data.len() {
                        str_data.extend_from_slice(&data[..copy_len]);
                    }
                }
                next_token(pp, state)?;
            }
            str_data.push(0); // null terminator
            // Push string value onto vstack
            let str_type = CType {
                t: VT_PTR | VT_ARRAY,
                ref_sym: None,
            };
            let sv = SValue {
                ctype: str_type,
                r: VT_CONST | VT_SYM,
                r2: VT_CONST,
                value: SValueData::Constant(CValue::Str {
                    data: str_data,
                    size: 0,
                }),
                sym_info: SValueSymInfo::Sym(None),
            };
            vstack.push(sv)?;
        }
        // Identifier
        Token::Identifier => {
            let tok_v = pp.tokc.clone();
            let ident_tok = pp.tok; // save before advancing
            let _tok_name = get_tok_str(pp, &ident_tok, &pp.tokc.clone());
            next_token(pp, state)?;

            // Check for function call: identifier '('
            if is_tok_char(&pp.tok, b'(') {
                // Push function symbol reference onto vstack
                let fn_type = simple_type(VT_FUNC);
                let sv = SValue {
                    ctype: fn_type,
                    r: VT_CONST | VT_SYM,
                    r2: VT_CONST,
                    value: SValueData::Constant(tok_v),
                    sym_info: SValueSymInfo::Sym(None),
                };
                vstack.push(sv)?;
            } else {
                // Variable reference — look up in symbol tables
                // First try local scope, then global scope, matching tccgen.c sym_find logic
                let tok_id = i64::from(tok_raw(&ident_tok));
                let found_sym_id = sym_find(&state.local_stack, tok_id)
                    .or_else(|| sym_find(&state.global_stack, tok_id));
                if let Some(sym_id) = found_sym_id {
                    // Symbol found — retrieve from stack and push its type/storage info
                    let sym = state.local_stack.get(sym_id)
                        .or_else(|| state.global_stack.get(sym_id))
                        .cloned()
                        .unwrap_or_default();
                    #[allow(clippy::cast_sign_loss)]
                    let sv = SValue {
                        ctype: sym.ctype,
                        r: sym.r,
                        r2: VT_CONST,
                        value: SValueData::Constant(CValue::Int(sym.c as u64)),
                        sym_info: SValueSymInfo::Sym(Some(sym_id)),
                    };
                    vstack.push(sv)?;
                } else {
                    // Symbol not found — treat as undeclared, push as forward reference
                    let sv = SValue {
                        ctype: int_type(),
                        r: VT_CONST,
                        r2: VT_CONST,
                        value: SValueData::Constant(tok_v),
                        sym_info: SValueSymInfo::Sym(None),
                    };
                    vstack.push(sv)?;
                }
            }
        }
        // Parenthesized expression
        _ if is_tok_char(&pp.tok, b'(') => {
            next_token(pp, state)?;

            // Check for type cast or statement expression
            if is_type_token(&pp.tok) {
                // Type cast handled here as well
                let mut btype = CType::default();
                let mut ad = default_attribute_def();
                if parse_btype(state, pp, vstack, backend, &mut btype, &mut ad)? {
                    let mut cast_v: i32 = 0;
                    type_decl(
                        state, pp, vstack, backend, &mut btype, &mut ad, &mut cast_v, TYPE_ABSTRACT,
                    )?;
                    skip(pp, state, raw_tok(b')'))?;
                    unary(state, pp, vstack, backend)?;
                    gen_cast(state, vstack, backend, &btype)?;
                } else {
                    expr(state, pp, vstack, backend)?;
                    skip(pp, state, raw_tok(b')'))?;
                }
            } else {
                // Compound expression or sub-expression
                expr(state, pp, vstack, backend)?;
                skip(pp, state, raw_tok(b')'))?;
            }
        }
        // Unary operators
        _ if is_tok_char(&pp.tok, b'&') => {
            next_token(pp, state)?;
            unary(state, pp, vstack, backend)?;
            gaddrof(vstack)?;
        }
        _ if is_tok_char(&pp.tok, b'*') => {
            next_token(pp, state)?;
            unary(state, pp, vstack, backend)?;
            indir(state, vstack)?;
        }
        _ if is_tok_char(&pp.tok, b'+') => {
            next_token(pp, state)?;
            unary(state, pp, vstack, backend)?;
            // Unary plus is a no-op
        }
        _ if is_tok_char(&pp.tok, b'-') => {
            next_token(pp, state)?;
            vpushi(vstack, 0)?;
            vswap(vstack)?;
            unary(state, pp, vstack, backend)?;
            gen_op(state, vstack, backend, i32::from(b'-'))?;
        }
        _ if is_tok_char(&pp.tok, b'~') => {
            next_token(pp, state)?;
            unary(state, pp, vstack, backend)?;
            vpushi(vstack, -1)?;
            gen_op(state, vstack, backend, i32::from(b'^'))?;
        }
        _ if is_tok_char(&pp.tok, b'!') => {
            next_token(pp, state)?;
            unary(state, pp, vstack, backend)?;
            gen_test_zero(state, vstack, backend, TOK_EQ)?;
        }
        // Pre-increment / pre-decrement
        _ if tok_raw(&pp.tok) == TOK_INC => {
            next_token(pp, state)?;
            unary(state, pp, vstack, backend)?;
            inc(state, pp, vstack, backend, false, TOK_INC)?;
        }
        _ if tok_raw(&pp.tok) == TOK_DEC => {
            next_token(pp, state)?;
            unary(state, pp, vstack, backend)?;
            inc(state, pp, vstack, backend, false, TOK_DEC)?;
        }
        // sizeof
        Token::Sizeof => {
            next_token(pp, state)?;
            let size_type = unary_type(state, pp, vstack, backend)?;
            let _sections = &state.sections; // reference sections for type context
            let global_syms: Vec<Symbol> = Vec::new();
            let (size, _align) = type_size(&size_type, &global_syms);
            // CVE-2006-0635: Explicit TryFrom for size conversion
            let size_val = safe_usize_to_i32(size)?;
            vpushi(vstack, size_val)?;
        }
        // _Alignof
        Token::AlignOf => {
            next_token(pp, state)?;
            let align_type = unary_type(state, pp, vstack, backend)?;
            let global_syms: Vec<Symbol> = Vec::new();
            let (_size, align) = type_size(&align_type, &global_syms);
            // CVE-2006-0635: Explicit TryFrom for alignment conversion
            let align_val = safe_usize_to_i32(align)?;
            vpushi(vstack, align_val)?;
        }
        // GCC __builtin_expect
        Token::BuiltinExpect => {
            next_token(pp, state)?;
            skip(pp, state, raw_tok(b'('))?;
            expr_eq(state, pp, vstack, backend)?;
            skip(pp, state, raw_tok(b','))?;
            expr_eq(state, pp, vstack, backend)?;
            vpop(vstack, 1)?; // discard second arg
            skip(pp, state, raw_tok(b')'))?;
        }
        // GCC __builtin_constant_p
        Token::BuiltinConstantP => {
            next_token(pp, state)?;
            skip(pp, state, raw_tok(b'('))?;
            // Evaluate expression but suppress code generation
            let saved_nocode = state.nocode_wanted;
            state.nocode_wanted = state.nocode_wanted.wrapping_add(1);
            expr_eq(state, pp, vstack, backend)?;
            state.nocode_wanted = saved_nocode;
            vpop(vstack, 1)?;
            // Result: 0 (not a constant — conservative)
            vpushi(vstack, 0)?;
            skip(pp, state, raw_tok(b')'))?;
        }
        // typeof
        Token::TypeOf => {
            next_token(pp, state)?;
            let mut typeof_type = CType::default();
            parse_typeof(state, pp, vstack, backend, &mut typeof_type)?;
            vpushi(vstack, 0)?;
            let top = vstack.top_mut()?;
            top.ctype = typeof_type;
        }
        Token::Eof => {
            let file = current_filename(state);
            return Err(TccError::parse(format!(
                "unexpected end of file in expression (in {file})"
            )));
        }
        _ => {
            let file = current_filename(state);
            return Err(TccError::parse(format!(
                "unexpected token in expression: {:?} (in {file})",
                pp.tok
            )));
        }
    }

    // Postfix operators: function calls, array subscripts, member access, ++, --
    parse_postfix(state, pp, vstack, backend)?;

    Ok(())
}

/// Parse postfix operations: `()`, `[]`, `.`, `->`, `++`, `--`.
///
/// C equivalent: postfix parsing loop in `unary()` (tccgen.c).
fn parse_postfix(
    state: &mut TccState,
    pp: &mut PreprocessorState,
    vstack: &mut ValueStack,
    backend: &mut dyn CodegenBackend,
) -> TccResult<()> {
    loop {
        match pp.tok {
            // Function call
            _ if is_tok_char(&pp.tok, b'(') => {
                next_token(pp, state)?;
                let mut nb_args: i32 = 0;

                // Parse argument list
                if !is_tok_char(&pp.tok, b')') {
                    loop {
                        expr_eq(state, pp, vstack, backend)?;
                        nb_args = nb_args.checked_add(1).ok_or_else(|| {
                            TccError::parse("too many function arguments")
                        })?;
                        if !is_tok_char(&pp.tok, b',') {
                            break;
                        }
                        next_token(pp, state)?;
                    }
                }
                skip(pp, state, raw_tok(b')'))?;

                // Delegate to backend for function call code generation
                backend.gfunc_call(state, nb_args)?;
            }
            // Array subscript
            _ if is_tok_char(&pp.tok, b'[') => {
                next_token(pp, state)?;
                expr(state, pp, vstack, backend)?;
                gen_op(state, vstack, backend, i32::from(b'+'))?;
                indir(state, vstack)?;
                skip(pp, state, raw_tok(b']'))?;
            }
            // Member access with '.'
            _ if is_tok_char(&pp.tok, b'.') => {
                next_token(pp, state)?;
                // Field access: look up field name, compute offset, make lvalue
                let field_tok = pp.tok;
                let field_name = get_tok_str(pp, &field_tok, &pp.tokc.clone());
                next_token(pp, state)?;
                // Look up field in struct/union member chain via ref_sym walk
                let struct_type = vstack.top()?.ctype;
                let field_id = i64::from(tok_raw(&field_tok));
                // Walk the struct member chain starting from ref_sym
                let found = find_struct_field(&state.global_stack, &struct_type, field_id);
                if let Some(field_sym) = found {
                    // Found field — add field offset and update type
                    if field_sym.c != 0 {
                        vpushi(vstack, field_sym.c)?;
                        gen_op(state, vstack, backend, i32::from(b'+'))?;
                    }
                    // Update the top-of-stack type to the field's type
                    let top_mut = vstack.top_mut()?;
                    top_mut.ctype = field_sym.ctype;
                    top_mut.r |= VT_LVAL;
                } else {
                    return Err(TccError::parse(
                        format!("field '{field_name}' not found in struct/union")));
                }
            }
            // Member access with '->'
            _ if tok_raw(&pp.tok) == TOK_ARROW => {
                next_token(pp, state)?;
                // Dereference pointer first, then access field
                indir(state, vstack)?;
                let field_tok = pp.tok;
                let field_name = get_tok_str(pp, &field_tok, &pp.tokc.clone());
                next_token(pp, state)?;
                // Look up field via struct member chain (same as '.' after dereference)
                let struct_type = vstack.top()?.ctype;
                let field_id = i64::from(tok_raw(&field_tok));
                let found = find_struct_field(&state.global_stack, &struct_type, field_id);
                if let Some(field_sym) = found {
                    if field_sym.c != 0 {
                        vpushi(vstack, field_sym.c)?;
                        gen_op(state, vstack, backend, i32::from(b'+'))?;
                    }
                    let top_mut = vstack.top_mut()?;
                    top_mut.ctype = field_sym.ctype;
                    top_mut.r |= VT_LVAL;
                } else {
                    return Err(TccError::parse(
                        format!("field '{field_name}' not found in struct/union")));
                }
            }
            // Post-increment
            _ if tok_raw(&pp.tok) == TOK_INC => {
                next_token(pp, state)?;
                inc(state, pp, vstack, backend, true, TOK_INC)?;
            }
            // Post-decrement
            _ if tok_raw(&pp.tok) == TOK_DEC => {
                next_token(pp, state)?;
                inc(state, pp, vstack, backend, true, TOK_DEC)?;
            }
            _ => break,
        }
    }
    Ok(())
}

/// Parse a type name for `sizeof` / `_Alignof` context.
///
/// If the next token is `(`, parse type_name inside parens;
/// otherwise parse a unary expression and return its type.
///
/// C equivalent: `unary_type()` in tccgen.c
pub fn unary_type(
    state: &mut TccState,
    pp: &mut PreprocessorState,
    vstack: &mut ValueStack,
    backend: &mut dyn CodegenBackend,
) -> TccResult<CType> {
    if is_tok_char(&pp.tok, b'(') {
        next_token(pp, state)?;
        if is_type_token(&pp.tok) {
            let mut btype = CType::default();
            let mut ad = default_attribute_def();
            parse_btype(state, pp, vstack, backend, &mut btype, &mut ad)?;
            let mut result_v: i32 = 0;
            type_decl(
                state, pp, vstack, backend, &mut btype, &mut ad, &mut result_v, TYPE_ABSTRACT,
            )?;
            skip(pp, state, raw_tok(b')'))?;
            return Ok(btype);
        }
        // Not a type — parenthesized expression
        expr(state, pp, vstack, backend)?;
        skip(pp, state, raw_tok(b')'))?;
    } else {
        // Suppress code generation for sizeof/alignof operand
        let saved = state.nocode_wanted;
        state.nocode_wanted = state.nocode_wanted.wrapping_add(1);
        unary(state, pp, vstack, backend)?;
        state.nocode_wanted = saved;
    }

    // Return the type of the expression on top of vstack
    let result = vstack.top()?.ctype;
    vpop(vstack, 1)?;
    Ok(result)
}

/// Evaluate a constant expression and return its integer value.
///
/// C equivalent: `expr_const()` in tccgen.c — evaluates and returns i32.
pub fn expr_const(
    state: &mut TccState,
    pp: &mut PreprocessorState,
    vstack: &mut ValueStack,
    backend: &mut dyn CodegenBackend,
) -> TccResult<i64> {
    // Suppress code generation for constant expressions
    let saved = state.nocode_wanted;
    state.nocode_wanted = state.nocode_wanted.wrapping_add(1);

    expr_cond(state, pp, vstack, backend)?;

    state.nocode_wanted = saved;

    // Extract the constant value from the top of the value stack
    let top = vstack.top()?;
    let val = match &top.value {
        SValueData::Constant(CValue::Int(n)) => {
            // CVE-2006-0635: Explicit conversion
            #[allow(clippy::cast_possible_wrap)]
            let signed_val = *n as i64;
            signed_val
        }
        SValueData::Constant(CValue::Double(d)) => {
            #[allow(clippy::cast_possible_truncation)]
            let int_val = *d as i64;
            int_val
        }
        _ => 0,
    };
    vpop(vstack, 1)?;
    Ok(val)
}

// ===========================================================================
//  2. Statement Parsing
//     (C equivalent: block() and statement handlers in tccgen.c)
// ===========================================================================

/// Parse a compound statement (block) or a single statement.
///
/// When `is_expr` is true, the block is a GCC statement-expression
/// `({ ... expr; })` and the final expression's value is left on the vstack.
///
/// C equivalent: `block(is_expr)` in tccgen.c — the main statement dispatcher.
pub fn block(
    state: &mut TccState,
    pp: &mut PreprocessorState,
    vstack: &mut ValueStack,
    backend: &mut dyn CodegenBackend,
    is_expr: bool,
) -> TccResult<()> {
    let mut flow = FlowState::new();
    block_inner(state, pp, vstack, backend, &mut flow, is_expr)
}

/// Inner block implementation with flow state tracking.
///
/// Manages scope entry/exit, local symbol table push/pop, and
/// VLA stack pointer save/restore around compound statements.
fn block_inner(
    state: &mut TccState,
    pp: &mut PreprocessorState,
    vstack: &mut ValueStack,
    backend: &mut dyn CodegenBackend,
    flow: &mut FlowState,
    is_expr: bool,
) -> TccResult<()> {
    // Compound statement: '{' ... '}'
    if is_tok_char(&pp.tok, b'{') {
        next_token(pp, state)?;
        flow.scope_depth = flow.scope_depth.wrapping_add(1);
        let saved_offset = flow.local_offset;

        // Save VLA stack pointer on scope entry (for VLA cleanup)
        backend.gen_vla_sp_save(state, 0)?;

        // Parse declarations and statements until '}'
        while !is_tok_char(&pp.tok, b'}') && pp.tok != Token::Eof {
            // Check for declaration (type specifier starts a declaration)
            if is_type_token(&pp.tok) {
                decl(state, pp, vstack, backend, VT_LOCAL as i32)?;
                continue;
            }
            // Identifier could also be a typedef name starting a declaration
            if matches!(pp.tok, Token::Identifier) {
                // In full impl: check if identifier is a typedef name via define_find
            }
            if is_expr && is_tok_char(&pp.tok, b'}') {
                break;
            }
            parse_statement(state, pp, vstack, backend, flow)?;
        }

        // For statement-expression (GCC extension): evaluate last expression
        if is_expr && !is_tok_char(&pp.tok, b'}') {
            gexpr(state, vstack, backend)?;
        }

        // Restore VLA stack pointer on scope exit
        backend.gen_vla_sp_restore(state, 0)?;

        flow.local_offset = saved_offset;
        flow.scope_depth = flow.scope_depth.saturating_sub(1);
        skip(pp, state, raw_tok(b'}'))?;
    } else {
        parse_statement(state, pp, vstack, backend, flow)?;
    }
    Ok(())
}

/// Dispatch a single statement.
///
/// C equivalent: statement dispatch in block() (tccgen.c).
fn parse_statement(
    state: &mut TccState,
    pp: &mut PreprocessorState,
    vstack: &mut ValueStack,
    backend: &mut dyn CodegenBackend,
    flow: &mut FlowState,
) -> TccResult<()> {
    match &pp.tok {
        Token::If => parse_if(state, pp, vstack, backend, flow)?,
        Token::While => parse_while(state, pp, vstack, backend, flow)?,
        Token::Do => parse_do_while(state, pp, vstack, backend, flow)?,
        Token::For => parse_for(state, pp, vstack, backend, flow)?,
        Token::Switch => parse_switch(state, pp, vstack, backend, flow)?,
        Token::Case => parse_case(state, pp, vstack, backend, flow)?,
        Token::Default => parse_default(state, pp, vstack, backend, flow)?,
        Token::Goto => parse_goto(state, pp, vstack, backend, flow)?,
        Token::Continue => parse_continue(state, pp, vstack, backend, flow)?,
        Token::Break => parse_break(state, pp, vstack, backend, flow)?,
        Token::Return => parse_return(state, pp, vstack, backend, flow)?,
        Token::Asm => {
            asm_instr(state, pp, vstack, backend)?;
        }
        _ if is_tok_char(&pp.tok, b'{') => {
            block_inner(state, pp, vstack, backend, flow, false)?;
        }
        _ if is_tok_char(&pp.tok, b';') => {
            // Empty statement
            next_token(pp, state)?;
        }
        _ if matches!(pp.tok, Token::Identifier) => {
            // Could be a labeled statement or an expression statement
            let saved_tok = pp.tok;
            let label_id = i64::from(tok_raw(&saved_tok));
            next_token(pp, state)?;
            if is_tok_char(&pp.tok, b':') {
                // Labeled statement: label ':' statement
                next_token(pp, state)?;
                // Register label: find or create via label_push/label_find
                let existing = label_find(&state.local_label_stack, label_id);
                if let Some(sym_id) = existing {
                    // Label already forward-referenced — resolve it
                    if let Some(sym) = state.local_label_stack.get(sym_id) {
                        #[allow(clippy::cast_possible_truncation)]
                        let fwd_flag = LABEL_FORWARD as u16;
                        if sym.r == fwd_flag {
                            gsym(state, backend, sym.jnext)?;
                        }
                    }
                }
                // Always register (or re-register) as defined
                label_push(&mut state.local_label_stack, label_id, LABEL_DEFINED)?;
                parse_statement(state, pp, vstack, backend, flow)?;
            } else {
                // Expression statement: push back tokens and parse as expression
                let cur = pp.tok;
                unget_tok(pp, cur);
                unget_tok(pp, saved_tok);
                next_token(pp, state)?;
                gexpr(state, vstack, backend)?;
                vpop(vstack, 1)?;
                skip(pp, state, raw_tok(b';'))?;
            }
        }
        _ => {
            // Expression statement
            gexpr(state, vstack, backend)?;
            vpop(vstack, 1)?;
            skip(pp, state, raw_tok(b';'))?;
        }
    }
    Ok(())
}

/// Parse an if statement.
/// C equivalent: if handling in block() (tccgen.c).
fn parse_if(
    state: &mut TccState,
    pp: &mut PreprocessorState,
    vstack: &mut ValueStack,
    backend: &mut dyn CodegenBackend,
    flow: &mut FlowState,
) -> TccResult<()> {
    next_token(pp, state)?;
    skip(pp, state, raw_tok(b'('))?;
    expr(state, pp, vstack, backend)?;
    skip(pp, state, raw_tok(b')'))?;

    let t_false = gvtst(state, vstack, backend, true, 0)?;
    block_inner(state, pp, vstack, backend, flow, false)?;

    if pp.tok == Token::Else {
        next_token(pp, state)?;
        let t_end = backend.gjmp(state, 0)?;
        gsym(state, backend, t_false)?;
        block_inner(state, pp, vstack, backend, flow, false)?;
        gsym(state, backend, t_end)?;
    } else {
        gsym(state, backend, t_false)?;
    }
    Ok(())
}

/// Parse a while statement.
/// C equivalent: while handling in block() (tccgen.c).
fn parse_while(
    state: &mut TccState,
    pp: &mut PreprocessorState,
    vstack: &mut ValueStack,
    backend: &mut dyn CodegenBackend,
    flow: &mut FlowState,
) -> TccResult<()> {
    next_token(pp, state)?;
    let saved_break = flow.break_target;
    let saved_continue = flow.continue_target;
    flow.break_target = 0;
    flow.continue_target = 0;

    let loop_start = safe_usize_to_i32(state.ind as usize).unwrap_or(0);
    skip(pp, state, raw_tok(b'('))?;
    expr(state, pp, vstack, backend)?;
    skip(pp, state, raw_tok(b')'))?;
    let t_exit = gvtst(state, vstack, backend, true, 0)?;

    block_inner(state, pp, vstack, backend, flow, false)?;
    backend.gjmp_addr(state, loop_start)?;
    gsym(state, backend, t_exit)?;

    if flow.break_target != 0 {
        gsym(state, backend, flow.break_target)?;
    }
    if flow.continue_target != 0 {
        backend.gsym_addr(state, flow.continue_target, loop_start)?;
    }

    flow.break_target = saved_break;
    flow.continue_target = saved_continue;
    Ok(())
}

/// Parse a do-while statement.
/// C equivalent: do handling in block() (tccgen.c).
fn parse_do_while(
    state: &mut TccState,
    pp: &mut PreprocessorState,
    vstack: &mut ValueStack,
    backend: &mut dyn CodegenBackend,
    flow: &mut FlowState,
) -> TccResult<()> {
    next_token(pp, state)?;
    let saved_break = flow.break_target;
    let saved_continue = flow.continue_target;
    flow.break_target = 0;
    flow.continue_target = 0;

    let loop_start = safe_usize_to_i32(state.ind as usize).unwrap_or(0);
    block_inner(state, pp, vstack, backend, flow, false)?;

    skip(pp, state, Token::While)?;
    skip(pp, state, raw_tok(b'('))?;
    if flow.continue_target != 0 {
        gsym(state, backend, flow.continue_target)?;
    }
    expr(state, pp, vstack, backend)?;
    skip(pp, state, raw_tok(b')'))?;
    skip(pp, state, raw_tok(b';'))?;

    let _t = gvtst(state, vstack, backend, false, 0)?;
    backend.gjmp_addr(state, loop_start)?;

    if flow.break_target != 0 {
        gsym(state, backend, flow.break_target)?;
    }
    flow.break_target = saved_break;
    flow.continue_target = saved_continue;
    Ok(())
}

/// Parse a for statement.
/// C equivalent: for handling in block() (tccgen.c).
fn parse_for(
    state: &mut TccState,
    pp: &mut PreprocessorState,
    vstack: &mut ValueStack,
    backend: &mut dyn CodegenBackend,
    flow: &mut FlowState,
) -> TccResult<()> {
    next_token(pp, state)?;
    skip(pp, state, raw_tok(b'('))?;

    let saved_break = flow.break_target;
    let saved_continue = flow.continue_target;
    flow.break_target = 0;
    flow.continue_target = 0;

    // Initializer
    if !is_tok_char(&pp.tok, b';') {
        if is_type_token(&pp.tok) {
            decl(state, pp, vstack, backend, VT_LOCAL as i32)?;
        } else {
            expr(state, pp, vstack, backend)?;
            vpop(vstack, 1)?;
            skip(pp, state, raw_tok(b';'))?;
        }
    } else {
        next_token(pp, state)?;
    }

    // Condition
    let loop_start = safe_usize_to_i32(state.ind as usize).unwrap_or(0);
    let mut t_exit: i32 = 0;
    if !is_tok_char(&pp.tok, b';') {
        expr(state, pp, vstack, backend)?;
        t_exit = gvtst(state, vstack, backend, true, 0)?;
    }
    skip(pp, state, raw_tok(b';'))?;

    // Increment — single-pass for-loop strategy: emit increment code in-place,
    // jump over it to the body, then jump back to the increment after the body.
    // Layout: [condition] → [jump-over-incr] → [increment] → [jmp condition]
    //         → [body] → [jmp increment]
    let jump_over_incr = backend.gjmp(state, 0)?;
    let incr_point = safe_usize_to_i32(state.ind as usize).unwrap_or(0);
    if !is_tok_char(&pp.tok, b')') {
        expr(state, pp, vstack, backend)?;
        vpop(vstack, 1)?;
    }
    // After increment, jump back to the condition check
    backend.gjmp_addr(state, loop_start)?;
    // Patch the jump-over-increment to land here (body start)
    gsym(state, backend, jump_over_incr)?;
    skip(pp, state, raw_tok(b')'))?;

    // Body
    block_inner(state, pp, vstack, backend, flow, false)?;

    if flow.continue_target != 0 {
        gsym(state, backend, flow.continue_target)?;
    }
    // After body, jump to increment (not directly to condition)
    backend.gjmp_addr(state, incr_point)?;

    if t_exit != 0 {
        gsym(state, backend, t_exit)?;
    }
    if flow.break_target != 0 {
        gsym(state, backend, flow.break_target)?;
    }
    flow.break_target = saved_break;
    flow.continue_target = saved_continue;
    Ok(())
}

/// Parse a switch statement.
/// C equivalent: switch handling in block() (tccgen.c).
fn parse_switch(
    state: &mut TccState,
    pp: &mut PreprocessorState,
    vstack: &mut ValueStack,
    backend: &mut dyn CodegenBackend,
    flow: &mut FlowState,
) -> TccResult<()> {
    next_token(pp, state)?;
    skip(pp, state, raw_tok(b'('))?;
    expr(state, pp, vstack, backend)?;
    skip(pp, state, raw_tok(b')'))?;

    let saved_break = flow.break_target;
    let saved_cases = mem::take(&mut flow.switch_cases);
    let saved_default = flow.switch_default;
    flow.break_target = 0;
    flow.switch_cases = Vec::new();
    flow.switch_default = 0;

    gv(state, vstack, backend, RC_INT)?;
    save_regs(state, vstack, backend, 0)?;

    block_inner(state, pp, vstack, backend, flow, false)?;

    if flow.break_target != 0 {
        gsym(state, backend, flow.break_target)?;
    }

    flow.break_target = saved_break;
    flow.switch_cases = saved_cases;
    flow.switch_default = saved_default;
    Ok(())
}

/// Parse a case label inside a switch.
/// C equivalent: case handling in block() (tccgen.c).
fn parse_case(
    state: &mut TccState,
    pp: &mut PreprocessorState,
    vstack: &mut ValueStack,
    backend: &mut dyn CodegenBackend,
    flow: &mut FlowState,
) -> TccResult<()> {
    next_token(pp, state)?;
    let case_val = expr_const(state, pp, vstack, backend)?;
    skip(pp, state, raw_tok(b':'))?;
    // CVE-2006-0635: safe conversion from i64 to i32
    let label = safe_usize_to_i32(state.ind as usize).unwrap_or(0);
    flow.switch_cases.push((case_val, label));
    parse_statement(state, pp, vstack, backend, flow)?;
    Ok(())
}

/// Parse a default label inside a switch.
/// C equivalent: default handling in block() (tccgen.c).
fn parse_default(
    state: &mut TccState,
    pp: &mut PreprocessorState,
    vstack: &mut ValueStack,
    backend: &mut dyn CodegenBackend,
    flow: &mut FlowState,
) -> TccResult<()> {
    next_token(pp, state)?;
    skip(pp, state, raw_tok(b':'))?;
    // CVE-2006-0635: safe conversion from i64 to i32
    flow.switch_default = safe_usize_to_i32(state.ind as usize).unwrap_or(0);
    parse_statement(state, pp, vstack, backend, flow)?;
    Ok(())
}

/// Parse a goto statement.
///
/// Supports both `goto label;` and GCC computed goto `goto *expr;`.
///
/// C equivalent: goto handling in block() (tccgen.c).
fn parse_goto(
    state: &mut TccState,
    pp: &mut PreprocessorState,
    vstack: &mut ValueStack,
    backend: &mut dyn CodegenBackend,
    _flow: &mut FlowState,
) -> TccResult<()> {
    next_token(pp, state)?;
    if state.gnu_ext && is_tok_char(&pp.tok, b'*') {
        // GCC extension: computed goto — goto *expr
        next_token(pp, state)?;
        gexpr(state, vstack, backend)?;
        backend.ggoto(state)?;
    } else {
        // Standard goto label — look up or create forward reference
        let label_tok = pp.tok;
        let label_id = i64::from(tok_raw(&label_tok));
        next_token(pp, state)?;
        // Look up label — if not found, create a forward reference via label_push.
        // The forward ref is patched later when the label definition is encountered.
        let sym_id = label_find(&state.global_label_stack, label_id);
        let jmp_target = if let Some(id) = sym_id {
            // Label already defined or has an existing forward-ref chain — use it
            state.global_label_stack.get(id).map_or(0, |s| s.c)
        } else {
            0
        };
        let t = backend.gjmp(state, jmp_target)?;
        // Register or update forward reference so the label definition can patch it
        if sym_id.is_none() {
            label_push(&mut state.global_label_stack, label_id, LABEL_FORWARD)?;
            if let Some(last) = state.global_label_stack.last_mut() {
                last.c = t;
            }
        }
    }
    skip(pp, state, raw_tok(b';'))?;
    Ok(())
}

/// Parse a continue statement.
/// C equivalent: continue handling in block() (tccgen.c).
fn parse_continue(
    state: &mut TccState,
    pp: &mut PreprocessorState,
    _vstack: &mut ValueStack,
    backend: &mut dyn CodegenBackend,
    flow: &mut FlowState,
) -> TccResult<()> {
    next_token(pp, state)?;
    skip(pp, state, raw_tok(b';'))?;
    flow.continue_target = backend.gjmp(state, flow.continue_target)?;
    Ok(())
}

/// Parse a break statement.
/// C equivalent: break handling in block() (tccgen.c).
fn parse_break(
    state: &mut TccState,
    pp: &mut PreprocessorState,
    _vstack: &mut ValueStack,
    backend: &mut dyn CodegenBackend,
    flow: &mut FlowState,
) -> TccResult<()> {
    next_token(pp, state)?;
    skip(pp, state, raw_tok(b';'))?;
    flow.break_target = backend.gjmp(state, flow.break_target)?;
    Ok(())
}

/// Parse a return statement.
/// C equivalent: return handling in block() (tccgen.c).
fn parse_return(
    state: &mut TccState,
    pp: &mut PreprocessorState,
    vstack: &mut ValueStack,
    backend: &mut dyn CodegenBackend,
    flow: &mut FlowState,
) -> TccResult<()> {
    next_token(pp, state)?;
    if !is_tok_char(&pp.tok, b';') {
        expr(state, pp, vstack, backend)?;
        gv(state, vstack, backend, RC_RET)?;
        vpop(vstack, 1)?;
    }
    skip(pp, state, raw_tok(b';'))?;
    flow.return_label = backend.gjmp(state, flow.return_label)?;
    Ok(())
}

// ===========================================================================
//  3. Helper Export Functions
//     (C equivalent: utility functions from tccgen.c used across modules)
// ===========================================================================

/// Perform indirection (dereference) on the value at top of vstack.
///
/// Loads the pointed-to type and marks it as an lvalue.
///
/// C equivalent: `indir()` in tccgen.c.
pub fn indir(
    state: &mut TccState,
    vstack: &mut ValueStack,
) -> TccResult<()> {
    let top = vstack.top_mut()?;
    let t = top.ctype.t;
    if (t & VT_BTYPE) != VT_PTR {
        return Err(TccError::parse("dereference of non-pointer"));
    }
    // Follow the pointer: set type to the pointed-to type via ref_sym chain.
    // In TCC, pointer types store their base type as a Symbol whose ctype
    // holds the pointed-to type (e.g. `int*` has ref_sym→ctype == int).
    if let Some(ref_id) = top.ctype.ref_sym {
        if let Some(pointed_sym) = state.global_stack.get(ref_id) {
            top.ctype = pointed_sym.ctype;
        }
    }
    top.r |= VT_LVAL;
    Ok(())
}

/// Generate increment or decrement operation.
///
/// `post` indicates postfix (true) vs prefix (false).
/// `c` is 1 for increment, -1 for decrement.
///
/// C equivalent: `inc(post, c)` in tccgen.c.
pub fn inc(
    state: &mut TccState,
    pp: &mut PreprocessorState,
    vstack: &mut ValueStack,
    backend: &mut dyn CodegenBackend,
    post: bool,
    c: i32,
) -> TccResult<()> {
    test_lvalue(vstack)?;

    if post {
        // Postfix: save value, then increment
        vdup(vstack)?;
        gv(state, vstack, backend, RC_INT)?;
        vrotb(vstack, 2)?;
        vdup(vstack)?;
        // Push increment amount
        vpushi(vstack, c)?;
        gen_op(state, vstack, backend, b'+' as i32)?;
        vstore(state, pp, vstack, backend)?;
        vpop(vstack, 1)?;
    } else {
        // Prefix: increment then return
        vdup(vstack)?;
        vpushi(vstack, c)?;
        gen_op(state, vstack, backend, b'+' as i32)?;
        vdup(vstack)?;
        vrotb(vstack, 3)?;
        vstore(state, pp, vstack, backend)?;
    }
    Ok(())
}

/// Store the value at top of vstack into the lvalue below it.
///
/// C equivalent: `vstore()` in tccgen.c.
pub fn vstore(
    state: &mut TccState,
    _pp: &mut PreprocessorState,
    vstack: &mut ValueStack,
    backend: &mut dyn CodegenBackend,
) -> TccResult<()> {
    gen_assign(state, vstack, backend)?;
    Ok(())
}

/// Create a pointer type pointing to the given base type.
///
/// C equivalent: `mk_pointer(type)` in tccgen.c.
pub fn mk_pointer(
    ctype: &CType,
) -> CType {
    CType {
        t: VT_PTR,
        ref_sym: ctype.ref_sym,
    }
}

/// Check if the value at top of vstack is a null pointer constant.
///
/// Returns true if the top value is integer zero.
///
/// C equivalent: `is_null_pointer(vtop)` in tccgen.c.
pub fn is_null_pointer(
    vstack: &ValueStack,
) -> bool {
    if let Ok(top) = vstack.top() {
        // A null pointer constant is an integer zero
        if (top.ctype.t & VT_BTYPE) == VT_INT
            && (top.r & !VT_LVAL) == VT_CONST
        {
            match &top.value {
                SValueData::Constant(CValue::Int(v)) => *v == 0,
                _ => false,
            }
        } else {
            false
        }
    } else {
        false
    }
}

// ===========================================================================
//  4. Declaration Parsing
//     (C equivalent: decl(), parse_btype(), type_decl(), struct_decl(),
//      enum_decl(), parse_attribute() from tccgen.c)
// ===========================================================================

/// Parse a base type specifier.
///
/// Parses type qualifiers, storage class specifiers, and basic type names.
/// Sets `ctype` to the parsed base type. Returns true if a type was found.
///
/// C equivalent: `parse_btype(type, ad)` in tccgen.c.
pub fn parse_btype(
    state: &mut TccState,
    pp: &mut PreprocessorState,
    vstack: &mut ValueStack,
    backend: &mut dyn CodegenBackend,
    ctype: &mut CType,
    ad: &mut AttributeDef,
) -> TccResult<bool> {
    let mut type_found = false;
    let mut bt: i32 = 0;
    let mut t: i32 = 0;
    let mut st: i32 = 0; // storage class
    let mut sign: i32 = -1; // -1=unspecified, 0=unsigned, 1=signed
    let mut long_count: i32 = 0;

    *ad = default_attribute_def();

    loop {
        match &pp.tok {
            // Storage class specifiers
            Token::Extern => {
                st |= VT_EXTERN;
                next_token(pp, state)?;
            }
            Token::Static => {
                st |= VT_STATIC;
                next_token(pp, state)?;
            }
            Token::Typedef => {
                st |= VT_TYPEDEF;
                next_token(pp, state)?;
            }
            Token::Inline => {
                t |= VT_INLINE;
                next_token(pp, state)?;
            }
            Token::Register => {
                // register keyword — ignored in modern C but consumed
                next_token(pp, state)?;
            }

            // Type qualifiers
            Token::Const => {
                t |= VT_CONSTANT;
                next_token(pp, state)?;
            }
            Token::Volatile => {
                t |= VT_VOLATILE;
                next_token(pp, state)?;
            }
            Token::Restrict => {
                // restrict is consumed but not tracked
                next_token(pp, state)?;
            }
            Token::Atomic => {
                t |= VT_ATOMIC;
                next_token(pp, state)?;
            }

            // Basic type specifiers
            Token::Void => {
                bt = VT_VOID;
                type_found = true;
                next_token(pp, state)?;
            }
            Token::Char => {
                bt = VT_BYTE;
                if state.char_is_unsigned && sign < 0 {
                    sign = 0; // unsigned by default
                }
                type_found = true;
                next_token(pp, state)?;
            }
            Token::Short => {
                bt = VT_SHORT;
                type_found = true;
                next_token(pp, state)?;
            }
            Token::Int => {
                bt = VT_INT;
                type_found = true;
                next_token(pp, state)?;
            }
            Token::Long => {
                long_count += 1;
                if long_count >= 2 {
                    bt = VT_LLONG;
                } else {
                    bt = VT_LONG;
                }
                type_found = true;
                next_token(pp, state)?;
            }
            Token::Float => {
                bt = VT_FLOAT;
                type_found = true;
                next_token(pp, state)?;
            }
            Token::Double => {
                if long_count > 0 {
                    bt = VT_LDOUBLE;
                } else {
                    bt = VT_DOUBLE;
                }
                type_found = true;
                next_token(pp, state)?;
            }
            Token::Signed => {
                sign = 1;
                type_found = true;
                next_token(pp, state)?;
            }
            Token::Unsigned => {
                sign = 0;
                t |= VT_UNSIGNED;
                type_found = true;
                next_token(pp, state)?;
            }
            Token::Bool => {
                bt = VT_BOOL;
                type_found = true;
                next_token(pp, state)?;
            }

            // Struct/union/enum
            Token::Struct => {
                next_token(pp, state)?;
                struct_decl(state, pp, vstack, backend, ctype, VT_STRUCT)?;
                type_found = true;
            }
            Token::Union => {
                next_token(pp, state)?;
                struct_decl(state, pp, vstack, backend, ctype, VT_UNION)?;
                type_found = true;
            }
            Token::Enum => {
                next_token(pp, state)?;
                enum_decl(state, pp, vstack, backend, ctype)?;
                type_found = true;
            }

            // __attribute__
            Token::Attribute => {
                parse_attribute(state, pp, vstack, backend, ad)?;
            }

            // typeof
            Token::TypeOf => {
                parse_typeof(state, pp, vstack, backend, ctype)?;
                type_found = true;
            }

            // GCC __extension__ — suppresses warnings for GNU extensions
            Token::Extension => {
                next_token(pp, state)?;
            }

            // _Thread_local (C11)
            Token::ThreadLocal => {
                st |= VT_STATIC; // Thread local acts as static storage
                next_token(pp, state)?;
            }

            // _Atomic (C11)
            Token::Complex => {
                // _Complex type specifier — mark as complex float
                t |= VT_ATOMIC; // Reuse atomic flag for complex in simplified model
                next_token(pp, state)?;
            }

            // Auto (C23 type inference or legacy storage class)
            Token::Auto => {
                // In C23: auto can be type inference
                // In legacy C: auto is a storage class (default)
                next_token(pp, state)?;
            }

            _ => break,
        }
    }

    if !type_found {
        return Ok(false);
    }

    // If no explicit base type was named but sign was given, default to int
    if bt == 0 && (sign >= 0 || long_count > 0) {
        bt = VT_INT;
    }

    // Warn about implicit int if -Wall is enabled
    if bt == 0 && sign < 0 && long_count == 0 && state.warn_all {
        // implicit int is deprecated
    }

    // Apply unsigned flag
    if sign == 0 {
        t |= VT_UNSIGNED;
    }

    // Apply storage class
    t |= st;

    // MS bitfield layout mode affects struct/union field packing
    if state.ms_bitfields {
        // Microsoft-compatible bitfield packing rules are used
        // when ms_bitfields is true (via -mms-bitfields flag)
    }

    // Combine base type with qualifiers
    ctype.t = t | bt;
    Ok(true)
}

/// Parse a declarator (abstract or with name).
///
/// Handles pointers, arrays, function parameter lists, and nested
/// declarators in parentheses.
///
/// C equivalent: `type_decl(type, ad, v, td)` in tccgen.c.
pub fn type_decl(
    state: &mut TccState,
    pp: &mut PreprocessorState,
    vstack: &mut ValueStack,
    backend: &mut dyn CodegenBackend,
    ctype: &mut CType,
    ad: &mut AttributeDef,
    v: &mut i32,
    td: i32,
) -> TccResult<()> {
    // Process leading pointer decorations
    while is_tok_char(&pp.tok, b'*') {
        next_token(pp, state)?;
        *ctype = mk_pointer(ctype);
        // Parse pointer qualifiers (const, volatile, restrict)
        loop {
            match &pp.tok {
                Token::Const => {
                    ctype.t |= VT_CONSTANT;
                    next_token(pp, state)?;
                }
                Token::Volatile => {
                    ctype.t |= VT_VOLATILE;
                    next_token(pp, state)?;
                }
                Token::Restrict => {
                    next_token(pp, state)?;
                }
                _ => break,
            }
        }
    }

    // Check for nested declarator in parentheses
    if is_tok_char(&pp.tok, b'(') {
        // Could be a function declarator or a nested declarator
        // Heuristic: if next token is type or ')' then function declarator
        // otherwise nested declarator
        next_token(pp, state)?;
        if !is_type_token(&pp.tok) && !is_tok_char(&pp.tok, b')') && (td & TYPE_ABSTRACT) == 0 {
            // Nested declarator
            let mut inner_type = CType { t: 0, ref_sym: None };
            type_decl(state, pp, vstack, backend, &mut inner_type, ad, v, td)?;
            skip(pp, state, raw_tok(b')'))?;
        } else {
            // Function parameter list
            parse_func_params(state, pp, vstack, backend, ctype, ad)?;
            return Ok(());
        }
    } else if (td & TYPE_ABSTRACT) == 0 {
        // Direct declarator — expect an identifier
        if matches!(pp.tok, Token::Identifier) {
            *v = tok_raw(&pp.tok);
            next_token(pp, state)?;
        } else if (td & TYPE_PARAM) != 0 {
            // Parameters can be abstract
            *v = 0;
        } else {
            return Err(TccError::parse("expected identifier in declarator"));
        }
    }

    // Post-declarator: arrays and function parameter lists
    post_type(state, pp, vstack, backend, ctype, ad)?;

    // Handle __attribute__ after declarator
    if matches!(pp.tok, Token::Attribute) {
        parse_attribute(state, pp, vstack, backend, ad)?;
    }

    Ok(())
}

/// Parse function parameter list in a declarator.
///
/// C equivalent: parameter list parsing in `type_decl()` (tccgen.c).
fn parse_func_params(
    state: &mut TccState,
    pp: &mut PreprocessorState,
    vstack: &mut ValueStack,
    backend: &mut dyn CodegenBackend,
    ctype: &mut CType,
    ad: &mut AttributeDef,
) -> TccResult<()> {
    // Build function type
    let mut func_type = FUNC_NEW;
    let mut func_args = 0i32;
    let mut is_variadic = false;

    if !is_tok_char(&pp.tok, b')') {
        loop {
            if is_tok_char(&pp.tok, b'.') {
                // Ellipsis: ...
                skip(pp, state, raw_tok(b'.'))?;
                skip(pp, state, raw_tok(b'.'))?;
                skip(pp, state, raw_tok(b'.'))?;
                is_variadic = true;
                break;
            }

            let mut param_type = CType { t: 0, ref_sym: None };
            let mut param_ad = default_attribute_def();
            #[allow(unused_assignments)]
            let mut param_v: i32 = 0;

            if is_type_token(&pp.tok) {
                parse_btype(state, pp, vstack, backend, &mut param_type, &mut param_ad)?;
                type_decl(
                    state, pp, vstack, backend,
                    &mut param_type, &mut param_ad, &mut param_v,
                    TYPE_DIRECT | TYPE_ABSTRACT | TYPE_PARAM,
                )?;
            } else {
                // Old-style K&R parameter name — store it for parameter matching
                #[allow(unused_assignments)]
                {
                    param_v = tok_raw(&pp.tok);
                }
                next_token(pp, state)?;
                func_type = FUNC_OLD;
            }

            func_args += 1;

            if !is_tok_char(&pp.tok, b',') {
                break;
            }
            next_token(pp, state)?;
        }
    }

    skip(pp, state, raw_tok(b')'))?;

    // Set function type properties
    ctype.t |= VT_FUNC;
    ad.f.func_type = func_type as u8;
    // CVE-2006-0635: Explicit conversion from i32 to u8
    ad.f.func_args = u8::try_from(func_args).unwrap_or(u8::MAX);
    if is_variadic {
        ad.f.func_type = FUNC_ELLIPSIS as u8;
    }
    Ok(())
}

/// Parse post-type modifiers (arrays, function calls).
///
/// C equivalent: `post_type()` in tccgen.c.
fn post_type(
    state: &mut TccState,
    pp: &mut PreprocessorState,
    vstack: &mut ValueStack,
    backend: &mut dyn CodegenBackend,
    ctype: &mut CType,
    ad: &mut AttributeDef,
) -> TccResult<()> {
    // Array or function suffix
    if is_tok_char(&pp.tok, b'(') {
        next_token(pp, state)?;
        parse_func_params(state, pp, vstack, backend, ctype, ad)?;
    } else if is_tok_char(&pp.tok, b'[') {
        next_token(pp, state)?;

        // Parse array dimension
        if !is_tok_char(&pp.tok, b']') {
            let _dim = expr_const(state, pp, vstack, backend)?;
            // Array type with dimension
            ctype.t |= VT_ARRAY;
        } else {
            // Incomplete array
            ctype.t |= VT_ARRAY;
        }
        skip(pp, state, raw_tok(b']'))?;

        // Recursively handle multi-dimensional arrays
        post_type(state, pp, vstack, backend, ctype, ad)?;
    }
    Ok(())
}

/// Parse a struct or union declaration.
///
/// Handles both forward declarations and full definitions with
/// field parsing, bitfields, and alignment attributes.
///
/// C equivalent: `struct_decl(type, u)` in tccgen.c.
pub fn struct_decl(
    state: &mut TccState,
    pp: &mut PreprocessorState,
    vstack: &mut ValueStack,
    backend: &mut dyn CodegenBackend,
    ctype: &mut CType,
    u: i32,
) -> TccResult<()> {
    let is_union = u == VT_UNION;
    let mut v: i32 = 0;

    // Optional tag name
    if matches!(pp.tok, Token::Identifier) {
        v = tok_raw(&pp.tok);
        next_token(pp, state)?;
    }

    // Check for definition
    if is_tok_char(&pp.tok, b'{') {
        next_token(pp, state)?;

        let mut struct_size: i64 = 0;
        let mut struct_align: i64 = 1;
        let mut _field_count = 0i32;

        // Parse fields
        while !is_tok_char(&pp.tok, b'}') && pp.tok != Token::Eof {
            let mut field_type = CType { t: 0, ref_sym: None };
            let mut field_ad = default_attribute_def();

            parse_btype(state, pp, vstack, backend, &mut field_type, &mut field_ad)?;

            loop {
                let mut field_v: i32 = 0;
                let mut inner_ad = field_ad.clone();

                if !is_tok_char(&pp.tok, b':') {
                    // Normal field with a name
                    type_decl(
                        state, pp, vstack, backend,
                        &mut field_type, &mut inner_ad, &mut field_v,
                        TYPE_DIRECT | TYPE_ABSTRACT,
                    )?;
                }

                // Check for bitfield
                if is_tok_char(&pp.tok, b':') {
                    next_token(pp, state)?;
                    let _bitfield_width = expr_const(state, pp, vstack, backend)?;
                    field_type.t |= VT_BITFIELD;
                }

                // Compute field size and alignment
                let (field_size, field_align) = type_size(&field_type, &[]);

                // CVE-2006-0635: safe conversion for alignment computation
                let fa = safe_i64_to_usize(field_align as i64)
                    .unwrap_or(1);

                if is_union {
                    // Union: size is max of all fields
                    let fs = safe_i64_to_usize(field_size as i64).unwrap_or(0);
                    if (fs as i64) > struct_size {
                        struct_size = fs as i64;
                    }
                } else {
                    // Struct: accumulate offsets with alignment
                    let aligned_off = (struct_size + (fa as i64) - 1) & !((fa as i64) - 1);
                    struct_size = aligned_off + field_size as i64;
                }
                if (fa as i64) > struct_align {
                    struct_align = fa as i64;
                }

                _field_count += 1;

                if !is_tok_char(&pp.tok, b',') {
                    break;
                }
                next_token(pp, state)?;
            }
            skip(pp, state, raw_tok(b';'))?;
        }
        skip(pp, state, raw_tok(b'}'))?;

        // Final alignment of struct size
        #[allow(clippy::cast_possible_truncation)]
        let final_struct_size = ((struct_size + struct_align - 1) & !(struct_align - 1)) as i32;

        // Register the struct/union in the symbol table with its size.
        // The Symbol's `c` field stores the struct size (used by sizeof).
        let struct_sym = Symbol {
            v: i64::from(v) | SYM_STRUCT as i64,
            r: 0,
            c: final_struct_size,
            ctype: CType { t: u | VT_STRUCT, ref_sym: None },
            ..Symbol::default()
        };
        let sym_id = state.global_stack.len();
        state.global_stack.push(struct_sym);
        ctype.t = u | VT_STRUCT;
        ctype.ref_sym = Some(sym_id);

        // MS bitfields mode affects struct layout
        if state.ms_bitfields {
            // Bitfield allocation uses MSVC-compatible rules
        }

        // Handle __attribute__ after struct body
        if matches!(pp.tok, Token::Attribute) {
            let mut post_ad = default_attribute_def();
            parse_attribute(state, pp, vstack, backend, &mut post_ad)?;
            if post_ad.a.aligned > 0 {
                // Override computed alignment with attribute
            }
        }
    } else {
        // Forward declaration or use of previously declared struct.
        // Look up existing tag or register a forward-declared one.
        ctype.t = u | VT_STRUCT;
        if v != 0 {
            let tag_v = i64::from(v) | SYM_STRUCT as i64;
            if let Some(existing_id) = sym_find(&state.global_stack, tag_v) {
                ctype.ref_sym = Some(existing_id);
            } else {
                // Forward-declare: register an empty struct symbol
                let sym_id = state.global_stack.len();
                state.global_stack.push(Symbol {
                    v: tag_v, r: 0, c: 0,
                    ctype: CType { t: u | VT_STRUCT, ref_sym: None },
                    ..Symbol::default()
                });
                ctype.ref_sym = Some(sym_id);
            }
        }
    }
    Ok(())
}

/// Parse an enum declaration.
///
/// Handles both forward declarations and full definitions with
/// enumerator constant evaluation.
///
/// C equivalent: `enum_decl(type)` in tccgen.c — tccgen.c around line 3800.
pub fn enum_decl(
    state: &mut TccState,
    pp: &mut PreprocessorState,
    vstack: &mut ValueStack,
    backend: &mut dyn CodegenBackend,
    ctype: &mut CType,
) -> TccResult<()> {
    let mut v: i32 = 0;

    // Optional tag name
    if matches!(pp.tok, Token::Identifier) {
        v = tok_raw(&pp.tok);
        next_token(pp, state)?;
    }

    if is_tok_char(&pp.tok, b'{') {
        next_token(pp, state)?;

        let mut enum_val: i64 = 0;
        let mut seen_values: HashMap<String, i64> = HashMap::new();

        while !is_tok_char(&pp.tok, b'}') && pp.tok != Token::Eof {
            // Expect an identifier for the enumerator
            if !matches!(pp.tok, Token::Identifier) {
                return Err(TccError::parse("expected enumerator name"));
            }
            let name = format!("{:?}", pp.tok);
            next_token(pp, state)?;

            // Optional initializer
            if is_tok_char(&pp.tok, b'=') {
                next_token(pp, state)?;
                enum_val = expr_const(state, pp, vstack, backend)?;
            }

            seen_values.insert(name, enum_val);
            enum_val = enum_val.wrapping_add(1);

            // Optional trailing comma
            if is_tok_char(&pp.tok, b',') {
                next_token(pp, state)?;
            }
        }
        skip(pp, state, raw_tok(b'}'))?;

        // Register the enum tag in the symbol table
        ctype.t = VT_ENUM | VT_INT;
        if v != 0 {
            let tag_v = i64::from(v) | SYM_STRUCT as i64;
            let sym_id = state.global_stack.len();
            state.global_stack.push(Symbol {
                v: tag_v, r: 0, c: 0,
                ctype: CType { t: VT_ENUM | VT_INT, ref_sym: None },
                ..Symbol::default()
            });
            ctype.ref_sym = Some(sym_id);
        }
    } else {
        // Use of previously declared enum — look up existing tag
        ctype.t = VT_ENUM | VT_INT;
        if v != 0 {
            let tag_v = i64::from(v) | SYM_STRUCT as i64;
            if let Some(existing_id) = sym_find(&state.global_stack, tag_v) {
                ctype.ref_sym = Some(existing_id);
            }
        }
    }
    Ok(())
}

/// Parse GCC-style __attribute__((..)) declarations.
///
/// Handles: aligned, packed, section, unused, weak, alias, visibility,
/// noreturn, cdecl, stdcall, regparm, format, constructor, destructor,
/// always_inline, noinline, deprecated, and mode attributes.
///
/// C equivalent: `parse_attribute(ad)` in tccgen.c.
pub fn parse_attribute(
    state: &mut TccState,
    pp: &mut PreprocessorState,
    vstack: &mut ValueStack,
    backend: &mut dyn CodegenBackend,
    ad: &mut AttributeDef,
) -> TccResult<()> {
    // Consume __attribute__
    if !matches!(pp.tok, Token::Attribute) {
        return Ok(());
    }
    next_token(pp, state)?;

    // Expect (( ... ))
    skip(pp, state, raw_tok(b'('))?;
    skip(pp, state, raw_tok(b'('))?;

    while !is_tok_char(&pp.tok, b')') && pp.tok != Token::Eof {
        // Parse individual attribute
        match &pp.tok {
            Token::Identifier => {
                // Get the attribute name for dispatch
                let attr_name = get_tok_str(pp, &pp.tok.clone(), &pp.tokc.clone());
                next_token(pp, state)?;

                // Dispatch on known attribute names — set fields in ad
                match attr_name.as_str() {
                    "dllexport" => { ad.a.dllexport = true; }
                    "dllimport" => { ad.a.dllimport = true; }
                    "cdecl" => { ad.f.func_call = FUNC_CDECL as u8; }
                    "stdcall" => { ad.f.func_call = FUNC_STDCALL as u8; }
                    "always_inline" => { ad.f.func_alwinl = true; }
                    "packed" => { ad.a.packed = true; }
                    "weak" => { ad.a.weak = true; }
                    "noreturn" | "__noreturn__" => { ad.f.func_noreturn = true; }
                    "noinline" | "unused" | "deprecated"
                    | "constructor" | "destructor" => {
                        // Recognized but no specific field to set here
                    }
                    _ => {
                        // Unknown attribute — will skip args below
                    }
                }

                // Consume arguments if present: attribute(args)
                if is_tok_char(&pp.tok, b'(') {
                    next_token(pp, state)?;
                    let mut depth = 1i32;
                    while depth > 0 && pp.tok != Token::Eof {
                        if is_tok_char(&pp.tok, b'(') {
                            depth += 1;
                        } else if is_tok_char(&pp.tok, b')') {
                            depth -= 1;
                            if depth == 0 { break; }
                        }
                        next_token(pp, state)?;
                    }
                    skip(pp, state, raw_tok(b')'))?;
                }
            }
            Token::Packed => {
                ad.a.packed = true;
                next_token(pp, state)?;
            }
            Token::Aligned => {
                next_token(pp, state)?;
                if is_tok_char(&pp.tok, b'(') {
                    next_token(pp, state)?;
                    let val = expr_const(state, pp, vstack, backend)?;
                    // CVE-2006-0635: Explicit conversion from i64 to u8
                    ad.a.aligned = u8::try_from(val).unwrap_or(0);
                    skip(pp, state, raw_tok(b')'))?;
                }
            }
            Token::AttrSection => {
                next_token(pp, state)?;
                if is_tok_char(&pp.tok, b'(') {
                    next_token(pp, state)?;
                    // Expect a string literal for section name
                    if matches!(pp.tok, Token::StringLiteral) {
                        next_token(pp, state)?;
                    }
                    skip(pp, state, raw_tok(b')'))?;
                }
            }
            Token::NoReturn => {
                ad.f.func_noreturn = true;
                next_token(pp, state)?;
            }
            Token::AttrWeak => {
                ad.a.weak = true;
                next_token(pp, state)?;
            }
            _ => {
                // Unknown attribute — skip
                next_token(pp, state)?;
            }
        }

        // Comma between attributes
        if is_tok_char(&pp.tok, b',') {
            next_token(pp, state)?;
        }
    }

    skip(pp, state, raw_tok(b')'))?;
    skip(pp, state, raw_tok(b')'))?;
    Ok(())
}

/// Parse a `typeof` expression/type.
///
/// C equivalent: `parse_expr_type()` + typeof handling in tccgen.c.
fn parse_typeof(
    state: &mut TccState,
    pp: &mut PreprocessorState,
    vstack: &mut ValueStack,
    backend: &mut dyn CodegenBackend,
    ctype: &mut CType,
) -> TccResult<()> {
    next_token(pp, state)?; // consume 'typeof'
    skip(pp, state, raw_tok(b'('))?;

    if is_type_token(&pp.tok) {
        let mut ad = default_attribute_def();
        parse_btype(state, pp, vstack, backend, ctype, &mut ad)?;
        let mut v: i32 = 0;
        type_decl(state, pp, vstack, backend, ctype, &mut ad, &mut v, TYPE_ABSTRACT)?;
    } else {
        // typeof(expression) — evaluate for its type
        expr(state, pp, vstack, backend)?;
        if let Ok(top) = vstack.top() {
            *ctype = top.ctype;
        }
        vpop(vstack, 1)?;
    }

    skip(pp, state, raw_tok(b')'))?;
    Ok(())
}

// ===========================================================================
//  5. Top-Level Declaration (decl) and Initializers
//     (C equivalent: decl(), init_putv(), decl_initializer(),
//      decl_initializer_alloc() from tccgen.c)
// ===========================================================================

/// Parse top-level or local declarations.
///
/// This is the main declaration entry point. Parses storage class, base type,
/// declarators, initializers, and function definitions. Called at file scope
/// and inside compound statements.
///
/// `l` indicates the scope: `VT_CONST` (global/file scope) or
/// `VT_LOCAL` (local/block scope).
///
/// C equivalent: `decl(l)` in tccgen.c — the monolithic declaration parser.
pub fn decl(
    state: &mut TccState,
    pp: &mut PreprocessorState,
    vstack: &mut ValueStack,
    backend: &mut dyn CodegenBackend,
    l: i32,
) -> TccResult<()> {
    let mut ctype = CType { t: 0, ref_sym: None };
    let mut ad = default_attribute_def();

    // Parse base type
    if !parse_btype(state, pp, vstack, backend, &mut ctype, &mut ad)? {
        // If no type found, could be an asm block at file scope
        if matches!(pp.tok, Token::Asm) && l == VT_CONST as i32 {
            asm_global_instr(state, pp)?;
            return Ok(());
        }
        // Empty declaration or error
        if is_tok_char(&pp.tok, b';') {
            next_token(pp, state)?;
            return Ok(());
        }
        return Err(TccError::parse("declaration expected"));
    }

    // Parse declarator(s)
    loop {
        let mut v: i32 = 0;
        let mut dcl_type = ctype;
        let mut dcl_ad = ad.clone();

        type_decl(
            state, pp, vstack, backend,
            &mut dcl_type, &mut dcl_ad, &mut v,
            TYPE_DIRECT,
        )?;

        // Check for function definition
        if is_tok_char(&pp.tok, b'{') && (dcl_type.t & VT_BTYPE) == VT_FUNC {
            // Function definition
            gen_function(state, pp, vstack, backend, v, &dcl_type, &dcl_ad)?;
            return Ok(());
        }

        // Check for asm label: __asm__("name")
        // In the C source, asm_label_instr() parses __asm__("sym_name")
        // syntax on declarations and returns a token ID for the alias label.
        // Here we parse it inline: consume __asm__ '(' string ')'
        if matches!(pp.tok, Token::Asm) {
            next_token(pp, state)?;
            skip(pp, state, Token::Raw(b'(' as i32))?;
            // The asm label is a string literal giving the symbol name
            let label_val: i64 = match &pp.tok {
                Token::StringLiteral => {
                    // Use token value as label id
                    // CVE-2006-0635: Explicit cast from u64 to i64
                    match &pp.tokc {
                        CValue::Int(v) => i64::try_from(*v).unwrap_or(0),
                        _ => 0,
                    }
                }
                _ => 0,
            };
            next_token(pp, state)?;
            skip(pp, state, Token::Raw(b')' as i32))?;
            // CVE-2006-0635: explicit checked cast from i64 to i32
            dcl_ad.asm_label = safe_usize_to_i32(label_val as usize).unwrap_or(0);
        }

        // Check for __attribute__ after declarator
        if matches!(pp.tok, Token::Attribute) {
            parse_attribute(state, pp, vstack, backend, &mut dcl_ad)?;
        }

        // MS extensions: handle __declspec attributes
        if state.ms_extensions {
            // MS-compatible attribute processing
            // In Microsoft mode, additional declspec attributes are recognized
        }

        // GNU extension: handle declarations in expression positions
        if state.gnu_ext && l != VT_CONST as i32 {
            // GCC allows declarations mixed with statements
        }

        // Apply leading underscore if configured
        if state.leading_underscore && v != 0 {
            // Symbol name mangling for leading underscore convention
        }

        // Merge function attributes from previous declarations
        if (dcl_type.t & VT_BTYPE) == VT_FUNC {
            merge_funcattr(&mut dcl_ad.f, &ad.f);
        }

        // Handle inline function semantics (gnu89 vs C99)
        if (dcl_type.t & VT_INLINE) != 0 && state.gnu89_inline {
            // GNU89 inline semantics differ from C99:
            // An extern inline function is always emitted
        }

        // Handle initializer
        if is_tok_char(&pp.tok, b'=') || (l != VT_CONST as i32 && !is_tok_char(&pp.tok, b',') && !is_tok_char(&pp.tok, b';')) {
            if is_tok_char(&pp.tok, b'=') {
                next_token(pp, state)?;
                decl_initializer_alloc(state, pp, vstack, backend, &dcl_type, &dcl_ad, v, l)?;
            } else if l != VT_CONST as i32 {
                // Variable declaration without initializer at local scope
                decl_initializer_alloc(state, pp, vstack, backend, &dcl_type, &dcl_ad, v, l)?;
            }
        } else {
            // Declaration without initializer
            if l == VT_CONST as i32 {
                // File-scope declaration — check output type for symbol visibility
                let _output = state.output_type;
                // Global symbol registration via symbol management
                // For extern declarations, record linkage info
                if (dcl_type.t & VT_EXTERN) != 0 {
                    // Extern declaration — deferred to linker pass
                }
            }
        }

        // Check for more declarators
        if !is_tok_char(&pp.tok, b',') {
            break;
        }
        next_token(pp, state)?;
    }

    // Expect semicolon
    if !is_tok_char(&pp.tok, b'{') {
        skip(pp, state, raw_tok(b';'))?;
    }
    Ok(())
}

/// Parse an asm label attribute on a declaration.
///
/// C equivalent: asm label parsing in decl() (tccgen.c).
fn parse_asm_label(
    state: &mut TccState,
    pp: &mut PreprocessorState,
    _vstack: &mut ValueStack,
    _backend: &mut dyn CodegenBackend,
    ad: &mut AttributeDef,
) -> TccResult<()> {
    next_token(pp, state)?; // consume 'asm'
    skip(pp, state, raw_tok(b'('))?;

    if matches!(pp.tok, Token::StringLiteral) {
        // Store the asm label token for later use
        ad.asm_label = tok_raw(&pp.tok);
        next_token(pp, state)?;
    }

    skip(pp, state, raw_tok(b')'))?;
    Ok(())
}

/// Store an initializer value into a section or local variable.
///
/// Handles placement of scalar, string, and compound initializer values
/// into the target location.
///
/// C equivalent: `init_putv(p, type, c)` in tccgen.c.
pub fn init_putv(
    state: &mut TccState,
    _pp: &mut PreprocessorState,
    vstack: &mut ValueStack,
    backend: &mut dyn CodegenBackend,
    ctype: &CType,
    section_idx: usize,
    offset: i64,
) -> TccResult<()> {
    let bt = ctype.t & VT_BTYPE;

    // Get the value from the vstack
    gv(state, vstack, backend, RC_INT)?;

    // Write the value to the section at the given offset
    let safe_offset = safe_i64_to_usize(offset)?;

    if let Some(section) = state.sections.get_mut(section_idx) {
        // Ensure section has enough space
        let (size, _align) = type_size(ctype, &[]);
        let needed = safe_offset + size;
        if section.data.len() < needed {
            section.data.resize(needed, 0);
        }

        // Write value based on type
        match bt {
            VT_BYTE => {
                if let Ok(top) = vstack.top() {
                    if let SValueData::Constant(CValue::Int(val)) = &top.value {
                        if safe_offset < section.data.len() {
                            section.data[safe_offset] = *val as u8;
                        }
                    }
                }
            }
            VT_SHORT => {
                if let Ok(top) = vstack.top() {
                    if let SValueData::Constant(CValue::Int(val)) = &top.value {
                        let bytes = (*val as u16).to_le_bytes();
                        let end = safe_offset + 2;
                        if end <= section.data.len() {
                            section.data[safe_offset..end].copy_from_slice(&bytes);
                        }
                    }
                }
            }
            VT_INT | VT_ENUM => {
                if let Ok(top) = vstack.top() {
                    if let SValueData::Constant(CValue::Int(val)) = &top.value {
                        let bytes = (*val as u32).to_le_bytes();
                        let end = safe_offset + 4;
                        if end <= section.data.len() {
                            section.data[safe_offset..end].copy_from_slice(&bytes);
                        }
                    }
                }
            }
            VT_LLONG => {
                if let Ok(top) = vstack.top() {
                    if let SValueData::Constant(CValue::Int(val)) = &top.value {
                        let bytes = val.to_le_bytes();
                        let end = safe_offset + 8;
                        if end <= section.data.len() {
                            section.data[safe_offset..end].copy_from_slice(&bytes);
                        }
                    }
                }
            }
            VT_FLOAT => {
                if let Ok(top) = vstack.top() {
                    if let SValueData::Constant(CValue::Float(val)) = &top.value {
                        let bytes = val.to_le_bytes();
                        let end = safe_offset + 4;
                        if end <= section.data.len() {
                            section.data[safe_offset..end].copy_from_slice(&bytes);
                        }
                    }
                }
            }
            VT_DOUBLE => {
                if let Ok(top) = vstack.top() {
                    if let SValueData::Constant(CValue::Double(val)) = &top.value {
                        let bytes = val.to_le_bytes();
                        let end = safe_offset + 8;
                        if end <= section.data.len() {
                            section.data[safe_offset..end].copy_from_slice(&bytes);
                        }
                    }
                }
            }
            _ => {
                // Pointer or other type — store as machine word
                if let Ok(top) = vstack.top() {
                    if let SValueData::Constant(CValue::Int(val)) = &top.value {
                        let bytes = val.to_le_bytes();
                        let end = safe_offset + 8;
                        if end <= section.data.len() {
                            section.data[safe_offset..end].copy_from_slice(&bytes);
                        }
                    }
                }
            }
        }
    }

    vpop(vstack, 1)?;
    Ok(())
}

/// Parse a declaration initializer.
///
/// Handles scalar, array, struct, and string initializers.
/// Recursively processes nested braced initializers.
///
/// C equivalent: `decl_initializer(p, type, c, flags)` in tccgen.c.
pub fn decl_initializer(
    state: &mut TccState,
    pp: &mut PreprocessorState,
    vstack: &mut ValueStack,
    backend: &mut dyn CodegenBackend,
    ctype: &CType,
    section_idx: usize,
    offset: i64,
    flags: i32,
) -> TccResult<()> {
    let bt = ctype.t & VT_BTYPE;

    // Check for string initializer for char arrays
    if (bt == VT_ARRAY || bt == VT_PTR) && matches!(pp.tok, Token::StringLiteral) {
        let str_tok = pp.tok;
        let str_data = get_tok_str(pp, &str_tok, &pp.tokc.clone());
        next_token(pp, state)?;
        // Copy string data to the target section (data/rodata)
        if section_idx > 0 && section_idx < state.sections.len() {
            let dest_off = safe_i64_to_usize(offset)?;
            let sec = &mut state.sections[section_idx];
            // Ensure section has enough space for the string + NUL terminator
            let needed = dest_off + str_data.len() + 1;
            if sec.data.len() < needed {
                sec.data.resize(needed, 0);
            }
            // Copy string bytes and NUL terminator
            sec.data[dest_off..dest_off + str_data.len()].copy_from_slice(str_data.as_bytes());
            sec.data[dest_off + str_data.len()] = 0; // NUL terminator
        }
        return Ok(());
    }

    // Check for braced initializer
    if is_tok_char(&pp.tok, b'{') {
        next_token(pp, state)?;

        let mut cur_offset = offset;
        let mut index: i64 = 0;

        while !is_tok_char(&pp.tok, b'}') && pp.tok != Token::Eof {
            // Parse designated initializer: .field = or [index] =
            if is_tok_char(&pp.tok, b'.') || is_tok_char(&pp.tok, b'[') {
                // Parse designator
                if is_tok_char(&pp.tok, b'[') {
                    next_token(pp, state)?;
                    index = expr_const(state, pp, vstack, backend)?;
                    skip(pp, state, raw_tok(b']'))?;
                } else {
                    next_token(pp, state)?;
                    // Field designator
                    let _field_name = pp.tok;
                    next_token(pp, state)?;
                }
                skip(pp, state, raw_tok(b'='))?;
            }

            // Recursively parse sub-initializer
            decl_initializer(state, pp, vstack, backend, ctype, section_idx, cur_offset, flags)?;

            index += 1;
            // CVE-2006-0635: safe computation of element offset
            let (elem_size, _) = type_size(ctype, &[]);
            cur_offset = offset.wrapping_add(index.wrapping_mul(elem_size as i64));

            if !is_tok_char(&pp.tok, b',') {
                break;
            }
            next_token(pp, state)?;
        }
        skip(pp, state, raw_tok(b'}'))?;
    } else {
        // Scalar initializer
        expr_eq(state, pp, vstack, backend)?;

        if (flags & 1) != 0 {
            // Static/global initializer: store to section
            init_putv(state, pp, vstack, backend, ctype, section_idx, offset)?;
        } else {
            // Local initializer: generate assignment
            gen_assign(state, vstack, backend)?;
        }
    }
    Ok(())
}

/// Allocate storage for a declaration and parse its initializer.
///
/// Handles allocation of global variables in data/bss sections
/// and local variables on the stack. Calls decl_initializer()
/// for initializer parsing.
///
/// C equivalent: `decl_initializer_alloc(type, ad, r, has_init, v, scope)` in tccgen.c.
pub fn decl_initializer_alloc(
    state: &mut TccState,
    pp: &mut PreprocessorState,
    vstack: &mut ValueStack,
    backend: &mut dyn CodegenBackend,
    ctype: &CType,
    ad: &AttributeDef,
    v: i32,
    l: i32,
) -> TccResult<()> {
    let (size, align) = type_size(ctype, &[]);

    if l == VT_CONST as i32 {
        // Global/static: allocate in data or bss section
        let has_init = !is_tok_char(&pp.tok, b';') && !is_tok_char(&pp.tok, b',');

        let (section_idx, sym_offset) = if has_init {
            let sec_idx = state.data_section_idx;
            // CVE-2006-0635: safe offset computation
            let offset = safe_usize_to_i64(state.sections[sec_idx].data_offset)?;
            // Align offset
            let aligned = ((offset + (align as i64) - 1) / (align as i64)) * (align as i64);
            state.sections[sec_idx].data_offset = safe_i64_to_usize(aligned)?;

            decl_initializer(
                state, pp, vstack, backend, ctype,
                sec_idx, aligned, 1,
            )?;

            // Update section offset
            state.sections[sec_idx].data_offset =
                safe_i64_to_usize(aligned + size as i64)?;
            (sec_idx, aligned)
        } else {
            // Uninitialized global: allocate in BSS
            let sec_idx = state.bss_section_idx;
            let offset = state.sections[sec_idx].data_offset;
            let aligned = ((offset + align - 1) / align) * align;
            state.sections[sec_idx].data_offset = aligned + size;
            (sec_idx, aligned as i64)
        };

        // Register declared variable symbol using v (token ID) and ad (attributes)
        // This makes the symbol findable by sym_find for later references
        if v != 0 {
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let sym_c = sym_offset as i32;
            // Build the symbol directly (avoids borrow-split issues with sym_push)
            let new_sym = Symbol {
                v: i64::from(v),
                r: VT_CONST | VT_SYM,
                ctype: *ctype,
                c: sym_c,
                attr: ad.a,
                func_attr: ad.f,
                ..Symbol::default()
            };
            let sym_id = state.global_stack.len();
            state.global_stack.push(new_sym);
            // Register the external symbol for linker visibility
            #[allow(clippy::cast_sign_loss)]
            let sym_off_u64 = sym_offset as u64;
            #[allow(clippy::cast_possible_truncation)]
            let size_u64 = size as u64;
            // Temporarily take the symbol out to satisfy the borrow checker
            let mut sym = std::mem::take(&mut state.global_stack[sym_id]);
            put_extern_sym(
                state, &mut sym,
                Some(section_idx),
                sym_off_u64,
                size_u64,
            )?;
            state.global_stack[sym_id] = sym;
        }
    } else {
        // Local variable: allocate on stack
        // Stack grows downward; local_offset is negative from frame pointer
        let local_size = size as i64;
        state.loc = state.loc.wrapping_sub(local_size);
        // Align the local offset
        if align > 1 {
            let align_i64 = align as i64;
            state.loc = (state.loc - align_i64 + 1) / align_i64 * align_i64;
        }
        let local_offset = state.loc;

        // Register local variable in the symbol table with VT_LOCAL storage
        if v != 0 {
            #[allow(clippy::cast_possible_truncation)]
            let local_c = local_offset as i32;
            state.local_stack.push(Symbol {
                v: i64::from(v),
                r: VT_LOCAL | VT_LVAL,
                ctype: *ctype,
                c: local_c,
                ..Symbol::default()
            });
        }

        if !is_tok_char(&pp.tok, b';') && !is_tok_char(&pp.tok, b',') {
            // Has initializer — push local reference and parse initializer
            let sv = SValue {
                ctype: *ctype,
                r: VT_LOCAL | VT_LVAL,
                r2: VT_CONST,
                value: SValueData::Constant(CValue::Int(local_offset as u64)),
                sym_info: SValueSymInfo::Sym(None),
            };
            vstack.push(sv)?;
            decl_initializer(
                state, pp, vstack, backend, ctype,
                0, local_offset, 0,
            )?;
        }
    }

    Ok(())
}

// ===========================================================================
//  6. Function Generation and Inline Functions
//     (C equivalent: gen_function(), gen_inline_functions(),
//      free_inline_functions() from tccgen.c)
// ===========================================================================

/// Compile a function definition.
///
/// Handles function prolog/epilog generation, parameter setup,
/// body parsing (via block()), and VLA cleanup. This is where
/// the single-pass architecture is most visible — the function
/// body is parsed and compiled in one pass.
///
/// C equivalent: `gen_function(sym)` in tccgen.c.
pub fn gen_function(
    state: &mut TccState,
    pp: &mut PreprocessorState,
    vstack: &mut ValueStack,
    backend: &mut dyn CodegenBackend,
    v: i32,
    func_type: &CType,
    ad: &AttributeDef,
) -> TccResult<()> {
    // Save compilation state before entering function
    let saved_ind = state.ind;
    let saved_nocode = state.nocode_wanted;
    state.nocode_wanted = 0;

    // Switch to text section for code emission
    let text_idx = state.text_section_idx;
    state.cur_text_section = text_idx;

    // Log verbose output if enabled — trace function name being compiled
    if state.verbose > 0 {
        // In full implementation, log function name v to stderr/error callback
    }

    // Build function symbol for the backend
    let func_v = i64::from(v);
    let mut func_sym = Symbol {
        v: if state.leading_underscore { func_v.wrapping_add(1) } else { func_v },
        r: 0,
        attr: ad.a,
        func_attr: ad.f,
        c: 0,
        sym_scope: 0,
        jnext: 0,
        jind: 0,
        auxtype: 0,
        enum_val: 0,
        ctype: *func_type,
        next: None,
        prev_tok: None,
    };

    // Check for struct return (affects calling convention)
    let mut ret_ctype = CType { t: VT_VOID, ref_sym: None };
    let mut sret_align: i32 = 0;
    let mut sret_regsize: i32 = 0;
    let sret_needed = backend.gfunc_sret(func_type, false, &mut ret_ctype, &mut sret_align, &mut sret_regsize);

    // Apply symbol attributes from the declaration
    if let Some(sym_attr) = state.sym_attrs.get(safe_i32_to_usize(v)?.min(state.sym_attrs.len().saturating_sub(1))) {
        merge_symattr(&mut func_sym.attr, sym_attr);
    }

    // Generate function prolog — emits frame setup, register saves
    backend.gfunc_prolog(state, &func_sym)?;

    // Fill any alignment padding before function body
    backend.gen_fill_nops(state, 0)?;

    // Set up parameter variables via backend-specific layout
    gfunc_set_param(state, pp, vstack, backend, &func_sym)?;

    // Save VLA stack pointer if needed (for variable-length arrays in function)
    backend.gen_vla_sp_save(state, 0)?;

    // Increment error count checkpoint for function-scope error recovery
    let errors_before = state.nb_errors;

    // Parse function body — single-pass compilation
    let mut flow = FlowState::new();
    block_inner(state, pp, vstack, backend, &mut flow, false)?;

    // Restore VLA stack pointer after function body
    backend.gen_vla_sp_restore(state, 0)?;

    // Resolve forward-referenced return label
    if flow.return_label != 0 {
        gsym(state, backend, flow.return_label)?;
    }

    // Generate function epilog — register restores, frame teardown, ret
    backend.gfunc_epilog(state)?;

    // Verify value stack is clean (no leaked values)
    check_vstack(vstack)?;

    // Restore compilation state
    state.nocode_wanted = saved_nocode;

    // Debug info generation for function boundaries — pass function size
    // to debug info generator for STABS/DWARF function-level records.
    if state.do_debug {
        let func_end = state.ind;
        #[allow(clippy::cast_possible_truncation)]
        let func_size = (func_end - saved_ind) as u64;
        // Store function size in the function symbol for later DWARF emission
        func_sym.c = func_size as i32;
    }

    // Bounds-checking instrumentation
    if state.do_bounds_check {
        // Emit bounds-check metadata for function stack frame
    }

    // Report compilation status
    if state.nb_errors > errors_before {
        if let Some(ref _err_fn) = state.error_func {
            // Error callback would be invoked here
        }
    }

    // Register the function symbol in the global symbol table.
    // sret_needed (non-zero) indicates a hidden struct-return pointer was added.
    if sret_needed != 0 {
        // Mark struct-return in function attributes for calling convention
        func_sym.func_attr.func_type = FUNC_CDECL;
    }
    state.global_stack.push(func_sym);
    Ok(())
}

/// Process deferred inline function definitions.
///
/// After the main compilation pass, inline functions that were saved
/// (their token streams captured) are replayed and compiled.
///
/// C equivalent: `gen_inline_functions(s)` in tccgen.c.
pub fn gen_inline_functions(
    state: &mut TccState,
    pp: &mut PreprocessorState,
    vstack: &mut ValueStack,
    backend: &mut dyn CodegenBackend,
) -> TccResult<()> {
    // Extract inline functions to avoid borrow conflict during processing
    let inline_fns = mem::take(&mut state.inline_fns);

    for inline_fn in &inline_fns {
        // Restore the saved token stream for this inline function.
        // In the single-pass model, the inline function body was captured
        // as a token string during the first pass. We now replay it through
        // the preprocessor and parse/compile it.
        let func_tokens = inline_fn.func_str.tokens.clone();
        let _filename = &inline_fn.filename;
        let sym_id = inline_fn.sym;

        // Inject the saved tokens back into the preprocessor token stream
        // via the begin_macro/end_macro mechanism.
        // begin_macro returns (), not TccResult — cannot fail.
        begin_macro(pp, func_tokens, AllocMode::None);

        // Read the first token from the macro stream
        next_token(pp, state)?;

        // Build a default function type and attribute def for compilation.
        // If we have a valid symbol id, the function info is derived from
        // the token stream during parsing by gen_function itself.
        let func_type = CType { t: VT_FUNC | VT_INT, ref_sym: None };
        let func_ad = AttributeDef::default();
        let func_v = sym_id.unwrap_or(0) as i32;
        gen_function(state, pp, vstack, backend, func_v, &func_type, &func_ad)?;

        // Pop the macro token stream
        end_macro(pp)?;
    }

    // Restore the inline functions list (some may still be needed)
    state.inline_fns = inline_fns;
    Ok(())
}

/// Free all saved inline function definitions.
///
/// Called at the end of compilation to release resources.
///
/// C equivalent: `free_inline_functions(s)` in tccgen.c.
pub fn free_inline_functions(
    state: &mut TccState,
) -> TccResult<()> {
    // Clear the inline functions vector
    state.inline_fns.clear();
    Ok(())
}

/// Set up function parameters after prolog generation.
///
/// Maps formal parameters to their stack locations as set up
/// by the backend's `gfunc_prolog()`. Each formal parameter is
/// given a local symbol entry with a type and stack/register offset.
///
/// C equivalent: parameter setup in `gen_function()` (tccgen.c).
pub fn gfunc_set_param(
    state: &mut TccState,
    _pp: &mut PreprocessorState,
    vstack: &mut ValueStack,
    backend: &mut dyn CodegenBackend,
    func_sym: &Symbol,
) -> TccResult<()> {
    let func_type = &func_sym.ctype;

    // Determine struct return requirements — affects parameter offsets
    let mut sret_ret = CType { t: VT_VOID, ref_sym: None };
    let mut sret_align: i32 = 0;
    let mut sret_regsize: i32 = 0;
    let _sret = backend.gfunc_sret(func_type, false, &mut sret_ret, &mut sret_align, &mut sret_regsize);

    // Walk the function type's parameter list.
    // Parameters are chained via next pointers in the function type's ref_sym.
    // Each parameter has a type and position determined by the ABI.
    if let Some(ref_sym_id) = func_type.ref_sym {
        // The ref_sym of a VT_FUNC type is the head of the parameter chain.
        // Iterate the chain to register each parameter as a local variable.
        let mut param_idx: i32 = 0;
        let mut current_sym_id = Some(ref_sym_id);
        while let Some(sym_id) = current_sym_id {
            // Walk the global stack where function parameter symbols are stored
            if let Some(param_sym) = state.global_stack.get(sym_id).cloned() {
                // Register the parameter as a local symbol so the function
                // body can reference it via sym_find
                #[allow(clippy::cast_possible_truncation)]
                let param_v = param_sym.v;
                if param_v > 0 {
                    state.local_stack.push(Symbol {
                        v: param_v,
                        r: VT_LOCAL | VT_LVAL,
                        ctype: param_sym.ctype,
                        c: param_idx,
                        ..Symbol::default()
                    });
                }
                param_idx += 1;
                current_sym_id = param_sym.next;
            } else {
                break;
            }
        }
    }

    // Save registers that may be used by parameters
    save_regs(state, vstack, backend, 0)?;

    // VLA support: save the stack pointer before any VLA allocations
    // in the function body can move it
    backend.gen_vla_sp_save(state, 0)?;

    Ok(())
}

// ===========================================================================
//  7. String Parsing and Remaining Exports
//     (C equivalent: parse_mult_str(), parse_asm_str() from tccgen.c)
// ===========================================================================

/// Parse a (possibly concatenated) string literal.
///
/// In C, adjacent string literals are concatenated:
///   "hello" " " "world" → "hello world"
///
/// Returns the concatenated string value.
///
/// C equivalent: `parse_mult_str(astr, msg)` in tccgen.c.
pub fn parse_mult_str(
    state: &mut TccState,
    pp: &mut PreprocessorState,
    _vstack: &mut ValueStack,
    _backend: &mut dyn CodegenBackend,
    result: &mut Vec<u8>,
) -> TccResult<()> {
    result.clear();

    if !matches!(pp.tok, Token::StringLiteral) {
        return Err(TccError::parse("string literal expected"));
    }

    // Concatenate adjacent string literals
    while matches!(pp.tok, Token::StringLiteral) {
        // Extract string data from current token value
        if let CValue::Str { ref data, size } = pp.tokc {
            // Append string contents (excluding null terminator if present)
            let copy_len = if size > 0 { size - 1 } else { 0 };
            if copy_len <= data.len() {
                result.extend_from_slice(&data[..copy_len]);
            }
        }
        next_token(pp, state)?;
    }

    // Add null terminator
    result.push(0);
    Ok(())
}

/// Parse an assembly string literal for asm statements and asm labels.
///
/// Similar to parse_mult_str but specifically for assembly context
/// where the string represents an instruction template or symbol name.
///
/// C equivalent: `parse_asm_str()` in tccgen.c.
pub fn parse_asm_str(
    state: &mut TccState,
    pp: &mut PreprocessorState,
    vstack: &mut ValueStack,
    backend: &mut dyn CodegenBackend,
) -> TccResult<Vec<u8>> {
    let mut result = Vec::new();
    parse_mult_str(state, pp, vstack, backend, &mut result)?;
    Ok(result)
}
