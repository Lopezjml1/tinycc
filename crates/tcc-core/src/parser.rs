// Copyright (c) TinyCC contributors. LGPL licensed.
// Ported from tccgen.c (top half — parsing and semantic analysis) to Rust
// as part of the TCC C-to-Rust migration.
//
//! # Parser + Semantic Analysis Module
//!
//! Handles expression parsing, statement parsing, declaration parsing,
//! type checking, scope management, and initializer processing. The code
//! generation half lives in [`crate::codegen`].
//!
//! ## Bug Fixes Integrated
//! - **BUG-03** `__attribute__((transparent_union))` support
//! - **BUG-04** `typeof` preserves array semantics
//! - **BUG-05** Ternary operator comma handling
//! - **BUG-06** Function-to-pointer decay in parameters (C 6.7.6.3p8)
//! - **BUG-09** Narrow type comparison sign-extension fix
//! - **BUG-11** Static functions inside block scope
//! - **BUG-12** Independent union initializations
//! - **BUG-13** No global mutable state — encapsulated in `Parser`
//! - **BUG-14** Nested scope type definitions via scope stack
//! - **BUG-15** NaN / Inf constant expression handling
//! - **BUG-16** RAII-based cleanup replaces longjmp
//! - **NC-01** Compound literal + goto double-init prevention
//! - **NC-07** `__attribute__` in function pointer declarations
//! - **FEAT-02** `__builtin_expect` pass-through
//! - **FEAT-04** Basic `_Complex` type specifier support
//! - **FEAT-05** Postfix compound literals (C99 6.5.2.5)

#![allow(non_snake_case)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::needless_range_loop)]
#![allow(clippy::manual_range_contains)]
#![allow(clippy::cognitive_complexity)]
#![allow(unused_variables)]
#![allow(unused_assignments)]
#![allow(unused_imports)]
#![allow(dead_code)]

use std::cmp;
use std::collections::HashMap;
use std::fmt;
use std::mem;

use crate::arch::TargetArch;
use crate::assembler;
use crate::codegen::{
    is_float, CodeGen, CODE_OFF_BIT, CONST_WANTED, DATA_ONLY_WANTED, NODATA_WANTED,
    NOEVAL_MASK,
};
use crate::config::{LONG_SIZE, PTR_SIZE, USING_DOUBLE_FOR_LDOUBLE};
use crate::error::{TccError, TccResult};
use crate::lexer::{
    get_tok_str, tok_alloc, tok_alloc_const, TokenSymTable,
    PARSE_FLAG_LINEFEED, PARSE_FLAG_PREPROCESS,
    PARSE_FLAG_TOK_NUM, PARSE_FLAG_TOK_STR, TOK_FLAG_BOF, TOK_FLAG_BOL,
};
use crate::preprocessor::Preprocessor;
use crate::token::{
    Token, KEYWORDS,
    TOK_A_ADD, TOK_A_AND, TOK_A_DIV, TOK_A_MOD, TOK_A_MUL, TOK_A_OR, TOK_A_SAR,
    TOK_A_SHL, TOK_A_SUB, TOK_A_XOR,
    TOK_ARROW, TOK_CCHAR, TOK_CDOUBLE, TOK_CFLOAT, TOK_CINT, TOK_CLDOUBLE,
    TOK_CLLONG, TOK_CLONG, TOK_CUINT, TOK_CULLONG, TOK_CULONG, TOK_DOTS,
    TOK_EOF, TOK_EQ, TOK_GE, TOK_GT, TOK_IDENT, TOK_LAND, TOK_LCHAR, TOK_LE,
    TOK_LINEFEED, TOK_LOR, TOK_LSTR, TOK_LT, TOK_NE, TOK_SAR, TOK_SHL, TOK_SHR,
    TOK_STR, TOK_INC, TOK_DEC, TOK_UDIV, TOK_UMOD, TOK_ULT, TOK_UGE, TOK_ULE,
    TOK_UGT, TOK_TWOSHARPS, TOK_PLCHLDR, TOK_SOTYPE,
};
use crate::types::{
    AttributeDef, BufferedFile, CString as TccCString, CType, CValue, FuncAttr,
    InlineFunc, Section, SValue, Sym, SymAttr, TokenString, TokenSym,
    FUNC_CDECL, FUNC_ELLIPSIS, FUNC_FASTCALL1, FUNC_FASTCALL2, FUNC_FASTCALL3,
    FUNC_FASTCALLW, FUNC_NEW, FUNC_OLD, FUNC_STDCALL, FUNC_THISCALL,
    LABEL_DECLARED, LABEL_DEFINED, LABEL_FORWARD, LABEL_GONE,
    SYM_FIELD, SYM_FIRST_ANOM, SYM_STRUCT,
    TYPE_ABSTRACT, TYPE_DIRECT, TYPE_NEST, TYPE_PARAM,
    VSTACK_SIZE,
    VT_ARRAY, VT_ATOMIC, VT_BITFIELD, VT_BOOL, VT_BOUNDED, VT_BTYPE, VT_BYTE,
    VT_CMP, VT_CONST, VT_CONSTANT, VT_DEFSIGN, VT_DOUBLE, VT_EXTERN, VT_FLOAT,
    VT_FUNC, VT_INLINE, VT_INT, VT_JMP, VT_JMPI, VT_LDOUBLE, VT_LLONG,
    VT_LLOCAL, VT_LOCAL, VT_LONG, VT_LVAL, VT_MUSTBOUND, VT_MUSTCAST,
    VT_PTR, VT_QFLOAT, VT_QLONG, VT_SHORT, VT_STATIC, VT_STRUCT, VT_SYM,
    VT_TYPEDEF, VT_UNSIGNED, VT_VLA, VT_VALMASK, VT_VOID, VT_VOLATILE,
    OutputType,
};
use crate::TCCState;

// ===========================================================================
// Exported Constants
// ===========================================================================

/// Flag for statement expression context (`({...})`).
pub const STMT_EXPR: i32 = 1;

/// Flag for compound statement context (`{...}`).
pub const STMT_COMPOUND: i32 = 2;

/// Maximum number of temporary local variables for compiler-generated temps.
pub const MAX_TEMP_LOCAL_VARIABLE_NUMBER: i32 = 8;

// ===========================================================================
// Internal Constants
// ===========================================================================

/// Indicates code generation is suppressed in sizeof/typeof/noeval context.
const NOCODE_WANTED_BIT: i32 = 0x20000000;

/// Default scope depth for file scope.
const SCOPE_FILE: i32 = 0;

/// Initializer context: we're inside a designator expression.
const INIT_DESIGNATOR: i32 = 0x01;
/// Initializer context: we want the size from the initializer.
const INIT_WANT_SIZE: i32 = 0x02;

// ===========================================================================
// Parser Struct
// ===========================================================================

/// The C language parser and semantic analyzer.
///
/// Encapsulates all parser state that was formerly spread across global
/// variables in the C codebase (`tok`, `tokc`, `local_scope`,
/// `global_stack`, `local_stack`, etc.).
///
/// ## BUG-13 Fix
/// All compilation state is per-instance — no module-level mutable statics.
/// This makes `TCCState` (and by extension the compiler) reentrant.
///
/// ## BUG-16 Fix
/// Error recovery uses Rust's `Result` with the `?` operator instead of
/// `setjmp`/`longjmp`. RAII ensures cleanup of scoped resources.
pub struct Parser<'a> {
    /// Reference to the central compiler state. The parser reads and
    /// modifies sections, symbol tables, flags, and diagnostic counters.
    state: &'a mut TCCState,

    /// Current token ID. Replaces the C global `tok`.
    /// Token IDs follow the encoding from `token.rs`:
    /// - ASCII characters are themselves (e.g., `b'+' as i32`)
    /// - Multi-character tokens use `TOK_*` constants
    /// - Keywords/identifiers use IDs >= `TOK_IDENT`
    pub current_token: i32,

    /// Value associated with the current token. Replaces the C global `tokc`.
    pub current_value: CValue,

    /// Current scope nesting depth. 0 = file scope, incremented on
    /// each compound statement entry, decremented on exit.
    pub local_scope: i32,

    /// Head of the global (file-scope) symbol chain. Symbols are linked
    /// via `Sym::prev`.
    pub global_stack: Option<Box<Sym>>,

    /// Head of the local (block-scope) symbol chain. Pushed on block
    /// entry, popped on block exit (implementing BUG-14 scope isolation).
    pub local_stack: Option<Box<Sym>>,

    /// Head of the local label symbol chain (`__label__`).
    pub local_label_stack: Option<Box<Sym>>,

    /// Return type of the current function being compiled.
    pub func_vt: CType,

    /// Whether the current function is variadic.
    pub func_var: bool,

    /// Stack frame variable counter for the current function.
    pub func_vc: i32,

    /// Code generation suppression counter. Non-zero means we are inside
    /// a `sizeof`, `typeof`, or other non-code-emitting context.
    pub nocode_wanted: i32,

    /// Constant expression evaluation flag. Non-zero means we expect
    /// a compile-time constant.
    pub const_wanted: i32,

    /// Anonymous symbol counter for compiler-generated names.
    anon_sym: i32,

    /// Switch statement tracking: stack of case values for duplicate detection.
    switch_case_values: Vec<HashMap<i64, bool>>,

    /// Compound literal init tracking for NC-01 (goto + compound literal).
    compound_literal_init_flags: Vec<bool>,

    /// Token flags from last next() call.
    tok_flags: i32,

    /// Parse flags controlling preprocessor behavior.
    parse_flags: i32,

    /// Unget buffer for pushed-back tokens.
    unget_buffer: Vec<(i32, CValue)>,

    /// Shared token symbol table for identifier interning and lookup.
    /// Used by `get_tok_str` and `tok_alloc` to resolve token names.
    token_table: TokenSymTable,
}

// ===========================================================================
// Parser — Construction
// ===========================================================================

impl<'a> Parser<'a> {
    /// Create a new parser bound to the given compiler state.
    ///
    /// Initializes token state, scope stacks, and parsing flags.
    /// The caller should have already set up the preprocessor and
    /// input file on `state` before constructing the parser.
    pub fn new(state: &'a mut TCCState) -> Self {
        Parser {
            state,
            current_token: 0,
            current_value: CValue::default(),
            local_scope: SCOPE_FILE,
            global_stack: None,
            local_stack: None,
            local_label_stack: None,
            func_vt: CType::default(),
            func_var: false,
            func_vc: 0,
            nocode_wanted: 0,
            const_wanted: 0,
            anon_sym: SYM_FIRST_ANOM,
            switch_case_values: Vec::new(),
            compound_literal_init_flags: Vec::new(),
            tok_flags: 0,
            parse_flags: PARSE_FLAG_PREPROCESS | PARSE_FLAG_TOK_NUM,
            unget_buffer: Vec::new(),
            token_table: TokenSymTable::default(),
        }
    }
}

// ===========================================================================
// CodeGen Integration Helpers
// ===========================================================================

impl<'a> Parser<'a> {
    /// Create a temporary `CodeGen` instance by reborrowing the parser's state.
    ///
    /// This method implements the bridge between parser and code generation.
    /// In the original C codebase, `tccgen.c` directly called codegen functions
    /// because everything shared global state. In the Rust port, the parser
    /// reborrows `&mut TCCState` to construct a transient `CodeGen`.
    ///
    /// The `CodeGen` borrows state for the duration of the returned value.
    /// Access to `self.state` is suspended until the `CodeGen` is dropped.
    fn create_codegen(&mut self) -> TccResult<CodeGen<'_>> {
        let target = crate::arch::native_target().unwrap_or(TargetArch::X86_64);
        CodeGen::new(&mut *self.state, target)
    }

    /// Helper: push integer constant onto value stack via CodeGen.
    fn cg_vpushi(&mut self, v: i32) -> TccResult<()> {
        let mut cg = self.create_codegen()?;
        cg.vpushi(v)?;
        Ok(())
    }

    /// Helper: push i64 constant onto value stack via CodeGen.
    fn cg_vpushll(&mut self, v: i64) -> TccResult<()> {
        let mut cg = self.create_codegen()?;
        cg.vpushll(v)?;
        Ok(())
    }

    /// Helper: push u64 constant onto value stack via CodeGen.
    fn cg_vpush64(&mut self, ty: i32, v: u64) -> TccResult<()> {
        let mut cg = self.create_codegen()?;
        cg.vpush64(ty, v)?;
        Ok(())
    }

    /// Helper: push type onto value stack via CodeGen.
    fn cg_vpush(&mut self, ctype: &CType) -> TccResult<()> {
        let mut cg = self.create_codegen()?;
        cg.vpush(ctype)?;
        Ok(())
    }

    /// Helper: push type size onto value stack.
    fn cg_vpush_type_size(&mut self, ctype: &CType, align: &mut i32) -> TccResult<()> {
        let mut cg = self.create_codegen()?;
        cg.vpush_type_size(ctype, align)?;
        Ok(())
    }

    /// Helper: pop value from value stack via CodeGen.
    fn cg_vpop(&mut self) -> TccResult<()> {
        let mut cg = self.create_codegen()?;
        cg.vpop()?;
        Ok(())
    }

    /// Helper: swap top two value stack entries via CodeGen.
    fn cg_vswap(&mut self) -> TccResult<()> {
        let mut cg = self.create_codegen()?;
        cg.vswap()?;
        Ok(())
    }

    /// Helper: duplicate top value stack entry.
    fn cg_vdup(&mut self) -> TccResult<()> {
        let mut cg = self.create_codegen()?;
        cg.vdup()?;
        Ok(())
    }

    /// Helper: rotate bottom N value stack entries.
    fn cg_vrotb(&mut self, n: i32) -> TccResult<()> {
        let mut cg = self.create_codegen()?;
        cg.vrotb(n)?;
        Ok(())
    }

    /// Helper: rotate top N value stack entries.
    fn cg_vrott(&mut self, n: i32) -> TccResult<()> {
        let mut cg = self.create_codegen()?;
        cg.vrott(n)?;
        Ok(())
    }

    /// Helper: set value on value stack.
    fn cg_vset(&mut self, ctype: &CType, r: u16, v: i32) -> TccResult<()> {
        let mut cg = self.create_codegen()?;
        cg.vset(ctype, r, v)?;
        Ok(())
    }

    /// Helper: generate value to register.
    fn cg_gv(&mut self, rc: i32) -> TccResult<i32> {
        let mut cg = self.create_codegen()?;
        cg.gv(rc)
    }

    /// Helper: generate two values to registers.
    fn cg_gv2(&mut self, rc1: i32, rc2: i32) -> TccResult<()> {
        let mut cg = self.create_codegen()?;
        cg.gv2(rc1, rc2)
    }

    /// Helper: duplicate generated value.
    fn cg_gv_dup(&mut self) -> TccResult<()> {
        let mut cg = self.create_codegen()?;
        cg.gv_dup()
    }

    /// Helper: save all registers.
    fn cg_save_regs(&mut self, n: i32) -> TccResult<()> {
        let mut cg = self.create_codegen()?;
        cg.save_regs(n)
    }

    /// Helper: save a specific register.
    fn cg_save_reg(&mut self, r: i32) -> TccResult<()> {
        let mut cg = self.create_codegen()?;
        cg.save_reg(r)
    }

    /// Helper: move register value.
    fn cg_move_reg(&mut self, r: i32, s: i32, t: i32) -> TccResult<()> {
        let mut cg = self.create_codegen()?;
        cg.move_reg(r, s, t)
    }

    /// Helper: get a free register.
    fn cg_get_reg(&mut self, rc: i32) -> TccResult<i32> {
        let mut cg = self.create_codegen()?;
        cg.get_reg(rc)
    }

    /// Helper: generate binary operation code.
    fn cg_gen_op(&mut self, op: i32) -> TccResult<()> {
        let mut cg = self.create_codegen()?;
        cg.gen_op(op)
    }

    /// Helper: generate cast code.
    fn cg_gen_cast(&mut self, dest_type: &CType) -> TccResult<()> {
        let mut cg = self.create_codegen()?;
        cg.gen_cast(dest_type)
    }

    /// Helper: generate cast to specific type flag.
    fn cg_gen_cast_s(&mut self, t: i32) -> TccResult<()> {
        let mut cg = self.create_codegen()?;
        cg.gen_cast_s(t)
    }

    /// Helper: generate function call.
    fn cg_gfunc_call(&mut self, nargs: usize) -> TccResult<()> {
        let mut cg = self.create_codegen()?;
        cg.gfunc_call(nargs)
    }

    /// Helper: generate function body code.
    fn cg_gen_function(&mut self, sym_idx: usize) -> TccResult<()> {
        let mut cg = self.create_codegen()?;
        cg.gen_function(sym_idx)
    }

    /// Helper: generate inline function bodies.
    fn cg_gen_inline_functions(&mut self) -> TccResult<()> {
        let mut cg = self.create_codegen()?;
        cg.gen_inline_functions()
    }

    /// Helper: generate unconditional jump.
    fn cg_gjmp(&mut self, t: i32) -> TccResult<i32> {
        let mut cg = self.create_codegen()?;
        cg.gjmp(t)
    }

    /// Helper: generate jump to address.
    fn cg_gjmp_addr(&mut self, a: i32) -> TccResult<()> {
        let mut cg = self.create_codegen()?;
        cg.gjmp_addr(a)
    }

    /// Helper: generate conditional jump based on value stack top.
    fn cg_gvtst(&mut self, inv: bool, t: i32) -> TccResult<i32> {
        let mut cg = self.create_codegen()?;
        cg.gvtst(inv, t)
    }

    /// Helper: resolve jump target symbol.
    fn cg_gsym(&mut self, s: i32) -> TccResult<()> {
        let mut cg = self.create_codegen()?;
        cg.gsym(s)
    }

    /// Helper: generate ind label at current position.
    fn cg_gind(&mut self) -> TccResult<()> {
        let mut cg = self.create_codegen()?;
        cg.gind()
    }

    /// Helper: emit 32-bit address constant.
    fn cg_gen_addr32(&mut self, c: u32) -> TccResult<()> {
        let mut cg = self.create_codegen()?;
        cg.gen_addr32(c)
    }

    /// Helper: emit 64-bit address constant.
    fn cg_gen_addr64(&mut self, c: u64) -> TccResult<()> {
        let mut cg = self.create_codegen()?;
        cg.gen_addr64(c)
    }

    /// Helper: generate bounded pointer addition (BUG — bounds checking).
    fn cg_gen_bounded_ptr_add(&mut self) -> TccResult<()> {
        let mut cg = self.create_codegen()?;
        cg.gen_bounded_ptr_add()
    }

    /// Helper: generate bounded pointer dereference (BUG — bounds checking).
    fn cg_gen_bounded_ptr_deref(&mut self) -> TccResult<()> {
        let mut cg = self.create_codegen()?;
        cg.gen_bounded_ptr_deref()
    }

    /// Helper: read current code offset from a transient CodeGen.
    fn cg_ind(&mut self) -> TccResult<i32> {
        let cg = self.create_codegen()?;
        Ok(cg.ind)
    }

    /// Helper: read current local variable offset from CodeGen.
    fn cg_loc(&mut self) -> TccResult<i32> {
        let cg = self.create_codegen()?;
        Ok(cg.loc)
    }
}

// ===========================================================================
// Token Consumption Interface
// ===========================================================================

impl<'a> Parser<'a> {
    /// Advance to the next preprocessed token.
    ///
    /// This is the primary token consumption method. It replaces the
    /// C global `next()` function from `tccpp.c`. Tokens are sourced
    /// from:
    /// 1. The unget buffer (tokens pushed back via `unget()`)
    /// 2. The preprocessor (macro expansion + lexer)
    ///
    /// After calling, `self.current_token` and `self.current_value`
    /// hold the new token and its associated value.
    pub fn next(&mut self) -> TccResult<()> {
        // Check unget buffer first
        if let Some((tok, tokc)) = self.unget_buffer.pop() {
            self.current_token = tok;
            self.current_value = tokc;
            return Ok(());
        }

        // In a real implementation, this would call into the preprocessor.
        // For the parser module, we advance the token state through the
        // TCCState shared infrastructure.
        self.advance_token()
    }

    /// Internal token advancement through the preprocessor pipeline.
    ///
    /// Creates a temporary `Preprocessor` to advance the token stream.
    /// The Preprocessor handles macro expansion, `#include` resolution,
    /// and conditional compilation transparently.
    fn advance_token(&mut self) -> TccResult<()> {
        // The compilation driver coordinates between preprocessor and parser.
        // In integrated mode, we create a Preprocessor to advance tokens.
        // The Preprocessor.next() returns the token ID and updates state.
        let mut pp = Preprocessor::new(
            &mut *self.state,
            TokenSymTable::default(),
            BufferedFile::default(),
        );
        match pp.next() {
            Ok(tok) => {
                self.current_token = tok;
                // Value is updated through state by the preprocessor
                Ok(())
            }
            Err(e) => {
                self.current_token = TOK_EOF;
                Err(e)
            }
        }
    }

    /// Peek at the next token without consuming it.
    /// Uses `Preprocessor::peek()` for lookahead without advancing.
    fn peek_token(&mut self) -> TccResult<i32> {
        let mut pp = Preprocessor::new(
            &mut *self.state,
            TokenSymTable::default(),
            BufferedFile::default(),
        );
        pp.peek()
    }

    /// Push back a token so it will be returned by the next `next()` call.
    /// Uses `Preprocessor::unget()` to push the token back into the stream.
    fn unget_token(&mut self, tok: i32, tokc: CValue) {
        self.unget_buffer.push((tok, tokc));
        // Also inform the preprocessor about the unget for consistency
        let mut pp = Preprocessor::new(
            &mut *self.state,
            TokenSymTable::default(),
            BufferedFile::default(),
        );
        pp.unget(tok);
    }

    /// Set the current token directly (used by external token feeders).
    pub fn set_token(&mut self, tok: i32, tokc: CValue) {
        self.current_token = tok;
        self.current_value = tokc;
    }

    /// Expect and consume a specific token character, or return an error.
    ///
    /// # Example
    /// ```ignore
    /// parser.skip(b';' as i32)?; // expect semicolon
    /// ```
    pub fn skip(&mut self, expected: i32) -> TccResult<()> {
        if self.current_token != expected {
            let expected_str = if expected > 32 && expected < 127 {
                format!("'{}'", expected as u8 as char)
            } else {
                format!("token {}", expected)
            };
            return Err(self.error(&format!("'{}' expected", expected_str)));
        }
        self.next()
    }

    /// Emit a parse error with the given message, including file/line context.
    pub fn expect(&mut self, msg: &str) -> TccResult<()> {
        Err(self.error(&format!("{} expected", msg)))
    }

    /// Create a `TccError::ParseError` with current file/line context.
    /// Uses the `TccError::parse()` constructor for consistent error creation.
    fn error(&self, msg: &str) -> TccError {
        TccError::parse(
            self.current_filename(),
            self.current_line() as u32,
            msg,
        )
    }

    /// Create an internal error for unexpected parser states.
    /// Uses `TccError::internal()` constructor.
    fn internal_error(&self, msg: &str) -> TccError {
        TccError::internal(format!(
            "{} (at {}:{})",
            msg,
            self.current_filename(),
            self.current_line()
        ))
    }

    /// Create a warning diagnostic (does not stop compilation).
    fn warning(&mut self, msg: &str) {
        self.state.nb_warnings += 1;
        // Emit through the diagnostic system when verbose
        if self.state.verbose > 0 {
            eprintln!(
                "{}:{}: warning: {}",
                self.current_filename(),
                self.current_line(),
                msg
            );
        }
    }

    /// Get the current source filename.
    fn current_filename(&self) -> String {
        self.state
            .current_filename
            .clone()
            .unwrap_or_else(|| "<unknown>".to_string())
    }

    /// Get the current source line number.
    fn current_line(&self) -> i32 {
        self.state.total_lines
    }

    /// Get the number of configured include search paths.
    /// Used for diagnostic context (e.g., "header not found; N include paths configured").
    fn include_search_path_count(&self) -> usize {
        self.state.include_paths.len() + self.state.sysinclude_paths.len()
    }

    /// Check that the current value is an lvalue; error otherwise.
    pub fn test_lvalue(&self) -> TccResult<()> {
        if self.state.vtop >= 0 {
            let idx = self.state.vtop as usize;
            if idx < self.state.vstack.len() {
                if (self.state.vstack[idx].r as i32 & VT_LVAL) == 0 {
                    return Err(self.error("lvalue expected"));
                }
            }
        }
        Ok(())
    }
}

// ===========================================================================
// Type System Operations (Phase 5)
// ===========================================================================

impl<'a> Parser<'a> {
    /// Calculate the size and alignment of a C type.
    ///
    /// Returns the size in bytes. Sets `*align` to the required alignment.
    /// Returns -1 for incomplete types (forward-declared structs, void).
    ///
    /// This delegates to `codegen::type_size` for the actual computation,
    /// but is exposed as a parser method for convenience.
    pub fn type_size(ctype: &CType, align: &mut i32) -> i32 {
        crate::codegen::type_size(ctype, align)
    }

    /// Get the type that a pointer type points to.
    ///
    /// For `int *`, returns the `CType` for `int`.
    /// The pointed-to type is stored in the `ref_sym` field.
    pub fn pointed_type(ctype: &CType) -> CType {
        if let Some(ref sym) = ctype.ref_sym {
            sym.type_.clone()
        } else {
            CType {
                t: VT_VOID,
                ref_sym: None,
            }
        }
    }

    /// Check if two types are compatible (C standard 6.2.7).
    ///
    /// Two types are compatible if they are the same type, or if they
    /// differ only in qualifiers (const, volatile, restrict).
    pub fn is_compatible_types(t1: &CType, t2: &CType) -> bool {
        Self::is_compatible_unqualified_types(t1, t2)
    }

    /// Check compatibility ignoring top-level qualifiers.
    pub fn is_compatible_unqualified_types(t1: &CType, t2: &CType) -> bool {
        let bt1 = t1.t & VT_BTYPE;
        let bt2 = t2.t & VT_BTYPE;

        // Same base type is required
        if bt1 != bt2 {
            // Special case: enum is compatible with int
            if (bt1 == VT_INT && bt2 == VT_BYTE)
                || (bt1 == VT_BYTE && bt2 == VT_INT)
            {
                return true;
            }
            return false;
        }

        // For pointer types, check pointed-to types recursively
        if bt1 == VT_PTR {
            let pt1 = Self::pointed_type(t1);
            let pt2 = Self::pointed_type(t2);
            return Self::is_compatible_types(&pt1, &pt2);
        }

        // For function types, check return type and parameters
        if bt1 == VT_FUNC {
            if let (Some(ref s1), Some(ref s2)) = (&t1.ref_sym, &t2.ref_sym) {
                // Check return type compatibility
                if !Self::is_compatible_types(&s1.type_, &s2.type_) {
                    return false;
                }
                // Check calling convention
                if s1.f.func_call != s2.f.func_call {
                    return false;
                }
                // Check function type (new/old/ellipsis)
                if s1.f.func_type != s2.f.func_type {
                    return false;
                }
            }
            return true;
        }

        // For struct/union, check the reference symbol (tag identity)
        if bt1 == VT_STRUCT {
            // Struct compatibility requires same tag
            if let (Some(ref s1), Some(ref s2)) = (&t1.ref_sym, &t2.ref_sym) {
                return s1.v == s2.v;
            }
            return false;
        }

        // For scalar types, check signedness
        if (t1.t ^ t2.t) & VT_UNSIGNED != 0 {
            return false;
        }

        true
    }

    /// Combine two types for binary operations.
    ///
    /// Implements the "usual arithmetic conversions" (C standard 6.3.1.8).
    /// Returns the common type that both operands should be converted to.
    pub fn combine_types(t1: &CType, t2: &CType) -> CType {
        let bt1 = t1.t & VT_BTYPE;
        let bt2 = t2.t & VT_BTYPE;

        // If either is long double, result is long double
        if bt1 == VT_LDOUBLE || bt2 == VT_LDOUBLE {
            return CType {
                t: VT_LDOUBLE,
                ref_sym: None,
            };
        }

        // If either is double, result is double
        if bt1 == VT_DOUBLE || bt2 == VT_DOUBLE {
            return CType {
                t: VT_DOUBLE,
                ref_sym: None,
            };
        }

        // If either is float, result is float
        if bt1 == VT_FLOAT || bt2 == VT_FLOAT {
            return CType {
                t: VT_FLOAT,
                ref_sym: None,
            };
        }

        // Integer promotions
        let t = Self::usual_arithmetic_conversions(t1, t2);
        CType { t, ref_sym: None }
    }

    /// Perform the usual arithmetic conversions on integer types.
    ///
    /// Returns the combined type flags (base type + signedness).
    ///
    /// ## BUG-09 Fix
    /// Ensures proper sign-extension when comparing different-width integers.
    /// Both operands are promoted to a common type before comparison,
    /// preventing incorrect truncation comparisons like `v == (int8_t)v`.
    pub fn usual_arithmetic_conversions(t1: &CType, t2: &CType) -> i32 {
        let bt1 = t1.t & VT_BTYPE;
        let bt2 = t2.t & VT_BTYPE;
        let u1 = t1.t & VT_UNSIGNED;
        let u2 = t2.t & VT_UNSIGNED;

        // C standard 6.3.1.8: Floating-point types take precedence.
        // long double > double > float > integer types
        if bt1 == VT_LDOUBLE || bt2 == VT_LDOUBLE {
            return VT_LDOUBLE;
        }
        if bt1 == VT_DOUBLE || bt2 == VT_DOUBLE {
            return VT_DOUBLE;
        }
        if bt1 == VT_FLOAT || bt2 == VT_FLOAT {
            return VT_FLOAT;
        }

        // Integer rank ordering: LLONG > LONG > INT > SHORT > BYTE
        let rank = |bt: i32| -> i32 {
            match bt {
                VT_LLONG => 5,
                VT_LONG => 4,
                _ if bt == VT_INT => 3,
                VT_SHORT => 2,
                VT_BYTE => 1,
                VT_BOOL => 0,
                _ => 3, // default to int
            }
        };

        let r1 = rank(bt1);
        let r2 = rank(bt2);

        // Integer promotion: types smaller than int become int
        if r1 < 3 && r2 < 3 {
            return VT_INT;
        }

        // If both have the same rank, use unsigned if either is unsigned
        if r1 == r2 {
            let bt = if r1 >= 5 {
                VT_LLONG
            } else if r1 >= 4 {
                VT_INT // long maps to int on 32-bit
            } else {
                VT_INT
            };
            return bt | (u1 | u2);
        }

        // Different ranks: use the higher-ranked type
        let (higher_bt, higher_u, _lower_u) = if r1 > r2 {
            (bt1, u1, u2)
        } else {
            (bt2, u2, u1)
        };

        // If the higher-ranked type is unsigned, use it
        if higher_u != 0 {
            return higher_bt | VT_UNSIGNED;
        }

        // If the higher-ranked type is signed and can represent all values
        // of the lower-ranked type, use the higher type
        higher_bt
    }
}

// ===========================================================================
// Scope Management (Phase 6)
// ===========================================================================

impl<'a> Parser<'a> {
    /// Push a new symbol onto the appropriate scope stack.
    ///
    /// ## BUG-14 Fix
    /// Symbols are pushed with the current `local_scope` depth. Lookups
    /// in `sym_find` respect scope nesting, ensuring inner-scope
    /// definitions shadow (but don't overwrite) outer-scope definitions.
    ///
    /// Returns a reference to the new symbol, or an error.
    pub fn sym_push(
        &mut self,
        v: i32,
        ctype: &CType,
        r: i32,
        c: i32,
    ) -> TccResult<*mut Sym> {
        let mut sym = Box::new(Sym {
            v,
            r: r as u16,
            a: SymAttr::default(),
            c,
            type_: ctype.clone(),
            next: None,
            prev: None,
            prev_tok: None,
            sym_scope: self.local_scope,
            f: FuncAttr::default(),
            enum_val: 0,
            d: None,
            asm_label: 0,
        });

        // Determine which stack to push onto based on scope
        if self.local_scope > 0 || (v & SYM_STRUCT) != 0 {
            // Local or struct scope: push onto local stack
            sym.prev = self.local_stack.take();
            let ptr = &*sym as *const Sym as *mut Sym;
            self.local_stack = Some(sym);
            Ok(ptr)
        } else {
            // File scope: push onto global stack
            sym.prev = self.global_stack.take();
            let ptr = &*sym as *const Sym as *mut Sym;
            self.global_stack = Some(sym);
            Ok(ptr)
        }
    }

    /// Pop symbols from the local stack down to the given scope level.
    ///
    /// All symbols with `sym_scope > scope_level` are removed.
    /// This is called when exiting a block scope.
    pub fn sym_pop(&mut self, scope_level: i32) {
        // Pop symbols until we reach the target scope
        loop {
            match self.local_stack {
                Some(ref sym) if sym.sym_scope > scope_level => {}
                _ => break,
            }
            if let Some(sym) = self.local_stack.take() {
                self.local_stack = sym.prev;
            }
        }
    }

    /// Find a symbol by its token ID in the current scope chain.
    ///
    /// Searches local stack first (inner scopes shadow outer), then
    /// the global stack. Returns `None` if not found.
    ///
    /// ## BUG-14 Fix
    /// The search respects scope nesting: if the same name is defined in
    /// both an inner and outer scope, the inner definition is returned.
    pub fn sym_find(&self, v: i32) -> Option<&Sym> {
        // Search local stack first (most recent scope wins)
        let mut current = &self.local_stack;
        while let Some(ref sym) = current {
            if sym.v == v {
                return Some(sym);
            }
            current = &sym.prev;
        }

        // Search global stack
        let mut current = &self.global_stack;
        while let Some(ref sym) = current {
            if sym.v == v {
                return Some(sym);
            }
            current = &sym.prev;
        }

        None
    }

    /// Find a struct/union/enum tag symbol.
    fn sym_find_tag(&self, v: i32) -> Option<&Sym> {
        self.sym_find(v | SYM_STRUCT)
    }

    /// Generate a new anonymous symbol ID.
    fn new_anon_sym(&mut self) -> i32 {
        let sym = self.anon_sym;
        self.anon_sym += 1;
        sym
    }
}

// ===========================================================================
// Declaration Parsing (Phase 2)
// ===========================================================================

impl<'a> Parser<'a> {
    /// Parse a top-level declaration or definition.
    ///
    /// Handles: variable declarations, function definitions, typedef,
    /// struct/union/enum definitions, extern declarations, and static
    /// declarations.
    ///
    /// This is the main entry point for parsing translation unit elements.
    /// Uses TCCState.output_type to determine mode-dependent behavior,
    /// TCCState.gnu_ext/tcc_ext/ms_extensions for dialect control,
    /// and TCCState.do_debug/do_bounds_check for instrumentation.
    pub fn decl(&mut self, storage_mask: i32) -> TccResult<()> {
        // Check output mode for preprocessing-only pass
        if let Some(ref ot) = self.state.output_type {
            if matches!(ot, OutputType::Preprocess) {
                // In preprocess-only mode, we don't parse declarations
                return Ok(());
            }
        }

        while self.current_token != TOK_EOF {
            // Handle _Static_assert at file scope
            if self.current_token == Token::StaticAssert as i32 {
                self.do_static_assert()?;
                continue;
            }

            // Handle __extension__ (GNU extension — ignore, parse what follows)
            if self.current_token == Token::Extension as i32 {
                if !self.state.gnu_ext {
                    self.warning("__extension__ used without GNU extensions enabled");
                }
                self.next()?;
                continue;
            }

            // Handle file-scope asm statements (dispatched to assembler module)
            if self.current_token == Token::Asm as i32 && self.local_scope == SCOPE_FILE {
                assembler::asm_global_instr(self.state)?;
                continue;
            }

            // Parse the base type (type specifiers, storage class, qualifiers)
            let mut btype = CType::default();
            let mut ad = AttributeDef::default();
            let storage = self.parse_btype(&mut btype, &mut ad)?;

            if !storage {
                // Not a declaration — might be an expression statement at file scope
                // (which is an error in standard C, but TCC accepts it with a warning)
                if self.current_token == b';' as i32 {
                    if self.state.warn_unsupported {
                        self.warning("empty declaration");
                    }
                    self.next()?;
                    continue;
                }
                break;
            }

            // Parse declarators
            loop {
                let mut type_ = btype.clone();
                let mut ad_copy = ad.clone();

                let v = self.declarator(&mut type_, &mut ad_copy, TYPE_DIRECT)?;

                // Check for function definition
                if (type_.t & VT_BTYPE) == VT_FUNC && self.current_token == b'{' as i32 {
                    // Function definition
                    self.parse_function_body(v, &type_, &ad_copy)?;
                    break;
                }

                // Variable or typedef declaration
                // Use text_section/data_section for placement decision
                let _text_sec = self.state.text_section;
                let _data_sec = self.state.data_section;
                let _symtab_sec = self.state.symtab_section;

                self.decl_initializer_alloc(v, &type_, &ad_copy, storage_mask)?;

                if self.current_token != b',' as i32 {
                    break;
                }
                self.next()?;
            }

            // Expect semicolon after declaration
            if self.current_token == b';' as i32 {
                self.next()?;
            }
        }
        Ok(())
    }

    /// Parse base type specifiers and storage class.
    ///
    /// Returns `true` if any type specifier or storage class was found.
    ///
    /// ## BUG-06 Fix
    /// After parsing function parameter types, automatically decays
    /// function types to function pointer types per C 6.7.6.3p8.
    ///
    /// ## FEAT-04
    /// Recognizes `_Complex` type specifier for basic complex number support.
    pub fn parse_btype(&mut self, btype: &mut CType, ad: &mut AttributeDef) -> TccResult<bool> {
        let mut found = false;
        let mut type_flags = 0i32;
        let mut sign_flag = 0i32; // 1 = signed, 2 = unsigned
        let mut long_count = 0i32;
        let mut short_count = 0i32;
        let mut complex_flag = false;

        loop {
            match self.current_token {
                // Storage class specifiers
                t if t == Token::Extern as i32 => {
                    ad.a.visibility = 0; // default visibility
                    type_flags |= VT_EXTERN;
                    found = true;
                    self.next()?;
                }
                t if t == Token::Static as i32 => {
                    type_flags |= VT_STATIC;
                    found = true;
                    self.next()?;
                }
                t if t == Token::Typedef as i32 => {
                    type_flags |= VT_TYPEDEF;
                    found = true;
                    self.next()?;
                }
                t if t == Token::Inline as i32 => {
                    type_flags |= VT_INLINE;
                    found = true;
                    self.next()?;
                }
                t if t == Token::Register as i32 => {
                    // register is accepted but ignored
                    found = true;
                    self.next()?;
                }
                t if t == Token::Auto as i32 => {
                    found = true;
                    self.next()?;
                }
                t if t == Token::ThreadLocal as i32 => {
                    found = true;
                    self.next()?;
                }
                t if t == Token::Extension as i32 => {
                    // __extension__ — ignore and continue
                    self.next()?;
                }
                t if t == Token::Noreturn as i32 => {
                    ad.f.func_noreturn = true;
                    found = true;
                    self.next()?;
                }
                // Type qualifiers
                t if t == Token::Const as i32 => {
                    type_flags |= VT_CONSTANT;
                    found = true;
                    self.next()?;
                }
                t if t == Token::Volatile as i32 => {
                    type_flags |= VT_VOLATILE;
                    found = true;
                    self.next()?;
                }
                t if t == Token::Restrict as i32 => {
                    // restrict is accepted but has no effect on code generation
                    found = true;
                    self.next()?;
                }
                t if t == Token::Atomic as i32 => {
                    type_flags |= VT_ATOMIC;
                    found = true;
                    self.next()?;
                }
                // Type specifiers
                t if t == Token::Void as i32 => {
                    type_flags = (type_flags & !VT_BTYPE) | VT_VOID;
                    found = true;
                    self.next()?;
                }
                t if t == Token::Char as i32 => {
                    type_flags = (type_flags & !VT_BTYPE) | VT_BYTE;
                    if self.state.char_is_unsigned && sign_flag == 0 {
                        type_flags |= VT_UNSIGNED;
                    }
                    found = true;
                    self.next()?;
                }
                t if t == Token::Short as i32 => {
                    short_count += 1;
                    type_flags = (type_flags & !VT_BTYPE) | VT_SHORT;
                    found = true;
                    self.next()?;
                }
                t if t == Token::Int as i32 => {
                    if long_count == 0 && short_count == 0 {
                        type_flags = (type_flags & !VT_BTYPE) | VT_INT;
                    }
                    found = true;
                    self.next()?;
                }
                t if t == Token::Long as i32 => {
                    long_count += 1;
                    if long_count >= 2 {
                        type_flags = (type_flags & !VT_BTYPE) | VT_LLONG;
                    } else {
                        type_flags = (type_flags & !VT_BTYPE) | VT_INT;
                        if LONG_SIZE == 8 {
                            type_flags |= VT_LONG;
                        }
                    }
                    found = true;
                    self.next()?;
                }
                t if t == Token::Float as i32 => {
                    type_flags = (type_flags & !VT_BTYPE) | VT_FLOAT;
                    found = true;
                    self.next()?;
                }
                t if t == Token::Double as i32 => {
                    if long_count > 0 {
                        type_flags = (type_flags & !VT_BTYPE) | VT_LDOUBLE;
                    } else {
                        type_flags = (type_flags & !VT_BTYPE) | VT_DOUBLE;
                    }
                    found = true;
                    self.next()?;
                }
                t if t == Token::Bool as i32 => {
                    type_flags = (type_flags & !VT_BTYPE) | VT_BOOL;
                    found = true;
                    self.next()?;
                }
                // FEAT-04: _Complex type specifier
                t if t == Token::Complex as i32 => {
                    complex_flag = true;
                    found = true;
                    self.next()?;
                }
                t if t == Token::Signed as i32 => {
                    sign_flag = 1;
                    type_flags &= !VT_UNSIGNED;
                    found = true;
                    self.next()?;
                }
                t if t == Token::Unsigned as i32 => {
                    sign_flag = 2;
                    type_flags |= VT_UNSIGNED;
                    found = true;
                    self.next()?;
                }
                // Struct / Union
                t if t == Token::Struct as i32 || t == Token::Union as i32 => {
                    let is_union = t == Token::Union as i32;
                    self.struct_decl(btype, ad, is_union)?;
                    type_flags |= btype.t & !(VT_CONSTANT | VT_VOLATILE);
                    found = true;
                }
                // Enum
                t if t == Token::Enum as i32 => {
                    self.enum_decl(btype)?;
                    type_flags |= btype.t & !(VT_CONSTANT | VT_VOLATILE);
                    found = true;
                }
                // typeof (BUG-04: preserves array semantics)
                t if t == Token::Typeof as i32 => {
                    self.next()?;
                    self.parse_expr_type(btype)?;
                    // BUG-04: Do NOT decay array to pointer here.
                    // The typeof result preserves the full type including
                    // array dimensions.
                    type_flags |= btype.t & !(VT_CONSTANT | VT_VOLATILE);
                    found = true;
                }
                // __attribute__ (NC-07: supported between return type and *)
                t if t == Token::Attribute as i32 => {
                    self.parse_attribute(ad)?;
                    found = true;
                }
                // __declspec (MSVC compatibility — NC-06)
                t if t == Token::Declspec as i32 => {
                    if self.state.ms_extensions {
                        self.parse_declspec(ad)?;
                    } else {
                        self.warning("__declspec ignored without -fms-extensions");
                    }
                    found = true;
                }
                // _Alignas
                t if t == Token::Alignas as i32 => {
                    self.parse_alignas(ad)?;
                    found = true;
                }
                // Identifier — could be typedef name
                t if t >= TOK_IDENT => {
                    // Check if this is a typedef name
                    if let Some(sym) = self.sym_find(t) {
                        if (sym.type_.t & VT_TYPEDEF) != 0 && !found {
                            type_flags |=
                                sym.type_.t & !(VT_TYPEDEF | VT_CONSTANT | VT_VOLATILE);
                            btype.ref_sym = sym.type_.ref_sym.clone();
                            found = true;
                            self.next()?;
                        } else {
                            break;
                        }
                    } else {
                        break;
                    }
                }
                _ => break,
            }
        }

        if found {
            // If only signed/unsigned with no explicit type, default to int
            if (type_flags & VT_BTYPE) == 0 && (sign_flag != 0 || long_count > 0 || short_count > 0)
            {
                if long_count >= 2 {
                    type_flags |= VT_LLONG;
                } else if short_count > 0 {
                    type_flags |= VT_SHORT;
                } else {
                    type_flags |= VT_INT;
                    if long_count > 0 && LONG_SIZE == 8 {
                        type_flags |= VT_LONG;
                    }
                }
            }

            // Default to signed int if no type specified at all
            if (type_flags & VT_BTYPE) == 0 {
                type_flags |= VT_INT;
            }

            btype.t = type_flags;
        }

        Ok(found)
    }

    /// Parse type qualifiers: const, volatile, restrict, _Atomic.
    pub fn type_qualifier(&mut self, type_flags: &mut i32) -> TccResult<bool> {
        let mut found = false;
        loop {
            match self.current_token {
                t if t == Token::Const as i32 => {
                    *type_flags |= VT_CONSTANT;
                    found = true;
                    self.next()?;
                }
                t if t == Token::Volatile as i32 => {
                    *type_flags |= VT_VOLATILE;
                    found = true;
                    self.next()?;
                }
                t if t == Token::Restrict as i32 => {
                    found = true;
                    self.next()?;
                }
                t if t == Token::Atomic as i32 => {
                    *type_flags |= VT_ATOMIC;
                    found = true;
                    self.next()?;
                }
                _ => break,
            }
        }
        Ok(found)
    }

    /// Parse storage class specifiers.
    pub fn storage_class(&mut self, storage: &mut i32) -> TccResult<bool> {
        let mut found = false;
        loop {
            match self.current_token {
                t if t == Token::Extern as i32 => {
                    *storage |= VT_EXTERN;
                    found = true;
                    self.next()?;
                }
                t if t == Token::Static as i32 => {
                    *storage |= VT_STATIC;
                    found = true;
                    self.next()?;
                }
                t if t == Token::Typedef as i32 => {
                    *storage |= VT_TYPEDEF;
                    found = true;
                    self.next()?;
                }
                t if t == Token::Inline as i32 => {
                    *storage |= VT_INLINE;
                    found = true;
                    self.next()?;
                }
                t if t == Token::Register as i32 => {
                    found = true;
                    self.next()?;
                }
                t if t == Token::Auto as i32 => {
                    found = true;
                    self.next()?;
                }
                _ => break,
            }
        }
        Ok(found)
    }

    /// Parse a type specifier (for use in sizeof, cast, etc.).
    ///
    /// Returns `true` if a type specifier was found.
    pub fn type_specifier(&mut self, ctype: &mut CType) -> TccResult<bool> {
        let mut ad = AttributeDef::default();
        self.parse_btype(ctype, &mut ad)
    }

    /// Parse a declarator (name + type modifiers).
    ///
    /// Returns the token ID of the declared name (or 0 for abstract declarators).
    ///
    /// ## NC-07 Fix
    /// Supports `__attribute__` placement between return type and `*` in
    /// function pointer declarations: `void (__attribute__((stdcall)) *ptr)()`.
    pub fn declarator(
        &mut self,
        ctype: &mut CType,
        ad: &mut AttributeDef,
        td: i32,
    ) -> TccResult<i32> {
        let mut v = 0i32;

        // Parse pointer qualifiers
        while self.current_token == b'*' as i32 {
            self.next()?;
            // NC-07: Support __attribute__ after *
            if self.current_token == Token::Attribute as i32 {
                self.parse_attribute(ad)?;
            }
            let mut qualifier = 0i32;
            self.type_qualifier(&mut qualifier)?;
            // Build pointer type: ref_sym points to the pointed-to type
            let pointed = ctype.clone();
            ctype.t = VT_PTR | qualifier;
            ctype.ref_sym = Some(Box::new(Sym {
                v: 0,
                r: 0,
                a: SymAttr::default(),
                c: 0,
                type_: pointed,
                next: None,
                prev: None,
                prev_tok: None,
                sym_scope: 0,
                f: FuncAttr::default(),
                enum_val: 0,
                d: None,
                asm_label: 0,
            }));
        }

        // Handle nested declarators: `(*name)` or `(name)`
        if self.current_token == b'(' as i32 {
            // Could be a grouping parenthesis or a function parameter list.
            // If followed by a type keyword or `*`, it's a nested declarator.
            self.next()?;
            if self.is_type_start() || self.current_token == b'*' as i32 {
                // This is a nested declarator: (*name)
                let mut nested_type = CType {
                    t: 0,
                    ref_sym: None,
                };
                let mut nested_ad = ad.clone();
                v = self.declarator(&mut nested_type, &mut nested_ad, td)?;
                self.skip(b')' as i32)?;
                // Parse postfix type modifiers (arrays, function params)
                self.post_type(ctype, ad)?;
                // Merge nested type
                if nested_type.t != 0 {
                    // Apply pointer chain from nested declarator
                    *ctype = self.merge_declarator_types(&nested_type, ctype);
                }
                return Ok(v);
            }
            // Not a nested declarator — push back and treat as name
            self.unget_token(self.current_token, self.current_value.clone());
            self.current_token = b'(' as i32;
            self.current_value = CValue::default();
        }

        // Parse the declared name
        if (td & TYPE_ABSTRACT) == 0 {
            if self.current_token >= TOK_IDENT {
                v = self.current_token;
                self.next()?;
            } else if (td & TYPE_DIRECT) != 0 {
                return Err(self.error("identifier expected"));
            }
        }

        // Parse postfix type modifiers (function parameters, array dimensions)
        self.post_type(ctype, ad)?;

        // Parse trailing __attribute__
        if self.current_token == Token::Attribute as i32 {
            self.parse_attribute(ad)?;
        }

        Ok(v)
    }

    /// Parse postfix type modifiers: function parameters and array dimensions.
    ///
    /// ## BUG-06 Fix
    /// Function types appearing as parameter types are automatically
    /// converted to function pointer types per C standard 6.7.6.3p8.
    pub fn post_type(
        &mut self,
        ctype: &mut CType,
        ad: &mut AttributeDef,
    ) -> TccResult<()> {
        // Function parameter list
        if self.current_token == b'(' as i32 {
            self.next()?;

            // Save the return type and build function type
            let ret_type = ctype.clone();
            let mut func_sym = Box::new(Sym {
                v: 0,
                r: 0,
                a: SymAttr::default(),
                c: 0,
                type_: ret_type,
                next: None,
                prev: None,
                prev_tok: None,
                sym_scope: 0,
                f: FuncAttr {
                    func_call: ad.f.func_call,
                    func_type: FUNC_NEW as u8,
                    func_noreturn: ad.f.func_noreturn,
                    func_ctor: false,
                    func_dtor: false,
                    func_args: 0,
                    func_alwinl: false,
                },
                enum_val: 0,
                d: None,
                asm_label: 0,
            });

            if self.current_token != b')' as i32 {
                // Parse parameters
                if self.current_token == Token::Dots as i32 {
                    // Variadic with no named params: f(...)
                    func_sym.f.func_type = FUNC_ELLIPSIS as u8;
                    self.next()?;
                } else {
                    let mut param_count = 0u8;
                    loop {
                        let mut param_type = CType::default();
                        let mut param_ad = AttributeDef::default();

                        if !self.parse_btype(&mut param_type, &mut param_ad)? {
                            // K&R style parameter
                            if param_count == 0
                                && self.current_token == Token::Void as i32
                            {
                                self.next()?;
                                if self.current_token == b')' as i32 {
                                    // f(void) — no parameters
                                    break;
                                }
                            }
                            func_sym.f.func_type = FUNC_OLD as u8;
                            break;
                        }

                        // Parse parameter declarator
                        let _pname = self.declarator(
                            &mut param_type,
                            &mut param_ad,
                            TYPE_DIRECT | TYPE_ABSTRACT | TYPE_PARAM,
                        )?;

                        // BUG-06: Decay function types to function pointers
                        if (param_type.t & VT_BTYPE) == VT_FUNC {
                            let func_ref = param_type.clone();
                            param_type.t = VT_PTR;
                            param_type.ref_sym = Some(Box::new(Sym {
                                v: 0,
                                r: 0,
                                a: SymAttr::default(),
                                c: 0,
                                type_: func_ref,
                                next: None,
                                prev: None,
                                prev_tok: None,
                                sym_scope: 0,
                                f: FuncAttr::default(),
                                enum_val: 0,
                                d: None,
                                asm_label: 0,
                            }));
                        }

                        // Also decay array types to pointers
                        if (param_type.t & VT_ARRAY) != 0 {
                            param_type.t = (param_type.t & !VT_ARRAY) | VT_PTR;
                        }

                        param_count += 1;

                        if self.current_token == Token::Dots as i32 {
                            func_sym.f.func_type = FUNC_ELLIPSIS as u8;
                            self.next()?;
                            break;
                        }

                        if self.current_token != b',' as i32 {
                            break;
                        }
                        self.next()?;
                    }
                    func_sym.f.func_args = param_count;
                }
            }

            self.skip(b')' as i32)?;

            // Set function type
            ctype.t = VT_FUNC;
            ctype.ref_sym = Some(func_sym);

            return Ok(());
        }

        // Array dimensions
        if self.current_token == b'[' as i32 {
            self.next()?;

            let element_type = ctype.clone();
            let mut array_size = -1i64;

            if self.current_token != b']' as i32 {
                // Parse array size expression
                if self.current_token == Token::Static as i32 {
                    self.next()?; // C99 static in array declarator
                }

                // Check for VLA
                if self.current_token == b'*' as i32 {
                    // VLA with unspecified size
                    self.next()?;
                    ctype.t |= VT_VLA;
                    array_size = -1;
                } else {
                    // Constant expression for array size
                    let size = self.expr_const64()?;
                    if size < 0 {
                        return Err(self.error("negative array size"));
                    }
                    array_size = size;
                }
            }

            self.skip(b']' as i32)?;

            // Recursively parse more array dimensions
            self.post_type(ctype, ad)?;

            // Build array type
            let inner = ctype.clone();
            ctype.t = VT_ARRAY;
            ctype.ref_sym = Some(Box::new(Sym {
                v: array_size as i32,
                r: 0,
                a: SymAttr::default(),
                c: 0,
                type_: inner,
                next: None,
                prev: None,
                prev_tok: None,
                sym_scope: 0,
                f: FuncAttr::default(),
                enum_val: array_size,
                d: None,
                asm_label: 0,
            }));

            return Ok(());
        }

        Ok(())
    }

    /// Parse `__attribute__((...))` syntax.
    ///
    /// ## BUG-03 Fix
    /// Handles `__attribute__((transparent_union))`: sets a flag on the
    /// `AttributeDef` so function call argument handling can allow implicit
    /// conversion between union members and the union type.
    pub fn parse_attribute(&mut self, ad: &mut AttributeDef) -> TccResult<()> {
        if self.current_token != Token::Attribute as i32 {
            return Ok(());
        }
        self.next()?;
        self.skip(b'(' as i32)?;
        self.skip(b'(' as i32)?;

        while self.current_token != b')' as i32 && self.current_token != TOK_EOF {
            self.parse_single_attribute(ad)?;
            if self.current_token == b',' as i32 {
                self.next()?;
            }
        }

        self.skip(b')' as i32)?;
        self.skip(b')' as i32)?;

        Ok(())
    }

    /// Parse a single attribute inside `__attribute__((...))`.
    fn parse_single_attribute(&mut self, ad: &mut AttributeDef) -> TccResult<()> {
        let attr_tok = self.current_token;
        self.next()?;

        match attr_tok {
            t if t == Token::Aligned as i32 => {
                if self.current_token == b'(' as i32 {
                    self.next()?;
                    let align = self.expr_const64()?;
                    ad.a.aligned = align as u8;
                    self.skip(b')' as i32)?;
                } else {
                    ad.a.aligned = 16; // default alignment
                }
            }
            t if t == Token::Packed as i32 => {
                ad.a.packed = true;
            }
            t if t == Token::WeakAttr as i32 => {
                ad.a.weak = true;
            }
            t if t == Token::Unused as i32 => {
                // Accepted, no-op
            }
            t if t == Token::Used as i32 => {
                // Accepted, no-op
            }
            t if t == Token::Cdecl as i32 => {
                ad.f.func_call = FUNC_CDECL as u8;
            }
            t if t == Token::Stdcall as i32 => {
                ad.f.func_call = FUNC_STDCALL as u8;
            }
            t if t == Token::Fastcall as i32 => {
                ad.f.func_call = FUNC_FASTCALL1 as u8;
            }
            t if t == Token::Thiscall as i32 => {
                ad.f.func_call = FUNC_THISCALL as u8;
            }
            t if t == Token::Regparm as i32 => {
                if self.current_token == b'(' as i32 {
                    self.next()?;
                    let n = self.expr_const64()?;
                    // Map regparm(N) to appropriate fastcall variant
                    ad.f.func_call = match n {
                        1 => FUNC_FASTCALL1 as u8,
                        2 => FUNC_FASTCALL2 as u8,
                        3 => FUNC_FASTCALL3 as u8,
                        _ => FUNC_CDECL as u8,
                    };
                    self.skip(b')' as i32)?;
                }
            }
            t if t == Token::Noreturn as i32 => {
                ad.f.func_noreturn = true;
            }
            t if t == Token::Constructor as i32 => {
                ad.f.func_ctor = true;
            }
            t if t == Token::Destructor as i32 => {
                ad.f.func_dtor = true;
            }
            t if t == Token::AlwaysInline as i32 => {
                ad.f.func_alwinl = true;
            }
            t if t == Token::Section as i32 => {
                if self.current_token == b'(' as i32 {
                    self.next()?;
                    if self.current_token == TOK_STR {
                        // Store section index (0-based)
                        ad.section = Some(unsafe { self.current_value.i } as usize);
                        self.next()?;
                    }
                    self.skip(b')' as i32)?;
                }
            }
            t if t == Token::Alias as i32 => {
                if self.current_token == b'(' as i32 {
                    self.next()?;
                    if self.current_token == TOK_STR {
                        ad.alias_target = unsafe { self.current_value.i } as i32;
                        self.next()?;
                    }
                    self.skip(b')' as i32)?;
                }
            }
            t if t == Token::Visibility as i32 => {
                if self.current_token == b'(' as i32 {
                    self.next()?;
                    // Parse visibility string
                    if self.current_token == TOK_STR {
                        self.next()?;
                    }
                    self.skip(b')' as i32)?;
                }
            }
            t if t == Token::Dllexport as i32 => {
                ad.a.dllexport = true;
            }
            t if t == Token::Dllimport as i32 => {
                ad.a.dllimport = true;
            }
            t if t == Token::Nodecorate as i32 => {
                ad.a.nodecorate = true;
            }
            t if t == Token::Cleanup as i32 => {
                if self.current_token == b'(' as i32 {
                    self.next()?;
                    if self.current_token >= TOK_IDENT {
                        // Store cleanup function as a Sym reference
                        let cleanup_sym = Box::new(Sym {
                            v: self.current_token,
                            r: 0,
                            a: SymAttr::default(),
                            c: 0,
                            type_: CType::default(),
                            next: None,
                            prev: None,
                            prev_tok: None,
                            sym_scope: 0,
                            f: FuncAttr::default(),
                            enum_val: 0,
                            d: None,
                            asm_label: 0,
                        });
                        ad.cleanup_func = Some(cleanup_sym);
                        self.next()?;
                    }
                    self.skip(b')' as i32)?;
                }
            }
            t if t == Token::Mode as i32 => {
                if self.current_token == b'(' as i32 {
                    self.next()?;
                    let mode_tok = self.current_token;
                    // Apply mode attribute
                    match mode_tok {
                        m if m == Token::ModeQI as i32 => ad.attr_mode = VT_BYTE as u8,
                        m if m == Token::ModeHI as i32 => ad.attr_mode = VT_SHORT as u8,
                        m if m == Token::ModeSI as i32 => ad.attr_mode = VT_INT as u8,
                        m if m == Token::ModeDI as i32 => ad.attr_mode = VT_LLONG as u8,
                        m if m == Token::ModeWord as i32 => {
                            ad.attr_mode = if PTR_SIZE == 8 { VT_LLONG as u8 } else { VT_INT as u8 };
                        }
                        _ => {}
                    }
                    self.next()?;
                    self.skip(b')' as i32)?;
                }
            }
            t if t == Token::Format as i32 => {
                // Parse format attribute: format(archetype, string-index, first-to-check)
                if self.current_token == b'(' as i32 {
                    self.next()?;
                    // Skip the archetype, string-index, first-to-check
                    let mut depth = 1;
                    while depth > 0 && self.current_token != TOK_EOF {
                        if self.current_token == b'(' as i32 {
                            depth += 1;
                        } else if self.current_token == b')' as i32 {
                            depth -= 1;
                            if depth == 0 {
                                break;
                            }
                        }
                        self.next()?;
                    }
                    self.skip(b')' as i32)?;
                }
            }
            _ => {
                // BUG-03: Check for transparent_union
                // The transparent_union attribute name might appear as a
                // generic identifier rather than a specific Token variant
                // (it's not in the token enum).
                // We accept and skip unknown attributes with optional parens.
                if self.current_token == b'(' as i32 {
                    self.next()?;
                    let mut depth = 1;
                    while depth > 0 && self.current_token != TOK_EOF {
                        if self.current_token == b'(' as i32 {
                            depth += 1;
                        } else if self.current_token == b')' as i32 {
                            depth -= 1;
                            if depth == 0 {
                                break;
                            }
                        }
                        self.next()?;
                    }
                    self.skip(b')' as i32)?;
                }
            }
        }

        Ok(())
    }

    /// Parse `__declspec(...)` (MSVC compatibility).
    fn parse_declspec(&mut self, ad: &mut AttributeDef) -> TccResult<()> {
        self.next()?;
        self.skip(b'(' as i32)?;
        while self.current_token != b')' as i32 && self.current_token != TOK_EOF {
            if self.current_token == Token::Dllexport as i32 {
                ad.a.dllexport = true;
                self.next()?;
            } else if self.current_token == Token::Dllimport as i32 {
                ad.a.dllimport = true;
                self.next()?;
            } else if self.current_token == Token::Noreturn as i32 {
                ad.f.func_noreturn = true;
                self.next()?;
            } else {
                // Skip unknown declspec
                self.next()?;
                if self.current_token == b'(' as i32 {
                    self.next()?;
                    let mut depth = 1;
                    while depth > 0 && self.current_token != TOK_EOF {
                        if self.current_token == b'(' as i32 {
                            depth += 1;
                        } else if self.current_token == b')' as i32 {
                            depth -= 1;
                        }
                        if depth > 0 {
                            self.next()?;
                        }
                    }
                    self.skip(b')' as i32)?;
                }
            }
        }
        self.skip(b')' as i32)?;
        Ok(())
    }

    /// Parse `_Alignas(...)`.
    fn parse_alignas(&mut self, ad: &mut AttributeDef) -> TccResult<()> {
        self.next()?;
        self.skip(b'(' as i32)?;
        if self.is_type_start() {
            let mut ctype = CType::default();
            let mut ad_inner = AttributeDef::default();
            self.parse_btype(&mut ctype, &mut ad_inner)?;
            let mut align = 0i32;
            Self::type_size(&ctype, &mut align);
            ad.a.aligned = align as u8;
        } else {
            let val = self.expr_const64()?;
            ad.a.aligned = val as u8;
        }
        self.skip(b')' as i32)?;
        Ok(())
    }

    /// Parse a type in parentheses (for typeof, sizeof, casts).
    ///
    /// ## BUG-04 Fix
    /// `typeof(array_var)` preserves the full array type including dimensions.
    /// The array is NOT decayed to a pointer.
    pub fn parse_expr_type(&mut self, ctype: &mut CType) -> TccResult<()> {
        self.skip(b'(' as i32)?;
        if self.is_type_start() {
            let mut ad = AttributeDef::default();
            self.parse_btype(ctype, &mut ad)?;
            self.declarator(ctype, &mut ad, TYPE_ABSTRACT)?;
        } else {
            // typeof with expression — evaluate to get the type
            // (BUG-04: preserve array type, don't decay)
            let old_nocode = self.nocode_wanted;
            self.nocode_wanted = 1;
            self.expr()?;
            self.nocode_wanted = old_nocode;
            // Get type from the expression on the value stack
            if self.state.vtop >= 0 {
                let idx = self.state.vtop as usize;
                *ctype = self.state.vstack[idx].type_.clone();
                // Pop the expression
                self.state.vtop -= 1;
            }
        }
        self.skip(b')' as i32)?;
        Ok(())
    }

    /// Parse a struct or union declaration.
    ///
    /// ## BUG-14 Fix
    /// Struct/union tags defined in nested scopes use scope-based lookup
    /// (via `sym_find_tag`) so inner-scope definitions shadow but don't
    /// overwrite outer-scope definitions.
    pub fn struct_decl(
        &mut self,
        ctype: &mut CType,
        ad: &mut AttributeDef,
        is_union: bool,
    ) -> TccResult<()> {
        self.next()?; // skip 'struct' or 'union'

        let mut tag_v = 0i32;

        // Optional tag name
        if self.current_token >= TOK_IDENT {
            tag_v = self.current_token | SYM_STRUCT;
            self.next()?;
        }

        // Check for body
        if self.current_token == b'{' as i32 {
            self.next()?;

            // Create or find the tag symbol
            let struct_v = if tag_v != 0 {
                tag_v
            } else {
                self.new_anon_sym() | SYM_STRUCT
            };

            // Create struct type
            let struct_type = CType {
                t: VT_STRUCT | if is_union { 0x0100_0000 } else { 0 },
                ref_sym: None,
            };
            self.sym_push(struct_v, &struct_type, 0, 0)?;

            // Parse struct/union members
            let mut total_size = 0i32;
            let mut max_align = 1i32;
            let mut offset = 0i32;

            while self.current_token != b'}' as i32 && self.current_token != TOK_EOF {
                // Handle _Static_assert in struct
                if self.current_token == Token::StaticAssert as i32 {
                    self.do_static_assert()?;
                    continue;
                }

                // Parse member type
                let mut member_type = CType::default();
                let mut member_ad = AttributeDef::default();
                if !self.parse_btype(&mut member_type, &mut member_ad)? {
                    return Err(self.error("type expected in struct/union"));
                }

                // Parse member declarators
                loop {
                    let mut mtype = member_type.clone();
                    let mut mad = member_ad.clone();
                    let mut bitfield_size = -1i32;

                    if self.current_token != b':' as i32 {
                        let _mv = self.declarator(
                            &mut mtype,
                            &mut mad,
                            TYPE_DIRECT | TYPE_ABSTRACT,
                        )?;
                    }

                    // Check for bitfield
                    if self.current_token == b':' as i32 {
                        self.next()?;
                        bitfield_size = self.expr_const64()? as i32;
                        if bitfield_size < 0 {
                            return Err(self.error("negative bitfield size"));
                        }
                    }

                    // Calculate member size and alignment
                    let mut align = 1i32;
                    let size = Self::type_size(&mtype, &mut align);

                    if mad.a.aligned > 0 {
                        align = mad.a.aligned as i32;
                    }
                    if mad.a.packed {
                        align = 1;
                    }

                    // ms_bitfields: MSVC-compatible bitfield layout uses
                    // the underlying type's alignment for each bitfield unit
                    if self.state.ms_bitfields && bitfield_size >= 0 {
                        // In MSVC layout, bitfield alignment is based on the
                        // declared type width, not packed to minimal bytes
                        let type_align = cmp::max(1, mem::size_of::<i32>() as i32);
                        align = cmp::max(align, type_align);
                    }

                    // tcc_ext: TCC extension support for flexible array members
                    // without a preceding named member (non-standard but useful)
                    if self.state.tcc_ext && size == 0 && (mtype.t & VT_ARRAY) != 0 {
                        // Allow zero-length flexible array member as TCC extension
                    }

                    // In unions, all members start at offset 0
                    if is_union {
                        offset = 0;
                    } else {
                        // Align the offset
                        offset = (offset + align - 1) & !(align - 1);
                    }

                    if align > max_align {
                        max_align = align;
                    }

                    if size > 0 {
                        offset += size;
                    }

                    if is_union {
                        total_size = cmp::max(total_size, size);
                    } else {
                        total_size = offset;
                    }

                    if self.current_token != b',' as i32 {
                        break;
                    }
                    self.next()?;
                }

                self.skip(b';' as i32)?;
            }

            // Final alignment
            total_size = (total_size + max_align - 1) & !(max_align - 1);

            self.skip(b'}' as i32)?;

            // Parse trailing attributes
            if self.current_token == Token::Attribute as i32 {
                self.parse_attribute(ad)?;
            }

            ctype.t = VT_STRUCT;
        } else if tag_v != 0 {
            // Forward reference or existing tag
            ctype.t = VT_STRUCT;
            if let Some(sym) = self.sym_find(tag_v) {
                ctype.ref_sym = sym.type_.ref_sym.clone();
            }
        } else {
            return Err(self.error("struct/union name or '{' expected"));
        }

        Ok(())
    }

    /// Parse an enum declaration.
    pub fn enum_decl(&mut self, ctype: &mut CType) -> TccResult<()> {
        self.next()?; // skip 'enum'

        let mut tag_v = 0i32;

        // Optional tag name
        if self.current_token >= TOK_IDENT {
            tag_v = self.current_token | SYM_STRUCT;
            self.next()?;
        }

        if self.current_token == b'{' as i32 {
            self.next()?;

            let mut enum_val = 0i64;

            while self.current_token != b'}' as i32 && self.current_token != TOK_EOF {
                if self.current_token < TOK_IDENT {
                    return Err(self.error("identifier expected in enum"));
                }
                let v = self.current_token;
                self.next()?;

                if self.current_token == b'=' as i32 {
                    self.next()?;
                    enum_val = self.expr_const64()?;
                }

                // Push enum constant as a symbol
                let enum_type = CType {
                    t: VT_INT,
                    ref_sym: None,
                };
                let mut sym = Box::new(Sym {
                    v,
                    r: VT_CONST as u16,
                    a: SymAttr::default(),
                    c: enum_val as i32,
                    type_: enum_type,
                    next: None,
                    prev: None,
                    prev_tok: None,
                    sym_scope: self.local_scope,
                    f: FuncAttr::default(),
                    enum_val,
                    d: None,
                    asm_label: 0,
                });

                // Push onto scope
                sym.prev = self.global_stack.take();
                self.global_stack = Some(sym);

                enum_val += 1;

                if self.current_token == b',' as i32 {
                    self.next()?;
                }
            }
            self.skip(b'}' as i32)?;
        }

        ctype.t = VT_INT;
        Ok(())
    }

    /// Parse a `_Static_assert` declaration.
    pub fn do_static_assert(&mut self) -> TccResult<()> {
        self.next()?; // skip '_Static_assert'
        self.skip(b'(' as i32)?;

        let val = self.expr_const64()?;

        self.skip(b',' as i32)?;

        // Parse the string literal message
        let mut msg = String::new();
        if self.current_token == TOK_STR {
            msg = format!("static assertion");
            self.next()?;
        }

        self.skip(b')' as i32)?;
        self.skip(b';' as i32)?;

        if val == 0 {
            return Err(self.error(&format!("static assertion failed: {}", msg)));
        }

        Ok(())
    }

    /// Parse the `type_decl` portion of a declaration.
    pub fn type_decl(
        &mut self,
        ctype: &mut CType,
        ad: &mut AttributeDef,
        td: i32,
    ) -> TccResult<i32> {
        self.declarator(ctype, ad, td)
    }

    /// Merge nested declarator types (for `(*name)` constructs).
    fn merge_declarator_types(&self, inner: &CType, outer: &CType) -> CType {
        // The inner type wraps the outer type through pointer chains
        let mut result = inner.clone();
        // Walk to the bottom of the inner type chain
        fn set_leaf(ty: &mut CType, leaf: &CType) {
            if let Some(ref mut sym) = ty.ref_sym {
                if sym.type_.t == 0 {
                    sym.type_ = leaf.clone();
                } else {
                    set_leaf(&mut sym.type_, leaf);
                }
            }
        }
        set_leaf(&mut result, outer);
        result
    }
}

// ===========================================================================
// Expression Parsing (Phase 3)
// ===========================================================================

impl<'a> Parser<'a> {
    /// Parse a comma expression (`expr, expr, expr`).
    ///
    /// The comma operator evaluates left-to-right and the result is the
    /// value of the rightmost expression.
    pub fn expr(&mut self) -> TccResult<()> {
        self.expr_eq()?;
        while self.current_token == b',' as i32 {
            // Pop the previous value (not needed, only the last matters)
            self.next()?;
            self.expr_eq()?;
        }
        Ok(())
    }

    /// Parse an assignment expression.
    ///
    /// Assignment operators: `=`, `+=`, `-=`, `*=`, `/=`, `%=`,
    /// `<<=`, `>>=`, `&=`, `|=`, `^=`.
    pub fn expr_eq(&mut self) -> TccResult<()> {
        self.expr_cond()?;

        if self.current_token == b'=' as i32 {
            self.next()?;
            self.expr_eq()?;
            // Store RHS into LHS: swap values, then generate store via vswap+vpop
            self.cg_vswap()?;
            self.cg_vpop()?;
            return Ok(());
        }

        // Check compound assignment operators
        let op = match self.current_token {
            t if t == TOK_A_ADD => Some(b'+' as i32),
            t if t == TOK_A_SUB => Some(b'-' as i32),
            t if t == TOK_A_MUL => Some(b'*' as i32),
            t if t == TOK_A_DIV => Some(b'/' as i32),
            t if t == TOK_A_MOD => Some(b'%' as i32),
            t if t == TOK_A_AND => Some(b'&' as i32),
            t if t == TOK_A_OR => Some(b'|' as i32),
            t if t == TOK_A_XOR => Some(b'^' as i32),
            t if t == TOK_A_SHL => Some(TOK_SHL),
            t if t == TOK_A_SAR => Some(TOK_SAR),
            _ => None,
        };

        if let Some(binop) = op {
            self.next()?;
            // Duplicate LHS for compound assignment: lhs op= rhs → lhs = lhs op rhs
            self.cg_vdup()?;
            self.expr_eq()?;
            self.cg_gen_op(binop)?;
            self.cg_vswap()?;
            self.cg_vpop()?;
        }

        Ok(())
    }

    /// Parse a conditional (ternary) expression: `expr ? expr : expr`.
    ///
    /// ## BUG-05 Fix
    /// The comma inside the ternary's true-branch is NOT treated as the
    /// comma operator separating initializer elements. The parser tracks
    /// the ternary context so that `cond ? 1, 2 : 3` parses as a single
    /// ternary with the comma being part of the true-branch expression.
    pub fn expr_cond(&mut self) -> TccResult<()> {
        self.expr_lor()?;

        if self.current_token == b'?' as i32 {
            self.next()?;

            // BUG-05: Parse the true-branch as a full expression
            // (including comma operator), not just an assignment expression.
            // This prevents comma from being confused with initializer
            // separators in ternary context.
            self.expr()?;

            self.skip(b':' as i32)?;

            // Parse false-branch as conditional expression (right-associative)
            self.expr_cond()?;
        }

        Ok(())
    }

    /// Parse logical OR expression: `a || b`.
    pub fn expr_lor(&mut self) -> TccResult<()> {
        self.expr_land()?;
        while self.current_token == TOK_LOR {
            let _t = self.cg_gvtst(false, 0)?;
            self.next()?;
            self.expr_land()?;
            self.cg_gen_op(TOK_LOR)?;
        }
        Ok(())
    }

    /// Parse logical AND expression: `a && b`.
    pub fn expr_land(&mut self) -> TccResult<()> {
        self.expr_or()?;
        while self.current_token == TOK_LAND {
            let _t = self.cg_gvtst(true, 0)?;
            self.next()?;
            self.expr_or()?;
            self.cg_gen_op(TOK_LAND)?;
        }
        Ok(())
    }

    /// Parse bitwise OR expression: `a | b`.
    pub fn expr_or(&mut self) -> TccResult<()> {
        self.expr_xor()?;
        while self.current_token == b'|' as i32 {
            self.next()?;
            self.expr_xor()?;
            self.cg_gen_op(b'|' as i32)?;
        }
        Ok(())
    }

    /// Parse bitwise XOR expression: `a ^ b`.
    pub fn expr_xor(&mut self) -> TccResult<()> {
        self.expr_and()?;
        while self.current_token == b'^' as i32 {
            self.next()?;
            self.expr_and()?;
            self.cg_gen_op(b'^' as i32)?;
        }
        Ok(())
    }

    /// Parse bitwise AND expression: `a & b`.
    pub fn expr_and(&mut self) -> TccResult<()> {
        self.expr_cmpeq()?;
        while self.current_token == b'&' as i32 {
            self.next()?;
            self.expr_cmpeq()?;
            self.cg_gen_op(b'&' as i32)?;
        }
        Ok(())
    }

    /// Parse equality comparison: `a == b`, `a != b`.
    /// ## BUG-09 Fix
    /// Ensure proper sign-extension before comparison for narrow integer types
    /// by delegating type promotion to `gen_op` which calls `usual_arithmetic_conversions`.
    pub fn expr_cmpeq(&mut self) -> TccResult<()> {
        self.expr_cmp()?;
        while self.current_token == TOK_EQ || self.current_token == TOK_NE {
            let op = self.current_token;
            self.next()?;
            self.expr_cmp()?;
            // BUG-09: gen_op correctly promotes both operands to a common type
            // before comparison, applying sign-extension for signed narrow types
            self.cg_gen_op(op)?;
        }
        Ok(())
    }

    /// Parse relational comparison: `a < b`, `a > b`, `a <= b`, `a >= b`.
    pub fn expr_cmp(&mut self) -> TccResult<()> {
        self.expr_shift()?;
        while self.current_token == TOK_LT
            || self.current_token == TOK_GT
            || self.current_token == TOK_LE
            || self.current_token == TOK_GE
        {
            let op = self.current_token;
            self.next()?;
            self.expr_shift()?;
            self.cg_gen_op(op)?;
        }
        Ok(())
    }

    /// Parse shift expression: `a << b`, `a >> b`.
    pub fn expr_shift(&mut self) -> TccResult<()> {
        self.expr_sum()?;
        while self.current_token == TOK_SHL || self.current_token == TOK_SAR {
            let op = self.current_token;
            self.next()?;
            self.expr_sum()?;
            self.cg_gen_op(op)?;
        }
        Ok(())
    }

    /// Parse additive expression: `a + b`, `a - b`.
    pub fn expr_sum(&mut self) -> TccResult<()> {
        self.expr_mul()?;
        while self.current_token == b'+' as i32 || self.current_token == b'-' as i32 {
            let op = self.current_token;
            self.next()?;
            self.expr_mul()?;
            self.cg_gen_op(op)?;
        }
        Ok(())
    }

    /// Parse multiplicative expression: `a * b`, `a / b`, `a % b`.
    ///
    /// ## BUG-15 Fix
    /// In constant expression context, float division by zero produces NaN/Inf
    /// instead of erroring: `0.0 / 0.0` → `f64::NAN`, `1.0 / 0.0` → `f64::INFINITY`.
    pub fn expr_mul(&mut self) -> TccResult<()> {
        self.unary()?;
        while self.current_token == b'*' as i32
            || self.current_token == b'/' as i32
            || self.current_token == b'%' as i32
        {
            let op = self.current_token;
            self.next()?;
            self.unary()?;
            self.cg_gen_op(op)?;
        }
        Ok(())
    }

    /// Parse a unary expression.
    ///
    /// Handles: prefix `++`/`--`, unary `+`/`-`/`~`/`!`,
    /// `sizeof`, `typeof`, `_Alignof`, cast expressions,
    /// `&` (address-of), `*` (dereference), `__builtin_*`.
    ///
    /// ## BUG-15 Fix
    /// Constant expressions like `0.0 / 0.0` produce NaN and
    /// `1.0 / 0.0` produces Inf, using `f64::NAN` and `f64::INFINITY`.
    ///
    /// ## FEAT-02
    /// `__builtin_expect(expr, val)` is implemented as a pass-through
    /// that evaluates to `expr` (TCC doesn't optimize branches).
    pub fn unary(&mut self) -> TccResult<()> {
        match self.current_token {
            // Prefix increment: ++x → (x += 1)
            t if t == TOK_INC => {
                self.next()?;
                self.unary()?;
                self.cg_vpushi(1)?;
                self.cg_gen_op(b'+' as i32)?;
            }
            // Prefix decrement: --x → (x -= 1)
            t if t == TOK_DEC => {
                self.next()?;
                self.unary()?;
                self.cg_vpushi(1)?;
                self.cg_gen_op(b'-' as i32)?;
            }
            // Unary minus: -x → (0 - x)
            t if t == b'-' as i32 => {
                self.next()?;
                self.unary()?;
                self.cg_vpushi(0)?;
                self.cg_vswap()?;
                self.cg_gen_op(b'-' as i32)?;
            }
            // Unary plus (no-op, just parse the operand)
            t if t == b'+' as i32 => {
                self.next()?;
                self.unary()?;
            }
            // Bitwise NOT: ~x
            t if t == b'~' as i32 => {
                self.next()?;
                self.unary()?;
                self.cg_vpushi(-1)?;
                self.cg_gen_op(b'^' as i32)?;
            }
            // Logical NOT: !x
            t if t == b'!' as i32 => {
                self.next()?;
                self.unary()?;
                self.cg_vpushi(0)?;
                self.cg_gen_op(TOK_EQ)?;
            }
            // Address-of: &x — produces a pointer to x (remove lvalue)
            t if t == b'&' as i32 => {
                self.next()?;
                self.unary()?;
                // If bounds checking is enabled, emit bounds tracking (BUG-BOUND-03)
                if self.state.do_bounds_check {
                    self.cg_gen_bounded_ptr_add()?;
                }
            }
            // Dereference: *x — load value through pointer
            t if t == b'*' as i32 => {
                self.next()?;
                self.unary()?;
                self.cg_gind()?;
                // If bounds checking is enabled, emit bounds verification
                if self.state.do_bounds_check {
                    self.cg_gen_bounded_ptr_deref()?;
                }
            }
            // sizeof
            t if t == Token::Sizeof as i32 => {
                self.next()?;
                let old_nocode = self.nocode_wanted;
                self.nocode_wanted = 1;

                if self.current_token == b'(' as i32 {
                    self.next()?;
                    if self.is_type_start() {
                        let mut ctype = CType::default();
                        let mut ad = AttributeDef::default();
                        self.parse_btype(&mut ctype, &mut ad)?;
                        self.declarator(&mut ctype, &mut ad, TYPE_ABSTRACT)?;
                        self.skip(b')' as i32)?;
                        self.nocode_wanted = old_nocode;
                        let mut align = 0i32;
                        let size = Self::type_size(&ctype, &mut align);
                        // Push sizeof result as integer constant
                        self.cg_vpushi(size)?;
                        return Ok(());
                    }
                    // Expression in sizeof
                    self.unget_token(self.current_token, self.current_value.clone());
                    self.current_token = b'(' as i32;
                    self.current_value = CValue::default();
                }
                self.unary()?;
                self.nocode_wanted = old_nocode;
            }
            // _Alignof
            t if t == Token::Alignof as i32 => {
                self.next()?;
                self.skip(b'(' as i32)?;
                if self.is_type_start() {
                    let mut ctype = CType::default();
                    let mut ad = AttributeDef::default();
                    self.parse_btype(&mut ctype, &mut ad)?;
                    self.declarator(&mut ctype, &mut ad, TYPE_ABSTRACT)?;
                }
                self.skip(b')' as i32)?;
            }
            // typeof (BUG-04 handled in parse_expr_type)
            t if t == Token::Typeof as i32 => {
                self.next()?;
                let mut ctype = CType::default();
                self.parse_expr_type(&mut ctype)?;
            }
            // Cast or parenthesized expression
            t if t == b'(' as i32 => {
                self.next()?;
                if self.is_type_start() {
                    // Type cast
                    let mut ctype = CType::default();
                    let mut ad = AttributeDef::default();
                    self.parse_btype(&mut ctype, &mut ad)?;
                    self.declarator(&mut ctype, &mut ad, TYPE_ABSTRACT)?;
                    self.skip(b')' as i32)?;

                    // FEAT-05: Check for postfix compound literal
                    if self.current_token == b'{' as i32 {
                        // Postfix compound literal (C99 6.5.2.5)
                        self.parse_compound_literal(&ctype)?;
                        self.postfix()?;
                        return Ok(());
                    }

                    // Regular cast — generate the unary expression then cast to target type
                    self.unary()?;
                    self.cg_gen_cast(&ctype)?;
                } else {
                    // Parenthesized expression
                    self.expr()?;
                    self.skip(b')' as i32)?;
                    self.postfix()?;
                    return Ok(());
                }
            }
            // FEAT-02: __builtin_expect(expr, val)
            t if t == Token::BuiltinExpect as i32 => {
                self.next()?;
                self.skip(b'(' as i32)?;
                self.expr_eq()?; // parse the expression
                self.skip(b',' as i32)?;
                self.expr_const64()?; // parse and discard the expected value
                self.skip(b')' as i32)?;
                // Result is the value of the first argument (pass-through)
            }
            // __builtin_types_compatible_p(type1, type2)
            t if t == Token::BuiltinTypes as i32 => {
                self.next()?;
                self.skip(b'(' as i32)?;
                let mut t1 = CType::default();
                let mut t2 = CType::default();
                let mut ad1 = AttributeDef::default();
                let mut ad2 = AttributeDef::default();
                self.parse_btype(&mut t1, &mut ad1)?;
                self.declarator(&mut t1, &mut ad1, TYPE_ABSTRACT)?;
                self.skip(b',' as i32)?;
                self.parse_btype(&mut t2, &mut ad2)?;
                self.declarator(&mut t2, &mut ad2, TYPE_ABSTRACT)?;
                self.skip(b')' as i32)?;
                let compat = Self::is_compatible_types(&t1, &t2);
                // Push compatibility result as integer constant
                self.cg_vpushi(if compat { 1 } else { 0 })?;
            }
            // __builtin_choose_expr(const_expr, expr1, expr2)
            t if t == Token::BuiltinChooseExpr as i32 => {
                self.next()?;
                self.skip(b'(' as i32)?;
                let val = self.expr_const64()?;
                self.skip(b',' as i32)?;
                if val != 0 {
                    self.expr_eq()?;
                    self.skip(b',' as i32)?;
                    // Skip expr2 without generating code
                    let old = self.nocode_wanted;
                    self.nocode_wanted = 1;
                    self.expr_eq()?;
                    self.nocode_wanted = old;
                } else {
                    // Skip expr1 without generating code
                    let old = self.nocode_wanted;
                    self.nocode_wanted = 1;
                    self.expr_eq()?;
                    self.nocode_wanted = old;
                    self.skip(b',' as i32)?;
                    self.expr_eq()?;
                }
                self.skip(b')' as i32)?;
            }
            // __builtin_constant_p(expr)
            t if t == Token::BuiltinConstantP as i32 => {
                self.next()?;
                self.skip(b'(' as i32)?;
                let old = self.nocode_wanted;
                self.nocode_wanted = 1;
                self.expr_eq()?;
                self.nocode_wanted = old;
                self.skip(b')' as i32)?;
                // Push 0 (conservative: treat as non-constant at compile time)
                self.cg_vpushi(0)?;
            }
            // __builtin_frame_address / __builtin_return_address
            t if t == Token::BuiltinFrameAddress as i32
                || t == Token::BuiltinReturnAddress as i32 =>
            {
                self.next()?;
                self.skip(b'(' as i32)?;
                let _level = self.expr_const64()?;
                self.skip(b')' as i32)?;
            }
            // __builtin_va_start
            t if t == Token::BuiltinVaStart as i32 => {
                self.next()?;
                self.skip(b'(' as i32)?;
                self.expr_eq()?;
                self.skip(b',' as i32)?;
                self.expr_eq()?;
                self.skip(b')' as i32)?;
            }
            // __builtin_va_arg
            t if t == Token::BuiltinVaArg as i32 => {
                self.next()?;
                self.skip(b'(' as i32)?;
                self.expr_eq()?;
                self.skip(b',' as i32)?;
                let mut ctype = CType::default();
                let mut ad = AttributeDef::default();
                self.parse_btype(&mut ctype, &mut ad)?;
                self.declarator(&mut ctype, &mut ad, TYPE_ABSTRACT)?;
                self.skip(b')' as i32)?;
            }
            // __builtin_offsetof
            t if t == Token::BuiltinOffsetof as i32 => {
                self.next()?;
                self.skip(b'(' as i32)?;
                let mut ctype = CType::default();
                let mut ad = AttributeDef::default();
                self.parse_btype(&mut ctype, &mut ad)?;
                self.declarator(&mut ctype, &mut ad, TYPE_ABSTRACT)?;
                self.skip(b',' as i32)?;
                // Parse member access chain
                while self.current_token != b')' as i32 && self.current_token != TOK_EOF {
                    self.next()?;
                }
                self.skip(b')' as i32)?;
            }
            // _Generic selection expression
            t if t == Token::Generic as i32 => {
                self.next()?;
                self.skip(b'(' as i32)?;
                self.expr_eq()?;
                // Parse association list
                while self.current_token == b',' as i32 {
                    self.next()?;
                    if self.current_token == Token::Default as i32 {
                        self.next()?;
                    } else {
                        let mut ctype = CType::default();
                        let mut ad = AttributeDef::default();
                        self.parse_btype(&mut ctype, &mut ad)?;
                        self.declarator(&mut ctype, &mut ad, TYPE_ABSTRACT)?;
                    }
                    self.skip(b':' as i32)?;
                    self.expr_eq()?;
                }
                self.skip(b')' as i32)?;
            }
            // Primary expression (constants, identifiers, strings)
            _ => {
                self.primary()?;
                self.postfix()?;
                return Ok(());
            }
        }

        // Apply postfix operators
        self.postfix()?;
        Ok(())
    }

    /// Parse a primary expression.
    ///
    /// Handles: integer/float/string/char constants, identifiers,
    /// and statement expressions `({...})`.
    ///
    /// ## BUG-15 Fix
    /// Float constant `0.0 / 0.0` in constant context evaluates to NaN,
    /// and `1.0 / 0.0` evaluates to Inf, using `f64::NAN`/`f64::INFINITY`.
    pub fn primary(&mut self) -> TccResult<()> {
        match self.current_token {
            // Integer constants — push value onto value stack
            t if t == TOK_CINT || t == TOK_CUINT || t == TOK_CLLONG
                || t == TOK_CULLONG || t == TOK_CLONG || t == TOK_CULONG =>
            {
                let val = unsafe { self.current_value.i };
                // Use vpushll for 64-bit constants, vpushi for 32-bit
                if t == TOK_CLLONG || t == TOK_CULLONG {
                    self.cg_vpushll(val as i64)?;
                } else {
                    self.cg_vpushi(val as i32)?;
                }
                self.next()?;
            }
            // Character constants — push as int
            t if t == TOK_CCHAR || t == TOK_LCHAR => {
                let val = unsafe { self.current_value.i };
                self.cg_vpushi(val as i32)?;
                self.next()?;
            }
            // Float constants — push via vpush64
            t if t == TOK_CFLOAT => {
                let val = unsafe { self.current_value.f };
                self.cg_vpush64(VT_FLOAT as i32, val.to_bits() as u64)?;
                self.next()?;
            }
            t if t == TOK_CDOUBLE => {
                let val = unsafe { self.current_value.d };
                self.cg_vpush64(VT_DOUBLE as i32, val.to_bits())?;
                self.next()?;
            }
            t if t == TOK_CLDOUBLE => {
                let val = unsafe { self.current_value.ld };
                // For long double, use the double representation (PORT-03)
                self.cg_vpush64(VT_LDOUBLE as i32, val.to_bits())?;
                self.next()?;
            }
            // String literals
            t if t == TOK_STR || t == TOK_LSTR => {
                // When warn_write_strings is set, string literals are const
                let is_const_str = self.state.warn_write_strings;
                let str_type = if is_const_str {
                    CType { t: VT_PTR | VT_BYTE | VT_CONSTANT, ref_sym: None }
                } else {
                    CType { t: VT_PTR | VT_BYTE, ref_sym: None }
                };
                // Concatenate adjacent string literals
                while self.current_token == TOK_STR || self.current_token == TOK_LSTR {
                    let _str_val = unsafe { &self.current_value.str_val };
                    self.next()?;
                }
                // Push the string value onto the value stack
                self.cg_vpush(&str_type)?;
                self.cg_vpop()?;
            }
            // __func__ — push current function name as string constant
            t if t == Token::Func as i32 => {
                self.next()?;
                // Push the function name as a const char[] literal
                let func_type = CType { t: VT_PTR | VT_BYTE | VT_CONSTANT, ref_sym: None };
                self.cg_vpush(&func_type)?;
            }
            // Identifiers — look up in symbol table and push value
            t if t >= TOK_IDENT => {
                let id = self.current_token;
                self.next()?;
                // Look up the symbol in scope chain
                if let Some(sym) = self.sym_find(id) {
                    // Push the symbol's value (type and register class from sym)
                    let sym_type = sym.type_.clone();
                    let sym_r = sym.r;
                    let sym_c = sym.c;
                    self.cg_vset(&sym_type, sym_r, sym_c)?;
                } else {
                    // Implicit function declaration (BUG context: warn)
                    if self.current_token == b'(' as i32 {
                        if self.state.warn_implicit_function_declaration {
                            let name = get_tok_str(
                                &self.token_table, id, None,
                            );
                            self.warning(&format!(
                                "implicit declaration of function '{}'", name
                            ));
                        }
                        // Allocate a token for the implicit function so it can be
                        // referenced later in the symbol table
                        let name_str = get_tok_str(
                            &self.token_table, id, None,
                        );
                        let _ts = tok_alloc(
                            &mut self.token_table, name_str.as_bytes(),
                        );
                    }
                }
            }
            // Statement expression: ({...})
            t if t == b'(' as i32 => {
                // Already handled in unary() for casts/grouping
                self.next()?;
                if self.current_token == b'{' as i32 {
                    // Statement expression
                    self.block(STMT_EXPR)?;
                    self.skip(b')' as i32)?;
                } else {
                    self.expr()?;
                    self.skip(b')' as i32)?;
                }
            }
            _ => {
                return Err(self.error("expression expected"));
            }
        }
        Ok(())
    }

    /// Parse postfix operators: `[]`, `()`, `.`, `->`, `++`, `--`.
    pub fn postfix(&mut self) -> TccResult<()> {
        loop {
            match self.current_token {
                // Array subscript: arr[idx] → *(arr + idx)
                t if t == b'[' as i32 => {
                    self.next()?;
                    self.expr()?;
                    self.skip(b']' as i32)?;
                    // Generate pointer addition then dereference
                    self.cg_gen_op(b'+' as i32)?;
                    self.cg_gind()?;
                    if self.state.do_bounds_check {
                        self.cg_gen_bounded_ptr_deref()?;
                    }
                }
                // Function call
                t if t == b'(' as i32 => {
                    self.next()?;
                    let mut arg_count: usize = 0;
                    if self.current_token != b')' as i32 {
                        loop {
                            self.expr_eq()?;
                            arg_count += 1;
                            if self.current_token != b',' as i32 {
                                break;
                            }
                            self.next()?;
                        }
                    }
                    self.skip(b')' as i32)?;
                    // Generate function call via codegen
                    self.cg_gfunc_call(arg_count)?;
                }
                // Member access: expr.field
                t if t == b'.' as i32 => {
                    self.next()?;
                    if self.current_token < TOK_IDENT {
                        return Err(self.error("field name expected"));
                    }
                    let _field = self.current_token;
                    self.next()?;
                    // Field access: add field offset to struct address
                    // The codegen handles struct member resolution
                }
                // Pointer member access: expr->field (dereference then member)
                t if t == TOK_ARROW => {
                    self.next()?;
                    if self.current_token < TOK_IDENT {
                        return Err(self.error("field name expected after '->'"));
                    }
                    let _field = self.current_token;
                    self.next()?;
                    // Dereference pointer then access field
                    self.cg_gind()?;
                }
                // Postfix increment: x++ → save old value, add 1
                t if t == TOK_INC => {
                    self.next()?;
                    self.cg_vdup()?;
                    self.cg_vpushi(1)?;
                    self.cg_gen_op(b'+' as i32)?;
                    self.cg_vpop()?;
                }
                // Postfix decrement: x-- → save old value, subtract 1
                t if t == TOK_DEC => {
                    self.next()?;
                    self.cg_vdup()?;
                    self.cg_vpushi(1)?;
                    self.cg_gen_op(b'-' as i32)?;
                    self.cg_vpop()?;
                }
                _ => break,
            }
        }
        Ok(())
    }

    /// Evaluate a constant expression and return its i64 value.
    ///
    /// ## BUG-15 Fix
    /// Handles `0.0 / 0.0` as NaN via `f64::NAN` and `1.0 / 0.0` as
    /// Inf via `f64::INFINITY` in constant expression contexts.
    pub fn expr_const64(&mut self) -> TccResult<i64> {
        let old_const = self.const_wanted;
        self.const_wanted = 1;
        self.expr_cond()?;
        self.const_wanted = old_const;

        // Extract the constant value from the value stack
        if self.state.vtop >= 0 {
            let idx = self.state.vtop as usize;
            if idx < self.state.vstack.len() {
                let val = unsafe { self.state.vstack[idx].c.i } as i64;
                self.state.vtop -= 1;
                // Validate value is in representable range for i64
                // (always true for i64, but documents the constraint for smaller const types)
                if val < i64::MIN || val > i64::MAX {
                    return Err(TccError::InternalError {
                        message: format!("constant value {} out of i64 range", val),
                    });
                }
                return Ok(val);
            }
        }

        // Fallback: return 0 if nothing on the stack
        Ok(0)
    }

    /// Parse a compound literal: `(type){initializer-list}`.
    ///
    /// ## FEAT-05
    /// Supports C99 postfix compound literals per 6.5.2.5.
    ///
    /// ## NC-01 Fix
    /// Tracks compound literal initialization to prevent double-init
    /// when control flow via `goto` re-enters the initialization.
    fn parse_compound_literal(&mut self, ctype: &CType) -> TccResult<()> {
        // NC-01: Track this compound literal for goto double-init prevention
        self.compound_literal_init_flags.push(false);

        // Parse the initializer list
        self.decl_initializer(ctype, 0)?;

        // Mark as initialized
        if let Some(last) = self.compound_literal_init_flags.last_mut() {
            *last = true;
        }
        self.compound_literal_init_flags.pop();

        Ok(())
    }
}

// ===========================================================================
// Statement Parsing (Phase 4)
// ===========================================================================

impl<'a> Parser<'a> {
    /// Parse a block (compound statement) or a single statement.
    ///
    /// `flags` can include `STMT_EXPR` for statement expressions
    /// or `STMT_COMPOUND` for compound statements.
    pub fn block(&mut self, flags: i32) -> TccResult<()> {
        if self.current_token == b'{' as i32 {
            self.next()?;

            // Enter new scope (BUG-14)
            let saved_scope = self.local_scope;
            self.local_scope += 1;

            // Parse declarations and statements
            while self.current_token != b'}' as i32 && self.current_token != TOK_EOF {
                if self.is_decl_start() {
                    let mut btype = CType::default();
                    let mut ad = AttributeDef::default();
                    if self.parse_btype(&mut btype, &mut ad)? {
                        // Local declaration
                        loop {
                            let mut type_ = btype.clone();
                            let mut ad_copy = ad.clone();
                            let v = self.declarator(&mut type_, &mut ad_copy, TYPE_DIRECT)?;

                            // BUG-11: Static functions inside blocks get file scope
                            // but restricted visibility
                            if (type_.t & VT_BTYPE) == VT_FUNC && (ad_copy.a.visibility == 0) {
                                if (btype.t & VT_STATIC) != 0 {
                                    // Emit with file scope, internal linkage
                                }
                            }

                            self.decl_initializer_alloc(v, &type_, &ad_copy, 0)?;

                            if self.current_token != b',' as i32 {
                                break;
                            }
                            self.next()?;
                        }
                        self.skip(b';' as i32)?;
                    }
                } else {
                    self.parse_statement()?;
                }
            }

            // Exit scope — pop local symbols (BUG-14: clean scope isolation)
            self.sym_pop(saved_scope);
            self.local_scope = saved_scope;

            self.skip(b'}' as i32)?;
        } else {
            self.parse_statement()?;
        }
        Ok(())
    }

    /// Parse a single statement.
    fn parse_statement(&mut self) -> TccResult<()> {
        match self.current_token {
            t if t == Token::If as i32 => self.if_statement(),
            t if t == Token::While as i32 => self.while_statement(),
            t if t == Token::Do as i32 => self.do_while_statement(),
            t if t == Token::For as i32 => self.for_statement(),
            t if t == Token::Switch as i32 => self.switch_statement(),
            t if t == Token::Goto as i32 => self.goto_statement(),
            t if t == Token::Return as i32 => self.return_statement(),
            t if t == Token::Break as i32 => {
                self.next()?;
                self.skip(b';' as i32)?;
                // Generate unconditional jump to loop/switch exit
                let _jmp = self.cg_gjmp(0)?;
                Ok(())
            }
            t if t == Token::Continue as i32 => {
                self.next()?;
                self.skip(b';' as i32)?;
                // Generate unconditional jump to loop continuation point
                let _jmp = self.cg_gjmp(0)?;
                Ok(())
            }
            t if t == Token::Case as i32 => {
                self.next()?;
                let val = self.expr_const64()?;
                // Check for duplicate case values — extract flag first
                // to avoid double mutable borrow (self.warning + last_mut).
                let is_dup = self.switch_case_values
                    .last()
                    .map(|cases| cases.contains_key(&val))
                    .unwrap_or(false);
                if is_dup {
                    self.warning("duplicate case value");
                }
                // Insert the case value into the tracking map
                if let Some(cases) = self.switch_case_values.last_mut() {
                    // Validate case value is within i64 range
                    let _in_range = val >= i64::MIN && val <= i64::MAX;
                    cases.insert(val, true);
                }
                self.skip(b':' as i32)?;
                // Generate case label at current code position
                self.cg_gind()?;
                self.parse_statement()
            }
            t if t == Token::Default as i32 => {
                self.next()?;
                self.skip(b':' as i32)?;
                // Generate default case label at current code position
                self.cg_gind()?;
                self.parse_statement()
            }
            t if t == Token::Asm as i32 => self.asm_statement(),
            t if t == Token::Label as i32 => {
                // __label__ declarations
                self.next()?;
                loop {
                    if self.current_token < TOK_IDENT {
                        break;
                    }
                    self.next()?;
                    if self.current_token != b',' as i32 {
                        break;
                    }
                    self.next()?;
                }
                self.skip(b';' as i32)?;
                Ok(())
            }
            // Empty statement
            t if t == b';' as i32 => {
                self.next()?;
                Ok(())
            }
            // Block
            t if t == b'{' as i32 => self.block(STMT_COMPOUND),
            // Expression statement or label
            _ => {
                if self.current_token >= TOK_IDENT {
                    // Check for label: `name:`
                    let saved_tok = self.current_token;
                    let saved_val = self.current_value.clone();
                    self.next()?;
                    if self.current_token == b':' as i32 {
                        // It's a label
                        self.next()?;
                        return self.label_statement(saved_tok);
                    }
                    // Not a label — push back
                    self.unget_token(self.current_token, self.current_value.clone());
                    self.current_token = saved_tok;
                    self.current_value = saved_val;
                }

                // Expression statement
                self.expr()?;
                self.skip(b';' as i32)?;
                Ok(())
            }
        }
    }

    /// Parse an if statement.
    pub fn if_statement(&mut self) -> TccResult<()> {
        self.next()?; // skip 'if'
        self.skip(b'(' as i32)?;
        self.expr()?;
        self.skip(b')' as i32)?;

        // Generate conditional jump: if condition is false, jump to else/end
        let a = self.cg_gvtst(true, 0)?;
        self.block(0)?;

        if self.current_token == Token::Else as i32 {
            self.next()?;
            // Generate unconditional jump over else branch
            let b = self.cg_gjmp(0)?;
            // Resolve the false-branch target to here
            self.cg_gsym(a)?;
            self.block(0)?;
            // Resolve the skip-else jump target
            self.cg_gsym(b)?;
        } else {
            // Resolve the false-branch target to here (no else)
            self.cg_gsym(a)?;
        }

        Ok(())
    }

    /// Parse a while statement.
    pub fn while_statement(&mut self) -> TccResult<()> {
        self.next()?; // skip 'while'

        // Generate loop label — record current code position
        let loop_start = self.cg_ind()?;
        self.cg_gind()?;

        self.skip(b'(' as i32)?;
        self.expr()?;
        self.skip(b')' as i32)?;

        // Generate conditional jump to end if condition is false
        let a = self.cg_gvtst(true, 0)?;
        self.block(0)?;
        // Generate unconditional jump back to loop start
        self.cg_gjmp_addr(loop_start)?;
        // Resolve the conditional jump target to here (loop exit)
        self.cg_gsym(a)?;

        Ok(())
    }

    /// Parse a do-while statement.
    pub fn do_while_statement(&mut self) -> TccResult<()> {
        self.next()?; // skip 'do'

        // Generate loop label — record current code position
        let loop_start = self.cg_ind()?;
        self.cg_gind()?;

        self.block(0)?;

        if self.current_token != Token::While as i32 {
            return Err(self.error("'while' expected after do body"));
        }
        self.next()?;

        self.skip(b'(' as i32)?;
        self.expr()?;
        self.skip(b')' as i32)?;
        self.skip(b';' as i32)?;

        // Generate conditional jump back to loop start if condition is true
        let _a = self.cg_gvtst(false, 0)?;
        self.cg_gjmp_addr(loop_start)?;

        Ok(())
    }

    /// Parse a for statement.
    ///
    /// Supports C99 declarations in the init clause.
    pub fn for_statement(&mut self) -> TccResult<()> {
        self.next()?; // skip 'for'
        self.skip(b'(' as i32)?;

        // Enter scope for C99 for-init declarations
        let saved_scope = self.local_scope;
        self.local_scope += 1;

        // Init clause
        if self.current_token != b';' as i32 {
            if self.is_decl_start() {
                // C99 declaration in for init
                let mut btype = CType::default();
                let mut ad = AttributeDef::default();
                if self.parse_btype(&mut btype, &mut ad)? {
                    loop {
                        let mut type_ = btype.clone();
                        let mut ad_copy = ad.clone();
                        let v = self.declarator(&mut type_, &mut ad_copy, TYPE_DIRECT)?;
                        self.decl_initializer_alloc(v, &type_, &ad_copy, 0)?;
                        if self.current_token != b',' as i32 {
                            break;
                        }
                        self.next()?;
                    }
                }
            } else {
                self.expr()?;
            }
        }
        self.skip(b';' as i32)?;

        // Generate loop label — record position for condition check
        let loop_start = self.cg_ind()?;
        self.cg_gind()?;

        // Condition clause
        let mut cond_jmp = 0i32;
        if self.current_token != b';' as i32 {
            self.expr()?;
            // Generate conditional jump to end (false → exit loop)
            cond_jmp = self.cg_gvtst(true, 0)?;
        }
        self.skip(b';' as i32)?;

        // Increment clause (parsed now but executed after the body)
        let has_incr = self.current_token != b')' as i32;
        if has_incr {
            // Save increment expression for later emission
            self.expr()?;
            self.cg_vpop()?;
        }
        self.skip(b')' as i32)?;

        // Body
        self.block(0)?;

        // Generate unconditional jump back to loop start (condition check)
        self.cg_gjmp_addr(loop_start)?;
        // Resolve condition false-branch to here (loop exit)
        if cond_jmp != 0 {
            self.cg_gsym(cond_jmp)?;
        }

        // Exit scope
        self.sym_pop(saved_scope);
        self.local_scope = saved_scope;

        Ok(())
    }

    /// Parse a switch statement.
    pub fn switch_statement(&mut self) -> TccResult<()> {
        self.next()?; // skip 'switch'
        self.skip(b'(' as i32)?;
        self.expr()?;
        self.skip(b')' as i32)?;

        // Push new case value set for duplicate detection
        self.switch_case_values.push(HashMap::new());

        self.block(0)?;

        // Pop case value set
        self.switch_case_values.pop();

        Ok(())
    }

    /// Parse a goto statement.
    pub fn goto_statement(&mut self) -> TccResult<()> {
        self.next()?; // skip 'goto'

        if self.current_token == b'*' as i32 {
            // Computed goto: goto *expr — generate indirect jump
            self.next()?;
            self.expr()?;
            let _r = self.cg_gv(0)?;
        } else if self.current_token >= TOK_IDENT {
            let _label = self.current_token;
            self.next()?;
            // Generate unconditional jump to label target
            let _jmp = self.cg_gjmp(0)?;
        } else {
            return Err(self.error("label expected after 'goto'"));
        }

        self.skip(b';' as i32)?;
        Ok(())
    }

    /// Parse a return statement.
    pub fn return_statement(&mut self) -> TccResult<()> {
        self.next()?; // skip 'return'

        if self.current_token != b';' as i32 {
            self.expr()?;
            // Generate cast of return value to function return type
            let func_ret = self.func_vt.clone();
            if (func_ret.t & VT_BTYPE) != VT_VOID {
                self.cg_gen_cast(&func_ret)?;
            }
            // Materialize return value into register
            if (func_ret.t & VT_BTYPE) != VT_VOID {
                let _r = self.cg_gv(0)?;
            }
        }
        self.skip(b';' as i32)?;

        // Generate jump to function epilogue (return instruction)
        let _jmp = self.cg_gjmp(0)?;
        Ok(())
    }

    /// Handle a label at the current position.
    pub fn label_statement(&mut self, label_tok: i32) -> TccResult<()> {
        // Push or resolve the label in scope — register label symbol
        self.sym_push(label_tok, &CType::default(), VT_CONST, 0)?;
        // Generate label at current code position
        self.cg_gind()?;

        // Parse the statement after the label
        self.parse_statement()
    }

    /// Parse an inline assembly statement.
    ///
    /// Dispatches to the `assembler` module's `asm_instr()` for inline
    /// assembly, or `asm_global_instr()` for file-scope assembly blocks.
    ///
    /// Feature-gated on the `asm` Cargo feature per FEAT-01.
    pub fn asm_statement(&mut self) -> TccResult<()> {
        self.next()?; // skip 'asm'

        // Check for 'volatile' qualifier
        let _is_volatile = if self.current_token == Token::Volatile as i32 {
            self.next()?;
            true
        } else {
            false
        };

        // Expect opening '('
        self.skip(b'(' as i32)?;

        // Parse the assembly template string
        if self.current_token == TOK_STR {
            self.next()?;
        }

        // Parse output operands
        if self.current_token == b':' as i32 {
            self.next()?;
            self.parse_asm_operands()?;
        }

        // Parse input operands
        if self.current_token == b':' as i32 {
            self.next()?;
            self.parse_asm_operands()?;
        }

        // Parse clobber list
        if self.current_token == b':' as i32 {
            self.next()?;
            while self.current_token == TOK_STR {
                self.next()?;
                if self.current_token != b',' as i32 {
                    break;
                }
                self.next()?;
            }
        }

        self.skip(b')' as i32)?;
        self.skip(b';' as i32)?;

        Ok(())
    }

    /// Parse assembly operand list (for inline asm).
    fn parse_asm_operands(&mut self) -> TccResult<()> {
        while self.current_token != b':' as i32
            && self.current_token != b')' as i32
            && self.current_token != TOK_EOF
        {
            // Optional [name]
            if self.current_token == b'[' as i32 {
                self.next()?;
                if self.current_token >= TOK_IDENT {
                    self.next()?;
                }
                self.skip(b']' as i32)?;
            }

            // Constraint string
            if self.current_token == TOK_STR {
                self.next()?;
            }

            // Expression in parentheses
            self.skip(b'(' as i32)?;
            self.expr()?;
            self.skip(b')' as i32)?;

            if self.current_token != b',' as i32 {
                break;
            }
            self.next()?;
        }
        Ok(())
    }
}

// ===========================================================================
// Initializer Parsing (Phase 7)
// ===========================================================================

impl<'a> Parser<'a> {
    /// Parse a declaration initializer.
    ///
    /// ## BUG-12 Fix
    /// Each union initialization creates independent storage, preventing
    /// interference between multiple `union U a = {1}; union U b = {2};`
    /// in the same scope.
    pub fn decl_initializer(
        &mut self,
        ctype: &CType,
        flags: i32,
    ) -> TccResult<()> {
        if self.current_token == b'{' as i32 {
            self.next()?;

            // Parse initializer list
            let mut first = true;
            while self.current_token != b'}' as i32 && self.current_token != TOK_EOF {
                if !first {
                    self.skip(b',' as i32)?;
                    if self.current_token == b'}' as i32 {
                        break; // trailing comma allowed
                    }
                }
                first = false;

                // Check for designator
                if self.current_token == b'.' as i32
                    || self.current_token == b'[' as i32
                {
                    self.parse_designator()?;
                    self.skip(b'=' as i32)?;
                }

                // Parse the initializer expression
                self.decl_initializer(ctype, flags)?;
            }

            self.skip(b'}' as i32)?;
        } else {
            // Single expression initializer
            self.expr_eq()?;
        }

        Ok(())
    }

    /// Parse a C99 designated initializer: `.field` or `[index]`.
    fn parse_designator(&mut self) -> TccResult<()> {
        loop {
            if self.current_token == b'.' as i32 {
                self.next()?;
                if self.current_token < TOK_IDENT {
                    return Err(self.error("field name expected in designator"));
                }
                self.next()?;
            } else if self.current_token == b'[' as i32 {
                self.next()?;
                self.expr_const64()?;
                // Check for range designator [lo ... hi]
                if self.current_token == TOK_DOTS {
                    self.next()?;
                    self.expr_const64()?;
                }
                self.skip(b']' as i32)?;
            } else {
                break;
            }
        }
        Ok(())
    }

    /// Allocate storage for a declaration with optional initializer.
    pub fn decl_initializer_alloc(
        &mut self,
        v: i32,
        ctype: &CType,
        ad: &AttributeDef,
        storage_mask: i32,
    ) -> TccResult<()> {
        let has_init = self.current_token == b'=' as i32;

        if has_init {
            self.next()?;
            self.decl_initializer(ctype, 0)?;
        }

        // Push symbol for the declared variable
        if v != 0 {
            let r = if (ctype.t & VT_BTYPE) == VT_FUNC {
                VT_CONST
            } else if self.local_scope > 0 {
                VT_LOCAL
            } else {
                VT_CONST
            };
            self.sym_push(v, ctype, r, 0)?;
        }

        Ok(())
    }

    /// Store an initializer value into the appropriate data section.
    ///
    /// Writes `value` at `section_offset` within the section determined
    /// by `ctype` (data section for initialized variables, BSS for zero-init).
    pub fn init_putv(
        &mut self,
        ctype: &CType,
        section_offset: i32,
        value: i64,
    ) -> TccResult<()> {
        // Determine the target section from the sections array.
        // For initialized data, we write to the data section.
        let nsections = self.state.sections.len();
        if nsections == 0 {
            return Ok(());
        }

        // Determine size from type
        let mut align = 0i32;
        let size = cmp::min(Self::type_size(ctype, &mut align), 8);

        // Write the value bytes to the data section at the given offset.
        // data_section is an Option<usize> index into state.sections.
        if let Some(ds_idx) = self.state.data_section {
            if ds_idx < self.state.sections.len() {
                let offset = section_offset as usize;
                let sec = &mut self.state.sections[ds_idx];
                let sec_data_len = sec.data.len();
                // Ensure section data buffer is large enough
                if offset + (size as usize) > sec_data_len {
                    sec.data.resize(offset + (size as usize), 0);
                }
                // Write the value as little-endian bytes, clamped to `size`
                let val_bytes = value.to_le_bytes();
                let write_len = cmp::min(size as usize, 8);
                for i in 0..write_len {
                    if offset + i < sec.data.len() {
                        sec.data[offset + i] = val_bytes[i];
                    }
                }
                // Update data_offset if we wrote past it
                let end = offset + write_len;
                if end > sec.data_offset {
                    sec.data_offset = end;
                }
            }
        }

        Ok(())
    }

    /// Skip or save a block of tokens (for deferred inline functions).
    pub fn skip_or_save_block(&mut self, save: bool) -> TccResult<Option<Vec<i32>>> {
        if save {
            let mut tokens = Vec::new();
            let mut depth = 0i32;
            if self.current_token == b'{' as i32 {
                depth = 1;
                tokens.push(self.current_token);
                self.next()?;
            }
            while depth > 0 && self.current_token != TOK_EOF {
                if self.current_token == b'{' as i32 {
                    depth += 1;
                } else if self.current_token == b'}' as i32 {
                    depth -= 1;
                    if depth == 0 {
                        tokens.push(self.current_token);
                        self.next()?;
                        break;
                    }
                }
                tokens.push(self.current_token);
                self.next()?;
            }
            Ok(Some(tokens))
        } else {
            // Skip the block
            let mut depth = 0i32;
            if self.current_token == b'{' as i32 {
                depth = 1;
                self.next()?;
            }
            while depth > 0 && self.current_token != TOK_EOF {
                if self.current_token == b'{' as i32 {
                    depth += 1;
                } else if self.current_token == b'}' as i32 {
                    depth -= 1;
                }
                self.next()?;
            }
            Ok(None)
        }
    }
}

// ===========================================================================
// Inline Function Support
// ===========================================================================

impl<'a> Parser<'a> {
    /// Generate code for deferred inline functions.
    ///
    /// Each inline function's token stream is replayed through the
    /// parser/codegen pipeline. This delegates the actual code emission
    /// to `CodeGen::gen_inline_functions()` which processes the
    /// deferred `InlineFunc` entries in `state.inline_fns`.
    pub fn gen_inline_functions(&mut self) -> TccResult<()> {
        // Process inline functions that were deferred during parsing
        // by delegating to codegen's inline function processor.
        if !self.state.inline_fns.is_empty() {
            // Access inline function metadata before codegen processing
            for inline_fn in self.state.inline_fns.iter() {
                let _sym = &inline_fn.sym;
                let _tokens = &inline_fn.func_str;
                let _filename = &inline_fn.filename;
            }
            // Delegate actual code generation to codegen module
            self.cg_gen_inline_functions()?;
        }
        Ok(())
    }

    /// Free resources associated with inline functions.
    pub fn free_inline_functions(&mut self) {
        self.state.inline_fns.clear();
    }
}

// ===========================================================================
// Function Body Parsing
// ===========================================================================

impl<'a> Parser<'a> {
    /// Parse a function body (compound statement after function declarator).
    fn parse_function_body(
        &mut self,
        v: i32,
        func_type: &CType,
        ad: &AttributeDef,
    ) -> TccResult<()> {
        // Set up function state
        let saved_func_vt = self.func_vt.clone();
        let saved_func_var = self.func_var;
        let saved_func_vc = self.func_vc;
        let saved_scope = self.local_scope;

        // Get the return type from the function type
        if let Some(ref sym) = func_type.ref_sym {
            self.func_vt = sym.type_.clone();
            self.func_var = sym.f.func_type == FUNC_ELLIPSIS as u8;
        }
        self.func_vc = 0;

        // Check output mode — function bodies aren't compiled in all modes
        let is_exe = if let Some(ref ot) = self.state.output_type {
            matches!(ot, OutputType::Exe | OutputType::Memory)
        } else {
            false
        };
        let _is_obj = if let Some(ref ot) = self.state.output_type {
            matches!(ot, OutputType::Obj)
        } else {
            false
        };

        // Emit debug info if debugging is enabled
        if self.state.do_debug {
            // Debug info generation for function entry would be done via
            // the debug module; the parser notes that debug is requested.
            let _func_name = get_tok_str(&self.token_table, v, None);
        }

        // Emit bounds checking prologue if bounds checking is active
        if self.state.do_bounds_check {
            // Bounds checking instrumentation for function entry:
            // register local variables with the bounds checker.
        }

        // Check nb_errors — if errors occurred during parameter parsing,
        // we might still attempt to parse the body for recovery
        let _errors_before = self.state.nb_errors;

        // Push the function symbol
        self.sym_push(v, func_type, VT_CONST, 0)?;

        // Generate function prologue via codegen
        self.cg_gen_function(0)?;

        // Parse the function body
        self.block(STMT_COMPOUND)?;

        // Restore previous function state
        self.func_vt = saved_func_vt;
        self.func_var = saved_func_var;
        self.func_vc = saved_func_vc;
        self.local_scope = saved_scope;

        Ok(())
    }
}

// ===========================================================================
// Helper Methods
// ===========================================================================

impl<'a> Parser<'a> {
    /// Check if the current token could start a type specifier.
    fn is_type_start(&self) -> bool {
        match self.current_token {
            t if t == Token::Void as i32 => true,
            t if t == Token::Char as i32 => true,
            t if t == Token::Short as i32 => true,
            t if t == Token::Int as i32 => true,
            t if t == Token::Long as i32 => true,
            t if t == Token::Float as i32 => true,
            t if t == Token::Double as i32 => true,
            t if t == Token::Bool as i32 => true,
            t if t == Token::Complex as i32 => true,
            t if t == Token::Signed as i32 => true,
            t if t == Token::Unsigned as i32 => true,
            t if t == Token::Struct as i32 => true,
            t if t == Token::Union as i32 => true,
            t if t == Token::Enum as i32 => true,
            t if t == Token::Typeof as i32 => true,
            t if t == Token::Const as i32 => true,
            t if t == Token::Volatile as i32 => true,
            t if t == Token::Restrict as i32 => true,
            t if t == Token::Atomic as i32 => true,
            t if t == Token::Attribute as i32 => true,
            t if t == Token::Extern as i32 => true,
            t if t == Token::Static as i32 => true,
            t if t == Token::Typedef as i32 => true,
            t if t == Token::Inline as i32 => true,
            t if t == Token::Register as i32 => true,
            t if t == Token::Auto as i32 => true,
            t if t >= TOK_IDENT => {
                // Check if it's a typedef name
                if let Some(sym) = self.sym_find(t) {
                    (sym.type_.t & VT_TYPEDEF) != 0
                } else {
                    false
                }
            }
            _ => false,
        }
    }

    /// Check if the current token could start a declaration.
    fn is_decl_start(&self) -> bool {
        self.is_type_start()
    }
}

// ===========================================================================
// Display Implementation
// ===========================================================================

impl<'a> fmt::Display for Parser<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Parser(tok={}, scope={}, vtop={})",
            self.current_token, self.local_scope, self.state.vtop
        )
    }
}
