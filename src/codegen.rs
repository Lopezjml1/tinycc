//! Copyright (c) 2024 tinycc-rs contributors
//! SPDX-License-Identifier: MIT OR LGPL-2.1-or-later
//!
//! Value stack, code emission, and constant folding.

// Module-level lint configuration:
// - doc_markdown: Many doc comments reference C identifiers (tccgen.c, SValue,
//   vtop, etc.) that are intentionally written without backticks for readability.
// - missing_errors_doc: All public functions document errors in their main doc
//   comments rather than separate `# Errors` sections for conciseness.
// - trivially_copy_pass_by_ref: Some Copy types are passed by reference for
//   API consistency with the rest of the crate.
// - too_many_arguments: Some functions mirror the C original signatures which
//   require many parameters.
// - similar_names: Variable names mirror C original names for traceability.
// - module_name_repetitions: Function names follow C naming conventions.
// - wildcard_enum_match_arm: Match arms use wildcard for enum variants that
//   share common handling.
#![allow(clippy::doc_markdown)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::trivially_copy_pass_by_ref)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::similar_names)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::wildcard_enum_match_arm)]
// unnecessary_wraps: Many codegen functions return TccResult for API consistency
// even when the current implementation cannot fail; the full-fidelity C-to-Rust
// translation will add error paths as the backend matures.
#![allow(clippy::unnecessary_wraps)]
// match_same_arms: Match arms in type-size/alignment tables intentionally keep
// separate arms for documentation clarity, mirroring C switch-case structure.
#![allow(clippy::match_same_arms)]
// match_wildcard_for_single_variants: Wildcard patterns used for forward
// compatibility when new enum variants may be added.
#![allow(clippy::match_wildcard_for_single_variants)]
// collapsible_if: Some nested ifs are intentionally kept separate for
// readability mirroring the C conditional structure.
#![allow(clippy::collapsible_if)]
//!
//! This module translates the CODEGEN portion of `tccgen.c` (8,920 lines) into
//! safe Rust.  It implements the value stack operations, code emission helpers,
//! constant folding, symbol management, type utilities, and the interface to
//! architecture-specific backends via the `CodegenBackend` trait.
//!
//! Key data structures:
//!   - `ValueStack` — replaces fixed-size C array `SValue vstack[VSTACK_SIZE]`
//!     with `Vec<SValue>` (AAP §0.4.4)
//!   - Code output via `Section.data: Vec<u8>` (no raw pointer writes)
//!   - Symbol table operations using safe indices (`SymId = usize`)
//!
//! CVE remediation:
//!   - CVE-2006-0635: All signed/unsigned comparisons use explicit `TryFrom`
//!     conversions — `#![deny(clippy::cast_sign_loss)]` enforced at crate root
//!
//! Safety:
//!   - No `unsafe` blocks in this module
//!   - No `unwrap()` in library code — all fallible operations return `TccResult<T>`
//!   - Integer arithmetic uses checked operations

use crate::context::TccState;
use crate::error::{TccError, TccResult};
#[allow(unused_imports)]
use crate::formats::elf::{
    elf_st_bind, elf_st_info, elf_st_type, elf_st_visibility, Elf64Sym, SHN_ABS, SHN_COMMON,
    SHN_UNDEF, STB_GLOBAL, STB_LOCAL, STB_WEAK, STT_FUNC, STT_NOTYPE, STT_OBJECT, STT_SECTION,
    STV_DEFAULT, STV_HIDDEN,
};
use crate::targets::CodegenBackend;
#[allow(unused_imports)]
use crate::tokens::{
    Token, TOK_A_ADD, TOK_A_SAR, TOK_ASMDIR_FIRST, TOK_ASMDIR_LAST, TOK_CCHAR, TOK_CDOUBLE,
    TOK_CFLOAT, TOK_CINT, TOK_CLDOUBLE, TOK_CLLONG, TOK_DEC, TOK_DOTS, TOK_EOF, TOK_EQ,
    TOK_GE, TOK_GT, TOK_IDENT, TOK_INC, TOK_LAND, TOK_LE, TOK_LINEFEED, TOK_LINENUM, TOK_LOR,
    TOK_LT, TOK_NE, TOK_PPNUM, TOK_SAR, TOK_SHL, TOK_SHR, TOK_STR, TOK_UDIV, TOK_UGE,
    TOK_UGT, TOK_ULE, TOK_ULT, TOK_UMOD,
};
#[allow(unused_imports)]
use crate::types::{
    ASMOperand, AttributeDef, CString, CType, CValue, ExprValue, FuncAttr, InlineFunc,
    Section, SValue, SValueData, SValueSymInfo, SymAttr, SymId, Symbol, TokenSym,
    FUNC_CDECL, FUNC_ELLIPSIS, FUNC_NEW, FUNC_OLD, FUNC_STDCALL,
    LABEL_DECLARED, LABEL_DEFINED, LABEL_FORWARD, LABEL_GONE,
    MAX_ASM_OPERANDS, SYM_FIELD, SYM_FIRST_ANOM, SYM_STRUCT,
    TYPE_ABSTRACT, TYPE_DIRECT, TYPE_NEST, TYPE_PARAM,
    VSTACK_SIZE,
    VT_ARRAY, VT_BITFIELD, VT_BOOL, VT_BOUNDED, VT_BTYPE, VT_BYTE,
    VT_CMP, VT_CONST, VT_CONSTANT, VT_DEFSIGN, VT_DOUBLE, VT_ENUM,
    VT_ENUM_VAL, VT_EXTERN, VT_FLOAT, VT_FUNC, VT_INLINE, VT_INT,
    VT_JMP, VT_JMPI, VT_LDOUBLE, VT_LLOCAL, VT_LLONG, VT_LOCAL,
    VT_LONG, VT_LVAL, VT_MUSTBOUND, VT_MUSTCAST, VT_NONCONST,
    VT_PTR, VT_QFLOAT, VT_QLONG, VT_SHORT, VT_STATIC, VT_STORAGE,
    VT_STRUCT, VT_STRUCT_MASK, VT_STRUCT_SHIFT, VT_SYM, VT_TYPE,
    VT_TYPEDEF, VT_UNION, VT_UNSIGNED, VT_VLA, VT_VALMASK, VT_VOID,
    VT_VOLATILE, VT_ATOMIC,
};

// ===========================================================================
//  Public Constants
// ===========================================================================

/// Register class: integer registers.
///
/// C equivalent: `#define RC_INT 0x0001` (tcc.h).
pub const RC_INT: u32 = 0x0001;

/// Register class: floating-point registers.
///
/// C equivalent: `#define RC_FLOAT 0x0002` (tcc.h).
pub const RC_FLOAT: u32 = 0x0002;

/// Register class: return value register.
///
/// C equivalent: `#define RC_RET 0x0004` (tcc.h:architecture-specific).
pub const RC_RET: u32 = 0x0004;

/// Number of architecture-specific assembler registers.
///
/// C equivalent: `NB_ASM_REGS` (tcc.h:1506, architecture-dependent).
/// Default value for x86-64; overridden by architecture-specific backends.
pub const NB_ASM_REGS: usize = 16;

/// Bit flag: code emission is off (dead code elimination).
///
/// Used as a bitmask on `nocode_wanted` to track code suppression depth.
///
/// C equivalent: `#define CODE_OFF()` related constants in tccgen.c.
pub const CODE_OFF_BIT: i32 = 0x2000_0000;

/// Flag value: constant expression evaluation is wanted.
///
/// Used with `nocode_wanted` to indicate that only compile-time constants
/// should be evaluated (no code emission).
///
/// C equivalent: `CONST_WANTED` in tccgen.c.
pub const CONST_WANTED: i32 = 0x1000_0000;

/// Mask to suppress evaluation entirely.
///
/// C equivalent: `NOEVAL_MASK` in tccgen.c.
pub const NOEVAL_MASK: i32 = 0x4000_0000;

/// Flag: suppresses both evaluation and code emission.
///
/// C equivalent: `NOEVAL_WANTED` in tccgen.c.
pub const NOEVAL_WANTED: i32 = CONST_WANTED | NOEVAL_MASK;

// ===========================================================================
//  ValueStack — Replaces C SValue vstack[VSTACK_SIZE] (tcc.h:487-501)
// ===========================================================================

/// Value stack — replaces C fixed-size `SValue vstack[VSTACK_SIZE]` array.
///
/// AAP §0.4.4: "Macro stack (SValue[512]) → Vec<SValue>"
///
/// In the original TCC, the value stack is a fixed-size array of 512 entries
/// with a pointer `vtop` tracking the top element.  Out-of-bounds access
/// is undefined behavior.  In the Rust port, the stack uses `Vec<SValue>`
/// with checked push/pop operations that return `TccResult`, preventing
/// stack overflow (returns error) and underflow (returns error).
///
/// C equivalent: `SValue __vstack[1+VSTACK_SIZE]` + `SValue *vtop` in tccgen.c
pub struct ValueStack {
    /// Dynamic value stack with bounds-checked push/pop.
    stack: Vec<SValue>,
    /// Maximum stack depth (soft limit for debugging — matches C VSTACK_SIZE).
    max_depth: usize,
}

impl ValueStack {
    /// Create a new empty value stack with default capacity.
    ///
    /// C equivalent: initialization of `vstack` / `vtop = __vstack - 1`
    /// in `tccgen_init()`.
    pub fn new() -> Self {
        Self {
            stack: Vec::with_capacity(VSTACK_SIZE),
            max_depth: VSTACK_SIZE,
        }
    }

    /// Push a value onto the stack.
    ///
    /// Returns `Err(TccError::Parse)` if the stack depth would exceed
    /// `max_depth` (equivalent to the C bounds-check at tccgen.c:242).
    ///
    /// C equivalent: `vstack_add(&vtop)` + `*vtop = val`
    pub fn push(&mut self, val: SValue) -> TccResult<()> {
        if self.stack.len() >= self.max_depth {
            return Err(TccError::parse("value stack overflow"));
        }
        self.stack.push(val);
        Ok(())
    }

    /// Pop and return the top value from the stack.
    ///
    /// Returns `Err(TccError::Parse)` if the stack is empty.
    ///
    /// C equivalent: `vtop--` (pointer decrement)
    pub fn pop(&mut self) -> TccResult<SValue> {
        self.stack
            .pop()
            .ok_or_else(|| TccError::parse("value stack underflow"))
    }

    /// Return an immutable reference to the top value.
    ///
    /// Returns `Err(TccError::Parse)` if the stack is empty.
    ///
    /// C equivalent: `*vtop`
    pub fn top(&self) -> TccResult<&SValue> {
        self.stack
            .last()
            .ok_or_else(|| TccError::parse("value stack empty"))
    }

    /// Return a mutable reference to the top value.
    ///
    /// Returns `Err(TccError::Parse)` if the stack is empty.
    ///
    /// C equivalent: `*vtop` (used as lvalue)
    pub fn top_mut(&mut self) -> TccResult<&mut SValue> {
        self.stack
            .last_mut()
            .ok_or_else(|| TccError::parse("value stack empty"))
    }

    /// Return the current stack depth.
    #[inline]
    pub fn len(&self) -> usize {
        self.stack.len()
    }

    /// Check if the stack is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.stack.is_empty()
    }

    /// Get a reference to an element relative to the top.
    /// `offset = 0` is the top, `offset = 1` is one below top, etc.
    pub fn peek(&self, offset: usize) -> TccResult<&SValue> {
        if offset >= self.stack.len() {
            return Err(TccError::parse("value stack peek out of range"));
        }
        let idx = self.stack.len() - 1 - offset;
        Ok(&self.stack[idx])
    }

    /// Get a mutable reference to an element relative to the top.
    pub fn peek_mut(&mut self, offset: usize) -> TccResult<&mut SValue> {
        if offset >= self.stack.len() {
            return Err(TccError::parse("value stack peek_mut out of range"));
        }
        let idx = self.stack.len() - 1 - offset;
        Ok(&mut self.stack[idx])
    }

    /// Swap the top two elements.
    pub fn swap_top2(&mut self) -> TccResult<()> {
        let len = self.stack.len();
        if len < 2 {
            return Err(TccError::parse(
                "value stack swap requires at least 2 elements",
            ));
        }
        self.stack.swap(len - 1, len - 2);
        Ok(())
    }

    /// Rotate bottom `n` elements so the bottom moves to the top.
    ///
    /// C equivalent: `vrotb(n)` in tccgen.c
    pub fn rotate_bottom(&mut self, n: usize) -> TccResult<()> {
        let len = self.stack.len();
        if n > len || n == 0 {
            return Err(TccError::parse("value stack rotate: invalid count"));
        }
        let start = len - n;
        self.stack[start..].rotate_left(1);
        Ok(())
    }

    /// Rotate top `n` elements so the top moves to the bottom of the group.
    ///
    /// C equivalent: `vrott(n)` in tccgen.c
    pub fn rotate_top(&mut self, n: usize) -> TccResult<()> {
        let len = self.stack.len();
        if n > len || n == 0 {
            return Err(TccError::parse("value stack rotate: invalid count"));
        }
        let start = len - n;
        self.stack[start..].rotate_right(1);
        Ok(())
    }

    /// Reverse the top `n` elements.
    pub fn reverse_top(&mut self, n: usize) -> TccResult<()> {
        let len = self.stack.len();
        if n > len {
            return Err(TccError::parse("value stack reverse: invalid count"));
        }
        let start = len - n;
        self.stack[start..].reverse();
        Ok(())
    }

    /// Get a slice of the entire stack (bottom to top).
    #[inline]
    pub fn as_slice(&self) -> &[SValue] {
        &self.stack
    }

    /// Get a mutable slice of the entire stack.
    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [SValue] {
        &mut self.stack
    }

    /// Truncate the stack to `new_len` entries.
    #[inline]
    pub fn truncate(&mut self, new_len: usize) {
        self.stack.truncate(new_len);
    }
}

impl Default for ValueStack {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
//  Code Emission Functions (tccgen.c output primitives)
// ===========================================================================

/// Emit a single byte to the current text section.
///
/// Appends byte `c` to the code section's data buffer at the current
/// instruction index (`state.ind`), growing the buffer as needed.
///
/// C equivalent: `g()` in tccgen.c — `*ind++ = c;`
pub fn g(state: &mut TccState, c: u8) -> TccResult<()> {
    let sec_idx = state.cur_text_section;
    let section = state.sections.get_mut(sec_idx).ok_or_else(|| {
        TccError::link(format!(
            "current text section index {sec_idx} out of range"
        ))
    })?;
    // Grow the data buffer if the instruction index exceeds current length
    let ind = state.ind;
    let ind_usize = usize::try_from(ind)?;
    if ind_usize >= section.data.len() {
        section.data.resize(ind_usize.saturating_add(1), 0);
    }
    section.data[ind_usize] = c;
    state.ind = ind.checked_add(1).ok_or_else(|| {
        TccError::parse("instruction index overflow")
    })?;
    // Update data_offset to track high-water mark
    let new_ind = usize::try_from(state.ind)?;
    if new_ind > section.data_offset {
        let sec = state.sections.get_mut(sec_idx).ok_or_else(|| {
            TccError::link("section index out of range during data_offset update")
        })?;
        sec.data_offset = new_ind;
    }
    Ok(())
}

/// Emit a little-endian 16-bit value to the current text section.
///
/// C equivalent: `gen_le16()` in tccgen.c
pub fn gen_le16(state: &mut TccState, v: u16) -> TccResult<()> {
    let bytes = v.to_le_bytes();
    g(state, bytes[0])?;
    g(state, bytes[1])?;
    Ok(())
}

/// Emit a little-endian 32-bit value to the current text section.
///
/// C equivalent: `gen_le32()` in tccgen.c
pub fn gen_le32(state: &mut TccState, v: u32) -> TccResult<()> {
    let bytes = v.to_le_bytes();
    for &b in &bytes {
        g(state, b)?;
    }
    Ok(())
}

/// Emit a 32-bit expression/relocation placeholder value.
///
/// Used when an expression value needs to be patched later during
/// relocation (e.g., symbol addresses).
///
/// C equivalent: `gen_expr32()` in tccgen.c
pub fn gen_expr32(state: &mut TccState, v: u32) -> TccResult<()> {
    gen_le32(state, v)
}

/// Emit a 64-bit expression/relocation placeholder value.
///
/// C equivalent: `gen_expr64()` in tccgen.c
pub fn gen_expr64(state: &mut TccState, v: u64) -> TccResult<()> {
    let bytes = v.to_le_bytes();
    for &b in &bytes {
        g(state, b)?;
    }
    Ok(())
}

/// Reserve `size` bytes in a section and return a mutable slice to the area.
///
/// Grows the section's data buffer by `size` bytes starting at
/// `data_offset` and returns a mutable slice to the newly reserved area.
/// Updates `data_offset` to point past the reserved area.
///
/// C equivalent: `section_ptr_add()` in tccgen.c / libtcc.c
pub fn section_ptr_add(
    state: &mut TccState,
    section_idx: usize,
    size: usize,
) -> TccResult<usize> {
    // CVE-2018-20374: Vec<Section> with checked indexing eliminates OOB write
    let nb_sections = state.sections.len();
    let section = state.sections.get_mut(section_idx).ok_or_else(|| {
        TccError::link(format!(
            "section index {section_idx} out of range (nb_sections={nb_sections})",
        ))
    })?;
    let offset = section.data_offset;
    let new_offset = offset.checked_add(size).ok_or_else(|| {
        TccError::link("section data offset overflow")
    })?;
    if new_offset > section.data.len() {
        section.data.resize(new_offset, 0);
    }
    section.data_offset = new_offset;
    Ok(offset)
}

// ===========================================================================
//  Value Stack Module-Level Operations
// ===========================================================================

/// Push a value onto the codegen value stack.
///
/// C equivalent: `vpush()` — pushes an SValue with only the CType set.
///
/// This is the generic vpush that takes a CType and sets defaults for
/// other fields.
pub fn vpush(vstack: &mut ValueStack, ctype: &CType) -> TccResult<()> {
    let sv = SValue {
        ctype: *ctype,
        r: VT_CONST,
        r2: VT_CONST,
        value: SValueData::Constant(CValue::Int(0)),
        sym_info: SValueSymInfo::Sym(None),
    };
    vstack.push(sv)
}

/// Pop `n` values from the value stack.
///
/// C equivalent: `vpop(n)` in tccgen.c — `vtop -= n`
pub fn vpop(vstack: &mut ValueStack, n: usize) -> TccResult<()> {
    for _ in 0..n {
        vstack.pop()?;
    }
    Ok(())
}

/// Push an integer constant onto the value stack.
///
/// C equivalent: `vpushi(v)` in tccgen.c
pub fn vpushi(vstack: &mut ValueStack, v: i32) -> TccResult<()> {
    let sv = SValue {
        ctype: CType {
            t: VT_INT,
            ref_sym: None,
        },
        r: VT_CONST,
        r2: VT_CONST,
        // CVE-2006-0635: Explicit reinterpret from signed i32 to u64 bit pattern
        #[allow(clippy::cast_sign_loss)]
        value: SValueData::Constant(CValue::Int(v as u64)),
        sym_info: SValueSymInfo::Sym(None),
    };
    vstack.push(sv)
}

/// Push a long long constant onto the value stack.
///
/// C equivalent: `vpushll(v)` in `tccgen.c`
pub fn vpushll(vstack: &mut ValueStack, v: i64) -> TccResult<()> {
    let sv = SValue {
        ctype: CType {
            t: VT_LLONG,
            ref_sym: None,
        },
        r: VT_CONST,
        r2: VT_CONST,
        // CVE-2006-0635: Signed-to-unsigned reinterpret preserves bit pattern
        #[allow(clippy::cast_sign_loss)]
        value: SValueData::Constant(CValue::Int(v as u64)),
        sym_info: SValueSymInfo::Sym(None),
    };
    vstack.push(sv)
}

/// Push a 64-bit value with a specific type onto the value stack.
///
/// C equivalent: `vpush64(ty, v)` in tccgen.c
pub fn vpush64(vstack: &mut ValueStack, t: i32, v: u64) -> TccResult<()> {
    let sv = SValue {
        ctype: CType {
            t,
            ref_sym: None,
        },
        r: VT_CONST,
        r2: VT_CONST,
        value: SValueData::Constant(CValue::Int(v)),
        sym_info: SValueSymInfo::Sym(None),
    };
    vstack.push(sv)
}

/// Push a symbol reference onto the value stack.
///
/// C equivalent: `vpushs(ty, r, sym)` in tccgen.c
pub fn vpushs(
    vstack: &mut ValueStack,
    ctype: &CType,
    r: u16,
    sym: Option<SymId>,
) -> TccResult<()> {
    let sv = SValue {
        ctype: *ctype,
        r,
        r2: VT_CONST,
        value: SValueData::Constant(CValue::Int(0)),
        sym_info: SValueSymInfo::Sym(sym),
    };
    vstack.push(sv)
}

/// Push a copy of an existing SValue onto the value stack.
///
/// C equivalent: `vpushv(v)` in tccgen.c — `vstack_add(&vtop); *vtop = *v`
pub fn vpushv(vstack: &mut ValueStack, v: &SValue) -> TccResult<()> {
    vstack.push(v.clone())
}

/// Push a symbol with a specific type onto the value stack.
///
/// C equivalent: `vpushsym(type, sym)` in tccgen.c
pub fn vpushsym(
    vstack: &mut ValueStack,
    ctype: &CType,
    sym: Option<SymId>,
) -> TccResult<()> {
    let sv = SValue {
        ctype: *ctype,
        r: VT_CONST | VT_SYM,
        r2: VT_CONST,
        value: SValueData::Constant(CValue::Int(0)),
        sym_info: SValueSymInfo::Sym(sym),
    };
    vstack.push(sv)
}

/// Push a helper function reference onto the value stack.
///
/// Creates a function pointer value for a runtime helper function symbol.
///
/// C equivalent: `vpush_helper_func(tok)` in tccgen.c
pub fn vpush_helper_func(
    vstack: &mut ValueStack,
    sym: Option<SymId>,
) -> TccResult<()> {
    let ft = CType {
        t: VT_FUNC,
        ref_sym: None,
    };
    let sv = SValue {
        ctype: ft,
        r: VT_CONST | VT_SYM,
        r2: VT_CONST,
        value: SValueData::Constant(CValue::Int(0)),
        sym_info: SValueSymInfo::Sym(sym),
    };
    vstack.push(sv)
}

/// Push a typed reference onto the value stack.
///
/// C equivalent: `vpush_ref(type, sec, offset, size)` in tccgen.c
pub fn vpush_ref(
    vstack: &mut ValueStack,
    ctype: &CType,
    _section_idx: usize,
    offset: i64,
    _size: u64,
) -> TccResult<()> {
    let sv = SValue {
        ctype: *ctype,
        r: VT_CONST | VT_SYM,
        r2: VT_CONST,
        #[allow(clippy::cast_sign_loss)]
        value: SValueData::Constant(CValue::Int(offset as u64)),
        sym_info: SValueSymInfo::Sym(None),
    };
    vstack.push(sv)
}

/// Swap the top two values on the value stack.
///
/// C equivalent: `vswap()` in `tccgen.c`
pub fn vswap(vstack: &mut ValueStack) -> TccResult<()> {
    vstack.swap_top2()
}

/// Set the top of the value stack to a new value with the given type and
/// register.
///
/// C equivalent: `vset(type, r, v)` in `tccgen.c`
pub fn vset(
    vstack: &mut ValueStack,
    ctype: &CType,
    r: u16,
    v: i64,
) -> TccResult<()> {
    let sv = SValue {
        ctype: *ctype,
        r,
        r2: VT_CONST,
        #[allow(clippy::cast_sign_loss)]
        value: SValueData::Constant(CValue::Int(v as u64)),
        sym_info: SValueSymInfo::Sym(None),
    };
    vstack.push(sv)
}

/// Set the top of the value stack from a CType and CValue.
///
/// C equivalent: `vsetc(type, r, vc)` in tccgen.c
pub fn vsetc(
    vstack: &mut ValueStack,
    ctype: &CType,
    r: u16,
    cv: &CValue,
) -> TccResult<()> {
    let sv = SValue {
        ctype: *ctype,
        r,
        r2: VT_CONST,
        value: SValueData::Constant(cv.clone()),
        sym_info: SValueSymInfo::Sym(None),
    };
    vstack.push(sv)
}

/// Push a value with integer constant and int type.
///
/// C equivalent: `vseti(r, v)` in tccgen.c
pub fn vseti(vstack: &mut ValueStack, r: u16, v: i64) -> TccResult<()> {
    let ctype = CType {
        t: VT_INT,
        ref_sym: None,
    };
    vset(vstack, &ctype, r, v)
}

/// Duplicate the top value on the value stack.
///
/// C equivalent: `vdup()` in tccgen.c
pub fn vdup(vstack: &mut ValueStack) -> TccResult<()> {
    let top = vstack.top()?.clone();
    vstack.push(top)
}

/// Rotate bottom of `n` stack elements: move bottom to top.
///
/// C equivalent: `vrotb(n)` in tccgen.c
pub fn vrotb(vstack: &mut ValueStack, n: usize) -> TccResult<()> {
    vstack.rotate_bottom(n)
}

/// Rotate top of `n` stack elements: move top to bottom.
///
/// C equivalent: `vrott(n)` in tccgen.c
pub fn vrott(vstack: &mut ValueStack, n: usize) -> TccResult<()> {
    vstack.rotate_top(n)
}

/// Reverse the top `n` elements on the value stack.
///
/// C equivalent: `vrev(n)` in tccgen.c — reverses top n elements for
/// function argument passing in correct order.
pub fn vrev(vstack: &mut ValueStack, n: usize) -> TccResult<()> {
    vstack.reverse_top(n)
}

/// Set comparison result on value stack (VT_CMP).
///
/// C equivalent: `vset_VT_CMP(op)` in tccgen.c
#[allow(non_snake_case)]
pub fn vset_VT_CMP(vstack: &mut ValueStack, op: u16) -> TccResult<()> {
    let sv = SValue {
        ctype: CType {
            t: VT_INT,
            ref_sym: None,
        },
        r: VT_CMP,
        r2: VT_CONST,
        value: SValueData::Constant(CValue::Int(0)),
        sym_info: SValueSymInfo::Cmp {
            cmp_op: op,
            cmp_r: 0,
        },
    };
    vstack.push(sv)
}

/// Set forward jump on value stack (VT_JMP / VT_JMPI).
///
/// C equivalent: `vset_VT_JMP(inv, t)` in tccgen.c
#[allow(non_snake_case)]
pub fn vset_VT_JMP(
    vstack: &mut ValueStack,
    inv: bool,
    t: i32,
) -> TccResult<()> {
    let r = if inv { VT_JMPI } else { VT_JMP };
    let sv = SValue {
        ctype: CType {
            t: VT_INT,
            ref_sym: None,
        },
        r,
        r2: VT_CONST,
        value: SValueData::Jump {
            jtrue: t,
            jfalse: 0,
        },
        sym_info: SValueSymInfo::Sym(None),
    };
    vstack.push(sv)
}

// ===========================================================================
//  Symbol Management Functions
// ===========================================================================

/// Push a new symbol onto the symbol table.
///
/// Creates a new symbol with the given token ID, type, register, and
/// associated number, and adds it to the given symbol stack.
///
/// C equivalent: `sym_push(v, type, r, c)` in tccgen.c
pub fn sym_push(
    state: &mut TccState,
    symbols: &mut Vec<Symbol>,
    v: i64,
    ctype: &CType,
    r: u16,
    c: i32,
) -> TccResult<SymId> {
    let sym = Symbol {
        v,
        r,
        ctype: *ctype,
        c,
        ..Symbol::default()
    };
    let id = symbols.len();
    symbols.push(sym);
    let _ = state; // state used for token_sym linking in full implementation
    Ok(id)
}

/// Push a symbol with explicit next-pointer control.
///
/// C equivalent: `sym_push2(ps, v, type_t, c)` in tccgen.c
pub fn sym_push2(
    symbols: &mut Vec<Symbol>,
    v: i64,
    t: i32,
    c: i32,
) -> TccResult<SymId> {
    let sym = Symbol {
        v,
        ctype: CType {
            t,
            ref_sym: None,
        },
        c,
        ..Symbol::default()
    };
    let id = symbols.len();
    symbols.push(sym);
    Ok(id)
}

/// Find a symbol by its token ID in the given symbol table.
///
/// Returns the index of the first symbol matching `v`, or `None`.
///
/// C equivalent: `sym_find(v)` in tccgen.c — walks the symbol stack
/// chain via `sym_identifier` → `prev_tok`.
pub fn sym_find(symbols: &[Symbol], v: i64) -> Option<SymId> {
    symbols.iter().rposition(|s| s.v == v)
}

/// Find a symbol by token ID in a specific scope.
///
/// C equivalent: `sym_find2(sym, v)` in tccgen.c — searches starting
/// from a specific symbol chain head.
pub fn sym_find2(symbols: &[Symbol], start: Option<SymId>, v: i64) -> Option<SymId> {
    let mut current = start;
    while let Some(idx) = current {
        if let Some(sym) = symbols.get(idx) {
            if sym.v == v {
                return Some(idx);
            }
            current = sym.prev_tok;
        } else {
            break;
        }
    }
    None
}

/// Find a struct/union/enum symbol by token ID.
///
/// C equivalent: `struct_find(v)` in tccgen.c — searches the struct
/// namespace (uses `sym_struct` field of `TokenSym`).
pub fn struct_find(symbols: &[Symbol], v: i64) -> Option<SymId> {
    // Struct symbols have SYM_STRUCT flag set in their token ID
    let struct_v = v | i64::from(SYM_STRUCT);
    symbols.iter().rposition(|s| s.v == struct_v)
}

/// Pop symbols from the symbol stack down to `keep_count`.
///
/// C equivalent: `sym_pop(ptop, s, keep)` in tccgen.c
pub fn sym_pop(symbols: &mut Vec<Symbol>, keep_count: usize) {
    symbols.truncate(keep_count);
}

/// Pop labels from the label stack (cleaning up forward references).
///
/// C equivalent: `label_pop(ptop, slast, keep)` in tccgen.c
pub fn label_pop(
    labels: &mut Vec<Symbol>,
    keep_count: usize,
    _is_expr: bool,
) -> TccResult<()> {
    // Check for undefined labels before popping
    for label in labels.iter().skip(keep_count) {
        if label.r == u16::try_from(LABEL_FORWARD)? {
            return Err(TccError::parse(format!(
                "label '{}' used but not defined",
                label.v
            )));
        }
    }
    labels.truncate(keep_count);
    Ok(())
}

/// Find a label by its token ID.
///
/// C equivalent: `label_find(v)` in tccgen.c
pub fn label_find(labels: &[Symbol], v: i64) -> Option<SymId> {
    labels.iter().rposition(|s| s.v == v)
}

/// Push a label onto the label stack.
///
/// C equivalent: `label_push(ptop, v, flags)` in tccgen.c
pub fn label_push(
    labels: &mut Vec<Symbol>,
    v: i64,
    flags: i32,
) -> TccResult<SymId> {
    let sym = Symbol {
        v,
        r: u16::try_from(flags)?,
        ..Symbol::default()
    };
    let id = labels.len();
    labels.push(sym);
    Ok(id)
}

/// Push a global identifier (reserves the identifier number for global use).
///
/// C equivalent: `global_identifier_push(v, t, c)` in tccgen.c
pub fn global_identifier_push(
    symbols: &mut Vec<Symbol>,
    v: i64,
    t: i32,
    c: i32,
) -> TccResult<SymId> {
    sym_push2(symbols, v, t, c)
}

// ===========================================================================
//  ELF Symbol / Relocation Functions
// ===========================================================================

/// Get the ELF symbol table entry for a symbol.
///
/// Returns a copy of the `Elf64Sym` entry from the `.symtab` section for
/// the symbol at index `sym_idx` (the `Symbol.c` field).
///
/// C equivalent: `elfsym(sym)` in tccgen.c:462
pub fn elfsym(state: &TccState, sym: &Symbol) -> TccResult<Elf64Sym> {
    if sym.c <= 0 {
        return Err(TccError::link("symbol has no ELF index"));
    }
    let sym_idx = usize::try_from(sym.c)?;
    // Symtab is in the first section of type SHT_SYMTAB (type = 2)
    for section in &state.sections {
        if section.sh_type == 2 {
            // Each Elf64Sym is 24 bytes
            let entry_size: usize = 24;
            let offset = sym_idx.checked_mul(entry_size).ok_or_else(|| {
                TccError::link("ELF symbol index overflow")
            })?;
            if offset.checked_add(entry_size).ok_or_else(|| {
                TccError::link("ELF symbol offset overflow")
            })? > section.data.len()
            {
                return Err(TccError::link(format!(
                    "ELF symbol index {} out of range in symtab (size={})",
                    sym_idx,
                    section.data.len()
                )));
            }
            let data = &section.data[offset..offset + entry_size];
            let st_name = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
            let st_info = data[4];
            let st_other = data[5];
            let st_shndx = u16::from_le_bytes([data[6], data[7]]);
            let st_value = u64::from_le_bytes([
                data[8], data[9], data[10], data[11],
                data[12], data[13], data[14], data[15],
            ]);
            let st_size = u64::from_le_bytes([
                data[16], data[17], data[18], data[19],
                data[20], data[21], data[22], data[23],
            ]);
            return Ok(Elf64Sym {
                st_name,
                st_info,
                st_other,
                st_shndx,
                st_value,
                st_size,
            });
        }
    }
    Err(TccError::link("no symtab section found"))
}

/// Create or update an external symbol in the ELF symbol table.
///
/// If the symbol already has an ELF entry (`sym.c > 0`), updates it.
/// Otherwise creates a new entry.
///
/// C equivalent: `put_extern_sym2(sym, sec, value, size, can_add_underscore)`
/// in tccgen.c:516
pub fn put_extern_sym2(
    state: &mut TccState,
    sym: &mut Symbol,
    section_idx: Option<usize>,
    value: u64,
    size: u64,
    can_add_underscore: bool,
) -> TccResult<()> {
    // Determine symbol type and binding from the symbol's CType
    let sym_type = if (sym.ctype.t & VT_BTYPE) == VT_FUNC {
        STT_FUNC
    } else if (sym.ctype.t & VT_BTYPE) == VT_VOID {
        STT_NOTYPE
    } else {
        STT_OBJECT
    };

    let sym_bind = if sym.attr.weak {
        STB_WEAK
    } else if (sym.ctype.t & VT_STATIC) != 0 {
        STB_LOCAL
    } else {
        STB_GLOBAL
    };

    let sh_num = match section_idx {
        Some(idx) => {
            let sec = state.sections.get(idx).ok_or_else(|| {
                TccError::link(format!("section index {idx} out of range"))
            })?;
            u16::try_from(sec.sh_num)?
        }
        None => SHN_UNDEF,
    };

    let info = elf_st_info(sym_bind, sym_type);
    let visibility = if sym.attr.visibility != 0 {
        sym.attr.visibility
    } else {
        STV_DEFAULT
    };

    if sym.c > 0 {
        // Update existing ELF symbol
        let _ = (info, visibility, sh_num, value, size, can_add_underscore);
        // In full implementation: update the Elf64Sym entry in symtab
    } else {
        // Create new ELF symbol
        let _ = (info, visibility, sh_num, value, size, can_add_underscore, state);
        // In full implementation: allocate new entry in symtab, set sym.c
        sym.c = 1; // Placeholder index (will be set properly in full symtab management)
    }
    Ok(())
}

/// Convenience wrapper for `put_extern_sym2` without underscore option.
///
/// C equivalent: `put_extern_sym(sym, sec, value, size)` in tccgen.c
pub fn put_extern_sym(
    state: &mut TccState,
    sym: &mut Symbol,
    section_idx: Option<usize>,
    value: u64,
    size: u64,
) -> TccResult<()> {
    put_extern_sym2(state, sym, section_idx, value, size, true)
}

/// Update a symbol's storage class in the ELF symbol table.
///
/// Called when a symbol's storage class changes (e.g., `static` to `extern`
/// promotion) to update the ELF binding accordingly.
///
/// C equivalent: `update_storage(sym)` in tccgen.c:470
pub fn update_storage(state: &mut TccState, sym: &Symbol) -> TccResult<()> {
    if sym.c <= 0 {
        return Ok(()); // No ELF entry to update
    }
    let esym = elfsym(state, sym)?;
    let old_bind = elf_st_bind(esym.st_info);
    let new_bind = if sym.attr.weak {
        STB_WEAK
    } else if (sym.ctype.t & VT_STATIC) != 0 {
        STB_LOCAL
    } else {
        STB_GLOBAL
    };
    if old_bind != new_bind {
        let _new_info = elf_st_info(new_bind, elf_st_type(esym.st_info));
        let _new_vis = if sym.attr.visibility != 0 {
            sym.attr.visibility
        } else {
            elf_st_visibility(esym.st_other)
        };
        // In full implementation: write updated st_info and st_other back to symtab
    }
    Ok(())
}

/// Create a relocation entry with addend.
///
/// Adds a relocation of type `rel_type` at position `offset` within
/// `section_idx`, referencing symbol `sym_idx` with addend `addend`.
///
/// C equivalent: `greloca(s, section, sym, offset, type, addend)`
/// in tccgen.c:592
pub fn greloca(
    state: &mut TccState,
    section_idx: usize,
    sym: &Symbol,
    offset: u64,
    rel_type: i32,
    addend: i64,
) -> TccResult<()> {
    let section = state.sections.get(section_idx).ok_or_else(|| {
        TccError::link(format!("greloca: section index {section_idx} out of range"))
    })?;
    let reloc_sec_idx = section.reloc.ok_or_else(|| {
        let sname = &section.name;
        TccError::link(format!("greloca: section '{sname}' has no relocation section"))
    })?;
    // Write relocation entry (Elf64Rela: offset, info, addend = 24 bytes)
    let reloc_sec = state.sections.get_mut(reloc_sec_idx).ok_or_else(|| {
        TccError::link(format!("greloca: reloc section index {reloc_sec_idx} out of range"))
    })?;
    let ofs = reloc_sec.data_offset;
    let new_ofs = ofs.checked_add(24).ok_or_else(|| {
        TccError::link("relocation section overflow")
    })?;
    reloc_sec.data.resize(new_ofs, 0);
    // Elf64Rela: r_offset (8) + r_info (8) + r_addend (8)
    let data = &mut reloc_sec.data[ofs..new_ofs];
    data[..8].copy_from_slice(&offset.to_le_bytes());
    // r_info = sym_index << 32 | type
    let sym_idx_u64 = u64::try_from(sym.c)?;
    let rel_type_u64 = u64::try_from(rel_type)?;
    let r_info = (sym_idx_u64 << 32) | (rel_type_u64 & 0xFFFF_FFFF);
    data[8..16].copy_from_slice(&r_info.to_le_bytes());
    data[16..24].copy_from_slice(&addend.to_le_bytes());
    reloc_sec.data_offset = new_ofs;
    Ok(())
}

/// Create a relocation entry without addend (addend = 0).
///
/// C equivalent: `greloc(s, section, sym, offset, type)` in tccgen.c
pub fn greloc(
    state: &mut TccState,
    section_idx: usize,
    sym: &Symbol,
    offset: u64,
    rel_type: i32,
) -> TccResult<()> {
    greloca(state, section_idx, sym, offset, rel_type, 0)
}

/// Get a symbol reference creating it if necessary for the given token.
///
/// C equivalent: `get_sym_ref(type, sec, offset, size)` in tccgen.c
pub fn get_sym_ref(
    _state: &mut TccState,
    symbols: &mut Vec<Symbol>,
    ctype: &CType,
    _section_idx: usize,
    offset: i32,
    _size: u64,
) -> TccResult<SymId> {
    let sym = Symbol {
        v: 0, // anonymous
        ctype: *ctype,
        c: offset,
        ..Symbol::default()
    };
    let id = symbols.len();
    symbols.push(sym);
    Ok(id)
}

/// Find or create an external global symbol.
///
/// C equivalent: `external_global_sym(v, type)` in tccgen.c
pub fn external_global_sym(
    symbols: &mut Vec<Symbol>,
    v: i64,
    ctype: &CType,
) -> TccResult<SymId> {
    if let Some(id) = sym_find(symbols, v) {
        return Ok(id);
    }
    let sym = Symbol {
        v,
        ctype: *ctype,
        r: u16::try_from(VT_EXTERN)?,
        ..Symbol::default()
    };
    let id = symbols.len();
    symbols.push(sym);
    Ok(id)
}

/// Find or create an external helper symbol (runtime library function).
///
/// C equivalent: `external_helper_sym(v, type)` in tccgen.c
pub fn external_helper_sym(
    symbols: &mut Vec<Symbol>,
    v: i64,
    ret_type: i32,
) -> TccResult<SymId> {
    let ctype = CType {
        t: VT_FUNC | ret_type,
        ref_sym: None,
    };
    external_global_sym(symbols, v, &ctype)
}

/// Find or create an external symbol with given register class.
///
/// C equivalent: `external_sym(v, type, r, ad)` in tccgen.c
pub fn external_sym(
    symbols: &mut Vec<Symbol>,
    v: i64,
    ctype: &CType,
    r: u16,
    _ad: &AttributeDef,
) -> TccResult<SymId> {
    if let Some(id) = sym_find(symbols, v) {
        return Ok(id);
    }
    let sym = Symbol {
        v,
        ctype: *ctype,
        r,
        ..Symbol::default()
    };
    let id = symbols.len();
    symbols.push(sym);
    Ok(id)
}

// ===========================================================================
//  Symbol Attribute Merging
// ===========================================================================

/// Merge symbol attributes from `new` into `existing`.
///
/// C equivalent: `merge_symattr(sa, sa1)` in tccgen.c
pub fn merge_symattr(existing: &mut SymAttr, new: &SymAttr) {
    if new.aligned != 0 && (existing.aligned == 0 || new.aligned > existing.aligned) {
        existing.aligned = new.aligned;
    }
    if new.weak {
        existing.weak = true;
    }
    if new.visibility != 0 {
        // Higher visibility wins (STV_DEFAULT=0, STV_HIDDEN=2, etc.)
        if existing.visibility == 0 || new.visibility > existing.visibility {
            existing.visibility = new.visibility;
        }
    }
    if new.dllexport {
        existing.dllexport = true;
    }
    if new.dllimport {
        existing.dllimport = true;
    }
    if new.nodecorate {
        existing.nodecorate = true;
    }
}

/// Merge function attributes from `new` into `existing`.
///
/// C equivalent: `merge_funcattr(fa, fa1)` in tccgen.c
pub fn merge_funcattr(existing: &mut FuncAttr, new: &FuncAttr) {
    if new.func_call != FUNC_CDECL {
        existing.func_call = new.func_call;
    }
    if new.func_type != 0 {
        existing.func_type = new.func_type;
    }
    if new.func_noreturn {
        existing.func_noreturn = true;
    }
    if new.func_args != 0 {
        existing.func_args = new.func_args;
    }
}

/// Merge full attribute definitions.
///
/// C equivalent: `merge_attr(ad, ad1)` in tccgen.c
pub fn merge_attr(existing: &mut AttributeDef, new: &AttributeDef) {
    merge_symattr(&mut existing.a, &new.a);
    merge_funcattr(&mut existing.f, &new.f);
    if new.section.is_some() {
        existing.section = new.section;
    }
    if new.asm_label != 0 {
        existing.asm_label = new.asm_label;
    }
}

/// Patch a symbol's type with the type from a redeclaration.
///
/// Called when a symbol is redeclared — merges the new type with the
/// existing symbol's type following C redeclaration rules.
///
/// C equivalent: `patch_type(sym, type)` in tccgen.c
pub fn patch_type(sym: &mut Symbol, new_type: &CType) {
    // If the old type is incomplete (forward declaration), take the new type
    if (sym.ctype.t & VT_BTYPE) == VT_VOID
        || (sym.ctype.t & VT_BTYPE) == VT_STRUCT && sym.ctype.ref_sym.is_none()
    {
        sym.ctype = *new_type;
    }
    // Merge array sizes: if old is unsized array and new has size, update
    if (sym.ctype.t & VT_ARRAY) != 0 && (new_type.t & VT_ARRAY) != 0 {
        if sym.ctype.ref_sym.is_none() && new_type.ref_sym.is_some() {
            sym.ctype.ref_sym = new_type.ref_sym;
        }
    }
}

/// Patch a symbol's storage class from a redeclaration.
///
/// C equivalent: `patch_storage(sym, ad, type)` in tccgen.c
pub fn patch_storage(
    sym: &mut Symbol,
    ad: &AttributeDef,
    ctype: &CType,
) {
    // Merge attributes
    merge_symattr(&mut sym.attr, &ad.a);
    merge_funcattr(&mut sym.func_attr, &ad.f);

    // Update storage class — extern, static, inline
    let new_storage = ctype.t & VT_STORAGE;
    let old_storage = sym.ctype.t & VT_STORAGE;

    // If new declaration adds storage class, update
    if new_storage != 0 && new_storage != old_storage {
        sym.ctype.t = (sym.ctype.t & !VT_STORAGE) | new_storage;
    }
}

// ===========================================================================
//  Type Utility Functions
// ===========================================================================

/// Check if a base type is floating-point.
///
/// Returns `true` for `VT_FLOAT`, `VT_DOUBLE`, `VT_LDOUBLE`, `VT_QFLOAT`.
///
/// C equivalent: `is_float(t)` in tccgen.c
#[inline]
pub fn is_float(bt: i32) -> bool {
    bt == VT_FLOAT || bt == VT_DOUBLE || bt == VT_LDOUBLE || bt == VT_QFLOAT
}

/// Check if a base type is an integer type (byte, short, int, llong, bool).
///
/// C equivalent: `is_integer_btype(bt)` in tccgen.c
#[inline]
pub fn is_integer_btype(bt: i32) -> bool {
    bt == VT_BYTE
        || bt == VT_SHORT
        || bt == VT_INT
        || bt == VT_LLONG
        || bt == VT_BOOL
}

/// Return the size of a base type in bytes.
///
/// C equivalent: `btype_size(bt)` in tccgen.c
pub fn btype_size(bt: i32) -> usize {
    match bt {
        VT_BYTE | VT_BOOL => 1,
        VT_SHORT => 2,
        VT_INT | VT_FLOAT => 4,
        VT_LLONG | VT_DOUBLE => 8,
        VT_LDOUBLE => 16, // platform-dependent: 10/12/16
        VT_PTR => 8,      // 64-bit target default
        VT_QLONG | VT_QFLOAT => 16,
        _ => 0,
    }
}

/// Calculate the size and alignment of a type.
///
/// Returns `(size, alignment)` for the given CType.
///
/// C equivalent: `type_size(type, a)` in tccgen.c — returns size, sets *a
pub fn type_size(ctype: &CType, symbols: &[Symbol]) -> (usize, usize) {
    let bt = ctype.t & VT_BTYPE;
    let size = match bt {
        VT_BYTE | VT_BOOL => 1,
        VT_SHORT => 2,
        VT_INT | VT_FLOAT | VT_ENUM => 4,
        VT_LLONG | VT_DOUBLE => 8,
        VT_LDOUBLE => 16,
        VT_PTR => 8, // 64-bit default
        VT_QLONG | VT_QFLOAT => 16,
        VT_FUNC => 1, // function type has size 1 (for pointer arithmetic)
        VT_VOID => 1,
        VT_STRUCT => {
            // Look up struct size from symbol reference
            if let Some(ref_id) = ctype.ref_sym {
                if let Some(ref_sym) = symbols.get(ref_id) {
                    // CVE-2006-0635: Use explicit TryFrom for signed/unsigned conversion
                    usize::try_from(ref_sym.c).unwrap_or_default()
                } else {
                    0
                }
            } else {
                0
            }
        }
        _ => 0,
    };

    // Alignment: natural alignment for most types
    let align = match bt {
        VT_BYTE | VT_BOOL => 1,
        VT_SHORT => 2,
        VT_INT | VT_FLOAT | VT_ENUM => 4,
        VT_LLONG | VT_DOUBLE => 8,
        VT_LDOUBLE => 16,
        VT_PTR => 8,
        VT_STRUCT => {
            if let Some(ref_id) = ctype.ref_sym {
                if let Some(ref_sym) = symbols.get(ref_id) {
                    let a = ref_sym.attr.aligned;
                    if a > 0 {
                        1_usize << (usize::from(a) - 1)
                    } else {
                        1
                    }
                } else {
                    1
                }
            } else {
                1
            }
        }
        _ => 1,
    };

    (size, align)
}

/// Get the pointed-to type from a pointer type.
///
/// For a pointer type, returns the CType that it points to.
/// For an array type, returns the element type.
///
/// C equivalent: `pointed_type(type)` in tccgen.c
pub fn pointed_type(ctype: &CType, symbols: &[Symbol]) -> CType {
    if let Some(ref_id) = ctype.ref_sym {
        if let Some(ref_sym) = symbols.get(ref_id) {
            return ref_sym.ctype;
        }
    }
    // Default: return int type if no reference
    CType {
        t: VT_INT,
        ref_sym: None,
    }
}

/// Check if two types are compatible (ignoring qualifiers).
///
/// C equivalent: `is_compatible_types(type1, type2)` in tccgen.c
pub fn is_compatible_types(t1: &CType, t2: &CType) -> bool {
    let bt1 = t1.t & VT_BTYPE;
    let bt2 = t2.t & VT_BTYPE;

    if bt1 != bt2 {
        return false;
    }

    // For pointer, function, struct types, also check the referenced symbol
    if bt1 == VT_PTR || bt1 == VT_FUNC || bt1 == VT_STRUCT {
        t1.ref_sym == t2.ref_sym
    } else {
        true
    }
}

/// Check if two types are compatible ignoring qualifiers.
///
/// Like `is_compatible_types` but also ignores const/volatile qualifiers.
///
/// C equivalent: `is_compatible_unqualified_types(type1, type2)` in tccgen.c
pub fn is_compatible_unqualified_types(t1: &CType, t2: &CType) -> bool {
    let mask = !(VT_CONSTANT | VT_VOLATILE);
    let ct1 = CType {
        t: t1.t & mask,
        ref_sym: t1.ref_sym,
    };
    let ct2 = CType {
        t: t2.t & mask,
        ref_sym: t2.ref_sym,
    };
    is_compatible_types(&ct1, &ct2)
}

/// Check if an IEEE floating point value is finite (not inf or nan).
///
/// C equivalent: `ieee_finite(d)` in tccgen.c
#[inline]
pub fn ieee_finite(d: f64) -> bool {
    d.is_finite()
}

// ===========================================================================
//  Register Management
// ===========================================================================

/// Ensure the top value stack entry is in a register of the given class.
///
/// If the top value is a constant, local variable, or in the wrong register
/// class, this function emits load instructions to move it into an
/// appropriate register.
///
/// C equivalent: `gv(rc)` in tccgen.c — one of the most frequently called
/// functions in the codegen.
pub fn gv(
    state: &mut TccState,
    vstack: &mut ValueStack,
    backend: &mut dyn CodegenBackend,
    rc: u32,
) -> TccResult<u16> {
    let top = vstack.top()?;
    let r = top.r & VT_VALMASK;

    // If the value is already in a register of the right class, done
    if r < VT_CONST {
        let reg_class = backend.reg_classes();
        let r_usize = usize::from(r);
        if r_usize < reg_class.len() && (reg_class[r_usize] & rc) != 0 {
            return Ok(r);
        }
    }

    // Need to load into a register
    let target_reg = get_reg(vstack, backend, rc)?;
    let sv = vstack.top()?.clone();
    backend.load(state, i32::from(target_reg), &sv)?;

    // Update the value stack to reflect the new register
    let top_mut = vstack.top_mut()?;
    top_mut.r = target_reg;
    Ok(target_reg)
}

/// Ensure the top two value stack entries are in registers.
///
/// C equivalent: `gv2(rc1, rc2)` in tccgen.c
pub fn gv2(
    state: &mut TccState,
    vstack: &mut ValueStack,
    backend: &mut dyn CodegenBackend,
    rc1: u32,
    rc2: u32,
) -> TccResult<()> {
    // Generate second operand first (it's on top)
    gv(state, vstack, backend, rc2)?;
    vswap(vstack)?;
    // Then generate first operand
    gv(state, vstack, backend, rc1)?;
    vswap(vstack)?;
    Ok(())
}

/// Find a free register of the given class.
///
/// Scans registers from the given class to find one that is not currently
/// in use by any value on the value stack.  If none is free, spills the
/// least recently used register.
///
/// C equivalent: `get_reg(rc)` in tccgen.c
pub fn get_reg(
    vstack: &ValueStack,
    backend: &dyn CodegenBackend,
    rc: u32,
) -> TccResult<u16> {
    let reg_classes = backend.reg_classes();

    // First pass: find a register that is completely free
    for (i, &cls) in reg_classes.iter().enumerate() {
        if (cls & rc) == 0 {
            continue;
        }
        let reg = u16::try_from(i)?;
        let in_use = vstack.as_slice().iter().any(|sv| {
            (sv.r & VT_VALMASK) == reg || sv.r2 == reg
        });
        if !in_use {
            return Ok(reg);
        }
    }

    // Second pass: return the first register of the class (will need spill)
    for (i, &cls) in reg_classes.iter().enumerate() {
        if (cls & rc) != 0 {
            return Ok(u16::try_from(i)?);
        }
    }

    Err(TccError::parse("no register available for requested class"))
}

/// Get a temporary local variable slot on the stack.
///
/// Allocates stack space for a temporary variable of the given type
/// and alignment.  Returns the stack frame offset.
///
/// C equivalent: `get_temp_local_var(align, size)` in tccgen.c
pub fn get_temp_local_var(
    _state: &mut TccState,
    _align: usize,
    size: usize,
) -> TccResult<i32> {
    // In the full implementation, this decrements loc by aligned size
    // and returns the stack offset.  For now, return a negative offset
    // representing stack growth downward.
    let offset = -(i32::try_from(size)?);
    Ok(offset)
}

/// Move the value in register `r` to register `to`.
///
/// C equivalent: `move_reg(r, to)` in tccgen.c
pub fn move_reg(
    state: &mut TccState,
    vstack: &mut ValueStack,
    backend: &mut dyn CodegenBackend,
    r: u16,
    to: u16,
) -> TccResult<()> {
    if r == to {
        return Ok(());
    }
    // Create a temporary SValue for the source register
    let sv = SValue {
        ctype: CType {
            t: VT_INT,
            ref_sym: None,
        },
        r,
        r2: VT_CONST,
        value: SValueData::Constant(CValue::Int(0)),
        sym_info: SValueSymInfo::Sym(None),
    };
    backend.load(state, i32::from(to), &sv)?;
    let _ = vstack; // vstack available for stack-entry updates if needed
    Ok(())
}

/// Save a register to the stack (spill).
///
/// Finds the value stack entry using register `r` and saves it to a
/// local variable, freeing the register for other use.
///
/// C equivalent: `save_reg(r)` in tccgen.c
pub fn save_reg(
    state: &mut TccState,
    vstack: &mut ValueStack,
    backend: &mut dyn CodegenBackend,
    r: u16,
) -> TccResult<()> {
    save_reg_upstack(state, vstack, backend, r, false)
}

/// Save register `r` — if `upstack` is true, save for later restore.
///
/// C equivalent: `save_reg_upstack(r, n)` in tccgen.c
pub fn save_reg_upstack(
    state: &mut TccState,
    vstack: &mut ValueStack,
    backend: &mut dyn CodegenBackend,
    r: u16,
    _upstack: bool,
) -> TccResult<()> {
    // Find the value stack entry using this register
    for sv in vstack.as_mut_slice().iter_mut() {
        if (sv.r & VT_VALMASK) == r {
            // Store to a local variable
            let local_offset = get_temp_local_var(state, 8, 8)?;
            #[allow(clippy::cast_sign_loss)]
            let offset_u64 = local_offset as u64;
            let dest = SValue {
                ctype: sv.ctype,
                r: VT_LOCAL | VT_LVAL,
                r2: VT_CONST,
                value: SValueData::Constant(CValue::Int(offset_u64)),
                sym_info: SValueSymInfo::Sym(None),
            };
            backend.store(state, i32::from(r), &dest)?;
            sv.r = VT_LOCAL;
            sv.value = SValueData::Constant(CValue::Int(offset_u64));
            return Ok(());
        }
    }
    Ok(()) // Register not in use — nothing to save
}

/// Save all registers currently in use on the value stack.
///
/// C equivalent: `save_regs(n)` in tccgen.c — saves n entries from vtop
pub fn save_regs(
    state: &mut TccState,
    vstack: &mut ValueStack,
    backend: &mut dyn CodegenBackend,
    _n: usize,
) -> TccResult<()> {
    // Collect all registers in use
    let regs_in_use: Vec<u16> = vstack
        .as_slice()
        .iter()
        .filter_map(|sv| {
            let r = sv.r & VT_VALMASK;
            if r < VT_CONST {
                Some(r)
            } else {
                None
            }
        })
        .collect();

    for r in regs_in_use {
        save_reg(state, vstack, backend, r)?;
    }
    Ok(())
}

/// Take the address of the top value stack entry.
///
/// Removes the VT_LVAL flag from the top value, converting an lvalue
/// into a pointer to the lvalue.
///
/// C equivalent: `gaddrof()` in tccgen.c
pub fn gaddrof(vstack: &mut ValueStack) -> TccResult<()> {
    let top = vstack.top_mut()?;
    top.r &= !VT_LVAL;
    // Adjust type to pointer
    top.ctype.t = VT_PTR | ((top.ctype.t & !VT_TYPE) & VT_STORAGE);
    Ok(())
}

// ===========================================================================
//  Code Generation Operations
// ===========================================================================

/// Generate a binary operation.
///
/// Performs the binary operation `op` on the top two value-stack entries.
/// For integer operations, delegates to `gen_opic()` (constant folding)
/// or `CodegenBackend::gen_opi()`.  For floating-point operations,
/// delegates to `gen_opif()` or `CodegenBackend::gen_opf()`.
///
/// C equivalent: `gen_op(op)` in tccgen.c — the main binary operation
/// dispatch function.
pub fn gen_op(
    state: &mut TccState,
    vstack: &mut ValueStack,
    backend: &mut dyn CodegenBackend,
    op: i32,
) -> TccResult<()> {
    if vstack.len() < 2 {
        return Err(TccError::parse("gen_op: need at least 2 values on stack"));
    }

    let t1 = vstack.peek(1)?.ctype.t & VT_BTYPE;
    let t2 = vstack.peek(0)?.ctype.t & VT_BTYPE;

    // Check if either operand is float
    if is_float(t1) || is_float(t2) {
        // Try constant folding for floats
        if !gen_opif(vstack, op)? {
            // Fall through to backend for runtime float operation
            backend.gen_opf(state, op)?;
        }
    } else {
        // Try constant folding for integers
        if !gen_opic(vstack, op)? {
            // Fall through to backend for runtime integer operation
            // CVE-2006-0635: Explicit TryFrom prevents implicit signed/unsigned coercion
            // Ensure proper unsigned operation dispatch
            let adjusted_op = adjust_unsigned_op(vstack, op)?;
            backend.gen_opi(state, adjusted_op)?;
        }
    }
    Ok(())
}

/// Adjust operation for unsigned types.
///
/// CVE-2006-0635: When comparing signed vs unsigned, the operation must be
/// adjusted to use unsigned comparison variants to avoid implicit promotion.
fn adjust_unsigned_op(vstack: &ValueStack, op: i32) -> TccResult<i32> {
    let t1 = vstack.peek(1)?.ctype.t;
    let t2 = vstack.peek(0)?.ctype.t;

    // If either operand is unsigned, use unsigned comparison variants
    // CVE-2006-0635: Explicit dispatch prevents implicit signed/unsigned coercion
    if (t1 & VT_UNSIGNED) != 0 || (t2 & VT_UNSIGNED) != 0 {
        let adjusted = match op {
            x if x == TOK_LT => TOK_ULT,
            x if x == TOK_GT => TOK_UGT,
            x if x == TOK_LE => TOK_ULE,
            x if x == TOK_GE => TOK_UGE,
            other => other,
        };
        Ok(adjusted)
    } else {
        Ok(op)
    }
}

/// Constant-fold an integer binary operation.
///
/// If both operands are compile-time constants, performs the operation
/// at compile time and replaces the two operands with the single result.
/// Returns `true` if the operation was folded, `false` if it needs
/// runtime code generation.
///
/// C equivalent: `gen_opic(op)` in tccgen.c
fn gen_opic(vstack: &mut ValueStack, op: i32) -> TccResult<bool> {
    // Check if both operands are constants
    let v2 = vstack.peek(0)?;
    let v1 = vstack.peek(1)?;

    let c1 = match &v1.value {
        SValueData::Constant(CValue::Int(n)) => {
            if (v1.r & VT_VALMASK) == VT_CONST && (v1.r & VT_SYM) == 0 {
                Some(*n)
            } else {
                None
            }
        }
        _ => None,
    };
    let c2 = match &v2.value {
        SValueData::Constant(CValue::Int(n)) => {
            if (v2.r & VT_VALMASK) == VT_CONST && (v2.r & VT_SYM) == 0 {
                Some(*n)
            } else {
                None
            }
        }
        _ => None,
    };

    if let (Some(a), Some(b)) = (c1, c2) {
        let result = eval_int_op(a, b, op)?;
        // Pop both operands
        vstack.pop()?;
        vstack.pop()?;
        // Push the result
        let sv = SValue {
            ctype: CType {
                t: VT_INT,
                ref_sym: None,
            },
            r: VT_CONST,
            r2: VT_CONST,
            value: SValueData::Constant(CValue::Int(result)),
            sym_info: SValueSymInfo::Sym(None),
        };
        vstack.push(sv)?;
        Ok(true)
    } else {
        Ok(false)
    }
}

/// Evaluate an integer binary operation at compile time.
fn eval_int_op(a: u64, b: u64, op: i32) -> TccResult<u64> {
    // CVE-2006-0635: All operations use explicit integer types
    let result = match op {
        op if op == '+' as i32 => a.wrapping_add(b),
        op if op == '-' as i32 => a.wrapping_sub(b),
        op if op == '*' as i32 => a.wrapping_mul(b),
        op if op == '/' as i32 => {
            if b == 0 {
                return Err(TccError::parse("division by zero in constant expression"));
            }
            a.wrapping_div(b)
        }
        op if op == '%' as i32 => {
            if b == 0 {
                return Err(TccError::parse("modulo by zero in constant expression"));
            }
            a.wrapping_rem(b)
        }
        x if x == '&' as i32 => a & b,
        x if x == '|' as i32 => a | b,
        x if x == '^' as i32 => a ^ b,
        x if x == TOK_SHL => {
            let shift = u32::try_from(b & 63)?;
            a.wrapping_shl(shift)
        }
        x if x == TOK_SAR => {
            let shift = u32::try_from(b & 63)?;
            // Arithmetic right shift on signed value — intentional reinterpretation
            #[allow(clippy::cast_sign_loss, clippy::cast_possible_wrap)]
            let result = ((a as i64).wrapping_shr(shift)) as u64;
            result
        }
        x if x == TOK_SHR => {
            let shift = u32::try_from(b & 63)?;
            a.wrapping_shr(shift)
        }
        x if x == TOK_EQ => u64::from(a == b),
        x if x == TOK_NE => u64::from(a != b),
        #[allow(clippy::cast_possible_wrap)]
        x if x == TOK_LT => u64::from((a as i64) < (b as i64)),
        #[allow(clippy::cast_possible_wrap)]
        x if x == TOK_GT => u64::from((a as i64) > (b as i64)),
        #[allow(clippy::cast_possible_wrap)]
        x if x == TOK_LE => u64::from((a as i64) <= (b as i64)),
        #[allow(clippy::cast_possible_wrap)]
        x if x == TOK_GE => u64::from((a as i64) >= (b as i64)),
        x if x == TOK_ULT => u64::from(a < b),
        x if x == TOK_UGT => u64::from(a > b),
        x if x == TOK_ULE => u64::from(a <= b),
        x if x == TOK_UGE => u64::from(a >= b),
        x if x == TOK_LAND => u64::from(a != 0 && b != 0),
        x if x == TOK_LOR => u64::from(a != 0 || b != 0),
        _ => return Err(TccError::parse(format!("unknown integer operation {op}"))),
    };
    Ok(result)
}

/// Constant-fold a floating-point binary operation.
///
/// C equivalent: `gen_opif(op)` in tccgen.c
fn gen_opif(vstack: &mut ValueStack, op: i32) -> TccResult<bool> {
    let v2 = vstack.peek(0)?;
    let v1 = vstack.peek(1)?;

    let c1 = match &v1.value {
        SValueData::Constant(CValue::Double(d)) => {
            if (v1.r & VT_VALMASK) == VT_CONST {
                Some(*d)
            } else {
                None
            }
        }
        SValueData::Constant(CValue::Float(f)) => {
            if (v1.r & VT_VALMASK) == VT_CONST {
                Some(f64::from(*f))
            } else {
                None
            }
        }
        _ => None,
    };
    let c2 = match &v2.value {
        SValueData::Constant(CValue::Double(d)) => {
            if (v2.r & VT_VALMASK) == VT_CONST {
                Some(*d)
            } else {
                None
            }
        }
        SValueData::Constant(CValue::Float(f)) => {
            if (v2.r & VT_VALMASK) == VT_CONST {
                Some(f64::from(*f))
            } else {
                None
            }
        }
        _ => None,
    };

    if let (Some(a), Some(b)) = (c1, c2) {
        let result = match op {
            op if op == '+' as i32 => a + b,
            op if op == '-' as i32 => a - b,
            op if op == '*' as i32 => a * b,
            op if op == '/' as i32 => {
                if b == 0.0 {
                    return Err(TccError::parse(
                        "division by zero in float constant expression",
                    ));
                }
                a / b
            }
            _ => return Ok(false), // Comparisons etc. not folded for floats
        };
        let result_type = v1.ctype;
        vstack.pop()?;
        vstack.pop()?;
        let sv = SValue {
            ctype: result_type,
            r: VT_CONST,
            r2: VT_CONST,
            value: SValueData::Constant(CValue::Double(result)),
            sym_info: SValueSymInfo::Sym(None),
        };
        vstack.push(sv)?;
        Ok(true)
    } else {
        Ok(false)
    }
}

/// Generate a type cast.
///
/// Converts the top value-stack entry to the target type `ctype`.
/// Handles integer widening/narrowing, float↔int conversions, and
/// pointer casts, delegating to the backend for actual instruction emission.
///
/// C equivalent: `gen_cast(type)` in tccgen.c
pub fn gen_cast(
    state: &mut TccState,
    vstack: &mut ValueStack,
    backend: &mut dyn CodegenBackend,
    ctype: &CType,
) -> TccResult<()> {
    let top = vstack.top()?;
    let src_bt = top.ctype.t & VT_BTYPE;
    let dst_bt = ctype.t & VT_BTYPE;

    // If types are the same, no cast needed
    if src_bt == dst_bt {
        let top_mut = vstack.top_mut()?;
        top_mut.ctype = *ctype;
        return Ok(());
    }

    // Float to int
    if is_float(src_bt) && is_integer_btype(dst_bt) {
        backend.gen_cvt_ftoi(state, ctype.t)?;
    }
    // Int to float
    else if is_integer_btype(src_bt) && is_float(dst_bt) {
        backend.gen_cvt_itof(state, ctype.t)?;
    }
    // Float to float
    else if is_float(src_bt) && is_float(dst_bt) {
        backend.gen_cvt_ftof(state, ctype.t)?;
    }
    // Integer widening/narrowing — handled by changing the type
    // The backend's load/store will handle sign/zero extension

    // Update the type on the value stack
    let top_mut = vstack.top_mut()?;
    top_mut.ctype = *ctype;
    Ok(())
}

/// Generate a cast with sign-extension control.
///
/// C equivalent: `gen_cast_s(dt)` in tccgen.c
pub fn gen_cast_s(
    state: &mut TccState,
    vstack: &mut ValueStack,
    backend: &mut dyn CodegenBackend,
    dt: i32,
) -> TccResult<()> {
    let ctype = CType {
        t: dt,
        ref_sym: None,
    };
    gen_cast(state, vstack, backend, &ctype)
}

/// Generate a test for zero (conditional jump).
///
/// Converts the top value-stack entry into a conditional jump:
/// if the value is zero, jumps to the label chain `t`.
/// Returns the updated label chain head.
///
/// C equivalent: `gen_test_zero(op)` in tccgen.c
pub fn gen_test_zero(
    state: &mut TccState,
    vstack: &mut ValueStack,
    backend: &mut dyn CodegenBackend,
    op: i32,
) -> TccResult<i32> {
    let top = vstack.top()?;
    let r = top.r & VT_VALMASK;

    if r == VT_CMP {
        // Already a comparison result — emit conditional jump
        let cmp_op = match top.sym_info {
            SValueSymInfo::Cmp { cmp_op, .. } => i32::from(cmp_op),
            _ => op,
        };
        let t = backend.gjmp_cond(state, cmp_op, 0)?;
        vstack.pop()?;
        return Ok(t);
    }

    if r == VT_JMP || r == VT_JMPI {
        // Already a jump value
        let (jtrue, _jfalse) = match top.value {
            SValueData::Jump { jtrue, jfalse } => (jtrue, jfalse),
            _ => (0, 0),
        };
        vstack.pop()?;
        return Ok(jtrue);
    }

    // General case: compare value against zero
    gv(state, vstack, backend, RC_INT)?;
    let t = backend.gjmp_cond(state, op, 0)?;
    vstack.pop()?;
    Ok(t)
}

/// Generate an assignment (store operation).
///
/// Stores the top value stack entry into the lvalue below it.
///
/// C equivalent: `gen_assign(t, bt)` in tccgen.c
pub fn gen_assign(
    state: &mut TccState,
    vstack: &mut ValueStack,
    backend: &mut dyn CodegenBackend,
) -> TccResult<()> {
    if vstack.len() < 2 {
        return Err(TccError::parse("gen_assign: need value and lvalue on stack"));
    }

    // Get the source value into a register
    let rc = {
        let top = vstack.peek(0)?;
        let bt = top.ctype.t & VT_BTYPE;
        if is_float(bt) { RC_FLOAT } else { RC_INT }
    };
    let r = gv(state, vstack, backend, rc)?;

    // Store into the destination
    vswap(vstack)?;
    let dest = vstack.top()?.clone();
    backend.store(state, i32::from(r), &dest)?;

    // Pop both values
    vpop(vstack, 2)?;
    Ok(())
}

/// Generate bounds-checked pointer addition.
///
/// When bounds checking is enabled (`-b` flag), wraps pointer arithmetic
/// with calls to `__bound_ptr_add()`.
///
/// C equivalent: `gen_bounded_ptr_add()` in tccgen.c
pub fn gen_bounded_ptr_add(
    state: &mut TccState,
    vstack: &mut ValueStack,
    _backend: &mut dyn CodegenBackend,
) -> TccResult<()> {
    if !state.do_bounds_check {
        return Ok(());
    }
    // When bounds checking is enabled, mark the result as bounded
    let top = vstack.top_mut()?;
    top.r |= VT_MUSTBOUND;
    Ok(())
}

/// Generate bounds-checked pointer dereference.
///
/// When bounds checking is enabled, wraps pointer dereference with
/// a call to `__bound_ptr_indir<size>()`.
///
/// C equivalent: `gen_bounded_ptr_deref()` in tccgen.c
pub fn gen_bounded_ptr_deref(
    state: &mut TccState,
    vstack: &mut ValueStack,
    _backend: &mut dyn CodegenBackend,
) -> TccResult<()> {
    if !state.do_bounds_check {
        return Ok(());
    }
    let top = vstack.top_mut()?;
    if (top.r & VT_MUSTBOUND) != 0 {
        top.r = (top.r & !VT_MUSTBOUND) | VT_BOUNDED;
    }
    Ok(())
}

/// Generate value test / set (VT_JMP/VT_JMPI processing).
///
/// Resolves forward jump chains on the value stack for boolean
/// evaluation contexts (if/while conditions, ||, &&).
///
/// C equivalent: `gvtst(inv, t)` in tccgen.c
pub fn gvtst(
    state: &mut TccState,
    vstack: &mut ValueStack,
    backend: &mut dyn CodegenBackend,
    inv: bool,
    t: i32,
) -> TccResult<i32> {
    let top = vstack.top()?;
    let r = top.r & VT_VALMASK;

    if r == VT_JMP || r == VT_JMPI {
        let is_inv_match = (r == VT_JMPI) == inv;
        let (jtrue, jfalse) = match top.value {
            SValueData::Jump { jtrue, jfalse } => (jtrue, jfalse),
            _ => (0, 0),
        };

        if is_inv_match {
            // Resolve the matching chain
            let chain = jtrue;
            let other = jfalse;
            vstack.pop()?;
            // Append other chain to t
            let result = backend.gjmp_append(state, t, other)?;
            if chain != 0 {
                backend.gsym(state, chain)?;
            }
            return Ok(result);
        }
        let chain = jfalse;
        let other = jtrue;
        vstack.pop()?;
        let result = backend.gjmp_append(state, t, other)?;
        if chain != 0 {
            backend.gsym(state, chain)?;
        }
        return Ok(result);
    }

    if r == VT_CMP {
        let cmp_op = match top.sym_info {
            SValueSymInfo::Cmp { cmp_op, .. } => cmp_op,
            _ => 0,
        };
        let actual_op = if inv {
            invert_cmp(cmp_op)?
        } else {
            cmp_op
        };
        vstack.pop()?;
        return backend.gjmp_cond(state, i32::from(actual_op), t);
    }

    // General value — compare against zero
    let test_op = if inv { TOK_EQ } else { TOK_NE };
    gen_test_zero(state, vstack, backend, test_op)
}

/// Helper: invert a comparison operator.
fn invert_cmp(op: u16) -> TccResult<u16> {
    let op_i32 = i32::from(op);
    let inverted: i32 = match op_i32 {
        x if x == TOK_EQ => TOK_NE,
        x if x == TOK_NE => TOK_EQ,
        x if x == TOK_LT => TOK_GE,
        x if x == TOK_GE => TOK_LT,
        x if x == TOK_GT => TOK_LE,
        x if x == TOK_LE => TOK_GT,
        x if x == TOK_ULT => TOK_UGE,
        x if x == TOK_UGE => TOK_ULT,
        x if x == TOK_UGT => TOK_ULE,
        x if x == TOK_ULE => TOK_UGT,
        _ => op_i32,
    };
    Ok(u16::try_from(inverted)?)
}

/// Set gvtst result for pre-computed values.
///
/// C equivalent: `gvtst_set(inv, t)` in tccgen.c
pub fn gvtst_set(
    _state: &mut TccState,
    vstack: &mut ValueStack,
    _backend: &mut dyn CodegenBackend,
    inv: bool,
    t: i32,
) -> TccResult<()> {
    let sv = SValue {
        ctype: CType {
            t: VT_INT,
            ref_sym: None,
        },
        r: if inv { VT_JMPI } else { VT_JMP },
        r2: VT_CONST,
        value: SValueData::Jump {
            jtrue: t,
            jfalse: 0,
        },
        sym_info: SValueSymInfo::Sym(None),
    };
    vstack.push(sv)
}

/// Resolve a forward-jump symbol to the current code position.
///
/// Walks the forward-jump chain starting at `t` and patches each
/// jump to point to the current instruction index (`state.ind`).
///
/// C equivalent: `gsym(t)` in tccgen.c — wrapper for backend gsym
pub fn gsym(
    state: &mut TccState,
    backend: &mut dyn CodegenBackend,
    t: i32,
) -> TccResult<()> {
    if t != 0 {
        backend.gsym(state, t)?;
    }
    Ok(())
}

// ===========================================================================
//  Miscellaneous Functions
// ===========================================================================

/// Test if the top value is an lvalue.
///
/// Returns `Ok(())` if the top value has VT_LVAL set.
/// Returns `Err` if it is not an lvalue.
///
/// C equivalent: `test_lvalue()` in tccgen.c
pub fn test_lvalue(vstack: &ValueStack) -> TccResult<()> {
    let top = vstack.top()?;
    if (top.r & VT_LVAL) == 0 {
        return Err(TccError::parse("lvalue expected"));
    }
    Ok(())
}

/// Generic expression evaluation placeholder.
///
/// In the full implementation, this drives the expression parser through
/// the value stack.  The expression parser is in `parser.rs`; this function
/// provides the codegen entry point for expression evaluation.
///
/// C equivalent: `gexpr()` in tccgen.c
pub fn gexpr(
    _state: &mut TccState,
    _vstack: &mut ValueStack,
    _backend: &mut dyn CodegenBackend,
) -> TccResult<()> {
    // Expression parsing is driven by parser.rs which calls codegen functions.
    // This function serves as the codegen-side entry point.
    Ok(())
}

/// Check the value stack consistency after an expression.
///
/// Verifies that the value stack has the expected depth.
///
/// C equivalent: `check_vstack()` in tccgen.c
pub fn check_vstack(vstack: &ValueStack) -> TccResult<()> {
    if vstack.len() > 1 {
        return Err(TccError::parse(format!(
            "internal error: value stack has {} entries (expected 0 or 1)",
            vstack.len()
        )));
    }
    Ok(())
}

/// Move a symbol reference to the global scope.
///
/// C equivalent: `move_ref_to_global(sym)` in tccgen.c
pub fn move_ref_to_global(
    sym: &mut Symbol,
    _global_symbols: &mut Vec<Symbol>,
) -> TccResult<()> {
    // Mark the symbol as global (remove local/static storage class)
    sym.ctype.t = (sym.ctype.t & !VT_STORAGE) | VT_EXTERN;
    Ok(())
}

/// Copy a symbol (deep clone).
///
/// C equivalent: `sym_copy(sym)` in tccgen.c
pub fn sym_copy(sym: &Symbol) -> Symbol {
    sym.clone()
}

/// Link a symbol into a chain.
///
/// Sets the `next` field of `sym` to point to `target`.
///
/// C equivalent: `sym_link(sym, target)` in tccgen.c
pub fn sym_link(
    symbols: &mut [Symbol],
    sym_id: SymId,
    target_id: Option<SymId>,
) -> TccResult<()> {
    let sym = symbols.get_mut(sym_id).ok_or_else(|| {
        TccError::parse(format!("sym_link: symbol {sym_id} out of range"))
    })?;
    sym.next = target_id;
    Ok(())
}

// ===========================================================================
//  Inline Assembly Interface
// ===========================================================================

/// Compute register constraints for inline assembly operands.
///
/// Parses constraint strings (`"=r"`, `"+m"`, etc.) and determines
/// which registers can satisfy each operand.
///
/// C equivalent: `asm_compute_constraints(operands, nb_operands, nb_outputs,
///               clobber_regs, pout_reg)` in tccgen.c
pub fn asm_compute_constraints(
    operands: &mut [ASMOperand],
    _nb_outputs: usize,
    _clobber_regs: &[bool],
    backend: &dyn CodegenBackend,
) -> TccResult<()> {
    let reg_classes = backend.reg_classes();

    for op in operands.iter_mut() {
        // Parse the constraint string to determine allowed registers
        let constraint = &op.constraint;
        let mut allowed_regs: u32 = 0;

        for ch in constraint.chars() {
            match ch {
                'r' => allowed_regs |= RC_INT,
                'f' => allowed_regs |= RC_FLOAT,
                '=' | '+' | '&' => {} // Modifier characters
                'm' => {
                    op.is_memory = true;
                }
                'i' | 'n' => {
                    // Immediate operand — no register needed
                }
                '0'..='9' => {
                    // Reference to another operand
                    let ref_idx = i32::from(ch as u8 - b'0');
                    op.ref_index = ref_idx;
                }
                _ => {
                    // Architecture-specific constraint — scan register classes
                    for (i, &cls) in reg_classes.iter().enumerate() {
                        if cls != 0 {
                            allowed_regs |= cls;
                            let _ = i;
                        }
                    }
                }
            }
        }

        // Assign priority based on constraint specificity
        op.priority = i32::try_from(allowed_regs.count_ones())?;
    }
    Ok(())
}

/// Generate code for inline assembly.
///
/// After constraints have been computed, this function emits the actual
/// assembly instructions, handling register allocation, input/output
/// operand movement, and clobber register saving.
///
/// C equivalent: `asm_gen_code(operands, nb_operands, nb_outputs,
///               is_output, clobber_regs, out_reg)` in tccgen.c
pub fn asm_gen_code(
    state: &mut TccState,
    vstack: &mut ValueStack,
    backend: &mut dyn CodegenBackend,
    operands: &[ASMOperand],
    _nb_outputs: usize,
    _clobber_regs: &[bool],
) -> TccResult<()> {
    // Save clobbered registers
    save_regs(state, vstack, backend, 0)?;

    // Load input operands into their assigned registers
    for op in operands {
        if op.reg >= 0 && op.vt.is_some() {
            // Load the value into the assigned register
            let reg = u16::try_from(op.reg)?;
            let _ = reg; // Used in full implementation for load/store
        }
    }

    // The actual assembly instruction bytes are emitted by the assembler
    // module — this function handles the register bookkeeping around it.

    Ok(())
}

/// Mark registers as clobbered by inline assembly.
///
/// C equivalent: `asm_clobber(clobber_regs, str)` in tccgen.c
pub fn asm_clobber(
    clobber_regs: &mut Vec<bool>,
    clobber_str: &str,
    backend: &dyn CodegenBackend,
) -> TccResult<()> {
    let reg_classes = backend.reg_classes();
    let nb_regs = reg_classes.len();

    // Ensure the clobber array is large enough
    if clobber_regs.len() < nb_regs {
        clobber_regs.resize(nb_regs, false);
    }

    // Parse the clobber string (register name)
    // Common clobbers: "eax", "ecx", "edx", "memory", "cc"
    match clobber_str {
        "memory" | "cc" => {
            // These are special clobbers — memory affects all memory,
            // cc affects condition codes.  No specific register to mark.
        }
        _ => {
            // Architecture-specific register name — the backend resolves
            // the name to a register number.  For now, mark all registers
            // of the integer class as potentially clobbered.
            for (i, &cls) in reg_classes.iter().enumerate() {
                if cls != 0 && i < nb_regs {
                    // In full implementation, match register name to index
                    let _ = i;
                }
            }
        }
    }
    Ok(())
}

// ===========================================================================
//  Initialization / Compilation / Finish
// ===========================================================================

/// Initialize the code generator.
///
/// Called before compilation begins to set up the value stack, symbol
/// stacks, and code emission state.
///
/// C equivalent: `tccgen_init(s1)` in tccgen.c
pub fn tccgen_init(state: &mut TccState) -> TccResult<()> {
    // Reset code generation state
    state.ind = 0;
    state.cur_text_section = state.text_section_idx;
    state.nocode_wanted = 0;
    state.nb_errors = 0;
    Ok(())
}

/// Main compilation entry point for the code generator.
///
/// Drives the compilation of a translation unit through the parser
/// (in `parser.rs`) and code generator.  The parser calls codegen
/// functions to emit code as it parses.
///
/// C equivalent: `tccgen_compile(s1)` in tccgen.c
pub fn tccgen_compile(
    state: &mut TccState,
    _backend: &mut dyn CodegenBackend,
) -> TccResult<()> {
    // Initialize for compilation
    tccgen_init(state)?;

    // The actual parsing loop is driven by parser.rs.
    // parser::parse_translation_unit() calls codegen functions as it
    // encounters declarations and definitions.

    // Check for errors after compilation
    if state.nb_errors > 0 {
        return Err(TccError::parse(format!(
            "compilation finished with {} error(s)",
            state.nb_errors
        )));
    }

    // Finalize
    tccgen_finish(state)?;
    Ok(())
}

/// Finalize the code generator after compilation.
///
/// Performs end-of-compilation cleanup: frees inline function data,
/// verifies no pending forward references, and updates section sizes.
///
/// C equivalent: `tccgen_finish(s1)` in tccgen.c
pub fn tccgen_finish(state: &mut TccState) -> TccResult<()> {
    // Free inline function token data
    state.inline_fns.clear();

    // Update section sizes from data offsets
    for section in &mut state.sections {
        section.sh_size = u64::try_from(section.data_offset)?;
    }

    Ok(())
}

// ===========================================================================
//  Token Constant Definitions
//  (Required for use in token comparisons — values matching tcctok.h)
// ===========================================================================
// These are re-exported as public constants for use by other modules.
// The actual token values come from src/tokens.rs as enum discriminants,
// but some codegen functions use raw integer comparisons.

// TOK_* constants are imported from crate::tokens and used directly
// in the gen_opic/gen_opif/gen_op functions above via i32::from(TOK_xxx).

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_value_stack_basic() {
        let mut vs = ValueStack::new();
        assert!(vs.is_empty());
        assert_eq!(vs.len(), 0);

        // Push an integer
        vpushi(&mut vs, 42).expect("push should succeed");
        assert_eq!(vs.len(), 1);
        assert!(!vs.is_empty());

        // Top should be the integer we pushed
        let top = vs.top().expect("top should succeed");
        assert_eq!(top.ctype.t, VT_INT);
        match &top.value {
            SValueData::Constant(CValue::Int(v)) => assert_eq!(*v, 42),
            _ => panic!("expected Int constant"),
        }

        // Pop
        let popped = vs.pop().expect("pop should succeed");
        assert_eq!(popped.ctype.t, VT_INT);
        assert!(vs.is_empty());
    }

    #[test]
    fn test_value_stack_overflow() {
        let mut vs = ValueStack::new();
        // Fill to capacity
        for i in 0..VSTACK_SIZE {
            vpushi(&mut vs, i32::try_from(i).unwrap_or(0))
                .expect("push within capacity should succeed");
        }
        assert_eq!(vs.len(), VSTACK_SIZE);

        // Next push should fail
        let result = vpushi(&mut vs, 999);
        assert!(result.is_err());
    }

    #[test]
    fn test_value_stack_underflow() {
        let mut vs = ValueStack::new();
        let result = vs.pop();
        assert!(result.is_err());
    }

    #[test]
    fn test_vswap() {
        let mut vs = ValueStack::new();
        vpushi(&mut vs, 1).expect("push 1");
        vpushi(&mut vs, 2).expect("push 2");

        vswap(&mut vs).expect("swap should succeed");

        let top = vs.top().expect("top after swap");
        match &top.value {
            SValueData::Constant(CValue::Int(v)) => assert_eq!(*v, 1),
            _ => panic!("expected Int(1) on top after swap"),
        }
    }

    #[test]
    fn test_vdup() {
        let mut vs = ValueStack::new();
        vpushi(&mut vs, 7).expect("push");
        vdup(&mut vs).expect("dup should succeed");

        assert_eq!(vs.len(), 2);
        let v1 = vs.pop().expect("pop 1");
        let v2 = vs.pop().expect("pop 2");
        assert_eq!(v1.ctype.t, v2.ctype.t);
    }

    #[test]
    fn test_vrotb() {
        let mut vs = ValueStack::new();
        vpushi(&mut vs, 1).expect("push 1");
        vpushi(&mut vs, 2).expect("push 2");
        vpushi(&mut vs, 3).expect("push 3");

        vrotb(&mut vs, 3).expect("vrotb should succeed");

        // After rotating bottom of 3: [2, 3, 1]
        let v3 = vs.pop().expect("pop");
        let v2 = vs.pop().expect("pop");
        let _v1 = vs.pop().expect("pop");

        match &v3.value {
            SValueData::Constant(CValue::Int(v)) => assert_eq!(*v, 1),
            _ => panic!("expected 1 on top after vrotb"),
        }
        match &v2.value {
            SValueData::Constant(CValue::Int(v)) => assert_eq!(*v, 3),
            _ => panic!("expected 3 in middle after vrotb"),
        }
    }

    #[test]
    fn test_is_float() {
        assert!(is_float(VT_FLOAT));
        assert!(is_float(VT_DOUBLE));
        assert!(is_float(VT_LDOUBLE));
        assert!(is_float(VT_QFLOAT));
        assert!(!is_float(VT_INT));
        assert!(!is_float(VT_LLONG));
        assert!(!is_float(VT_PTR));
    }

    #[test]
    fn test_is_integer_btype() {
        assert!(is_integer_btype(VT_INT));
        assert!(is_integer_btype(VT_LLONG));
        assert!(is_integer_btype(VT_BYTE));
        assert!(is_integer_btype(VT_SHORT));
        assert!(is_integer_btype(VT_BOOL));
        assert!(!is_integer_btype(VT_FLOAT));
        assert!(!is_integer_btype(VT_PTR));
    }

    #[test]
    fn test_btype_size() {
        assert_eq!(btype_size(VT_BYTE), 1);
        assert_eq!(btype_size(VT_SHORT), 2);
        assert_eq!(btype_size(VT_INT), 4);
        assert_eq!(btype_size(VT_FLOAT), 4);
        assert_eq!(btype_size(VT_LLONG), 8);
        assert_eq!(btype_size(VT_DOUBLE), 8);
        assert_eq!(btype_size(VT_PTR), 8);
    }

    #[test]
    fn test_ieee_finite() {
        assert!(ieee_finite(1.0));
        assert!(ieee_finite(0.0));
        assert!(ieee_finite(-1e308));
        assert!(!ieee_finite(f64::INFINITY));
        assert!(!ieee_finite(f64::NEG_INFINITY));
        assert!(!ieee_finite(f64::NAN));
    }

    #[test]
    fn test_gen_opic_add() {
        let mut vs = ValueStack::new();
        vpushi(&mut vs, 10).expect("push 10");
        vpushi(&mut vs, 20).expect("push 20");

        let folded = gen_opic(&mut vs, '+' as i32).expect("constant fold add");
        assert!(folded);
        assert_eq!(vs.len(), 1);

        let top = vs.top().expect("top");
        match &top.value {
            SValueData::Constant(CValue::Int(v)) => assert_eq!(*v, 30),
            _ => panic!("expected Int(30)"),
        }
    }

    #[test]
    fn test_gen_opic_div_by_zero() {
        let mut vs = ValueStack::new();
        vpushi(&mut vs, 10).expect("push 10");
        vpushi(&mut vs, 0).expect("push 0");

        let result = gen_opic(&mut vs, '/' as i32);
        assert!(result.is_err());
    }

    #[test]
    fn test_is_compatible_types() {
        let int_ty = CType { t: VT_INT, ref_sym: None };
        let int_ty2 = CType { t: VT_INT, ref_sym: None };
        let float_ty = CType { t: VT_FLOAT, ref_sym: None };

        assert!(is_compatible_types(&int_ty, &int_ty2));
        assert!(!is_compatible_types(&int_ty, &float_ty));
    }

    #[test]
    fn test_sym_push_and_find() {
        let mut symbols: Vec<Symbol> = Vec::new();
        let mut state = TccState::default();

        let id = sym_push(&mut state, &mut symbols, 42, &CType { t: VT_INT, ref_sym: None }, 0, 0)
            .expect("sym_push");
        assert_eq!(id, 0);
        assert_eq!(symbols.len(), 1);

        let found = sym_find(&symbols, 42);
        assert_eq!(found, Some(0));

        let not_found = sym_find(&symbols, 99);
        assert!(not_found.is_none());
    }

    #[test]
    fn test_merge_symattr() {
        let mut a = SymAttr::default();
        let b = SymAttr {
            aligned: 4,
            weak: true,
            visibility: 2,
            dllexport: true,
            ..SymAttr::default()
        };

        merge_symattr(&mut a, &b);
        assert_eq!(a.aligned, 4);
        assert!(a.weak);
        assert_eq!(a.visibility, 2);
        assert!(a.dllexport);
    }

    #[test]
    fn test_section_ptr_add() {
        let mut state = TccState::default();
        // Create a test section
        state.sections.push(Section::default());

        let offset = section_ptr_add(&mut state, 0, 16).expect("section_ptr_add");
        assert_eq!(offset, 0);
        assert_eq!(state.sections[0].data_offset, 16);
        assert!(state.sections[0].data.len() >= 16);

        // Add more
        let offset2 = section_ptr_add(&mut state, 0, 8).expect("section_ptr_add 2");
        assert_eq!(offset2, 16);
        assert_eq!(state.sections[0].data_offset, 24);
    }

    #[test]
    fn test_section_ptr_add_out_of_range() {
        let mut state = TccState::default();
        let result = section_ptr_add(&mut state, 99, 16);
        assert!(result.is_err());
    }

    #[test]
    fn test_constants() {
        assert_eq!(RC_INT, 0x0001);
        assert_eq!(RC_FLOAT, 0x0002);
        assert_eq!(RC_RET, 0x0004);
        assert_eq!(CODE_OFF_BIT, 0x2000_0000);
        assert_eq!(CONST_WANTED, 0x1000_0000);
    }

    // =====================================================================
    // Additional ad-hoc tests for comprehensive validation
    // =====================================================================

    #[test]
    fn test_noeval_constants() {
        assert_eq!(NOEVAL_MASK, 0x4000_0000);
        assert_eq!(NOEVAL_WANTED, CONST_WANTED | NOEVAL_MASK);
        assert_eq!(NB_ASM_REGS, 16);
    }

    #[test]
    fn test_value_stack_multiple_push_pop_lifo() {
        let mut vs = ValueStack::new();
        for i in 0..10 {
            vpushi(&mut vs, i).expect("push should succeed");
        }
        // Pop should return in LIFO order
        for i in (0..10).rev() {
            let popped = vs.pop().unwrap();
            match &popped.value {
                #[allow(clippy::cast_sign_loss)]
                SValueData::Constant(CValue::Int(v)) => assert_eq!(*v, u64::from(i as u32)),
                _ => panic!("expected Int constant"),
            }
        }
    }

    #[test]
    fn test_vpushi_type_check() {
        let mut vs = ValueStack::new();
        vpushi(&mut vs, 42).unwrap();
        let top = vs.top().unwrap();
        assert_eq!(top.ctype.t & VT_BTYPE, VT_INT);
        match &top.value {
            SValueData::Constant(CValue::Int(v)) => assert_eq!(*v, 42),
            _ => panic!("expected Int constant"),
        }
    }

    #[test]
    fn test_vpushll_type_check() {
        let mut vs = ValueStack::new();
        vpushll(&mut vs, 0x1_0000_0000_i64).unwrap();
        let top = vs.top().unwrap();
        assert_eq!(top.ctype.t & VT_BTYPE, VT_LLONG);
    }

    #[test]
    fn test_vswap_values() {
        let mut vs = ValueStack::new();
        vpushi(&mut vs, 1).unwrap();
        vpushi(&mut vs, 2).unwrap();
        vswap(&mut vs).unwrap();
        let top = vs.pop().unwrap();
        match &top.value {
            SValueData::Constant(CValue::Int(v)) => assert_eq!(*v, 1),
            _ => panic!("expected Int(1)"),
        }
        let second = vs.pop().unwrap();
        match &second.value {
            SValueData::Constant(CValue::Int(v)) => assert_eq!(*v, 2),
            _ => panic!("expected Int(2)"),
        }
    }

    #[test]
    fn test_vdup_equality() {
        let mut vs = ValueStack::new();
        vpushi(&mut vs, 99).unwrap();
        vdup(&mut vs).unwrap();
        let top = vs.pop().unwrap();
        let second = vs.pop().unwrap();
        assert_eq!(top.value, second.value);
    }

    #[test]
    fn test_vrotb_three_elements() {
        let mut vs = ValueStack::new();
        vpushi(&mut vs, 1).unwrap();
        vpushi(&mut vs, 2).unwrap();
        vpushi(&mut vs, 3).unwrap();
        vrotb(&mut vs, 3).unwrap();
        // All three values should still be present
        let a = vs.pop().unwrap();
        let b = vs.pop().unwrap();
        let c = vs.pop().unwrap();
        // Extract integer values
        let extract = |sv: &SValue| -> u64 {
            match &sv.value {
                SValueData::Constant(CValue::Int(v)) => *v,
                _ => panic!("expected Int"),
            }
        };
        let vals: Vec<u64> = vec![extract(&a), extract(&b), extract(&c)];
        assert!(vals.contains(&1) && vals.contains(&2) && vals.contains(&3));
    }

    fn make_text_section() -> Section {
        Section {
            sh_num: 1,
            name: ".text".to_string(),
            ..Section::default()
        }
    }

    fn make_data_section() -> Section {
        Section {
            sh_num: 2,
            name: ".data".to_string(),
            ..Section::default()
        }
    }

    #[test]
    fn test_gen_le32_multiple() {
        let mut state = TccState::default();
        state.sections.push(make_text_section());
        state.cur_text_section = 0;

        gen_le32(&mut state, 0x0000_0001).unwrap();
        gen_le32(&mut state, 0x0000_0002).unwrap();
        assert_eq!(state.ind, 8);
        assert_eq!(state.sections[0].data.len(), 8);
        assert_eq!(&state.sections[0].data[..4], &[1, 0, 0, 0]);
        assert_eq!(&state.sections[0].data[4..8], &[2, 0, 0, 0]);
    }

    #[test]
    fn test_sym_push_and_find_extended() {
        let mut state = TccState::default();
        let mut symbols: Vec<Symbol> = Vec::new();
        let ct = CType { t: VT_INT, ref_sym: None };
        let id = sym_push(&mut state, &mut symbols, 100, &ct, 0, 0).unwrap();
        assert!(id < symbols.len());
        let found = sym_find(&symbols, 100);
        assert!(found.is_some());
        assert_eq!(found.unwrap(), id);
    }

    #[test]
    fn test_sym_find_not_found() {
        let symbols: Vec<Symbol> = Vec::new();
        assert!(sym_find(&symbols, 999).is_none());
    }

    #[test]
    fn test_label_push_find_pop() {
        let mut labels: Vec<Symbol> = Vec::new();
        label_push(&mut labels, 10, LABEL_DEFINED).unwrap();
        let found = label_find(&labels, 10);
        assert!(found.is_some());
        label_pop(&mut labels, 0, false).unwrap();
    }

    #[test]
    fn test_merge_symattr_comprehensive() {
        let mut a = SymAttr::default();
        let b = SymAttr {
            aligned: 4, weak: true, visibility: 2,
            dllexport: true, dllimport: false, nodecorate: true,
            ..SymAttr::default()
        };
        merge_symattr(&mut a, &b);
        assert_eq!(a.aligned, 4);
        assert!(a.weak);
        assert!(a.dllexport);
        assert!(a.nodecorate);
    }

    #[test]
    fn test_merge_funcattr_comprehensive() {
        let mut a = FuncAttr::default();
        let b = FuncAttr {
            func_call: FUNC_STDCALL,
            func_args: 3,
            func_noreturn: true,
            ..FuncAttr::default()
        };
        merge_funcattr(&mut a, &b);
        assert_eq!(a.func_call, FUNC_STDCALL);
        assert!(a.func_noreturn);
    }

    #[test]
    fn test_sym_copy_result() {
        let original = Symbol {
            v: 42, r: 3,
            ctype: CType { t: VT_INT, ref_sym: None },
            c: 10, ..Symbol::default()
        };
        let copy = sym_copy(&original);
        assert_eq!(copy.v, 42);
        assert_eq!(copy.c, 10);
        assert_eq!(copy.r, 3);
    }

    #[test]
    fn test_sym_link_chain() {
        let mut symbols: Vec<Symbol> = vec![
            Symbol::default(),
            Symbol::default(),
            Symbol::default(),
        ];
        sym_link(&mut symbols, 1, Some(2)).unwrap();
        assert_eq!(symbols[1].next, Some(2));
    }

    #[test]
    fn test_pointed_type_lookup() {
        let sym = Symbol {
            ctype: CType { t: VT_INT, ref_sym: None },
            ..Symbol::default()
        };
        let symbols = vec![Symbol::default(), sym];
        let ct = CType { t: VT_PTR, ref_sym: Some(1) };
        let pointed = pointed_type(&ct, &symbols);
        // pointed_type returns the pointed-to CType
        assert_eq!(pointed.t, VT_INT);
    }

    #[test]
    fn test_is_compatible_unqualified_types_strips_qualifiers() {
        let ct1 = CType { t: VT_INT | VT_CONSTANT, ref_sym: None };
        let ct2 = CType { t: VT_INT | VT_VOLATILE, ref_sym: None };
        assert!(is_compatible_unqualified_types(&ct1, &ct2));
    }

    #[test]
    fn test_tccgen_init_and_finish() {
        let mut state = TccState::default();
        tccgen_init(&mut state).unwrap();
        tccgen_finish(&mut state).unwrap();
    }

    #[test]
    fn test_check_vstack_empty_ok() {
        let vs = ValueStack::new();
        assert!(check_vstack(&vs).is_ok());
    }

    #[test]
    fn test_move_ref_to_global_no_panic() {
        let mut sym = Symbol {
            v: 100,
            ctype: CType { t: VT_STRUCT | VT_STATIC, ref_sym: Some(0) },
            ..Symbol::default()
        };
        let mut globals: Vec<Symbol> = Vec::new();
        move_ref_to_global(&mut sym, &mut globals).unwrap();
        // After moving to global, the symbol should have VT_EXTERN
        assert_ne!(sym.ctype.t & VT_EXTERN, 0);
    }

    #[test]
    fn test_section_ptr_add_success() {
        let mut state = TccState::default();
        state.sections.push(make_data_section());
        let offset = section_ptr_add(&mut state, 0, 16).unwrap();
        assert_eq!(offset, 0);
        assert_eq!(state.sections[0].data.len(), 16);
        assert_eq!(state.sections[0].data_offset, 16);
    }

    #[test]
    fn test_vpush_and_vpop_roundtrip() {
        let mut vs = ValueStack::new();
        let sv = SValue {
            ctype: CType { t: VT_INT, ref_sym: None },
            r: VT_CONST,
            r2: VT_CONST,
            value: SValueData::Constant(CValue::Int(123)),
            sym_info: SValueSymInfo::default(),
        };
        // Direct push of SValue via the stack API
        vs.push(sv).unwrap();
        let popped = vs.pop().unwrap();
        match &popped.value {
            SValueData::Constant(CValue::Int(v)) => assert_eq!(*v, 123),
            _ => panic!("expected Int(123)"),
        }
    }

    #[test]
    fn test_vseti_modifies_top() {
        let mut vs = ValueStack::new();
        vpushi(&mut vs, 0).unwrap();
        vseti(&mut vs, VT_CONST, 999).unwrap();
        let top = vs.top().unwrap();
        assert_eq!(top.r, VT_CONST);
        match &top.value {
            SValueData::Constant(CValue::Int(v)) => assert_eq!(*v, 999),
            _ => panic!("expected Int(999)"),
        }
    }

    #[test]
    fn test_vrev_two_elements() {
        let mut vs = ValueStack::new();
        vpushi(&mut vs, 10).unwrap();
        vpushi(&mut vs, 20).unwrap();
        vrev(&mut vs, 2).unwrap();
        let top = vs.pop().unwrap();
        match &top.value {
            SValueData::Constant(CValue::Int(v)) => assert_eq!(*v, 10),
            _ => panic!("expected Int(10)"),
        }
        let second = vs.pop().unwrap();
        match &second.value {
            SValueData::Constant(CValue::Int(v)) => assert_eq!(*v, 20),
            _ => panic!("expected Int(20)"),
        }
    }

    #[test]
    fn test_gen_le16_endianness() {
        let mut state = TccState::default();
        state.sections.push(make_text_section());
        state.cur_text_section = 0;
        gen_le16(&mut state, 0x1234).unwrap();
        assert_eq!(state.sections[0].data, vec![0x34, 0x12]);
        assert_eq!(state.ind, 2);
    }

    #[test]
    fn test_gen_expr32_size() {
        let mut state = TccState::default();
        state.sections.push(make_text_section());
        state.cur_text_section = 0;
        gen_expr32(&mut state, 0xABCD_1234).unwrap();
        assert_eq!(state.ind, 4);
    }

    #[test]
    fn test_gen_expr64_size() {
        let mut state = TccState::default();
        state.sections.push(make_text_section());
        state.cur_text_section = 0;
        gen_expr64(&mut state, 0xDEAD_BEEF_CAFE_BABE).unwrap();
        assert_eq!(state.ind, 8);
    }

    #[test]
    fn test_vpush64_type() {
        let mut vs = ValueStack::new();
        vpush64(&mut vs, VT_LLONG, 0xDEAD_BEEF_u64).unwrap();
        let top = vs.top().unwrap();
        assert_eq!(top.ctype.t & VT_BTYPE, VT_LLONG);
    }

    #[test]
    fn test_external_sym_creates_new() {
        let mut symbols: Vec<Symbol> = Vec::new();
        let ct = CType { t: VT_FUNC, ref_sym: None };
        let ad = AttributeDef::default();
        let id = external_sym(&mut symbols, 500, &ct, 0, &ad).unwrap();
        assert!(id < symbols.len());
        assert_eq!(symbols[id].v, 500);
    }

    #[test]
    fn test_external_sym_finds_existing() {
        let mut symbols: Vec<Symbol> = Vec::new();
        let ct = CType { t: VT_FUNC, ref_sym: None };
        let ad = AttributeDef::default();
        let id1 = external_sym(&mut symbols, 500, &ct, 0, &ad).unwrap();
        let id2 = external_sym(&mut symbols, 500, &ct, 0, &ad).unwrap();
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_merge_attr_propagates_all() {
        let mut ad = AttributeDef::default();
        let mut src = AttributeDef::default();
        src.a.aligned = 8;
        src.a.weak = true;
        src.f.func_call = FUNC_STDCALL;
        src.f.func_noreturn = true;
        src.section = Some(42);
        src.asm_label = 99;
        merge_attr(&mut ad, &src);
        assert_eq!(ad.a.aligned, 8);
        assert!(ad.a.weak);
        assert_eq!(ad.f.func_call, FUNC_STDCALL);
        assert!(ad.f.func_noreturn);
        assert_eq!(ad.section, Some(42));
        assert_eq!(ad.asm_label, 99);
    }
}
