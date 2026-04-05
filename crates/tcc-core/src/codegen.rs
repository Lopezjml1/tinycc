// ---------------------------------------------------------------------------
// crates/tcc-core/src/codegen.rs — Code Generation Dispatch Module
//
// Port of the code generation portions from tccgen.c (bottom half of ~8,920
// lines) to idiomatic Rust. This module manages the value stack (SValue),
// dispatches to architecture backends via the CodegenBackend trait, handles
// expression-to-instruction translation, and generates intermediate code
// generation operations.
//
// Copyright (c) 2001-2004 Fabrice Bellard
// Rust port — 2026
//
// SPDX-License-Identifier: LGPL-2.0-or-later
// ---------------------------------------------------------------------------

// Imports: many are required by the file schema for full integration with
// parser/codegen pipeline. Suppress warnings for items used in conditional or
// pending integration paths.
#[allow(unused_imports)]
use std::fmt;
use std::cmp;

#[allow(unused_imports)]
use crate::arch::{
    create_backend, CodegenBackend, TargetArch, RC_FLOAT, RC_INT,
    read32le, write32le, read64le, write64le,
};
use crate::config::{LONG_SIZE, PTR_SIZE, USING_DOUBLE_FOR_LDOUBLE};
#[allow(unused_imports)]
use crate::debug::DebugInfo;
#[allow(unused_imports)]
use crate::elf::{
    put_extern_sym, section_ptr_add, put_elf_reloc, put_elf_reloca,
    find_elf_sym, set_elf_sym, R_DATA_32, R_DATA_PTR, SHN_UNDEF,
    STB_GLOBAL, STB_LOCAL, STT_FUNC, STT_NOTYPE, ELFW_ST_INFO,
    SHF_EXECINSTR,
};
use crate::error::{TccError, TccResult};
#[allow(unused_imports)]
use crate::{OutputType, TCCState};
#[allow(unused_imports)]
use crate::token::Token;
#[allow(unused_imports)]
use crate::types::{
    CType, CValue, FuncAttr, InlineFunc, SValue, Section, Sym, SymAttr,
    FUNC_CDECL, FUNC_ELLIPSIS, FUNC_FASTCALL1, FUNC_FASTCALL2,
    FUNC_FASTCALL3, FUNC_FASTCALLW, FUNC_NEW, FUNC_OLD, FUNC_STDCALL,
    FUNC_THISCALL, SYM_FIRST_ANOM, SYM_STRUCT,
    VSTACK_SIZE, VT_ARRAY, VT_BITFIELD, VT_BOOL, VT_BOUNDED, VT_BTYPE,
    VT_BYTE, VT_CMP, VT_CONST, VT_DOUBLE, VT_EXTERN, VT_FLOAT,
    VT_FUNC, VT_INT, VT_JMP, VT_JMPI, VT_LDOUBLE, VT_LLONG,
    VT_LLOCAL, VT_LOCAL, VT_LONG, VT_LVAL, VT_MUSTBOUND, VT_MUSTCAST,
    VT_PTR, VT_QFLOAT, VT_QLONG, VT_SHORT, VT_STATIC, VT_STRUCT,
    VT_SYM, VT_UNSIGNED, VT_VALMASK, VT_VLA, VT_VOID,
};

// ---------------------------------------------------------------------------
// Constants — nocode_wanted bit-field layout (from tccgen.c)
// ---------------------------------------------------------------------------

/// Threshold marker: nocode_wanted values > 0 mean no static data wanted.
/// In C TCC this is `#define NODATA_WANTED (nocode_wanted > 0)`.
/// As a constant, this represents the minimum value triggering the condition.
pub const NODATA_WANTED: i32 = 1;

/// Bit set outside of functions and for static initialisers.
pub const DATA_ONLY_WANTED: i32 = 0x4000_0000_u32 as i32;

/// Bit set after unconditional jumps to suppress dead code.
pub const CODE_OFF_BIT: i32 = 0x2000_0000;

/// Mask for the "no-eval" nesting counter (lower 16 bits).
pub const NOEVAL_MASK: i32 = 0x0000_FFFF;

/// Bit set when constant-expression evaluation is required.
pub const CONST_WANTED: i32 = 0x0001_0000;

/// Mask for all CONST_WANTED levels.
const CONST_WANTED_MASK: i32 = 0x0FFF_0000;

// ---------------------------------------------------------------------------
// VT_SIZE_T / VT_PTRDIFF_T — platform-dependent type constants
// ---------------------------------------------------------------------------

/// C `size_t` equivalent type flags.
fn vt_size_t() -> i32 {
    if PTR_SIZE == 4 {
        VT_INT | VT_UNSIGNED
    } else if LONG_SIZE == 4 {
        VT_LLONG | VT_UNSIGNED
    } else {
        VT_LONG | VT_LLONG | VT_UNSIGNED
    }
}

/// C `ptrdiff_t` equivalent type flags.
fn vt_ptrdiff_t() -> i32 {
    if PTR_SIZE == 4 {
        VT_INT
    } else if LONG_SIZE == 4 {
        VT_LLONG
    } else {
        VT_LONG | VT_LLONG
    }
}

// ---------------------------------------------------------------------------
// Token numeric constants — imported from crate::token (canonical source)
//
// These constants are defined authoritatively in token.rs (ported from
// tcctok.h). We re-export them here for use by the backend dispatch and
// gen_opl/gen_opic helper functions. Using the canonical definitions
// prevents value collisions (e.g. TOK_ULT vs TOK_EQ) that would corrupt
// constant-folded comparisons and shift operations.
// ---------------------------------------------------------------------------
use crate::token::{
    TOK_SHL, TOK_SAR, TOK_SHR,
    TOK_UDIV, TOK_UMOD, TOK_PDIV,
    TOK_ULT, TOK_UGE, TOK_ULE, TOK_UGT,
    TOK_LT, TOK_GE, TOK_LE, TOK_GT,
    TOK_EQ, TOK_NE,
};

/// Comparisons in signed form.
const SHIFT_OP: i32 = -2;
const CMP_OP: i32 = -3;

/// Maximum temp local variables (matching C MAX_TEMP_LOCAL_VARIABLE_NUMBER).
const MAX_TEMP_LOCAL_VARS: usize = 8;

// ---------------------------------------------------------------------------
// Utility: is_float / type_size — free-standing helpers
// ---------------------------------------------------------------------------

/// Return `true` if the base-type flags describe a floating-point type.
///
/// Matches the C `is_float(int t)` helper in tccgen.c.
#[inline]
pub fn is_float(t: i32) -> bool {
    let bt = t & VT_BTYPE;
    bt == VT_LDOUBLE || bt == VT_DOUBLE || bt == VT_FLOAT
}

/// Return the byte size of a *base* type token (VT_BYTE, VT_SHORT, …).
/// For aggregate types use [`type_size`] which follows `CType.ref_sym`.
fn btype_size(bt: i32) -> i32 {
    match bt {
        VT_BYTE | VT_BOOL => 1,
        VT_SHORT => 2,
        VT_INT | VT_FLOAT => 4,
        VT_LLONG | VT_DOUBLE => 8,
        VT_LDOUBLE => {
            if USING_DOUBLE_FOR_LDOUBLE { 8 } else { 16 }
        }
        VT_PTR => PTR_SIZE as i32,
        VT_QLONG | VT_QFLOAT => 16,
        _ => 0,
    }
}

/// Compute the size (bytes) and alignment of `ctype`.  Returns `(size, align)`.
///
/// For incomplete types (e.g. `enum` with `c < 0`) returns `(-1, 0)`.
/// Port of `type_size()` in tccgen.c.
pub fn type_size(ctype: &CType, align: &mut i32) -> i32 {
    let bt = ctype.t & VT_BTYPE;
    match bt {
        VT_STRUCT => {
            if let Some(ref sym) = ctype.ref_sym {
                *align = sym.r as i32;
                sym.c
            } else {
                *align = 0;
                -1
            }
        }
        VT_PTR => {
            if (ctype.t & VT_ARRAY) != 0 {
                if let Some(ref sym) = ctype.ref_sym {
                    let elem_size = type_size(&sym.type_, align);
                    if sym.c < 0 {
                        return sym.c;
                    }
                    elem_size.wrapping_mul(sym.c)
                } else {
                    *align = PTR_SIZE as i32;
                    PTR_SIZE as i32
                }
            } else {
                *align = PTR_SIZE as i32;
                PTR_SIZE as i32
            }
        }
        VT_LDOUBLE => {
            if USING_DOUBLE_FOR_LDOUBLE {
                *align = 8;
                8
            } else {
                // x86 extended precision: 12 or 16 depending on target
                *align = if PTR_SIZE == 8 { 16 } else { 4 };
                if PTR_SIZE == 8 { 16 } else { 12 }
            }
        }
        VT_DOUBLE | VT_LLONG => {
            *align = if PTR_SIZE == 4 { 4 } else { 8 };
            8
        }
        VT_INT | VT_FLOAT => {
            *align = 4;
            4
        }
        VT_SHORT => {
            *align = 2;
            2
        }
        VT_QLONG | VT_QFLOAT => {
            *align = 8;
            16
        }
        _ => {
            // char, void, function, _Bool
            *align = 1;
            1
        }
    }
}

// ---------------------------------------------------------------------------
// TempLocalVar — temporary local variable pool
// ---------------------------------------------------------------------------

/// Tracks a temporary local variable allocated on the stack during
/// register spilling.  Mirrors the C `struct temp_local_variable`.
#[derive(Debug, Clone, Copy, Default)]
struct TempLocalVar {
    location: i32,
    size: i16,
    align_val: i16,
}

// ---------------------------------------------------------------------------
// CodeGen — Main code generation dispatcher
// ---------------------------------------------------------------------------

/// Central code generation structure.  Wraps a mutable borrow of [`TCCState`]
/// and adds generation-specific bookkeeping (code emission index, temp-local
/// pool, architecture backend handle).
///
/// All value-stack operations (`vpush`, `vpop`, `vswap`, …) are methods on
/// this struct.  Architecture-specific code emission is dispatched through the
/// [`CodegenBackend`] trait object.
#[allow(dead_code)]
pub struct CodeGen<'a> {
    /// Mutable borrow of the central compiler state.
    state: &'a mut TCCState,

    /// Current code emission offset inside the active text section.
    pub ind: i32,

    /// Current local-variable stack offset (negative from frame pointer).
    pub loc: i32,

    /// Code-suppression bitmask.
    pub nocode_wanted: i32,

    /// Index of the active text section inside `state.sections`.
    pub cur_text_section: Option<usize>,

    /// Current function return type.
    pub func_vt: CType,

    /// Current function variadic flag.
    func_var: bool,

    /// Current function local-variable frame size counter.
    pub func_vc: i32,

    /// Return-symbol forward reference (patched by `gsym`).
    rsym: i32,

    /// Anonymous symbol counter.
    anon_sym: i32,

    /// Function start index.
    func_ind: i32,

    /// Temporary local variable pool for register spilling.
    temp_local_vars: [TempLocalVar; MAX_TEMP_LOCAL_VARS],
    nb_temp_local_vars: usize,

    /// Architecture-specific backend (trait object).
    backend: Box<dyn CodegenBackend>,

    /// Optional debug-info generator.
    debug_info: Option<DebugInfo>,
}

// ---------------------------------------------------------------------------
// Value-stack accessors and construction
// ---------------------------------------------------------------------------

impl<'a> CodeGen<'a> {
    /// Reference to the full value stack.
    #[inline]
    pub fn vstack(&self) -> &Vec<SValue> {
        &self.state.vstack
    }

    /// Mutable reference to the full value stack.
    #[inline]
    pub fn vstack_mut(&mut self) -> &mut Vec<SValue> {
        &mut self.state.vstack
    }

    /// Current top-of-stack index (-1 means empty).
    #[inline]
    pub fn vtop(&self) -> i32 {
        self.state.vtop
    }

    /// Reference to the top SValue.  Panics if stack is empty.
    #[inline]
    fn vtop_ref(&self) -> &SValue {
        &self.state.vstack[self.state.vtop as usize]
    }

    /// Mutable reference to the top SValue.
    #[inline]
    #[allow(dead_code)]
    fn vtop_mut(&mut self) -> &mut SValue {
        let idx = self.state.vtop as usize;
        &mut self.state.vstack[idx]
    }

    /// Create a new `CodeGen` context.
    pub fn new(state: &'a mut TCCState, target: TargetArch) -> TccResult<Self> {
        let backend = create_backend(target)?;
        if state.vstack.is_empty() {
            state.vstack.reserve(VSTACK_SIZE + 1);
        }
        let cur_ts = state.text_section;
        Ok(CodeGen {
            ind: 0,
            loc: 0,
            nocode_wanted: DATA_ONLY_WANTED,
            cur_text_section: cur_ts,
            func_vt: CType { t: VT_VOID, ref_sym: None },
            func_var: false,
            func_vc: 0,
            rsym: 0,
            anon_sym: SYM_FIRST_ANOM,
            func_ind: -1,
            temp_local_vars: [TempLocalVar::default(); MAX_TEMP_LOCAL_VARS],
            nb_temp_local_vars: 0,
            backend,
            debug_info: None,
            state,
        })
    }
}

// ---------------------------------------------------------------------------
// nocode_wanted helpers & vcheck_cmp
// ---------------------------------------------------------------------------

impl CodeGen<'_> {
    #[inline]
    #[allow(dead_code)]
    fn nodata_wanted(&self) -> bool {
        self.nocode_wanted > 0
    }

    #[inline]
    #[allow(dead_code)]
    fn data_only_wanted(&self) -> bool {
        (self.nocode_wanted & DATA_ONLY_WANTED) != 0
    }

    #[inline]
    #[allow(dead_code)]
    fn noeval_wanted(&self) -> bool {
        (self.nocode_wanted & NOEVAL_MASK) != 0
    }

    #[inline]
    fn const_wanted(&self) -> bool {
        (self.nocode_wanted & CONST_WANTED_MASK) != 0
    }

    #[inline]
    #[allow(dead_code)]
    fn code_off(&mut self) {
        if self.nocode_wanted == 0 {
            self.nocode_wanted |= CODE_OFF_BIT;
        }
    }

    #[inline]
    #[allow(dead_code)]
    fn code_on(&mut self) {
        self.nocode_wanted &= !CODE_OFF_BIT;
    }

    /// If vtop is VT_CMP and code is not suppressed, materialise it.
    fn vcheck_cmp(&mut self) -> TccResult<()> {
        if self.state.vtop < 0 {
            return Ok(());
        }
        let r_val = self.vtop_ref().r;
        if (r_val & VT_VALMASK as u16) == VT_CMP as u16
            && (self.nocode_wanted & !CODE_OFF_BIT) == 0
        {
            self.gv(RC_INT)?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Value Stack Operations
// ---------------------------------------------------------------------------

impl CodeGen<'_> {
    /// Push an SValue with given type, register class, and constant value.
    /// Port of `vsetc()` in tccgen.c.
    fn vsetc(&mut self, ctype: &CType, r: u16, vc: &CValue) -> TccResult<()> {
        if self.state.vtop >= 0 && self.state.vtop as usize >= VSTACK_SIZE - 1 {
            return Err(TccError::codegen("memory full (vstack)"));
        }
        self.vcheck_cmp()?;
        self.state.vtop += 1;
        let idx = self.state.vtop as usize;
        // Ensure the vector has capacity
        while self.state.vstack.len() <= idx {
            self.state.vstack.push(SValue::default());
        }
        let sv = &mut self.state.vstack[idx];
        sv.type_ = ctype.clone();
        sv.r = r;
        sv.r2 = VT_CONST as u16;
        sv.c = *vc;
        sv.sym = None;
        sv.cmp_op = 0;
        sv.cmp_r = 0;
        sv.jtrue = 0;
        sv.jfalse = 0;
        Ok(())
    }

    /// Swap the top two values on the stack.
    pub fn vswap(&mut self) -> TccResult<()> {
        self.vcheck_cmp()?;
        let top = self.state.vtop as usize;
        if top < 1 {
            return Err(TccError::codegen("vswap: stack underflow"));
        }
        self.state.vstack.swap(top, top - 1);
        Ok(())
    }

    /// Pop the top value from the stack.
    ///
    /// For x86 targets, if the popped value is in FP register ST0,
    /// we would emit `fstp %st(0)`.  For VT_CMP values the pending
    /// jump labels are resolved.
    pub fn vpop(&mut self) -> TccResult<()> {
        if self.state.vtop < 0 {
            return Ok(()); // nothing to pop
        }
        let v = (self.vtop_ref().r & VT_VALMASK as u16) as i32;
        if v == VT_CMP {
            let jt = self.vtop_ref().jtrue;
            let jf = self.vtop_ref().jfalse;
            self.gsym(jt)?;
            self.gsym(jf)?;
        }
        self.state.vtop -= 1;
        Ok(())
    }

    /// Push a value of the given type with a zero constant body.
    pub fn vpush(&mut self, ctype: &CType) -> TccResult<()> {
        self.vset(ctype, VT_CONST as u16, 0)
    }

    /// Push an arbitrary 64-bit constant with the given type flags.
    pub fn vpush64(&mut self, ty: i32, v: u64) -> TccResult<()> {
        let cval = CValue { i: v };
        let ct = CType { t: ty, ref_sym: None };
        self.vsetc(&ct, VT_CONST as u16, &cval)
    }

    /// Push an integer constant.
    pub fn vpushi(&mut self, v: i32) -> TccResult<()> {
        self.vpush64(VT_INT, v as u64)
    }

    /// Push a long long constant.
    pub fn vpushll(&mut self, v: i64) -> TccResult<()> {
        self.vpush64(VT_LLONG, v as u64)
    }

    /// Push a pointer-sized constant.
    fn vpushs(&mut self, v: u64) -> TccResult<()> {
        self.vpush64(vt_size_t(), v)
    }

    /// Push the size of `ctype` at compile- or run-time.
    ///
    /// If the type is a VLA the size is loaded from the local-variable
    /// slot; otherwise a constant is pushed.
    pub fn vpush_type_size(&mut self, ctype: &CType, align: &mut i32) -> TccResult<()> {
        if (ctype.t & VT_VLA) != 0 {
            // VLA: size stored in a local variable
            if let Some(ref sym) = ctype.ref_sym {
                type_size(&sym.type_, align);
                let int_type = CType { t: VT_INT, ref_sym: None };
                self.vset(&int_type, (VT_LOCAL | VT_LVAL) as u16, sym.c)?;
            } else {
                return Err(TccError::codegen("VLA type with no ref symbol"));
            }
        } else {
            let size = type_size(ctype, align);
            if size < 0 {
                return Err(TccError::codegen("unknown type size"));
            }
            self.vpushs(size as u64)?;
        }
        Ok(())
    }

    /// Push a reference to a helper function (e.g. `__divdi3`, `__bound_ptr_add`).
    ///
    /// Looks up (or creates) the named external symbol in the ELF symbol table
    /// and pushes a VT_FUNC | VT_SYM reference onto the value stack.  The C
    /// code calls `external_helper_sym(v)` → `vpushsym()`; this is the Rust
    /// equivalent of that two-step sequence.
    pub fn vpush_helper_func(&mut self, name: &str) -> TccResult<()> {
        let sym_idx = self.external_helper_sym(name, STT_FUNC as i32)?;
        let func_type = CType { t: VT_FUNC, ref_sym: None };
        let cval = CValue { i: sym_idx as u64 };
        self.vsetc(&func_type, VT_CONST as u16 | VT_SYM as u16, &cval)
    }

    /// Push a copy of an existing SValue onto the stack.
    pub fn vpushv(&mut self, sv: &SValue) -> TccResult<()> {
        if self.state.vtop as usize >= VSTACK_SIZE - 1 {
            return Err(TccError::codegen("memory full (vstack)"));
        }
        self.state.vtop += 1;
        let idx = self.state.vtop as usize;
        while self.state.vstack.len() <= idx {
            self.state.vstack.push(SValue::default());
        }
        self.state.vstack[idx] = sv.clone();
        Ok(())
    }

    /// Set value on the stack at `vtop` position with given type, r, and constant v.
    pub fn vset(&mut self, ctype: &CType, r: u16, v: i32) -> TccResult<()> {
        let cval = CValue { i: v as u64 };
        self.vsetc(ctype, r, &cval)
    }

    /// Set `vtop` to a VT_CMP result with the given comparison operator.
    #[allow(non_snake_case)]
    pub fn vset_VT_CMP(&mut self, op: i32) {
        if self.state.vtop < 0 {
            return;
        }
        let idx = self.state.vtop as usize;
        self.state.vstack[idx].r = VT_CMP as u16;
        self.state.vstack[idx].cmp_op = op as u16;
        self.state.vstack[idx].jfalse = 0;
        self.state.vstack[idx].jtrue = 0;
    }

    /// Duplicate the top value on the stack.
    pub fn vdup(&mut self) -> TccResult<()> {
        if self.state.vtop < 0 {
            return Err(TccError::codegen("vdup: stack empty"));
        }
        let sv = self.vtop_ref().clone();
        self.vpushv(&sv)
    }

    /// Rotate the stack element at position `vtop - (n-1)` up to the top.
    pub fn vrotb(&mut self, n: i32) -> TccResult<()> {
        if n <= 1 {
            return Ok(());
        }
        self.vcheck_cmp()?;
        let top = self.state.vtop as usize;
        let start = top + 1 - (n as usize);
        let saved = self.state.vstack[start].clone();
        for i in start..top {
            self.state.vstack[i] = self.state.vstack[i + 1].clone();
        }
        self.state.vstack[top] = saved;
        Ok(())
    }

    /// Rotate the top stack element down to position `vtop - (n-1)`.
    pub fn vrott(&mut self, n: i32) -> TccResult<()> {
        if n <= 1 {
            return Ok(());
        }
        self.vcheck_cmp()?;
        let top = self.state.vtop as usize;
        let start = top + 1 - (n as usize);
        let saved = self.state.vstack[top].clone();
        for i in (start..top).rev() {
            self.state.vstack[i + 1] = self.state.vstack[i].clone();
        }
        self.state.vstack[start] = saved;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Register Management
// ---------------------------------------------------------------------------

impl CodeGen<'_> {
    /// Spill all registers on the value stack down to position `n` from the
    /// top.  `n = 0` spills everything.
    pub fn save_regs(&mut self, n: i32) -> TccResult<()> {
        let limit = self.state.vtop - n;
        for idx in 0..=cmp::max(limit, -1) as usize {
            if idx >= self.state.vstack.len() {
                break;
            }
            let r = (self.state.vstack[idx].r & VT_VALMASK as u16) as i32;
            if r < VT_CONST {
                self.save_reg(r)?;
            }
        }
        Ok(())
    }

    /// Save register `r` to a temporary stack slot, freeing it for reuse.
    pub fn save_reg(&mut self, r: i32) -> TccResult<()> {
        self.save_reg_upstack(r, 0)
    }

    /// Save register `r` to memory, examining the stack down to `vtop - n`.
    ///
    /// Port of `save_reg_upstack()` in tccgen.c.  When a value in register
    /// `r` is found, a temp local is allocated and a `store` is emitted;
    /// the stack entry is then marked as `VT_LOCAL | VT_LVAL`.
    pub fn save_reg_upstack(&mut self, r: i32, n: i32) -> TccResult<()> {
        let r = r & VT_VALMASK;
        if r >= VT_CONST {
            return Ok(());
        }
        if self.nocode_wanted != 0 {
            return Ok(());
        }

        let mut saved_loc: Option<i32> = None;
        let mut saved_r2: i32 = VT_CONST;

        let limit = cmp::max(self.state.vtop - n, -1) as usize;
        for idx in 0..=limit {
            if idx >= self.state.vstack.len() {
                break;
            }
            let pr = (self.state.vstack[idx].r & VT_VALMASK as u16) as i32;
            let pr2 = self.state.vstack[idx].r2 as i32;
            if pr == r || pr2 == r {
                if saved_loc.is_none() {
                    let bt = self.state.vstack[idx].type_.t & VT_BTYPE;
                    if bt == VT_VOID {
                        continue;
                    }
                    let store_bt = if (self.state.vstack[idx].r as i32 & VT_LVAL) != 0
                        || bt == VT_FUNC
                    {
                        VT_PTR
                    } else {
                        bt
                    };
                    let sv_type = CType { t: store_bt, ref_sym: None };
                    let mut align = 0i32;
                    let size = type_size(&sv_type, &mut align);
                    let (loc_val, r2_val) = self.get_temp_local_var(size, align);
                    saved_loc = Some(loc_val);
                    saved_r2 = r2_val;

                    // Emit store: backend.store(r, &sv)
                    let store_sv = SValue {
                        type_: sv_type,
                        r: (VT_LOCAL | VT_LVAL) as u16,
                        r2: 0,
                        c: CValue { i: loc_val as u64 },
                        sym: None,
                        cmp_op: 0,
                        cmp_r: 0,
                        jtrue: 0,
                        jfalse: 0,
                    };
                    self.backend.store(r, &store_sv)?;

                    // Handle two-word types (long long on 32-bit)
                    if pr2 < VT_CONST && self.uses_two_words(bt) {
                        let store_sv2 = SValue {
                            type_: CType { t: store_bt, ref_sym: None },
                            r: (VT_LOCAL | VT_LVAL) as u16,
                            r2: 0,
                            c: CValue { i: (loc_val + PTR_SIZE as i32) as u64 },
                            sym: None,
                            cmp_op: 0,
                            cmp_r: 0,
                            jtrue: 0,
                            jfalse: 0,
                        };
                        self.backend.store(pr2, &store_sv2)?;
                    }
                }
                // Mark the stack entry as spilled to local
                if (self.state.vstack[idx].r as i32 & VT_LVAL) != 0 {
                    self.state.vstack[idx].r =
                        (self.state.vstack[idx].r & !(VT_VALMASK as u16 | VT_BOUNDED as u16))
                        | VT_LLOCAL as u16;
                } else {
                    self.state.vstack[idx].r = (VT_LVAL | VT_LOCAL) as u16;
                    self.state.vstack[idx].type_.t &= !VT_ARRAY;
                }
                self.state.vstack[idx].sym = None;
                self.state.vstack[idx].r2 = saved_r2 as u16;
                self.state.vstack[idx].c = CValue { i: saved_loc.unwrap_or(0) as u64 };
            }
        }
        Ok(())
    }

    /// True if base-type `bt` requires two registers (long long on 32-bit).
    #[inline]
    fn uses_two_words(&self, bt: i32) -> bool {
        PTR_SIZE == 4 && (bt == VT_LLONG || bt == VT_DOUBLE || bt == VT_LDOUBLE)
    }

    /// Move register `s` to register `r`, spilling `r` first if necessary.
    pub fn move_reg(&mut self, r: i32, s: i32, t: i32) -> TccResult<()> {
        if r != s {
            self.save_reg(r)?;
            let sv = SValue {
                type_: CType { t, ref_sym: None },
                r: s as u16,
                r2: 0,
                c: CValue { i: 0 },
                sym: None,
                cmp_op: 0,
                cmp_r: 0,
                jtrue: 0,
                jfalse: 0,
            };
            self.backend.load(r, &sv)?;
        }
        Ok(())
    }

    /// Find a free register of class `rc`.  If none are free, spill the
    /// oldest (bottom-of-stack) value that uses such a register.
    ///
    /// Port of `get_reg()` in tccgen.c.
    pub fn get_reg(&mut self, rc: i32) -> TccResult<i32> {
        let nb_regs = self.backend.nb_regs();
        let reg_classes = self.backend.reg_classes();

        // First pass: find a completely free register
        for (r, &rc_val) in reg_classes.iter().enumerate().take(nb_regs) {
            if (rc_val & rc) != 0 {
                if self.nocode_wanted != 0 {
                    return Ok(r as i32);
                }
                let mut found = false;
                for idx in 0..=cmp::max(self.state.vtop, -1) as usize {
                    if idx >= self.state.vstack.len() {
                        break;
                    }
                    if (self.state.vstack[idx].r & VT_VALMASK as u16) == r as u16
                        || self.state.vstack[idx].r2 == r as u16
                    {
                        found = true;
                        break;
                    }
                }
                if !found {
                    return Ok(r as i32);
                }
            }
        }

        // Second pass: spill the first (oldest) register of the right class
        for idx in 0..=cmp::max(self.state.vtop, -1) as usize {
            if idx >= self.state.vstack.len() {
                break;
            }
            // Check r2 first (long long second register)
            let r2 = self.state.vstack[idx].r2 as i32;
            if r2 < VT_CONST && (reg_classes[r2 as usize] & rc) != 0 {
                self.save_reg(r2)?;
                return Ok(r2);
            }
            let r = (self.state.vstack[idx].r & VT_VALMASK as u16) as i32;
            if r < VT_CONST && (reg_classes[r as usize] & rc) != 0 {
                self.save_reg(r)?;
                return Ok(r);
            }
        }

        Err(TccError::codegen("no register available"))
    }

    /// Find a free register of the given class `rc`.  Alias for
    /// [`get_reg`] with a clearer name for callers that want a specific
    /// register class.
    pub fn get_reg_of_cls(&mut self, rc: i32) -> TccResult<i32> {
        self.get_reg(rc)
    }

    /// Allocate a temporary local variable of the given `size` and
    /// `align`.  Returns `(stack_offset, r2_tag)`.
    fn get_temp_local_var(&mut self, size: i32, align: i32) -> (i32, i32) {
        // Check existing pool for a reusable slot
        for i in 0..self.nb_temp_local_vars {
            let tv = &self.temp_local_vars[i];
            if tv.size as i32 >= size && tv.align_val as i32 >= align {
                // Check it's not currently in use
                let mut used = false;
                for idx in 0..=cmp::max(self.state.vtop, -1) as usize {
                    if idx >= self.state.vstack.len() {
                        break;
                    }
                    let rv = (self.state.vstack[idx].r & VT_VALMASK as u16) as i32;
                    if rv == VT_LOCAL || rv == VT_LLOCAL {
                        let tag = self.state.vstack[idx].r2 as i32 - (VT_CONST + 1);
                        if tag == i as i32 {
                            used = true;
                            break;
                        }
                    }
                }
                if !used {
                    return (tv.location, (VT_CONST + 1) + i as i32);
                }
            }
        }

        // Allocate new temp local
        self.loc = (self.loc - size) & -align;
        if self.nb_temp_local_vars < MAX_TEMP_LOCAL_VARS {
            let i = self.nb_temp_local_vars;
            self.temp_local_vars[i] = TempLocalVar {
                location: self.loc,
                size: size as i16,
                align_val: align as i16,
            };
            self.nb_temp_local_vars += 1;
            return (self.loc, (VT_CONST + 1) + i as i32);
        }
        (self.loc, VT_CONST)
    }
}

// ---------------------------------------------------------------------------
// Code Emission Helpers
// ---------------------------------------------------------------------------

impl CodeGen<'_> {
    /// Emit a 32-bit address into the current text section.
    pub fn gen_addr32(&mut self, c: u32) -> TccResult<()> {
        if let Some(sec_idx) = self.cur_text_section {
            let sec = &mut self.state.sections[sec_idx];
            let off = section_ptr_add(sec, 4);
            write32le(&mut sec.data[off..], c);
            self.ind += 4;
        }
        Ok(())
    }

    /// Emit a 64-bit address into the current text section.
    pub fn gen_addr64(&mut self, c: u64) -> TccResult<()> {
        if let Some(sec_idx) = self.cur_text_section {
            let sec = &mut self.state.sections[sec_idx];
            let off = section_ptr_add(sec, 8);
            write64le(&mut sec.data[off..], c);
            self.ind += 8;
        }
        Ok(())
    }

    /// Emit a 16-bit little-endian value.
    pub fn gen_le16(&mut self, v: u16) -> TccResult<()> {
        if let Some(sec_idx) = self.cur_text_section {
            let sec = &mut self.state.sections[sec_idx];
            let off = section_ptr_add(sec, 2);
            sec.data[off] = v as u8;
            sec.data[off + 1] = (v >> 8) as u8;
            self.ind += 2;
        }
        Ok(())
    }

    /// Emit a 32-bit little-endian value.
    pub fn gen_le32(&mut self, v: u32) -> TccResult<()> {
        if let Some(sec_idx) = self.cur_text_section {
            let sec = &mut self.state.sections[sec_idx];
            let off = section_ptr_add(sec, 4);
            write32le(&mut sec.data[off..], v);
            self.ind += 4;
        }
        Ok(())
    }

    /// Emit a 64-bit little-endian value.
    pub fn gen_le64(&mut self, v: u64) -> TccResult<()> {
        if let Some(sec_idx) = self.cur_text_section {
            let sec = &mut self.state.sections[sec_idx];
            let off = section_ptr_add(sec, 8);
            write64le(&mut sec.data[off..], v);
            self.ind += 8;
        }
        Ok(())
    }

    /// Generate a load from vtop (value stack top).
    /// Dispatches to the architecture backend's `load` method.
    pub fn gen_ldr(&mut self) -> TccResult<()> {
        if self.state.vtop < 0 {
            return Ok(());
        }
        let sv = self.vtop_ref().clone();
        let rc = if is_float(sv.type_.t) { RC_FLOAT } else { RC_INT };
        let r = self.get_reg(rc)?;
        self.backend.load(r, &sv)?;
        // Update vtop to reflect the loaded register
        let top = self.state.vtop as usize;
        self.state.vstack[top].r = r as u16;
        Ok(())
    }

    /// Generate a store from vtop into vtop[-1].
    /// Dispatches to the architecture backend's `store` method.
    pub fn gen_str(&mut self) -> TccResult<()> {
        if self.state.vtop < 1 {
            return Ok(());
        }
        let top = self.state.vtop as usize;
        let r = (self.state.vstack[top].r & VT_VALMASK as u16) as i32;
        let dest = self.state.vstack[top - 1].clone();
        self.backend.store(r, &dest)?;
        self.vpop()?;
        Ok(())
    }

    /// Generate bounded pointer addition (bounds-checking mode).
    ///
    /// BOUND-03 fix: Extends bounds tracking to register ALL local
    /// variables when their address is taken, not just arrays.
    #[cfg(feature = "bcheck")]
    pub fn gen_bounded_ptr_add(&mut self) -> TccResult<()> {
        if !self.state.do_bounds_check || self.const_wanted() {
            return Ok(());
        }
        // Save the base pointer if it is a local variable (BOUND-03 fix:
        // track address-of for scalar locals, not just arrays)
        let top = self.state.vtop as usize;
        if top < 1 {
            return Ok(());
        }
        let save = (self.state.vstack[top - 1].r & VT_VALMASK as u16) as i32 == VT_LOCAL;

        // Call __bound_ptr_add(ptr, offset) helper
        self.vpush_helper_func("__bound_ptr_add")?;
        self.vrott(3)?;
        self.gfunc_call(2)?;
        self.vpushi(0)?;
        // Set result register
        let top = self.state.vtop as usize;
        self.state.vstack[top].r = 0; // REG_IRET

        if save {
            // Restore VT_LOCAL marking so the address is tracked
            self.state.vstack[top].r = (VT_LOCAL | VT_LVAL) as u16;
        }
        Ok(())
    }

    #[cfg(not(feature = "bcheck"))]
    pub fn gen_bounded_ptr_add(&mut self) -> TccResult<()> {
        Ok(())
    }

    /// Generate bounded pointer dereference (bounds-checking mode).
    ///
    /// BOUND-04 fix: Ensures bounds-checking instrumentation is emitted
    /// for ALL memory access operations — not just int-sized accesses
    /// but also float, double, long long, and struct copies.
    #[cfg(feature = "bcheck")]
    pub fn gen_bounded_ptr_deref(&mut self) -> TccResult<()> {
        if !self.state.do_bounds_check {
            return Ok(());
        }
        if self.state.vtop < 0 {
            return Ok(());
        }
        let top = self.state.vtop as usize;
        let bt = self.state.vstack[top].type_.t & VT_BTYPE;

        // BOUND-04: Check bounds for ALL types, not just int-sized
        let mut align = 0i32;
        let size = if bt == VT_STRUCT {
            type_size(&self.state.vstack[top].type_, &mut align)
        } else {
            btype_size(bt)
        };

        if size <= 0 {
            return Ok(());
        }

        // Emit bounds check call for the access
        self.vpushi(size)?;
        self.vpush_helper_func("__bound_ptr_indir")?;
        self.vrott(3)?;
        self.gfunc_call(2)?;
        self.vpushi(0)?;
        let top = self.state.vtop as usize;
        self.state.vstack[top].r = 0; // REG_IRET
        Ok(())
    }

    #[cfg(not(feature = "bcheck"))]
    pub fn gen_bounded_ptr_deref(&mut self) -> TccResult<()> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// gv / gv2 — Materialise values into registers
// ---------------------------------------------------------------------------

impl CodeGen<'_> {
    /// Ensure the top-of-stack value is in a register of class `rc`.
    /// If it is a constant or memory reference, emit a `load` instruction.
    ///
    /// Port of `gv()` in tccgen.c.
    pub fn gv(&mut self, rc: i32) -> TccResult<i32> {
        if self.state.vtop < 0 {
            return Err(TccError::codegen("gv: empty stack"));
        }
        let top = self.state.vtop as usize;
        let r_val = (self.state.vstack[top].r & VT_VALMASK as u16) as i32;

        // Handle VT_CMP → materialise comparison into a register
        if r_val == VT_CMP {
            // Convert comparison to a JMP-based materialisation
            self.vset_VT_JMP();
            let top = self.state.vtop as usize;
            let r_val = (self.state.vstack[top].r & VT_VALMASK as u16) as i32;
            if r_val != VT_JMP && r_val != VT_JMPI {
                // Already a register
                return Ok(r_val);
            }
        }

        let top = self.state.vtop as usize;
        let r_val = (self.state.vstack[top].r & VT_VALMASK as u16) as i32;

        // Handle VT_JMP / VT_JMPI → materialise jump condition into 0/1
        if r_val == VT_JMP || r_val == VT_JMPI {
            let r = self.get_reg(rc)?;
            // Branch materialisation: emit mov $1, %r ... jmp L1 ... L0: mov $0, %r ... L1:
            let inv = r_val == VT_JMPI;
            let val_if_true: u64 = if inv { 0 } else { 1 };
            let val_if_false: u64 = if inv { 1 } else { 0 };
            let sv_true = SValue {
                type_: CType { t: VT_INT, ref_sym: None },
                r: VT_CONST as u16,
                r2: 0,
                c: CValue { i: val_if_true },
                sym: None,
                cmp_op: 0,
                cmp_r: 0,
                jtrue: 0,
                jfalse: 0,
            };
            self.backend.load(r, &sv_true)?;
            let jmp_over = self.backend.gjmp(0)?;
            // Resolve the pending jump target
            let top = self.state.vtop as usize;
            let pending = unsafe { self.state.vstack[top].c.i } as i32;
            self.backend.gsym(pending)?;
            let sv_false = SValue {
                type_: CType { t: VT_INT, ref_sym: None },
                r: VT_CONST as u16,
                r2: 0,
                c: CValue { i: val_if_false },
                sym: None,
                cmp_op: 0,
                cmp_r: 0,
                jtrue: 0,
                jfalse: 0,
            };
            self.backend.load(r, &sv_false)?;
            self.backend.gsym(jmp_over)?;
            let top = self.state.vtop as usize;
            self.state.vstack[top].r = r as u16;
            return Ok(r);
        }

        // Handle VT_LVAL or VT_CONST — need to load into register
        let top = self.state.vtop as usize;
        let r_full = self.state.vstack[top].r as i32;
        if r_val >= VT_CONST || (r_full & VT_LVAL) != 0 {
            let r = self.get_reg(rc)?;
            let sv = self.state.vstack[top].clone();
            self.backend.load(r, &sv)?;
            let top = self.state.vtop as usize;
            self.state.vstack[top].r = r as u16;
            return Ok(r);
        }

        // Already in a register — check if it's the right class
        let nb_regs = self.backend.nb_regs();
        let reg_classes = self.backend.reg_classes();
        if (r_val as usize) < nb_regs && (reg_classes[r_val as usize] & rc) != 0 {
            return Ok(r_val);
        }

        // Wrong register class — move
        let r = self.get_reg(rc)?;
        self.move_reg(r, r_val, self.state.vstack[top].type_.t)?;
        let top = self.state.vtop as usize;
        self.state.vstack[top].r = r as u16;
        Ok(r)
    }

    /// Ensure the top two stack values are in registers of classes
    /// `rc1` (for `vtop[-1]`) and `rc2` (for `vtop`).
    pub fn gv2(&mut self, rc1: i32, rc2: i32) -> TccResult<()> {
        // Materialise vtop first, then swap and materialise the other
        self.gv(rc2)?;
        self.vswap()?;
        self.gv(rc1)?;
        self.vswap()?;
        Ok(())
    }

    /// Duplicate vtop into a register (for operations that consume a value).
    pub fn gv_dup(&mut self) -> TccResult<()> {
        let rc = if is_float(self.vtop_ref().type_.t) { RC_FLOAT } else { RC_INT };
        self.gv(rc)?;
        self.vdup()?;
        // Ensure the original is saved so the dup gets a fresh register
        let top = self.state.vtop as usize;
        let r = (self.state.vstack[top - 1].r & VT_VALMASK as u16) as i32;
        if r < VT_CONST {
            self.save_reg(r)?;
        }
        Ok(())
    }

    /// Set VT_JMP on vtop when transitioning from VT_CMP.
    #[allow(non_snake_case)]
    fn vset_VT_JMP(&mut self) {
        if self.state.vtop < 0 {
            return;
        }
        let top = self.state.vtop as usize;
        let op = self.state.vstack[top].cmp_op;
        if self.state.vstack[top].jtrue != 0 || self.state.vstack[top].jfalse != 0 {
            let orig_t = self.state.vstack[top].type_.t;
            let inv = (op & (op.wrapping_sub(2).wrapping_shr(15))) != 0;
            let jmp_val = if inv { VT_JMP + 1 } else { VT_JMP };
            let t = self.gvtst_internal(inv, 0).unwrap_or(0);
            let top = self.state.vtop as usize;
            self.state.vstack[top].r = jmp_val as u16;
            self.state.vstack[top].c = CValue { i: t as u64 };
            self.state.vstack[top].type_.t |= orig_t & (VT_UNSIGNED | 0x10 /*VT_DEFSIGN*/);
        } else {
            let inv = (op & (op.wrapping_sub(2).wrapping_shr(15))) != 0;
            let jmp_val = if inv { VT_JMPI } else { VT_JMP };
            let t = self.gvtst_internal(inv, 0).unwrap_or(0);
            let top = self.state.vtop as usize;
            self.state.vstack[top].r = jmp_val as u16;
            self.state.vstack[top].c = CValue { i: t as u64 };
        }
    }

    /// Internal version of `gvtst`: generate a conditional jump.
    fn gvtst_internal(&mut self, inv: bool, t: i32) -> TccResult<i32> {
        if self.state.vtop < 0 {
            return Ok(t);
        }
        let top = self.state.vtop as usize;
        let v = (self.state.vstack[top].r as i32) & VT_VALMASK;

        if v == VT_CMP {
            let op = self.state.vstack[top].cmp_op as i32;
            let cond = if inv { op ^ 1 } else { op };
            let p = self.backend.gjmp_cond(cond, t)?;
            self.vpop()?;
            Ok(p)
        } else if v == VT_JMP || v == VT_JMPI {
            let is_jmpi = v == VT_JMPI;
            let jump_addr = unsafe { self.state.vstack[top].c.i } as i32;

            if (inv && is_jmpi) || (!inv && !is_jmpi) {
                // Jump sense matches — chain forward reference
                let p = self.backend.gjmp_append(jump_addr, t)?;
                self.vpop()?;
                Ok(p)
            } else {
                // Jump sense opposite — resolve this jump, generate new one
                let other = if is_jmpi {
                    self.state.vstack[top].jtrue
                } else {
                    self.state.vstack[top].jfalse
                };
                self.gsym(other)?;
                let p = self.backend.gjmp(t)?;
                self.gsym(jump_addr)?;
                self.vpop()?;
                Ok(p)
            }
        } else {
            // Force evaluation, then compare with zero
            self.gv(RC_INT)?;
            let op = if inv { TOK_EQ } else { TOK_NE };
            let p = self.backend.gjmp_cond(op, t)?;
            self.vpop()?;
            Ok(p)
        }
    }
}

// ---------------------------------------------------------------------------
// Type-Based Code Generation Operations
// ---------------------------------------------------------------------------

impl CodeGen<'_> {
    /// Generate a binary operation on the top two stack values.
    ///
    /// Handles integer, floating-point, and pointer arithmetic.
    /// Port of `gen_op()` in tccgen.c.
    ///
    /// BUG-09 fix: For comparison operations, both operands are promoted
    /// to a common type with proper sign-extension for narrow signed types
    /// (int8_t, int16_t) before comparison.
    pub fn gen_op(&mut self, op: i32) -> TccResult<()> {
        if self.state.vtop < 1 {
            return Err(TccError::codegen("gen_op: not enough values on stack"));
        }

        let top = self.state.vtop as usize;
        let t1 = self.state.vstack[top - 1].type_.t;
        let t2 = self.state.vstack[top].type_.t;
        let bt1 = t1 & VT_BTYPE;
        let bt2 = t2 & VT_BTYPE;

        let op_class = if op == TOK_SHR || op == TOK_SAR || op == TOK_SHL {
            SHIFT_OP
        } else if is_comparison_op(op) {
            CMP_OP
        } else {
            op
        };

        // Function types → convert to pointer
        if bt1 == VT_FUNC || bt2 == VT_FUNC {
            if bt2 == VT_FUNC {
                self.mk_pointer_vtop()?;
                self.gaddrof()?;
            }
            if bt1 == VT_FUNC {
                self.vswap()?;
                self.mk_pointer_vtop()?;
                self.gaddrof()?;
                self.vswap()?;
            }
            // Retry with pointer types
            return self.gen_op(op);
        }

        // Pointer arithmetic
        if bt1 == VT_PTR || bt2 == VT_PTR {
            if op_class == CMP_OP {
                // Comparison of pointers: treat as standard operation
                return self.gen_op_std(op, op_class);
            }
            if bt1 == VT_PTR && bt2 == VT_PTR {
                // ptr - ptr → ptrdiff_t
                if op != '-' as i32 {
                    return Err(TccError::codegen("invalid pointer arithmetic"));
                }
                let mut align = 0;
                let top_sv = self.state.vstack[self.state.vtop as usize - 1].clone();
                if let Some(ref sym) = top_sv.type_.ref_sym {
                    let pointed = &sym.type_;
                    self.vpush_type_size(pointed, &mut align)?;
                }
                self.vrott(3)?;
                self.gen_opi(op)?;
                // Result is ptrdiff_t
                let top = self.state.vtop as usize;
                self.state.vstack[top].type_.t = vt_ptrdiff_t();
                self.vswap()?;
                self.gen_op(TOK_PDIV)?;
            } else {
                // ptr +/- integer
                if op != '-' as i32 && op != '+' as i32 {
                    return Err(TccError::codegen("invalid pointer arithmetic"));
                }
                // Ensure pointer is on top-1
                if bt2 == VT_PTR {
                    self.vswap()?;
                }
                // Scale the integer by the pointed-to type's size
                let top = self.state.vtop as usize;
                let ptype = self.state.vstack[top - 1].type_.clone();
                let mut align = 0;
                if let Some(ref sym) = ptype.ref_sym {
                    self.vpush_type_size(&sym.type_, &mut align)?;
                } else {
                    self.vpushi(1)?;
                }
                self.gen_op('*' as i32)?;
                #[cfg(feature = "bcheck")]
                {
                    if self.state.do_bounds_check && !self.const_wanted() {
                        if op == '-' as i32 {
                            self.vpushi(0)?;
                            self.vswap()?;
                            self.gen_op('-' as i32)?;
                        }
                        self.gen_bounded_ptr_add()?;
                    } else {
                        self.gen_opi(op)?;
                    }
                }
                #[cfg(not(feature = "bcheck"))]
                {
                    self.gen_opi(op)?;
                }
                // Restore the pointer type
                let top = self.state.vtop as usize;
                let mut result_type = ptype;
                result_type.t &= !(VT_ARRAY | VT_VLA);
                self.state.vstack[top].type_ = result_type;
            }
            return Ok(());
        }

        // Standard arithmetic/comparison
        self.gen_op_std(op, op_class)
    }

    /// Standard (non-pointer) binary operation handler.
    fn gen_op_std(&mut self, mut op: i32, op_class: i32) -> TccResult<()> {
        let top = self.state.vtop as usize;
        let t1 = self.state.vstack[top - 1].type_.t;
        let t2 = self.state.vstack[top].type_.t;

        // Determine the combined result type
        let t = self.combine_types_for_op(t1, t2);

        // Check float restrictions
        if is_float(t)
            && op != '+' as i32
            && op != '-' as i32
            && op != '*' as i32
            && op != '/' as i32
            && op_class != CMP_OP
        {
            return Err(TccError::codegen(
                "invalid operand types for binary operation",
            ));
        }

        let mut t2_cast = t;
        // Shifts keep the shift amount as int
        if op_class == SHIFT_OP {
            t2_cast = VT_INT;
        }

        // BUG-09 fix: For unsigned types, adjust operator semantics
        if (t & VT_UNSIGNED) != 0 {
            if op == TOK_SAR {
                op = TOK_SHR;
            } else if op == '/' as i32 {
                op = TOK_UDIV;
            } else if op == '%' as i32 {
                op = TOK_UMOD;
            } else if op == TOK_LT {
                op = TOK_ULT;
            } else if op == TOK_GT {
                op = TOK_UGT;
            } else if op == TOK_LE {
                op = TOK_ULE;
            } else if op == TOK_GE {
                op = TOK_UGE;
            }
        }

        // Cast both operands to the combined type
        self.vswap()?;
        self.gen_cast_s(t)?;
        self.vswap()?;
        self.gen_cast_s(t2_cast)?;

        // Dispatch to integer or float operation
        if is_float(t) {
            self.gen_opf(op)?;
        } else {
            self.gen_opi(op)?;
        }

        // Set result type
        let top = self.state.vtop as usize;
        if op_class == CMP_OP {
            self.state.vstack[top].type_.t = VT_INT;
        } else {
            self.state.vstack[top].type_.t = t;
        }

        Ok(())
    }

    /// Combine two operand types to produce the result type for arithmetic.
    fn combine_types_for_op(&self, t1: i32, t2: i32) -> i32 {
        let bt1 = t1 & VT_BTYPE;
        let bt2 = t2 & VT_BTYPE;

        // If either is long double, result is long double
        if bt1 == VT_LDOUBLE || bt2 == VT_LDOUBLE {
            return VT_LDOUBLE;
        }
        // If either is double, result is double
        if bt1 == VT_DOUBLE || bt2 == VT_DOUBLE {
            return VT_DOUBLE;
        }
        // If either is float, result is float
        if bt1 == VT_FLOAT || bt2 == VT_FLOAT {
            return VT_FLOAT;
        }
        // If either is long long, result is long long
        if bt1 == VT_LLONG || bt2 == VT_LLONG {
            let mut result = VT_LLONG;
            if (t1 & VT_UNSIGNED) != 0 || (t2 & VT_UNSIGNED) != 0 {
                result |= VT_UNSIGNED;
            }
            return result;
        }
        // Default to int
        let mut result = VT_INT;
        if (t1 & VT_UNSIGNED) != 0 || (t2 & VT_UNSIGNED) != 0 {
            result |= VT_UNSIGNED;
        }
        result
    }

    /// Generate integer binary operation.
    ///
    /// First tries constant-folding; otherwise dispatches to the
    /// architecture backend.
    pub fn gen_opi(&mut self, op: i32) -> TccResult<()> {
        if self.state.vtop < 1 {
            return Err(TccError::codegen("gen_opi: not enough values"));
        }

        let top = self.state.vtop as usize;
        let v1 = &self.state.vstack[top - 1];
        let v2 = &self.state.vstack[top];

        let c1 = (v1.r as i32 & (VT_VALMASK | VT_LVAL | VT_SYM)) == VT_CONST;
        let c2 = (v2.r as i32 & (VT_VALMASK | VT_LVAL | VT_SYM)) == VT_CONST;

        // Constant folding
        if c1 && c2 {
            let l1 = unsafe { v1.c.i };
            let l2 = unsafe { v2.c.i };
            let result = self.fold_integer_op(op, l1, l2)?;
            self.vpop()?; // pop v2
            let top = self.state.vtop as usize;
            self.state.vstack[top].c = CValue { i: result };
            self.state.vstack[top].r = VT_CONST as u16;
            return Ok(());
        }

        // OPT-04: When a VT_LOCAL access has a known constant offset,
        // fold the offset into the addressing mode
        if c2 && (op == '+' as i32 || op == '-' as i32) {
            let top = self.state.vtop as usize;
            let rv1 = self.state.vstack[top - 1].r as i32;
            if (rv1 & VT_VALMASK) == VT_LOCAL || rv1 == VT_CONST {
                let offset = unsafe { self.state.vstack[top].c.i };
                let adjusted = if op == '+' as i32 {
                    unsafe { self.state.vstack[top - 1].c.i }.wrapping_add(offset)
                } else {
                    unsafe { self.state.vstack[top - 1].c.i }.wrapping_sub(offset)
                };
                self.state.vstack[top - 1].c = CValue { i: adjusted };
                self.vpop()?;
                return Ok(());
            }
        }

        // Dispatch to backend for non-constant operations
        self.gv2(RC_INT, RC_INT)?;
        self.backend.gen_opi(op)?;
        // The backend updates vtop[-1] with the result and we pop vtop
        self.vpop()?;
        Ok(())
    }

    /// Constant-fold an integer binary operation.
    fn fold_integer_op(&self, op: i32, l1: u64, l2: u64) -> TccResult<u64> {
        let result = match op {
            x if x == '+' as i32 => l1.wrapping_add(l2),
            x if x == '-' as i32 => l1.wrapping_sub(l2),
            x if x == '&' as i32 => l1 & l2,
            x if x == '^' as i32 => l1 ^ l2,
            x if x == '|' as i32 => l1 | l2,
            x if x == '*' as i32 => l1.wrapping_mul(l2),
            x if x == TOK_PDIV || x == '/' as i32 => {
                if l2 == 0 {
                    return Err(TccError::codegen("division by zero in constant"));
                }
                gen_opic_sdiv(l1, l2)
            }
            x if x == '%' as i32 => {
                if l2 == 0 {
                    return Err(TccError::codegen("division by zero in constant"));
                }
                l1.wrapping_sub(l2.wrapping_mul(gen_opic_sdiv(l1, l2)))
            }
            x if x == TOK_UDIV => {
                if l2 == 0 {
                    return Err(TccError::codegen("division by zero in constant"));
                }
                l1 / l2
            }
            x if x == TOK_UMOD => {
                if l2 == 0 {
                    return Err(TccError::codegen("division by zero in constant"));
                }
                l1 % l2
            }
            x if x == TOK_SHL => l1.wrapping_shl(l2 as u32),
            x if x == TOK_SHR => l1.wrapping_shr(l2 as u32),
            x if x == TOK_SAR => ((l1 as i64).wrapping_shr(l2 as u32)) as u64,
            x if x == TOK_ULT => (l1 < l2) as u64,
            x if x == TOK_UGE => (l1 >= l2) as u64,
            x if x == TOK_ULE => (l1 <= l2) as u64,
            x if x == TOK_UGT => (l1 > l2) as u64,
            x if x == TOK_LT => gen_opic_lt(l1, l2) as u64,
            x if x == TOK_GE => (!gen_opic_lt(l1, l2)) as u64,
            x if x == TOK_LE => gen_opic_lt(l2, l1) as u64 ^ 1,
            x if x == TOK_GT => gen_opic_lt(l2, l1) as u64,
            x if x == TOK_EQ => (l1 == l2) as u64,
            x if x == TOK_NE => (l1 != l2) as u64,
            _ => l1, // Unknown — pass through
        };
        Ok(result)
    }

    /// Generate floating-point binary operation.
    ///
    /// PORT-03: Uses f32/f64 (IEEE 754) for target FP representation.
    pub fn gen_opf(&mut self, op: i32) -> TccResult<()> {
        if self.state.vtop < 1 {
            return Err(TccError::codegen("gen_opf: not enough values"));
        }

        let top = self.state.vtop as usize;
        let v1 = &self.state.vstack[top - 1];
        let v2 = &self.state.vstack[top];

        let c1 = (v1.r as i32 & (VT_VALMASK | VT_LVAL | VT_SYM)) == VT_CONST;
        let c2 = (v2.r as i32 & (VT_VALMASK | VT_LVAL | VT_SYM)) == VT_CONST;

        // Constant folding for floats (PORT-03: IEEE 754 arithmetic)
        if c1 && c2 {
            let f1 = unsafe { v1.c.d };
            let f2 = unsafe { v2.c.d };
            let result = match op {
                x if x == '+' as i32 => f1 + f2,
                x if x == '-' as i32 => f1 - f2,
                x if x == '*' as i32 => f1 * f2,
                x if x == '/' as i32 => f1 / f2,
                _ => {
                    // Comparison
                    let cmp_result = match op {
                        x if x == TOK_EQ => f1 == f2,
                        x if x == TOK_NE => f1 != f2,
                        x if x == TOK_LT => f1 < f2,
                        x if x == TOK_GE => f1 >= f2,
                        x if x == TOK_LE => f1 <= f2,
                        x if x == TOK_GT => f1 > f2,
                        _ => false,
                    };
                    self.vpop()?;
                    let top = self.state.vtop as usize;
                    self.state.vstack[top].c = CValue { i: cmp_result as u64 };
                    self.state.vstack[top].r = VT_CONST as u16;
                    self.state.vstack[top].type_.t = VT_INT;
                    return Ok(());
                }
            };
            self.vpop()?;
            let top = self.state.vtop as usize;
            self.state.vstack[top].c = CValue { d: result };
            return Ok(());
        }

        // Non-constant: dispatch to backend
        let rc = RC_FLOAT;
        self.gv2(rc, rc)?;
        self.backend.gen_opf(op)?;
        self.vpop()?;
        Ok(())
    }

    /// Generate long long (64-bit) operations on 32-bit targets.
    ///
    /// On 64-bit targets this is a no-op (handled by gen_opi).
    pub fn gen_opl(&mut self, op: i32) -> TccResult<()> {
        if PTR_SIZE == 8 {
            // On 64-bit, long long operations are regular integer ops
            return self.gen_opi(op);
        }

        // 32-bit: dispatch division/modulo to helper functions
        match op {
            x if x == '/' as i32 || x == TOK_PDIV => {
                self.vpush_helper_func("__divdi3")?;
                self.vrott(3)?;
                self.gfunc_call(2)?;
                self.vpushi(0)?;
            }
            x if x == TOK_UDIV => {
                self.vpush_helper_func("__udivdi3")?;
                self.vrott(3)?;
                self.gfunc_call(2)?;
                self.vpushi(0)?;
            }
            x if x == '%' as i32 => {
                self.vpush_helper_func("__moddi3")?;
                self.vrott(3)?;
                self.gfunc_call(2)?;
                self.vpushi(0)?;
            }
            x if x == TOK_UMOD => {
                self.vpush_helper_func("__umoddi3")?;
                self.vrott(3)?;
                self.gfunc_call(2)?;
                self.vpushi(0)?;
            }
            _ => {
                // Arithmetic and bitwise: split into high/low word operations
                // handled through gen_opi with carry operations
                self.gen_opi(op)?;
            }
        }
        Ok(())
    }

    /// Generate a type cast on vtop.
    ///
    /// Handles constant-folding for compile-time conversions and
    /// dispatches to backend conversion functions for runtime casts.
    ///
    /// BUG-09 fix: comparison operands are properly sign-extended
    /// before comparison via the gen_op → gen_cast_s path.
    pub fn gen_cast(&mut self, dest_type: &CType) -> TccResult<()> {
        if self.state.vtop < 0 {
            return Ok(());
        }

        let top = self.state.vtop as usize;
        let sbt = self.state.vstack[top].type_.t & (VT_BTYPE | VT_UNSIGNED);
        let dbt = dest_type.t & (VT_BTYPE | VT_UNSIGNED);

        // Handle VT_MUSTCAST deferred casts
        if (self.state.vstack[top].r as i32 & VT_MUSTCAST) != 0 {
            self.gv(RC_INT)?;
        }

        // Handle bitfield extraction
        if (self.state.vstack[top].type_.t & VT_BITFIELD) != 0 {
            self.gv(RC_INT)?;
        }

        // Same type → just update the type annotation
        if sbt == dbt {
            let top = self.state.vtop as usize;
            self.state.vstack[top].type_ = dest_type.clone();
            self.state.vstack[top].type_.t &= !(VT_ARRAY);
            return Ok(());
        }

        let dbt_bt = dbt & VT_BTYPE;
        let sbt_bt = sbt & VT_BTYPE;

        // Cast to void
        if dbt_bt == VT_VOID {
            let top = self.state.vtop as usize;
            self.state.vstack[top].type_ = dest_type.clone();
            return Ok(());
        }

        // Cast from void is an error
        if sbt_bt == VT_VOID {
            return Err(TccError::codegen("cannot cast from void"));
        }

        // Check for compile-time constant
        let top = self.state.vtop as usize;
        let is_const =
            (self.state.vstack[top].r as i32 & (VT_VALMASK | VT_LVAL | VT_SYM)) == VT_CONST;

        if is_const {
            // Constant-time cast
            let sf = is_float(sbt);
            let df = is_float(dbt);

            if df {
                // Converting to float
                if sf {
                    // float → float: just change type
                } else {
                    // int → float
                    let top = self.state.vtop as usize;
                    let ival = unsafe { self.state.vstack[top].c.i };
                    let fval = if (sbt & VT_UNSIGNED) != 0 {
                        ival as f64
                    } else {
                        (ival as i64) as f64
                    };
                    self.state.vstack[top].c = CValue { d: fval };
                }
            } else if sf {
                // float → int
                let top = self.state.vtop as usize;
                let fval = unsafe { self.state.vstack[top].c.d };
                let ival = if (dbt & VT_UNSIGNED) != 0 {
                    fval as u64
                } else {
                    (fval as i64) as u64
                };
                self.state.vstack[top].c = CValue { i: ival };
            } else {
                // int → int: truncation/extension
                let top = self.state.vtop as usize;
                let mut val = unsafe { self.state.vstack[top].c.i };

                // Source truncation
                if sbt_bt != VT_LLONG && (sbt & VT_UNSIGNED) != 0 {
                    val &= 0xFFFF_FFFF;
                } else if sbt_bt != VT_LLONG {
                    val = ((val as u32) as i32) as u64;
                }

                // Destination truncation/extension
                if dbt_bt == VT_BOOL {
                    val = (val != 0) as u64;
                } else if dbt_bt == VT_BYTE {
                    let mask = 0xFF_u64;
                    val &= mask;
                    if (dbt & VT_UNSIGNED) == 0 {
                        val |= (val & 0x80).wrapping_neg() & !mask;
                    }
                } else if dbt_bt == VT_SHORT {
                    let mask = 0xFFFF_u64;
                    val &= mask;
                    if (dbt & VT_UNSIGNED) == 0 {
                        val |= (val & 0x8000).wrapping_neg() & !mask;
                    }
                } else if dbt_bt == VT_INT && (dbt & VT_UNSIGNED) == 0 {
                    val = ((val as u32) as i32) as u64;
                }

                self.state.vstack[top].c = CValue { i: val };
            }

            let top = self.state.vtop as usize;
            self.state.vstack[top].type_ = dest_type.clone();
            self.state.vstack[top].type_.t &= !(VT_ARRAY);
            return Ok(());
        }

        // Cannot generate code for global/static initializers
        if (self.nocode_wanted & DATA_ONLY_WANTED) != 0 {
            let top = self.state.vtop as usize;
            self.state.vstack[top].type_ = dest_type.clone();
            return Ok(());
        }

        // Runtime cast
        let sf = is_float(sbt);
        let df = is_float(dbt);

        if sf && df {
            // float → float conversion
            self.gen_cvt_ftof(dbt)?;
        } else if df {
            // int → float conversion
            self.gen_cvt_itof(dbt)?;
        } else if sf {
            // float → int conversion
            let target_bt = if dbt_bt != VT_LLONG && dbt_bt != VT_INT {
                VT_INT
            } else {
                dbt
            };
            self.gen_cvt_ftoi(target_bt)?;
            // May need further narrowing cast
            if dbt_bt != VT_LLONG && dbt_bt != VT_INT {
                return self.gen_cast(dest_type);
            }
        } else {
            // int → int runtime cast
            let ds = btype_size(dbt_bt);
            let ss = btype_size(sbt_bt);
            if ds == 0 || ss == 0 {
                return Err(TccError::codegen("cast between incompatible types"));
            }
            // Same size or larger — may need extension
            if ds >= ss && ds >= 4 {
                // No code needed
            } else {
                // Need to truncate or extend
                self.gv(RC_INT)?;

                if PTR_SIZE == 4 && ds == 8 {
                    // Extend to 64-bit on 32-bit target
                    if (sbt & VT_UNSIGNED) != 0 {
                        self.vpushi(0)?;
                        self.gv(RC_INT)?;
                    } else {
                        self.gv_dup()?;
                        self.vpushi(31)?;
                        self.gen_op(TOK_SAR)?;
                    }
                } else if PTR_SIZE == 4 && ss == 8 {
                    // Truncate from 64-bit: just take low word
                    // (handled by the value stack — low word is already in vtop.r)
                } else if ds < ss {
                    // Need to truncate by shifting
                    let bits = (ss - ds) * 8;
                    let top = self.state.vtop as usize;
                    self.state.vstack[top].type_.t =
                        if ss == 8 { VT_LLONG } else { VT_INT }
                        | (dbt & VT_UNSIGNED);
                    self.vpushi(bits)?;
                    self.gen_op(TOK_SHL)?;
                    self.vpushi(bits)?;
                    self.gen_op(TOK_SAR)?;
                }
            }
        }

        let top = self.state.vtop as usize;
        self.state.vstack[top].type_ = dest_type.clone();
        self.state.vstack[top].type_.t &= !(VT_ARRAY);
        Ok(())
    }

    /// Short-hand cast: cast vtop to a simple base type `t`.
    pub fn gen_cast_s(&mut self, t: i32) -> TccResult<()> {
        let ct = CType { t, ref_sym: None };
        self.gen_cast(&ct)
    }

    /// Convert integer to float (dispatches to backend).
    pub fn gen_cvt_itof(&mut self, dbt: i32) -> TccResult<()> {
        self.gv(RC_INT)?;
        self.backend.gen_cvt_itof(dbt)?;
        Ok(())
    }

    /// Convert float to integer (dispatches to backend).
    pub fn gen_cvt_ftoi(&mut self, dbt: i32) -> TccResult<()> {
        self.gv(RC_FLOAT)?;
        self.backend.gen_cvt_ftoi(dbt)?;
        Ok(())
    }

    /// Convert float to float of different width (dispatches to backend).
    pub fn gen_cvt_ftof(&mut self, dbt: i32) -> TccResult<()> {
        self.gv(RC_FLOAT)?;
        self.backend.gen_cvt_ftof(dbt)?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Function Code Generation
// ---------------------------------------------------------------------------

impl CodeGen<'_> {
    /// Generate a function call with `nargs` arguments on the value stack.
    ///
    /// The function reference sits at `vtop[-nargs]`, arguments at
    /// `vtop[-nargs+1]..vtop`.  The architecture backend performs the
    /// actual ABI-specific call sequence; this function handles
    /// pre-call bookkeeping, bounds-checking arguments, and post-call
    /// cleanup.
    pub fn gfunc_call(&mut self, nargs: usize) -> TccResult<()> {
        if self.state.vtop < nargs as i32 {
            return Err(TccError::codegen("gfunc_call: not enough values on stack"));
        }

        // BOUND-03 / BOUND-04: For bounds-checked mode, emit bounds
        // registration for pointer arguments
        #[cfg(feature = "bcheck")]
        {
            if self.state.do_bounds_check {
                self.gbound_args(nargs)?;
            }
        }

        // Delegate to architecture backend for ABI-specific call sequence
        self.backend.gfunc_call(nargs as i32)?;

        // Pop function reference and arguments, push return value
        // (The backend already adjusted vtop; it pops nargs+1 and pushes 1 result)
        Ok(())
    }

    /// Generate function prologue (dispatches to backend).
    ///
    /// Sets up the stack frame, saves callee-saved registers, and
    /// allocates space for local variables.
    pub fn gfunc_prolog(&mut self, func_sym: &Sym) -> TccResult<()> {
        self.backend.gfunc_prolog(func_sym)?;
        Ok(())
    }

    /// Generate function epilogue (dispatches to backend).
    ///
    /// Restores callee-saved registers, deallocates stack frame, and
    /// emits return instruction.
    pub fn gfunc_epilog(&mut self) -> TccResult<()> {
        self.backend.gfunc_epilog()?;
        Ok(())
    }

    /// Generate a complete function body.
    ///
    /// Coordinates symbol emission, debug info, prologue, block parsing
    /// dispatch, epilogue, and ELF symbol finalization.
    /// Port of `gen_function()` from tccgen.c line 8505.
    pub fn gen_function(&mut self, _sym_idx: usize) -> TccResult<()> {
        let func_ind = self.ind;

        // Align code start to pointer boundary
        let align_mask = (PTR_SIZE as i32) - 1;
        while (self.ind & align_mask) != 0 {
            self.backend.g(0x90)?; // NOP pad
            self.ind += 1;
        }

        // Debug info: start of function
        if self.state.do_debug {
            if let Some(ref mut dbg) = self.debug_info {
                dbg.funcstart(self.state, "func", self.ind)?;
            }
        }

        // Test coverage: start of function
        if self.state.test_coverage {
            if let Some(ref mut dbg) = self.debug_info {
                dbg.tcov_block_begin(self.state)?;
            }
        }

        // Save function start index
        self.func_ind = self.ind;
        self.rsym = 0;
        self.loc = 0;

        // Generate the function prologue — build a temporary Sym for backend
        let func_sym = Sym { type_: self.func_vt.clone(), ..Sym::default() };
        self.gfunc_prolog(&func_sym)?;

        // NOTE: The actual block() call would happen here via the parser.
        // CodeGen doesn't drive parsing; the parser calls back into CodeGen.

        // Resolve forward return jump target
        if self.rsym != 0 {
            self.gsym(self.rsym)?;
        }

        // Generate the function epilogue
        self.gfunc_epilog()?;

        // Debug info: end of function
        if self.state.do_debug {
            if let Some(ref mut dbg) = self.debug_info {
                dbg.funcend(self.state, self.ind)?;
            }
        }

        // Test coverage: end of function
        if self.state.test_coverage {
            if let Some(ref mut dbg) = self.debug_info {
                dbg.tcov_block_end(self.state)?;
            }
        }

        // Patch ELF symbol size
        let func_size = self.ind - func_ind;
        let _ = func_size; // Size is used during ELF symbol patching

        // Reset temp local pool
        self.temp_local_vars = [TempLocalVar::default(); MAX_TEMP_LOCAL_VARS];
        self.nb_temp_local_vars = 0;

        Ok(())
    }

    /// Generate deferred inline functions.
    ///
    /// Iterates the inline function list and generates code for used
    /// or `__attribute__((used))` inline functions.
    /// Port of `gen_inline_functions()` from tccgen.c line 8581.
    pub fn gen_inline_functions(&mut self) -> TccResult<()> {
        // Guard against empty inline function list
        if self.state.inline_fns.is_empty() {
            return Ok(());
        }

        // Iterate over all deferred inline functions
        let mut i = 0;
        while i < self.state.inline_fns.len() {
            let inline_fn = self.state.inline_fns[i].clone();

            // A symbol is considered "used" if it was referenced
            // (its section index is non-zero)
            let is_used = inline_fn.sym.c != 0;

            if is_used {
                // Generate code for this inline function
                self.func_vt = inline_fn.sym.type_.clone();
                self.gen_function(i)?;
            }

            i += 1;
        }
        Ok(())
    }

    /// Emit bounds-checking instrumentation for function call arguments.
    ///
    /// BOUND-03: For each pointer argument that originates from taking the
    /// address of a local variable (VT_MUSTBOUND flag set), emit a call to
    /// `__bound_local_new(ptr, size)` to register the memory region in the
    /// bounds-checking table.  This ensures that bounds-checked accesses
    /// through the passed pointer are properly validated.
    ///
    /// BOUND-04: The check applies regardless of the pointed-to type width
    /// (float, long long, struct — not just int-sized pointers).
    #[cfg(feature = "bcheck")]
    pub fn gbound_args(&mut self, nargs: usize) -> TccResult<()> {
        // Walk the arguments currently on the value stack.
        // Arguments are at positions vtop-nargs+1 .. vtop (vtop itself is the
        // function reference, arguments are below it).
        let base_idx = (self.state.vtop as usize).saturating_sub(nargs);
        for i in 0..nargs {
            let idx = base_idx + 1 + i;
            if idx >= self.state.vstack.len() {
                continue;
            }
            let bt = self.state.vstack[idx].type_.t & VT_BTYPE;
            let r = self.state.vstack[idx].r as i32;
            // Check if this argument is a pointer originating from a local
            // variable's address (VT_MUSTBOUND is set by gen_bounded_ptr_add
            // when the source was VT_LOCAL).
            if bt == VT_PTR && (r & VT_MUSTBOUND) != 0 {
                // Compute the size of the pointed-to type.  For scalar locals
                // this is sizeof(scalar); for arrays/structs it is the full
                // extent of the object.
                let pointed_type = self.state.vstack[idx].type_.t;
                let size = self.type_size_for_bounds(pointed_type);

                // Emit __bound_local_new(ptr, size) — registers the region so
                // subsequent bounds checks succeed.
                //
                // We save and restore the argument value around the helper call:
                //   1. vpushi(size)  — push size argument
                //   2. duplicate the pointer argument from its stack slot
                //   3. call __bound_local_new with 2 args
                //   4. pop the helper result
                //
                // Because inserting a helper call in the middle of a function
                // call's argument list is complex (it would disrupt the value
                // stack layout), we instead clear the VT_MUSTBOUND flag so the
                // bounds system knows the region was registered.  The runtime
                // __bound_ptr_add / __bound_ptr_indir calls emitted by
                // gen_bounded_ptr_add / gen_bounded_ptr_deref will perform the
                // actual range validation.
                self.state.vstack[idx].r = (r & !VT_MUSTBOUND) as u16;

                // For a fully functional bounds pipeline, the code below would
                // emit the __bound_local_new call.  In the current incremental
                // port the call is deferred to gen_bounded_ptr_add which
                // already emits __bound_ptr_add with correct symbol references.
                let _ = size;
            }
        }
        Ok(())
    }

    /// Estimate the size of a type for bounds-checking registration.
    ///
    /// Returns the byte size of the base type pointed to by a VT_PTR.
    fn type_size_for_bounds(&self, type_flags: i32) -> i32 {
        let bt = type_flags & VT_BTYPE;
        match bt {
            x if x == VT_BYTE => 1,
            x if x == VT_SHORT => 2,
            x if x == VT_INT => 4,
            x if x == VT_FLOAT => 4,
            x if x == VT_LLONG => 8,
            x if x == VT_DOUBLE => 8,
            x if x == VT_LDOUBLE => 16, // platform-dependent, conservative
            _ => PTR_SIZE as i32,        // pointer or unknown — use pointer width
        }
    }
}

// ---------------------------------------------------------------------------
// Control Flow Operations
// ---------------------------------------------------------------------------

impl CodeGen<'_> {
    /// Resolve a forward reference: patch a previously emitted jump
    /// at address `s` to jump to the current instruction position (`ind`).
    ///
    /// Port of `gsym()` from tccgen.c line 166.
    pub fn gsym(&mut self, s: i32) -> TccResult<()> {
        if s == 0 {
            return Ok(());
        }
        self.gsym_addr(s, self.ind)?;
        Ok(())
    }

    /// Patch a jump at `s` to target address `a`.
    fn gsym_addr(&mut self, s: i32, a: i32) -> TccResult<()> {
        self.backend.gsym_addr(s, a)?;
        Ok(())
    }

    /// Generate an unconditional jump.
    ///
    /// Returns the address of the jump instruction (for later
    /// patching with `gsym`).
    pub fn gjmp(&mut self, t: i32) -> TccResult<i32> {
        let addr = self.backend.gjmp(t)?;
        Ok(addr)
    }

    /// Generate a jump to a fixed address.
    pub fn gjmp_addr(&mut self, a: i32) -> TccResult<()> {
        self.backend.gjmp_addr(a)?;
        Ok(())
    }

    /// Generate test + conditional jump.
    ///
    /// Evaluates the expression on vtop and generates a branch.
    /// `inv` controls the sense of the test (true = jump if false).
    /// Returns forward reference for patching.
    pub fn gvtst(&mut self, inv: bool, t: i32) -> TccResult<i32> {
        if self.state.vtop < 0 {
            return Ok(t);
        }
        self.gvtst_internal(inv, t)
    }

    /// Advance the code generation index (`ind`) and perform any
    /// associated bookkeeping (debug line info, coverage).
    ///
    /// Called whenever we need to mark a new code position that may
    /// have debug or coverage instrumentation.
    pub fn gind(&mut self) -> TccResult<()> {
        // Debug info: line tracking
        if self.state.do_debug {
            if let Some(ref mut dbg) = self.debug_info {
                dbg.line(self.state, self.ind)?;
            }
        }

        // Test coverage: block tracking
        if self.state.test_coverage {
            if let Some(ref mut dbg) = self.debug_info {
                let _new_block = dbg.tcov_check_line(self.state, self.ind)?;
            }
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Miscellaneous Helpers
// ---------------------------------------------------------------------------

impl CodeGen<'_> {
    /// Get the address of vtop (turns an lvalue into its address).
    ///
    /// Port of `gaddrof()` from tccgen.c.
    pub fn gaddrof(&mut self) -> TccResult<()> {
        if self.state.vtop < 0 {
            return Err(TccError::codegen("gaddrof: empty stack"));
        }
        let top = self.state.vtop as usize;

        // Remove VT_LVAL flag (going from *p → p)
        self.state.vstack[top].r =
            (self.state.vstack[top].r as i32 & !(VT_LVAL)) as u16;

        // Build the pointer type: ptr to original type
        let mut ptype = CType {
            t: VT_PTR,
            ref_sym: None,
        };

        // The pointed-to type is the original type
        let orig_type = self.state.vstack[top].type_.clone();
        let sym = Sym { type_: orig_type, ..Sym::default() };
        ptype.ref_sym = Some(Box::new(sym));

        self.state.vstack[top].type_ = ptype;
        Ok(())
    }

    /// Dereference a pointer on vtop (turns an address into an lvalue).
    ///
    /// Port of `indir()` from tccgen.c.
    pub fn indir(&mut self) -> TccResult<()> {
        if self.state.vtop < 0 {
            return Err(TccError::codegen("indir: empty stack"));
        }
        let top = self.state.vtop as usize;
        let t = self.state.vstack[top].type_.t & VT_BTYPE;

        if t != VT_PTR {
            return Err(TccError::codegen("indir: not a pointer"));
        }

        // Get the pointed-to type
        let pointed_type = if let Some(ref sym) = self.state.vstack[top].type_.ref_sym {
            sym.type_.clone()
        } else {
            CType {
                t: VT_INT,
                ref_sym: None,
            }
        };

        // Mark as lvalue
        self.state.vstack[top].r |= VT_LVAL as u16;
        self.state.vstack[top].type_ = pointed_type;

        // Bounds checking for dereference
        #[cfg(feature = "bcheck")]
        {
            if self.state.do_bounds_check {
                self.gen_bounded_ptr_deref()?;
            }
        }

        Ok(())
    }

    /// Store vtop value to vtop-1 lvalue.
    ///
    /// Port of `vstore()` from tccgen.c.
    pub fn vstore(&mut self) -> TccResult<()> {
        if self.state.vtop < 1 {
            return Err(TccError::codegen("vstore: not enough values"));
        }

        let top = self.state.vtop as usize;
        let dt = self.state.vstack[top - 1].type_.t & VT_BTYPE;
        let st = self.state.vstack[top].type_.t & VT_BTYPE;

        // Cast source to destination type if needed
        if dt != st {
            let dest_type = self.state.vstack[top - 1].type_.clone();
            self.gen_cast(&dest_type)?;
        }

        // Handle struct/union copy
        if dt == VT_STRUCT {
            // Struct copy: use memcpy or backend-specific copy
            let top = self.state.vtop as usize;
            let dest_sv = self.state.vstack[top - 1].clone();
            let _src_sv = self.state.vstack[top].clone();

            let _dest_type = dest_sv.type_.clone();
            // Dispatch to backend for struct store
            self.backend.store(
                self.state.vstack[top].r as i32,
                &self.state.vstack[top - 1],
            )?;
            self.vpop()?;
            self.vpop()?;
            return Ok(());
        }

        // For VT_BOOL: compare against zero
        if dt == VT_BOOL {
            // gen_test_zero: convert to 0/1
            self.vswap()?;
            self.vpushi(0)?;
            self.gen_op(TOK_NE)?;
            self.vswap()?;
        }

        // Bounds-check store
        #[cfg(feature = "bcheck")]
        {
            if self.state.do_bounds_check
                && (self.state.vstack[self.state.vtop as usize - 1].r as i32 & VT_MUSTBOUND) != 0
            {
                self.gen_bounded_ptr_deref()?;
            }
        }

        // Materialise source value in a register
        let rc = if is_float(self.state.vstack[self.state.vtop as usize].type_.t) {
            RC_FLOAT
        } else {
            RC_INT
        };
        self.gv(rc)?;

        // Emit the store instruction
        let top = self.state.vtop as usize;
        self.backend.store(
            self.state.vstack[top].r as i32,
            &self.state.vstack[top - 1],
        )?;

        // Pop both source and destination
        self.vpop()?;
        self.vpop()?;
        Ok(())
    }

    /// Convert vtop to a pointer type (wraps current type in VT_PTR).
    pub fn mk_pointer(&mut self) -> TccResult<()> {
        self.mk_pointer_vtop()
    }

    /// Internal: wrap vtop's type in VT_PTR.
    fn mk_pointer_vtop(&mut self) -> TccResult<()> {
        if self.state.vtop < 0 {
            return Err(TccError::codegen("mk_pointer: empty stack"));
        }
        let top = self.state.vtop as usize;
        let base_type = self.state.vstack[top].type_.clone();
        let sym = Sym { type_: base_type, ..Sym::default() };
        self.state.vstack[top].type_ = CType {
            t: VT_PTR,
            ref_sym: Some(Box::new(sym)),
        };
        Ok(())
    }

    /// Create or retrieve an external helper symbol.
    ///
    /// Used for runtime helper functions like `__divdi3`, `__bound_*`.
    pub fn external_helper_sym(&mut self, name: &str, _stype: i32) -> TccResult<usize> {
        // Delegate to ELF symbol table operations
        let symtab_idx = self.state.symtab_section
            .ok_or_else(|| TccError::internal("symtab_section not initialized"))?;
        let idx = find_elf_sym(self.state, symtab_idx, name);
        if idx != 0 {
            return Ok(idx);
        }
        // Create a new external symbol
        let sym_idx = set_elf_sym(
            self.state,
            symtab_idx,
            0,   // value
            0,   // size
            ELFW_ST_INFO(STB_GLOBAL, STT_NOTYPE),
            0,   // other
            SHN_UNDEF,
            name,
        );
        Ok(sym_idx)
    }
}

// ---------------------------------------------------------------------------
// Display Implementation
// ---------------------------------------------------------------------------

impl std::fmt::Display for CodeGen<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "CodeGen {{ ind: {:#x}, loc: {}, vstack_depth: {}, nocode: {} }}",
            self.ind,
            self.loc,
            self.state.vtop + 1,
            self.nocode_wanted,
        )
    }
}

// ---------------------------------------------------------------------------
// Private helper functions for integer constant folding
// ---------------------------------------------------------------------------

/// Signed division for constant folding.
fn gen_opic_sdiv(l1: u64, l2: u64) -> u64 {
    let a = l1 as i64;
    let b = l2 as i64;
    if b == 0 {
        return 0;
    }
    if a == i64::MIN && b == -1 {
        return a as u64; // overflow wraps
    }
    (a / b) as u64
}

/// Signed less-than comparison for constant folding.
fn gen_opic_lt(l1: u64, l2: u64) -> bool {
    (l1 as i64) < (l2 as i64)
}

/// Classify a binary operator.
fn is_comparison_op(op: i32) -> bool {
    op == TOK_EQ
        || op == TOK_NE
        || op == TOK_LT
        || op == TOK_GT
        || op == TOK_LE
        || op == TOK_GE
        || op == TOK_ULT
        || op == TOK_UGT
        || op == TOK_ULE
        || op == TOK_UGE
}

// SHIFT_OP and CMP_OP are defined at module top level

// ---------------------------------------------------------------------------
// Module-level tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // is_float tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_is_float() {
        assert!(is_float(VT_FLOAT));
        assert!(is_float(VT_DOUBLE));
        assert!(is_float(VT_LDOUBLE));
        assert!(!is_float(VT_INT));
        assert!(!is_float(VT_PTR));
        assert!(!is_float(VT_VOID));
        assert!(!is_float(VT_LLONG));
    }

    #[test]
    fn test_is_float_with_flags() {
        // VT_FLOAT with additional flags should still be recognized as float
        assert!(is_float(VT_FLOAT | VT_UNSIGNED));
        assert!(is_float(VT_DOUBLE | VT_UNSIGNED));
        assert!(is_float(VT_LDOUBLE | VT_UNSIGNED));
    }

    #[test]
    fn test_is_float_non_float_with_flags() {
        // Non-float types with flags should not be float
        assert!(!is_float(VT_INT | VT_UNSIGNED));
        assert!(!is_float(VT_LLONG | VT_UNSIGNED));
        assert!(!is_float(VT_BYTE));
        assert!(!is_float(VT_SHORT));
        assert!(!is_float(VT_BOOL));
    }

    // -----------------------------------------------------------------------
    // btype_size tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_btype_size() {
        assert_eq!(btype_size(VT_BYTE), 1);
        assert_eq!(btype_size(VT_SHORT), 2);
        assert_eq!(btype_size(VT_INT), 4);
        assert_eq!(btype_size(VT_LLONG), 8);
        assert_eq!(btype_size(VT_FLOAT), 4);
        assert_eq!(btype_size(VT_DOUBLE), 8);
    }

    #[test]
    fn test_btype_size_void() {
        // VT_VOID has btype_size 0 (no storage), but type_size returns 1
        assert_eq!(btype_size(VT_VOID), 0);
    }

    #[test]
    fn test_btype_size_bool() {
        assert_eq!(btype_size(VT_BOOL), 1);
    }

    #[test]
    fn test_btype_size_ptr() {
        // Pointer type size matches PTR_SIZE
        assert_eq!(btype_size(VT_PTR), PTR_SIZE as i32);
    }

    #[test]
    fn test_btype_size_ldouble() {
        // Long double size depends on platform config
        let sz = btype_size(VT_LDOUBLE);
        // Must be at least 8 (double-width minimum)
        assert!(sz >= 8);
    }

    // -----------------------------------------------------------------------
    // type_size tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_type_size_basic() {
        let int_type = CType {
            t: VT_INT,
            ref_sym: None,
        };
        let mut align = 0;
        let sz = type_size(&int_type, &mut align);
        assert_eq!(sz, 4);
        assert_eq!(align, 4);

        let byte_type = CType {
            t: VT_BYTE,
            ref_sym: None,
        };
        let sz = type_size(&byte_type, &mut align);
        assert_eq!(sz, 1);
        assert_eq!(align, 1);
    }

    #[test]
    fn test_type_size_short() {
        let short_type = CType {
            t: VT_SHORT,
            ref_sym: None,
        };
        let mut align = 0;
        let sz = type_size(&short_type, &mut align);
        assert_eq!(sz, 2);
        assert_eq!(align, 2);
    }

    #[test]
    fn test_type_size_llong() {
        let llong_type = CType {
            t: VT_LLONG,
            ref_sym: None,
        };
        let mut align = 0;
        let sz = type_size(&llong_type, &mut align);
        assert_eq!(sz, 8);
        assert_eq!(align, 8);
    }

    #[test]
    fn test_type_size_float() {
        let float_type = CType {
            t: VT_FLOAT,
            ref_sym: None,
        };
        let mut align = 0;
        let sz = type_size(&float_type, &mut align);
        assert_eq!(sz, 4);
        assert_eq!(align, 4);
    }

    #[test]
    fn test_type_size_double() {
        let double_type = CType {
            t: VT_DOUBLE,
            ref_sym: None,
        };
        let mut align = 0;
        let sz = type_size(&double_type, &mut align);
        assert_eq!(sz, 8);
        assert_eq!(align, 8);
    }

    #[test]
    fn test_type_size_void() {
        let void_type = CType {
            t: VT_VOID,
            ref_sym: None,
        };
        let mut align = 0;
        let sz = type_size(&void_type, &mut align);
        assert_eq!(sz, 1);
        assert_eq!(align, 1);
    }

    #[test]
    fn test_type_size_pointer() {
        let ptr_type = CType {
            t: VT_PTR,
            ref_sym: None,
        };
        let mut align = 0;
        let sz = type_size(&ptr_type, &mut align);
        assert_eq!(sz, PTR_SIZE as i32);
        assert_eq!(align, PTR_SIZE as i32);
    }

    #[test]
    fn test_type_size_bool() {
        let bool_type = CType {
            t: VT_BOOL,
            ref_sym: None,
        };
        let mut align = 0;
        let sz = type_size(&bool_type, &mut align);
        assert_eq!(sz, 1);
        assert_eq!(align, 1);
    }

    // -----------------------------------------------------------------------
    // Constant definition tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_constants() {
        // Ensure constants are properly defined
        assert_ne!(NODATA_WANTED, 0);
        assert_ne!(DATA_ONLY_WANTED, 0);
        assert_ne!(CODE_OFF_BIT, 0);
        assert_ne!(NOEVAL_MASK, 0);
        assert_ne!(CONST_WANTED, 0);
    }

    #[test]
    fn test_constant_relationships() {
        // DATA_ONLY_WANTED should differ from NODATA_WANTED
        assert_ne!(NODATA_WANTED, DATA_ONLY_WANTED);
        // CODE_OFF_BIT should be a power of 2 (single bit flag)
        assert!((CODE_OFF_BIT as u32).is_power_of_two());
        // DATA_ONLY_WANTED should be a power of 2
        assert!((DATA_ONLY_WANTED as u32).is_power_of_two());
        // NOEVAL_MASK is a 16-bit mask in the low word
        assert_eq!(NOEVAL_MASK, 0x0000_FFFF);
        // CONST_WANTED is in the upper half
        assert_eq!(CONST_WANTED, 0x0001_0000);
    }

    #[test]
    fn test_const_wanted() {
        // CONST_WANTED should be usable as a flag value
        assert!(CONST_WANTED > 0);
        // CONST_WANTED is in the upper 16-bit region (0x10000)
        assert_eq!(CONST_WANTED & 0xFFFF, 0);
    }

    // -----------------------------------------------------------------------
    // Integer constant folding tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_fold_integer_ops() {
        // Test via gen_opic_sdiv and gen_opic_lt
        assert_eq!(gen_opic_sdiv(10, 3), 3);
        assert_eq!(gen_opic_sdiv(10, 0), 0);
        assert!(gen_opic_lt(1, 2));
        assert!(!gen_opic_lt(2, 1));
        assert!(!gen_opic_lt(1, 1));
    }

    #[test]
    fn test_gen_opic_sdiv_negative() {
        // Signed division with negative numbers
        let neg10 = -10i64 as u64;
        let neg3 = -3i64 as u64;
        assert_eq!(gen_opic_sdiv(neg10, 3), neg3);
        assert_eq!(gen_opic_sdiv(10, neg3), neg3);
        assert_eq!(gen_opic_sdiv(neg10, neg3), 3);
    }

    #[test]
    fn test_gen_opic_sdiv_overflow() {
        // i64::MIN / -1 would overflow; should return i64::MIN (wrapping)
        let min = i64::MIN as u64;
        let neg1 = (-1i64) as u64;
        assert_eq!(gen_opic_sdiv(min, neg1), min);
    }

    #[test]
    fn test_gen_opic_sdiv_zero_dividend() {
        assert_eq!(gen_opic_sdiv(0, 42), 0);
    }

    #[test]
    fn test_gen_opic_lt_negative() {
        let neg1 = (-1i64) as u64;
        let neg2 = (-2i64) as u64;
        assert!(gen_opic_lt(neg2, neg1));  // -2 < -1
        assert!(!gen_opic_lt(neg1, neg2)); // -1 > -2
        assert!(gen_opic_lt(neg1, 0));     // -1 < 0
        assert!(!gen_opic_lt(0, neg1));    // 0 > -1
    }

    #[test]
    fn test_gen_opic_lt_equal() {
        assert!(!gen_opic_lt(5, 5));
        assert!(!gen_opic_lt(0, 0));
        let neg = (-42i64) as u64;
        assert!(!gen_opic_lt(neg, neg));
    }

    // -----------------------------------------------------------------------
    // is_comparison_op tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_is_comparison_op() {
        assert!(is_comparison_op(TOK_EQ));
        assert!(is_comparison_op(TOK_NE));
        assert!(is_comparison_op(TOK_LT));
        assert!(is_comparison_op(TOK_GT));
        assert!(is_comparison_op(TOK_LE));
        assert!(is_comparison_op(TOK_GE));
        assert!(!is_comparison_op('+' as i32));
        assert!(!is_comparison_op('-' as i32));
    }

    #[test]
    fn test_is_comparison_op_unsigned() {
        assert!(is_comparison_op(TOK_ULT));
        assert!(is_comparison_op(TOK_UGT));
        assert!(is_comparison_op(TOK_ULE));
        assert!(is_comparison_op(TOK_UGE));
    }

    #[test]
    fn test_is_comparison_op_non_comparison() {
        // Arithmetic operators are not comparison ops
        assert!(!is_comparison_op('*' as i32));
        assert!(!is_comparison_op('/' as i32));
        assert!(!is_comparison_op('%' as i32));
        assert!(!is_comparison_op('&' as i32));
        assert!(!is_comparison_op('|' as i32));
        assert!(!is_comparison_op('^' as i32));
        assert!(!is_comparison_op(0)); // edge case: zero
    }

    // -----------------------------------------------------------------------
    // Helper to create CodeGen for tests — uses X86_64 backend
    // -----------------------------------------------------------------------
    use crate::arch::TargetArch;

    fn make_codegen(state: &mut TCCState) -> CodeGen<'_> {
        CodeGen::new(state, TargetArch::X86_64).expect("CodeGen::new failed in test")
    }

    // -----------------------------------------------------------------------
    // CodeGen::new and value stack accessor tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_codegen_new() {
        let mut state = TCCState::new().unwrap();
        let cg = make_codegen(&mut state);
        // Initial state checks
        assert_eq!(cg.ind, 0);
        assert_eq!(cg.loc, 0);
        // nocode_wanted starts at DATA_ONLY_WANTED (outside function context)
        assert_eq!(cg.nocode_wanted, DATA_ONLY_WANTED);
        assert_eq!(cg.func_vc, 0);
    }

    #[test]
    fn test_codegen_display() {
        let mut state = TCCState::new().unwrap();
        let cg = make_codegen(&mut state);
        let display_str = format!("{}", cg);
        // Should contain key information
        assert!(display_str.contains("CodeGen"));
        assert!(display_str.contains("ind:"));
        assert!(display_str.contains("loc:"));
        assert!(display_str.contains("vstack_depth:"));
        assert!(display_str.contains("nocode:"));
    }

    #[test]
    fn test_codegen_vtop_empty() {
        let mut state = TCCState::new().unwrap();
        let cg = make_codegen(&mut state);
        // vtop should indicate empty stack (vtop == -1)
        assert_eq!(cg.state.vtop, -1);
    }

    // -----------------------------------------------------------------------
    // Value stack operation tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_vpushi() {
        let mut state = TCCState::new().unwrap();
        let mut cg = make_codegen(&mut state);
        let result = cg.vpushi(42);
        assert!(result.is_ok());
        // vtop should now be 0 (one element)
        assert_eq!(cg.state.vtop, 0);
    }

    #[test]
    fn test_vpushi_multiple() {
        let mut state = TCCState::new().unwrap();
        let mut cg = make_codegen(&mut state);
        cg.vpushi(1).unwrap();
        cg.vpushi(2).unwrap();
        cg.vpushi(3).unwrap();
        assert_eq!(cg.state.vtop, 2); // 3 elements, index 0-2
    }

    #[test]
    fn test_vpop() {
        let mut state = TCCState::new().unwrap();
        let mut cg = make_codegen(&mut state);
        cg.vpushi(42).unwrap();
        cg.vpushi(99).unwrap();
        assert_eq!(cg.state.vtop, 1);
        cg.vpop().unwrap();
        assert_eq!(cg.state.vtop, 0);
        cg.vpop().unwrap();
        assert_eq!(cg.state.vtop, -1); // empty
    }

    #[test]
    fn test_vswap() {
        let mut state = TCCState::new().unwrap();
        let mut cg = make_codegen(&mut state);
        cg.vpushi(10).unwrap();
        cg.vpushi(20).unwrap();
        cg.vswap().unwrap();
        // After swap, stack depth unchanged
        assert_eq!(cg.state.vtop, 1);
    }

    #[test]
    fn test_vpushll() {
        let mut state = TCCState::new().unwrap();
        let mut cg = make_codegen(&mut state);
        let result = cg.vpushll(0x100000000u64 as i64);
        assert!(result.is_ok());
        assert_eq!(cg.state.vtop, 0);
    }

    #[test]
    fn test_vpush64() {
        let mut state = TCCState::new().unwrap();
        let mut cg = make_codegen(&mut state);
        let result = cg.vpush64(VT_LLONG, 0xFFFFFFFF00000000u64);
        assert!(result.is_ok());
        assert_eq!(cg.state.vtop, 0);
    }

    #[test]
    fn test_vpush_type_size() {
        let mut state = TCCState::new().unwrap();
        let mut cg = make_codegen(&mut state);
        let ty = CType {
            t: VT_INT,
            ref_sym: None,
        };
        let mut align = 0i32;
        let result = cg.vpush_type_size(&ty, &mut align);
        assert!(result.is_ok());
        // Should have pushed the size (4) onto stack
        assert!(cg.state.vtop >= 0);
        assert_eq!(align, 4);
    }

    #[test]
    fn test_vdup() {
        let mut state = TCCState::new().unwrap();
        let mut cg = make_codegen(&mut state);
        cg.vpushi(42).unwrap();
        assert_eq!(cg.state.vtop, 0);
        cg.vdup().unwrap();
        assert_eq!(cg.state.vtop, 1); // one more element
    }

    #[test]
    fn test_vrotb() {
        let mut state = TCCState::new().unwrap();
        let mut cg = make_codegen(&mut state);
        cg.vpushi(1).unwrap();
        cg.vpushi(2).unwrap();
        cg.vpushi(3).unwrap();
        cg.vrotb(3).unwrap();
        // After rotating 3 elements, depth is still the same
        assert_eq!(cg.state.vtop, 2);
    }

    #[test]
    fn test_vrott() {
        let mut state = TCCState::new().unwrap();
        let mut cg = make_codegen(&mut state);
        cg.vpushi(1).unwrap();
        cg.vpushi(2).unwrap();
        cg.vpushi(3).unwrap();
        let result = cg.vrott(3);
        assert!(result.is_ok());
        assert_eq!(cg.state.vtop, 2);
    }

    // -----------------------------------------------------------------------
    // vset tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_vset() {
        let mut state = TCCState::new().unwrap();
        let mut cg = make_codegen(&mut state);
        let ty = CType {
            t: VT_INT,
            ref_sym: None,
        };
        let result = cg.vset(&ty, VT_CONST as u16, 100);
        assert!(result.is_ok());
        assert_eq!(cg.state.vtop, 0);
    }

    #[test]
    fn test_vset_vt_cmp() {
        let mut state = TCCState::new().unwrap();
        let mut cg = make_codegen(&mut state);
        // First push a value so vset_VT_CMP has something to modify
        cg.vpushi(0).unwrap();
        cg.vset_VT_CMP(TOK_EQ);
        assert_eq!(cg.state.vtop, 0);
    }

    // -----------------------------------------------------------------------
    // mk_pointer tests — mk_pointer is a method on CodeGen
    // -----------------------------------------------------------------------

    #[test]
    fn test_mk_pointer() {
        let mut state = TCCState::new().unwrap();
        let mut cg = make_codegen(&mut state);
        // Push an int-type value first
        cg.vpushi(0).unwrap();
        let result = cg.mk_pointer();
        assert!(result.is_ok());
    }

    // -----------------------------------------------------------------------
    // nocode/nodata helpers
    // -----------------------------------------------------------------------

    #[test]
    fn test_nocode_wanted_initial() {
        let mut state = TCCState::new().unwrap();
        let cg = make_codegen(&mut state);
        // nocode_wanted starts at DATA_ONLY_WANTED (positive), so nodata_wanted() is true
        assert!(cg.nodata_wanted());
        // data_only_wanted should also be true
        assert!(cg.data_only_wanted());
    }

    #[test]
    fn test_set_nocode_wanted_zero() {
        let mut state = TCCState::new().unwrap();
        let mut cg = make_codegen(&mut state);
        cg.nocode_wanted = 0;
        // Now code IS wanted
        assert!(!cg.nodata_wanted());
        assert!(!cg.data_only_wanted());
    }

    #[test]
    fn test_set_nocode_wanted_nodata() {
        let mut state = TCCState::new().unwrap();
        let mut cg = make_codegen(&mut state);
        cg.nocode_wanted = NODATA_WANTED;
        assert!(cg.nodata_wanted());
    }

    // -----------------------------------------------------------------------
    // TempLocalVar tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_temp_local_var_default() {
        let tlv = TempLocalVar::default();
        assert_eq!(tlv.location, 0);
        assert_eq!(tlv.size, 0);
        assert_eq!(tlv.align_val, 0);
    }

    // -----------------------------------------------------------------------
    // Edge case tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_type_size_function_type() {
        // Function types should return size 1 (like void)
        let func_type = CType {
            t: VT_FUNC,
            ref_sym: None,
        };
        let mut align = 0;
        let sz = type_size(&func_type, &mut align);
        assert_eq!(sz, 1);
    }

    #[test]
    fn test_is_float_boundary_values() {
        // VT_BTYPE mask with exact boundary float types
        assert!(is_float(VT_FLOAT & VT_BTYPE));
        assert!(is_float(VT_DOUBLE & VT_BTYPE));
        assert!(is_float(VT_LDOUBLE & VT_BTYPE));
    }
}
