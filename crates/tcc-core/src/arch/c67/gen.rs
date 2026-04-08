//! TMS320C67xx DSP code generator — full port of `c67-gen.c` (2,543 lines).
//!
//! Implements VLIW instruction emission, dual-side (A/B) data-path handling,
//! pipeline delay-slot management, register mapping, function call/prolog/epilog
//! generation, and integer/floating-point arithmetic operations for the
//! TMS320C67xx DSP family.
//!
//! # Architecture Notes
//!
//! - C67 is a VLIW (Very Long Instruction Word) architecture with A-side and B-side
//!   functional units.
//! - Uses COFF output format (not ELF).
//! - `o()` function is NOT available for C67.
//! - VLAs, `long double`, and `long long` are NOT supported.
//! - Maximum of 10 function parameters (passed in register pairs A4:A5 through B12:B13).
//! - Bounds checking is disabled on this target.

use crate::error::{TccError, TccResult};
use crate::types::{
    CType, CValue, SValue, Sym,
    VT_BTYPE, VT_BYTE, VT_CMP, VT_CONST, VT_DOUBLE, VT_FLOAT, VT_INT,
    VT_JMP, VT_JMPI, VT_LDOUBLE, VT_LLOCAL, VT_LVAL, VT_LOCAL, VT_SHORT,
    VT_SYM, VT_UNSIGNED, VT_VALMASK,
};
use crate::token::{
    TOK_ADDC1, TOK_ADDC2, TOK_EQ, TOK_GE, TOK_GT, TOK_LE, TOK_LT, TOK_NE,
    TOK_PDIV, TOK_SAR, TOK_SHL, TOK_SHR, TOK_SUBC1, TOK_SUBC2, TOK_UDIV,
    TOK_UGE, TOK_UGT, TOK_ULE, TOK_ULT, TOK_UMOD, TOK_UMULL,
};
use crate::arch::{RC_INT, RC_FLOAT, write32le, read32le};
use crate::arch::c67::link::{R_C60HI16, R_C60LO16};

// ===========================================================================
// C67 Register Architecture Constants
// From c67-gen.c lines 2-113 (TARGET_DEFS_ONLY section)
// ===========================================================================

/// Number of registers available to TCC's register allocator (24).
pub const NB_REGS: usize = 24;

// --- Register class bitmask constants ---
pub const RC_C67_A4: i32  = 0x0000_0004;
pub const RC_C67_A5: i32  = 0x0000_0008;
pub const RC_C67_B4: i32  = 0x0000_0010;
pub const RC_C67_B5: i32  = 0x0000_0020;
pub const RC_C67_A6: i32  = 0x0000_0040;
pub const RC_C67_A7: i32  = 0x0000_0080;
pub const RC_C67_B6: i32  = 0x0000_0100;
pub const RC_C67_B7: i32  = 0x0000_0200;
pub const RC_C67_A8: i32  = 0x0000_0400;
pub const RC_C67_A9: i32  = 0x0000_0800;
pub const RC_C67_B8: i32  = 0x0000_1000;
pub const RC_C67_B9: i32  = 0x0000_2000;
pub const RC_C67_A10: i32 = 0x0000_4000;
pub const RC_C67_A11: i32 = 0x0000_8000;
pub const RC_C67_B10: i32 = 0x0001_0000;
pub const RC_C67_B11: i32 = 0x0002_0000;
pub const RC_C67_A12: i32 = 0x0004_0000;
pub const RC_C67_A13: i32 = 0x0008_0000;
pub const RC_C67_B12: i32 = 0x0010_0000;
pub const RC_C67_B13: i32 = 0x0020_0000;

/// EAX class — maps to A2 register (general purpose).
pub const RC_EAX: i32 = 0x0000_0004;
/// Integer registers on the B side (for comparisons requiring B-side src1).
pub const RC_INT_BSIDE: i32 = RC_C67_B4;
/// ECX class — maps to A3 (used with EAX for register pairs).
pub const RC_ECX: i32 = 0x0000_0008;
/// EDX class — maps to B0 (used as condition register).
pub const RC_EDX: i32 = 0x0000_0010;
/// ST0 class — maps to B1 (used as float scratch).
pub const RC_ST0: i32 = 0x0000_0020;

// --- TCC register numbers (TREG_*) ---
pub const TREG_EAX: i32 = 0;
pub const TREG_ECX: i32 = 1;
pub const TREG_EDX: i32 = 2;
pub const TREG_ST0: i32 = 3;
pub const TREG_C67_A4: i32 = 4;
pub const TREG_C67_A5: i32 = 5;
pub const TREG_C67_B4: i32 = 6;
pub const TREG_C67_B5: i32 = 7;
pub const TREG_C67_A6: i32 = 8;
pub const TREG_C67_A7: i32 = 9;
pub const TREG_C67_B6: i32 = 10;
pub const TREG_C67_B7: i32 = 11;
pub const TREG_C67_A8: i32 = 12;
pub const TREG_C67_A9: i32 = 13;
pub const TREG_C67_B8: i32 = 14;
pub const TREG_C67_B9: i32 = 15;
pub const TREG_C67_A10: i32 = 16;
pub const TREG_C67_A11: i32 = 17;
pub const TREG_C67_B10: i32 = 18;
pub const TREG_C67_B11: i32 = 19;
pub const TREG_C67_A12: i32 = 20;
pub const TREG_C67_A13: i32 = 21;
pub const TREG_C67_B12: i32 = 22;
pub const TREG_C67_B13: i32 = 23;

/// Integer return register (A4).
pub const REG_IRET: i32 = TREG_C67_A4;
/// Second integer return register (A5).
pub const REG_IRE2: i32 = TREG_C67_A5;
/// Float return register (A4, same physical register).
pub const REG_FRET: i32 = TREG_C67_A4;

/// Pointer size for C67 target (32-bit).
pub const PTR_SIZE: usize = 4;

// --- Special registers not tracked by TCC's allocator ---
const C67_A0: i32 = 105;
const C67_SP: i32 = 106;
const C67_B3: i32 = 107;
const C67_FP: i32 = 108;
const C67_B2: i32 = 109;
/// Special value: no condition register test.
const C67_CREG_ZERO: i32 = -1;

/// Maximum number of function call arguments (passed in register pairs).
const MAX_FUNC_ARGS: usize = 10;

/// Register class table for the C67 register allocator.
/// Indexed by TREG_* number.
pub const REG_CLASSES: [i32; NB_REGS] = [
    RC_INT | RC_EAX,               // 0 = TREG_EAX → A2
    RC_INT | RC_ECX,               // 1 = TREG_ECX → A3
    RC_INT | RC_EDX,               // 2 = TREG_EDX → B0
    RC_INT | RC_ST0,               // 3 = TREG_ST0 → B1
    RC_INT | RC_FLOAT | RC_C67_A4, // 4 = A4
    RC_INT | RC_FLOAT | RC_C67_A5, // 5 = A5
    RC_INT | RC_FLOAT | RC_C67_B4, // 6 = B4
    RC_INT | RC_FLOAT | RC_C67_B5, // 7 = B5
    RC_INT | RC_FLOAT | RC_C67_A6, // 8 = A6
    RC_INT | RC_FLOAT | RC_C67_A7, // 9 = A7
    RC_INT | RC_FLOAT | RC_C67_B6, // 10 = B6
    RC_INT | RC_FLOAT | RC_C67_B7, // 11 = B7
    RC_INT | RC_FLOAT | RC_C67_A8, // 12 = A8
    RC_INT | RC_FLOAT | RC_C67_A9, // 13 = A9
    RC_INT | RC_FLOAT | RC_C67_B8, // 14 = B8
    RC_INT | RC_FLOAT | RC_C67_B9, // 15 = B9
    RC_INT | RC_FLOAT | RC_C67_A10,// 16 = A10
    RC_INT | RC_FLOAT | RC_C67_A11,// 17 = A11
    RC_INT | RC_FLOAT | RC_C67_B10,// 18 = B10
    RC_INT | RC_FLOAT | RC_C67_B11,// 19 = B11
    RC_INT | RC_FLOAT | RC_C67_A12,// 20 = A12
    RC_INT | RC_FLOAT | RC_C67_A13,// 21 = A13
    RC_INT | RC_FLOAT | RC_C67_B12,// 22 = B12
    RC_INT | RC_FLOAT | RC_C67_B13,// 23 = B13
];

// ===========================================================================
// Code generation context — synced by CodeGen before/after trait calls.
// Mirrors I386CodegenCtx pattern.
// ===========================================================================

/// Code emission context for the C67 backend.
///
/// This struct is synced by `CodeGen` before and after each backend trait
/// method call, mirroring the `I386CodegenCtx` pattern. It contains the
/// mutable state needed for instruction emission and value stack access.
pub struct C67CodegenCtx {
    /// Current code position (byte offset in code_buf).
    pub ind: i32,
    /// When non-zero, instruction emission is suppressed.
    pub nocode_wanted: i32,
    /// Current local variable offset.
    pub loc: i32,
    /// Function return type.
    pub func_vt: CType,
    /// Code buffer — holds emitted instruction bytes.
    pub code_buf: Vec<u8>,
    /// Value stack snapshot (synced from TCCState.vstack).
    pub vstack: Vec<SValue>,
    /// Index of the value stack top (-1 = empty).
    pub vtop_idx: i32,
}

impl C67CodegenCtx {
    /// Create a new zeroed-out code generation context.
    pub fn new() -> Self {
        Self {
            ind: 0,
            nocode_wanted: 0,
            loc: 0,
            func_vt: CType::default(),
            code_buf: Vec::new(),
            vstack: Vec::new(),
            vtop_idx: -1,
        }
    }
}

impl Default for C67CodegenCtx {
    fn default() -> Self {
        Self::new()
    }
}

/// A pending relocation to be applied by CodeGen when syncing back.
///
/// Since the backend cannot directly call ELF relocation functions (they
/// require `&mut TCCState`), relocations are queued here and processed
/// by CodeGen after the trait method returns.
pub struct PendingReloc {
    /// Offset in the code section where the relocation applies.
    pub offset: u64,
    /// Relocation type (e.g., R_C60LO16, R_C60HI16).
    pub reloc_type: u32,
    /// Symbol name for named relocations (helper functions).
    pub symbol_name: Option<String>,
    /// Symbol token index (`Sym.v`) for previously known symbols.
    pub symbol_v: Option<i32>,
    /// Symbol section offset (`Sym.c`) for previously known symbols.
    pub symbol_c: Option<i32>,
}

// ===========================================================================
// C67-specific code generation state
// From c67-gen.c lines 152-187
// ===========================================================================

/// Internal code generation state for the C67 backend.
///
/// This struct replaces the global mutable variables from c67-gen.c.
/// All fields are `pub` to allow access from mod.rs trait delegation.
pub struct C67GenState {
    /// Stack pointer offset for function sub (c67-gen.c line 179).
    pub func_sub_sp_offset: u64,
    /// Function return subtraction value (c67-gen.c line 180).
    pub func_ret_sub: i32,
    /// Whether to invert the test condition (c67-gen.c line 182).
    pub c67_invert_test: bool,
    /// Register used for comparison results (c67-gen.c line 183).
    pub c67_compare_reg: i32,
    /// Number of current function arguments (c67-gen.c line 159).
    pub no_of_cur_func_args: usize,
    /// Translation from stack offsets to registers (c67-gen.c line 160).
    pub translate_stack_to_reg: [i32; MAX_FUNC_ARGS],
    /// Parameter locations on stack (c67-gen.c line 161).
    pub param_loc_on_stack: [i32; MAX_FUNC_ARGS],
    /// Total bytes pushed on stack (c67-gen.c line 162).
    pub total_bytes_pushed_on_stack: i32,
}

impl C67GenState {
    /// Create a new default-initialized C67 generation state.
    pub fn new() -> Self {
        Self {
            func_sub_sp_offset: 0,
            func_ret_sub: 0,
            c67_invert_test: false,
            c67_compare_reg: C67_CREG_ZERO,
            no_of_cur_func_args: 0,
            translate_stack_to_reg: [0; MAX_FUNC_ARGS],
            param_loc_on_stack: [0; MAX_FUNC_ARGS],
            total_bytes_pushed_on_stack: 0,
        }
    }
}

impl Default for C67GenState {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// Instruction type enum — replaces string-matching in C67_asm()
// From c67-gen.c lines 374-1194
// ===========================================================================

/// All TMS320C67xx instruction variants emitted by the code generator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
enum C67Instr {
    Mvkl, Mvkh,
    StwSpPostDec, StbSpA0, SthSpA0, StwSpA0,
    StbPtr, SthPtr, StwPtr, StwPtrPreInc,
    LdwSpPreInc, LddwSpPreInc,
    LdwSpA0, LddwSpA0, LdhSpA0, LdbSpA0, LdhuSpA0, LdbuSpA0,
    LdwPtr, LddwPtr, LdhPtr, LdbPtr, LdhuPtr, LdbuPtr, LdwPtrPreInc,
    CmpltSp, CmpgtSp, CmpeqSp,
    CmpltDp, CmpgtDp, CmpeqDp,
    Cmplt, Cmpgt, Cmpeq, Cmpltu, Cmpgtu,
    BDisp, BS2x,
    MvL, SptruncL, DptruncL,
    IntspL, IntspuL, IntdpL, IntdpuL,
    SpdpL, DpspL,
    AddL, SubL, OrL, AndL, XorL,
    AddspL, AdddpL, SubspL, SubdpL,
    MpyspM, MpydpM, MpyiM,
    ShrS, ShruS, ShlS,
    Addk, AdkkParallel,
    Nop,
}

// ===========================================================================
// Register Mapping Functions
// From c67-gen.c lines 248-370
// ===========================================================================

/// Map TCC register numbers to actual C67 hardware register numbers.
/// From c67-gen.c lines 258-286.
fn c67_map_regn(r: i32) -> i32 {
    match r {
        0 => 0x2,  // TREG_EAX → A2
        1 => 0x3,  // TREG_ECX → A3
        2 => 0x0,  // TREG_EDX → B0
        3 => 0x1,  // TREG_ST0 → B1
        r if r >= TREG_C67_A4 && r <= TREG_C67_B13 => {
            (((r & !3) >> 1) | (r & 1)) + 2
        }
        r if r == C67_A0 => 0,   // A0
        r if r == C67_B2 => 2,   // B2
        r if r == C67_B3 => 3,   // B3
        r if r == C67_SP => 15,  // B15 (SP)
        r if r == C67_FP => 15,  // A15 (FP)
        _ => 0,
    }
}

/// Map register to condition code field.
/// From c67-gen.c lines 299-315.
fn c67_map_regc(r: i32) -> i32 {
    match r {
        0 => 0x5,  // TREG_EAX/A2
        2 => 0x1,  // TREG_EDX/B0
        3 => 0x2,  // TREG_ST0/B1
        r if r == C67_B2 => 0x3,
        r if r == C67_CREG_ZERO => 0,
        _ => {
            debug_assert!(false, "c67_map_regc: unsupported register {}", r);
            0
        }
    }
}

/// Map register to data path side (A=0, B=1).
/// From c67-gen.c lines 320-346.
fn c67_map_regs(r: i32) -> i32 {
    match r {
        0 | 1 => 0,  // A-side
        2 | 3 => 1,  // B-side
        r if r >= TREG_C67_A4 && r <= TREG_C67_B13 => (r & 2) >> 1,
        r if r == C67_A0 => 0,
        r if r == C67_B2 => 1,
        r if r == C67_B3 => 1,
        r if r == C67_SP => 1,  // B15
        r if r == C67_FP => 0,  // A15
        _ => 0,
    }
}

/// Return side as 1 or 2 (for debug/display).
#[allow(dead_code)]
fn c67_map_s12(r: i32) -> i32 {
    c67_map_regs(r) + 1
}

/// Return 'A' or 'B' data path identifier.
#[allow(dead_code)]
fn c67_map_d12(r: i32) -> char {
    if c67_map_regs(r) == 0 { 'A' } else { 'B' }
}

// ===========================================================================
// Helper methods on C67Backend for code emission and value stack access
// ===========================================================================

use super::C67Backend;

impl C67Backend {
    /// Get the value at the top of the value stack (vtop[0]).
    #[inline]
    #[allow(dead_code)]
    pub(crate) fn vtop(&self) -> &SValue {
        &self.ctx.vstack[self.ctx.vtop_idx as usize]
    }

    /// Mutably get the value at the top of the value stack.
    #[inline]
    #[allow(dead_code)]
    pub(crate) fn vtop_mut(&mut self) -> &mut SValue {
        let idx = self.ctx.vtop_idx as usize;
        &mut self.ctx.vstack[idx]
    }

    /// Get vtop[-1] (second from top).
    #[inline]
    #[allow(dead_code)]
    pub(crate) fn vtop_1(&self) -> &SValue {
        &self.ctx.vstack[(self.ctx.vtop_idx - 1) as usize]
    }

    /// Mutably get vtop[-1].
    #[inline]
    #[allow(dead_code)]
    pub(crate) fn vtop_1_mut(&mut self) -> &mut SValue {
        let idx = (self.ctx.vtop_idx - 1) as usize;
        &mut self.ctx.vstack[idx]
    }

    /// Get vtop[-n].
    #[inline]
    #[allow(dead_code)]
    pub(crate) fn vtop_n(&self, n: i32) -> &SValue {
        &self.ctx.vstack[(self.ctx.vtop_idx - n) as usize]
    }

    /// Decrement the value stack top index (pop one entry).
    #[inline]
    pub(crate) fn vtop_dec(&mut self) {
        self.ctx.vtop_idx -= 1;
    }

    /// Ensure the code buffer can hold `new_ind` bytes.
    fn ensure_code_buf(&mut self, new_ind: usize) {
        if new_ind > self.ctx.code_buf.len() {
            let new_size = (new_ind + 256).next_power_of_two();
            self.ctx.code_buf.resize(new_size, 0);
        }
    }

    /// Store a pending relocation entry for a named symbol.
    pub(crate) fn add_reloc_named(&mut self, offset: u64, reloc_type: u32, sym_name: &str) {
        self.pending_relocs.push(PendingReloc {
            offset,
            reloc_type,
            symbol_name: Some(sym_name.to_string()),
            symbol_v: None,
            symbol_c: None,
        });
    }

    /// Store a pending relocation entry for a known symbol (from SValue.sym).
    pub(crate) fn add_reloc_sym(&mut self, offset: u64, reloc_type: u32, sym: &Sym) {
        self.pending_relocs.push(PendingReloc {
            offset,
            reloc_type,
            symbol_name: None,
            symbol_v: Some(sym.v),
            symbol_c: Some(sym.c),
        });
    }

    /// Store a pending relocation entry with no symbol (patched inline).
    pub(crate) fn add_reloc_bare(&mut self, offset: u64, reloc_type: u32) {
        self.pending_relocs.push(PendingReloc {
            offset,
            reloc_type,
            symbol_name: None,
            symbol_v: None,
            symbol_c: None,
        });
    }

    /// Read a little-endian u32 from code_buf at byte offset.
    fn read_code_le32(&self, offset: usize) -> u32 {
        if offset + 4 <= self.ctx.code_buf.len() {
            read32le(&self.ctx.code_buf[offset..offset + 4])
        } else {
            0
        }
    }

    /// Write a little-endian u32 to code_buf at byte offset.
    fn write_code_le32(&mut self, offset: usize, val: u32) {
        self.ensure_code_buf(offset + 4);
        write32le(&mut self.ctx.code_buf[offset..offset + 4], val);
    }
}

// ===========================================================================
// Core instruction emission
// ===========================================================================

/// Emit a 32-bit instruction word to the code buffer.
/// Port of c67-gen.c lines 189-205.
fn c67_g(backend: &mut C67Backend, c: u32) {
    if backend.ctx.nocode_wanted != 0 {
        return;
    }
    let ind = backend.ctx.ind as usize;
    backend.ensure_code_buf(ind + 4);
    write32le(&mut backend.ctx.code_buf[ind..ind + 4], c);
    backend.ctx.ind += 4;
}

// ===========================================================================
// Core instruction encoder — port of C67_asm()
// c67-gen.c lines 374-1194
// ===========================================================================

/// Encode and emit a C67 instruction.
///
/// This is the core instruction encoder. Each instruction variant maps to a
/// specific 32-bit encoding with fields for condition register, source/dest
/// registers, opcode, side, cross-path, and parallel execution bit.
fn c67_asm(backend: &mut C67Backend, instr: C67Instr, a: i32, b: i32, c: i32) {
    let au = a as u32;
    #[allow(unused_variables)]
    let bu = b as u32;
    #[allow(unused_variables)]
    let cu = c as u32;

    let inst: u32 = match instr {
        // ===== MVKL: Move constant low 16 bits =====
        C67Instr::Mvkl => {
            let mut v: u32 = 0xa << 2;
            v |= (au & 0xffff) << 7;
            v |= (c67_map_regn(b) as u32 & 0x1f) << 23;
            v |= (c67_map_regs(b) as u32) << 1;
            v
        }
        // ===== MVKH: Move constant high 16 bits =====
        C67Instr::Mvkh => {
            let mut v: u32 = 0xe << 2;
            v |= ((au >> 16) & 0xffff) << 7;
            v |= (c67_map_regn(b) as u32 & 0x1f) << 23;
            v |= (c67_map_regs(b) as u32) << 1;
            v
        }
        // ===== STW.D SP POST DEC (push) =====
        C67Instr::StwSpPostDec => {
            let mut v: u32 = 0x0f74 << 2;
            v |= (c67_map_regn(a) as u32 & 0x1f) << 23;
            v |= (c67_map_regn(b) as u32 & 0x1f) << 18;
            v |= (c67_map_regn(C67_SP) as u32 & 0x1f) << 13;
            v |= c67_map_regs(C67_SP) as u32;
            v
        }
        // ===== STB/STH/STW.D *+SP[A0] =====
        C67Instr::StbSpA0 => encode_sp_a0_store(0x0174, a, b),
        C67Instr::SthSpA0 => encode_sp_a0_store(0x0574, a, b),
        C67Instr::StwSpA0 => encode_sp_a0_store(0x0f74, a, b),

        // ===== Store via pointer =====
        C67Instr::StbPtr => encode_ptr_store(0x0174, a, b, c),
        C67Instr::SthPtr => encode_ptr_store(0x0574, a, b, c),
        C67Instr::StwPtr => encode_ptr_store(0x0f74, a, b, c),

        // ===== STW.D +* (pre-increment) =====
        C67Instr::StwPtrPreInc => {
            let mut v: u32 = 0x0f74 << 2;
            v |= (c67_map_regn(a) as u32 & 0x1f) << 23;
            v |= (c67_map_regn(b) as u32 & 0x1f) << 18;
            v |= (cu & 0x1f) << 13; // constant offset
            v |= (c67_map_regs(b) as u32) << 1;
            v |= 1 << 9; // pre-increment mode
            v
        }

        // ===== LDW/LDDW.D SP PRE INC (pop/pop_dw) =====
        C67Instr::LdwSpPreInc => {
            let mut v: u32 = 0x0f6c << 2;
            v |= (c67_map_regn(a) as u32 & 0x1f) << 23;
            v |= (c67_map_regn(b) as u32 & 0x1f) << 18;
            v |= (c67_map_regn(C67_SP) as u32 & 0x1f) << 13;
            v |= c67_map_regs(C67_SP) as u32;
            v
        }
        C67Instr::LddwSpPreInc => {
            let mut v: u32 = 0x0f4c << 2;
            v |= (c67_map_regn(a) as u32 & 0x1f) << 23;
            v |= (c67_map_regn(b) as u32 & 0x1f) << 18;
            v |= (c67_map_regn(C67_SP) as u32 & 0x1f) << 13;
            v |= c67_map_regs(C67_SP) as u32;
            v
        }

        // ===== Load via SP + A0 index =====
        C67Instr::LdwSpA0  => encode_sp_a0_load(0x0f6c, a, b),
        C67Instr::LddwSpA0 => encode_sp_a0_load(0x0f4c, a, b),
        C67Instr::LdhSpA0  => encode_sp_a0_load(0x046c, a, b),
        C67Instr::LdbSpA0  => encode_sp_a0_load(0x006c, a, b),
        C67Instr::LdhuSpA0 => encode_sp_a0_load(0x076c, a, b),
        C67Instr::LdbuSpA0 => encode_sp_a0_load(0x016c, a, b),

        // ===== Load via pointer =====
        C67Instr::LdwPtr  => encode_ptr_load(0x0f6c, a, b, c),
        C67Instr::LddwPtr => encode_ptr_load(0x0f4c, a, b, c),
        C67Instr::LdhPtr  => encode_ptr_load(0x046c, a, b, c),
        C67Instr::LdbPtr  => encode_ptr_load(0x006c, a, b, c),
        C67Instr::LdhuPtr => encode_ptr_load(0x076c, a, b, c),
        C67Instr::LdbuPtr => encode_ptr_load(0x016c, a, b, c),

        // ===== LDW.D +* (pre-increment load) =====
        C67Instr::LdwPtrPreInc => {
            let mut v: u32 = 0x0f6c << 2;
            v |= (c67_map_regn(a) as u32 & 0x1f) << 23;
            v |= (c67_map_regn(b) as u32 & 0x1f) << 18;
            v |= (cu & 0x1f) << 13;
            v |= (c67_map_regs(b) as u32) << 1;
            v |= 1 << 9;
            v
        }

        // ===== Float compares (.S unit) =====
        C67Instr::CmpltSp => encode_s_float_cmp(0x3a, a, b, c),
        C67Instr::CmpgtSp => encode_s_float_cmp(0x3b, a, b, c),
        C67Instr::CmpeqSp => encode_s_float_cmp(0x3c, a, b, c),
        C67Instr::CmpltDp => encode_s_float_cmp(0x2a, a, b, c),
        C67Instr::CmpgtDp => encode_s_float_cmp(0x2b, a, b, c),
        C67Instr::CmpeqDp => encode_s_float_cmp(0x2c, a, b, c),

        // ===== Integer compares (.L unit) =====
        C67Instr::Cmplt  => encode_l_int_cmp(0x57, a, b, c),
        C67Instr::Cmpgt  => encode_l_int_cmp(0x47, a, b, c),
        C67Instr::Cmpeq  => encode_l_int_cmp(0x53, a, b, c),
        C67Instr::Cmpltu => encode_l_int_cmp(0x5f, a, b, c),
        C67Instr::Cmpgtu => encode_l_int_cmp(0x4f, a, b, c),

        // ===== Branch =====
        C67Instr::BDisp => {
            // B DISP — c67-gen.c lines 802-821
            let mut v: u32 = 0x10 << 2;
            v |= (au & 0x1fffff) << 7;
            v |= (c67_map_regc(backend.gen_state.c67_compare_reg) as u32) << 29;
            if backend.gen_state.c67_invert_test {
                v |= 1 << 28;
            }
            v
        }
        C67Instr::BS2x => {
            // B.S2x (register indirect) — c67-gen.c lines 810-821
            let mut v: u32 = (0x0d << 26) | (0x0 << 2);
            v |= (c67_map_regn(a) as u32 & 0x1f) << 18;
            // xpath: cross if src is A-side, B.S2x needs B-side dispatch
            v |= (c67_map_regs(a) as u32 ^ 1) << 12;
            v |= 1; // side = B (S2)
            v |= (c67_map_regc(backend.gen_state.c67_compare_reg) as u32) << 29;
            if backend.gen_state.c67_invert_test {
                v |= 1 << 28;
            }
            v
        }

        // ===== Move/Convert (.L unit) =====
        C67Instr::MvL => {
            // MV.L — c67-gen.c lines 822-838
            let opcode: u32 = 0x02;
            let mut v: u32 = (opcode << 5) | (0x6 << 2);
            v |= (c67_map_regn(c) as u32 & 0x1f) << 23; // dst
            v |= (c67_map_regn(b) as u32 & 0x1f) << 18; // src2
            v |= ((c67_map_regs(b) as u32) ^ (c67_map_regs(c) as u32)) << 12; // xpath
            v |= (c67_map_regs(c) as u32) << 1; // side from dst
            v
        }
        C67Instr::SptruncL => encode_l_convert(0x0b, c, b),
        C67Instr::DptruncL => encode_l_convert(0x01, c, b),
        C67Instr::IntspL   => encode_l_convert(0x4a, c, b),
        C67Instr::IntspuL  => encode_l_convert(0x49, c, b),
        C67Instr::IntdpL   => encode_l_convert(0x39, c, b),
        C67Instr::IntdpuL  => encode_l_convert(0x3b, c, b),
        C67Instr::SpdpL => {
            // SPDP.L — c67-gen.c lines 928-938
            let opcode: u32 = 0x02;
            let mut v: u32 = (opcode << 6) | (0x8 << 2);
            v |= (c67_map_regn(c) as u32 & 0x1f) << 23;
            v |= (c67_map_regn(b) as u32 & 0x1f) << 18;
            v |= ((c67_map_regs(b) as u32) ^ (c67_map_regs(c) as u32)) << 12;
            v |= (c67_map_regs(c) as u32) << 1;
            v
        }
        C67Instr::DpspL => encode_l_convert(0x09, c, b),

        // ===== Integer arithmetic (.L unit) =====
        C67Instr::AddL => encode_l_arith(0x03, a, b, c),
        C67Instr::SubL => encode_l_arith(0x07, a, b, c),
        C67Instr::OrL  => encode_l_arith(0x7f, a, b, c),
        C67Instr::AndL => encode_l_arith(0x7b, a, b, c),
        C67Instr::XorL => encode_l_arith(0x6f, a, b, c),

        // ===== Float arithmetic (.L unit) =====
        C67Instr::AddspL => encode_l_arith(0x70, a, b, c),
        C67Instr::AdddpL => encode_l_arith(0x18, a, b, c),
        C67Instr::SubspL => encode_l_arith(0x71, a, b, c),
        C67Instr::SubdpL => encode_l_arith(0x19, a, b, c),

        // ===== Multiply (.M unit) =====
        C67Instr::MpyspM => encode_m_mult(0x1c, a, b, c),
        C67Instr::MpydpM => encode_m_mult(0x0e, a, b, c),
        C67Instr::MpyiM  => encode_m_mult(0x00, a, b, c),

        // ===== Shifts (.S unit) =====
        C67Instr::ShrS  => encode_s_shift(0x37, a, b, c),
        C67Instr::ShruS => encode_s_shift(0x27, a, b, c),
        C67Instr::ShlS  => encode_s_shift(0x33, a, b, c),

        // ===== ADDK =====
        C67Instr::Addk => {
            let mut v: u32 = 0x14 << 2;
            v |= ((au as u32) & 0xffff) << 7;
            v |= (c67_map_regn(b) as u32 & 0x1f) << 23;
            v |= (c67_map_regs(b) as u32) << 1;
            v
        }
        C67Instr::AdkkParallel => {
            let mut v: u32 = 0x14 << 2;
            v |= ((au as u32) & 0xffff) << 7;
            v |= (c67_map_regn(b) as u32 & 0x1f) << 23;
            v |= (c67_map_regs(b) as u32) << 1;
            v |= 1; // parallel bit
            v
        }

        // ===== NOP =====
        C67Instr::Nop => {
            let count = if au < 1 { 1 } else { au };
            ((count - 1) & 0xf) << 13
        }
    };

    c67_g(backend, inst);
}

// ===========================================================================
// Encoding helper functions for instruction format families
// ===========================================================================

/// Encode SP+A0 indexed store instruction.
fn encode_sp_a0_store(opcode_base: u32, a: i32, b: i32) -> u32 {
    let mut v: u32 = opcode_base << 2;
    v |= (c67_map_regn(a) as u32 & 0x1f) << 23;
    v |= (c67_map_regn(b) as u32 & 0x1f) << 18;
    v |= (c67_map_regn(C67_SP) as u32 & 0x1f) << 13;
    v |= (c67_map_regs(C67_SP) as u32) << 1;
    v
}

/// Encode pointer-based store instruction.
fn encode_ptr_store(opcode_base: u32, a: i32, b: i32, c: i32) -> u32 {
    let mut v: u32 = opcode_base << 2;
    v |= (c67_map_regn(a) as u32 & 0x1f) << 23;
    v |= (c67_map_regn(b) as u32 & 0x1f) << 18;
    v |= (c67_map_regn(c) as u32 & 0x1f) << 13;
    v |= ((c67_map_regs(c) as u32) ^ (c67_map_regs(b) as u32)) << 12;
    v |= (c67_map_regs(b) as u32) << 1;
    v
}

/// Encode SP+A0 indexed load instruction.
fn encode_sp_a0_load(opcode_base: u32, a: i32, b: i32) -> u32 {
    let mut v: u32 = opcode_base << 2;
    v |= (c67_map_regn(a) as u32 & 0x1f) << 23;
    v |= (c67_map_regn(b) as u32 & 0x1f) << 18;
    v |= (c67_map_regn(C67_SP) as u32 & 0x1f) << 13;
    v |= (c67_map_regs(C67_SP) as u32) << 1;
    v
}

/// Encode pointer-based load instruction.
fn encode_ptr_load(opcode_base: u32, a: i32, b: i32, c: i32) -> u32 {
    let mut v: u32 = opcode_base << 2;
    v |= (c67_map_regn(a) as u32 & 0x1f) << 23;
    v |= (c67_map_regn(b) as u32 & 0x1f) << 18;
    v |= (c67_map_regn(c) as u32 & 0x1f) << 13;
    v |= ((c67_map_regs(c) as u32) ^ (c67_map_regs(b) as u32)) << 12;
    v |= (c67_map_regs(b) as u32) << 1;
    v
}

/// Encode .S-unit floating-point comparison.
fn encode_s_float_cmp(opcode: u32, a: i32, b: i32, c: i32) -> u32 {
    let mut v: u32 = (opcode << 5) | (0x20 << 2);
    v |= (c67_map_regn(c) as u32 & 0x1f) << 23; // dst
    v |= (c67_map_regn(b) as u32 & 0x1f) << 18; // src2
    v |= (c67_map_regn(a) as u32 & 0x1f) << 13; // src1
    v |= ((c67_map_regs(a) as u32) ^ (c67_map_regs(b) as u32)) << 12; // xpath
    v |= (c67_map_regs(b) as u32) << 1; // side
    v
}

/// Encode .L-unit integer comparison.
fn encode_l_int_cmp(opcode: u32, a: i32, b: i32, c: i32) -> u32 {
    let mut v: u32 = (opcode << 5) | (0x6 << 2);
    v |= (c67_map_regn(c) as u32 & 0x1f) << 23; // dst
    v |= (c67_map_regn(b) as u32 & 0x1f) << 18; // src2
    v |= (c67_map_regn(a) as u32 & 0x1f) << 13; // src1
    v |= ((c67_map_regs(a) as u32) ^ (c67_map_regs(b) as u32)) << 12; // xpath
    v |= (c67_map_regs(b) as u32) << 1; // side
    v
}

/// Encode .L-unit convert/move (2-operand: src, dst).
fn encode_l_convert(opcode: u32, dst: i32, src: i32) -> u32 {
    let mut v: u32 = (opcode << 5) | (0x6 << 2);
    v |= (c67_map_regn(dst) as u32 & 0x1f) << 23;
    v |= (c67_map_regn(src) as u32 & 0x1f) << 18;
    v |= ((c67_map_regs(src) as u32) ^ (c67_map_regs(dst) as u32)) << 12;
    v |= (c67_map_regs(dst) as u32) << 1;
    v
}

/// Encode .L-unit arithmetic (3-operand: src1, src2, dst).
fn encode_l_arith(opcode: u32, a: i32, b: i32, c: i32) -> u32 {
    let mut v: u32 = (opcode << 5) | (0x6 << 2);
    v |= (c67_map_regn(c) as u32 & 0x1f) << 23; // dst
    v |= (c67_map_regn(b) as u32 & 0x1f) << 18; // src2
    v |= (c67_map_regn(a) as u32 & 0x1f) << 13; // src1
    v |= ((c67_map_regs(a) as u32) ^ (c67_map_regs(c) as u32)) << 12; // xpath
    v |= (c67_map_regs(c) as u32) << 1; // side from dst
    v
}

/// Encode .M-unit multiply (3-operand: src1, src2, dst).
fn encode_m_mult(opcode: u32, a: i32, b: i32, c: i32) -> u32 {
    let mut v: u32 = (opcode << 7) | (0x0 << 2);
    v |= (c67_map_regn(c) as u32 & 0x1f) << 23; // dst
    v |= (c67_map_regn(b) as u32 & 0x1f) << 18; // src2
    v |= (c67_map_regn(a) as u32 & 0x1f) << 13; // src1
    v |= ((c67_map_regs(a) as u32) ^ (c67_map_regs(c) as u32)) << 12;
    v |= (c67_map_regs(c) as u32) << 1;
    v
}

/// Encode .S-unit shift (3-operand: src1(shift), src2(val), dst).
fn encode_s_shift(opcode: u32, a: i32, b: i32, c: i32) -> u32 {
    let mut v: u32 = (opcode << 6) | (0x8 << 2);
    v |= (c67_map_regn(c) as u32 & 0x1f) << 23; // dst
    v |= (c67_map_regn(b) as u32 & 0x1f) << 18; // src2 (value)
    v |= (c67_map_regn(a) as u32 & 0x1f) << 13; // src1 (shift count)
    v |= ((c67_map_regs(a) as u32) ^ (c67_map_regs(c) as u32)) << 12;
    v |= (c67_map_regs(c) as u32) << 1;
    v
}

// ===========================================================================
// Convenience wrapper functions — thin wrappers around c67_asm
// ===========================================================================

fn c67_mvkl(b: &mut C67Backend, r: i32, fc: i32) {
    c67_asm(b, C67Instr::Mvkl, fc, r, 0);
}

fn c67_mvkh(b: &mut C67Backend, r: i32, fc: i32) {
    c67_asm(b, C67Instr::Mvkh, fc, r, 0);
}

fn c67_stb_sp_a0(b: &mut C67Backend, r: i32) {
    c67_asm(b, C67Instr::StbSpA0, r, C67_A0, 0);
}

fn c67_sth_sp_a0(b: &mut C67Backend, r: i32) {
    c67_asm(b, C67Instr::SthSpA0, r, C67_A0, 0);
}

fn c67_stw_sp_a0(b: &mut C67Backend, r: i32) {
    c67_asm(b, C67Instr::StwSpA0, r, C67_A0, 0);
}

fn c67_stb_ptr(b: &mut C67Backend, r: i32, ptr: i32) {
    c67_asm(b, C67Instr::StbPtr, r, C67_A0, ptr);
}

fn c67_sth_ptr(b: &mut C67Backend, r: i32, ptr: i32) {
    c67_asm(b, C67Instr::SthPtr, r, C67_A0, ptr);
}

fn c67_stw_ptr(b: &mut C67Backend, r: i32, ptr: i32) {
    c67_asm(b, C67Instr::StwPtr, r, C67_A0, ptr);
}

#[allow(dead_code)]
fn c67_stw_ptr_pre_inc(b: &mut C67Backend, r: i32, ptr: i32, off: i32) {
    c67_asm(b, C67Instr::StwPtrPreInc, r, ptr, off);
}

fn c67_push(b: &mut C67Backend, r: i32) {
    c67_asm(b, C67Instr::StwSpPostDec, r, C67_SP, 0);
}

fn c67_ldw_sp_a0(b: &mut C67Backend, r: i32) {
    c67_asm(b, C67Instr::LdwSpA0, r, C67_A0, 0);
}

fn c67_lddw_sp_a0(b: &mut C67Backend, r: i32) {
    c67_asm(b, C67Instr::LddwSpA0, r, C67_A0, 0);
}

fn c67_ldh_sp_a0(b: &mut C67Backend, r: i32) {
    c67_asm(b, C67Instr::LdhSpA0, r, C67_A0, 0);
}

fn c67_ldb_sp_a0(b: &mut C67Backend, r: i32) {
    c67_asm(b, C67Instr::LdbSpA0, r, C67_A0, 0);
}

fn c67_ldhu_sp_a0(b: &mut C67Backend, r: i32) {
    c67_asm(b, C67Instr::LdhuSpA0, r, C67_A0, 0);
}

fn c67_ldbu_sp_a0(b: &mut C67Backend, r: i32) {
    c67_asm(b, C67Instr::LdbuSpA0, r, C67_A0, 0);
}

fn c67_ldw_ptr(b: &mut C67Backend, r: i32, ptr: i32) {
    c67_asm(b, C67Instr::LdwPtr, r, C67_A0, ptr);
}

fn c67_lddw_ptr(b: &mut C67Backend, r: i32, ptr: i32) {
    c67_asm(b, C67Instr::LddwPtr, r, C67_A0, ptr);
}

fn c67_ldh_ptr(b: &mut C67Backend, r: i32, ptr: i32) {
    c67_asm(b, C67Instr::LdhPtr, r, C67_A0, ptr);
}

fn c67_ldb_ptr(b: &mut C67Backend, r: i32, ptr: i32) {
    c67_asm(b, C67Instr::LdbPtr, r, C67_A0, ptr);
}

fn c67_ldhu_ptr(b: &mut C67Backend, r: i32, ptr: i32) {
    c67_asm(b, C67Instr::LdhuPtr, r, C67_A0, ptr);
}

fn c67_ldbu_ptr(b: &mut C67Backend, r: i32, ptr: i32) {
    c67_asm(b, C67Instr::LdbuPtr, r, C67_A0, ptr);
}

fn c67_pop(b: &mut C67Backend, r: i32) {
    c67_asm(b, C67Instr::LdwSpPreInc, r, C67_SP, 0);
}

#[allow(dead_code)]
fn c67_pop_dw(b: &mut C67Backend, r: i32) {
    c67_asm(b, C67Instr::LddwSpPreInc, r, C67_SP, 0);
}

// --- Integer compares ---
fn c67_cmplt(b: &mut C67Backend, s1: i32, s2: i32, dst: i32) {
    c67_asm(b, C67Instr::Cmplt, s1, s2, dst);
}
fn c67_cmpgt(b: &mut C67Backend, s1: i32, s2: i32, dst: i32) {
    c67_asm(b, C67Instr::Cmpgt, s1, s2, dst);
}
fn c67_cmpeq(b: &mut C67Backend, s1: i32, s2: i32, dst: i32) {
    c67_asm(b, C67Instr::Cmpeq, s1, s2, dst);
}
fn c67_cmpltu(b: &mut C67Backend, s1: i32, s2: i32, dst: i32) {
    c67_asm(b, C67Instr::Cmpltu, s1, s2, dst);
}
fn c67_cmpgtu(b: &mut C67Backend, s1: i32, s2: i32, dst: i32) {
    c67_asm(b, C67Instr::Cmpgtu, s1, s2, dst);
}

// --- Float compares ---
fn c67_cmpltsp(b: &mut C67Backend, s1: i32, s2: i32, dst: i32) {
    c67_asm(b, C67Instr::CmpltSp, s1, s2, dst);
}
fn c67_cmpgtsp(b: &mut C67Backend, s1: i32, s2: i32, dst: i32) {
    c67_asm(b, C67Instr::CmpgtSp, s1, s2, dst);
}
fn c67_cmpeqsp(b: &mut C67Backend, s1: i32, s2: i32, dst: i32) {
    c67_asm(b, C67Instr::CmpeqSp, s1, s2, dst);
}
fn c67_cmpltdp(b: &mut C67Backend, s1: i32, s2: i32, dst: i32) {
    c67_asm(b, C67Instr::CmpltDp, s1, s2, dst);
}
fn c67_cmpgtdp(b: &mut C67Backend, s1: i32, s2: i32, dst: i32) {
    c67_asm(b, C67Instr::CmpgtDp, s1, s2, dst);
}
fn c67_cmpeqdp(b: &mut C67Backend, s1: i32, s2: i32, dst: i32) {
    c67_asm(b, C67Instr::CmpeqDp, s1, s2, dst);
}

// --- Branch ---
#[allow(dead_code)]
fn c67_ireg_b_reg(b: &mut C67Backend, inv: i32, creg: i32, src: i32) {
    b.gen_state.c67_invert_test = inv != 0;
    b.gen_state.c67_compare_reg = creg;
    c67_asm(b, C67Instr::BS2x, src, 0, 0);
}

#[allow(dead_code)]
fn c67_b_disp(b: &mut C67Backend, disp: i32) {
    c67_asm(b, C67Instr::BDisp, disp, 0, 0);
}

fn c67_nop(b: &mut C67Backend, count: i32) {
    c67_asm(b, C67Instr::Nop, count, 0, 0);
}

fn c67_addk(b: &mut C67Backend, val: i32, r: i32) {
    c67_asm(b, C67Instr::Addk, val, r, 0);
}

fn c67_addk_parallel(b: &mut C67Backend, val: i32, r: i32) {
    c67_asm(b, C67Instr::AdkkParallel, val, r, 0);
}

/// Patch an ADDK instruction at `offset` with new constant value.
fn c67_adjust_addk(b: &mut C67Backend, offset: u64, val: i32) {
    let off = offset as usize;
    let mut inst = b.read_code_le32(off);
    inst &= !(0xffff << 7); // clear old constant field
    inst |= ((val as u32) & 0xffff) << 7;
    b.write_code_le32(off, inst);
}

fn c67_mv(b: &mut C67Backend, dst: i32, src: i32) {
    c67_asm(b, C67Instr::MvL, 0, src, dst);
}

fn c67_dptrunc(b: &mut C67Backend, dst: i32, src: i32) {
    c67_asm(b, C67Instr::DptruncL, 0, src, dst);
}
fn c67_sptrunc(b: &mut C67Backend, dst: i32, src: i32) {
    c67_asm(b, C67Instr::SptruncL, 0, src, dst);
}

fn c67_intsp(b: &mut C67Backend, dst: i32, src: i32) {
    c67_asm(b, C67Instr::IntspL, 0, src, dst);
}
fn c67_intdp(b: &mut C67Backend, dst: i32, src: i32) {
    c67_asm(b, C67Instr::IntdpL, 0, src, dst);
}
fn c67_intspu(b: &mut C67Backend, dst: i32, src: i32) {
    c67_asm(b, C67Instr::IntspuL, 0, src, dst);
}
fn c67_intdpu(b: &mut C67Backend, dst: i32, src: i32) {
    c67_asm(b, C67Instr::IntdpuL, 0, src, dst);
}

fn c67_spdp(b: &mut C67Backend, dst: i32, src: i32) {
    c67_asm(b, C67Instr::SpdpL, 0, src, dst);
}
fn c67_dpsp(b: &mut C67Backend, dst: i32, src: i32) {
    c67_asm(b, C67Instr::DpspL, 0, src, dst);
}

// --- Integer arithmetic ---
fn c67_add(b: &mut C67Backend, r: i32, v: i32) {
    c67_asm(b, C67Instr::AddL, v, r, v);
}
fn c67_sub(b: &mut C67Backend, r: i32, v: i32) {
    c67_asm(b, C67Instr::SubL, v, r, v);
}
fn c67_and(b: &mut C67Backend, r: i32, v: i32) {
    c67_asm(b, C67Instr::AndL, v, r, v);
}
fn c67_or(b: &mut C67Backend, r: i32, v: i32) {
    c67_asm(b, C67Instr::OrL, v, r, v);
}
fn c67_xor(b: &mut C67Backend, r: i32, v: i32) {
    c67_asm(b, C67Instr::XorL, v, r, v);
}

// --- Float arithmetic ---
fn c67_addsp(b: &mut C67Backend, r: i32, v: i32) {
    c67_asm(b, C67Instr::AddspL, v, r, v);
}
fn c67_subsp(b: &mut C67Backend, r: i32, v: i32) {
    c67_asm(b, C67Instr::SubspL, v, r, v);
}
fn c67_mpysp(b: &mut C67Backend, r: i32, v: i32) {
    c67_asm(b, C67Instr::MpyspM, v, r, v);
}

fn c67_adddp(b: &mut C67Backend, r: i32, v: i32) {
    c67_asm(b, C67Instr::AdddpL, v, r, v);
}
fn c67_subdp(b: &mut C67Backend, r: i32, v: i32) {
    c67_asm(b, C67Instr::SubdpL, v, r, v);
}
fn c67_mpydp(b: &mut C67Backend, r: i32, v: i32) {
    c67_asm(b, C67Instr::MpydpM, v, r, v);
}

fn c67_mpyi(b: &mut C67Backend, r: i32, v: i32) {
    c67_asm(b, C67Instr::MpyiM, v, r, v);
}

// --- Shifts ---
fn c67_shl(b: &mut C67Backend, r: i32, v: i32) {
    c67_asm(b, C67Instr::ShlS, r, v, v);
}
fn c67_shru(b: &mut C67Backend, r: i32, v: i32) {
    c67_asm(b, C67Instr::ShruS, r, v, v);
}
fn c67_shr(b: &mut C67Backend, r: i32, v: i32) {
    c67_asm(b, C67Instr::ShrS, r, v, v);
}

// ===========================================================================
// Helper: emit MVKL/MVKH pair to load a 32-bit address with relocations
// ===========================================================================

/// Emit MVKL/MVKH pair for loading a symbol address into register `r`.
/// Stores two pending relocations (R_C60LO16 and R_C60HI16).
fn emit_mvkl_mvkh_reloc_named(
    b: &mut C67Backend,
    r: i32,
    fc: i32,
    sym_name: &str,
) {
    let lo_off = b.ctx.ind as u64;
    c67_mvkl(b, r, fc);
    let hi_off = b.ctx.ind as u64;
    c67_mvkh(b, r, fc);

    b.add_reloc_named(lo_off, R_C60LO16, sym_name);
    b.add_reloc_named(hi_off, R_C60HI16, sym_name);
}

/// Emit MVKL/MVKH pair with relocations referencing an existing Sym.
#[allow(dead_code)]
fn emit_mvkl_mvkh_reloc_sym(
    b: &mut C67Backend,
    r: i32,
    fc: i32,
    sym: &Sym,
) {
    let lo_off = b.ctx.ind as u64;
    c67_mvkl(b, r, fc);
    let hi_off = b.ctx.ind as u64;
    c67_mvkh(b, r, fc);

    b.add_reloc_sym(lo_off, R_C60LO16, sym);
    b.add_reloc_sym(hi_off, R_C60HI16, sym);
}

/// Emit MVKL/MVKH pair with bare (no-symbol) relocations.
fn emit_mvkl_mvkh_reloc_bare(
    b: &mut C67Backend,
    r: i32,
    fc: i32,
) {
    let lo_off = b.ctx.ind as u64;
    c67_mvkl(b, r, fc);
    let hi_off = b.ctx.ind as u64;
    c67_mvkh(b, r, fc);

    b.add_reloc_bare(lo_off, R_C60LO16);
    b.add_reloc_bare(hi_off, R_C60HI16);
}

/// Emit a helper function call sequence: move args, MVKL/MVKH addr,
/// branch via B3, NOP delay. Used for division/modulo.
fn emit_helper_call(b: &mut C67Backend, helper_name: &str, fr: i32, r: i32) {
    // Move operands to parameter registers A4, B4 if not already there
    if r != TREG_C67_A4 {
        c67_mv(b, TREG_C67_A4, r);
    }
    if fr != TREG_C67_B4 {
        c67_mv(b, TREG_C67_B4, fr);
    }

    // Load helper function address via MVKL/MVKH with named relocation
    emit_mvkl_mvkh_reloc_named(b, TREG_EDX, 0, helper_name);

    // Branch to helper
    b.gen_state.c67_invert_test = false;
    b.gen_state.c67_compare_reg = C67_CREG_ZERO;
    c67_asm(b, C67Instr::BS2x, TREG_EDX, 0, 0);

    // 5 NOP delay slots for branch
    c67_nop(b, 5);
}

// ===========================================================================
// Private helper: gcall_or_jmp
// Port of c67-gen.c lines 1816-1869
// ===========================================================================

/// Generate a function call or jump to a symbol/register target.
fn gcall_or_jmp(b: &mut C67Backend, is_jmp: bool) -> TccResult<()> {
    let vtop_idx = b.ctx.vtop_idx as usize;
    let vtop_r = b.ctx.vstack[vtop_idx].r as i32;
    // SAFETY: CValue.i is the canonical integer field of the union,
    // holding the constant value/offset for this vstack entry.
    let vtop_c_i = unsafe { b.ctx.vstack[vtop_idx].c.i } as i32;

    if (vtop_r & (VT_VALMASK | VT_LVAL)) == VT_CONST {
        // Constant target (possibly with symbol)
        let has_sym = (vtop_r & VT_SYM) != 0;

        // Load function address into B3 via MVKL/MVKH with relocation
        let lo_off = b.ctx.ind as u64;
        c67_mvkl(b, C67_B3, vtop_c_i);
        let hi_off = b.ctx.ind as u64;
        c67_mvkh(b, C67_B3, vtop_c_i);

        if has_sym {
            // Extract sym info before mutating self to avoid borrow conflict
            let sym_info = b.ctx.vstack[vtop_idx].sym.as_ref().map(|s| (s.v, s.c));
            if let Some((sv, sc)) = sym_info {
                b.pending_relocs.push(PendingReloc {
                    offset: lo_off,
                    reloc_type: R_C60LO16,
                    symbol_name: None,
                    symbol_v: Some(sv),
                    symbol_c: Some(sc),
                });
                b.pending_relocs.push(PendingReloc {
                    offset: hi_off,
                    reloc_type: R_C60HI16,
                    symbol_name: None,
                    symbol_v: Some(sv),
                    symbol_c: Some(sc),
                });
            }
        }

        // Branch to B3
        b.gen_state.c67_invert_test = false;
        b.gen_state.c67_compare_reg = C67_CREG_ZERO;
        c67_asm(b, C67Instr::BS2x, C67_B3, 0, 0);
        c67_nop(b, 5);
    } else {
        // Indirect call/jump via register
        let target_r = vtop_r & VT_VALMASK;
        b.gen_state.c67_invert_test = false;
        b.gen_state.c67_compare_reg = C67_CREG_ZERO;
        c67_asm(b, C67Instr::BS2x, target_r, 0, 0);
        c67_nop(b, 5);
    }
    let _ = is_jmp; // Both call and jump use same instruction sequence on C67
    Ok(())
}

// ===========================================================================
// PUBLIC EXPORTED FUNCTIONS — CodegenBackend trait implementations
// ===========================================================================

/// Resolve forward branch targets.
/// Port of c67-gen.c lines 209-234.
///
/// Walks a chain of MVKH/MVKL instruction pairs, extracting the next link
/// from their 16-bit constant fields, then patches with relocations.
pub fn gsym_addr(backend: &mut C67Backend, mut t: i32, a: i32) -> TccResult<()> {
    while t != 0 {
        let t_off = t as usize;
        // Read MVKL instruction to extract next link (low 16 bits at bits 7..22)
        let mvkl_inst = backend.read_code_le32(t_off);
        let lo = (mvkl_inst >> 7) & 0xffff;

        // Read MVKH instruction (next word) to extract high 16 bits
        let mvkh_inst = backend.read_code_le32(t_off + 4);
        let hi = (mvkh_inst >> 7) & 0xffff;

        // Combine to get next link in chain
        let next = ((hi << 16) | lo) as i32;

        // Patch this MVKL/MVKH pair with the target address
        // Clear old constant fields and set new address
        let new_mvkl = (mvkl_inst & !(0xffff << 7)) | (((a as u32) & 0xffff) << 7);
        let new_mvkh = (mvkh_inst & !(0xffff << 7)) | ((((a as u32) >> 16) & 0xffff) << 7);
        backend.write_code_le32(t_off, new_mvkl);
        backend.write_code_le32(t_off + 4, new_mvkh);

        // Store relocations for symbol resolution
        backend.add_reloc_bare(t_off as u64, R_C60LO16);
        backend.add_reloc_bare((t_off + 4) as u64, R_C60HI16);

        t = next;
    }
    Ok(())
}

/// Load value into register.
/// Port of c67-gen.c lines 1551-1709.
pub fn load(backend: &mut C67Backend, r: i32, sv: &SValue) -> TccResult<()> {
    let sv_r = sv.r as i32;
    let v: i32 = sv_r & VT_VALMASK;
    // SAFETY: CValue.i is the canonical integer field of the union,
    // holding the constant value or address offset for this SValue.
    let fc: i32 = unsafe { sv.c.i } as i32;
    let fr: i32 = sv_r & VT_VALMASK;

    if v == VT_LLOCAL {
        // Load local reference: first load the address, then load the value
        let local_sv = SValue {
            type_: CType { t: VT_INT, ref_sym: None },
            r: (VT_LOCAL | VT_LVAL) as u16,
            r2: 0,
            c: sv.c,
            sym: None,
            cmp_op: 0,
            cmp_r: 0,
            jtrue: 0,
            jfalse: 0,
        };
        // Recursive load: load the address into r
        load(backend, r, &local_sv)?;
        // Now use the loaded pointer to do the actual load
        let deref_sv = SValue {
            type_: sv.type_.clone(),
            r: (r as u16) | (VT_LVAL as u16),
            r2: 0,
            c: CValue { i: 0 },
            sym: None,
            cmp_op: 0,
            cmp_r: 0,
            jtrue: 0,
            jfalse: 0,
        };
        load(backend, r, &deref_sv)?;
        return Ok(());
    }

    if (sv_r & VT_LVAL) != 0 {
        // Load from memory
        let bt = sv.type_.t & VT_BTYPE;

        if v == VT_LOCAL {
            // Check if this is a parameter that was passed in a register
            if fc < backend.gen_state.total_bytes_pushed_on_stack as i32 {
                // Check translate table
                for i in 0..backend.gen_state.no_of_cur_func_args {
                    if backend.gen_state.param_loc_on_stack[i] == fc {
                        let src_reg = backend.gen_state.translate_stack_to_reg[i];
                        if bt == VT_DOUBLE {
                            c67_mv(backend, r, src_reg);
                            c67_mv(backend, r + 1, src_reg + 1);
                        } else {
                            c67_mv(backend, r, src_reg);
                        }
                        return Ok(());
                    }
                }
            }

            // Load from stack via SP + A0 offset
            c67_mvkl(backend, C67_A0, fc);
            c67_mvkh(backend, C67_A0, fc);

            match bt {
                VT_BYTE => {
                    if (sv.type_.t & VT_UNSIGNED) != 0 {
                        c67_ldbu_sp_a0(backend, r);
                    } else {
                        c67_ldb_sp_a0(backend, r);
                    }
                }
                VT_SHORT => {
                    if (sv.type_.t & VT_UNSIGNED) != 0 {
                        c67_ldhu_sp_a0(backend, r);
                    } else {
                        c67_ldh_sp_a0(backend, r);
                    }
                }
                VT_DOUBLE => c67_lddw_sp_a0(backend, r),
                _ => c67_ldw_sp_a0(backend, r),
            }
            // Load needs 4 NOP delay slots
            c67_nop(backend, 4);
        } else if v == VT_CONST {
            // Load from constant address (possibly with symbol)
            if (sv_r & VT_SYM) != 0 {
                let lo_off = backend.ctx.ind as u64;
                c67_mvkl(backend, C67_A0, fc);
                let hi_off = backend.ctx.ind as u64;
                c67_mvkh(backend, C67_A0, fc);

                if let Some(ref sym) = sv.sym {
                    backend.add_reloc_sym(lo_off, R_C60LO16, sym);
                    backend.add_reloc_sym(hi_off, R_C60HI16, sym);
                } else {
                    backend.add_reloc_bare(lo_off, R_C60LO16);
                    backend.add_reloc_bare(hi_off, R_C60HI16);
                }
            } else {
                c67_mvkl(backend, C67_A0, fc);
                c67_mvkh(backend, C67_A0, fc);
            }

            match bt {
                VT_BYTE => {
                    if (sv.type_.t & VT_UNSIGNED) != 0 {
                        c67_ldbu_ptr(backend, r, C67_A0);
                    } else {
                        c67_ldb_ptr(backend, r, C67_A0);
                    }
                }
                VT_SHORT => {
                    if (sv.type_.t & VT_UNSIGNED) != 0 {
                        c67_ldhu_ptr(backend, r, C67_A0);
                    } else {
                        c67_ldh_ptr(backend, r, C67_A0);
                    }
                }
                VT_DOUBLE => c67_lddw_ptr(backend, r, C67_A0),
                _ => c67_ldw_ptr(backend, r, C67_A0),
            }
            c67_nop(backend, 4);
        } else {
            // Load via register pointer
            match bt {
                VT_BYTE => {
                    if (sv.type_.t & VT_UNSIGNED) != 0 {
                        c67_ldbu_ptr(backend, r, fr);
                    } else {
                        c67_ldb_ptr(backend, r, fr);
                    }
                }
                VT_SHORT => {
                    if (sv.type_.t & VT_UNSIGNED) != 0 {
                        c67_ldhu_ptr(backend, r, fr);
                    } else {
                        c67_ldh_ptr(backend, r, fr);
                    }
                }
                VT_DOUBLE => c67_lddw_ptr(backend, r, fr),
                _ => c67_ldw_ptr(backend, r, fr),
            }
            c67_nop(backend, 4);
        }
    } else {
        // Non-lval: immediate/constant/comparison result
        if v == VT_CONST {
            if (sv_r & VT_SYM) != 0 {
                let lo_off = backend.ctx.ind as u64;
                c67_mvkl(backend, r, fc);
                let hi_off = backend.ctx.ind as u64;
                c67_mvkh(backend, r, fc);

                if let Some(ref sym) = sv.sym {
                    backend.add_reloc_sym(lo_off, R_C60LO16, sym);
                    backend.add_reloc_sym(hi_off, R_C60HI16, sym);
                } else {
                    backend.add_reloc_bare(lo_off, R_C60LO16);
                    backend.add_reloc_bare(hi_off, R_C60HI16);
                }
            } else {
                c67_mvkl(backend, r, fc);
                c67_mvkh(backend, r, fc);
            }
        } else if v == VT_LOCAL {
            c67_mvkl(backend, r, fc);
            c67_mvkh(backend, r, fc);
            c67_add(backend, C67_FP, r);
        } else if v == VT_CMP {
            // Comparison result — already in compare register
            c67_mv(backend, r, backend.gen_state.c67_compare_reg);
        } else if v == VT_JMP || v == VT_JMPI {
            // Jump: set 1 or 0 based on condition
            c67_mvkl(backend, r, if v == VT_JMPI { 1 } else { 0 });
            // Resolve pending forward jump
            let target = fc;
            gsym_addr(backend, target, backend.ctx.ind)?;
            c67_mvkl(backend, r, if v == VT_JMPI { 0 } else { 1 });
        } else if v != r {
            // Register move
            c67_mv(backend, r, v);
            if (sv.type_.t & VT_BTYPE) == VT_DOUBLE {
                // For doubles, also move the high register
                c67_mv(backend, r + 1, v + 1);
            }
        }
    }
    Ok(())
}

/// Store register to memory.
/// Port of c67-gen.c lines 1713-1813.
pub fn store(backend: &mut C67Backend, r: i32, sv: &SValue) -> TccResult<()> {
    let sv_r = sv.r as i32;
    let v = sv_r & VT_VALMASK;
    // SAFETY: CValue.i is the canonical integer field of the union,
    // holding the constant value or address offset for this SValue.
    let fc = unsafe { sv.c.i } as i32;
    let bt = sv.type_.t & VT_BTYPE;

    if (sv_r & VT_LVAL) != 0 || v == VT_LOCAL {
        if v == VT_CONST && (sv_r & VT_SYM) != 0 {
            // Store to constant symbol address
            let lo_off = backend.ctx.ind as u64;
            c67_mvkl(backend, C67_A0, fc);
            let hi_off = backend.ctx.ind as u64;
            c67_mvkh(backend, C67_A0, fc);

            if let Some(ref sym) = sv.sym {
                backend.add_reloc_sym(lo_off, R_C60LO16, sym);
                backend.add_reloc_sym(hi_off, R_C60HI16, sym);
            } else {
                backend.add_reloc_bare(lo_off, R_C60LO16);
                backend.add_reloc_bare(hi_off, R_C60HI16);
            }

            match bt {
                VT_BYTE => c67_stb_ptr(backend, r, C67_A0),
                VT_SHORT => c67_sth_ptr(backend, r, C67_A0),
                VT_DOUBLE => {
                    c67_stw_ptr(backend, r, C67_A0);
                    c67_addk(backend, 4, C67_A0);
                    c67_stw_ptr(backend, r + 1, C67_A0);
                }
                _ => c67_stw_ptr(backend, r, C67_A0),
            }
        } else if v == VT_LOCAL {
            // Check if this is a parameter in a register
            for i in 0..backend.gen_state.no_of_cur_func_args {
                if backend.gen_state.param_loc_on_stack[i] == fc {
                    let dst_reg = backend.gen_state.translate_stack_to_reg[i];
                    if bt == VT_DOUBLE {
                        c67_mv(backend, dst_reg, r);
                        c67_mv(backend, dst_reg + 1, r + 1);
                    } else {
                        c67_mv(backend, dst_reg, r);
                    }
                    return Ok(());
                }
            }

            // Store to stack via SP + A0 offset
            c67_mvkl(backend, C67_A0, fc);
            c67_mvkh(backend, C67_A0, fc);

            match bt {
                VT_BYTE => c67_stb_sp_a0(backend, r),
                VT_SHORT => c67_sth_sp_a0(backend, r),
                VT_DOUBLE => {
                    c67_stw_sp_a0(backend, r);
                    c67_addk(backend, 4, C67_A0);
                    c67_stw_sp_a0(backend, r + 1);
                }
                _ => c67_stw_sp_a0(backend, r),
            }
        } else {
            // Store via register pointer
            let ptr = v;
            match bt {
                VT_BYTE => c67_stb_ptr(backend, r, ptr),
                VT_SHORT => c67_sth_ptr(backend, r, ptr),
                VT_DOUBLE => {
                    c67_stw_ptr(backend, r, ptr);
                    c67_addk(backend, 4, ptr);
                    c67_stw_ptr(backend, r + 1, ptr);
                }
                _ => c67_stw_ptr(backend, r, ptr),
            }
        }
    }
    Ok(())
}

/// Return struct-return info. C67 never returns structs in registers.
/// Port of c67-gen.c lines 1873-1876.
/// Returns (use_ptr, sret_type, sret_align, sret_size).
pub fn gfunc_sret(_backend: &C67Backend, _vt: &CType, _variadic: bool) -> (bool, CType, i32, i32) {
    // C67 never returns structs in regs — always use pointer
    (false, CType { t: 0, ref_sym: None }, 4, 4)
}

/// Generate function call.
/// Port of c67-gen.c lines 1880-1936.
pub fn gfunc_call(backend: &mut C67Backend, nb_args: i32) -> TccResult<()> {
    if nb_args as usize > MAX_FUNC_ARGS {
        return Err(TccError::codegen(
            "C67: too many function arguments (max 10)",
        ));
    }

    // Push arguments to stack in reverse order, then pop into parameter regs
    // C67 passes args in A4/A5, B4/B5, A6/A7, B6/B7, A8/A9, B8/B9,
    // A10/A11, B10/B11, A12/A13, B12/B13
    let param_regs = [
        TREG_C67_A4, TREG_C67_B4, TREG_C67_A6, TREG_C67_B6,
        TREG_C67_A8, TREG_C67_B8, TREG_C67_A10, TREG_C67_B10,
        TREG_C67_A12, TREG_C67_B12,
    ];

    // Move arguments from vstack into parameter registers
    // The arguments are on the vstack: vtop[-nb_args+1] through vtop[0]
    for i in 0..nb_args as usize {
        let stack_idx = (backend.ctx.vtop_idx - nb_args + 1 + i as i32) as usize;
        if stack_idx < backend.ctx.vstack.len() {
            let src_r = backend.ctx.vstack[stack_idx].r as i32 & VT_VALMASK;
            let target_r = param_regs[i];
            if src_r != target_r && src_r < NB_REGS as i32 {
                c67_mv(backend, target_r, src_r);
            }
        }
    }

    // Pop arguments from vstack (adjust vtop)
    backend.ctx.vtop_idx -= nb_args - 1;

    // Generate the call
    gcall_or_jmp(backend, false)?;

    // Pop the function pointer from vstack
    backend.ctx.vtop_idx -= 1;

    Ok(())
}

/// Generate function prologue.
/// Port of c67-gen.c lines 1949-2020.
pub fn gfunc_prolog(backend: &mut C67Backend, func_sym: &Sym) -> TccResult<()> {
    // Count parameters and track their stack locations
    let mut addr: i32 = 8; // start after saved FP and return addr
    let mut param_idx: usize = 0;

    backend.gen_state.no_of_cur_func_args = 0;
    backend.gen_state.total_bytes_pushed_on_stack = 0;

    let param_regs = [
        TREG_C67_A4, TREG_C67_B4, TREG_C67_A6, TREG_C67_B6,
        TREG_C67_A8, TREG_C67_B8, TREG_C67_A10, TREG_C67_B10,
        TREG_C67_A12, TREG_C67_B12,
    ];

    // Walk the parameter list. The func_sym.type_.ref_sym points to the
    // function type's symbol whose `next` chain lists parameters.
    // First sym in chain is return type; skip it.
    // Collect parameter info by iterating the chain safely.
    {
        let mut param_sizes: Vec<(i32, i32)> = Vec::new(); // (bt, size)

        // Get the first sym (return type), then iterate its `next` chain for params
        if let Some(ref func_type_sym) = func_sym.type_.ref_sym {
            let mut current: Option<&Sym> = func_type_sym.next.as_deref();
            while let Some(s) = current {
                let bt = s.type_.t & VT_BTYPE;
                let size = if bt == VT_DOUBLE { 8 } else { 4 };
                param_sizes.push((bt, size));
                current = s.next.as_deref();
            }
        }

        for (_bt, size) in &param_sizes {
            let align = *size;
            addr = (addr + align - 1) & !(align - 1);

            if param_idx < MAX_FUNC_ARGS {
                backend.gen_state.translate_stack_to_reg[param_idx] = param_regs[param_idx];
                backend.gen_state.param_loc_on_stack[param_idx] = addr;
                backend.gen_state.no_of_cur_func_args = param_idx + 1;
            }

            addr += size;
            param_idx += 1;
        }
    }

    backend.gen_state.total_bytes_pushed_on_stack = addr;

    // Emit prologue instructions:
    // 1. Save FP to A0, move SP to FP
    c67_mv(backend, C67_A0, C67_FP);
    c67_mv(backend, C67_FP, C67_SP);

    // 2. Push all register arguments to stack
    for i in (0..backend.gen_state.no_of_cur_func_args).rev() {
        c67_push(backend, param_regs[i]);
        if (backend.gen_state.param_loc_on_stack[i] > 0)
            && ((backend.gen_state.param_loc_on_stack[i] & 7) == 0)
        {
            // Double: push high register too
            c67_push(backend, param_regs[i] + 1);
        }
    }

    // 3. Reserve local variable space (patched later in epilog)
    backend.gen_state.func_sub_sp_offset = backend.ctx.ind as u64;
    c67_addk(backend, 0, C67_SP); // placeholder, patched in gfunc_epilog

    // 4. Push saved FP and return address
    c67_push(backend, C67_A0); // old FP
    c67_push(backend, C67_B3); // return address

    Ok(())
}

/// Generate function epilogue.
/// Port of c67-gen.c lines 2023-2037.
pub fn gfunc_epilog(backend: &mut C67Backend) -> TccResult<()> {
    // Pop B3 (return address)
    c67_pop(backend, C67_B3);
    c67_nop(backend, 4);

    // Pop FP
    c67_pop(backend, C67_FP);
    c67_nop(backend, 4);

    // Branch to B3 (return)
    backend.gen_state.c67_invert_test = false;
    backend.gen_state.c67_compare_reg = C67_CREG_ZERO;
    c67_asm(backend, C67Instr::BS2x, C67_B3, 0, 0);

    // Restore SP with ADDK (parallel with branch delay)
    let local_size = -(backend.ctx.loc) as i32;
    c67_addk_parallel(backend, local_size, C67_SP);
    c67_nop(backend, 4);

    // Patch the prologue's ADDK with actual local size
    c67_adjust_addk(backend, backend.gen_state.func_sub_sp_offset, -local_size);

    Ok(())
}

/// Fill N bytes with NOP instructions (4 bytes each).
/// Port of c67-gen.c lines 2039-2047.
pub fn gen_fill_nops(backend: &mut C67Backend, n: i32) -> TccResult<()> {
    let mut remaining = n;
    while remaining >= 4 {
        c67_nop(backend, 1);
        remaining -= 4;
    }
    Ok(())
}

/// Generate unconditional jump. Returns the jump target chain.
/// Port of c67-gen.c lines 2050-2061.
pub fn gjmp(backend: &mut C67Backend, t: i32) -> TccResult<i32> {
    let ret = backend.ctx.ind;

    // Emit MVKL/MVKH pair with the chain link encoded
    c67_mvkl(backend, C67_A0, t);
    c67_mvkh(backend, C67_A0, t);

    // Unconditional branch via B.S2x
    backend.gen_state.c67_invert_test = false;
    backend.gen_state.c67_compare_reg = C67_CREG_ZERO;
    c67_asm(backend, C67Instr::BS2x, C67_A0, 0, 0);
    c67_nop(backend, 5);

    Ok(ret)
}

/// Generate jump to absolute address.
/// Port of c67-gen.c lines 2063-2078.
pub fn gjmp_addr(backend: &mut C67Backend, a: i32) -> TccResult<()> {
    // Load address with MVKL/MVKH and branch
    emit_mvkl_mvkh_reloc_bare(backend, C67_A0, a);

    backend.gen_state.c67_invert_test = false;
    backend.gen_state.c67_compare_reg = C67_CREG_ZERO;
    c67_asm(backend, C67Instr::BS2x, C67_A0, 0, 0);
    c67_nop(backend, 5);
    Ok(())
}

/// Generate conditional jump based on comparison register.
/// Port of c67-gen.c lines 2081-2106.
pub fn gjmp_cond(backend: &mut C67Backend, op: i32, t: i32) -> TccResult<i32> {
    let ret = backend.ctx.ind;

    // Move compare result to B2 for conditional branch if needed
    if backend.gen_state.c67_compare_reg != C67_B2 {
        c67_mv(backend, C67_B2, backend.gen_state.c67_compare_reg);
        c67_nop(backend, 4);
    }

    // Encode MVKL/MVKH with chain link
    c67_mvkl(backend, C67_A0, t);
    c67_mvkh(backend, C67_A0, t);

    // Conditional branch — invert based on comparison type
    backend.gen_state.c67_compare_reg = C67_B2;
    backend.gen_state.c67_invert_test = op == TOK_EQ;
    c67_asm(backend, C67Instr::BS2x, C67_A0, 0, 0);
    c67_nop(backend, 5);

    Ok(ret)
}

/// Append jump target to forward reference chain.
/// Port of c67-gen.c lines 2108-2129.
pub fn gjmp_append(backend: &mut C67Backend, n0: i32, t: i32) -> TccResult<i32> {
    if n0 != 0 {
        // Walk the chain to find the end
        let mut p = n0;
        loop {
            let off = p as usize;
            let mvkl = backend.read_code_le32(off);
            let mvkh = backend.read_code_le32(off + 4);
            let lo = (mvkl >> 7) & 0xffff;
            let hi = (mvkh >> 7) & 0xffff;
            let next = ((hi << 16) | lo) as i32;
            if next == 0 {
                // Patch this entry with the new target
                let new_mvkl = (mvkl & !(0xffff << 7)) | (((t as u32) & 0xffff) << 7);
                let new_mvkh = (mvkh & !(0xffff << 7)) | ((((t as u32) >> 16) & 0xffff) << 7);
                backend.write_code_le32(off, new_mvkl);
                backend.write_code_le32(off + 4, new_mvkh);
                break;
            }
            p = next;
        }
        Ok(n0)
    } else {
        Ok(t)
    }
}

/// Integer binary operations.
/// Port of c67-gen.c lines 2132-2285.
///
/// Note: CodeGen has already called gv2(RC_INT, RC_INT) before this function,
/// so both operands are in registers.
pub fn gen_opi(backend: &mut C67Backend, op: i32) -> TccResult<()> {
    let vtop_idx = backend.ctx.vtop_idx as usize;
    let r = backend.ctx.vstack[vtop_idx - 1].r as i32 & VT_VALMASK;
    let fr = backend.ctx.vstack[vtop_idx].r as i32 & VT_VALMASK;

    match op {
        // --- Comparisons ---
        x if x == TOK_LT => {
            c67_cmplt(backend, fr, r, TREG_EDX);
            backend.gen_state.c67_compare_reg = TREG_EDX;
            backend.gen_state.c67_invert_test = false;
            set_vtop_cmp(backend);
        }
        x if x == TOK_GE => {
            c67_cmplt(backend, fr, r, TREG_EDX);
            backend.gen_state.c67_compare_reg = TREG_EDX;
            backend.gen_state.c67_invert_test = true;
            set_vtop_cmp(backend);
        }
        x if x == TOK_GT => {
            c67_cmpgt(backend, fr, r, TREG_EDX);
            backend.gen_state.c67_compare_reg = TREG_EDX;
            backend.gen_state.c67_invert_test = false;
            set_vtop_cmp(backend);
        }
        x if x == TOK_LE => {
            c67_cmpgt(backend, fr, r, TREG_EDX);
            backend.gen_state.c67_compare_reg = TREG_EDX;
            backend.gen_state.c67_invert_test = true;
            set_vtop_cmp(backend);
        }
        x if x == TOK_EQ => {
            c67_cmpeq(backend, fr, r, TREG_EDX);
            backend.gen_state.c67_compare_reg = TREG_EDX;
            backend.gen_state.c67_invert_test = false;
            set_vtop_cmp(backend);
        }
        x if x == TOK_NE => {
            c67_cmpeq(backend, fr, r, TREG_EDX);
            backend.gen_state.c67_compare_reg = TREG_EDX;
            backend.gen_state.c67_invert_test = true;
            set_vtop_cmp(backend);
        }
        // --- Unsigned comparisons ---
        x if x == TOK_ULT => {
            c67_cmpltu(backend, fr, r, TREG_EDX);
            backend.gen_state.c67_compare_reg = TREG_EDX;
            backend.gen_state.c67_invert_test = false;
            set_vtop_cmp(backend);
        }
        x if x == TOK_UGE => {
            c67_cmpltu(backend, fr, r, TREG_EDX);
            backend.gen_state.c67_compare_reg = TREG_EDX;
            backend.gen_state.c67_invert_test = true;
            set_vtop_cmp(backend);
        }
        x if x == TOK_UGT => {
            c67_cmpgtu(backend, fr, r, TREG_EDX);
            backend.gen_state.c67_compare_reg = TREG_EDX;
            backend.gen_state.c67_invert_test = false;
            set_vtop_cmp(backend);
        }
        x if x == TOK_ULE => {
            c67_cmpgtu(backend, fr, r, TREG_EDX);
            backend.gen_state.c67_compare_reg = TREG_EDX;
            backend.gen_state.c67_invert_test = true;
            set_vtop_cmp(backend);
        }

        // --- Arithmetic ---
        x if x == '+' as i32 => c67_add(backend, fr, r),
        x if x == '-' as i32 => c67_sub(backend, fr, r),
        x if x == '&' as i32 => c67_and(backend, fr, r),
        x if x == '|' as i32 => c67_or(backend, fr, r),
        x if x == '^' as i32 => c67_xor(backend, fr, r),

        // --- Multiply ---
        x if x == '*' as i32 => {
            c67_mpyi(backend, fr, r);
            c67_nop(backend, 8);
        }

        // --- Shifts ---
        x if x == TOK_SHL => {
            c67_shl(backend, fr, r);
            c67_nop(backend, 1);
        }
        x if x == TOK_SHR => {
            c67_shru(backend, fr, r);
            c67_nop(backend, 1);
        }
        x if x == TOK_SAR => {
            c67_shr(backend, fr, r);
            c67_nop(backend, 1);
        }

        // --- Division/Modulo via helper functions ---
        x if x == '/' as i32 || x == TOK_PDIV => {
            emit_helper_call(backend, "__c67_divi", fr, r);
            // Result is in A4 (REG_IRET)
            set_vtop_reg(backend, REG_IRET);
        }
        x if x == TOK_UDIV => {
            emit_helper_call(backend, "__c67_divu", fr, r);
            set_vtop_reg(backend, REG_IRET);
        }
        x if x == '%' as i32 => {
            emit_helper_call(backend, "__c67_remi", fr, r);
            set_vtop_reg(backend, REG_IRET);
        }
        x if x == TOK_UMOD => {
            emit_helper_call(backend, "__c67_remu", fr, r);
            set_vtop_reg(backend, REG_IRET);
        }

        // --- Carry operations (not supported on C67, emit NOPs) ---
        x if x == TOK_ADDC1 || x == TOK_ADDC2 ||
             x == TOK_SUBC1 || x == TOK_SUBC2 => {
            c67_add(backend, fr, r);
        }

        // --- Unsigned multiply long ---
        x if x == TOK_UMULL => {
            c67_mpyi(backend, fr, r);
            c67_nop(backend, 8);
        }

        _ => {
            return Err(TccError::codegen(
                &format!("C67: unsupported integer operation {}", op),
            ));
        }
    }
    Ok(())
}

/// Float binary operations.
/// Port of c67-gen.c lines 2290-2417.
///
/// Note: CodeGen has already called gv2(RC_FLOAT, RC_FLOAT) before this.
pub fn gen_opf(backend: &mut C67Backend, op: i32) -> TccResult<()> {
    let vtop_idx = backend.ctx.vtop_idx as usize;
    let r = backend.ctx.vstack[vtop_idx - 1].r as i32 & VT_VALMASK;
    let fr = backend.ctx.vstack[vtop_idx].r as i32 & VT_VALMASK;
    let bt = backend.ctx.vstack[vtop_idx - 1].type_.t & VT_BTYPE;
    let is_double = bt == VT_DOUBLE;

    match op {
        // --- Comparisons ---
        x if x == TOK_LT || x == TOK_GE || x == TOK_GT ||
             x == TOK_LE || x == TOK_EQ || x == TOK_NE => {
            if is_double {
                match x {
                    TOK_LT => c67_cmpltdp(backend, fr, r, TREG_EDX),
                    TOK_GE => { c67_cmpltdp(backend, fr, r, TREG_EDX); backend.gen_state.c67_invert_test = true; }
                    TOK_GT => c67_cmpgtdp(backend, fr, r, TREG_EDX),
                    TOK_LE => { c67_cmpgtdp(backend, fr, r, TREG_EDX); backend.gen_state.c67_invert_test = true; }
                    TOK_EQ => c67_cmpeqdp(backend, fr, r, TREG_EDX),
                    TOK_NE => { c67_cmpeqdp(backend, fr, r, TREG_EDX); backend.gen_state.c67_invert_test = true; }
                    _ => {}
                }
            } else {
                match x {
                    TOK_LT => c67_cmpltsp(backend, fr, r, TREG_EDX),
                    TOK_GE => { c67_cmpltsp(backend, fr, r, TREG_EDX); backend.gen_state.c67_invert_test = true; }
                    TOK_GT => c67_cmpgtsp(backend, fr, r, TREG_EDX),
                    TOK_LE => { c67_cmpgtsp(backend, fr, r, TREG_EDX); backend.gen_state.c67_invert_test = true; }
                    TOK_EQ => c67_cmpeqsp(backend, fr, r, TREG_EDX),
                    TOK_NE => { c67_cmpeqsp(backend, fr, r, TREG_EDX); backend.gen_state.c67_invert_test = true; }
                    _ => {}
                }
            }
            backend.gen_state.c67_compare_reg = TREG_EDX;
            if !matches!(x, TOK_GE | TOK_LE | TOK_NE) {
                backend.gen_state.c67_invert_test = false;
            }
            set_vtop_cmp(backend);
        }

        // --- Addition ---
        x if x == '+' as i32 => {
            if is_double {
                c67_adddp(backend, fr, r);
                c67_nop(backend, 6);
            } else {
                c67_addsp(backend, fr, r);
                c67_nop(backend, 3);
            }
        }

        // --- Subtraction ---
        x if x == '-' as i32 => {
            if is_double {
                c67_subdp(backend, fr, r);
                c67_nop(backend, 6);
            } else {
                c67_subsp(backend, fr, r);
                c67_nop(backend, 3);
            }
        }

        // --- Multiplication ---
        x if x == '*' as i32 => {
            if is_double {
                c67_mpydp(backend, fr, r);
                c67_nop(backend, 9);
            } else {
                c67_mpysp(backend, fr, r);
                c67_nop(backend, 3);
            }
        }

        // --- Division via helper functions ---
        x if x == '/' as i32 => {
            if is_double {
                emit_helper_call(backend, "__c67_divd", fr, r);
            } else {
                emit_helper_call(backend, "__c67_divf", fr, r);
            }
            set_vtop_reg(backend, REG_FRET);
        }

        _ => {
            return Err(TccError::codegen(
                &format!("C67: unsupported float operation {}", op),
            ));
        }
    }
    Ok(())
}

/// Integer to float conversion.
/// Port of c67-gen.c lines 2422-2446.
pub fn gen_cvt_itof(backend: &mut C67Backend, t: i32) -> TccResult<()> {
    let vtop_idx = backend.ctx.vtop_idx as usize;
    let r = backend.ctx.vstack[vtop_idx].r as i32 & VT_VALMASK;
    let is_unsigned = (backend.ctx.vstack[vtop_idx].type_.t & VT_UNSIGNED) != 0;
    let target_bt = t & VT_BTYPE;

    match target_bt {
        VT_DOUBLE => {
            if is_unsigned {
                c67_intdpu(backend, r, r);
            } else {
                c67_intdp(backend, r, r);
            }
            c67_nop(backend, 4);
        }
        VT_FLOAT => {
            if is_unsigned {
                c67_intspu(backend, r, r);
            } else {
                c67_intsp(backend, r, r);
            }
            c67_nop(backend, 3);
        }
        VT_LDOUBLE => {
            return Err(TccError::codegen("C67: long double not supported"));
        }
        _ => {
            return Err(TccError::codegen("C67: unexpected type in gen_cvt_itof"));
        }
    }
    Ok(())
}

/// Float to integer conversion.
/// Port of c67-gen.c lines 2450-2471.
pub fn gen_cvt_ftoi(backend: &mut C67Backend, t: i32) -> TccResult<()> {
    let target_bt = t & VT_BTYPE;
    if target_bt != VT_INT {
        return Err(TccError::codegen(
            "C67: only VT_INT target supported in gen_cvt_ftoi",
        ));
    }

    let vtop_idx = backend.ctx.vtop_idx as usize;
    let r = backend.ctx.vstack[vtop_idx].r as i32 & VT_VALMASK;
    let src_bt = backend.ctx.vstack[vtop_idx].type_.t & VT_BTYPE;

    match src_bt {
        VT_DOUBLE => {
            c67_dptrunc(backend, r, r);
            c67_nop(backend, 4);
        }
        VT_FLOAT => {
            c67_sptrunc(backend, r, r);
            c67_nop(backend, 3);
        }
        _ => {
            return Err(TccError::codegen(
                "C67: unsupported source type in gen_cvt_ftoi",
            ));
        }
    }
    Ok(())
}

/// Float-to-float conversion (single ↔ double).
/// Port of c67-gen.c lines 2474-2516.
pub fn gen_cvt_ftof(backend: &mut C67Backend, t: i32) -> TccResult<()> {
    let target_bt = t & VT_BTYPE;
    let vtop_idx = backend.ctx.vtop_idx as usize;
    let r = backend.ctx.vstack[vtop_idx].r as i32 & VT_VALMASK;
    let src_bt = backend.ctx.vstack[vtop_idx].type_.t & VT_BTYPE;

    if target_bt == VT_LDOUBLE || src_bt == VT_LDOUBLE {
        return Err(TccError::codegen("C67: long double not supported"));
    }

    if target_bt == VT_DOUBLE && src_bt == VT_FLOAT {
        // float → double: SPDP
        c67_spdp(backend, r, r);
        c67_nop(backend, 1);
    } else if target_bt == VT_FLOAT && src_bt == VT_DOUBLE {
        // double → float: DPSP
        c67_dpsp(backend, r, r);
        c67_nop(backend, 4);
    }
    // Same type: no conversion needed
    Ok(())
}

/// Computed goto — jump to address on vtop.
/// Port of c67-gen.c lines 2519-2523.
pub fn ggoto(backend: &mut C67Backend) -> TccResult<()> {
    gcall_or_jmp(backend, true)?;
    backend.vtop_dec();
    Ok(())
}

/// VLA stack save — not supported on C67.
pub fn gen_vla_sp_save(_backend: &mut C67Backend, _addr: i32) -> TccResult<()> {
    Err(TccError::codegen(
        "C67: variable-length arrays are not supported",
    ))
}

/// VLA stack restore — not supported on C67.
pub fn gen_vla_sp_restore(_backend: &mut C67Backend, _addr: i32) -> TccResult<()> {
    Err(TccError::codegen(
        "C67: variable-length arrays are not supported",
    ))
}

/// VLA allocation — not supported on C67.
pub fn gen_vla_alloc(_backend: &mut C67Backend, _typ: &CType, _align: i32) -> TccResult<()> {
    Err(TccError::codegen(
        "C67: variable-length arrays are not supported",
    ))
}

// ===========================================================================
// Internal helpers for vstack result setting
// ===========================================================================

/// Set vtop[-1] to VT_CMP (comparison result).
fn set_vtop_cmp(backend: &mut C67Backend) {
    let idx = (backend.ctx.vtop_idx - 1) as usize;
    if idx < backend.ctx.vstack.len() {
        backend.ctx.vstack[idx].r = VT_CMP as u16;
        backend.ctx.vstack[idx].type_.t = VT_INT;
    }
}

/// Set vtop[-1].r to a specific register (for division results).
fn set_vtop_reg(backend: &mut C67Backend, reg: i32) {
    let idx = (backend.ctx.vtop_idx - 1) as usize;
    if idx < backend.ctx.vstack.len() {
        backend.ctx.vstack[idx].r = reg as u16;
    }
}

// ===========================================================================
// Unit tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_mapping_regn() {
        assert_eq!(c67_map_regn(0), 0x2); // A2
        assert_eq!(c67_map_regn(1), 0x3); // A3
        assert_eq!(c67_map_regn(2), 0x0); // B0
        assert_eq!(c67_map_regn(3), 0x1); // B1
        assert_eq!(c67_map_regn(C67_SP), 15); // B15
        assert_eq!(c67_map_regn(C67_FP), 15); // A15
        assert_eq!(c67_map_regn(C67_A0), 0);
        assert_eq!(c67_map_regn(C67_B3), 3);
    }

    #[test]
    fn test_register_mapping_regs() {
        assert_eq!(c67_map_regs(0), 0); // A-side
        assert_eq!(c67_map_regs(1), 0); // A-side
        assert_eq!(c67_map_regs(2), 1); // B-side
        assert_eq!(c67_map_regs(3), 1); // B-side
        assert_eq!(c67_map_regs(C67_SP), 1); // B15
        assert_eq!(c67_map_regs(C67_FP), 0); // A15
    }

    #[test]
    fn test_register_mapping_regc() {
        assert_eq!(c67_map_regc(0), 0x5);  // A2
        assert_eq!(c67_map_regc(2), 0x1);  // B0
        assert_eq!(c67_map_regc(3), 0x2);  // B1
        assert_eq!(c67_map_regc(C67_B2), 0x3);
        assert_eq!(c67_map_regc(C67_CREG_ZERO), 0);
    }

    #[test]
    fn test_c67_gen_state_defaults() {
        let gs = C67GenState::new();
        assert_eq!(gs.func_sub_sp_offset, 0);
        assert_eq!(gs.func_ret_sub, 0);
        assert!(!gs.c67_invert_test);
        assert_eq!(gs.c67_compare_reg, -1); // C67_CREG_ZERO
        assert_eq!(gs.no_of_cur_func_args, 0);
        assert_eq!(gs.total_bytes_pushed_on_stack, 0);
    }

    #[test]
    fn test_c67_codegen_ctx_defaults() {
        let ctx = C67CodegenCtx::new();
        assert_eq!(ctx.ind, 0);
        assert_eq!(ctx.nocode_wanted, 0);
        assert_eq!(ctx.vtop_idx, -1);
        assert!(ctx.code_buf.is_empty());
        assert!(ctx.vstack.is_empty());
    }

    #[test]
    fn test_reg_classes_count() {
        assert_eq!(REG_CLASSES.len(), NB_REGS);
    }

    #[test]
    fn test_reg_classes_int_membership() {
        for i in 0..NB_REGS {
            assert_ne!(REG_CLASSES[i] & RC_INT, 0,
                "Register {} should have RC_INT", i);
        }
    }

    #[test]
    fn test_reg_classes_float_membership() {
        // Registers 0-3 do NOT have RC_FLOAT
        for i in 0..4 {
            assert_eq!(REG_CLASSES[i] & RC_FLOAT, 0,
                "Register {} should NOT have RC_FLOAT", i);
        }
        // Registers 4-23 have RC_FLOAT
        for i in 4..NB_REGS {
            assert_ne!(REG_CLASSES[i] & RC_FLOAT, 0,
                "Register {} should have RC_FLOAT", i);
        }
    }

    #[test]
    fn test_constants() {
        assert_eq!(PTR_SIZE, 4);
        assert_eq!(NB_REGS, 24);
        assert_eq!(REG_IRET, TREG_C67_A4);
        assert_eq!(REG_FRET, TREG_C67_A4);
    }
}
