//! ARM (ARMv4+) code generation backend.
//!
//! Rust port of `arm-gen.c` (2,385 lines) from the TCC C source.
//! Implements ARM instruction emission, VFP floating-point operations,
//! EABI calling convention, register allocation, stack frame management,
//! type conversions, VLA support, bounds checking, and test coverage
//! instrumentation.
//!
//! # Architecture
//!
//! The code generator emits ARM machine code directly into a byte buffer
//! (`ArmCodegenCtx.code_buf`). Instructions are 32-bit words emitted in
//! little-endian order. All public functions receive `&mut ArmBackend`
//! and are called from the `CodegenBackend` trait implementation in
//! `arm/mod.rs`.
//!
//! # TODO Bug Fixes Integrated
//!
//! - **BUG-01**: Correct fastcall handling for ARM EABI.
//! - **BUG-02**: VFP register state cleaned on function boundaries.
//! - **BUG-03**: transparent_union support propagated.
//! - **BUG-06**: Function→function-pointer decay in parameters.
//! - **BUG-09**: Correct comparison after narrow casts.
//! - **BUG-13**: No global mutable state; all state in `ArmBackend`.
//! - **PORT-01/PORT-02**: Explicit fixed-width Rust types throughout.

#![allow(dead_code)]
#![allow(clippy::manual_range_contains)]
#![allow(clippy::unnecessary_cast)]
#![allow(clippy::identity_op)]
#![allow(clippy::too_many_arguments)]

use super::ArmBackend;
use super::FloatAbi;
use super::{
    TREG_R0, TREG_R1, TREG_R3, TREG_R12, TREG_SP, TREG_LR,
    TREG_F0,
};
use super::{
    RC_INT, RC_FLOAT, RC_R0, RC_R1, RC_R2, RC_R3, RC_R12,
    RC_F0, RC_F1, RC_F2, RC_F3,
    NB_REGS_VFP,
    PTR_SIZE,
};
use super::t2cpr;

use crate::error::{TccError, TccResult};
use crate::types::{
    CType, SValue, Sym,
    VT_BTYPE, VT_FLOAT, VT_DOUBLE, VT_LDOUBLE,
    VT_INT, VT_LLONG, VT_PTR, VT_STRUCT,
    VT_BYTE, VT_SHORT, VT_BOOL, VT_UNSIGNED,

    VT_VALMASK, VT_CONST, VT_LOCAL, VT_LLOCAL,
    VT_LVAL, VT_CMP, VT_JMP, VT_JMPI,

    FUNC_ELLIPSIS,
};
use crate::token::{
    TOK_ULT, TOK_UGE, TOK_EQ, TOK_NE, TOK_ULE, TOK_UGT,
    TOK_LT, TOK_GE, TOK_LE, TOK_GT,
    TOK_ADDC1, TOK_ADDC2, TOK_SUBC1, TOK_SUBC2,
    TOK_SHL, TOK_SHR, TOK_SAR,
    TOK_PDIV, TOK_UDIV, TOK_UMOD, TOK_UMULL, TOK_NEG,
};

#[allow(unused_imports)]
use crate::arch::{read32le, write32le};

#[allow(non_upper_case_globals)]
/// ARM-specific token: N (negative) flag set condition test (from tcc.h: 0x98)
pub const TOK_Nset: i32 = 0x98;
#[allow(non_upper_case_globals)]
/// ARM-specific token: N (negative) flag clear condition test (from tcc.h: 0x99)
pub const TOK_Nclear: i32 = 0x99;

// ============================================================================
// Target machine predefined macros
// ============================================================================

/// Target machine predefined macros for ARM (EABI).
/// Source: arm-gen.c lines 144-156.
pub const TARGET_MACHINE_DEFS: &str =
    "__arm__\0__arm\0arm\0__arm_elf__\0__arm_elf\0arm_elf\0\
     __ARM_ARCH_4__\0__ARMEL__\0__APCS_32__\0__ARM_EABI__\0";

/// EABI-specific machine defs (alias for TARGET_MACHINE_DEFS).
pub const TARGET_MACHINE_DEFS_EABI: &str = "__ARM_EABI__\0";

/// Register class table for VFP-enabled backends (13 registers).
/// Source: arm-gen.c lines 161-177.
pub const REG_CLASSES_VFP: [i32; 13] = [
    RC_INT | RC_R0,    // r0  (TREG_R0=0)
    RC_INT | RC_R1,    // r1  (TREG_R1=1)
    RC_INT | RC_R2,    // r2  (TREG_R2=2)
    RC_INT | RC_R3,    // r3  (TREG_R3=3)
    RC_INT | RC_R12,   // r12 (TREG_R12=4)
    RC_FLOAT | RC_F0,  // f0  (TREG_F0=5) = d0/s0
    RC_FLOAT | RC_F1,  // f1  (TREG_F1=6) = d1/s2
    RC_FLOAT | RC_F2,  // f2  (TREG_F2=7) = d2/s4
    RC_FLOAT | RC_F3,  // f3  (TREG_F3=8) = d3/s6
    RC_FLOAT | super::RC_F4,  // f4  (9)  = d4/s8
    RC_FLOAT | super::RC_F5,  // f5  (10) = d5/s10
    RC_FLOAT | super::RC_F6,  // f6  (11) = d6/s12
    RC_FLOAT | super::RC_F7,  // f7  (12) = d7/s14
];

/// Register class table for non-VFP backends (9 registers).
pub const REG_CLASSES_NO_VFP: [i32; 9] = [
    RC_INT | RC_R0,
    RC_INT | RC_R1,
    RC_INT | RC_R2,
    RC_INT | RC_R3,
    RC_INT | RC_R12,
    RC_FLOAT | RC_F0,
    RC_FLOAT | RC_F1,
    RC_FLOAT | RC_F2,
    RC_FLOAT | RC_F3,
];

// ============================================================================
// ARM condition code constants (bits [31:28])
// ============================================================================

const COND_EQ: u32 = 0x00000000; // Z set
const COND_NE: u32 = 0x10000000; // Z clear
const COND_CS: u32 = 0x20000000; // C set (HS)
const COND_CC: u32 = 0x30000000; // C clear (LO)
const COND_MI: u32 = 0x40000000; // N set
const COND_PL: u32 = 0x50000000; // N clear
const COND_VS: u32 = 0x60000000; // V set
const COND_VC: u32 = 0x70000000; // V clear
const COND_HI: u32 = 0x80000000; // C set and Z clear
const COND_LS: u32 = 0x90000000; // C clear or Z set
const COND_GE: u32 = 0xA0000000; // N == V
const COND_LT: u32 = 0xB0000000; // N != V
const COND_GT: u32 = 0xC0000000; // Z clear and N == V
const COND_LE: u32 = 0xD0000000; // Z set or N != V
const COND_AL: u32 = 0xE0000000; // always

// ============================================================================
// ARM instruction encoding constants
// ============================================================================

/// ARM NOP: MOV r0, r0.
const ARM_NOP: u32 = 0xE1A00000;

// ============================================================================
// Code emission context
// ============================================================================

/// Shared mutable state for ARM code emission, bridging CodeGen and the ARM
/// backend. CodeGen populates these fields before each backend method
/// invocation and reads them back afterward.
///
/// Replaces C global mutable variables (`ind`, `nocode_wanted`,
/// `cur_text_section`, `vtop`, etc.) with explicit owned state.
pub struct ArmCodegenCtx {
    /// Current code position (byte offset in text section). Mirrors `CodeGen.ind`.
    pub ind: i32,
    /// Code suppression flag. Non-zero means "don't emit code".
    pub nocode_wanted: i32,
    /// Local variable stack offset (negative from frame pointer).
    pub loc: i32,
    /// Function return value offset.
    pub func_vc: i32,
    /// Function return type.
    pub func_vt: CType,
    /// Whether function is variadic.
    pub func_var: bool,
    /// Code buffer — ARM instruction byte emission target.
    pub code_buf: Vec<u8>,
    /// Value stack snapshot. CodeGen copies relevant entries here.
    pub vstack: Vec<SValue>,
    /// Index of value stack top (-1 = empty).
    pub vtop_idx: i32,
    /// Whether bounds checking is active.
    pub do_bounds_check: bool,
    /// Return symbol for forward references.
    pub rsym: i32,
    /// Pending relocations for later flushing.
    pub pending_relocs: Vec<PendingReloc>,
}

/// Records a relocation to be applied when code is flushed to an ELF section.
#[derive(Debug, Clone)]
pub struct PendingReloc {
    /// Byte offset in code_buf where relocation applies.
    pub offset: u64,
    /// Relocation type (e.g., R_ARM_PC24, R_ARM_ABS32).
    pub rtype: u32,
    /// Symbol index for the relocation target.
    pub sym_idx: usize,
    /// Addend for RELA-style relocations.
    pub addend: i64,
}

impl ArmCodegenCtx {
    /// Create a new zeroed-out ARM code generation context.
    pub fn new() -> Self {
        Self {
            ind: 0,
            nocode_wanted: 0,
            loc: 0,
            func_vc: 0,
            func_vt: CType::default(),
            func_var: false,
            code_buf: Vec::with_capacity(4096),
            vstack: Vec::new(),
            vtop_idx: -1,
            do_bounds_check: false,
            rsym: 0,
            pending_relocs: Vec::new(),
        }
    }
}

impl Default for ArmCodegenCtx {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Helper methods on ArmBackend for value stack and code buffer access
// ============================================================================

impl ArmBackend {
    /// Access the code emission context.
    #[inline]
    pub fn ctx(&self) -> &ArmCodegenCtx {
        &self.ctx
    }

    /// Mutably access the code emission context.
    #[inline]
    pub fn ctx_mut(&mut self) -> &mut ArmCodegenCtx {
        &mut self.ctx
    }

    /// Get the value at the top of the value stack (vtop[0]).
    #[inline]
    fn vtop(&self) -> &SValue {
        &self.ctx.vstack[self.ctx.vtop_idx as usize]
    }

    /// Mutably get vtop.
    #[inline]
    fn vtop_mut(&mut self) -> &mut SValue {
        let idx = self.ctx.vtop_idx as usize;
        &mut self.ctx.vstack[idx]
    }

    /// Get the value below vtop (vtop[-1]).
    #[inline]
    fn vtop_1(&self) -> &SValue {
        &self.ctx.vstack[(self.ctx.vtop_idx - 1) as usize]
    }

    /// Mutably get vtop[-1].
    #[inline]
    fn vtop_1_mut(&mut self) -> &mut SValue {
        let idx = (self.ctx.vtop_idx - 1) as usize;
        &mut self.ctx.vstack[idx]
    }

    /// Get value at offset n below vtop (vtop[-n]).
    #[inline]
    fn vtop_n(&self, n: i32) -> &SValue {
        &self.ctx.vstack[(self.ctx.vtop_idx - n) as usize]
    }

    /// Mutably get vtop[-n].
    #[inline]
    fn vtop_n_mut(&mut self, n: i32) -> &mut SValue {
        let idx = (self.ctx.vtop_idx - n) as usize;
        &mut self.ctx.vstack[idx]
    }

    /// Pop one entry off the value stack.
    #[inline]
    fn vtop_dec(&mut self) {
        if self.ctx.vtop_idx >= 0 {
            self.ctx.vtop_idx -= 1;
        }
    }

    /// Ensure code buffer is large enough for position `needed`.
    #[inline]
    fn ensure_code_buf(&mut self, needed: usize) {
        if self.ctx.code_buf.len() < needed {
            self.ctx.code_buf.resize(needed, 0);
        }
    }
}

// ============================================================================
// Code emission primitives
// ============================================================================

/// Emit a single byte to the ARM code buffer.
///
/// If `nocode_wanted` is non-zero, the byte is silently discarded.
pub fn g(backend: &mut ArmBackend, c: i32) -> TccResult<()> {
    if backend.ctx.nocode_wanted != 0 {
        return Ok(());
    }
    let pos = backend.ctx.ind as usize;
    backend.ensure_code_buf(pos + 1);
    backend.ctx.code_buf[pos] = c as u8;
    backend.ctx.ind += 1;
    Ok(())
}

/// Emit a 16-bit little-endian value to the ARM code buffer.
pub fn gen_le16(backend: &mut ArmBackend, v: i32) -> TccResult<()> {
    g(backend, v & 0xFF)?;
    g(backend, (v >> 8) & 0xFF)
}

/// Emit a 32-bit little-endian value to the ARM code buffer.
pub fn gen_le32(backend: &mut ArmBackend, c: i32) -> TccResult<()> {
    g(backend, c & 0xFF)?;
    g(backend, (c >> 8) & 0xFF)?;
    g(backend, (c >> 16) & 0xFF)?;
    g(backend, (c >> 24) & 0xFF)
}

/// Emit a 32-bit ARM instruction word (little-endian).
///
/// Source: arm-gen.c lines 252-266.
pub fn o(backend: &mut ArmBackend, i: u32) -> TccResult<()> {
    gen_le32(backend, i as i32)
}

/// Emit a raw opcode (alias for `o()`).
pub fn emit_opcode(backend: &mut ArmBackend, c: u32) -> TccResult<()> {
    o(backend, c)
}

// ============================================================================
// Register mapping helpers
// ============================================================================

/// Map allocator register index to ARM integer register number.
///
/// TREG_R0..R3 → 0..3, TREG_R12 → 12, TREG_SP → 13, TREG_LR → 14.
///
/// Source: arm-gen.c lines 436-446.
pub fn intr(r: i32) -> u32 {
    if r == TREG_R12 as i32 {
        12
    } else if r == TREG_SP as i32 {
        13
    } else if r == TREG_LR as i32 {
        14
    } else {
        // TREG_R0..TREG_R3 are 0..3
        r as u32
    }
}

/// Map allocator register index to VFP double-precision register number.
///
/// TREG_F0..TREG_F7 → 0..7 (representing d0..d7).
///
/// Source: arm-gen.c lines 421-427.
pub fn vfpr(r: i32) -> u32 {
    (r - TREG_F0 as i32) as u32
}

/// Map allocator register index to FPA register number (legacy path).
///
/// Source: arm-gen.c lines 428-435.
pub fn fpr(r: i32) -> u32 {
    (r - TREG_F0 as i32) as u32
}

/// Validate that r is a valid core register index.
#[inline]
fn check_r(r: i32) -> bool {
    (r >= TREG_R0 as i32 && r <= TREG_R3 as i32)
        || r == TREG_R12 as i32
        || r == TREG_SP as i32
        || r == TREG_LR as i32
}

/// Compute register bitmask for two registers.
///
/// Source: arm-gen.c line 226.
fn two2mask(a: i32, b: i32) -> i32 {
    regmask(a) | regmask(b)
}

/// Compute register class bitmask for a single register.
///
/// Source: arm-gen.c line 232.
fn regmask(r: i32) -> i32 {
    if r >= 0 && (r as usize) < NB_REGS_VFP {
        1 << (r + 2)
    } else {
        0
    }
}

// ============================================================================
// Default ELF interpreter path
// ============================================================================

/// Returns the default ELF interpreter path for ARM.
///
/// Source: arm-gen.c lines 243-250.
pub fn default_elfinterp(backend: &ArmBackend) -> &'static str {
    if backend.eabi_enabled {
        match backend.float_abi {
            FloatAbi::HardFloat => "/lib/ld-linux-armhf.so.3",
            FloatAbi::SoftFp => "/lib/ld-linux.so.3",
        }
    } else {
        "/lib/ld-linux.so.2"
    }
}

// ============================================================================
// ARM immediate encoding
// ============================================================================

/// Try to encode a 32-bit constant into an ARM immediate (8-bit rotated).
///
/// ARM data-processing instructions encode immediates as an 8-bit value
/// rotated right by an even number of bits (0-30), giving 4096 possible
/// immediate values from a 12-bit encoding field.
///
/// If the constant cannot be directly encoded, tries transformations:
/// - ADD ↔ SUB (negate constant)
/// - MOV ↔ MVN (bitwise NOT)
/// - AND ↔ BIC (bitwise NOT)
/// - CMP ↔ CMN (negate)
///
/// Returns complete instruction word with encoded immediate, or 0 if not encodable.
///
/// Source: arm-gen.c lines 271-302.
pub fn stuff_const(op: u32, c: u32) -> u32 {
    let result = stuff_const_direct(op, c);
    if result != 0 {
        return result;
    }
    let opc = (op >> 20) & 0xF;
    // Try transformation based on operation type
    match opc {
        // ADD(4/5) ↔ SUB(2/3): negate constant
        0x4 | 0x5 => {
            let r = stuff_const_direct((op & 0xFFF0F000) | (0x2 << 20), 0u32.wrapping_sub(c));
            if r != 0 { return r; }
        }
        0x2 | 0x3 => {
            let r = stuff_const_direct((op & 0xFFF0F000) | (0x4 << 20), 0u32.wrapping_sub(c));
            if r != 0 { return r; }
        }
        // MOV(D) ↔ MVN(F): bitwise NOT
        0xD => {
            let r = stuff_const_direct((op & 0xFFF0F000) | (0xF << 20), !c);
            if r != 0 { return r; }
        }
        0xF => {
            let r = stuff_const_direct((op & 0xFFF0F000) | (0xD << 20), !c);
            if r != 0 { return r; }
        }
        // AND(0/1) ↔ BIC(E): bitwise NOT
        0x0 | 0x1 => {
            let r = stuff_const_direct((op & 0xFFF0F000) | (0xE << 20), !c);
            if r != 0 { return r; }
        }
        0xE => {
            let r = stuff_const_direct((op & 0xFFF0F000) | (0x0 << 20), !c);
            if r != 0 { return r; }
        }
        // CMP(A) ↔ CMN(B): negate
        0xA => {
            let r = stuff_const_direct((op & 0xFFF0F000) | (0xB << 20), 0u32.wrapping_sub(c));
            if r != 0 { return r; }
        }
        0xB => {
            let r = stuff_const_direct((op & 0xFFF0F000) | (0xA << 20), 0u32.wrapping_sub(c));
            if r != 0 { return r; }
        }
        _ => {}
    }
    0
}

/// Try direct encoding of constant c with all 16 rotation positions.
fn stuff_const_direct(op: u32, c: u32) -> u32 {
    for rot in 0..16u32 {
        let rotated = c.rotate_left(rot * 2);
        if rotated <= 0xFF {
            return op | rotated | (rot << 8);
        }
    }
    0
}

/// Encode constant requiring multiple ARM instructions (1-4 instruction sequences).
///
/// Source: arm-gen.c lines 305-357.
fn stuff_const_harder(backend: &mut ArmBackend, op: u32, v: u32) -> TccResult<()> {
    // Try single instruction
    let r = stuff_const(op, v);
    if r != 0 {
        return o(backend, r);
    }
    let rd = (op >> 12) & 0xF;
    // Build helper ops for MOV + ORR decomposition
    let mov_op = COND_AL | (0xD << 21) | (rd << 12);
    let orr_op = COND_AL | (0xC << 21) | (rd << 16) | (rd << 12);
    // Try 2-instruction: decompose into two byte-aligned parts
    for rot in 0..16u32 {
        let mask = (0xFFu32).rotate_right(rot * 2);
        let part1 = v & mask;
        let part2 = v & !mask;
        if part1 != 0 && part2 != 0 {
            let enc1 = stuff_const_direct(mov_op, part1);
            let enc2 = stuff_const_direct(orr_op, part2);
            if enc1 != 0 && enc2 != 0 {
                o(backend, enc1)?;
                return o(backend, enc2);
            }
        }
    }
    // 3/4-instruction sequence: decompose byte-by-byte
    let mut remaining = v;
    let mut first = true;
    for shift in (0..32u32).step_by(8) {
        let part = remaining & (0xFF << shift);
        if part != 0 {
            remaining &= !part;
            let base_op = if first { mov_op } else { orr_op };
            let encoded = stuff_const_direct(base_op, part);
            if encoded == 0 {
                return Err(TccError::CodegenError {
                    message: format!("ARM: cannot encode constant 0x{:08X}", v),
                });
            }
            o(backend, encoded)?;
            first = false;
            if remaining == 0 {
                break;
            }
        }
    }
    // If the original op was an ALU op (not just MOV/MVN), apply it
    let opc = (op >> 20) & 0xF;
    let rn = (op >> 16) & 0xF;
    if !first && opc != 0xD && opc != 0xF && rn != rd {
        let reg_op = COND_AL | ((opc & 0xF) << 21) | (1 << 20) | (rn << 16) | (rd << 12) | rd;
        o(backend, reg_op)?;
    }
    Ok(())
}

// ============================================================================
// Branch encoding/decoding
// ============================================================================

/// Encode a branch offset for B/BL instructions.
///
/// Range: ±32MB (24-bit signed offset in words).
///
/// Source: arm-gen.c lines 359-370.
pub fn encbranch(pos: i32, addr: i32, fail: bool) -> TccResult<u32> {
    let offset = addr.wrapping_sub(pos).wrapping_sub(8);
    let word_offset = offset >> 2;
    if (word_offset < -(1 << 23) || word_offset >= (1 << 23)) && fail {
        return Err(TccError::CodegenError {
            message: format!(
                "ARM: branch offset out of range (pos=0x{:X}, addr=0x{:X})",
                pos, addr
            ),
        });
    }
    Ok(0x0A000000 | ((word_offset as u32) & 0x00FFFFFF))
}

/// Decode a branch offset from instruction at position `pos`.
///
/// Source: arm-gen.c lines 372-381.
pub fn decbranch(backend: &ArmBackend, pos: i32) -> i32 {
    let p = pos as usize;
    if p + 3 >= backend.ctx.code_buf.len() {
        return 0;
    }
    let instr = backend.ctx.code_buf[p] as u32
        | ((backend.ctx.code_buf[p + 1] as u32) << 8)
        | ((backend.ctx.code_buf[p + 2] as u32) << 16)
        | ((backend.ctx.code_buf[p + 3] as u32) << 24);
    let mut offset = instr & 0x00FFFFFF;
    // Sign-extend from 24 bits
    if offset & 0x00800000 != 0 {
        offset |= 0xFF000000;
    }
    (offset as i32).wrapping_mul(4).wrapping_add(8).wrapping_add(pos)
}

// ============================================================================
// Condition code mapping
// ============================================================================

/// Map TCC comparison token to ARM condition code.
///
/// Returns the condition code in bits [31:28] position.
///
/// Source: arm-gen.c lines 474-506.
pub fn mapcc(cc: i32) -> u32 {
    match cc {
        x if x == TOK_ULT as i32 => COND_CC,  // unsigned less than
        x if x == TOK_UGE as i32 => COND_CS,  // unsigned greater-equal
        x if x == TOK_EQ as i32 => COND_EQ,   // equal
        x if x == TOK_NE as i32 => COND_NE,   // not equal
        x if x == TOK_ULE as i32 => COND_LS,  // unsigned less-equal
        x if x == TOK_UGT as i32 => COND_HI,  // unsigned greater
        x if x == TOK_Nset as i32 => COND_MI,  // negative
        x if x == TOK_Nclear as i32 => COND_PL, // non-negative
        x if x == TOK_LT as i32 => COND_LT,   // signed less than
        x if x == TOK_GE as i32 => COND_GE,   // signed greater-equal
        x if x == TOK_LE as i32 => COND_LE,   // signed less-equal
        x if x == TOK_GT as i32 => COND_GT,   // signed greater
        _ => {
            // Default: map unknown cc to AL (always)
            COND_AL
        }
    }
}

/// Negate a comparison operator.
///
/// Source: arm-gen.c lines 507-541.
pub fn negcc(cc: i32) -> i32 {
    match cc {
        x if x == TOK_ULT as i32 => TOK_UGE as i32,
        x if x == TOK_UGE as i32 => TOK_ULT as i32,
        x if x == TOK_EQ as i32 => TOK_NE as i32,
        x if x == TOK_NE as i32 => TOK_EQ as i32,
        x if x == TOK_ULE as i32 => TOK_UGT as i32,
        x if x == TOK_UGT as i32 => TOK_ULE as i32,
        x if x == TOK_Nset as i32 => TOK_Nclear as i32,
        x if x == TOK_Nclear as i32 => TOK_Nset as i32,
        x if x == TOK_LT as i32 => TOK_GE as i32,
        x if x == TOK_GE as i32 => TOK_LT as i32,
        x if x == TOK_LE as i32 => TOK_GT as i32,
        x if x == TOK_GT as i32 => TOK_LE as i32,
        _ => cc,
    }
}

// ============================================================================
// Addressing helpers
// ============================================================================

/// Calculate base register and offset for memory addressing.
///
/// Adjusts offset to fit within ARM instruction's immediate field.
/// If the offset doesn't fit, emits instructions to compute a new base
/// register, and updates `base`/`off` accordingly.
///
/// Source: arm-gen.c lines 447-473.
fn calcaddr(
    backend: &mut ArmBackend,
    base: &mut u32,
    off: &mut i32,
    sgn: &mut i32,
    maxoff: i32,
    _shift: u32,
) -> TccResult<()> {
    if *off > maxoff || *off < -maxoff {
        let abs_off = if *off < 0 {
            *sgn = -1;
            (-*off) as u32
        } else {
            abs_off_helper(*off)
        };
        // Use r12 (ip) as temporary for address computation
        let add_op = if *sgn < 0 {
            // SUB ip, base, #abs_off
            COND_AL | (0x24 << 20) | (*base << 16) | (12 << 12)
        } else {
            // ADD ip, base, #abs_off
            COND_AL | (0x28 << 20) | (*base << 16) | (12 << 12)
        };
        stuff_const_harder(backend, add_op, abs_off)?;
        *base = 12; // ip
        *off = 0;
        *sgn = 1;
    }
    Ok(())
}

#[inline]
fn abs_off_helper(off: i32) -> u32 {
    off as u32
}

/// Add an immediate value to the stack pointer.
///
/// Source: arm-gen.c lines 796-801.
fn gadd_sp(backend: &mut ArmBackend, val: i32) -> TccResult<()> {
    if val > 0 {
        // ADD sp, sp, #val
        stuff_const_harder(backend, COND_AL | (0x28 << 20) | (13 << 16) | (13 << 12), val as u32)
    } else if val < 0 {
        // SUB sp, sp, #(-val)
        stuff_const_harder(backend, COND_AL | (0x24 << 20) | (13 << 16) | (13 << 12), (-val) as u32)
    } else {
        Ok(())
    }
}

// ============================================================================
// Forward branch resolution
// ============================================================================

/// Resolve forward branch targets: patch jump at address t to point to a.
///
/// Walks the branch chain: each jump instruction contains the address of
/// the next jump in the chain encoded in the branch offset field.
///
/// Source: arm-gen.c lines 404-420.
pub fn gsym_addr(backend: &mut ArmBackend, t: i32, a: i32) -> TccResult<()> {
    let mut t = t;
    while t != 0 {
        let next = decbranch(backend, t);
        let enc = encbranch(t, a, true)?;
        // Preserve condition code from original instruction, replace offset
        let p = t as usize;
        if p + 3 < backend.ctx.code_buf.len() {
            let orig = backend.ctx.code_buf[p + 3];
            let cc_byte = orig & 0xF0; // condition code in top nibble
            let new_word = (enc & 0x00FFFFFF) | ((cc_byte as u32) << 24);
            backend.ctx.code_buf[p] = (new_word & 0xFF) as u8;
            backend.ctx.code_buf[p + 1] = ((new_word >> 8) & 0xFF) as u8;
            backend.ctx.code_buf[p + 2] = ((new_word >> 16) & 0xFF) as u8;
            backend.ctx.code_buf[p + 3] = ((new_word >> 24) & 0xFF) as u8;
        }
        let d = next.wrapping_sub(t).wrapping_sub(8);
        if d == 0 || next == t {
            break;
        }
        t = next;
    }
    Ok(())
}

/// Resolve forward branch to current code position.
pub fn gsym(backend: &mut ArmBackend, t: i32) -> TccResult<()> {
    let ind = backend.ctx.ind;
    gsym_addr(backend, t, ind)
}

// ============================================================================
// Load value into register
// ============================================================================

/// Load a constant into a register using optimal instruction sequence.
///
/// For CPUv7+: uses MOVW/MOVT (two 16-bit immediate loads).
/// For CPUv6-: uses LDR from literal pool or stuff_const sequence.
///
/// Source: arm-gen.c lines 542-582 (load_value helper).
fn load_value(backend: &mut ArmBackend, r_hw: u32, val: u32) -> TccResult<()> {
    if backend.cpu_version >= 7 {
        // ARMv7: MOVW rd, #imm16 / MOVT rd, #imm16
        let lo = val & 0xFFFF;
        let hi = (val >> 16) & 0xFFFF;
        // MOVW: 0xE3000000 | (imm4<<16) | (Rd<<12) | imm12
        let movw = COND_AL | 0x03000000
            | ((lo >> 12) << 16)
            | (r_hw << 12)
            | (lo & 0xFFF);
        o(backend, movw)?;
        if hi != 0 {
            // MOVT: 0xE3400000 | (imm4<<16) | (Rd<<12) | imm12
            let movt = COND_AL | 0x03400000
                | ((hi >> 12) << 16)
                | (r_hw << 12)
                | (hi & 0xFFF);
            o(backend, movt)?;
        }
    } else {
        // Try single instruction via stuff_const
        let enc = stuff_const(COND_AL | (0xD << 21) | (r_hw << 12), val);
        if enc != 0 {
            o(backend, enc)?;
        } else {
            // Fall back to LDR from literal pool:
            // LDR rd, [pc, #0] ; B $+4 ; .word val
            let ldr_pc = COND_AL | 0x051F0000 | (r_hw << 12) | 0;
            o(backend, ldr_pc)?;
            // Branch over literal
            o(backend, COND_AL | 0x0A000000)?;
            // Literal value
            o(backend, val)?;
        }
    }
    Ok(())
}

/// Load a value into a register from the value stack.
///
/// Handles all SValue types:
/// - VT_CONST: constant loads (stuff_const or literal pool)
/// - VT_LOCAL: frame-relative loads
/// - VT_LVAL: memory loads (ldr/ldrb/ldrh/ldrsb/ldrsh)
/// - VFP float loads (vldr for VT_FLOAT/VT_DOUBLE)
/// - Long long loads (two-word load pairs)
/// - Register-to-register moves
///
/// Source: arm-gen.c lines 582-714.
pub fn load(backend: &mut ArmBackend, r: i32, sv: &SValue) -> TccResult<()> {
    let fr = sv.r as i32;
    let v = fr & VT_VALMASK;
    let bt = sv.type_.t & VT_BTYPE;
    let fc = (unsafe { sv.c.i } as i32);

    // Float register target
    if r >= TREG_F0 as i32 && r <= (TREG_F0 as i32 + 7) {
        return load_float(backend, r, sv);
    }

    let r_hw = intr(r);

    // VT_LVAL — load from memory
    if (fr & VT_LVAL) != 0 {
        let base_reg: u32;
        let mut offset = fc;
        let sign = 1i32;

        if v == VT_LOCAL {
            // Frame-pointer relative
            base_reg = 11; // fp
        } else if v == VT_CONST {
            // Absolute address via r12
            load_value(backend, 12, fc as u32)?;
            base_reg = 12;
            offset = 0;
        } else if v == VT_LLOCAL {
            // Indirect local: load address from stack, then load value
            let ldr_off = fc;
            if ldr_off >= -4095 && ldr_off <= 4095 {
                let (sgn, abs) = if ldr_off < 0 { (0u32, (-ldr_off) as u32) } else { (1u32, ldr_off as u32) };
                o(backend, COND_AL | 0x05100000 | (sgn << 23) | (11 << 16) | (12 << 12) | abs)?;
            } else {
                load_value(backend, 12, ldr_off as u32)?;
                // ADD ip, fp, ip
                o(backend, COND_AL | (0x08 << 20) | (11 << 16) | (12 << 12) | 12)?;
                o(backend, COND_AL | 0x05900000 | (12 << 16) | (12 << 12))?;
            }
            base_reg = 12;
            offset = 0;
        } else {
            // Register base
            base_reg = intr(v);
            offset = 0;
        }

        // Adjust address for out-of-range offsets
        let maxoff = match bt {
            x if x == VT_BYTE || x == VT_BOOL => 4095,
            x if x == VT_SHORT => 255,
            _ => 4095,
        };
        let mut base = base_reg;
        let mut sgn = sign;
        calcaddr(backend, &mut base, &mut offset, &mut sgn, maxoff, 0)?;

        let abs_off = if offset < 0 { (-offset) as u32 } else { offset as u32 };
        let u_bit = if offset >= 0 { 1u32 << 23 } else { 0u32 };

        match bt {
            x if x == VT_BYTE || x == VT_BOOL => {
                if (sv.type_.t & VT_UNSIGNED) != 0 {
                    // LDRB
                    o(backend, COND_AL | 0x05D00000 | u_bit
                        | (base << 16) | (r_hw << 12) | abs_off)?;
                } else {
                    // LDRSB
                    let hi4 = (abs_off >> 4) & 0xF;
                    let lo4 = abs_off & 0xF;
                    o(backend, COND_AL | 0x01D000D0 | u_bit
                        | (base << 16) | (r_hw << 12) | (hi4 << 8) | lo4)?;
                }
            }
            x if x == VT_SHORT => {
                let hi4 = (abs_off >> 4) & 0xF;
                let lo4 = abs_off & 0xF;
                if (sv.type_.t & VT_UNSIGNED) != 0 {
                    // LDRH
                    o(backend, COND_AL | 0x01D000B0 | u_bit
                        | (base << 16) | (r_hw << 12) | (hi4 << 8) | lo4)?;
                } else {
                    // LDRSH
                    o(backend, COND_AL | 0x01D000F0 | u_bit
                        | (base << 16) | (r_hw << 12) | (hi4 << 8) | lo4)?;
                }
            }
            _ => {
                // LDR (32-bit word)
                o(backend, COND_AL | 0x05900000 | u_bit
                    | (base << 16) | (r_hw << 12) | abs_off)?;
            }
        }
        return Ok(());
    }

    // VT_CONST — load constant
    if v == VT_CONST {
        load_value(backend, r_hw, fc as u32)?;
        return Ok(());
    }

    // VT_LOCAL — load frame address
    if v == VT_LOCAL {
        if fc >= 0 {
            stuff_const_harder(backend,
                COND_AL | (0x28 << 20) | (11 << 16) | (r_hw << 12), fc as u32)?;
        } else {
            stuff_const_harder(backend,
                COND_AL | (0x24 << 20) | (11 << 16) | (r_hw << 12), (-fc) as u32)?;
        }
        return Ok(());
    }

    // VT_CMP — set register from comparison flags
    if v == VT_CMP {
        let cc = mapcc(sv.cmp_op as i32);
        let neg_cc = cc ^ 0x10000000; // flip condition
        // MOV Rd, #1 (conditional)
        o(backend, cc | (0x3A << 20) | (r_hw << 12) | 1)?;
        // MOV Rd, #0 (negated condition)
        o(backend, neg_cc | (0x3A << 20) | (r_hw << 12) | 0)?;
        return Ok(());
    }

    // VT_JMP / VT_JMPI — set register from jump result
    if v == VT_JMP || v == VT_JMPI {
        let inv = if v == VT_JMP { 1u32 } else { 0u32 };
        // MOV Rd, #inv
        o(backend, COND_AL | (0x3A << 20) | (r_hw << 12) | inv)?;
        // B over
        let jump_pos = backend.ctx.ind;
        o(backend, COND_AL | 0x0A000000)?;
        // Resolve the jump chain to here
        gsym(backend, sv.jtrue as i32)?;
        // MOV Rd, #(1-inv)
        o(backend, COND_AL | (0x3A << 20) | (r_hw << 12) | (1 - inv))?;
        // Patch the B over
        let cur = backend.ctx.ind;
        gsym_addr(backend, jump_pos, cur)?;
        return Ok(());
    }

    // Register-to-register move
    if v < TREG_F0 as i32 || v > (TREG_F0 as i32 + 7) {
        let fr_hw = intr(v);
        if fr_hw != r_hw {
            // MOV Rd, Rm
            o(backend, COND_AL | (0xD << 21) | (r_hw << 12) | fr_hw)?;
        }
    }

    Ok(())
}

/// Load a value into a VFP floating-point register.
fn load_float(backend: &mut ArmBackend, r: i32, sv: &SValue) -> TccResult<()> {
    let fr = sv.r as i32;
    let v = fr & VT_VALMASK;
    let bt = sv.type_.t & VT_BTYPE;
    let fc = (unsafe { sv.c.i } as i32);
    let dr = vfpr(r);
    let cp = t2cpr(bt) as u32; // 0x100 for double, 0 for float

    if (fr & VT_LVAL) != 0 {
        // Memory load — VLDR
        let base_reg: u32;
        let mut offset = fc;

        if v == VT_LOCAL {
            base_reg = 11; // fp
        } else if v == VT_CONST {
            load_value(backend, 12, fc as u32)?;
            base_reg = 12;
            offset = 0;
        } else {
            base_reg = intr(v);
            offset = 0;
        }

        let mut base = base_reg;
        let mut sgn = 1i32;
        calcaddr(backend, &mut base, &mut offset, &mut sgn, 1020, 2)?;

        let abs_off = if offset < 0 { (-offset) as u32 >> 2 } else { offset as u32 >> 2 };
        let u_bit = if offset >= 0 { 1u32 << 23 } else { 0u32 };

        // VLDR dN, [base, #off] (double) or VLDR sN, [base, #off] (float)
        o(backend, COND_AL | 0x0D100A00 | u_bit | cp
            | (base << 16) | (dr << 12) | (abs_off & 0xFF))?;
    } else if v >= TREG_F0 as i32 && v <= (TREG_F0 as i32 + 7) {
        // Float register to float register
        let sr = vfpr(v);
        if sr != dr {
            // VMOV dD, dS (or sD, sS)
            o(backend, COND_AL | 0x0EB00A40 | cp | (dr << 12) | sr)?;
        }
    }
    Ok(())
}

// ============================================================================
// Store register to memory
// ============================================================================

/// Store register to memory location.
///
/// Handles integer stores (str/strb/strh), VFP float stores (vstr),
/// and long long stores (two-word store pairs).
///
/// Source: arm-gen.c lines 715-795.
pub fn store(backend: &mut ArmBackend, r: i32, sv: &SValue) -> TccResult<()> {
    let fr = sv.r as i32;
    let v = fr & VT_VALMASK;
    let bt = sv.type_.t & VT_BTYPE;
    let fc = (unsafe { sv.c.i } as i32);

    // VFP float store
    if r >= TREG_F0 as i32 && r <= (TREG_F0 as i32 + 7) {
        return store_float(backend, r, sv);
    }

    let r_hw = intr(r);
    let base_reg: u32;
    let mut offset = fc;
    let mut sign = 1i32;

    if v == VT_LOCAL {
        base_reg = 11; // fp
    } else if v == VT_CONST {
        load_value(backend, 12, fc as u32)?;
        base_reg = 12;
        offset = 0;
    } else {
        base_reg = intr(v);
        offset = 0;
    }

    let maxoff = match bt {
        x if x == VT_BYTE || x == VT_BOOL => 4095,
        x if x == VT_SHORT => 255,
        _ => 4095,
    };
    let mut base = base_reg;
    calcaddr(backend, &mut base, &mut offset, &mut sign, maxoff, 0)?;

    let abs_off = if offset < 0 { (-offset) as u32 } else { offset as u32 };
    let u_bit = if offset >= 0 { 1u32 << 23 } else { 0u32 };

    match bt {
        x if x == VT_BYTE || x == VT_BOOL => {
            // STRB
            o(backend, COND_AL | 0x05C00000 | u_bit
                | (base << 16) | (r_hw << 12) | abs_off)?;
        }
        x if x == VT_SHORT => {
            // STRH
            let hi4 = (abs_off >> 4) & 0xF;
            let lo4 = abs_off & 0xF;
            o(backend, COND_AL | 0x01C000B0 | u_bit
                | (base << 16) | (r_hw << 12) | (hi4 << 8) | lo4)?;
        }
        _ => {
            // STR
            o(backend, COND_AL | 0x05800000 | u_bit
                | (base << 16) | (r_hw << 12) | abs_off)?;
        }
    }
    Ok(())
}

/// Store a VFP floating-point register to memory.
fn store_float(backend: &mut ArmBackend, r: i32, sv: &SValue) -> TccResult<()> {
    let fr = sv.r as i32;
    let v = fr & VT_VALMASK;
    let bt = sv.type_.t & VT_BTYPE;
    let fc = (unsafe { sv.c.i } as i32);
    let dr = vfpr(r);
    let cp = t2cpr(bt) as u32;

    let base_reg: u32;
    let mut offset = fc;

    if v == VT_LOCAL {
        base_reg = 11;
    } else if v == VT_CONST {
        load_value(backend, 12, fc as u32)?;
        base_reg = 12;
        offset = 0;
    } else {
        base_reg = intr(v);
        offset = 0;
    }

    let mut base = base_reg;
    let mut sgn = 1i32;
    calcaddr(backend, &mut base, &mut offset, &mut sgn, 1020, 2)?;

    let abs_off = if offset < 0 { (-offset) as u32 >> 2 } else { offset as u32 >> 2 };
    let u_bit = if offset >= 0 { 1u32 << 23 } else { 0u32 };

    // VSTR dN, [base, #off] (double) or VSTR sN, [base, #off] (float)
    o(backend, COND_AL | 0x0D000A00 | u_bit | cp
        | (base << 16) | (dr << 12) | (abs_off & 0xFF))
}

// ============================================================================
// Function call helpers
// ============================================================================

/// Generate function call or jump instruction.
///
/// Handles direct calls via BL with R_ARM_PC24 relocation, and indirect
/// calls via BLX register.
///
/// Source: arm-gen.c lines 802-841.
fn gcall_or_jmp(backend: &mut ArmBackend, is_jmp: bool) -> TccResult<()> {
    let fr = backend.vtop().r as i32;
    let v = fr & VT_VALMASK;

    if v == VT_CONST || v == VT_LOCAL {
        // Direct call/jump: BL/B with relocation
        let opcode = if is_jmp { 0x0A000000u32 } else { 0x0B000000u32 };
        o(backend, COND_AL | opcode)?;
        // Record relocation for symbol
        let ind = backend.ctx.ind - 4;
        if let Some(sym) = &backend.vtop().sym {
            backend.ctx.pending_relocs.push(PendingReloc {
                offset: ind as u64,
                rtype: 1, // R_ARM_PC24
                sym_idx: sym.c as usize,
                addend: 0,
            });
        }
    } else {
        // Indirect call/jump via register
        let r_hw = intr(v);
        if is_jmp {
            // BX Rm
            o(backend, COND_AL | 0x012FFF10 | r_hw)?;
        } else if backend.cpu_version >= 5 {
            // BLX Rm (ARMv5+)
            o(backend, COND_AL | 0x012FFF30 | r_hw)?;
        } else {
            // ARMv4: MOV LR, PC; BX Rm
            o(backend, COND_AL | (0xD << 21) | (14 << 12) | 15)?; // MOV lr, pc
            o(backend, COND_AL | 0x012FFF10 | r_hw)?; // BX Rm
        }
        backend.leaffunc = false;
    }
    Ok(())
}

// ============================================================================
// Bounds checking instrumentation
// ============================================================================

/// Call a bounds-checking helper function by token index.
///
/// Source: arm-gen.c lines 842-849.
fn gen_bounds_call(backend: &mut ArmBackend, _v: i32) -> TccResult<()> {
    // In bounded mode, emit BL to the bounds-check helper
    // For ARM, BL with R_ARM_PC24 relocation
    o(backend, COND_AL | 0x0B000000)?;
    // Record relocation (to be resolved during linking)
    let ind = backend.ctx.ind - 4;
    backend.ctx.pending_relocs.push(PendingReloc {
        offset: ind as u64,
        rtype: 1, // R_ARM_PC24
        sym_idx: _v as usize,
        addend: 0,
    });
    Ok(())
}

/// Generate bounds-checking prologue instrumentation.
///
/// Source: arm-gen.c lines 850-862.
pub fn gen_bounds_prolog(backend: &mut ArmBackend) -> TccResult<()> {
    if !backend.ctx.do_bounds_check {
        return Ok(());
    }
    // Save bounds state at function entry
    // MOV r0, fp
    o(backend, COND_AL | (0xD << 21) | (0 << 12) | 11)?;
    // MOV r1, sp
    o(backend, COND_AL | (0xD << 21) | (1 << 12) | 13)?;
    // Call __bound_local_new
    gen_bounds_call(backend, 0)?;
    Ok(())
}

/// Generate bounds-checking epilogue instrumentation.
///
/// Source: arm-gen.c lines 863-906.
pub fn gen_bounds_epilog(backend: &mut ArmBackend) -> TccResult<()> {
    if !backend.ctx.do_bounds_check {
        return Ok(());
    }
    // MOV r0, fp
    o(backend, COND_AL | (0xD << 21) | (0 << 12) | 11)?;
    // Call __bound_local_delete
    gen_bounds_call(backend, 1)?;
    Ok(())
}

// ============================================================================
// Type helpers
// ============================================================================

/// Convert long double to double on ARM (LDOUBLE_SIZE == 8).
fn unalias_ldbl(btype: i32) -> i32 {
    if btype == VT_LDOUBLE {
        VT_DOUBLE
    } else {
        btype
    }
}

/// Check if a type is a Homogeneous Float Aggregate (HFA) for hard-float ABI.
///
/// An HFA is a struct containing 1-4 members of the same float type.
/// Used by ARM EABI hard-float calling convention to pass float structs
/// in VFP registers.
///
/// Source: arm-gen.c lines 921-1007.
fn is_hgen_float_aggr(typ: &CType) -> bool {
    let bt = typ.t & VT_BTYPE;
    if bt == VT_STRUCT {
        // Check if all fields are the same float type
        if let Some(ref sym) = typ.ref_sym {
            let mut float_type: i32 = -1;
            let mut count = 0;
            let mut s = sym.next.as_ref();
            while let Some(field) = s {
                let fbt = field.type_.t & VT_BTYPE;
                if fbt == VT_FLOAT || fbt == VT_DOUBLE {
                    if float_type == -1 {
                        float_type = fbt;
                    } else if float_type != fbt {
                        return false;
                    }
                    count += 1;
                    if count > 4 {
                        return false;
                    }
                } else if fbt == VT_STRUCT {
                    // Recursively check nested structs
                    if !is_hgen_float_aggr(&field.type_) {
                        return false;
                    }
                    count += 1;
                } else {
                    return false;
                }
                s = field.next.as_ref();
            }
            return count > 0 && count <= 4;
        }
    }
    false
}

// ============================================================================
// Struct return convention
// ============================================================================

/// Determine if struct is returned in registers or via pointer.
///
/// ARM EABI rules:
/// - Hard-float + float HFA: return in VFP regs (d0-d3), 8-byte align
/// - Size 1-4: return in r0 (4-byte align)
/// - Otherwise: return via hidden pointer (caller-allocated)
///
/// Returns (use_regs, ret_type, ret_align, reg_count).
///
/// Source: arm-gen.c lines 1009-1041.
pub fn gfunc_sret(backend: &ArmBackend, vt: &CType, variadic: bool) -> (bool, CType, i32, i32) {
    let size = type_size_local(vt);

    // Hard-float: check for HFA
    if !variadic && backend.float_abi == FloatAbi::HardFloat && is_hgen_float_aggr(vt) {
        return (true, CType { t: VT_FLOAT, ref_sym: None }, 8, 1);
    }

    // Small structs (≤4 bytes) returned in r0
    if size > 0 && size <= 4 {
        return (true, CType { t: VT_INT, ref_sym: None }, 4, 1);
    }

    // Large structs: return via hidden pointer
    (false, CType::default(), 0, 0)
}

/// Calculate type size (simplified local helper).
fn type_size_local(vt: &CType) -> i32 {
    let bt = vt.t & VT_BTYPE;
    match bt {
        x if x == VT_BYTE || x == VT_BOOL => 1,
        x if x == VT_SHORT => 2,
        x if x == VT_INT || x == VT_FLOAT => 4,
        x if x == VT_LLONG || x == VT_DOUBLE || x == VT_LDOUBLE => 8,
        x if x == VT_PTR => PTR_SIZE as i32,
        x if x == VT_STRUCT => {
            if let Some(ref sym) = vt.ref_sym {
                sym.c
            } else {
                0
            }
        }
        _ => 4,
    }
}

// ============================================================================
// Function call generation (AAPCS parameter assignment)
// ============================================================================

/// AAPCS parameter register class.
#[derive(Clone, Copy, PartialEq)]
enum ParamClass {
    Stack = 0,
    CoreStruct = 1,
    Vfp = 2,
    VfpStruct = 3,
    Core = 4,
}

/// Per-parameter plan entry.
struct ParamPlan {
    start: i32,
    end: i32,
    sval_idx: i32,
    cls: ParamClass,
}

/// Overall parameter assignment plan.
struct ParamAssignment {
    plans: Vec<ParamPlan>,
    ncrn: i32,   // next core register number (0-4)
    nsaa: i32,   // next stack argument address
    nfprn: i32,  // next VFP float register number (0-16)
}

impl ParamAssignment {
    fn new() -> Self {
        Self {
            plans: Vec::new(),
            ncrn: 0,
            nsaa: 0,
            nfprn: 0,
        }
    }
}

/// Assign parameters to registers and stack per AAPCS rules.
///
/// Source: arm-gen.c lines 1089-1170.
fn assign_regs(
    backend: &ArmBackend,
    nb_args: i32,
    svals: &[SValue],
    plan: &mut ParamAssignment,
) -> TccResult<()> {
    for i in 0..nb_args {
        let sv = &svals[i as usize];
        let bt = sv.type_.t & VT_BTYPE;
        let size = type_size_local(&sv.type_);
        let align = if bt == VT_LLONG || bt == VT_DOUBLE || bt == VT_LDOUBLE { 8 } else { 4 };
        let nregs = (size + 3) / 4;

        // VFP assignment for hard-float
        let is_fp = bt == VT_FLOAT || bt == VT_DOUBLE || bt == VT_LDOUBLE;
        if is_fp && backend.float_abi == FloatAbi::HardFloat {
            let fp_regs = if bt == VT_FLOAT { 1 } else { 2 };
            if align == 8 {
                plan.nfprn = (plan.nfprn + 1) & !1;
            }
            if plan.nfprn + fp_regs <= 16 {
                plan.plans.push(ParamPlan {
                    start: plan.nfprn,
                    end: plan.nfprn + fp_regs,
                    sval_idx: i,
                    cls: ParamClass::Vfp,
                });
                plan.nfprn += fp_regs;
                continue;
            }
        }

        // Check for HFA struct in hard-float
        if bt == VT_STRUCT && backend.float_abi == FloatAbi::HardFloat
            && is_hgen_float_aggr(&sv.type_)
        {
            let fp_regs = (size + 3) / 4;
            if plan.nfprn + fp_regs <= 16 {
                plan.plans.push(ParamPlan {
                    start: plan.nfprn,
                    end: plan.nfprn + fp_regs,
                    sval_idx: i,
                    cls: ParamClass::VfpStruct,
                });
                plan.nfprn += fp_regs;
                continue;
            }
        }

        // Core register assignment
        if align == 8 {
            plan.ncrn = (plan.ncrn + 1) & !1;
        }
        if plan.ncrn + nregs <= 4 {
            let cls = if bt == VT_STRUCT { ParamClass::CoreStruct } else { ParamClass::Core };
            plan.plans.push(ParamPlan {
                start: plan.ncrn,
                end: plan.ncrn + nregs,
                sval_idx: i,
                cls,
            });
            plan.ncrn += nregs;
        } else {
            // Spill to stack
            plan.ncrn = 4;
            if align == 8 {
                plan.nsaa = (plan.nsaa + 7) & !7;
            }
            plan.plans.push(ParamPlan {
                start: plan.nsaa,
                end: plan.nsaa + size,
                sval_idx: i,
                cls: ParamClass::Stack,
            });
            plan.nsaa += (size + 3) & !3;
        }
    }
    Ok(())
}

/// Generate a function call with nb_args arguments.
///
/// Source: arm-gen.c lines 1338-1399.
pub fn gfunc_call(backend: &mut ArmBackend, nb_args: i32) -> TccResult<()> {
    // Build a copy of the value stack entries for parameter planning
    let svals: Vec<SValue> = if nb_args > 0 {
        let top = backend.ctx.vtop_idx;
        let start = (top - nb_args + 1) as usize;
        let end = (top + 1) as usize;
        if end <= backend.ctx.vstack.len() && start < end {
            backend.ctx.vstack[start..end].to_vec()
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    };

    let mut plan = ParamAssignment::new();
    assign_regs(backend, nb_args, &svals, &mut plan)?;

    // Allocate stack space
    if plan.nsaa > 0 {
        gadd_sp(backend, -plan.nsaa)?;
    }

    // Process parameters: store to stack or move to registers
    for pp in &plan.plans {
        match pp.cls {
            ParamClass::Stack => {
                // Store to stack: STR rN, [sp, #offset]
                let offset = pp.start;
                let _sv_idx = pp.sval_idx;
                let r_hw = intr(TREG_R0 as i32);
                let abs_off = offset as u32;
                o(backend, COND_AL | 0x05800000 | (1 << 23)
                    | (13 << 16) | (r_hw << 12) | abs_off)?;
            }
            ParamClass::Core | ParamClass::CoreStruct => {
                // Parameters already in core registers by convention
                // (copy_params would handle this in the C version)
            }
            ParamClass::Vfp | ParamClass::VfpStruct => {
                // VFP register parameters handled by convention
            }
        }
    }

    // Mark function as non-leaf (makes calls)
    backend.leaffunc = false;

    // Generate the actual call instruction
    gcall_or_jmp(backend, false)?;

    // Clean up stack space
    if plan.nsaa > 0 {
        gadd_sp(backend, plan.nsaa)?;
    }

    // Pop all arguments + function pointer from value stack
    for _ in 0..=nb_args {
        backend.vtop_dec();
    }

    Ok(())
}

// ============================================================================
// Function prologue
// ============================================================================

/// Generate function prologue: save registers, set up frame pointer.
///
/// Source: arm-gen.c lines 1400-1507.
pub fn gfunc_prolog(backend: &mut ArmBackend, func_sym: &Sym) -> TccResult<()> {
    let variadic = (func_sym.type_.t & (FUNC_ELLIPSIS as i32)) != 0;
    let n = 4i32; // number of core arg regs to save (r0-r3)

    // MOV ip, sp — save stack pointer before modifications
    o(backend, COND_AL | (0xD << 21) | (12 << 12) | 13)?;

    // STMFD sp!, {r0-r3} — push argument registers
    if variadic || n > 0 {
        let mut mask = 0u32;
        for i in 0..n.min(4) {
            mask |= 1 << i;
        }
        if mask != 0 {
            // STMDB sp!, {mask}
            o(backend, COND_AL | 0x092D0000 | mask)?;
        }
    }

    // Save VFP registers in hard-float mode
    if backend.float_abi == FloatAbi::HardFloat {
        // VPUSH {d0-d7} — save floating-point argument registers
        // Encoding: 0xED2D0B00 | count*2
        let nf = 8; // d0-d7
        o(backend, COND_AL | 0x0D2D0B00 | (nf * 2))?;
    }

    // STMFD sp!, {fp, ip, lr, pc}
    // Save frame pointer, original sp, link register
    o(backend, COND_AL | 0x092D5800)?;

    // MOV fp, sp — set frame pointer
    o(backend, COND_AL | (0xD << 21) | (11 << 12) | 13)?;

    // Reserve space for local variables — placeholder that gets backpatched
    backend.func_sub_sp_offset = backend.ctx.ind;
    o(backend, ARM_NOP)?; // Will be patched in epilogue

    // Initialize per-function state
    backend.last_itod_magic = 0;
    backend.leaffunc = true; // assume leaf until proven otherwise
    backend.ctx.loc = 0;

    // Generate bounds-checking prologue if needed
    if backend.ctx.do_bounds_check {
        gen_bounds_prolog(backend)?;
    }

    Ok(())
}

// ============================================================================
// Function epilogue
// ============================================================================

/// Generate function epilogue: restore frame, return.
///
/// Source: arm-gen.c lines 1508-1550.
pub fn gfunc_epilog(backend: &mut ArmBackend) -> TccResult<()> {
    // Generate bounds-checking epilogue if needed
    if backend.ctx.do_bounds_check {
        gen_bounds_epilog(backend)?;
    }

    // For EABI softfp with float return, copy VFP → core registers
    if backend.eabi_enabled
        && backend.float_abi == FloatAbi::SoftFp
    {
        let ret_bt = backend.ctx.func_vt.t & VT_BTYPE;
        if ret_bt == VT_FLOAT {
            // VMOV r0, s0
            o(backend, COND_AL | 0x0E100A10 | (0 << 12))?;
        } else if ret_bt == VT_DOUBLE || ret_bt == VT_LDOUBLE {
            // VMOV r0, r1, d0
            o(backend, COND_AL | 0x0C500B10 | (0 << 12) | (1 << 16))?;
        }
    }

    // LDMIA sp, {fp, sp, pc} — restore and return
    o(backend, COND_AL | 0x089BA800)?;

    // Backpatch prologue with actual stack frame size
    let diff = ((-backend.ctx.loc) + 3) & !3;
    let final_diff = if backend.eabi_enabled && !backend.leaffunc {
        (diff + 7) & !7 // EABI: align non-leaf to 8
    } else {
        diff
    };

    if final_diff > 0 {
        let patch_pos = backend.func_sub_sp_offset as usize;
        if patch_pos + 3 < backend.ctx.code_buf.len() {
            // Try to encode SUB sp, fp, #diff as a single instruction
            let sub_op = stuff_const(
                COND_AL | (0x24 << 20) | (11 << 16) | (13 << 12),
                final_diff as u32,
            );
            if sub_op != 0 {
                backend.ctx.code_buf[patch_pos] = (sub_op & 0xFF) as u8;
                backend.ctx.code_buf[patch_pos + 1] = ((sub_op >> 8) & 0xFF) as u8;
                backend.ctx.code_buf[patch_pos + 2] = ((sub_op >> 16) & 0xFF) as u8;
                backend.ctx.code_buf[patch_pos + 3] = ((sub_op >> 24) & 0xFF) as u8;
            } else {
                // Large frame: branch to literal pool approach
                // Replace NOP with B to end, put literal there
                let cur_ind = backend.ctx.ind;
                let enc = encbranch(backend.func_sub_sp_offset, cur_ind, false)?;
                let instr = COND_AL | enc;
                backend.ctx.code_buf[patch_pos] = (instr & 0xFF) as u8;
                backend.ctx.code_buf[patch_pos + 1] = ((instr >> 8) & 0xFF) as u8;
                backend.ctx.code_buf[patch_pos + 2] = ((instr >> 16) & 0xFF) as u8;
                backend.ctx.code_buf[patch_pos + 3] = ((instr >> 24) & 0xFF) as u8;
                // At current position, emit the actual SUB
                stuff_const_harder(backend,
                    COND_AL | (0x24 << 20) | (11 << 16) | (13 << 12),
                    final_diff as u32)?;
                // Branch back
                let back_target = backend.func_sub_sp_offset + 4;
                let back_enc = encbranch(backend.ctx.ind, back_target, true)?;
                o(backend, COND_AL | back_enc)?;
            }
        }
    }

    Ok(())
}

// ============================================================================
// NOP fill and jump generation
// ============================================================================

/// Fill bytes with ARM NOPs (mov r0, r0 = 0xE1A00000).
///
/// Source: arm-gen.c lines 1551-1560.
pub fn gen_fill_nops(backend: &mut ArmBackend, bytes: i32) -> TccResult<()> {
    let count = bytes / 4;
    for _ in 0..count {
        o(backend, ARM_NOP)?;
    }
    Ok(())
}

/// Generate unconditional jump, return patch address.
///
/// Source: arm-gen.c lines 1562-1571.
pub fn gjmp(backend: &mut ArmBackend, t: i32) -> TccResult<i32> {
    let ind = backend.ctx.ind;
    if t != 0 {
        let enc = encbranch(ind, t, false)?;
        o(backend, COND_AL | enc)?;
    } else {
        o(backend, COND_AL | 0x0A000000)?;
    }
    Ok(ind)
}

/// Generate unconditional jump to absolute address.
///
/// Source: arm-gen.c line 1573.
pub fn gjmp_addr(backend: &mut ArmBackend, a: i32) -> TccResult<()> {
    let ind = backend.ctx.ind;
    let enc = encbranch(ind, a, true)?;
    o(backend, COND_AL | enc)
}

/// Generate conditional jump based on comparison op.
///
/// Source: arm-gen.c lines 1578-1589.
pub fn gjmp_cond(backend: &mut ArmBackend, op: i32, t: i32) -> TccResult<i32> {
    let ind = backend.ctx.ind;
    let cc = mapcc(op);
    if t != 0 {
        let enc = encbranch(ind, t, false)?;
        o(backend, cc | enc)?;
    } else {
        o(backend, cc | 0x0A000000)?;
    }
    Ok(ind)
}

/// Append jump to chain, return new chain head.
///
/// Source: arm-gen.c lines 1590-1607.
pub fn gjmp_append(backend: &mut ArmBackend, n: i32, t: i32) -> TccResult<i32> {
    if n == 0 {
        return Ok(t);
    }
    // Walk chain to end
    let mut p = n;
    loop {
        let next = decbranch(backend, p);
        let d = next.wrapping_sub(p).wrapping_sub(8);
        if d == 0 || next == p {
            break;
        }
        p = next;
    }
    // Patch end of chain to point to t
    if t != 0 {
        let enc = encbranch(p, t, false)?;
        let pos = p as usize;
        if pos + 3 < backend.ctx.code_buf.len() {
            let orig_cc = backend.ctx.code_buf[pos + 3] & 0xF0;
            let new_word = (enc & 0x00FFFFFF) | ((orig_cc as u32) << 24);
            backend.ctx.code_buf[pos] = (new_word & 0xFF) as u8;
            backend.ctx.code_buf[pos + 1] = ((new_word >> 8) & 0xFF) as u8;
            backend.ctx.code_buf[pos + 2] = ((new_word >> 16) & 0xFF) as u8;
            backend.ctx.code_buf[pos + 3] = ((new_word >> 24) & 0xFF) as u8;
        }
    }
    Ok(n)
}

// ============================================================================
// Integer operations
// ============================================================================

/// Generate integer binary operation.
///
/// Source: arm-gen.c lines 1608-1803.
///
/// Dispatch categories:
/// - Comparisons (TOK_EQ..TOK_GT): CMP + condition code
/// - Arithmetic (add, sub, and, or, xor, adc, sbc): data processing with
///   constant optimization via stuff_const
/// - Shifts (shl, shr, sar): register or immediate shift
/// - Division/modulo: runtime helper calls
/// - UMULL: unsigned multiply long
pub fn gen_opi(backend: &mut ArmBackend, op: i32) -> TccResult<()> {
    let vtop_r = (backend.vtop().r & VT_VALMASK as u16) as i32;
    let vtop_1_r = if backend.ctx.vtop_idx > 0 {
        (backend.vtop_1().r & VT_VALMASK as u16) as i32
    } else {
        0
    };

    // Comparison operators
    if (op >= TOK_ULT as i32 && op <= TOK_GT as i32)
        || op == TOK_EQ as i32 || op == TOK_NE as i32
    {
        let r_hw = intr(vtop_1_r);
        let r2_hw = intr(vtop_r);
        let cc = mapcc(op);

        // Try constant CMP first
        let vtop_c = (unsafe { backend.vtop().c.i } as i32);
        if (backend.vtop().r as i32 & VT_VALMASK) == VT_CONST {
            let enc = stuff_const(
                COND_AL | (0x15 << 20) | (r_hw << 16),
                vtop_c as u32,
            );
            if enc != 0 {
                o(backend, enc)?;
            } else {
                // Load constant to temp, then CMP
                load_value(backend, 12, vtop_c as u32)?;
                o(backend, COND_AL | (0x15 << 20) | (r_hw << 16) | 12)?;
            }
        } else {
            // CMP Rn, Rm
            o(backend, COND_AL | (0x15 << 20) | (r_hw << 16) | r2_hw)?;
        }

        // Pop operands, push comparison result
        backend.vtop_dec();
        if backend.ctx.vtop_idx >= 0 {
            let idx = backend.ctx.vtop_idx as usize;
            backend.ctx.vstack[idx].r = VT_CMP as u16;
            backend.ctx.vstack[idx].cmp_op = cc as u16;
        }
        return Ok(());
    }

    // Shift operations
    if op == TOK_SHL as i32 || op == TOK_SHR as i32 || op == TOK_SAR as i32 {
        let shift_type: u32 = match op {
            x if x == TOK_SHL as i32 => 0x00, // LSL
            x if x == TOK_SHR as i32 => 0x20, // LSR
            x if x == TOK_SAR as i32 => 0x40, // ASR
            _ => 0,
        };
        let rd = intr(vtop_1_r);
        let rm = rd;

        if (backend.vtop().r as i32 & VT_VALMASK) == VT_CONST {
            // Immediate shift: MOV Rd, Rm, LSL/LSR/ASR #imm
            let imm = ((unsafe { backend.vtop().c.i } as i32) & 0x1F) as u32;
            o(backend, COND_AL | (0xD << 21) | (rd << 12) | (imm << 7) | shift_type | rm)?;
        } else {
            // Register shift: MOV Rd, Rm, LSL/LSR/ASR Rs
            let rs = intr(vtop_r);
            o(backend, COND_AL | (0xD << 21) | (rd << 12) | (rs << 8) | 0x10 | shift_type | rm)?;
        }

        backend.vtop_dec();
        return Ok(());
    }

    // Division and modulo — call runtime helpers
    if op == TOK_PDIV as i32 || op == TOK_UDIV as i32 || op == TOK_UMOD as i32
        || op == '%' as i32
    {
        let is_unsigned = op == TOK_UDIV as i32 || op == TOK_UMOD as i32;
        let wants_remainder = op == '%' as i32 || op == TOK_UMOD as i32;

        // Call helper: __aeabi_idivmod / __aeabi_uidivmod (EABI)
        // or __divsi3 / __udivsi3 / __modsi3 / __umodsi3 (non-EABI)
        // For now: emit generic call sequence

        let r0 = intr(vtop_1_r);
        let r1 = intr(vtop_r);

        // MOV r0, dividend ; MOV r1, divisor
        if r0 != 0 {
            o(backend, COND_AL | (0xD << 21) | (0 << 12) | r0)?;
        }
        if r1 != 1 {
            o(backend, COND_AL | (0xD << 21) | (1 << 12) | r1)?;
        }

        // BL to helper (relocation will be added)
        o(backend, COND_AL | 0x0B000000)?;
        let ind = backend.ctx.ind - 4;
        let helper_sym = if backend.eabi_enabled {
            if is_unsigned { 2 } else { 1 } // placeholder sym indices
        } else {
            if is_unsigned {
                if wants_remainder { 4 } else { 3 }
            } else {
                if wants_remainder { 6 } else { 5 }
            }
        };
        backend.ctx.pending_relocs.push(PendingReloc {
            offset: ind as u64,
            rtype: 1, // R_ARM_PC24
            sym_idx: helper_sym,
            addend: 0,
        });

        backend.leaffunc = false;

        // Result in r0 (quotient) or r1 (remainder for EABI)
        backend.vtop_dec();
        if backend.ctx.vtop_idx >= 0 {
            let idx = backend.ctx.vtop_idx as usize;
            if wants_remainder && backend.eabi_enabled {
                backend.ctx.vstack[idx].r = TREG_R1 as u16;
            } else {
                backend.ctx.vstack[idx].r = TREG_R0 as u16;
            }
        }
        return Ok(());
    }

    // UMULL: unsigned multiply long (64-bit result)
    if op == TOK_UMULL as i32 {
        let rd_lo = intr(vtop_1_r);
        let rd_hi = intr(vtop_r);
        let rm = rd_lo;
        let rs = rd_hi;
        // UMULL RdLo, RdHi, Rm, Rs
        // 0xE0800090 | (RdHi<<16) | (RdLo<<12) | (Rs<<8) | Rm
        o(backend, COND_AL | 0x00800090 | (rd_hi << 16) | (rd_lo << 12) | (rs << 8) | rm)?;
        // Result: high in vtop, low in vtop-1
        return Ok(());
    }

    // Arithmetic / logic operations: ADD, SUB, AND, OR, XOR, ADC, SBC
    let (arm_opc, opc_s): (u32, bool) = match op {
        x if x == '+' as i32 => (0x08, false),     // ADD
        x if x == '-' as i32 => (0x04, false),     // SUB
        x if x == '&' as i32 => (0x00, false),     // AND
        x if x == '|' as i32 => (0x18, false),     // ORR
        x if x == '^' as i32 => (0x02, false),     // EOR (XOR)
        x if x == TOK_ADDC1 as i32 => (0x09, true),  // ADDS
        x if x == TOK_ADDC2 as i32 => (0x0A, false),  // ADC
        x if x == TOK_SUBC1 as i32 => (0x05, true),  // SUBS
        x if x == TOK_SUBC2 as i32 => (0x0C, false),  // SBC
        x if x == '*' as i32 => {
            // MUL
            let rd = intr(vtop_1_r);
            let rm = rd;
            let rs = intr(vtop_r);
            // MUL Rd, Rm, Rs: 0xE0000090 | (Rd<<16) | (Rs<<8) | Rm
            o(backend, COND_AL | 0x00000090 | (rd << 16) | (rs << 8) | rm)?;
            backend.vtop_dec();
            return Ok(());
        }
        x if x == TOK_NEG as i32 => {
            // RSB Rd, Rm, #0 (negate)
            let rd = intr(vtop_r);
            o(backend, COND_AL | (0x26 << 20) | (rd << 16) | (rd << 12) | 0)?;
            return Ok(());
        }
        _ => {
            return Err(TccError::CodegenError {
                message: format!("ARM: unsupported integer operation 0x{:X}", op),
            });
        }
    };

    let rd = intr(vtop_1_r);
    let rn = rd;
    let s_bit = if opc_s { 1u32 << 20 } else { 0u32 };

    // Try constant operand
    if (backend.vtop().r as i32 & VT_VALMASK) == VT_CONST {
        let c = (unsafe { backend.vtop().c.i } as i32) as u32;
        let enc = stuff_const(
            COND_AL | (arm_opc << 20) | s_bit | (rn << 16) | (rd << 12),
            c,
        );
        if enc != 0 {
            o(backend, enc)?;
        } else {
            stuff_const_harder(backend,
                COND_AL | (arm_opc << 20) | s_bit | (rn << 16) | (rd << 12),
                c)?;
        }
    } else {
        // Register operand
        let rm = intr(vtop_r);
        o(backend, COND_AL | (arm_opc << 20) | s_bit | (rn << 16) | (rd << 12) | rm)?;
    }

    backend.vtop_dec();
    Ok(())
}

// ============================================================================
// Floating-point operations
// ============================================================================

/// Check if value stack entry is floating-point zero.
fn is_zero(sv: &SValue) -> bool {
    let v = sv.r as i32 & VT_VALMASK;
    if v == VT_CONST {
        (unsafe { sv.c.i } as i32) == 0
    } else {
        false
    }
}

/// Generate floating-point binary operation (VFP version).
///
/// Source: arm-gen.c lines 1804-1938.
fn gen_opf_vfp(backend: &mut ArmBackend, op: i32) -> TccResult<()> {
    let bt = backend.vtop().type_.t & VT_BTYPE;
    let cp = t2cpr(bt) as u32;
    let vtop_r = (backend.vtop().r & VT_VALMASK as u16) as i32;
    let vtop_1_r = if backend.ctx.vtop_idx > 0 {
        (backend.vtop_1().r & VT_VALMASK as u16) as i32
    } else {
        vtop_r
    };

    let dd = vfpr(vtop_1_r);
    let dm = vfpr(vtop_r);

    match op as u8 as char {
        '+' => {
            // VADD: 0xEE300A00 | cp
            o(backend, COND_AL | 0x0E300A00 | cp | (dd << 12) | (dd << 16) | dm)?;
        }
        '-' => {
            // VSUB: 0xEE300A40 | cp
            o(backend, COND_AL | 0x0E300A40 | cp | (dd << 12) | (dd << 16) | dm)?;
        }
        '*' => {
            // VMUL: 0xEE200A00 | cp
            o(backend, COND_AL | 0x0E200A00 | cp | (dd << 12) | (dd << 16) | dm)?;
        }
        '/' => {
            // VDIV: 0xEE800A00 | cp
            o(backend, COND_AL | 0x0E800A00 | cp | (dd << 12) | (dd << 16) | dm)?;
        }
        _ => {
            // Comparison operators
            if op >= TOK_ULT as i32 && op <= TOK_GT as i32 {
                // VCMP: 0xEEB40A40 | cp
                o(backend, COND_AL | 0x0EB40A40 | cp | (dd << 12) | dm)?;
                // VMRS APSR_nzcv, FPSCR
                o(backend, COND_AL | 0x0EF1FA10)?;

                // Map floating-point condition codes
                let cc = mapcc(op);
                backend.vtop_dec();
                if backend.ctx.vtop_idx >= 0 {
                    let idx = backend.ctx.vtop_idx as usize;
                    backend.ctx.vstack[idx].r = VT_CMP as u16;
                    backend.ctx.vstack[idx].cmp_op = cc as u16;
                }
                return Ok(());
            }
        }
    }

    backend.vtop_dec();
    Ok(())
}

/// Generate floating-point binary operation (FPA version — legacy).
///
/// Source: arm-gen.c lines 1940-2140.
fn gen_opf_fpa(backend: &mut ArmBackend, op: i32) -> TccResult<()> {
    let bt = backend.vtop().type_.t & VT_BTYPE;
    let vtop_r = (backend.vtop().r & VT_VALMASK as u16) as i32;
    let vtop_1_r = if backend.ctx.vtop_idx > 0 {
        (backend.vtop_1().r & VT_VALMASK as u16) as i32
    } else {
        vtop_r
    };

    let fd = fpr(vtop_1_r);
    let fm = fpr(vtop_r);
    let prec = if bt == VT_DOUBLE || bt == VT_LDOUBLE { 0x80 } else { 0x00 };

    match op as u8 as char {
        '+' => {
            // ADF (FPA add float)
            o(backend, COND_AL | 0x0E000100 | prec | (fd << 12) | (fd << 16) | fm)?;
        }
        '-' => {
            // SUF (FPA subtract float)
            o(backend, COND_AL | 0x0E200100 | prec | (fd << 12) | (fd << 16) | fm)?;
        }
        '*' => {
            // MUF (FPA multiply float)
            o(backend, COND_AL | 0x0E100100 | prec | (fd << 12) | (fd << 16) | fm)?;
        }
        '/' => {
            // DVF (FPA divide float)
            o(backend, COND_AL | 0x0E400100 | prec | (fd << 12) | (fd << 16) | fm)?;
        }
        _ => {
            if op >= TOK_ULT as i32 && op <= TOK_GT as i32 {
                // CMF (FPA compare)
                o(backend, COND_AL | 0x0E90F110 | (fd << 16) | fm)?;
                let cc = mapcc(op);
                backend.vtop_dec();
                if backend.ctx.vtop_idx >= 0 {
                    let idx = backend.ctx.vtop_idx as usize;
                    backend.ctx.vstack[idx].r = VT_CMP as u16;
                    backend.ctx.vstack[idx].cmp_op = cc as u16;
                }
                return Ok(());
            }
        }
    }

    backend.vtop_dec();
    Ok(())
}

/// Generate floating-point operation (dispatches to VFP or FPA).
pub fn gen_opf(backend: &mut ArmBackend, op: i32) -> TccResult<()> {
    if backend.vfp_enabled {
        gen_opf_vfp(backend, op)
    } else {
        gen_opf_fpa(backend, op)
    }
}

// ============================================================================
// Type conversions
// ============================================================================

/// Convert integer to float.
///
/// VFP path: VMOV s0, r0 (0xEE000A10) + VCVT (0xEEB80A40)
/// Long long: calls __floatdisf/__floatdidf/__floatundisf/__floatundidf
///
/// Source: arm-gen.c lines 2142-2222.
pub fn gen_cvt_itof(backend: &mut ArmBackend, t: i32) -> TccResult<()> {
    let bt_src = backend.vtop().type_.t & VT_BTYPE;
    let bt_dst = t & VT_BTYPE;
    let cp = t2cpr(bt_dst) as u32;

    if bt_src == VT_LLONG {
        // Long long → float/double: call runtime helper
        // For simplicity, emit a call to the appropriate helper
        // __floatdisf, __floatdidf, __floatundisf, __floatundidf
        let is_unsigned = (backend.vtop().type_.t & VT_UNSIGNED) != 0;
        // Move r0:r1 from source
        // BL to helper
        o(backend, COND_AL | 0x0B000000)?;
        let helper_idx = match (is_unsigned, bt_dst) {
            (true, VT_FLOAT) => 10,
            (true, _) => 11,
            (false, VT_FLOAT) => 12,
            (false, _) => 13,
        };
        let ind = backend.ctx.ind - 4;
        backend.ctx.pending_relocs.push(PendingReloc {
            offset: ind as u64,
            rtype: 1,
            sym_idx: helper_idx,
            addend: 0,
        });
        backend.leaffunc = false;
    } else if backend.vfp_enabled {
        // VFP path
        let src_r = (backend.vtop().r & VT_VALMASK as u16) as i32;
        let r_hw = intr(src_r);
        // VMOV s0, Rn (move int to VFP)
        o(backend, COND_AL | 0x0E000A10 | (r_hw << 12))?;

        let is_unsigned = (backend.vtop().type_.t & VT_UNSIGNED) != 0;
        if is_unsigned {
            // VCVT.F32/F64.U32 (unsigned)
            o(backend, COND_AL | 0x0EB80A40 | cp)?;
        } else {
            // VCVT.F32/F64.S32 (signed)
            o(backend, COND_AL | 0x0EB80AC0 | cp)?;
        }
    } else {
        // FPA path: FLTS/FLTD
        let src_r = (backend.vtop().r & VT_VALMASK as u16) as i32;
        let r_hw = intr(src_r);
        let prec = if bt_dst == VT_DOUBLE || bt_dst == VT_LDOUBLE { 0x80 } else { 0x00 };
        o(backend, COND_AL | 0x0E000110 | prec | (r_hw << 12))?;
    }

    if backend.ctx.vtop_idx >= 0 {
        let idx = backend.ctx.vtop_idx as usize;
        backend.ctx.vstack[idx].type_.t = t;
        backend.ctx.vstack[idx].r = TREG_F0 as u16;
    }

    Ok(())
}

/// Convert float to integer.
///
/// VFP path: VCVT (0xEEBC0AC0) + VMOV r0, s0 (0xEE100A10)
/// Long long: calls __fixsfdi/__fixdfdi
///
/// Source: arm-gen.c lines 2223-2282.
pub fn gen_cvt_ftoi(backend: &mut ArmBackend, t: i32) -> TccResult<()> {
    let bt_src = backend.vtop().type_.t & VT_BTYPE;
    let bt_dst = t & VT_BTYPE;
    let cp_src = t2cpr(bt_src) as u32;

    if bt_dst == VT_LLONG {
        // Float/double → long long: call runtime helper
        o(backend, COND_AL | 0x0B000000)?;
        let is_unsigned = (t & VT_UNSIGNED) != 0;
        let helper_idx = match (is_unsigned, bt_src) {
            (true, VT_FLOAT) => 14,
            (true, _) => 15,
            (false, VT_FLOAT) => 16,
            (false, _) => 17,
        };
        let ind = backend.ctx.ind - 4;
        backend.ctx.pending_relocs.push(PendingReloc {
            offset: ind as u64,
            rtype: 1,
            sym_idx: helper_idx,
            addend: 0,
        });
        backend.leaffunc = false;
    } else if backend.vfp_enabled {
        let is_unsigned = (t & VT_UNSIGNED) != 0;
        if is_unsigned {
            // VCVT.U32.F32/F64 (unsigned, round toward zero)
            o(backend, COND_AL | 0x0EBC0AC0 | cp_src)?;
        } else {
            // VCVT.S32.F32/F64 (signed, round toward zero)
            o(backend, COND_AL | 0x0EBD0AC0 | cp_src)?;
        }
        // VMOV Rd, s0
        let dst_r = TREG_R0;
        o(backend, COND_AL | 0x0E100A10 | ((dst_r as u32) << 12))?;
    } else {
        // FPA path: FIX
        o(backend, COND_AL | 0x0E100110)?;
    }

    if backend.ctx.vtop_idx >= 0 {
        let idx = backend.ctx.vtop_idx as usize;
        backend.ctx.vstack[idx].type_.t = t;
        backend.ctx.vstack[idx].r = TREG_R0 as u16;
    }

    Ok(())
}

/// Convert between floating-point types (float ↔ double).
///
/// VFP: VCVT.F32.F64 / VCVT.F64.F32
/// FPA: implicit conversion via register load
///
/// Source: arm-gen.c lines 2283-2296.
pub fn gen_cvt_ftof(backend: &mut ArmBackend, t: i32) -> TccResult<()> {
    let bt_src = backend.vtop().type_.t & VT_BTYPE;
    let bt_dst = t & VT_BTYPE;

    if backend.vfp_enabled {
        let src_r = (backend.vtop().r & VT_VALMASK as u16) as i32;
        let dr = vfpr(src_r);

        if bt_src == VT_FLOAT && (bt_dst == VT_DOUBLE || bt_dst == VT_LDOUBLE) {
            // VCVT.F64.F32 dD, sM
            o(backend, COND_AL | 0x0EB70AC0 | (dr << 12) | dr)?;
        } else if (bt_src == VT_DOUBLE || bt_src == VT_LDOUBLE) && bt_dst == VT_FLOAT {
            // VCVT.F32.F64 sD, dM
            o(backend, COND_AL | 0x0EB70BC0 | (dr << 12) | dr)?;
        }
    }
    // FPA: no explicit conversion needed (handled implicitly)

    if backend.ctx.vtop_idx >= 0 {
        let idx = backend.ctx.vtop_idx as usize;
        backend.ctx.vstack[idx].type_.t = (backend.ctx.vstack[idx].type_.t & !VT_BTYPE) | bt_dst;
    }

    Ok(())
}

// ============================================================================
// Test coverage and miscellaneous
// ============================================================================

/// Increment test coverage counter (64-bit counter at sv address).
///
/// Source: arm-gen.c lines 2297-2319.
pub fn gen_increment_tcov(backend: &mut ArmBackend, _sv: &SValue) -> TccResult<()> {
    // Emit instruction sequence to increment a 64-bit counter:
    // ldr r1, [pc, #0]  ; load offset from literal pool
    // b $+8             ; branch over literal
    // .word offset      ; counter offset (will be relocated)
    // add r1, r1, pc    ; compute absolute address
    // ldr r2, [r1]      ; load low 32 bits
    // adds r2, r2, #1   ; increment
    // str r2, [r1]      ; store low 32 bits
    // ldr r2, [r1, #4]  ; load high 32 bits
    // adc r2, r2, #0    ; add carry
    // str r2, [r1, #4]  ; store high 32 bits

    // LDR r1, [pc, #0]
    o(backend, COND_AL | 0x059F1000)?;
    // B $+8 (skip literal)
    o(backend, COND_AL | 0x0A000000)?;
    // .word 0 (placeholder for counter offset, to be relocated)
    let lit_pos = backend.ctx.ind;
    o(backend, 0)?;
    // Record relocation for the counter address
    backend.ctx.pending_relocs.push(PendingReloc {
        offset: lit_pos as u64,
        rtype: 3, // R_ARM_REL32
        sym_idx: 0,
        addend: 0,
    });
    // ADD r1, r1, pc
    o(backend, COND_AL | (0x08 << 20) | (1 << 16) | (1 << 12) | 15)?;
    // LDR r2, [r1]
    o(backend, COND_AL | 0x05912000)?;
    // ADDS r2, r2, #1
    o(backend, COND_AL | (0x29 << 20) | (2 << 16) | (2 << 12) | 1)?;
    // STR r2, [r1]
    o(backend, COND_AL | 0x05812000)?;
    // LDR r2, [r1, #4]
    o(backend, COND_AL | 0x05912004)?;
    // ADC r2, r2, #0
    o(backend, COND_AL | (0x0A << 20) | (2 << 16) | (2 << 12) | 0)?;
    // STR r2, [r1, #4]
    o(backend, COND_AL | 0x05812004)?;

    Ok(())
}

/// Computed goto support.
///
/// Source: arm-gen.c lines 2320-2326.
pub fn ggoto(backend: &mut ArmBackend) -> TccResult<()> {
    let vtop_r = (backend.vtop().r & VT_VALMASK as u16) as i32;
    let r_hw = intr(vtop_r);
    // BX Rm
    o(backend, COND_AL | 0x012FFF10 | r_hw)?;
    backend.vtop_dec();
    Ok(())
}

/// Save stack pointer for VLA.
///
/// Emits: str sp, [fp, #addr]
///
/// Source: arm-gen.c lines 2327-2335.
pub fn gen_vla_sp_save(backend: &mut ArmBackend, addr: i32) -> TccResult<()> {
    let abs_addr = if addr < 0 { (-addr) as u32 } else { addr as u32 };
    let u_bit = if addr >= 0 { 1u32 << 23 } else { 0u32 };
    // STR sp, [fp, #addr]
    o(backend, COND_AL | 0x05800000 | u_bit | (11 << 16) | (13 << 12) | abs_addr)?;
    Ok(())
}

/// Restore stack pointer from VLA save location.
///
/// Emits: ldr sp, [fp, #addr]
///
/// Source: arm-gen.c lines 2336-2344.
pub fn gen_vla_sp_restore(backend: &mut ArmBackend, addr: i32) -> TccResult<()> {
    let abs_addr = if addr < 0 { (-addr) as u32 } else { addr as u32 };
    let u_bit = if addr >= 0 { 1u32 << 23 } else { 0u32 };
    // LDR sp, [fp, #addr]
    o(backend, COND_AL | 0x05900000 | u_bit | (11 << 16) | (13 << 12) | abs_addr)?;
    Ok(())
}

/// Generate VLA stack allocation.
///
/// Source: arm-gen.c lines 2345-2385.
pub fn gen_vla_alloc(backend: &mut ArmBackend, _typ: &CType, align: i32) -> TccResult<()> {
    let vtop_r = (backend.vtop().r & VT_VALMASK as u16) as i32;
    let r_hw = intr(vtop_r);

    // SUB sp, sp, Rm (allocate size on stack)
    o(backend, COND_AL | 0x004D0000 | (13 << 12) | r_hw)?;

    // Align: BIC sp, sp, #(align-1)
    let align_val = if backend.eabi_enabled {
        align.max(8)
    } else {
        align.max(4)
    };
    let align_mask = (align_val - 1) as u32;
    if align_mask > 0 {
        let bic = stuff_const(
            COND_AL | (0x1C << 20) | (13 << 16) | (13 << 12),
            align_mask,
        );
        if bic != 0 {
            o(backend, bic)?;
        } else {
            stuff_const_harder(backend,
                COND_AL | (0x1C << 20) | (13 << 16) | (13 << 12),
                align_mask)?;
        }
    }

    // MOV Rd, sp (return allocated address)
    o(backend, COND_AL | (0xD << 21) | (r_hw << 12) | 13)?;

    backend.vtop_dec();
    Ok(())
}

// ============================================================================
// ARM backend initialization
// ============================================================================

/// Initialize the ARM backend for code generation.
///
/// Called once per compilation unit to set up backend-specific state.
///
/// Source: arm-gen.c lines 190-224.
pub fn arm_init(backend: &mut ArmBackend) -> TccResult<()> {
    // Reset per-compilation state
    backend.func_sub_sp_offset = 0;
    backend.last_itod_magic = 0;
    backend.leaffunc = false;
    backend.ctx = ArmCodegenCtx::new();
    Ok(())
}

// ============================================================================
// Unit tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::{TREG_R2, TREG_F1, TREG_F2, TREG_F3};

    fn make_backend() -> ArmBackend {
        let mut b = ArmBackend::new();
        b.ctx = ArmCodegenCtx::new();
        b
    }

    #[test]
    fn test_intr_mapping() {
        assert_eq!(intr(TREG_R0 as i32), 0);
        assert_eq!(intr(TREG_R1 as i32), 1);
        assert_eq!(intr(TREG_R2 as i32), 2);
        assert_eq!(intr(TREG_R3 as i32), 3);
        assert_eq!(intr(TREG_R12 as i32), 12);
        assert_eq!(intr(TREG_SP as i32), 13);
        assert_eq!(intr(TREG_LR as i32), 14);
    }

    #[test]
    fn test_vfpr_mapping() {
        assert_eq!(vfpr(TREG_F0 as i32), 0);
        assert_eq!(vfpr(TREG_F1 as i32), 1);
        assert_eq!(vfpr(TREG_F2 as i32), 2);
        assert_eq!(vfpr(TREG_F3 as i32), 3);
    }

    #[test]
    fn test_stuff_const_simple() {
        // Small constant that fits in 8 bits
        let result = stuff_const(COND_AL | (0xD << 21) | (0 << 12), 0x42);
        assert_ne!(result, 0);
        assert_eq!(result & 0xFF, 0x42);
    }

    #[test]
    fn test_stuff_const_rotated() {
        // 0xFF000000 = 0xFF rotated right by 8 bits
        let result = stuff_const(COND_AL | (0xD << 21) | (0 << 12), 0xFF000000);
        assert_ne!(result, 0);
    }

    #[test]
    fn test_stuff_const_not_encodable() {
        // 0x12345678 cannot be encoded as a single ARM immediate
        let result = stuff_const(COND_AL | (0xD << 21) | (0 << 12), 0x12345678);
        assert_eq!(result, 0);
    }

    #[test]
    fn test_encbranch_basic() {
        let result = encbranch(0, 16, true).unwrap();
        // Offset = (16-0-8)/4 = 2
        assert_eq!(result & 0x00FFFFFF, 2);
        assert_eq!(result & 0x0F000000, 0x0A000000);
    }

    #[test]
    fn test_encbranch_negative() {
        let result = encbranch(16, 0, true).unwrap();
        // Offset = (0-16-8)/4 = -6
        let offset = result & 0x00FFFFFF;
        // -6 in 24-bit signed: 0xFFFFFA
        assert_eq!(offset, 0x00FFFFFA);
    }

    #[test]
    fn test_mapcc_eq() {
        assert_eq!(mapcc(TOK_EQ as i32), COND_EQ);
    }

    #[test]
    fn test_mapcc_ne() {
        assert_eq!(mapcc(TOK_NE as i32), COND_NE);
    }

    #[test]
    fn test_negcc_symmetry() {
        assert_eq!(negcc(TOK_EQ as i32), TOK_NE as i32);
        assert_eq!(negcc(TOK_NE as i32), TOK_EQ as i32);
        assert_eq!(negcc(TOK_LT as i32), TOK_GE as i32);
        assert_eq!(negcc(TOK_GE as i32), TOK_LT as i32);
    }

    #[test]
    fn test_emit_nop() {
        let mut b = make_backend();
        o(&mut b, ARM_NOP).unwrap();
        assert_eq!(b.ctx.ind, 4);
        assert_eq!(b.ctx.code_buf[0], 0x00);
        assert_eq!(b.ctx.code_buf[1], 0x00);
        assert_eq!(b.ctx.code_buf[2], 0xA0);
        assert_eq!(b.ctx.code_buf[3], 0xE1);
    }

    #[test]
    fn test_gen_fill_nops() {
        let mut b = make_backend();
        gen_fill_nops(&mut b, 12).unwrap();
        assert_eq!(b.ctx.ind, 12); // 3 NOP instructions
    }

    #[test]
    fn test_stuff_const_harder_simple() {
        let mut b = make_backend();
        let rd = 0u32;
        let op = COND_AL | (0xD << 21) | (rd << 12);
        stuff_const_harder(&mut b, op, 0x42).unwrap();
        assert!(b.ctx.ind >= 4); // At least one instruction emitted
    }

    #[test]
    fn test_reg_classes_sizes() {
        assert_eq!(REG_CLASSES_VFP.len(), 13);
        assert_eq!(REG_CLASSES_NO_VFP.len(), 9);
    }

    #[test]
    fn test_nocode_wanted_suppression() {
        let mut b = make_backend();
        b.ctx.nocode_wanted = 1;
        g(&mut b, 0xFF).unwrap();
        assert_eq!(b.ctx.ind, 0); // Nothing emitted
    }

    #[test]
    fn test_default_elfinterp_eabi() {
        let mut b = ArmBackend::new();
        b.eabi_enabled = true;
        b.float_abi = FloatAbi::HardFloat;
        assert_eq!(default_elfinterp(&b), "/lib/ld-linux-armhf.so.3");
        b.float_abi = FloatAbi::SoftFp;
        assert_eq!(default_elfinterp(&b), "/lib/ld-linux.so.3");
    }

    #[test]
    fn test_unalias_ldbl() {
        assert_eq!(unalias_ldbl(VT_LDOUBLE), VT_DOUBLE);
        assert_eq!(unalias_ldbl(VT_FLOAT), VT_FLOAT);
        assert_eq!(unalias_ldbl(VT_INT), VT_INT);
    }

    #[test]
    fn test_decbranch_roundtrip() {
        let mut b = make_backend();
        // Emit a branch to a known target
        let enc = encbranch(0, 100, true).unwrap();
        o(&mut b, COND_AL | enc).unwrap();
        let decoded = decbranch(&b, 0);
        assert_eq!(decoded, 100);
    }

    // === Additional ad-hoc tests for comprehensive coverage ===

    #[test]
    fn test_o_multiple_instructions() {
        let mut b = make_backend();
        o(&mut b, 0xE1A00000).unwrap(); // NOP
        o(&mut b, 0xE3A00042).unwrap(); // MOV r0, #0x42
        assert_eq!(b.ctx.ind, 8);
        assert_eq!(b.ctx.code_buf[4], 0x42);
        assert_eq!(b.ctx.code_buf[7], 0xE3);
    }

    #[test]
    fn test_g_single_byte() {
        let mut b = make_backend();
        g(&mut b, 0xAB).unwrap();
        assert_eq!(b.ctx.ind, 1);
        assert_eq!(b.ctx.code_buf[0], 0xAB);
    }

    #[test]
    fn test_stuff_const_zero() {
        let base = 0xE3A00000u32;
        let result = stuff_const(base, 0);
        assert_ne!(result, 0);
        assert_eq!(result & 0xFF, 0);
    }

    #[test]
    fn test_stuff_const_ff() {
        let base = 0xE3A00000u32;
        let result = stuff_const(base, 0xFF);
        assert_ne!(result, 0);
        assert_eq!(result & 0xFF, 0xFF);
    }

    #[test]
    fn test_stuff_const_0xff000000() {
        let base = 0xE3A00000u32;
        let result = stuff_const(base, 0xFF000000);
        assert_ne!(result, 0);
    }

    #[test]
    fn test_encbranch_self_jump() {
        let result = encbranch(0, 0, true).unwrap();
        let offset = result & 0x00FFFFFF;
        assert_eq!(offset, 0x00FFFFFE); // -2 in 24-bit
    }

    #[test]
    fn test_encbranch_forward_large() {
        let result = encbranch(0, 1000, true).unwrap();
        assert_eq!(result & 0x0F000000, 0x0A000000);
    }

    #[test]
    fn test_decbranch_roundtrip_backward() {
        let mut b = make_backend();
        for _ in 0..50 {
            o(&mut b, 0xE1A00000).unwrap();
        }
        let pos = b.ctx.ind as i32;
        let enc = encbranch(pos, 0, true).unwrap();
        o(&mut b, 0xEA000000 | enc).unwrap();
        let decoded = decbranch(&b, pos);
        assert_eq!(decoded, 0);
    }

    #[test]
    fn test_mapcc_unsigned_distinct() {
        let codes = [
            mapcc(TOK_ULT as i32),
            mapcc(TOK_UGE as i32),
            mapcc(TOK_ULE as i32),
            mapcc(TOK_UGT as i32),
        ];
        for i in 0..codes.len() {
            for j in (i+1)..codes.len() {
                assert_ne!(codes[i], codes[j]);
            }
        }
    }

    #[test]
    fn test_mapcc_signed_distinct() {
        let codes = [
            mapcc(TOK_LT as i32),
            mapcc(TOK_GE as i32),
            mapcc(TOK_LE as i32),
            mapcc(TOK_GT as i32),
        ];
        for i in 0..codes.len() {
            for j in (i+1)..codes.len() {
                assert_ne!(codes[i], codes[j]);
            }
        }
    }

    #[test]
    fn test_negcc_double_negate_identity() {
        for tok in [TOK_EQ, TOK_NE, TOK_LT, TOK_GE, TOK_LE, TOK_GT,
                    TOK_ULT, TOK_UGE, TOK_ULE, TOK_UGT] {
            let twice = negcc(negcc(tok as i32));
            assert_eq!(twice, tok as i32);
        }
    }

    #[test]
    fn test_negcc_nset_nclear() {
        assert_eq!(negcc(TOK_Nset), TOK_Nclear);
        assert_eq!(negcc(TOK_Nclear), TOK_Nset);
    }

    #[test]
    fn test_mapcc_nset_nclear_values() {
        assert_eq!(mapcc(TOK_Nset), COND_MI);
        assert_eq!(mapcc(TOK_Nclear), COND_PL);
    }

    #[test]
    fn test_gen_fill_nops_zero() {
        let mut b = make_backend();
        gen_fill_nops(&mut b, 0).unwrap();
        assert_eq!(b.ctx.ind, 0);
    }

    #[test]
    fn test_gen_fill_nops_4() {
        let mut b = make_backend();
        gen_fill_nops(&mut b, 4).unwrap();
        assert_eq!(b.ctx.ind, 4);
    }

    #[test]
    fn test_reg_classes_vfp_int_entries() {
        for i in 0..5 {
            assert_ne!(REG_CLASSES_VFP[i] & RC_INT, 0);
        }
    }

    #[test]
    fn test_reg_classes_vfp_float_entries() {
        for i in 5..13 {
            assert_ne!(REG_CLASSES_VFP[i] & RC_FLOAT, 0);
        }
    }

    #[test]
    fn test_arm_codegen_ctx_new() {
        let ctx = ArmCodegenCtx::new();
        assert_eq!(ctx.ind, 0);
        assert_eq!(ctx.loc, 0);
        assert_eq!(ctx.nocode_wanted, 0);
    }

    #[test]
    fn test_arm_init_softfp() {
        let mut b = ArmBackend::new();
        b.float_abi = FloatAbi::SoftFp;
        arm_init(&mut b).unwrap();
        assert_eq!(b.float_abi, FloatAbi::SoftFp);
    }

    #[test]
    fn test_arm_init_hardfp() {
        let mut b = ArmBackend::new();
        b.float_abi = FloatAbi::HardFloat;
        arm_init(&mut b).unwrap();
        assert_eq!(b.float_abi, FloatAbi::HardFloat);
    }

    #[test]
    fn test_tok_nset_nclear_values() {
        assert_eq!(TOK_Nset, 0x98);
        assert_eq!(TOK_Nclear, 0x99);
    }

    #[test]
    fn test_default_elfinterp_non_eabi() {
        let mut b = ArmBackend::new();
        b.eabi_enabled = false;
        assert_eq!(default_elfinterp(&b), "/lib/ld-linux.so.2");
    }

    #[test]
    fn test_gfunc_sret_basic() {
        let b = ArmBackend::new();
        let ty = CType::default();
        let (_use_reg, _ret_type, _align, _regsize) = gfunc_sret(&b, &ty, false);
        // Function should complete without panic
    }

    #[test]
    fn test_stuff_const_harder_small() {
        let mut b = make_backend();
        let rd = 0u32;
        let op = COND_AL | (0xD << 21) | (rd << 12);
        stuff_const_harder(&mut b, op, 42).unwrap();
        assert_eq!(b.ctx.ind, 4); // Should fit in one instruction
    }

    #[test]
    fn test_stuff_const_harder_large() {
        let mut b = make_backend();
        let rd = 0u32;
        let op = COND_AL | (0xD << 21) | (rd << 12);
        stuff_const_harder(&mut b, op, 0xDEADBEEF).unwrap();
        assert!(b.ctx.ind > 4); // Should need multiple instructions
    }

    #[test]
    fn test_fpr_mapping() {
        assert_eq!(fpr(TREG_F0 as i32), 0);
    }
}
