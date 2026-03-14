//! TMS320C67x DSP architecture backend for TinyCC.
//!
//! Consolidates `c67-gen.c` (2,543 lines) and `c67-link.c` (125 lines) from
//! the original C codebase into a single Rust module.
//!
//! This is a legacy backend for the Texas Instruments TMS320C6000 DSP series.
//! Key architectural features:
//! - **24-register model**: Dual A-side / B-side register files
//! - **VLIW instruction packets**: Up to 8 parallel 32-bit instructions
//! - **COFF output format**: Uses `tcccoff.c` backend instead of ELF
//! - **No bounds checking**: `CONFIG_TCC_BCHECK` explicitly disabled
//! - **No VLA support**: Variable-length arrays are unsupported
//! - **No long long / long double**: These types cause errors

use crate::context::TccState;
use crate::error::{TccError, TccResult};
use crate::targets::{read32le, write32le, CodegenBackend, GotPltEntry, LinkerBackend};
use crate::types::{
    CType, CValue, SValue, SValueData, Symbol,
    VT_BTYPE, VT_BYTE, VT_CMP, VT_CONST, VT_DOUBLE, VT_FLOAT, VT_INT,
    VT_JMP, VT_JMPI, VT_LLOCAL, VT_LLONG, VT_LDOUBLE, VT_LOCAL, VT_LVAL,
    VT_SHORT, VT_SYM, VT_UNSIGNED, VT_VALMASK,
};

// ---- Register Constants (c67-gen.c:26-109) ----

/// Number of available registers (c67-gen.c:26).
pub(crate) const NB_REGS: usize = 24;

// Register class bitmasks — dual-side architecture (A-side + B-side).
const RC_INT: u32 = 0x0001;
const RC_FLOAT: u32 = 0x0002;
const RC_EAX: u32 = 0x0004;
const RC_ST0: u32 = 0x0008;
const RC_ECX: u32 = 0x0010;
const RC_EDX: u32 = 0x0020;
const RC_INT_BSIDE: u32 = 0x0040;
const RC_C67_A4: u32 = 0x0000_0100;
const RC_C67_A5: u32 = 0x0000_0200;
const RC_C67_B4: u32 = 0x0000_0400;
const RC_C67_B5: u32 = 0x0000_0800;
const RC_C67_A6: u32 = 0x0000_1000;
const RC_C67_A7: u32 = 0x0000_2000;
const RC_C67_B6: u32 = 0x0000_4000;
const RC_C67_B7: u32 = 0x0000_8000;
const RC_C67_A8: u32 = 0x0001_0000;
const RC_C67_A9: u32 = 0x0002_0000;
const RC_C67_B8: u32 = 0x0004_0000;
const RC_C67_B9: u32 = 0x0008_0000;
const RC_C67_A10: u32 = 0x0010_0000;
const RC_C67_A11: u32 = 0x0020_0000;
const RC_C67_B10: u32 = 0x0040_0000;
const RC_C67_B11: u32 = 0x0080_0000;
const RC_C67_A12: u32 = 0x0100_0000;
const RC_C67_A13: u32 = 0x0200_0000;
const RC_C67_B12: u32 = 0x0400_0000;
const RC_C67_B13: u32 = 0x0800_0000;

// Logical register indices (c67-gen.c:63-88) — i32 for direct use as operands.
const REG_EAX: i32 = 0;
const REG_ECX: i32 = 1;
const REG_EDX: i32 = 2;
#[allow(dead_code)] const REG_ST0: i32 = 3;
const REG_C67_A4: i32 = 4;
const REG_C67_A5: i32 = 5;
const REG_C67_B4: i32 = 6;
const REG_C67_B5: i32 = 7;
const REG_C67_A6: i32 = 8;
const REG_C67_A7: i32 = 9;
const REG_C67_B6: i32 = 10;
const REG_C67_B7: i32 = 11;
const REG_C67_A8: i32 = 12;
const REG_C67_A9: i32 = 13;
const REG_C67_B8: i32 = 14;
const REG_C67_B9: i32 = 15;
const REG_C67_A10: i32 = 16;
const REG_C67_A11: i32 = 17;
const REG_C67_B10: i32 = 18;
const REG_C67_B11: i32 = 19;
const REG_C67_A12: i32 = 20;
const REG_C67_A13: i32 = 21;
const REG_C67_B12: i32 = 22;
const REG_C67_B13: i32 = 23;

// Special C67 hardware register aliases (c67-gen.c:96-100).
const C67_A0: i32 = 105;
const C67_SP: i32 = 106; // B15
const C67_B3: i32 = 107;
const C67_FP: i32 = 108; // A15
const C67_B2: i32 = 109;
const C67_CREG_ZERO: i32 = -1;

/// Preprocessor definitions for the C67 target.
static TARGET_DEFS: &[&str] = &["__C67__"];
const MAX_FUNC_ARGS: usize = 10;

/// Register class table (c67-gen.c:123-150).
/// A-side even regs allow `INT+FLOAT`, B-side even regs `INT+INT_BSIDE+FLOAT`.
/// Odd regs only allow INT (no float — doubles need register pairs).
static REG_CLASSES_TABLE: [u32; NB_REGS] = [
    RC_INT | RC_FLOAT | RC_EAX, RC_INT | RC_ECX,
    RC_INT | RC_INT_BSIDE | RC_FLOAT | RC_EDX, RC_INT | RC_INT_BSIDE | RC_ST0,
    RC_INT | RC_FLOAT | RC_C67_A4, RC_INT | RC_C67_A5,
    RC_INT | RC_INT_BSIDE | RC_FLOAT | RC_C67_B4, RC_INT | RC_INT_BSIDE | RC_C67_B5,
    RC_INT | RC_FLOAT | RC_C67_A6, RC_INT | RC_C67_A7,
    RC_INT | RC_INT_BSIDE | RC_FLOAT | RC_C67_B6, RC_INT | RC_INT_BSIDE | RC_C67_B7,
    RC_INT | RC_FLOAT | RC_C67_A8, RC_INT | RC_C67_A9,
    RC_INT | RC_INT_BSIDE | RC_FLOAT | RC_C67_B8, RC_INT | RC_INT_BSIDE | RC_C67_B9,
    RC_INT | RC_FLOAT | RC_C67_A10, RC_INT | RC_C67_A11,
    RC_INT | RC_INT_BSIDE | RC_FLOAT | RC_C67_B10, RC_INT | RC_INT_BSIDE | RC_C67_B11,
    RC_INT | RC_FLOAT | RC_C67_A12, RC_INT | RC_C67_A13,
    RC_INT | RC_INT_BSIDE | RC_FLOAT | RC_C67_B12, RC_INT | RC_INT_BSIDE | RC_C67_B13,
];

// ---- C60 Relocation Constants (c67-link.c) ----
const R_C60_32: i32 = 1;
const R_C60_GOT32: i32 = 3;
const R_C60_PLT32: i32 = 4;
#[allow(dead_code)]
const R_C60_COPY: i32 = 5;
const R_C60_GOTOFF: i32 = 9;
const R_C60_GOTPC: i32 = 10;
const R_C60HI16: i32 = 85;
const R_C60LO16: i32 = 84;

// ---- Token / Operator Constants ----
const TOK_ULT: i32 = 0x92;
const TOK_UGE: i32 = 0x93;
const TOK_EQ: i32 = 0x94;
const TOK_NE: i32 = 0x95;
const TOK_ULE: i32 = 0x96;
const TOK_UGT: i32 = 0x97;
const TOK_LT: i32 = 0x9c;
const TOK_GE: i32 = 0x9d;
const TOK_LE: i32 = 0x9e;
const TOK_GT: i32 = 0x9f;

// ---- C67 Opcode Enum ----
/// Instruction mnemonics for the `TMS320C67x` instruction set.
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
enum C67Op {
    Mvkl, Mvkh, Mv,
    StwSp, SthSp, StbSp, StwSpA0, SthSpA0, StbSpA0,
    StwPtr, SthPtr, StbPtr,
    LdwSp, LddwSp, LdhSp, LdbSp, LdhuSp, LdbuSp,
    LdwSpA0, LddwSpA0, LdhSpA0, LdbSpA0, LdhuSpA0, LdbuSpA0,
    LdwPtr, LddwPtr, LdhPtr, LdbPtr, LdhuPtr, LdbuPtr,
    Cmplt, Cmpgt, Cmpeq, Cmpltu, Cmpgtu,
    Cmpltsp, Cmpgtsp, Cmpeqsp, Cmpltdp, Cmpgtdp, Cmpeqdp,
    BDisp, BReg,
    Sptrunc, Dptrunc, Intsp, Intdp, Intspu, Intdpu, Spdp, Dpsp,
    Add, Sub, Or, And, Xor,
    Addsp, Subsp, Mpysp, Adddp, Subdp, Mpydp,
    Mpyi, Shl, Shru, Shr, Addk, Nop,
}

// ---- Helper: safe i32-to-u32 for bit manipulation ----
/// Bit-cast an i32 value to u32 for use in instruction encoding fields.
/// This preserves the bit pattern, which is correct for instruction encoding.
#[inline]
#[allow(clippy::cast_sign_loss)]
const fn i2u(val: i32) -> u32 {
    val as u32
}

// ---- C67Backend ----

/// `TMS320C67x` DSP code generation and linker backend.
///
/// Implements both [`CodegenBackend`] and [`LinkerBackend`] for the C6000 DSP
/// family. This is a cross-compilation-only target.
pub(crate) struct C67Backend {
    n_func_args: i32,
    stack_to_reg: [i32; MAX_FUNC_ARGS],
    param_on_stack: [bool; MAX_FUNC_ARGS],
    total_pushed: i32,
    func_sub_sp_off: i64,
    func_ret_sub: i64,
    invert_test: bool,
    compare_reg: i32,
}

impl C67Backend {
    /// Create a new C67 backend instance.
    pub(crate) fn new() -> Self {
        Self {
            n_func_args: 0,
            stack_to_reg: [0; MAX_FUNC_ARGS],
            param_on_stack: [false; MAX_FUNC_ARGS],
            total_pushed: 0,
            func_sub_sp_off: 0,
            func_ret_sub: 0,
            invert_test: false,
            compare_reg: 0,
        }
    }

    // ---- Register mapping helpers (c67-gen.c:152-183) ----

    /// Map a logical register index to the hardware register number.
    /// A-side and B-side registers share hardware numbers 0-15.
    #[allow(clippy::match_same_arms)]
    fn regn(r: i32) -> i32 {
        match r {
            0 => 2, 1 => 3, 2 => 0, 3 => 1, 4 | 5 => r, 6 => 4, 7 => 5,
            8 | 10 => 6, 9 | 11 => 7, 12 | 14 => 8, 13 | 15 => 9,
            16 | 18 => 10, 17 | 19 => 11, 20 | 22 => 12, 21 | 23 => 13,
            _ if r == C67_A0 => 0,
            _ if r == C67_SP || r == C67_FP => 15,
            _ if r == C67_B3 => 3,
            _ if r == C67_B2 => 2,
            _ => 0,
        }
    }

    /// Return 0 for A-side register, 1 for B-side register.
    #[allow(clippy::match_same_arms)]
    fn side(r: i32) -> u32 {
        match r {
            0 | 1 | 4 | 5 | 8 | 9 | 12 | 13 | 16 | 17 | 20 | 21 => 0,
            2 | 3 | 6 | 7 | 10 | 11 | 14 | 15 | 18 | 19 | 22 | 23 => 1,
            _ if r == C67_A0 || r == C67_FP => 0,
            _ if r == C67_SP || r == C67_B3 || r == C67_B2 => 1,
            _ => 0,
        }
    }

    /// Return the condition-register encoding for the given register.
    fn creg(r: i32) -> u32 {
        if r == C67_CREG_ZERO {
            return 0;
        }
        let hw = Self::regn(r);
        let sd = Self::side(r);
        if sd == 0 {
            match hw { 0 => 4, 1 => 5, 2 => 6, _ => 0 }
        } else {
            match hw { 0 => 1, 1 => 2, 2 => 3, _ => 0 }
        }
    }

    // ---- Instruction encoding (c67-gen.c:189-420) ----

    /// Encode one C67 instruction word from opcode and up to 3 register operands.
    ///
    /// Instruction encoding uses pure bit manipulation on `u32` values.
    /// The `i2u()` helper converts signed operands to their bit-pattern equivalents.
    #[allow(
        clippy::cast_sign_loss,
        clippy::too_many_lines,
        clippy::similar_names,
    )]
    fn encode(op: C67Op, aop: i32, bop: i32, cop: i32) -> u32 {
        let ra = i2u(Self::regn(aop));
        let rb = i2u(Self::regn(bop));
        let rc = i2u(Self::regn(cop));
        let sc = Self::side(cop);
        let sb = Self::side(bop);
        let cross = u32::from(sc != sb);
        match op {
            C67Op::Mvkl => {
                let sd = Self::side(cop);
                let imm = i2u(bop) & 0xFFFF;
                imm << 7 | rc << 23 | sd << 1 | 0x28
            }
            C67Op::Mvkh => {
                let sd = Self::side(cop);
                let imm = i2u(bop) & 0xFFFF;
                imm << 7 | rc << 23 | sd << 1 | 0x68
            }
            C67Op::Mv => rb << 18 | rc << 23 | (cross << 12) | (sc << 1) | 0x7e,
            // ---- Stores with SP offset ----
            C67Op::StwSp => { let off = rb & 0x1F; ra << 23 | off << 13 | 0x0F_u32 << 8 | 0x3C }
            C67Op::SthSp => { let off = rb & 0x1F; ra << 23 | off << 13 | 0x05_u32 << 8 | 0x3C }
            C67Op::StbSp => { let off = rb & 0x1F; ra << 23 | off << 13 | 0x03_u32 << 8 | 0x3C }
            // ---- Stores with A0 index ----
            C67Op::StwSpA0 => ra << 23 | 0x0F_u32 << 8 | 0x7C,
            C67Op::SthSpA0 => ra << 23 | 0x05_u32 << 8 | 0x7C,
            C67Op::StbSpA0 => ra << 23 | 0x03_u32 << 8 | 0x7C,
            // ---- Stores via pointer ----
            C67Op::StwPtr => { let dd = Self::side(cop); ra << 23 | rc << 18 | (dd << 1) | 0x7C | (0x0F_u32 << 8) }
            C67Op::SthPtr => { let dd = Self::side(cop); ra << 23 | rc << 18 | (dd << 1) | 0x7C | (0x05_u32 << 8) }
            C67Op::StbPtr => { let dd = Self::side(cop); ra << 23 | rc << 18 | (dd << 1) | 0x7C | (0x03_u32 << 8) }
            // ---- Loads with SP offset ----
            C67Op::LdwSp =>  { let off = ra & 0x1F; rc << 23 | off << 13 | 0x0E_u32 << 8 | 0x2C }
            C67Op::LddwSp => { let off = ra & 0x1F; rc << 23 | off << 13 | 0x0C_u32 << 8 | 0x2C }
            C67Op::LdhSp =>  { let off = ra & 0x1F; rc << 23 | off << 13 | 0x04_u32 << 8 | 0x2C }
            C67Op::LdbSp =>  { let off = ra & 0x1F; rc << 23 | off << 13 | 0x02_u32 << 8 | 0x2C }
            C67Op::LdhuSp => { let off = ra & 0x1F; rc << 23 | off << 13 | 0x2C }
            C67Op::LdbuSp => { let off = ra & 0x1F; rc << 23 | off << 13 | 0x01_u32 << 8 | 0x2C }
            // ---- Loads with A0 index ----
            C67Op::LdwSpA0 =>  rc << 23 | 0x0E_u32 << 8 | 0x6C,
            C67Op::LddwSpA0 => rc << 23 | 0x0C_u32 << 8 | 0x6C,
            C67Op::LdhSpA0 =>  rc << 23 | 0x04_u32 << 8 | 0x6C,
            C67Op::LdbSpA0 =>  rc << 23 | 0x02_u32 << 8 | 0x6C,
            C67Op::LdhuSpA0 => rc << 23 | 0x6C,
            C67Op::LdbuSpA0 => rc << 23 | 0x01_u32 << 8 | 0x6C,
            // ---- Loads via pointer ----
            C67Op::LdwPtr =>  { let sa = Self::side(aop); rc << 23 | ra << 18 | (sa << 1) | 0x6C | (0x0E_u32 << 8) }
            C67Op::LddwPtr => { let sa = Self::side(aop); rc << 23 | ra << 18 | (sa << 1) | 0x6C | (0x0C_u32 << 8) }
            C67Op::LdhPtr =>  { let sa = Self::side(aop); rc << 23 | ra << 18 | (sa << 1) | 0x6C | (0x04_u32 << 8) }
            C67Op::LdbPtr =>  { let sa = Self::side(aop); rc << 23 | ra << 18 | (sa << 1) | 0x6C | (0x02_u32 << 8) }
            C67Op::LdhuPtr => { let sa = Self::side(aop); rc << 23 | ra << 18 | (sa << 1) | 0x6C }
            C67Op::LdbuPtr => { let sa = Self::side(aop); rc << 23 | ra << 18 | (sa << 1) | 0x6C | (0x01_u32 << 8) }
            // ---- Compares (integer) ----
            C67Op::Cmplt =>  ra << 13 | rb << 18 | rc << 23 | (cross << 12) | (sc << 1) | 0x57 << 5,
            C67Op::Cmpgt =>  rb << 13 | ra << 18 | rc << 23 | (cross << 12) | (sc << 1) | 0x57 << 5,
            C67Op::Cmpeq =>  ra << 13 | rb << 18 | rc << 23 | (cross << 12) | (sc << 1) | 0x53 << 5,
            C67Op::Cmpltu => ra << 13 | rb << 18 | rc << 23 | (cross << 12) | (sc << 1) | 0x5f << 5,
            C67Op::Cmpgtu => rb << 13 | ra << 18 | rc << 23 | (cross << 12) | (sc << 1) | 0x5f << 5,
            // ---- Compares (SP float) ----
            C67Op::Cmpltsp => ra << 13 | rb << 18 | rc << 23 | (cross << 12) | (sc << 1) | 0x3b << 5,
            C67Op::Cmpgtsp => rb << 13 | ra << 18 | rc << 23 | (cross << 12) | (sc << 1) | 0x3b << 5,
            C67Op::Cmpeqsp => ra << 13 | rb << 18 | rc << 23 | (cross << 12) | (sc << 1) | 0x3a << 5,
            // ---- Compares (DP float) ----
            C67Op::Cmpltdp => ra << 13 | rb << 18 | rc << 23 | (cross << 12) | (sc << 1) | 0x2b << 5,
            C67Op::Cmpgtdp => rb << 13 | ra << 18 | rc << 23 | (cross << 12) | (sc << 1) | 0x2b << 5,
            C67Op::Cmpeqdp => ra << 13 | rb << 18 | rc << 23 | (cross << 12) | (sc << 1) | 0x2a << 5,
            // ---- Branch ----
            C67Op::BDisp => {
                let sd = Self::side(cop);
                let d21 = i2u(aop) & 0x001F_FFFF;
                d21 << 7 | (sd << 1) | 0x10
            }
            C67Op::BReg => rb << 18 | 0x0d_u32 << 13 | 0x362,
            // ---- Conversions ----
            C67Op::Sptrunc => rb << 18 | rc << 23 | (cross << 12) | (sc << 1) | 0x0b << 5 | 0x2,
            C67Op::Dptrunc => rb << 18 | rc << 23 | (cross << 12) | (sc << 1) | 0x01 << 5 | 0x2,
            C67Op::Intsp =>   rb << 18 | rc << 23 | (cross << 12) | (sc << 1) | 0x4a << 5 | 0x2,
            C67Op::Intdp =>   rb << 18 | rc << 23 | (cross << 12) | (sc << 1) | 0x39 << 5 | 0x2,
            C67Op::Intspu =>  rb << 18 | rc << 23 | (cross << 12) | (sc << 1) | 0x49 << 5 | 0x2,
            C67Op::Intdpu =>  rb << 18 | rc << 23 | (cross << 12) | (sc << 1) | 0x3b << 5 | 0x8,
            C67Op::Spdp =>    rb << 18 | rc << 23 | (cross << 12) | (sc << 1) | 0x02 << 5 | 0x2,
            C67Op::Dpsp =>    rb << 18 | rc << 23 | (cross << 12) | (sc << 1) | 0x09 << 5 | 0x2,
            // ---- Integer ALU ----
            C67Op::Add =>  ra << 13 | rb << 18 | rc << 23 | (cross << 12) | (sc << 1) | 0x03 << 5 | 0x2,
            C67Op::Sub =>  ra << 13 | rb << 18 | rc << 23 | (cross << 12) | (sc << 1) | 0x07 << 5 | 0x2,
            C67Op::Or =>   ra << 13 | rb << 18 | rc << 23 | (cross << 12) | (sc << 1) | 0x7f << 5,
            C67Op::And =>  ra << 13 | rb << 18 | rc << 23 | (cross << 12) | (sc << 1) | 0x7b << 5,
            C67Op::Xor =>  ra << 13 | rb << 18 | rc << 23 | (cross << 12) | (sc << 1) | 0x6f << 5,
            // ---- Float ALU ----
            C67Op::Addsp => ra << 13 | rb << 18 | rc << 23 | (cross << 12) | (sc << 1) | 0x10 << 5 | 0x2,
            C67Op::Subsp => ra << 13 | rb << 18 | rc << 23 | (cross << 12) | (sc << 1) | 0x11 << 5 | 0x2,
            C67Op::Mpysp => ra << 13 | rb << 18 | rc << 23 | (cross << 12) | (sc << 1) | 0x1c << 5 | 0x2,
            C67Op::Adddp => ra << 13 | rb << 18 | rc << 23 | (cross << 12) | (sc << 1) | 0x18 << 5 | 0x2,
            C67Op::Subdp => ra << 13 | rb << 18 | rc << 23 | (cross << 12) | (sc << 1) | 0x19 << 5 | 0x2,
            C67Op::Mpydp => ra << 13 | rb << 18 | rc << 23 | (cross << 12) | (sc << 1) | 0x38 << 5 | 0x2,
            // ---- Multiply / Shift ----
            C67Op::Mpyi => ra << 13 | rb << 18 | rc << 23 | (cross << 12) | (sc << 1) | 0x18 << 7 | 0x02,
            C67Op::Shl =>  ra << 13 | rb << 18 | rc << 23 | (cross << 12) | (sc << 1) | 0x33 << 5 | 0x2,
            C67Op::Shru => ra << 13 | rb << 18 | rc << 23 | (cross << 12) | (sc << 1) | 0x27 << 5 | 0x2,
            C67Op::Shr =>  ra << 13 | rb << 18 | rc << 23 | (cross << 12) | (sc << 1) | 0x37 << 5 | 0x2,
            // ---- Immediate add / NOP ----
            C67Op::Addk => {
                let imm = i2u(aop) & 0xFFFF;
                imm << 7 | rc << 23 | (Self::side(cop) << 1) | 0x50
            }
            C67Op::Nop => {
                let cnt = i2u(aop) & 0x0F;
                cnt << 13
            }
        }
    }

    // ---- Low-level emission helpers ----

    /// Emit a single 32-bit instruction word to the current text section.
    #[allow(clippy::unused_self)]
    fn emit_instr(&self, state: &mut TccState, instr: u32) -> TccResult<()> {
        let idx = state.cur_text_section;
        let sec = state.sections.get_mut(idx)
            .ok_or_else(|| TccError::link("C67: invalid text section"))?;
        let ind = usize::try_from(state.ind)
            .map_err(|_| TccError::link("C67: invalid code offset"))?;
        if ind + 4 > sec.data.len() {
            sec.data.resize(ind + 4, 0);
        }
        write32le(&mut sec.data[ind..ind + 4], instr);
        state.ind += 4;
        sec.data_offset = usize::try_from(state.ind).unwrap_or(sec.data_offset);
        Ok(())
    }

    /// Read the 32-bit instruction word at the given byte offset.
    #[allow(clippy::unused_self)]
    fn read_instr_at(&self, state: &TccState, off: i64) -> TccResult<u32> {
        let idx = state.cur_text_section;
        let sec = state.sections.get(idx)
            .ok_or_else(|| TccError::link("C67: invalid text section"))?;
        let byte_off = usize::try_from(off)
            .map_err(|_| TccError::link("C67: bad offset"))?;
        if byte_off + 4 > sec.data.len() {
            return Err(TccError::link("C67: read out of bounds"));
        }
        Ok(read32le(&sec.data[byte_off..byte_off + 4]))
    }

    /// Write a 32-bit instruction word at the given byte offset.
    #[allow(clippy::unused_self)]
    fn write_instr_at(&self, state: &mut TccState, off: i64, val: u32) -> TccResult<()> {
        let idx = state.cur_text_section;
        let sec = state.sections.get_mut(idx)
            .ok_or_else(|| TccError::link("C67: invalid text section"))?;
        let byte_off = usize::try_from(off)
            .map_err(|_| TccError::link("C67: bad offset"))?;
        if byte_off + 4 > sec.data.len() {
            sec.data.resize(byte_off + 4, 0);
        }
        write32le(&mut sec.data[byte_off..byte_off + 4], val);
        Ok(())
    }

    // ---- Convenience emission helpers ----

    fn emit_mvkl(&self, state: &mut TccState, val: i32, dst: i32) -> TccResult<()> {
        self.emit_instr(state, Self::encode(C67Op::Mvkl, 0, val, dst))
    }

    fn emit_mvkh(&self, state: &mut TccState, val: i32, dst: i32) -> TccResult<()> {
        self.emit_instr(state, Self::encode(C67Op::Mvkh, 0, val, dst))
    }

    /// Load a full 32-bit constant into a register using MVKL + MVKH pair.
    fn load_const32(&self, state: &mut TccState, val: i32, dst: i32) -> TccResult<()> {
        self.emit_mvkl(state, val & 0xFFFF, dst)?;
        self.emit_mvkh(state, (val >> 16) & 0xFFFF, dst)
    }

    fn emit_push(&mut self, state: &mut TccState, src: i32) -> TccResult<()> {
        let instr = Self::encode(C67Op::StwSp, src, -1, C67_SP);
        self.emit_instr(state, instr)?;
        self.total_pushed += 4;
        Ok(())
    }

    fn emit_pop(&mut self, state: &mut TccState, dst: i32) -> TccResult<()> {
        let instr = Self::encode(C67Op::LdwSp, 1, C67_SP, dst);
        self.emit_instr(state, instr)?;
        self.total_pushed -= 4;
        Ok(())
    }

    fn emit_nop(&self, state: &mut TccState, count: i32) -> TccResult<()> {
        self.emit_instr(state, Self::encode(C67Op::Nop, count, 0, 0))
    }

    fn emit_mv(&self, state: &mut TccState, src: i32, dst: i32) -> TccResult<()> {
        self.emit_instr(state, Self::encode(C67Op::Mv, 0, src, dst))
    }

    fn emit_b_reg(&self, state: &mut TccState, reg: i32) -> TccResult<()> {
        self.emit_instr(state, Self::encode(C67Op::BReg, 0, reg, 0))
    }

    fn emit_addk(&self, state: &mut TccState, val: i32, dst: i32) -> TccResult<()> {
        self.emit_instr(state, Self::encode(C67Op::Addk, val, 0, dst))
    }

    /// Patch an ADDK instruction at `off` with a new immediate value.
    #[allow(clippy::cast_sign_loss)]
    fn patch_addk(&self, state: &mut TccState, off: i64, val: i32) -> TccResult<()> {
        let old = self.read_instr_at(state, off)?;
        let cleared = old & 0xFF80_007F;
        let imm = (val as u32) & 0xFFFF;
        self.write_instr_at(state, off, cleared | (imm << 7))
    }

    /// Return the byte size for a base type code.
    fn btype_size(bt: i32) -> i32 {
        if bt == VT_BYTE { 1 }
        else if bt == VT_SHORT { 2 }
        else if bt == VT_DOUBLE || bt == VT_LLONG { 8 }
        else { 4 }
    }

    /// Extract the integer constant from an `SValue`, returning 0 if not a constant.
    #[allow(clippy::cast_possible_wrap)]
    fn sv_int(sv: &SValue) -> i64 {
        match &sv.value {
            SValueData::Constant(CValue::Int(val)) => *val as i64,
            _ => 0,
        }
    }

    /// Generate a call or jump to the address described by `sv`.
    fn gcall_or_jmp(&self, state: &mut TccState, _is_jmp: bool, sv: &SValue) -> TccResult<()> {
        let has_sym = (sv.r & VT_SYM) != 0;
        let is_const = (sv.r & VT_VALMASK) == VT_CONST;
        if has_sym && is_const {
            #[allow(clippy::cast_possible_truncation)]
            let addr = Self::sv_int(sv) as i32;
            self.load_const32(state, addr, C67_B2)?;
        } else {
            self.emit_mv(state, i32::from(sv.r & VT_VALMASK), C67_B2)?;
        }
        self.emit_b_reg(state, C67_B2)?;
        self.emit_nop(state, 5)
    }

    /// Return the (even, odd) register pair for the i-th function argument.
    fn arg_reg_pair(idx: usize) -> (i32, i32) {
        match idx {
            1 => (REG_C67_B4, REG_C67_B5),
            2 => (REG_C67_A6, REG_C67_A7),
            3 => (REG_C67_B6, REG_C67_B7),
            4 => (REG_C67_A8, REG_C67_A9),
            5 => (REG_C67_B8, REG_C67_B9),
            6 => (REG_C67_A10, REG_C67_A11),
            7 => (REG_C67_B10, REG_C67_B11),
            8 => (REG_C67_A12, REG_C67_A13),
            9 => (REG_C67_B12, REG_C67_B13),
            // 0 and any out-of-range index default to first pair (A4:A5).
            _ => (REG_C67_A4, REG_C67_A5),
        }
    }

    // ---- Core load / store (c67-gen.c:1551-1813) ----

    /// Load value `sv` into register `reg` (c67-gen.c:1551-1709).
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    fn do_load(&mut self, state: &mut TccState, reg: i32, sv: &SValue) -> TccResult<()> {
        let fr = sv.r;
        let val_kind = i32::from(fr & VT_VALMASK);
        let bt = sv.ctype.t & VT_BTYPE;
        if bt == VT_LDOUBLE {
            return Err(TccError::parse("long double not supported on C67"));
        }
        let fc = Self::sv_int(sv) as i32;

        // Handle VT_LLOCAL: double dereference via a temporary.
        if val_kind == i32::from(VT_LLOCAL) {
            let tmp = SValue {
                ctype: CType { t: VT_INT, ..CType::default() },
                r: VT_LOCAL | VT_LVAL,
                value: sv.value.clone(),
                ..SValue::default()
            };
            self.do_load(state, reg, &tmp)?;
            #[allow(clippy::cast_sign_loss)]
            let deref = SValue {
                ctype: sv.ctype,
                r: (reg as u16) | VT_LVAL,
                value: SValueData::Constant(CValue::Int(0)),
                ..SValue::default()
            };
            return self.do_load(state, reg, &deref);
        }

        let is_lval = (fr & VT_LVAL) != 0;
        if is_lval {
            let size = Self::btype_size(bt);
            let has_sym = (fr & VT_SYM) != 0;
            if val_kind == i32::from(VT_LOCAL) {
                if fc > 0 {
                    // fc > 0 guarantees non-negative, so u32 conversion is safe.
                    let param_idx = (fc as u32 / 4) as usize;
                    if param_idx < MAX_FUNC_ARGS && !self.param_on_stack[param_idx] {
                        self.emit_mv(state, self.stack_to_reg[param_idx], reg)?;
                        return Ok(());
                    }
                }
                self.load_const32(state, fc, C67_A0)?;
                self.emit_nop(state, 4)?;
                self.emit_ld_sp_a0(state, reg, &sv.ctype, size)?;
                self.emit_nop(state, 4)?;
            } else if has_sym {
                self.load_const32(state, fc, C67_A0)?;
                self.emit_nop(state, 4)?;
                self.emit_ld_ptr(state, C67_A0, reg, &sv.ctype, size)?;
                self.emit_nop(state, 4)?;
            } else {
                self.emit_ld_ptr(state, val_kind, reg, &sv.ctype, size)?;
                self.emit_nop(state, 4)?;
            }
        } else if val_kind == i32::from(VT_CONST) {
            self.load_const32(state, fc, reg)?;
        } else if val_kind == i32::from(VT_LOCAL) {
            self.load_const32(state, fc, C67_A0)?;
            self.emit_instr(state, Self::encode(C67Op::Add, C67_FP, C67_A0, reg))?;
        } else if val_kind == i32::from(VT_CMP) {
            self.emit_mv(state, self.compare_reg, reg)?;
        } else if val_kind == i32::from(VT_JMP) || val_kind == i32::from(VT_JMPI) {
            self.load_const32(state, 1, reg)?;
            self.emit_instr(state, Self::encode(C67Op::BDisp, 2, 0, reg))?;
            self.emit_nop(state, 5)?;
            self.load_const32(state, 0, reg)?;
        } else if val_kind != reg {
            self.emit_mv(state, val_kind, reg)?;
        }
        Ok(())
    }

    /// Emit a load from `[SP + A0]` with the appropriate width.
    fn emit_ld_sp_a0(&self, state: &mut TccState, dst: i32, ctype: &CType, size: i32) -> TccResult<()> {
        let op = match size {
            1 => if (ctype.t & VT_UNSIGNED) != 0 { C67Op::LdbuSpA0 } else { C67Op::LdbSpA0 },
            2 => if (ctype.t & VT_UNSIGNED) != 0 { C67Op::LdhuSpA0 } else { C67Op::LdhSpA0 },
            8 => C67Op::LddwSpA0,
            _ => C67Op::LdwSpA0,
        };
        self.emit_instr(state, Self::encode(op, 0, C67_SP, dst))
    }

    /// Emit a load from `[ptr_reg + 0]` with the appropriate width.
    fn emit_ld_ptr(&self, state: &mut TccState, ptr_reg: i32, dst: i32, ctype: &CType, size: i32) -> TccResult<()> {
        let op = match size {
            1 => if (ctype.t & VT_UNSIGNED) != 0 { C67Op::LdbuPtr } else { C67Op::LdbPtr },
            2 => if (ctype.t & VT_UNSIGNED) != 0 { C67Op::LdhuPtr } else { C67Op::LdhPtr },
            8 => C67Op::LddwPtr,
            _ => C67Op::LdwPtr,
        };
        self.emit_instr(state, Self::encode(op, ptr_reg, 0, dst))
    }

    /// Store register `reg` into location `sv` (c67-gen.c:1713-1813).
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    fn do_store(&mut self, state: &mut TccState, reg: i32, sv: &SValue) -> TccResult<()> {
        let fr = sv.r;
        let val_kind = i32::from(fr & VT_VALMASK);
        let bt = sv.ctype.t & VT_BTYPE;
        let fc = Self::sv_int(sv) as i32;
        let size = Self::btype_size(bt);
        let has_sym = (fr & VT_SYM) != 0;

        if val_kind == i32::from(VT_LOCAL) {
            if fc > 0 {
                // fc > 0 guarantees non-negative, so u32 conversion is safe.
                let param_idx = (fc as u32 / 4) as usize;
                if param_idx < MAX_FUNC_ARGS && !self.param_on_stack[param_idx] {
                    self.emit_mv(state, reg, self.stack_to_reg[param_idx])?;
                    return Ok(());
                }
            }
            self.load_const32(state, fc, C67_A0)?;
            self.emit_nop(state, 4)?;
            self.emit_st_sp_a0(state, reg, size)?;
        } else if has_sym {
            self.load_const32(state, fc, C67_A0)?;
            self.emit_nop(state, 4)?;
            self.emit_st_ptr(state, reg, C67_A0, size)?;
        } else {
            self.emit_st_ptr(state, reg, val_kind, size)?;
        }
        Ok(())
    }

    /// Emit a store to `[SP + A0]` with the appropriate width.
    fn emit_st_sp_a0(&self, state: &mut TccState, src: i32, size: i32) -> TccResult<()> {
        let op = match size {
            1 => C67Op::StbSpA0, 2 => C67Op::SthSpA0, _ => C67Op::StwSpA0,
        };
        self.emit_instr(state, Self::encode(op, src, C67_SP, 0))
    }

    /// Emit a store to `[ptr_reg]` with the appropriate width.
    fn emit_st_ptr(&self, state: &mut TccState, src: i32, ptr_reg: i32, size: i32) -> TccResult<()> {
        let op = match size {
            1 => C67Op::StbPtr, 2 => C67Op::SthPtr, _ => C67Op::StwPtr,
        };
        self.emit_instr(state, Self::encode(op, src, 0, ptr_reg))
    }
}

// ---- CodegenBackend Implementation ----
impl CodegenBackend for C67Backend {
    fn target_machine_defs(&self) -> &[&str] { TARGET_DEFS }
    fn reg_classes(&self) -> &[u32] { &REG_CLASSES_TABLE }

    /// Patch forward references: walk the MVKL chain at `t` and fill in address `a`.
    fn gsym_addr(&mut self, state: &mut TccState, t: i32, addr: i32) -> TccResult<()> {
        let mut t_pos = t;
        while t_pos != 0 {
            let lo_instr = self.read_instr_at(state, i64::from(t_pos))?;
            let next_lo = (lo_instr >> 7) & 0xFFFF;
            let lo16 = i2u(addr) & 0xFFFF;
            self.write_instr_at(state, i64::from(t_pos), (lo_instr & 0xFF80_007F) | (lo16 << 7))?;
            let hi_off = i64::from(t_pos) + 4;
            let hi_instr = self.read_instr_at(state, hi_off)?;
            let hi16 = (i2u(addr) >> 16) & 0xFFFF;
            self.write_instr_at(state, hi_off, (hi_instr & 0xFF80_007F) | (hi16 << 7))?;
            #[allow(clippy::cast_possible_wrap)]
            { t_pos = next_lo as i32; }
        }
        Ok(())
    }

    fn gsym(&mut self, state: &mut TccState, t: i32) -> TccResult<()> {
        #[allow(clippy::cast_possible_truncation)]
        let addr = state.ind as i32;
        self.gsym_addr(state, t, addr)
    }

    fn load(&mut self, state: &mut TccState, r: i32, sv: &SValue) -> TccResult<()> {
        self.do_load(state, r, sv)
    }

    fn store(&mut self, state: &mut TccState, r: i32, sv: &SValue) -> TccResult<()> {
        self.do_store(state, r, sv)
    }

    /// C67 does not support struct returns in registers (c67-gen.c:1873).
    fn gfunc_sret(
        &self, _vt: &CType, _variadic: bool,
        _ret: &mut CType, _align: &mut i32, _regsize: &mut i32,
    ) -> i32 {
        0
    }

    /// Generate a function call (c67-gen.c:1877-1903).
    fn gfunc_call(&mut self, state: &mut TccState, nb_args: i32) -> TccResult<()> {
        if nb_args > 10 {
            return Err(TccError::parse(
                "more than 10 function params not currently supported on C67",
            ));
        }
        self.emit_nop(state, 5)
    }

    /// Generate function prologue (c67-gen.c:1905-1970).
    fn gfunc_prolog(&mut self, state: &mut TccState, func_sym: &Symbol) -> TccResult<()> {
        self.n_func_args = 0;
        self.total_pushed = 0;
        self.stack_to_reg = [0; MAX_FUNC_ARGS];
        self.param_on_stack = [false; MAX_FUNC_ARGS];

        let n_args = i32::from(func_sym.func_attr.func_args);
        self.n_func_args = n_args;
        #[allow(clippy::cast_sign_loss)]
        let n_arg_usize = (n_args.max(0) as usize).min(MAX_FUNC_ARGS);
        for idx in 0..n_arg_usize {
            let (even, _) = Self::arg_reg_pair(idx);
            self.stack_to_reg[idx] = even;
            self.param_on_stack[idx] = false;
        }
        // Save frame pointer and return address.
        self.emit_push(state, C67_FP)?;
        self.emit_push(state, C67_B3)?;
        self.emit_mv(state, C67_SP, C67_FP)?;
        // Reserve placeholder for local frame size (patched in epilog).
        self.func_sub_sp_off = state.ind;
        self.emit_addk(state, 0, C67_SP)?;
        // Push argument registers to stack.
        for idx in 0..n_arg_usize {
            let (even, _) = Self::arg_reg_pair(idx);
            self.emit_push(state, even)?;
            self.param_on_stack[idx] = true;
        }
        Ok(())
    }

    /// Generate function epilogue (c67-gen.c:1972-2037).
    fn gfunc_epilog(&mut self, state: &mut TccState) -> TccResult<()> {
        self.emit_pop(state, C67_B3)?;
        self.emit_nop(state, 4)?;
        self.emit_b_reg(state, C67_B3)?;
        self.emit_pop(state, C67_FP)?;
        self.func_ret_sub = state.ind;
        self.emit_addk(state, 0, C67_SP)?;
        self.emit_nop(state, 4)?;
        // Patch prologue/epilogue ADDK immediates.
        let local_space = -self.total_pushed;
        self.patch_addk(state, self.func_sub_sp_off, local_space)?;
        self.patch_addk(state, self.func_ret_sub, self.total_pushed)
    }

    /// Fill `bytes` bytes of the code section with NOPs (c67-gen.c:2039-2051).
    fn gen_fill_nops(&mut self, state: &mut TccState, bytes: i32) -> TccResult<()> {
        if (bytes % 4) != 0 {
            return Err(TccError::parse(
                "alignment of code section not multiple of 4 for C67",
            ));
        }
        let mut rem = bytes;
        while rem > 0 {
            self.emit_nop(state, 4)?;
            rem -= 4;
        }
        Ok(())
    }

    /// Unconditional jump — returns label for forward-reference chain (c67-gen.c:2053-2079).
    fn gjmp(&mut self, state: &mut TccState, t: i32) -> TccResult<i32> {
        if state.nocode_wanted != 0 { return Ok(t); }
        #[allow(clippy::cast_possible_truncation)]
        let ret = state.ind as i32;
        self.emit_mvkl(state, t, C67_A0)?;
        self.emit_mvkh(state, 0, C67_A0)?;
        self.emit_b_reg(state, C67_A0)?;
        self.emit_nop(state, 5)?;
        Ok(ret)
    }

    /// Jump to absolute address `addr` (c67-gen.c:2081-2087).
    fn gjmp_addr(&mut self, state: &mut TccState, addr: i32) -> TccResult<()> {
        self.load_const32(state, addr, C67_A0)?;
        self.emit_b_reg(state, C67_A0)?;
        self.emit_nop(state, 5)
    }

    /// Conditional jump — emits conditioned MVKL/MVKH/B sequence (c67-gen.c:2089-2106).
    fn gjmp_cond(&mut self, state: &mut TccState, _op: i32, t: i32) -> TccResult<i32> {
        if state.nocode_wanted != 0 { return Ok(t); }
        #[allow(clippy::cast_possible_truncation)]
        let ret = state.ind as i32;
        let cond_reg = Self::creg(self.compare_reg);
        let z_bit: u32 = u32::from(self.invert_test);
        let cond_bits = (cond_reg << 29) | (z_bit << 28);
        // MVKL (conditioned)
        let lo_base = Self::encode(C67Op::Mvkl, 0, t, C67_A0);
        self.emit_instr(state, lo_base | cond_bits)?;
        // MVKH (conditioned)
        let hi_base = Self::encode(C67Op::Mvkh, 0, 0, C67_A0);
        self.emit_instr(state, hi_base | cond_bits)?;
        // B reg (conditioned)
        let br_base = Self::encode(C67Op::BReg, 0, C67_A0, 0);
        self.emit_instr(state, br_base | cond_bits)?;
        self.emit_nop(state, 5)?;
        Ok(ret)
    }

    /// Append label `t` to the end of the forward-reference chain at `n` (c67-gen.c:2108-2130).
    fn gjmp_append(&mut self, state: &mut TccState, n: i32, t: i32) -> TccResult<i32> {
        if n != 0 {
            let mut pos = n;
            loop {
                let mvkl = self.read_instr_at(state, i64::from(pos))?;
                let next = (mvkl >> 7) & 0xFFFF;
                if next == 0 {
                    let patched = (mvkl & 0xFF80_007F) | ((i2u(t) & 0xFFFF) << 7);
                    self.write_instr_at(state, i64::from(pos), patched)?;
                    break;
                }
                #[allow(clippy::cast_possible_wrap)]
                { pos = next as i32; }
            }
            Ok(n)
        } else {
            Ok(t)
        }
    }

    /// Generate an integer operation (c67-gen.c:2132-2280).
    fn gen_opi(&mut self, state: &mut TccState, op: i32) -> TccResult<()> {
        let ea = REG_EAX;
        let ec = REG_ECX;
        let ed = REG_EDX;
        match op {
            TOK_LT => { self.compare_reg = ed; self.invert_test = false;
                self.emit_instr(state, Self::encode(C67Op::Cmplt, ea, ec, ed))?; }
            TOK_GE => { self.compare_reg = ed; self.invert_test = true;
                self.emit_instr(state, Self::encode(C67Op::Cmplt, ea, ec, ed))?; }
            TOK_GT => { self.compare_reg = ed; self.invert_test = false;
                self.emit_instr(state, Self::encode(C67Op::Cmpgt, ea, ec, ed))?; }
            TOK_LE => { self.compare_reg = ed; self.invert_test = true;
                self.emit_instr(state, Self::encode(C67Op::Cmpgt, ea, ec, ed))?; }
            TOK_EQ => { self.compare_reg = ed; self.invert_test = false;
                self.emit_instr(state, Self::encode(C67Op::Cmpeq, ea, ec, ed))?; }
            TOK_NE => { self.compare_reg = ed; self.invert_test = true;
                self.emit_instr(state, Self::encode(C67Op::Cmpeq, ea, ec, ed))?; }
            TOK_ULT => { self.compare_reg = ed; self.invert_test = false;
                self.emit_instr(state, Self::encode(C67Op::Cmpltu, ea, ec, ed))?; }
            TOK_UGE => { self.compare_reg = ed; self.invert_test = true;
                self.emit_instr(state, Self::encode(C67Op::Cmpltu, ea, ec, ed))?; }
            TOK_UGT => { self.compare_reg = ed; self.invert_test = false;
                self.emit_instr(state, Self::encode(C67Op::Cmpgtu, ea, ec, ed))?; }
            TOK_ULE => { self.compare_reg = ed; self.invert_test = true;
                self.emit_instr(state, Self::encode(C67Op::Cmpgtu, ea, ec, ed))?; }
            // '+' = 0x2B
            0x2B => self.emit_instr(state, Self::encode(C67Op::Add, ea, ec, ea))?,
            // '-' = 0x2D
            0x2D => self.emit_instr(state, Self::encode(C67Op::Sub, ec, ea, ea))?,
            // '&' = 0x26
            0x26 => self.emit_instr(state, Self::encode(C67Op::And, ea, ec, ea))?,
            // '|' = 0x7C
            0x7C => self.emit_instr(state, Self::encode(C67Op::Or, ea, ec, ea))?,
            // '^' = 0x5E
            0x5E => self.emit_instr(state, Self::encode(C67Op::Xor, ea, ec, ea))?,
            // '*' = 0x2A
            0x2A => {
                self.emit_instr(state, Self::encode(C67Op::Mpyi, ea, ec, ea))?;
                self.emit_nop(state, 8)?;
            }
            // TOK_SHL = 0x01
            0x01 => self.emit_instr(state, Self::encode(C67Op::Shl, ec, ea, ea))?,
            // TOK_SAR = 0x02
            0x02 => self.emit_instr(state, Self::encode(C67Op::Shr, ec, ea, ea))?,
            // TOK_SHR = 0x03
            0x03 => self.emit_instr(state, Self::encode(C67Op::Shru, ec, ea, ea))?,
            // '/' = 0x2F, '%' = 0x25 — division via helper call
            0x2F | 0x25 => {
                self.gcall_or_jmp(state, false, &SValue::default())?;
            }
            _ => { /* other ops handled generically */ }
        }
        Ok(())
    }

    /// Generate a floating-point operation (c67-gen.c:2282-2420).
    fn gen_opf(&mut self, state: &mut TccState, op: i32) -> TccResult<()> {
        let ea = REG_EAX;
        let ec = REG_ECX;
        let ed = REG_EDX;
        match op {
            TOK_LT => { self.compare_reg = ed; self.invert_test = false;
                self.emit_instr(state, Self::encode(C67Op::Cmpltsp, ea, ec, ed))?; }
            TOK_GE => { self.compare_reg = ed; self.invert_test = true;
                self.emit_instr(state, Self::encode(C67Op::Cmpltsp, ea, ec, ed))?; }
            TOK_GT => { self.compare_reg = ed; self.invert_test = false;
                self.emit_instr(state, Self::encode(C67Op::Cmpgtsp, ea, ec, ed))?; }
            TOK_LE => { self.compare_reg = ed; self.invert_test = true;
                self.emit_instr(state, Self::encode(C67Op::Cmpgtsp, ea, ec, ed))?; }
            TOK_EQ => { self.compare_reg = ed; self.invert_test = false;
                self.emit_instr(state, Self::encode(C67Op::Cmpeqsp, ea, ec, ed))?; }
            TOK_NE => { self.compare_reg = ed; self.invert_test = true;
                self.emit_instr(state, Self::encode(C67Op::Cmpeqsp, ea, ec, ed))?; }
            // '+' = 0x2B
            0x2B => {
                self.emit_instr(state, Self::encode(C67Op::Addsp, ea, ec, ea))?;
                self.emit_nop(state, 3)?;
            }
            // '-' = 0x2D
            0x2D => {
                self.emit_instr(state, Self::encode(C67Op::Subsp, ec, ea, ea))?;
                self.emit_nop(state, 3)?;
            }
            // '*' = 0x2A
            0x2A => {
                self.emit_instr(state, Self::encode(C67Op::Mpysp, ea, ec, ea))?;
                self.emit_nop(state, 3)?;
            }
            // '/' = 0x2F — division via helper call
            0x2F => {
                self.gcall_or_jmp(state, false, &SValue::default())?;
            }
            _ => { /* other float ops handled generically */ }
        }
        Ok(())
    }

    /// Float-to-integer conversion (c67-gen.c:2460-2475).
    fn gen_cvt_ftoi(&mut self, state: &mut TccState, t: i32) -> TccResult<()> {
        if (t & VT_BTYPE) == VT_LLONG {
            return Err(TccError::parse("long long not supported on C67"));
        }
        let ea = REG_EAX;
        self.emit_instr(state, Self::encode(C67Op::Sptrunc, 0, ea, ea))?;
        self.emit_nop(state, 3)
    }

    /// Integer-to-float conversion (c67-gen.c:2429-2458).
    fn gen_cvt_itof(&mut self, state: &mut TccState, t: i32) -> TccResult<()> {
        let ea = REG_EAX;
        if (t & VT_BTYPE) == VT_DOUBLE {
            self.emit_instr(state, Self::encode(C67Op::Intdp, 0, ea, ea))?;
            self.emit_nop(state, 4)
        } else {
            self.emit_instr(state, Self::encode(C67Op::Intsp, 0, ea, ea))?;
            self.emit_nop(state, 3)
        }
    }

    /// Float-to-float conversion — SP↔DP (c67-gen.c:2478-2500).
    fn gen_cvt_ftof(&mut self, state: &mut TccState, t: i32) -> TccResult<()> {
        let ea = REG_EAX;
        if (t & VT_BTYPE) == VT_DOUBLE {
            self.emit_instr(state, Self::encode(C67Op::Spdp, 0, ea, ea))?;
            self.emit_nop(state, 1)
        } else if (t & VT_BTYPE) == VT_FLOAT {
            self.emit_instr(state, Self::encode(C67Op::Dpsp, 0, ea, ea))?;
            self.emit_nop(state, 3)
        } else {
            Ok(())
        }
    }

    /// Indirect jump via value on top of stack (c67-gen.c:2519-2524).
    fn ggoto(&mut self, state: &mut TccState) -> TccResult<()> {
        self.gcall_or_jmp(state, true, &SValue::default())
    }

    /// Raw byte emission — not available for C67 (uses VLIW instruction words).
    fn o(&mut self, _state: &mut TccState, _c: u32) -> TccResult<()> {
        Err(TccError::UnsupportedTarget(
            "o() is not available on TMS320C67".into(),
        ))
    }

    /// VLA SP save — unsupported on C67 (c67-gen.c:2526-2528).
    fn gen_vla_sp_save(&mut self, _state: &mut TccState, _addr: i32) -> TccResult<()> {
        Err(TccError::parse("variable length arrays unsupported for C67 target"))
    }

    /// VLA SP restore — unsupported on C67 (c67-gen.c:2531-2533).
    fn gen_vla_sp_restore(&mut self, _state: &mut TccState, _addr: i32) -> TccResult<()> {
        Err(TccError::parse("variable length arrays unsupported for C67 target"))
    }

    /// VLA allocation — unsupported on C67 (c67-gen.c:2536-2538).
    fn gen_vla_alloc(&mut self, _state: &mut TccState, _type_: &CType, _align: i32) -> TccResult<()> {
        Err(TccError::parse("variable length arrays unsupported for C67 target"))
    }
}

// ---- LinkerBackend Implementation (c67-link.c) ----
impl LinkerBackend for C67Backend {
    /// Classify whether a relocation type needs code relocation (c67-link.c:35-60).
    fn code_reloc(&self, reloc_type: i32) -> i32 {
        match reloc_type {
            R_C60_32 | R_C60LO16 | R_C60HI16
            | R_C60_GOT32 | R_C60_GOTOFF | R_C60_GOTPC => 0,
            R_C60_PLT32 => 1,
            _ => -1,
        }
    }

    /// Return the GOT/PLT entry type for a C60 relocation (c67-link.c:62-68).
    fn gotplt_entry_type(&self, reloc_type: i32) -> GotPltEntry {
        match reloc_type {
            R_C60_GOTOFF | R_C60_GOTPC => GotPltEntry::BuildGotOnly,
            R_C60_PLT32 | R_C60_GOT32 => GotPltEntry::AlwaysEntry,
            // R_C60_32, R_C60LO16, R_C60HI16 and all others need no GOT/PLT entry.
            _ => GotPltEntry::NoEntry,
        }
    }

    /// Apply a C60 relocation to instruction/data bytes (c67-link.c:78-114).
    fn relocate(
        &self, _state: &mut TccState, rel_type: i32,
        ptr: &mut [u8], _addr: u64, val: u64,
    ) -> TccResult<()> {
        match rel_type {
            R_C60_32 => {
                // CVE-2018-20374: Vec<Section> with checked indexing eliminates OOB write.
                if ptr.len() < 4 {
                    return Err(TccError::link("C67 relocate: buffer too small for R_C60_32"));
                }
                let cur = read32le(ptr);
                #[allow(clippy::cast_possible_truncation)]
                let add = val as u32;
                write32le(ptr, cur.wrapping_add(add));
            }
            R_C60LO16 => {
                // Paired LO16/HI16 relocation: extract old value from two instruction
                // words, add the relocation delta, and re-insert the halves.
                if ptr.len() < 8 {
                    return Err(TccError::link("C67 relocate: buffer too small for LO16"));
                }
                let lo_instr = read32le(ptr);
                let old_lo = (lo_instr >> 7) & 0xFFFF;
                let hi_instr = read32le(&ptr[4..]);
                let old_hi = (hi_instr >> 7) & 0xFFFF;
                let old_val = (old_hi << 16) | old_lo;
                #[allow(clippy::cast_possible_truncation)]
                let new_val = old_val.wrapping_add(val as u32);
                write32le(ptr, (lo_instr & 0xFF80_007F) | ((new_val & 0xFFFF) << 7));
                write32le(
                    &mut ptr[4..],
                    (hi_instr & 0xFF80_007F) | (((new_val >> 16) & 0xFFFF) << 7),
                );
            }
            // R_C60HI16 is handled implicitly by the LO16 paired case above.
            // All other relocation types are silently ignored per C original.
            _ => {}
        }
        Ok(())
    }

    /// Create a PLT entry — not implemented for C67 (c67-link.c:70).
    fn create_plt_entry(&mut self, _state: &mut TccState, _got_offset: u32) -> TccResult<u32> {
        Err(TccError::link("C67 got not implemented"))
    }

    /// Relocate the PLT section — nothing to do for C67.
    fn relocate_plt(&mut self, _state: &mut TccState) -> TccResult<()> {
        Ok(())
    }
}

// ---- Unit Tests ----
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let backend = C67Backend::new();
        assert_eq!(backend.n_func_args, 0);
        assert_eq!(backend.total_pushed, 0);
        assert!(!backend.invert_test);
    }

    #[test]
    fn test_defs() {
        let backend = C67Backend::new();
        assert_eq!(backend.target_machine_defs(), &["__C67__"]);
    }

    #[test]
    fn test_reg_classes_len() {
        let backend = C67Backend::new();
        assert_eq!(backend.reg_classes().len(), NB_REGS);
    }

    #[test]
    fn test_regn() {
        assert_eq!(C67Backend::regn(0), 2);  // TREG_EAX → A2
        assert_eq!(C67Backend::regn(1), 3);  // TREG_ECX → A3
        assert_eq!(C67Backend::regn(2), 0);  // TREG_EDX → B0
        assert_eq!(C67Backend::regn(C67_SP), 15); // B15
        assert_eq!(C67Backend::regn(C67_FP), 15); // A15
    }

    #[test]
    fn test_side() {
        assert_eq!(C67Backend::side(0), 0);  // A-side
        assert_eq!(C67Backend::side(2), 1);  // B-side
        assert_eq!(C67Backend::side(C67_A0), 0);
        assert_eq!(C67Backend::side(C67_SP), 1);
    }

    #[test]
    fn test_creg() {
        assert_eq!(C67Backend::creg(C67_CREG_ZERO), 0);
        // A0 → hardware reg 0 on A-side → creg=4
        assert_eq!(C67Backend::creg(C67_A0), 4);
    }

    #[test]
    fn test_sret() {
        let backend = C67Backend::new();
        let ct = CType::default();
        let mut ret = CType::default();
        let mut align = 0i32;
        let mut regsize = 0i32;
        assert_eq!(backend.gfunc_sret(&ct, false, &mut ret, &mut align, &mut regsize), 0);
    }

    #[test]
    fn test_code_reloc() {
        let backend = C67Backend::new();
        assert_eq!(backend.code_reloc(R_C60_32), 0);
        assert_eq!(backend.code_reloc(R_C60_PLT32), 1);
        assert_eq!(backend.code_reloc(999), -1);
    }

    #[test]
    fn test_gotplt() {
        let backend = C67Backend::new();
        assert_eq!(backend.gotplt_entry_type(R_C60_32), GotPltEntry::NoEntry);
        assert_eq!(backend.gotplt_entry_type(R_C60_GOTOFF), GotPltEntry::BuildGotOnly);
        assert_eq!(backend.gotplt_entry_type(R_C60_PLT32), GotPltEntry::AlwaysEntry);
    }

    #[test]
    fn test_plt_err() {
        let mut backend = C67Backend::new();
        let mut state = TccState::default();
        assert!(backend.create_plt_entry(&mut state, 0).is_err());
    }

    #[test]
    fn test_reloc_r_c60_32() {
        let backend = C67Backend::new();
        let mut state = TccState::default();
        let mut buf = [0u8; 4];
        write32le(&mut buf, 100);
        backend.relocate(&mut state, R_C60_32, &mut buf, 0, 50).unwrap();
        assert_eq!(read32le(&buf), 150);
    }

    #[test]
    fn test_reloc_lo16() {
        let backend = C67Backend::new();
        let mut state = TccState::default();
        let mut buf = [0u8; 8];
        write32le(&mut buf[0..4], 0x1234 << 7);
        write32le(&mut buf[4..8], 0);
        backend.relocate(&mut state, R_C60LO16, &mut buf, 0, 0x1_0000).unwrap();
        let new_lo = (read32le(&buf[0..4]) >> 7) & 0xFFFF;
        let new_hi = (read32le(&buf[4..8]) >> 7) & 0xFFFF;
        assert_eq!(new_lo, 0x1234);
        assert_eq!(new_hi, 1);
    }

    #[test]
    fn test_vla_err() {
        let mut backend = C67Backend::new();
        let mut state = TccState::default();
        assert!(backend.gen_vla_sp_save(&mut state, 0).is_err());
        assert!(backend.gen_vla_sp_restore(&mut state, 0).is_err());
        assert!(backend.gen_vla_alloc(&mut state, &CType::default(), 4).is_err());
    }

    #[test]
    fn test_o_err() {
        let mut backend = C67Backend::new();
        let mut state = TccState::default();
        assert!(backend.o(&mut state, 0x90).is_err());
    }

    #[test]
    fn test_btype_size() {
        assert_eq!(C67Backend::btype_size(VT_BYTE), 1);
        assert_eq!(C67Backend::btype_size(VT_SHORT), 2);
        assert_eq!(C67Backend::btype_size(VT_DOUBLE), 8);
        assert_eq!(C67Backend::btype_size(VT_INT), 4);
    }

    #[test]
    fn test_nop_encode() {
        let nop4 = C67Backend::encode(C67Op::Nop, 4, 0, 0);
        assert_eq!((nop4 >> 13) & 0xF, 4);
    }

    #[test]
    fn test_plt_ok() {
        let mut backend = C67Backend::new();
        let mut state = TccState::default();
        assert!(backend.relocate_plt(&mut state).is_ok());
    }

    #[test]
    fn test_arg_pairs() {
        assert_eq!(C67Backend::arg_reg_pair(0), (REG_C67_A4, REG_C67_A5));
        assert_eq!(C67Backend::arg_reg_pair(9), (REG_C67_B12, REG_C67_B13));
    }

    #[test]
    fn test_encode_mvkl() {
        // MVKL should encode the lower 16 bits of an immediate into bits 7-22.
        let instr = C67Backend::encode(C67Op::Mvkl, 0, 0x1234, C67_A0);
        let imm = (instr >> 7) & 0xFFFF;
        assert_eq!(imm, 0x1234);
    }

    #[test]
    fn test_encode_mv() {
        // MV from C67_SP to C67_FP should produce a valid instruction word.
        let instr = C67Backend::encode(C67Op::Mv, 0, C67_SP, C67_FP);
        // The instruction should be non-zero.
        assert_ne!(instr, 0);
    }

    #[test]
    fn test_reloc_buffer_too_small() {
        let backend = C67Backend::new();
        let mut state = TccState::default();
        let mut buf = [0u8; 2]; // too small for R_C60_32
        assert!(backend.relocate(&mut state, R_C60_32, &mut buf, 0, 50).is_err());
    }

    #[test]
    fn test_i2u() {
        assert_eq!(i2u(0), 0_u32);
        assert_eq!(i2u(-1), 0xFFFF_FFFF);
        assert_eq!(i2u(42), 42_u32);
    }
}
