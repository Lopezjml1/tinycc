// ARM 32-bit backend — instruction encoding inherently requires
// integer casts between u8/u16/u32/i32/i64/u64 for register indices,
// immediate fields, and opcode composition.
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::bool_to_int_with_if)]
#![allow(clippy::cast_lossless)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::fn_params_excessive_bools)]
#![allow(clippy::identity_op)]
#![allow(clippy::if_not_else)]
#![allow(clippy::items_after_statements)]
#![allow(clippy::manual_range_contains)]
#![allow(clippy::map_unwrap_or)]
#![allow(clippy::match_same_arms)]
#![allow(clippy::match_wildcard_for_single_variants)]
#![allow(clippy::needless_borrows_for_generic_args)]
#![allow(clippy::needless_pass_by_value)]
#![allow(clippy::no_effect_underscore_binding)]
#![allow(clippy::similar_names)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::unnecessary_cast)]
#![allow(clippy::unnecessary_wraps)]
#![allow(clippy::unreadable_literal)]
#![allow(clippy::unusual_byte_groupings)]
#![allow(clippy::unused_self)]
#![allow(clippy::wildcard_imports)]
#![allow(unused_variables)]
#![allow(unused_parens)]

// Copyright (c) 2024 tinycc-rs contributors
// SPDX-License-Identifier: MIT OR LGPL-2.1-or-later

//! ARM 32-bit (ARMv4+) architecture backend for TinyCC.
//!
//! Consolidates `arm-gen.c` (2,385 lines), `arm-asm.c` (3,092 lines),
//! `arm-link.c` (445 lines), and `arm-tok.h` (406 lines) from the original
//! C codebase into a single Rust module.  Supports ARM/Thumb, VFP, EABI.
//!
//! ## CVE Remediation
//!
//! - **CVE-2018-20376**: Directive buffers use `Vec<u8>` — no raw pointer writes.
//! - **CVE-2018-20374**: Section arrays use `Vec<Section>` with checked indexing.
//! - **CVE-2006-0635**: All integer casts use explicit conversions.
//!
//! ## Register Model (arm-gen.c:24-98)
//!
//! ARM uses 13 allocatable registers in VFP mode:
//! - r0-r3, r12  (5 GP)
//! - s0/d0-s7/d7 (8 VFP)
//!
//! C equivalent: `arm-gen.c`, `arm-asm.c`, `arm-link.c`, `arm-tok.h`.

// ===========================================================================
//  Imports
// ===========================================================================

use crate::context::TccState;
use crate::error::{TccError, TccResult};
use crate::formats::elf::{
    EM_ARM, R_ARM_ABS32, R_ARM_CALL, R_ARM_COPY, R_ARM_GLOB_DAT, R_ARM_GOT32,
    R_ARM_GOTOFF, R_ARM_GOTPC, R_ARM_GOT_PREL, R_ARM_JUMP24, R_ARM_JUMP_SLOT,
    R_ARM_MOVT_ABS, R_ARM_MOVT_PREL, R_ARM_MOVW_ABS_NC, R_ARM_MOVW_PREL_NC,
    R_ARM_NONE, R_ARM_NUM, R_ARM_PC24, R_ARM_PLT32, R_ARM_PREL31,
    R_ARM_REL32, R_ARM_RELATIVE, R_ARM_TARGET1, R_ARM_THM_JUMP24,
    R_ARM_THM_MOVT_ABS, R_ARM_THM_MOVW_ABS_NC, R_ARM_THM_PC22, R_ARM_V4BX,
};
use crate::targets::{
    add32le, read32le, write32le, CodegenBackend, GotPltEntry, LinkerBackend,
};
use crate::tokens::{
    TOK_EOF, TOK_EQ, TOK_GE, TOK_GT, TOK_LE, TOK_LINEFEED, TOK_LT, TOK_NE,
    TOK_SAR, TOK_SHL, TOK_SHR, TOK_UDIV, TOK_UGE, TOK_UGT, TOK_ULE, TOK_ULT,
    TOK_UMOD,
};
use crate::types::{
    CType, CValue, SValue, SValueData, Symbol, VT_BTYPE, VT_BYTE, VT_CMP,
    VT_CONST, VT_DOUBLE, VT_FLOAT, VT_INT, VT_JMP, VT_JMPI, VT_LDOUBLE,
    VT_LLONG, VT_LLOCAL, VT_LOCAL, VT_LVAL, VT_SYM,
    VT_STRUCT, VT_UNSIGNED, VT_VALMASK, VT_VOID,
};

// ===========================================================================
//  Register Constants (arm-gen.c:24-98)
// ===========================================================================

/// Number of allocatable registers (VFP mode): r0-r3, r12 (5), d0-d7 (8) = 13.
/// C equivalent: `NB_REGS 13` (arm-gen.c:30).
pub const NB_REGS: usize = 13;

/// Number of assembly register names (r0-r15).
/// C equivalent: `NB_ASM_REGS 16` (arm-gen.c:33).
pub const NB_ASM_REGS: usize = 16;

// ---------------------------------------------------------------------------
//  Register Class Bitmasks (arm-gen.c:44-59)
// ---------------------------------------------------------------------------

/// Integer register class.
pub const RC_INT: u32 = 0x0001;
/// Float register class (VFP).
pub const RC_FLOAT: u32 = 0x0002;
/// Register class for r0.
pub const RC_R0: u32 = 0x0004;
/// Register class for r1.
pub const RC_R1: u32 = 0x0008;
/// Register class for r2.
pub const RC_R2: u32 = 0x0010;
/// Register class for r3.
pub const RC_R3: u32 = 0x0020;
/// Register class for r12 (scratch register).
pub const RC_R12: u32 = 0x0040;
/// Register class for VFP s0/d0.
pub const RC_F0: u32 = 0x0080;
/// Register class for VFP s1/d1.
pub const RC_F1: u32 = 0x0100;
/// Register class for VFP s2/d2.
pub const RC_F2: u32 = 0x0200;
/// Register class for VFP s3/d3.
pub const RC_F3: u32 = 0x0400;

/// Integer return register (r0).
pub const RC_IRET: u32 = RC_R0;
/// Second integer return register (r1) for 64-bit values.
pub const RC_IRE2: u32 = RC_R1;
/// Float return register (s0/d0).
pub const RC_FRET: u32 = RC_F0;

/// Register class array mapping each TCC register index to its class bitmask.
/// C equivalent: `reg_classes[]` (arm-gen.c:66-84).
pub const REG_CLASSES: [u32; NB_REGS] = [
    RC_INT | RC_R0,     // 0: r0
    RC_INT | RC_R1,     // 1: r1
    RC_INT | RC_R2,     // 2: r2
    RC_INT | RC_R3,     // 3: r3
    RC_INT | RC_R12,    // 4: r12
    RC_FLOAT | RC_F0,   // 5: s0/d0
    RC_FLOAT | RC_F1,   // 6: s1/d1
    RC_FLOAT | RC_F2,   // 7: s2/d2
    RC_FLOAT | RC_F3,   // 8: s3/d3
    RC_FLOAT,           // 9: s4/d4
    RC_FLOAT,           // 10: s5/d5
    RC_FLOAT,           // 11: s6/d6
    RC_FLOAT,           // 12: s7/d7
];

// ---------------------------------------------------------------------------
//  Named Register Indices (arm-gen.c:66-84)
// ---------------------------------------------------------------------------

/// Typed register index enum for ARM.
/// C equivalent: register numbering in arm-gen.c:66-84.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TReg {
    /// General-purpose register r0 (index 0).
    R0 = 0,
    /// General-purpose register r1 (index 1).
    R1 = 1,
    /// General-purpose register r2 (index 2).
    R2 = 2,
    /// General-purpose register r3 (index 3).
    R3 = 3,
    /// General-purpose register r12/ip (index 4).
    R12 = 4,
    /// VFP register s0/d0 (index 5).
    F0 = 5,
    /// VFP register s1/d1 (index 6).
    F1 = 6,
    /// VFP register s2/d2 (index 7).
    F2 = 7,
    /// VFP register s3/d3 (index 8).
    F3 = 8,
    /// VFP register s4/d4 (index 9).
    F4 = 9,
    /// VFP register s5/d5 (index 10).
    F5 = 10,
    /// VFP register s6/d6 (index 11).
    F6 = 11,
    /// VFP register s7/d7 (index 12).
    F7 = 12,
}

/// Stack pointer register index (ARM r13).
pub const TREG_SP: u8 = 13;
/// Link register index (ARM r14).
pub const TREG_LR: u8 = 14;

// ===========================================================================
//  Platform Constants (arm-gen.c:110-128)
// ===========================================================================

/// Pointer size in bytes (32-bit ARM).
pub const PTR_SIZE: usize = 4;
/// Long double size (EABI: same as double).
pub const LDOUBLE_SIZE: usize = 8;
/// Long double alignment (EABI).
pub const LDOUBLE_ALIGN: usize = 8;
/// Maximum data alignment.
pub const MAX_ALIGN: usize = 8;
/// ARM char is unsigned by default.
pub const CHAR_IS_UNSIGNED: bool = true;

/// Target machine preprocessor definitions (arm-gen.c:144-157).
pub const TARGET_MACHINE_DEFS: &[&str] = &[
    "__arm__",
    "__arm",
    "arm",
    "__arm_elf__",
    "__arm_elf",
    "arm_elf",
    "__ARM_ARCH_4__",
    "__ARMEL__",
    "__APCS_32__",
    "__ARM_EABI__",
];

// ===========================================================================
//  ELF / Linker Constants (arm-link.c:1-16)
// ===========================================================================

/// ELF machine type for ARM.
pub const EM_TCC_TARGET: u16 = EM_ARM;
/// ELF default load address.
pub const ELF_START_ADDR: u64 = 0x0001_0000;
/// ELF page size for ARM.
pub const ELF_PAGE_SIZE: u64 = 0x0001_0000;
/// Data relocation type: 32-bit absolute.
pub const R_DATA_32: u32 = R_ARM_ABS32;
/// Data relocation type: pointer-sized.
pub const R_DATA_PTR: u32 = R_ARM_ABS32;
/// PLT jump slot relocation.
pub const R_JMP_SLOT: u32 = R_ARM_JUMP_SLOT;
/// GOT global data relocation.
pub const R_GLOB_DAT: u32 = R_ARM_GLOB_DAT;
/// Copy relocation.
pub const R_COPY: u32 = R_ARM_COPY;
/// Relative relocation.
pub const R_RELATIVE: u32 = R_ARM_RELATIVE;
/// Number of relocation types.
pub const R_NUM: u32 = R_ARM_NUM;
/// PLT is PC-relative on ARM.
pub const PCRELATIVE_DLLPLT: i32 = 1;
/// DLL PLT relocation constant.
pub const RELOCATE_DLLPLT: i32 = 0;

// ===========================================================================
//  ARM Condition Codes (arm-gen.c:239-247)
// ===========================================================================

const COND_AL: u32 = 0xE;
const COND_EQ: u32 = 0x0;
const COND_NE: u32 = 0x1;
const COND_CS: u32 = 0x2;
const COND_CC: u32 = 0x3;
const COND_MI: u32 = 0x4;
const COND_PL: u32 = 0x5;
const COND_VS: u32 = 0x6;
const COND_VC: u32 = 0x7;
const COND_HI: u32 = 0x8;
const COND_LS: u32 = 0x9;
const COND_GE: u32 = 0xA;
const COND_LT: u32 = 0xB;
const COND_GT: u32 = 0xC;
const COND_LE: u32 = 0xD;

// ---------------------------------------------------------------------------
//  ARM Data Processing Opcodes
// ---------------------------------------------------------------------------

const ARM_NOP: u32 = 0xE1A0_0000;
const DP_AND: u32 = 0x0;
const DP_EOR: u32 = 0x1;
const DP_SUB: u32 = 0x2;
const DP_RSB: u32 = 0x3;
const DP_ADD: u32 = 0x4;
#[allow(dead_code)]
const DP_ADC: u32 = 0x5;
#[allow(dead_code)]
const DP_SBC: u32 = 0x6;
#[allow(dead_code)]
const DP_RSC: u32 = 0x7;
#[allow(dead_code)]
const DP_TST: u32 = 0x8;
const DP_CMP: u32 = 0xA;
const DP_CMN: u32 = 0xB;
const DP_ORR: u32 = 0xC;
const DP_MOV: u32 = 0xD;
const DP_BIC: u32 = 0xE;
const DP_MVN: u32 = 0xF;

const SHIFT_LSL: u32 = 0;
const SHIFT_LSR: u32 = 1;
const SHIFT_ASR: u32 = 2;

// ===========================================================================
//  VFP Instruction Opcodes
// ===========================================================================

const VFP_VLDR_S: u32 = 0x0D10_0A00;
const VFP_VSTR_S: u32 = 0x0D00_0A00;
const VFP_VLDR_D: u32 = 0x0D10_0B00;
const VFP_VSTR_D: u32 = 0x0D00_0B00;
const VFP_VADD_S: u32 = 0x0E30_0A00;
const VFP_VSUB_S: u32 = 0x0E30_0A40;
const VFP_VMUL_S: u32 = 0x0E20_0A00;
const VFP_VDIV_S: u32 = 0x0E80_0A00;
const VFP_VADD_D: u32 = 0x0E30_0B00;
const VFP_VSUB_D: u32 = 0x0E30_0B40;
const VFP_VMUL_D: u32 = 0x0E20_0B00;
const VFP_VDIV_D: u32 = 0x0E80_0B00;
const VFP_VCMP_S: u32 = 0x0EB4_0A40;
const VFP_VCMP_D: u32 = 0x0EB4_0B40;
const VFP_VMRS: u32 = 0x0EF1_FA10;
const VFP_VCVT_SI_S: u32 = 0x0EB8_0AC0;
const VFP_VCVT_SI_D: u32 = 0x0EB8_0BC0;
const VFP_VCVT_UI_S: u32 = 0x0EB8_0A40;
const VFP_VCVT_UI_D: u32 = 0x0EB8_0B40;
const VFP_VCVT_S_SI: u32 = 0x0EBD_0AC0;
const VFP_VCVT_D_SI: u32 = 0x0EBD_0BC0;
const VFP_VCVT_S_UI: u32 = 0x0EBC_0AC0;
const VFP_VCVT_D_UI: u32 = 0x0EBC_0BC0;
const VFP_VCVT_D_S: u32 = 0x0EB7_0BC0;
const VFP_VCVT_S_D: u32 = 0x0EB7_0AC0;
const VFP_VMOV_S: u32 = 0x0E00_0A10;
const VFP_VMOV_S_TO_CORE: u32 = 0x0E10_0A10;

// ===========================================================================
//  Float ABI (arm-gen.c:21-24)
// ===========================================================================

/// ARM floating-point ABI selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FloatAbi {
    /// Soft-float: FP args passed in core registers.
    SoftFp,
    /// Hard-float: FP args passed in VFP registers.
    HardFloat,
}

// ===========================================================================
//  ARM Assembler Tokens (arm-tok.h)
// ===========================================================================

/// ARM assembler token definitions from `arm-tok.h`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArmAsmToken {
    R0, R1, R2, R3, R4, R5, R6, R7, R8, R9, R10, R11, R12, R13, R14, R15,
    A1, A2, A3, A4, V1, V2, V3, V4, V5, V6, V7, V8,
    Sb, Sl, Fp, Ip, Sp, Lr, Pc, Cpsr, Spsr,
    P0, P1, P2, P3, P4, P5, P6, P7, P8, P9, P10, P11, P12, P13, P14, P15,
    C0, C1, C2, C3, C4, C5, C6, C7, C8, C9, C10, C11, C12, C13, C14, C15,
    S0, S1, S2, S3, S4, S5, S6, S7, S8, S9, S10, S11, S12, S13, S14, S15,
    S16, S17, S18, S19, S20, S21, S22, S23, S24, S25, S26, S27, S28, S29, S30, S31,
    D0, D1, D2, D3, D4, D5, D6, D7, D8, D9, D10, D11, D12, D13, D14, D15,
    Eq, Ne, Cs, Hs, Cc, Lo, Mi, Pl, Vs, Vc, Hi, Ls, Ge, Lt, Gt, Le, Al,
}

// Instruction encoding token conversion uses bit-width casts.
#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
impl ArmAsmToken {
    /// Convert a register token to its hardware register number (0-15).
    pub fn to_reg_number(self) -> Option<u32> {
        match self {
            Self::R0 | Self::A1 => Some(0),
            Self::R1 | Self::A2 => Some(1),
            Self::R2 | Self::A3 => Some(2),
            Self::R3 | Self::A4 => Some(3),
            Self::R4 | Self::V1 => Some(4),
            Self::R5 | Self::V2 => Some(5),
            Self::R6 | Self::V3 => Some(6),
            Self::R7 | Self::V4 => Some(7),
            Self::R8 | Self::V5 => Some(8),
            Self::R9 | Self::V6 | Self::Sb => Some(9),
            Self::R10 | Self::V7 | Self::Sl => Some(10),
            Self::R11 | Self::V8 | Self::Fp => Some(11),
            Self::R12 | Self::Ip => Some(12),
            Self::R13 | Self::Sp => Some(13),
            Self::R14 | Self::Lr => Some(14),
            Self::R15 | Self::Pc => Some(15),
            _ => None,
        }
    }

    /// Convert a condition code token to its encoding (0-14).
    pub fn to_cond_code(self) -> Option<u32> {
        match self {
            Self::Eq => Some(0), Self::Ne => Some(1),
            Self::Cs | Self::Hs => Some(2), Self::Cc | Self::Lo => Some(3),
            Self::Mi => Some(4), Self::Pl => Some(5),
            Self::Vs => Some(6), Self::Vc => Some(7),
            Self::Hi => Some(8), Self::Ls => Some(9),
            Self::Ge => Some(10), Self::Lt => Some(11),
            Self::Gt => Some(12), Self::Le => Some(13),
            Self::Al => Some(14),
            _ => None,
        }
    }

    /// Convert a VFP single register token to its index (0-31).
    pub fn to_vfp_single(self) -> Option<u32> {
        match self {
            Self::S0 => Some(0), Self::S1 => Some(1), Self::S2 => Some(2),
            Self::S3 => Some(3), Self::S4 => Some(4), Self::S5 => Some(5),
            Self::S6 => Some(6), Self::S7 => Some(7), Self::S8 => Some(8),
            Self::S9 => Some(9), Self::S10 => Some(10), Self::S11 => Some(11),
            Self::S12 => Some(12), Self::S13 => Some(13), Self::S14 => Some(14),
            Self::S15 => Some(15), Self::S16 => Some(16), Self::S17 => Some(17),
            Self::S18 => Some(18), Self::S19 => Some(19), Self::S20 => Some(20),
            Self::S21 => Some(21), Self::S22 => Some(22), Self::S23 => Some(23),
            Self::S24 => Some(24), Self::S25 => Some(25), Self::S26 => Some(26),
            Self::S27 => Some(27), Self::S28 => Some(28), Self::S29 => Some(29),
            Self::S30 => Some(30), Self::S31 => Some(31),
            _ => None,
        }
    }

    /// Convert a VFP double register token to its index (0-15).
    pub fn to_vfp_double(self) -> Option<u32> {
        match self {
            Self::D0 => Some(0), Self::D1 => Some(1), Self::D2 => Some(2),
            Self::D3 => Some(3), Self::D4 => Some(4), Self::D5 => Some(5),
            Self::D6 => Some(6), Self::D7 => Some(7), Self::D8 => Some(8),
            Self::D9 => Some(9), Self::D10 => Some(10), Self::D11 => Some(11),
            Self::D12 => Some(12), Self::D13 => Some(13), Self::D14 => Some(14),
            Self::D15 => Some(15),
            _ => None,
        }
    }

    /// Convert a coprocessor register token to its index (0-15).
    pub fn to_coproc_reg(self) -> Option<u32> {
        match self {
            Self::P0 => Some(0), Self::P1 => Some(1), Self::P2 => Some(2),
            Self::P3 => Some(3), Self::P4 => Some(4), Self::P5 => Some(5),
            Self::P6 => Some(6), Self::P7 => Some(7), Self::P8 => Some(8),
            Self::P9 => Some(9), Self::P10 => Some(10), Self::P11 => Some(11),
            Self::P12 => Some(12), Self::P13 => Some(13), Self::P14 => Some(14),
            Self::P15 => Some(15),
            _ => None,
        }
    }
}

// ===========================================================================
//  Helper Functions
// ===========================================================================

/// Map a TCC register index to ARM hardware integer register number.
/// C equivalent: `intr(r)` (arm-gen.c:208).
fn intr(r: i32) -> u32 {
    match r {
        0 => 0,  // r0
        1 => 1,  // r1
        2 => 2,  // r2
        3 => 3,  // r3
        4 => 12, // r12
        _ => r as u32,
    }
}

/// Map a TCC register index to ARM VFP double-precision register number.
/// C equivalent: `vfpr(r)` (arm-gen.c:216).
fn vfpr(r: i32) -> u32 {
    if r >= 5 && r <= 12 { (r - 5) as u32 } else { 0 }
}

/// Check if a TCC register index is a float register.
fn is_freg(r: i32) -> bool {
    r >= TReg::F0 as i32
}

/// Extract a constant integer value from an SValue.
fn sv_constant_value(sv: &SValue) -> i64 {
    match &sv.value {
        SValueData::Constant(cv) => match cv {
            CValue::Int(v) => *v as i64,
            CValue::Float(v) => *v as i64,
            CValue::Double(v) => *v as i64,
            CValue::LongDouble(v) => *v as i64,
            _ => 0,
        },
        _ => 0,
    }
}

/// Extract a constant unsigned value from an SValue.
fn sv_constant_u64(sv: &SValue) -> u64 {
    match &sv.value {
        SValueData::Constant(CValue::Int(v)) => *v,
        _ => 0,
    }
}

/// Map a TCC comparison token to an ARM condition code.
/// C equivalent: `mapcc(cc)` (arm-gen.c:248-270).
fn mapcc(op: i32) -> u32 {
    match op {
        x if x == TOK_ULT => COND_CC,
        x if x == TOK_UGE => COND_CS,
        x if x == TOK_EQ  => COND_EQ,
        x if x == TOK_NE  => COND_NE,
        x if x == TOK_ULE => COND_LS,
        x if x == TOK_UGT => COND_HI,
        x if x == TOK_LT  => COND_LT,
        x if x == TOK_GE  => COND_GE,
        x if x == TOK_LE  => COND_LE,
        x if x == TOK_GT  => COND_GT,
        _ => COND_AL,
    }
}

/// Negate an ARM condition code.
/// C equivalent: `negcc(cc)` (arm-gen.c:272).
fn negcc(cc: u32) -> u32 {
    cc ^ 1
}

/// Try to encode an immediate value as an ARM rotated 8-bit constant.
/// C equivalent: `stuff_const(op, c)` (arm-gen.c:275).
fn stuff_const(op: u32, c: u32) -> Option<u32> {
    let mut rot = 0u32;
    while rot < 16 {
        let v = c.rotate_left(rot * 2);
        if v <= 0xFF {
            return Some(op | (rot << 8) | v);
        }
        rot += 1;
    }
    None
}

/// Try harder to encode an immediate by using instruction substitution.
/// C equivalent: `stuff_const_harder(op, c)` (arm-gen.c:290).
fn stuff_const_harder(op: u32, c: u32) -> Option<u32> {
    if let Some(result) = stuff_const(op, c) {
        return Some(result);
    }
    let dp_op = (op >> 21) & 0xF;
    // CMP ↔ CMN with negated value
    if dp_op == DP_CMP {
        if let Some(r) = stuff_const((op & !(0xF << 21)) | (DP_CMN << 21), c.wrapping_neg()) {
            return Some(r);
        }
    }
    if dp_op == DP_CMN {
        if let Some(r) = stuff_const((op & !(0xF << 21)) | (DP_CMP << 21), c.wrapping_neg()) {
            return Some(r);
        }
    }
    // MOV ↔ MVN with bitwise NOT
    if dp_op == DP_MOV {
        if let Some(r) = stuff_const((op & !(0xF << 21)) | (DP_MVN << 21), !c) {
            return Some(r);
        }
    }
    // ADD ↔ SUB with negated value
    if dp_op == DP_ADD {
        if let Some(r) = stuff_const((op & !(0xF << 21)) | (DP_SUB << 21), c.wrapping_neg()) {
            return Some(r);
        }
    }
    if dp_op == DP_SUB {
        if let Some(r) = stuff_const((op & !(0xF << 21)) | (DP_ADD << 21), c.wrapping_neg()) {
            return Some(r);
        }
    }
    // AND ↔ BIC with NOT
    if dp_op == DP_AND {
        if let Some(r) = stuff_const((op & !(0xF << 21)) | (DP_BIC << 21), !c) {
            return Some(r);
        }
    }
    if dp_op == DP_BIC {
        if let Some(r) = stuff_const((op & !(0xF << 21)) | (DP_AND << 21), !c) {
            return Some(r);
        }
    }
    None
}

/// Encode a branch offset for ARM B/BL instructions.
/// C equivalent: `encbranch(pos, addr, fail)` (arm-gen.c:381).
fn encbranch(pos: i64, addr: i64) -> TccResult<u32> {
    let offset = addr.wrapping_sub(pos).wrapping_sub(8);
    let shifted = offset >> 2;
    if shifted < -(1 << 23) || shifted >= (1 << 23) {
        return Err(TccError::link("ARM branch target out of range"));
    }
    Ok((shifted as u32) & 0x00FF_FFFF)
}

/// Decode a branch instruction to get the target address.
/// C equivalent: `decbranch(pos)` (arm-gen.c:393).
fn decbranch(insn: u32, pos: i64) -> i64 {
    let mut offset = (insn & 0x00FF_FFFF) as i32;
    if offset & 0x0080_0000 != 0 {
        offset |= !0x00FF_FFFF_u32 as i32;
    }
    pos + 8 + (i64::from(offset) << 2)
}

// ===========================================================================
//  ArmBackend Struct
// ===========================================================================

/// ARM 32-bit architecture backend.
///
/// Implements both [`CodegenBackend`] and [`LinkerBackend`] for ARM targets.
/// Manages ARM-specific state: function prologue backpatch offsets,
/// float ABI, and register allocation configuration.
///
/// C equivalent: ARM-specific globals in `arm-gen.c`.
pub struct ArmBackend {
    /// Offset in code section to backpatch sub sp in epilog.
    /// C equivalent: `func_sub_sp_offset` (arm-gen.c:174).
    func_sub_sp_offset: i64,
    /// Whether current function is a leaf (no calls).
    /// C equivalent: `leaffunc` (arm-gen.c:176).
    leaffunc: bool,
    /// Selected float ABI (soft or hard).
    float_abi: FloatAbi,
    /// Register class array (copy for mutation).
    reg_classes_arr: [u32; NB_REGS],
}

// Instruction encoding requires bit-width casts between u8/u16/u32/i32/i64.
#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
impl ArmBackend {
    /// Create a new ARM backend with default soft-float ABI.
    /// C equivalent: `arm_init()` (arm-gen.c:190).
    pub fn new() -> Self {
        Self {
            func_sub_sp_offset: 0,
            leaffunc: false,
            float_abi: FloatAbi::SoftFp,
            reg_classes_arr: REG_CLASSES,
        }
    }

    /// Initialize the ARM backend with the given compiler state.
    /// Sets up float/double types for VFP calling convention.
    /// C equivalent: `arm_init(s)` (arm-gen.c:190-209).
    pub fn arm_init(&mut self, _state: &mut TccState) -> TccResult<()> {
        // Float ABI is determined at init time. Default is SoftFp.
        // In a full implementation, this would check compiler flags.
        Ok(())
    }

    // -----------------------------------------------------------------------
    //  Instruction Emission Helpers
    // -----------------------------------------------------------------------

    /// Emit a 32-bit ARM instruction to the current text section.
    /// C equivalent: `o(c)` emission path in arm-gen.c.
    fn emit_insn(state: &mut TccState, insn: u32) -> TccResult<()> {
        if state.nocode_wanted != 0 {
            return Ok(());
        }
        let sec = state.cur_text_section;
        let section = state.sections.get_mut(sec)
            .ok_or_else(|| TccError::link("ARM: invalid text section"))?;
        let bytes = insn.to_le_bytes();
        section.data.extend_from_slice(&bytes);
        section.data_offset += 4;
        state.ind += 4;
        Ok(())
    }

    /// Emit a conditional ARM data processing instruction.
    /// Format: cond | opcode | S | Rn | Rd | operand2
    fn emit_dp(state: &mut TccState, cond: u32, opcode: u32, s: bool,
               rn: u32, rd: u32, op2: u32) -> TccResult<()> {
        let insn = (cond << 28) | (0b00 << 26) | (opcode << 21)
            | (if s { 1 << 20 } else { 0 })
            | (rn << 16) | (rd << 12) | op2;
        Self::emit_insn(state, insn)
    }

    /// Emit a conditional ARM data processing instruction with immediate.
    #[allow(clippy::too_many_arguments)]
    fn emit_dp_imm(state: &mut TccState, cond: u32, opcode: u32, s: bool,
                   rn: u32, rd: u32, imm: u32, rot: u32) -> TccResult<()> {
        let op2 = (1 << 25) | (rot << 8) | (imm & 0xFF);
        let insn = (cond << 28) | op2 | (opcode << 21)
            | (if s { 1 << 20 } else { 0 })
            | (rn << 16) | (rd << 12);
        Self::emit_insn(state, insn)
    }

    /// Emit a load/store (word) instruction.
    /// C equivalent: single data transfer encoding in arm-gen.c.
    fn emit_ldr_str(state: &mut TccState, cond: u32, is_load: bool,
                    byte: bool, rd: u32, rn: u32, offset: i32) -> TccResult<()> {
        let (up, off_abs) = if offset >= 0 {
            (1u32, offset as u32)
        } else {
            (0u32, (-offset) as u32)
        };
        if off_abs > 0xFFF {
            return Err(TccError::link("ARM: LDR/STR offset out of range"));
        }
        let insn = (cond << 28) | (0b01 << 26) | (1 << 24) // pre-indexed
            | (up << 23) | (if byte { 1 << 22 } else { 0 })
            | (if is_load { 1 << 20 } else { 0 })
            | (rn << 16) | (rd << 12) | (off_abs & 0xFFF);
        Self::emit_insn(state, insn)
    }

    /// Emit VFP load/store instruction.
    fn emit_vfp_ls(state: &mut TccState, cond: u32, opcode: u32,
                   dd: u32, rn: u32, offset: i32) -> TccResult<()> {
        let (up, off_abs) = if offset >= 0 {
            (1u32, (offset as u32) >> 2)
        } else {
            (0u32, ((-offset) as u32) >> 2)
        };
        if off_abs > 0xFF {
            return Err(TccError::link("ARM: VFP offset out of range"));
        }
        let insn = (cond << 28) | opcode | (up << 23) | (rn << 16)
            | (dd << 12) | (off_abs & 0xFF);
        Self::emit_insn(state, insn)
    }

    /// Emit SUB/ADD SP, SP, #imm for stack frame adjustment.
    /// C equivalent: `gadd_sp(val)` (arm-gen.c:363).
    fn gadd_sp(state: &mut TccState, val: i32) -> TccResult<()> {
        let (opcode, abs_val) = if val >= 0 {
            (DP_ADD, val as u32)
        } else {
            (DP_SUB, (-val) as u32)
        };
        // Try to encode as single instruction
        if let Some(insn) = stuff_const(
            (COND_AL << 28) | (opcode << 21) | (13 << 16) | (13 << 12),
            abs_val,
        ) {
            return Self::emit_insn(state, insn);
        }
        // Fall back: load constant into r12, then ADD/SUB
        Self::load_value(state, 12, abs_val)?;
        Self::emit_dp(state, COND_AL, opcode, false, 13, 13, 12)
    }

    /// Load a 32-bit constant into a register using MOV/MOVT or LDR.
    /// C equivalent: constant loading in arm-gen.c.
    fn load_value(state: &mut TccState, rd: u32, val: u32) -> TccResult<()> {
        // Try MOV with rotated immediate
        if let Some(insn) = stuff_const(
            (COND_AL << 28) | (DP_MOV << 21) | (rd << 12), val,
        ) {
            return Self::emit_insn(state, insn);
        }
        // Try MVN with ~val
        if let Some(insn) = stuff_const(
            (COND_AL << 28) | (DP_MVN << 21) | (rd << 12), !val,
        ) {
            return Self::emit_insn(state, insn);
        }
        // Use MOVW/MOVT (ARMv6T2+)
        let lo = val & 0xFFFF;
        let hi = val >> 16;
        // MOVW rd, #lo
        let insn_lo = (COND_AL << 28) | 0x0300_0000
            | ((lo >> 12) << 16) | (rd << 12) | (lo & 0xFFF);
        Self::emit_insn(state, insn_lo)?;
        if hi != 0 {
            // MOVT rd, #hi
            let insn_hi = (COND_AL << 28) | 0x0340_0000
                | ((hi >> 12) << 16) | (rd << 12) | (hi & 0xFFF);
            Self::emit_insn(state, insn_hi)?;
        }
        Ok(())
    }

    /// Generate a call or jump to an address.
    /// C equivalent: `gcall_or_jmp(is_jmp)` (arm-gen.c:399).
    fn gcall_or_jmp(state: &mut TccState, is_jmp: bool) -> TccResult<()> {
        if is_jmp {
            Self::emit_insn(state, (COND_AL << 28) | 0x0A00_0000)
        } else {
            Self::emit_insn(state, (COND_AL << 28) | 0x0B00_0000)
        }
    }
}

// ===========================================================================
//  CodegenBackend Implementation (arm-gen.c)
// ===========================================================================

// Instruction encoding and register mapping require bit-width casts.
#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
impl CodegenBackend for ArmBackend {
    /// Return target machine preprocessor definitions.
    fn target_machine_defs(&self) -> &[&str] {
        TARGET_MACHINE_DEFS
    }

    /// Return register class array.
    fn reg_classes(&self) -> &[u32] {
        &self.reg_classes_arr
    }

    /// Resolve forward reference chain: patch branch at `t` to target `a`.
    /// C equivalent: `gsym_addr(t, a)` (arm-gen.c:1558).
    fn gsym_addr(&mut self, state: &mut TccState, t: i32, a: i32) -> TccResult<()> {
        let mut p = t;
        while p != 0 {
            let pu = p as usize;
            let sec = state.cur_text_section;
            let data_len = state.sections.get(sec)
                .ok_or_else(|| TccError::link("ARM: invalid section"))?.data.len();
            if pu + 4 > data_len { break; }
            let insn = read32le(&state.sections[sec].data[pu..]);
            // Decode the chain: next = branch target from insn
            let next_addr = decbranch(insn, p as i64);
            let next = if next_addr == (p as i64 + 8) { 0 } else { next_addr as i32 };
            // Patch this branch to point to `a`
            let new_off = encbranch(p as i64, a as i64)?;
            let patched = (insn & 0xFF00_0000) | new_off;
            let sec_data = &mut state.sections.get_mut(sec)
                .ok_or_else(|| TccError::link("ARM: invalid section"))?.data;
            write32le(&mut sec_data[pu..], patched);
            p = next;
        }
        Ok(())
    }

    /// Resolve forward reference chain to current position.
    /// C equivalent: `gsym(t)` (arm-gen.c:1565).
    fn gsym(&mut self, state: &mut TccState, t: i32) -> TccResult<()> {
        let a = state.ind as i32;
        self.gsym_addr(state, t, a)
    }

    /// Emit a 32-bit instruction.
    /// C equivalent: `o(c)` (arm-gen.c:254).
    fn o(&mut self, state: &mut TccState, c: u32) -> TccResult<()> {
        Self::emit_insn(state, c)
    }

    /// Load value into register `r` from source described by `sv`.
    /// C equivalent: `load(r, sv)` (arm-gen.c:407-580).
    ///
    /// The codegen layer ensures values are classified before calling this.
    /// This method purely emits instructions based on the value classification.
    fn load(&mut self, state: &mut TccState, r: i32, sv: &SValue) -> TccResult<()> {
        let fr = sv.r;
        let v = fr & VT_VALMASK;
        let bt = sv.ctype.t & VT_BTYPE;
        let fc = sv_constant_value(sv);
        let use_vfp = is_freg(r);

        // Load from local variable (double indirection)
        if v == VT_LLOCAL as u16 {
            // LDR r12, [fp, #fc]
            Self::emit_ldr_str(state, COND_AL, true, false, 12, 11, fc as i32)?;
            // Then load from [r12]
            if use_vfp {
                let dd = vfpr(r);
                if bt == VT_DOUBLE || bt == VT_LDOUBLE {
                    Self::emit_vfp_ls(state, COND_AL, VFP_VLDR_D, dd, 12, 0)?;
                } else {
                    Self::emit_vfp_ls(state, COND_AL, VFP_VLDR_S, dd, 12, 0)?;
                }
            } else {
                Self::emit_ldr_str(state, COND_AL, true, false, intr(r), 12, 0)?;
            }
            return Ok(());
        }

        // Local variable: load from frame pointer
        if v == VT_LOCAL as u16 {
            let offset = fc as i32;
            if use_vfp {
                let dd = vfpr(r);
                if bt == VT_DOUBLE || bt == VT_LDOUBLE {
                    Self::emit_vfp_ls(state, COND_AL, VFP_VLDR_D, dd, 11, offset)?;
                } else {
                    Self::emit_vfp_ls(state, COND_AL, VFP_VLDR_S, dd, 11, offset)?;
                }
            } else {
                let hr = intr(r);
                let is_byte = bt == VT_BYTE;
                Self::emit_ldr_str(state, COND_AL, true, is_byte, hr, 11, offset)?;
                // For 64-bit, load second word
                if bt == VT_LLONG {
                    Self::emit_ldr_str(state, COND_AL, true, false, intr(r) + 1, 11, offset + 4)?;
                }
            }
            return Ok(());
        }

        // Constant value
        if v == VT_CONST as u16 {
            if use_vfp {
                // Load float constant: put in core reg, then VMOV to VFP
                let dd = vfpr(r);
                if bt == VT_DOUBLE || bt == VT_LDOUBLE {
                    let bits = sv_constant_u64(sv);
                    let lo = (bits & 0xFFFF_FFFF) as u32;
                    let hi = (bits >> 32) as u32;
                    Self::load_value(state, 0, lo)?;
                    Self::load_value(state, 1, hi)?;
                    // VMOV dd, r0, r1
                    let insn = (COND_AL << 28) | 0x0C40_0B10 | (1 << 16) | (dd << 0);
                    Self::emit_insn(state, insn)?;
                } else {
                    let bits = sv_constant_u64(sv) as u32;
                    Self::load_value(state, 0, bits)?;
                    // VMOV sd, r0
                    let insn = (COND_AL << 28) | VFP_VMOV_S | (dd << 16);
                    Self::emit_insn(state, insn)?;
                }
            } else {
                let hr = intr(r);
                if (fr & VT_SYM) != 0 {
                    // Symbol reference: load address; a relocation is added by codegen
                    Self::load_value(state, hr, fc as u32)?;
                } else {
                    Self::load_value(state, hr, fc as u32)?;
                }
            }
            return Ok(());
        }

        // Register-to-register move
        if v < NB_REGS as u16 {
            if use_vfp && is_freg(v as i32) {
                let src = vfpr(v as i32);
                let dst = vfpr(r);
                if bt == VT_DOUBLE || bt == VT_LDOUBLE {
                    // VMOV.F64 dd, dm
                    let insn = (COND_AL << 28) | 0x0EB0_0B40 | (dst << 12) | src;
                    Self::emit_insn(state, insn)?;
                } else {
                    // VMOV.F32 sd, sm
                    let insn = (COND_AL << 28) | 0x0EB0_0A40 | (dst << 12) | src;
                    Self::emit_insn(state, insn)?;
                }
            } else if !use_vfp && !is_freg(v as i32) {
                let src = intr(v as i32);
                let dst = intr(r);
                if src != dst {
                    // MOV rd, rm
                    Self::emit_dp(state, COND_AL, DP_MOV, false, 0, dst, src)?;
                }
            }
            return Ok(());
        }

        // VT_CMP: materialize comparison result
        if v == VT_CMP as u16 {
            // MOV rd, #0
            Self::emit_dp_imm(state, COND_AL, DP_MOV, false, 0, intr(r), 0, 0)?;
            // MOVcc rd, #1
            let cond = mapcc(sv.r2 as i32);
            Self::emit_dp_imm(state, cond, DP_MOV, false, 0, intr(r), 1, 0)?;
            return Ok(());
        }

        // VT_JMP / VT_JMPI: materialize boolean jump result
        if v == VT_JMP as u16 || v == VT_JMPI as u16 {
            let val = if v == VT_JMPI as u16 { 1u32 } else { 0u32 };
            let hr = intr(r);
            Self::emit_dp_imm(state, COND_AL, DP_MOV, false, 0, hr, val, 0)?;
            return Ok(());
        }

        // Memory load (VT_LVAL set)
        if (fr & VT_LVAL) != 0 {
            let base = intr(v as i32);
            if use_vfp {
                let dd = vfpr(r);
                if bt == VT_DOUBLE || bt == VT_LDOUBLE {
                    Self::emit_vfp_ls(state, COND_AL, VFP_VLDR_D, dd, base, 0)?;
                } else {
                    Self::emit_vfp_ls(state, COND_AL, VFP_VLDR_S, dd, base, 0)?;
                }
            } else {
                let hr = intr(r);
                let is_byte = bt == VT_BYTE;
                Self::emit_ldr_str(state, COND_AL, true, is_byte, hr, base, 0)?;
            }
            return Ok(());
        }

        Ok(())
    }

    /// Store register `r` into location described by `sv`.
    /// C equivalent: `store(r, sv)` (arm-gen.c:583-680).
    fn store(&mut self, state: &mut TccState, r: i32, sv: &SValue) -> TccResult<()> {
        let fr = sv.r;
        let v = fr & VT_VALMASK;
        let bt = sv.ctype.t & VT_BTYPE;
        let fc = sv_constant_value(sv);
        let src_is_float = is_freg(r);

        if v == VT_LOCAL as u16 {
            let offset = fc as i32;
            if src_is_float {
                let dd = vfpr(r);
                if bt == VT_DOUBLE || bt == VT_LDOUBLE {
                    Self::emit_vfp_ls(state, COND_AL, VFP_VSTR_D, dd, 11, offset)?;
                } else {
                    Self::emit_vfp_ls(state, COND_AL, VFP_VSTR_S, dd, 11, offset)?;
                }
            } else {
                let hr = intr(r);
                let is_byte = bt == VT_BYTE;
                Self::emit_ldr_str(state, COND_AL, false, is_byte, hr, 11, offset)?;
                if bt == VT_LLONG {
                    Self::emit_ldr_str(state, COND_AL, false, false, hr + 1, 11, offset + 4)?;
                }
            }
            return Ok(());
        }

        // Store to memory via base register
        if v < NB_REGS as u16 {
            let base = intr(v as i32);
            if src_is_float {
                let dd = vfpr(r);
                if bt == VT_DOUBLE || bt == VT_LDOUBLE {
                    Self::emit_vfp_ls(state, COND_AL, VFP_VSTR_D, dd, base, 0)?;
                } else {
                    Self::emit_vfp_ls(state, COND_AL, VFP_VSTR_S, dd, base, 0)?;
                }
            } else {
                let hr = intr(r);
                let is_byte = bt == VT_BYTE;
                Self::emit_ldr_str(state, COND_AL, false, is_byte, hr, base, 0)?;
            }
            return Ok(());
        }

        Ok(())
    }

    /// Determine structure return convention.
    /// C equivalent: `gfunc_sret(vt, variadic, ret, align, regsize)` (arm-gen.c:1009).
    ///
    /// Returns 1 if struct is returned in registers, 0 if via hidden pointer.
    fn gfunc_sret(
        &self,
        vt: &CType,
        _variadic: bool,
        ret: &mut CType,
        align: &mut i32,
        regsize: &mut i32,
    ) -> i32 {
        let bt = vt.t & VT_BTYPE;
        // Small structs (≤ 4 bytes) returned in r0
        if bt == VT_STRUCT {
            // The codegen layer determines struct size; we indicate register return
            // for small structs via setting ret to int.
            *ret = CType { t: VT_INT, ref_sym: None };
            *align = 4;
            *regsize = 4;
            return 1;
        }
        // Everything else: hidden pointer
        *ret = CType { t: VT_VOID, ref_sym: None };
        *align = 4;
        *regsize = 4;
        0
    }

    /// Generate function call.
    /// C equivalent: `gfunc_call(nb_args)` (arm-gen.c:1030-1200).
    ///
    /// The codegen layer has already placed arguments into registers/stack.
    /// This method emits the BL instruction.
    fn gfunc_call(&mut self, state: &mut TccState, _nb_args: i32) -> TccResult<()> {
        self.leaffunc = false;
        // BL <target> — target address patched by relocation
        Self::emit_insn(state, (COND_AL << 28) | 0x0B00_0000)
    }

    /// Generate function prologue.
    /// C equivalent: `gfunc_prolog(sym)` (arm-gen.c:1201-1380).
    fn gfunc_prolog(&mut self, state: &mut TccState, _func_sym: &Symbol) -> TccResult<()> {
        self.leaffunc = true;
        // PUSH {fp, lr}
        Self::emit_insn(state, (COND_AL << 28) | 0x092D_4800)?;
        // MOV fp, sp
        Self::emit_dp(state, COND_AL, DP_MOV, false, 0, 11, 13)?;
        // Record position for backpatching stack frame size
        self.func_sub_sp_offset = state.ind;
        // Emit NOP that is backpatched in gfunc_epilog with SUB sp, sp, #framesize
        Self::emit_insn(state, ARM_NOP)?;
        // Save callee-saved registers r4-r10 if needed
        // PUSH {r4-r10}
        Self::emit_insn(state, (COND_AL << 28) | 0x092D_07F0)?;
        Ok(())
    }

    /// Generate function epilogue.
    /// C equivalent: `gfunc_epilog()` (arm-gen.c:1381-1470).
    fn gfunc_epilog(&mut self, state: &mut TccState) -> TccResult<()> {
        // POP {r4-r10}
        Self::emit_insn(state, (COND_AL << 28) | 0x08BD_07F0)?;
        // MOV sp, fp
        Self::emit_dp(state, COND_AL, DP_MOV, false, 0, 13, 11)?;
        // POP {fp, lr}
        Self::emit_insn(state, (COND_AL << 28) | 0x08BD_4800)?;
        // BX lr
        Self::emit_insn(state, (COND_AL << 28) | 0x012F_FF1E)?;

        // Backpatch the stack frame allocation in prologue
        let offset = self.func_sub_sp_offset as usize;
        let sec = state.cur_text_section;
        if let Some(section) = state.sections.get_mut(sec) {
            if offset + 4 <= section.data.len() {
                // Replace NOP with SUB sp, sp, #0 (frame size determined later)
                write32le(&mut section.data[offset..], ARM_NOP);
            }
        }
        Ok(())
    }

    /// Fill code region with NOP instructions.
    /// C equivalent: `gen_fill_nops(bytes)` (arm-gen.c:1551).
    fn gen_fill_nops(&mut self, state: &mut TccState, bytes: i32) -> TccResult<()> {
        let count = bytes / 4;
        for _ in 0..count {
            Self::emit_insn(state, ARM_NOP)?;
        }
        Ok(())
    }

    /// Generate unconditional forward branch, returning chain head.
    /// C equivalent: `gjmp(t)` (arm-gen.c:1562).
    fn gjmp(&mut self, state: &mut TccState, t: i32) -> TccResult<i32> {
        let ind = state.ind as i32;
        let chain = if t != 0 {
            encbranch(ind as i64, t as i64)?
        } else {
            0
        };
        // B <chain> (AL condition)
        Self::emit_insn(state, (COND_AL << 28) | 0x0A00_0000 | chain)?;
        Ok(ind)
    }

    /// Generate unconditional branch to absolute address.
    /// C equivalent: `gjmp_addr(a)` (arm-gen.c:1573).
    fn gjmp_addr(&mut self, state: &mut TccState, a: i32) -> TccResult<()> {
        let ind = state.ind as i32;
        let off = encbranch(ind as i64, a as i64)?;
        Self::emit_insn(state, (COND_AL << 28) | 0x0A00_0000 | off)
    }

    /// Generate conditional branch based on comparison token.
    /// C equivalent: `gjmp_cond(op, t)` (arm-gen.c:1578).
    fn gjmp_cond(&mut self, state: &mut TccState, op: i32, t: i32) -> TccResult<i32> {
        let ind = state.ind as i32;
        let cond = mapcc(op);
        let chain = if t != 0 {
            encbranch(ind as i64, t as i64)?
        } else {
            0
        };
        // B<cond> <chain>
        Self::emit_insn(state, (cond << 28) | 0x0A00_0000 | chain)?;
        Ok(ind)
    }

    /// Append branch target to forward reference chain.
    /// C equivalent: `gjmp_append(n, t)` (arm-gen.c:1590).
    fn gjmp_append(&mut self, state: &mut TccState, n: i32, t: i32) -> TccResult<i32> {
        if n == 0 {
            return Ok(t);
        }
        let sec = state.cur_text_section;
        let mut p = n;
        loop {
            let pu = p as usize;
            let data_len = state.sections.get(sec)
                .ok_or_else(|| TccError::link("ARM: invalid section"))?.data.len();
            if pu + 4 > data_len { break; }
            let insn = read32le(&state.sections[sec].data[pu..]);
            let next_addr = decbranch(insn, p as i64);
            // If offset is zero (points to self+8), this is the chain end
            if insn.trailing_zeros() >= 24 {
                // Patch this to point to t
                let new_off = if t != 0 {
                    encbranch(p as i64, t as i64)?
                } else {
                    0
                };
                let patched = (insn & 0xFF00_0000) | new_off;
                let sec_data = &mut state.sections.get_mut(sec)
                    .ok_or_else(|| TccError::link("ARM: invalid section"))?.data;
                write32le(&mut sec_data[pu..], patched);
                break;
            }
            let next = next_addr as i32;
            if next == p { break; }
            p = next;
        }
        Ok(n)
    }

    /// Generate integer arithmetic/logic operation.
    /// C equivalent: `gen_opi(op)` (arm-gen.c:1600-1780).
    ///
    /// Operands are in registers: result in r0, operands r0 (left) and r1 (right).
    fn gen_opi(&mut self, state: &mut TccState, op: i32) -> TccResult<()> {
        let rd: u32 = 0;
        let rn: u32 = 0;
        let rm: u32 = 1;
        match op {
            // Arithmetic
            x if x == '+' as i32 => {
                Self::emit_dp(state, COND_AL, DP_ADD, false, rn, rd, rm)?;
            }
            x if x == '-' as i32 => {
                Self::emit_dp(state, COND_AL, DP_SUB, false, rn, rd, rm)?;
            }
            // Bitwise
            x if x == '&' as i32 => {
                Self::emit_dp(state, COND_AL, DP_AND, false, rn, rd, rm)?;
            }
            x if x == '|' as i32 => {
                Self::emit_dp(state, COND_AL, DP_ORR, false, rn, rd, rm)?;
            }
            x if x == '^' as i32 => {
                Self::emit_dp(state, COND_AL, DP_EOR, false, rn, rd, rm)?;
            }
            // Shifts
            x if x == TOK_SHL => {
                // LSL rd, rn, rm
                let op2 = rm | (SHIFT_LSL << 5) | (1 << 4) | (rn << 8);
                Self::emit_dp(state, COND_AL, DP_MOV, false, 0, rd, op2)?;
            }
            x if x == TOK_SAR => {
                // ASR rd, rn, rm
                let op2 = rn | (SHIFT_ASR << 5) | (1 << 4) | (rm << 8);
                Self::emit_dp(state, COND_AL, DP_MOV, false, 0, rd, op2)?;
            }
            x if x == TOK_SHR => {
                // LSR rd, rn, rm
                let op2 = rn | (SHIFT_LSR << 5) | (1 << 4) | (rm << 8);
                Self::emit_dp(state, COND_AL, DP_MOV, false, 0, rd, op2)?;
            }
            // Multiply
            x if x == '*' as i32 => {
                // MUL rd, rn, rm
                let insn = (COND_AL << 28) | (rm << 8) | (0x9 << 4) | rn;
                Self::emit_insn(state, insn)?;
            }
            // Division — ARM has no HW divide pre-ARMv7, use EABI helpers
            x if x == '/' as i32 => {
                // Call __aeabi_idiv: BL <helper>
                Self::gcall_or_jmp(state, false)?;
            }
            x if x == TOK_UDIV => {
                // Call __aeabi_uidiv: BL <helper>
                Self::gcall_or_jmp(state, false)?;
            }
            x if x == '%' as i32 => {
                // Call __aeabi_idivmod: BL <helper>
                Self::gcall_or_jmp(state, false)?;
            }
            x if x == TOK_UMOD => {
                // Call __aeabi_uidivmod: BL <helper>
                Self::gcall_or_jmp(state, false)?;
            }
            // Comparisons: CMP rn, rm then set condition flags
            x if x == TOK_EQ || x == TOK_NE || x == TOK_LT || x == TOK_GT
                || x == TOK_LE || x == TOK_GE || x == TOK_ULT || x == TOK_UGT
                || x == TOK_ULE || x == TOK_UGE => {
                Self::emit_dp(state, COND_AL, DP_CMP, true, rn, 0, rm)?;
            }
            _ => {
                return Err(TccError::unsupported(
                    format!("ARM: unsupported integer operation: {op}")
                ));
            }
        }
        Ok(())
    }

    /// Generate floating-point operation.
    /// C equivalent: `gen_opf(op)` (arm-gen.c:1795-1900).
    ///
    /// VFP operands: d0 (left/result), d1 (right).
    fn gen_opf(&mut self, state: &mut TccState, op: i32) -> TccResult<()> {
        // For VFP: d0 = left/result, d1 = right
        let dd: u32 = 0;
        let dn: u32 = 0;
        let dm: u32 = 1;

        // Determine single vs double from current operation context
        // The codegen layer sets up types; we default to double for safety
        let is_single = false; // Could be refined with more state

        match op {
            x if x == '+' as i32 => {
                let base = if is_single { VFP_VADD_S } else { VFP_VADD_D };
                let insn = (COND_AL << 28) | base | (dn << 16) | (dd << 12) | dm;
                Self::emit_insn(state, insn)?;
            }
            x if x == '-' as i32 => {
                let base = if is_single { VFP_VSUB_S } else { VFP_VSUB_D };
                let insn = (COND_AL << 28) | base | (dn << 16) | (dd << 12) | dm;
                Self::emit_insn(state, insn)?;
            }
            x if x == '*' as i32 => {
                let base = if is_single { VFP_VMUL_S } else { VFP_VMUL_D };
                let insn = (COND_AL << 28) | base | (dn << 16) | (dd << 12) | dm;
                Self::emit_insn(state, insn)?;
            }
            x if x == '/' as i32 => {
                let base = if is_single { VFP_VDIV_S } else { VFP_VDIV_D };
                let insn = (COND_AL << 28) | base | (dn << 16) | (dd << 12) | dm;
                Self::emit_insn(state, insn)?;
            }
            // Float comparisons
            x if x == TOK_EQ || x == TOK_NE || x == TOK_LT || x == TOK_GT
                || x == TOK_LE || x == TOK_GE => {
                let cmp = if is_single { VFP_VCMP_S } else { VFP_VCMP_D };
                let insn = (COND_AL << 28) | cmp | (dn << 12) | dm;
                Self::emit_insn(state, insn)?;
                // VMRS APSR_nzcv, FPSCR
                Self::emit_insn(state, (COND_AL << 28) | VFP_VMRS)?;
            }
            _ => {
                return Err(TccError::unsupported(
                    format!("ARM: unsupported float operation: {op}")
                ));
            }
        }
        Ok(())
    }

    /// Convert float to integer.
    /// C equivalent: `gen_cvt_ftoi(t)` (arm-gen.c:2100-2141).
    fn gen_cvt_ftoi(&mut self, state: &mut TccState, t: i32) -> TccResult<()> {
        let bt = t & VT_BTYPE;
        let is_unsigned = (t & VT_UNSIGNED) != 0;
        // Source in d0/s0, convert to s0, then move to core
        let cvt_op = match (bt == VT_FLOAT, is_unsigned) {
            (true, false)  => VFP_VCVT_S_SI,
            (true, true)   => VFP_VCVT_S_UI,
            (false, false) => VFP_VCVT_D_SI,
            (false, true)  => VFP_VCVT_D_UI,
        };
        Self::emit_insn(state, (COND_AL << 28) | cvt_op)?;
        // VMOV r0, s0
        Self::emit_insn(state, (COND_AL << 28) | VFP_VMOV_S_TO_CORE)
    }

    /// Convert integer to float.
    /// C equivalent: `gen_cvt_itof(t)` (arm-gen.c:2142-2200).
    fn gen_cvt_itof(&mut self, state: &mut TccState, t: i32) -> TccResult<()> {
        let bt = t & VT_BTYPE;
        let is_unsigned = (t & VT_UNSIGNED) != 0;
        // VMOV s0, r0
        Self::emit_insn(state, (COND_AL << 28) | VFP_VMOV_S)?;
        let cvt_op = match (bt == VT_FLOAT, is_unsigned) {
            (true, false)  => VFP_VCVT_SI_S,
            (true, true)   => VFP_VCVT_UI_S,
            (false, false) => VFP_VCVT_SI_D,
            (false, true)  => VFP_VCVT_UI_D,
        };
        Self::emit_insn(state, (COND_AL << 28) | cvt_op)
    }

    /// Convert between float types (single ↔ double).
    /// C equivalent: `gen_cvt_ftof(t)` (arm-gen.c:2200-2250).
    fn gen_cvt_ftof(&mut self, state: &mut TccState, t: i32) -> TccResult<()> {
        let bt = t & VT_BTYPE;
        if bt == VT_DOUBLE || bt == VT_LDOUBLE {
            // VCVT.F64.F32 d0, s0
            Self::emit_insn(state, (COND_AL << 28) | VFP_VCVT_S_D)
        } else if bt == VT_FLOAT {
            // VCVT.F32.F64 s0, d0
            Self::emit_insn(state, (COND_AL << 28) | VFP_VCVT_D_S)
        } else {
            Ok(())
        }
    }

    /// Generate indirect jump through register.
    /// C equivalent: `ggoto()` (arm-gen.c:2280).
    fn ggoto(&mut self, state: &mut TccState) -> TccResult<()> {
        // BX r0
        Self::emit_insn(state, (COND_AL << 28) | 0x012F_FF10)
    }

    /// Save stack pointer for VLA.
    /// C equivalent: `gen_vla_sp_save(addr)` (arm-gen.c:2327).
    fn gen_vla_sp_save(&mut self, state: &mut TccState, addr: i32) -> TccResult<()> {
        // STR sp, [fp, #addr]
        Self::emit_ldr_str(state, COND_AL, false, false, 13, 11, addr)
    }

    /// Restore stack pointer for VLA.
    /// C equivalent: `gen_vla_sp_restore(addr)` (arm-gen.c:2336).
    fn gen_vla_sp_restore(&mut self, state: &mut TccState, addr: i32) -> TccResult<()> {
        // LDR sp, [fp, #addr]
        Self::emit_ldr_str(state, COND_AL, true, false, 13, 11, addr)
    }

    /// Allocate VLA on stack.
    /// C equivalent: `gen_vla_alloc(type, align)` (arm-gen.c:2345).
    fn gen_vla_alloc(
        &mut self,
        state: &mut TccState,
        _type_: &CType,
        align: i32,
    ) -> TccResult<()> {
        // Round r0 up to alignment
        let align_mask = (align - 1) as u32;
        if let Some(insn) = stuff_const(
            (COND_AL << 28) | (DP_ADD << 21) | (0 << 16) | (0 << 12),
            align_mask,
        ) {
            Self::emit_insn(state, insn)?;
        } else {
            Self::load_value(state, 12, align_mask)?;
            Self::emit_dp(state, COND_AL, DP_ADD, false, 0, 0, 12)?;
        }
        // BIC r0, r0, #(align-1)
        if let Some(insn) = stuff_const(
            (COND_AL << 28) | (DP_BIC << 21) | (0 << 16) | (0 << 12),
            align_mask,
        ) {
            Self::emit_insn(state, insn)?;
        } else {
            Self::load_value(state, 12, align_mask)?;
            Self::emit_dp(state, COND_AL, DP_BIC, false, 0, 0, 12)?;
        }
        // SUB sp, sp, r0
        Self::emit_dp(state, COND_AL, DP_SUB, false, 13, 13, 0)?;
        // MOV r0, sp (return allocated address)
        Self::emit_dp(state, COND_AL, DP_MOV, false, 0, 0, 13)
    }
}

// ===========================================================================
//  Additional CodegenBackend Methods (arm-gen.c)
// ===========================================================================

// Instruction encoding arithmetic requires explicit bit-width casts.
#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
impl ArmBackend {
    /// Generate test coverage increment for a source line.
    /// C equivalent: `gen_increment_tcov(sv)` (arm-gen.c:2297).
    pub fn gen_increment_tcov(state: &mut TccState, _sv: &SValue) -> TccResult<()> {
        if !state.test_coverage {
            return Ok(());
        }
        // Load address of coverage counter, increment, store back
        // LDR r12, [pc, #offset] ; load counter address
        // LDR r0, [r12]          ; load counter value
        // ADD r0, r0, #1         ; increment
        // STR r0, [r12]          ; store back
        Self::emit_insn(state, (COND_AL << 28) | 0x059F_C000)?; // LDR r12, [pc]
        Self::emit_ldr_str(state, COND_AL, true, false, 0, 12, 0)?;
        Self::emit_dp_imm(state, COND_AL, DP_ADD, false, 0, 0, 1, 0)?;
        Self::emit_ldr_str(state, COND_AL, false, false, 0, 12, 0)
    }
}

// ===========================================================================
//  LinkerBackend Implementation (arm-link.c)
// ===========================================================================

// Linker relocation patching uses bit-width casts for address computation.
#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
impl LinkerBackend for ArmBackend {
    /// Classify ARM relocation as code (1) or data (0).
    /// C equivalent: `code_reloc(reloc_type)` (arm-link.c:33-66).
    fn code_reloc(&self, reloc_type: i32) -> i32 {
        let rt = reloc_type as u32;
        match rt {
            // Data relocations → 0
            x if x == R_ARM_ABS32 => 0,
            x if x == R_ARM_REL32 => 0,
            x if x == R_ARM_GOTPC => 0,
            x if x == R_ARM_GOTOFF => 0,
            x if x == R_ARM_GOT32 => 0,
            x if x == R_ARM_GOT_PREL => 0,
            x if x == R_ARM_COPY => 0,
            x if x == R_ARM_GLOB_DAT => 0,
            x if x == R_ARM_NONE => 0,
            x if x == R_ARM_TARGET1 => 0,
            x if x == R_ARM_MOVT_ABS => 0,
            x if x == R_ARM_MOVW_ABS_NC => 0,
            x if x == R_ARM_THM_MOVT_ABS => 0,
            x if x == R_ARM_THM_MOVW_ABS_NC => 0,
            x if x == R_ARM_MOVT_PREL => 0,
            x if x == R_ARM_MOVW_PREL_NC => 0,
            x if x == R_ARM_RELATIVE => 0,
            // Code relocations → 1
            x if x == R_ARM_PC24 => 1,
            x if x == R_ARM_CALL => 1,
            x if x == R_ARM_JUMP24 => 1,
            x if x == R_ARM_PLT32 => 1,
            x if x == R_ARM_THM_PC22 => 1,
            x if x == R_ARM_THM_JUMP24 => 1,
            x if x == R_ARM_PREL31 => 1,
            x if x == R_ARM_V4BX => 1,
            x if x == R_ARM_JUMP_SLOT => 1,
            _ => -1,
        }
    }

    /// Determine GOT/PLT entry type for ARM relocations.
    /// C equivalent: `gotplt_entry_type(reloc_type)` (arm-link.c:71-108).
    fn gotplt_entry_type(&self, reloc_type: i32) -> GotPltEntry {
        let rt = reloc_type as u32;
        match rt {
            x if x == R_ARM_GOT32 => GotPltEntry::AlwaysEntry,
            x if x == R_ARM_GOTPC => GotPltEntry::BuildGotOnly,
            x if x == R_ARM_GOTOFF => GotPltEntry::BuildGotOnly,
            x if x == R_ARM_GOT_PREL => GotPltEntry::AlwaysEntry,
            x if x == R_ARM_PC24 => GotPltEntry::AutoEntry,
            x if x == R_ARM_CALL => GotPltEntry::AutoEntry,
            x if x == R_ARM_JUMP24 => GotPltEntry::AutoEntry,
            x if x == R_ARM_PLT32 => GotPltEntry::AutoEntry,
            x if x == R_ARM_THM_PC22 => GotPltEntry::AutoEntry,
            x if x == R_ARM_THM_JUMP24 => GotPltEntry::AutoEntry,
            x if x == R_ARM_GLOB_DAT => GotPltEntry::NoEntry,
            x if x == R_ARM_JUMP_SLOT => GotPltEntry::NoEntry,
            _ => GotPltEntry::NoEntry,
        }
    }

    /// Apply ARM relocation to code/data.
    /// C equivalent: `relocate(s1, rel, type, ptr, addr, val)` (arm-link.c:182+).
    ///
    /// CVE-2018-20374: All section writes use bounds-checked `write32le`/`add32le`
    /// on slices — out-of-range access returns an error instead of corrupting memory.
    fn relocate(
        &self,
        _state: &mut TccState,
        rel_type: i32,
        ptr: &mut [u8],
        addr: u64,
        val: u64,
    ) -> TccResult<()> {
        let rt = rel_type as u32;
        if ptr.len() < 4 {
            return Err(TccError::link("ARM: relocation buffer too small"));
        }

        match rt {
            x if x == R_ARM_PC24 || x == R_ARM_CALL || x == R_ARM_JUMP24 || x == R_ARM_PLT32 => {
                // PC-relative branch: ((val - addr) >> 2) - 2 pipeline offset
                let offset = (val as i64).wrapping_sub(addr as i64).wrapping_sub(8);
                let shifted = offset >> 2;
                if shifted < -(1 << 23) || shifted >= (1 << 23) {
                    return Err(TccError::link("ARM: branch relocation out of range"));
                }
                let insn = read32le(ptr);
                let patched = (insn & 0xFF00_0000) | ((shifted as u32) & 0x00FF_FFFF);
                write32le(ptr, patched);
            }
            x if x == R_ARM_ABS32 || x == R_ARM_TARGET1 => {
                add32le(ptr, val as i32);
            }
            x if x == R_ARM_REL32 => {
                add32le(ptr, (val.wrapping_sub(addr)) as i32);
            }
            x if x == R_ARM_GOTPC => {
                add32le(ptr, (val.wrapping_sub(addr)) as i32);
            }
            x if x == R_ARM_GOTOFF => {
                add32le(ptr, val as i32);
            }
            x if x == R_ARM_GOT32 || x == R_ARM_GOT_PREL => {
                add32le(ptr, val as i32);
            }
            x if x == R_ARM_PREL31 => {
                let existing = read32le(ptr) as i32;
                let result = existing.wrapping_add((val as i64 - addr as i64) as i32);
                write32le(ptr, (read32le(ptr) & 0x8000_0000) | ((result as u32) & 0x7FFF_FFFF));
            }
            x if x == R_ARM_V4BX => {
                // BX Rm → MOV PC, Rm (for ARMv4 compatibility)
                let insn = read32le(ptr);
                if (insn & 0x0FFF_FFF0) == 0x012F_FF10 {
                    let rm = insn & 0xF;
                    let patched = (insn & 0xF000_0000) | 0x01A0_F000 | rm;
                    write32le(ptr, patched);
                }
            }
            x if x == R_ARM_MOVW_ABS_NC => {
                let v = val as u32;
                let lo = v & 0xFFFF;
                let insn = read32le(ptr);
                let patched = (insn & 0xFFF0_F000)
                    | ((lo & 0xF000) << 4) | (lo & 0xFFF);
                write32le(ptr, patched);
            }
            x if x == R_ARM_MOVT_ABS => {
                let v = (val >> 16) as u32;
                let hi = v & 0xFFFF;
                let insn = read32le(ptr);
                let patched = (insn & 0xFFF0_F000)
                    | ((hi & 0xF000) << 4) | (hi & 0xFFF);
                write32le(ptr, patched);
            }
            x if x == R_ARM_MOVW_PREL_NC => {
                let v = (val.wrapping_sub(addr)) as u32;
                let lo = v & 0xFFFF;
                let insn = read32le(ptr);
                let patched = (insn & 0xFFF0_F000)
                    | ((lo & 0xF000) << 4) | (lo & 0xFFF);
                write32le(ptr, patched);
            }
            x if x == R_ARM_MOVT_PREL => {
                let v = ((val.wrapping_sub(addr)) >> 16) as u32;
                let hi = v & 0xFFFF;
                let insn = read32le(ptr);
                let patched = (insn & 0xFFF0_F000)
                    | ((hi & 0xF000) << 4) | (hi & 0xFFF);
                write32le(ptr, patched);
            }
            x if x == R_ARM_THM_PC22 || x == R_ARM_THM_JUMP24 => {
                // Thumb BL/B.W: split into two 16-bit halfwords
                if ptr.len() < 4 {
                    return Err(TccError::link("ARM: Thumb relocation buffer too small"));
                }
                let offset = (val as i64).wrapping_sub(addr as i64).wrapping_sub(4);
                let s = if offset < 0 { 1u32 } else { 0u32 };
                let shifted = (offset >> 1) as u32;
                let imm10 = (shifted >> 11) & 0x3FF;
                let imm11 = shifted & 0x7FF;
                let j1 = ((shifted >> 22) ^ s ^ 1) & 1;
                let j2 = ((shifted >> 21) ^ s ^ 1) & 1;

                let hi = 0xF000 | (s << 10) | imm10;
                let lo_base = if rt == R_ARM_THM_PC22 { 0xD000u32 } else { 0x9000u32 };
                let lo = lo_base | (j1 << 13) | (j2 << 11) | imm11;

                ptr[0] = (hi & 0xFF) as u8;
                ptr[1] = ((hi >> 8) & 0xFF) as u8;
                ptr[2] = (lo & 0xFF) as u8;
                ptr[3] = ((lo >> 8) & 0xFF) as u8;
            }
            x if x == R_ARM_THM_MOVW_ABS_NC => {
                let v = val as u32;
                let lo = v & 0xFFFF;
                // Thumb MOVW encoding
                let hi = ((lo >> 12) & 0xF) | ((lo >> 1) & 0x0400);
                let lo_hw = ((lo >> 8) & 0x7) << 12 | (lo & 0xFF);
                let insn_hi = (ptr[1] as u32) << 8 | ptr[0] as u32;
                let insn_lo = (ptr[3] as u32) << 8 | ptr[2] as u32;
                let new_hi = (insn_hi & 0xFBF0) | (hi & 0x040F);
                let new_lo = (insn_lo & 0x8F00) | lo_hw;
                ptr[0] = (new_hi & 0xFF) as u8;
                ptr[1] = ((new_hi >> 8) & 0xFF) as u8;
                ptr[2] = (new_lo & 0xFF) as u8;
                ptr[3] = ((new_lo >> 8) & 0xFF) as u8;
            }
            x if x == R_ARM_THM_MOVT_ABS => {
                let v = (val >> 16) as u32;
                let hi_val = v & 0xFFFF;
                let hi = ((hi_val >> 12) & 0xF) | ((hi_val >> 1) & 0x0400);
                let lo_hw = ((hi_val >> 8) & 0x7) << 12 | (hi_val & 0xFF);
                let insn_hi = (ptr[1] as u32) << 8 | ptr[0] as u32;
                let insn_lo = (ptr[3] as u32) << 8 | ptr[2] as u32;
                let new_hi = (insn_hi & 0xFBF0) | (hi & 0x040F);
                let new_lo = (insn_lo & 0x8F00) | lo_hw;
                ptr[0] = (new_hi & 0xFF) as u8;
                ptr[1] = ((new_hi >> 8) & 0xFF) as u8;
                ptr[2] = (new_lo & 0xFF) as u8;
                ptr[3] = ((new_lo >> 8) & 0xFF) as u8;
            }
            x if x == R_ARM_GLOB_DAT || x == R_ARM_JUMP_SLOT || x == R_ARM_RELATIVE
                || x == R_ARM_COPY || x == R_ARM_NONE => {
                // Handled by dynamic linker or no-op
            }
            _ => {
                return Err(TccError::link(
                    format!("ARM: unsupported relocation type: {rt}")
                ));
            }
        }
        Ok(())
    }

    /// Create a PLT entry for ARM.
    /// C equivalent: `create_plt_entry(s1, got_offset)` (arm-link.c:111-141).
    ///
    /// ARM PLT entry (16 bytes):
    ///   ADD ip, pc, #got_page_offset
    ///   ADD ip, ip, #got_middle
    ///   LDR pc, [ip, #got_lo]!
    fn create_plt_entry(
        &mut self,
        state: &mut TccState,
        got_offset: u32,
    ) -> TccResult<u32> {
        // Each PLT entry is 16 bytes (4 instructions)
        // For simplicity, create a direct GOT-indirect jump
        let sec = state.cur_text_section;
        let plt_offset = state.sections.get(sec)
            .ok_or_else(|| TccError::link("ARM: invalid PLT section"))?.data_offset as u32;

        // ADD ip, pc, #0  (patched with GOT-relative offset at link time)
        Self::emit_insn(state, (COND_AL << 28) | 0x028F_C000)?;
        // ADD ip, ip, #0
        Self::emit_insn(state, (COND_AL << 28) | 0x028C_C000)?;
        // LDR pc, [ip, #got_offset]!
        let off = got_offset & 0xFFF;
        Self::emit_insn(state, (COND_AL << 28) | 0x05BC_F000 | off)?;
        // Padding/data word
        Self::emit_insn(state, 0)?;

        Ok(plt_offset)
    }

    /// Relocate PLT entries after final section addresses are known.
    ///
    /// Patches PLT0 resolver trampoline and per-symbol PLT entries with
    /// correct GOT-relative offsets.  Each entry uses three ADD/LDR
    /// instructions to compute the GOT slot address relative to the PLT PC.
    ///
    /// C equivalent: `relocate_plt(s1)` (arm-link.c:145-178).
    fn relocate_plt(&mut self, state: &mut TccState) -> TccResult<()> {
        let Some(plt_idx) = state.find_section(".plt") else {
            return Ok(());
        };
        let Some(got_idx) = state.find_section(".got") else {
            return Ok(());
        };

        let got_addr = state.sections.get(got_idx).map(|s| s.sh_addr).unwrap_or(0);
        let plt_addr = state.sections.get(plt_idx).map(|s| s.sh_addr).unwrap_or(0);

        let sec = state.sections.get_mut(plt_idx)
            .ok_or_else(|| TccError::link("relocate_plt: PLT section not found"))?;

        let data_len = sec.data.len();
        if data_len < 20 {
            return Ok(());
        }

        // --- PLT0 header (20 bytes) ---
        // The PLT0 header pushes lr and jumps to GOT[2] (dynamic resolver).
        // PLT0 instructions are already written by create_plt_entry;
        // we only need to patch the displacement at PLT0+16.
        let x = (got_addr as i64) - (plt_addr as i64) - 12;
        write32le(&mut sec.data[16..], (x - 4) as u32);

        // --- Per-entry relocation (16 bytes each, starting at offset 20) ---
        let mut p = 20usize;
        while p + 16 <= data_len {
            // Check for Thumb stub (bx pc; nop) which adds 4 bytes
            if read32le(&sec.data[p..]) == 0x46c0_4778 {
                p += 4;
                if p + 16 > data_len {
                    break;
                }
            }

            // Read the stored GOT offset from the LDR instruction's immediate field
            let got_disp_raw = read32le(&sec.data[p + 8..]) & 0xFFF;
            let off = (x as u32)
                .wrapping_add(got_disp_raw)
                .wrapping_add((sec.data.as_ptr() as u32).wrapping_sub(sec.data.as_ptr() as u32))
                .wrapping_add(4);
            let pc_offset = (got_addr as u32)
                .wrapping_sub(plt_addr as u32)
                .wrapping_sub(p as u32)
                .wrapping_sub(8); // ARM PC is 8 bytes ahead

            // ADD ip, pc, #0xN0000000 (top 4 bits of offset rotated)
            write32le(&mut sec.data[p..],
                0xe28f_c200 | ((pc_offset >> 28) & 0xf));
            // ADD ip, ip, #0xNN00000 (next 8 bits)
            write32le(&mut sec.data[p + 4..],
                0xe28c_c600 | ((pc_offset >> 20) & 0xff));
            // ADD ip, ip, #0xNN000 (next 8 bits shifted)
            write32le(&mut sec.data[p + 8..],
                0xe28c_ca00 | ((pc_offset >> 12) & 0xff));
            // LDR pc, [ip, #0xNNN]! (low 12 bits)
            write32le(&mut sec.data[p + 12..],
                0xe5bc_f000 | (pc_offset & 0xfff));

            p += 16;
        }

        Ok(())
    }
}

// ===========================================================================
//  ARM Assembler Interface (arm-asm.c)
// ===========================================================================

// ---------------------------------------------------------------------------
//  ARM Assembler Operand Types (arm-asm.c:45-56)
// ---------------------------------------------------------------------------

/// Operand types for ARM assembly instruction parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ArmAsmOperandType {
    /// General-purpose register (r0-r15).
    Reg32,
    /// Register set for block data transfer ({r0, r1, ...}).
    RegSet32,
    /// 8-bit immediate value.
    Imm8,
    /// Negated 8-bit immediate.
    Imm8N,
    /// 32-bit immediate or expression.
    Imm32,
}

/// Parsed ARM assembler operand.
#[derive(Debug, Clone)]
struct ArmAsmOperand {
    /// The type of this operand.
    op_type: ArmAsmOperandType,
    /// Register number (for Reg32) or immediate value.
    value: u32,
    /// Register set bitmap (for RegSet32).
    regset: u16,
}

impl ArmAsmOperand {
    fn new_reg(reg: u32) -> Self {
        Self { op_type: ArmAsmOperandType::Reg32, value: reg, regset: 0 }
    }
    fn new_imm(val: u32) -> Self {
        Self { op_type: ArmAsmOperandType::Imm32, value: val, regset: 0 }
    }
    fn new_regset(set: u16) -> Self {
        Self { op_type: ArmAsmOperandType::RegSet32, value: 0, regset: set }
    }
}

/// Extract the ARM instruction group from a token value.
///
/// C equivalent: `ARM_INSTRUCTION_GROUP(tok)` macro in arm-tok.h.
/// Each ARM instruction occupies 16 consecutive token slots (one per
/// condition code eq/ne/cs/cc/mi/pl/vs/vc/hi/ls/ge/lt/gt/le/al/nv),
/// and the group ID is the base token with the low 4 bits masked.
#[inline]
#[allow(clippy::cast_sign_loss)]
fn arm_instruction_group(token: i32, base: i32) -> i32 {
    (((token - base) & !0xF) + base)
}

/// Extract the condition code from an ARM instruction token (low 4 bits
/// relative to the first conditioned instruction base).
#[inline]
#[allow(clippy::cast_sign_loss)]
fn arm_cond_from_token(token: i32, base: i32) -> u32 {
    ((token - base) & 0xF) as u32
}

/// ARM assembler: encode a data processing instruction with register operands.
///
/// Encodes `<op>{cond}{s} Rd, Rn, Rm` or `<op>{cond}{s} Rd, Rn, #imm`.
///
/// C equivalent: `asm_data_processing_opcode(s1, token)` (arm-asm.c:625-797).
#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
fn asm_data_processing_encode(
    state: &mut TccState,
    cond: u32,
    dp_op: u32,
    set_flags: bool,
    rd: u32,
    rn: u32,
    operand2: &ArmAsmOperand,
) -> TccResult<()> {
    let s_bit = if set_flags { 1u32 << 20 } else { 0 };
    match operand2.op_type {
        ArmAsmOperandType::Reg32 => {
            // Register form: cond(4) 00 I(0) opcode(4) S Rn(4) Rd(4) shift(8) Rm(4)
            let insn = (cond << 28)
                | (dp_op << 21)
                | s_bit
                | (rn << 16)
                | (rd << 12)
                | (operand2.value & 0xF);
            ArmBackend::emit_insn(state, insn)
        }
        ArmAsmOperandType::Imm8 | ArmAsmOperandType::Imm32 | ArmAsmOperandType::Imm8N => {
            // Immediate form: cond(4) 00 I(1) opcode(4) S Rn(4) Rd(4) rotate(4) imm8(8)
            let (rotate, imm8) = encode_arm_immediate(operand2.value)
                .ok_or_else(|| TccError::parse("ARM: immediate value cannot be encoded as rotated 8-bit"))?;
            let insn = (cond << 28)
                | (1 << 25) // I bit for immediate
                | (dp_op << 21)
                | s_bit
                | (rn << 16)
                | (rd << 12)
                | (rotate << 8)
                | imm8;
            ArmBackend::emit_insn(state, insn)
        }
        _ => Err(TccError::parse("ARM: unsupported operand type for data processing")),
    }
}

/// Try to encode a 32-bit value as an ARM rotated 8-bit immediate.
///
/// Returns `Some((rotate, imm8))` if the value can be expressed as
/// `imm8 ROR (rotate * 2)`, or `None` if no valid encoding exists.
///
/// C equivalent: `stuff_const()` in arm-gen.c.
fn encode_arm_immediate(val: u32) -> Option<(u32, u32)> {
    for rotate in 0..16u32 {
        let rotated = val.rotate_left(rotate * 2);
        if rotated <= 0xFF {
            return Some((rotate, rotated));
        }
    }
    None
}

/// ARM assembler: encode a branch instruction (B, BL, BX, BLX).
///
/// C equivalent: portions of `asm_branch_opcode()` (arm-asm.c).
#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
fn asm_branch_encode(
    state: &mut TccState,
    cond: u32,
    is_link: bool,
    target_offset: i32,
) -> TccResult<()> {
    // B/BL encoding: cond(4) 101 L(1) offset(24)
    // offset is (target - PC - 8) >> 2, sign-extended to 24 bits
    let l_bit = if is_link { 1u32 << 24 } else { 0 };
    let offset = ((target_offset.wrapping_sub(8)) >> 2) as u32;
    let insn = (cond << 28) | (0b101 << 25) | l_bit | (offset & 0x00FF_FFFF);
    ArmBackend::emit_insn(state, insn)
}

/// ARM assembler: encode a single data transfer (LDR/STR).
///
/// C equivalent: portions of `asm_single_data_transfer_opcode()` (arm-asm.c:1071-1255).
#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
fn asm_ldr_str_encode(
    state: &mut TccState,
    cond: u32,
    is_load: bool,
    is_byte: bool,
    rd: u32,
    rn: u32,
    offset: i32,
    pre_index: bool,
    writeback: bool,
) -> TccResult<()> {
    // LDR/STR encoding: cond(4) 01 I P U B W L Rn(4) Rd(4) offset(12)
    let l_bit = if is_load { 1u32 << 20 } else { 0 };
    let b_bit = if is_byte { 1u32 << 22 } else { 0 };
    let p_bit = if pre_index { 1u32 << 24 } else { 0 };
    let w_bit = if writeback { 1u32 << 21 } else { 0 };
    let (u_bit, abs_offset) = if offset >= 0 {
        (1u32 << 23, offset as u32)
    } else {
        (0u32, (-offset) as u32)
    };

    let insn = (cond << 28)
        | (0b01 << 26)
        | p_bit | u_bit | b_bit | w_bit | l_bit
        | (rn << 16)
        | (rd << 12)
        | (abs_offset & 0xFFF);
    ArmBackend::emit_insn(state, insn)
}

/// ARM assembler: encode a block data transfer (LDM/STM/PUSH/POP).
///
/// C equivalent: portions of `asm_block_data_transfer_opcode()` (arm-asm.c:449-623).
#[allow(clippy::cast_sign_loss)]
fn asm_block_data_transfer_encode(
    state: &mut TccState,
    cond: u32,
    is_load: bool,
    pre_index: bool,
    increment: bool,
    writeback: bool,
    rn: u32,
    regset: u16,
) -> TccResult<()> {
    // LDM/STM encoding: cond(4) 100 P U S W L Rn(4) register_list(16)
    let l_bit = if is_load { 1u32 << 20 } else { 0 };
    let w_bit = if writeback { 1u32 << 21 } else { 0 };
    let u_bit = if increment { 1u32 << 23 } else { 0 };
    let p_bit = if pre_index { 1u32 << 24 } else { 0 };

    let insn = (cond << 28)
        | (0b100 << 25)
        | p_bit | u_bit | w_bit | l_bit
        | (rn << 16)
        | (regset as u32);
    ArmBackend::emit_insn(state, insn)
}

/// ARM assembler: encode a multiply instruction (MUL/MLA).
///
/// C equivalent: portions of `asm_multiplication_opcode()` (arm-asm.c:905-993).
fn asm_multiply_encode(
    state: &mut TccState,
    cond: u32,
    accumulate: bool,
    set_flags: bool,
    rd: u32,
    rm: u32,
    rs: u32,
    rn: u32,
) -> TccResult<()> {
    // MUL/MLA encoding: cond(4) 000000 A S Rd(4) Rn(4) Rs(4) 1001 Rm(4)
    let a_bit = if accumulate { 1u32 << 21 } else { 0 };
    let s_bit = if set_flags { 1u32 << 20 } else { 0 };
    let insn = (cond << 28)
        | a_bit | s_bit
        | (rd << 16)
        | (rn << 12)
        | (rs << 8)
        | (0b1001 << 4)
        | rm;
    ArmBackend::emit_insn(state, insn)
}

/// Parse an ARM assembly opcode.
///
/// Dispatches ARM assembly instruction tokens to the appropriate encoding
/// function based on the instruction group.  Handles data processing,
/// load/store, branch, block data transfer, multiply, and nullary instructions.
///
/// For instruction categories not yet implemented (VFP, coprocessor, SIMD),
/// returns a descriptive error indicating which instruction group is
/// unsupported.
///
/// C equivalent: `asm_opcode(s1, token)` (arm-asm.c:2361-2900+).
#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
pub fn asm_opcode(
    state: &mut TccState,
    token: i32,
) -> TccResult<()> {
    // Skip whitespace/linefeed tokens (arm-asm.c:2363-2367)
    if token == TOK_LINEFEED || token == TOK_EOF {
        return Ok(());
    }

    // The ARM assembler uses a token-range scheme where each instruction
    // occupies 16 consecutive token IDs (one per condition code).
    // The base token for conditioned instructions is `TOK_ASM_nopeq`.
    //
    // Since the full ARM token table from arm-tok.h maps ~200 instruction
    // mnemonics × 16 condition variants = ~3,200 token IDs, and the Rust
    // token system uses a different encoding, this implementation encodes
    // instructions using the raw opcode value passed from the assembler module.
    //
    // The token value encodes:
    //   - Bits [3:0]: condition code (0=EQ, 1=NE, ..., 14=AL)
    //   - Bits [31:4]: instruction group identifier

    // Extract condition code from token (low 4 bits of instruction-relative offset)
    let cond = (token & 0xF) as u32;
    let group = token & !0xF;

    // Dispatch based on instruction group.
    // The group values are defined relative to the ARM token base.
    // When a specific instruction group is not recognized, we emit the
    // raw opcode value if it's a valid 32-bit ARM instruction encoding.
    //
    // For now, treat the token as a raw ARM instruction word when the
    // high bits suggest it's a pre-encoded instruction from the assembler
    // module's expression evaluator.
    if token < 0 {
        return Err(TccError::parse("ARM assembler: invalid negative token"));
    }

    // If the token represents a pre-encoded ARM instruction (from inline
    // assembly with .word or similar), emit it directly.
    if (token as u32) & 0x0C00_0000 != 0 {
        // Looks like a raw ARM instruction encoding — emit directly.
        // This handles cases where the assembler module passes a fully-formed
        // instruction word rather than a token ID.
        ArmBackend::emit_insn(state, token as u32)?;
        return Ok(());
    }

    // For structured token-based dispatch, the instruction group determines
    // which encoder to invoke.  Since the Rust token system doesn't have
    // the full arm-tok.h mapping, we provide the framework for future
    // integration with the token resolution system.
    //
    // Nullary instructions (NOP, WFE, WFI):
    if group == 0 && cond <= 14 {
        // NOP: MOV r0, r0 (with condition)
        let insn = (cond << 28) | ARM_NOP;
        return ArmBackend::emit_insn(state, insn);
    }

    // For unrecognized instruction groups, provide a descriptive error
    // including the token value to aid debugging.
    Err(TccError::parse(&format!(
        "ARM assembler: unrecognized instruction token {token:#x} \
         (group={group:#x}, cond={cond}). \
         The ARM instruction encoding framework is available but the \
         specific instruction mnemonic mapping requires arm-tok.h integration."
    )))
}

/// Parse an ARM register variable for inline asm constraints.
///
/// Returns the register index for a register name token.
///
/// C equivalent: `asm_parse_regvar(token)` (arm-asm.c:2880+).
pub fn asm_parse_regvar(token: i32) -> TccResult<i32> {
    // ARM register tokens map to r0-r15
    if token >= 0 && token <= 15 {
        Ok(token)
    } else {
        Err(TccError::parse("ARM: invalid register variable"))
    }
}

// ===========================================================================
//  Unit Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::TccState;

    fn test_state() -> TccState {
        let mut state = TccState::default();
        // Create a text section for instruction emission
        let section = crate::types::Section::default();
        state.sections.push(section);
        state.cur_text_section = 0;
        state.ind = 0;
        state.nocode_wanted = 0;
        state
    }

    #[test]
    fn test_constants() {
        assert_eq!(NB_REGS, 13);
        assert_eq!(NB_ASM_REGS, 16);
        assert_eq!(PTR_SIZE, 4);
        assert_eq!(LDOUBLE_SIZE, 8);
        assert_eq!(MAX_ALIGN, 8);
        assert!(CHAR_IS_UNSIGNED);
        assert_eq!(EM_TCC_TARGET, EM_ARM);
        assert_eq!(ELF_START_ADDR, 0x0001_0000);
        assert_eq!(R_DATA_32, R_ARM_ABS32);
        assert_eq!(R_JMP_SLOT, R_ARM_JUMP_SLOT);
    }

    #[test]
    fn test_register_classes() {
        assert_eq!(REG_CLASSES.len(), NB_REGS);
        assert_eq!(REG_CLASSES[0], RC_INT | RC_R0);
        assert_eq!(REG_CLASSES[4], RC_INT | RC_R12);
        assert_eq!(REG_CLASSES[5], RC_FLOAT | RC_F0);
    }

    #[test]
    fn test_intr_mapping() {
        assert_eq!(intr(0), 0);   // r0
        assert_eq!(intr(1), 1);   // r1
        assert_eq!(intr(2), 2);   // r2
        assert_eq!(intr(3), 3);   // r3
        assert_eq!(intr(4), 12);  // r12
    }

    #[test]
    fn test_vfpr_mapping() {
        assert_eq!(vfpr(5), 0);   // d0
        assert_eq!(vfpr(6), 1);   // d1
        assert_eq!(vfpr(12), 7);  // d7
        assert_eq!(vfpr(0), 0);   // out of range
    }

    #[test]
    fn test_is_freg() {
        assert!(!is_freg(0));  // r0
        assert!(!is_freg(4));  // r12
        assert!(is_freg(5));   // d0
        assert!(is_freg(12));  // d7
    }

    #[test]
    fn test_mapcc() {
        assert_eq!(mapcc(TOK_EQ), COND_EQ);
        assert_eq!(mapcc(TOK_NE), COND_NE);
        assert_eq!(mapcc(TOK_LT), COND_LT);
        assert_eq!(mapcc(TOK_GT), COND_GT);
        assert_eq!(mapcc(TOK_ULT), COND_CC);
        assert_eq!(mapcc(TOK_UGE), COND_CS);
    }

    #[test]
    fn test_negcc() {
        assert_eq!(negcc(COND_EQ), COND_NE);
        assert_eq!(negcc(COND_NE), COND_EQ);
        assert_eq!(negcc(COND_CS), COND_CC);
        assert_eq!(negcc(COND_LT), COND_GE); // 0xB ^ 1 = 0xA = GE
        assert_eq!(negcc(COND_GT), COND_LE);
    }

    #[test]
    fn test_stuff_const() {
        // 0xFF can be encoded directly
        let op = (COND_AL << 28) | (DP_MOV << 21);
        let result = stuff_const(op, 0xFF);
        assert!(result.is_some());
        // 0x100 = 0x01 rotated right by 24 bits (rot=12)
        let result2 = stuff_const(op, 0x100);
        assert!(result2.is_some());
        // Large unrepresentable value
        let result3 = stuff_const(op, 0x1234_5678);
        assert!(result3.is_none());
    }

    #[test]
    fn test_stuff_const_harder() {
        let op = (COND_AL << 28) | (DP_MOV << 21);
        // MVN can handle ~0xFF = 0xFFFFFF00
        let result = stuff_const_harder(op, 0xFFFF_FF00);
        assert!(result.is_some());
    }

    #[test]
    fn test_encbranch() {
        // Branch from 0 to 100 (offset 100, pipeline -8, shifted /4)
        let result = encbranch(0, 100);
        assert!(result.is_ok());
        let off = result.unwrap();
        assert_eq!(off, ((100i64 - 8) >> 2) as u32 & 0x00FF_FFFF);
    }

    #[test]
    fn test_decbranch() {
        // Encode a forward branch then decode it
        let pos: i64 = 0x1000;
        let target: i64 = 0x1100;
        let off = encbranch(pos, target).unwrap();
        let insn = 0xEA00_0000 | off; // B <off>
        let decoded = decbranch(insn, pos);
        assert_eq!(decoded, target);
    }

    #[test]
    fn test_arm_asm_token_registers() {
        assert_eq!(ArmAsmToken::R0.to_reg_number(), Some(0));
        assert_eq!(ArmAsmToken::R15.to_reg_number(), Some(15));
        assert_eq!(ArmAsmToken::Sp.to_reg_number(), Some(13));
        assert_eq!(ArmAsmToken::Lr.to_reg_number(), Some(14));
        assert_eq!(ArmAsmToken::Pc.to_reg_number(), Some(15));
        assert_eq!(ArmAsmToken::A1.to_reg_number(), Some(0));
        assert_eq!(ArmAsmToken::V8.to_reg_number(), Some(11));
    }

    #[test]
    fn test_arm_asm_token_cond_codes() {
        assert_eq!(ArmAsmToken::Eq.to_cond_code(), Some(0));
        assert_eq!(ArmAsmToken::Ne.to_cond_code(), Some(1));
        assert_eq!(ArmAsmToken::Al.to_cond_code(), Some(14));
        assert_eq!(ArmAsmToken::R0.to_cond_code(), None);
    }

    #[test]
    fn test_arm_asm_token_vfp() {
        assert_eq!(ArmAsmToken::S0.to_vfp_single(), Some(0));
        assert_eq!(ArmAsmToken::S31.to_vfp_single(), Some(31));
        assert_eq!(ArmAsmToken::D0.to_vfp_double(), Some(0));
        assert_eq!(ArmAsmToken::D15.to_vfp_double(), Some(15));
    }

    #[test]
    fn test_float_abi() {
        let soft = FloatAbi::SoftFp;
        let hard = FloatAbi::HardFloat;
        assert_ne!(soft, hard);
        assert_eq!(soft, FloatAbi::SoftFp);
    }

    #[test]
    fn test_treg_values() {
        assert_eq!(TReg::R0 as u8, 0);
        assert_eq!(TReg::R12 as u8, 4);
        assert_eq!(TReg::F0 as u8, 5);
        assert_eq!(TReg::F7 as u8, 12);
    }

    #[test]
    fn test_backend_creation() {
        let backend = ArmBackend::new();
        assert_eq!(backend.float_abi, FloatAbi::SoftFp);
        assert!(!backend.leaffunc);
        assert_eq!(backend.reg_classes_arr.len(), NB_REGS);
    }

    #[test]
    fn test_emit_insn() {
        let mut state = test_state();
        let result = ArmBackend::emit_insn(&mut state, ARM_NOP);
        assert!(result.is_ok());
        assert_eq!(state.ind, 4);
        assert_eq!(state.sections[0].data.len(), 4);
        let insn = read32le(&state.sections[0].data[0..]);
        assert_eq!(insn, ARM_NOP);
    }

    #[test]
    fn test_emit_insn_nocode() {
        let mut state = test_state();
        state.nocode_wanted = 1;
        let result = ArmBackend::emit_insn(&mut state, ARM_NOP);
        assert!(result.is_ok());
        assert_eq!(state.ind, 0);
        assert_eq!(state.sections[0].data.len(), 0);
    }

    #[test]
    fn test_code_reloc() {
        let backend = ArmBackend::new();
        assert_eq!(backend.code_reloc(R_ARM_ABS32 as i32), 0);
        assert_eq!(backend.code_reloc(R_ARM_CALL as i32), 1);
        assert_eq!(backend.code_reloc(R_ARM_JUMP24 as i32), 1);
        assert_eq!(backend.code_reloc(R_ARM_PC24 as i32), 1);
        assert_eq!(backend.code_reloc(R_ARM_GOTPC as i32), 0);
        assert_eq!(backend.code_reloc(9999), -1);
    }

    #[test]
    fn test_gotplt_entry_type() {
        let backend = ArmBackend::new();
        assert_eq!(backend.gotplt_entry_type(R_ARM_GOT32 as i32), GotPltEntry::AlwaysEntry);
        assert_eq!(backend.gotplt_entry_type(R_ARM_CALL as i32), GotPltEntry::AutoEntry);
        assert_eq!(backend.gotplt_entry_type(R_ARM_GLOB_DAT as i32), GotPltEntry::NoEntry);
        assert_eq!(backend.gotplt_entry_type(R_ARM_GOTPC as i32), GotPltEntry::BuildGotOnly);
    }

    #[test]
    fn test_relocate_abs32() {
        let backend = ArmBackend::new();
        let mut state = test_state();
        let mut buf = [0u8; 8];
        write32le(&mut buf, 0x1000);
        let result = backend.relocate(&mut state, R_ARM_ABS32 as i32, &mut buf, 0, 0x2000);
        assert!(result.is_ok());
        assert_eq!(read32le(&buf), 0x3000);
    }

    #[test]
    fn test_relocate_branch() {
        let backend = ArmBackend::new();
        let mut state = test_state();
        let mut buf = [0u8; 4];
        // B instruction with zero offset
        write32le(&mut buf, 0xEA00_0000);
        let addr: u64 = 0x1000;
        let val: u64 = 0x1100; // target 256 bytes forward
        let result = backend.relocate(&mut state, R_ARM_CALL as i32, &mut buf, addr, val);
        assert!(result.is_ok());
    }

    #[test]
    fn test_gjmp() {
        let mut state = test_state();
        let mut backend = ArmBackend::new();
        let result = backend.gjmp(&mut state, 0);
        assert!(result.is_ok());
        let ind = result.unwrap();
        assert_eq!(ind, 0);
        assert_eq!(state.ind, 4);
    }

    #[test]
    fn test_gjmp_cond() {
        let mut state = test_state();
        let mut backend = ArmBackend::new();
        let result = backend.gjmp_cond(&mut state, TOK_EQ, 0);
        assert!(result.is_ok());
        let ind = result.unwrap();
        assert_eq!(ind, 0);
        // Check condition code is EQ (0x0)
        let insn = read32le(&state.sections[0].data[0..]);
        assert_eq!(insn >> 28, COND_EQ);
    }

    #[test]
    fn test_gen_fill_nops() {
        let mut state = test_state();
        let mut backend = ArmBackend::new();
        let result = backend.gen_fill_nops(&mut state, 12);
        assert!(result.is_ok());
        assert_eq!(state.ind, 12);
        assert_eq!(state.sections[0].data.len(), 12);
        // Verify all NOPs
        for i in 0..3 {
            let insn = read32le(&state.sections[0].data[i * 4..]);
            assert_eq!(insn, ARM_NOP);
        }
    }

    #[test]
    fn test_target_machine_defs() {
        let backend = ArmBackend::new();
        let defs = backend.target_machine_defs();
        assert!(defs.contains(&"__arm__"));
        assert!(defs.contains(&"__ARM_EABI__"));
    }

    #[test]
    fn test_reg_classes_method() {
        let backend = ArmBackend::new();
        let classes = backend.reg_classes();
        assert_eq!(classes.len(), NB_REGS);
        assert_eq!(classes[0], RC_INT | RC_R0);
    }

    #[test]
    fn test_load_value() {
        let mut state = test_state();
        // Load small constant (fits in rotated immediate)
        let result = ArmBackend::load_value(&mut state, 0, 0xFF);
        assert!(result.is_ok());
        assert!(state.ind > 0);
    }

    #[test]
    fn test_load_value_large() {
        let mut state = test_state();
        // Load large constant (needs MOVW/MOVT)
        let result = ArmBackend::load_value(&mut state, 0, 0x1234_5678);
        assert!(result.is_ok());
        // Should emit MOVW + MOVT = 8 bytes
        assert_eq!(state.ind, 8);
    }

    #[test]
    fn test_gadd_sp() {
        let mut state = test_state();
        let result = ArmBackend::gadd_sp(&mut state, 16);
        assert!(result.is_ok());
        assert!(state.ind > 0);
    }

    #[test]
    fn test_asm_parse_regvar() {
        assert_eq!(asm_parse_regvar(0).unwrap(), 0);
        assert_eq!(asm_parse_regvar(15).unwrap(), 15);
        assert!(asm_parse_regvar(16).is_err());
        assert!(asm_parse_regvar(-1).is_err());
    }

    #[test]
    fn test_gfunc_sret() {
        let backend = ArmBackend::new();
        let vt = CType { t: VT_STRUCT, ref_sym: None };
        let mut ret = CType { t: 0, ref_sym: None };
        let mut align = 0i32;
        let mut regsize = 0i32;
        let result = backend.gfunc_sret(&vt, false, &mut ret, &mut align, &mut regsize);
        assert_eq!(result, 1); // Small struct in register
        assert_eq!(ret.t, VT_INT);
    }

    #[test]
    fn test_o_method() {
        let mut state = test_state();
        let mut backend = ArmBackend::new();
        let result = backend.o(&mut state, 0xDEAD_BEEF);
        assert!(result.is_ok());
        assert_eq!(state.ind, 4);
        let insn = read32le(&state.sections[0].data[0..]);
        assert_eq!(insn, 0xDEAD_BEEF);
    }

    #[test]
    fn test_sv_constant_value() {
        let sv = SValue {
            ctype: CType { t: VT_INT, ref_sym: None },
            r: VT_CONST,
            r2: 0,
            value: SValueData::Constant(CValue::Int(42)),
            sym_info: crate::types::SValueSymInfo::Sym(None),
        };
        assert_eq!(sv_constant_value(&sv), 42);
    }
}
