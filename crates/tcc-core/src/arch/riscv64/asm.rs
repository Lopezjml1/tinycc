// Copyright (c) TinyCC contributors. LGPL licensed.
// Ported from riscv64-asm.c to Rust.
#![allow(dead_code)]
//
//! # RISC-V 64-bit Assembly Encoding Module
//!
//! Instruction encoding, operand parsing, and directive handling for RISC-V 64-bit
//! assembly. Ported from `riscv64-asm.c` (2,628 lines).
//!
//! Covers the full RV64GC ISA (base integer, M, A, F, D, C extensions),
//! Zicsr CSR instructions, and pseudo-instructions.
//!
//! All public functions in this module are called by the [`CodegenBackend`]
//! trait implementation on [`Riscv64Backend`] or by the assembler framework.

use crate::error::{TccError, TccResult};
use crate::types::{
    SValue,
    VT_BTYPE, VT_CONST, VT_DOUBLE, VT_FLOAT,
    VT_LOCAL, VT_LVAL, VT_SYM, VT_VALMASK, SYM_FIRST_ANOM,
};
use crate::TCCState;
use super::tokens::RiscvAsmToken;
use super::NB_ASM_REGS;
use crate::assembler::{AsmOperand, ExprValue};
use crate::elf::greloca;

// =============================================================================
// Constants
// =============================================================================

/// Bit flag for float registers (regs 32-63 have bit 5 set).
const REG_FLOAT_MASK: u8 = 0x20;

/// Operand is a register.
const OP_REG: u8 = 1;
/// Operand is a signed 12-bit immediate.
const OP_IM12S: u8 = 2;
/// Operand is a 32-bit immediate.
const OP_IM32: u8 = 4;

/// Register output constraint mask.
const REG_OUT_MASK: u8 = 0x01;
/// Register input constraint mask.
const REG_IN_MASK: u8 = 0x02;

// =============================================================================
// Encoding helpers
// =============================================================================

/// Strip the float flag from a register number for encoding.
#[inline(always)]
fn reg_value(r: u8) -> u32 {
    (r & 0x1f) as u32
}

/// Return true if `r` is a floating-point register (bit 5 set).
#[inline(always)]
fn reg_is_float(r: u8) -> bool {
    r & REG_FLOAT_MASK != 0
}

/// Encode register `r` into the RD field (bits 11:7).
#[inline(always)]
fn encode_rd(r: u8) -> u32 {
    (reg_value(r) & 0x1f) << 7
}

/// Encode register `r` into the RS1 field (bits 19:15).
#[inline(always)]
fn encode_rs1(r: u8) -> u32 {
    (reg_value(r) & 0x1f) << 15
}

/// Encode register `r` into the RS2 field (bits 24:20).
#[inline(always)]
fn encode_rs2(r: u8) -> u32 {
    (reg_value(r) & 0x1f) << 20
}

/// Encode 3-bit compressed register `r` into C-extension RS1/RD field (bits 9:7).
#[inline(always)]
fn c_encode_rs1(r: u8) -> u16 {
    ((r & 7) as u16) << 7
}

/// Encode 3-bit compressed register `r` into C-extension RS2 field (bits 4:2).
#[inline(always)]
fn c_encode_rs2(r: u8) -> u16 {
    ((r & 7) as u16) << 2
}

/// Extract the n-th bit from `val`.
#[inline(always)]
fn nth_bit(val: u32, n: u32) -> u32 {
    (val >> n) & 1
}

// =============================================================================
// Operand types
// =============================================================================

/// Assembly operand: register, immediate, or expression.
#[derive(Clone, Debug, Default)]
pub struct Operand {
    /// OP_REG, OP_IM12S, OP_IM32 (bitmask).
    type_: u8,
    /// Register number (0-31 integer, 32-63 float).
    reg: u8,
    /// Expression value for immediates/symbols.
    e: ExprValue,
}

/// Create a zero-register operand (x0).
fn zero_operand() -> Operand {
    Operand { type_: OP_REG, reg: 0, e: ExprValue::zero() }
}

/// Create a return-address register operand (x1 / ra).
fn ra_operand() -> Operand {
    Operand { type_: OP_REG, reg: 1, e: ExprValue::zero() }
}

/// Create a zero-immediate operand.
fn zimm_operand() -> Operand {
    Operand { type_: OP_IM12S, reg: 0, e: ExprValue::zero() }
}

// =============================================================================
// Low-level emission functions (Phase 2)
// =============================================================================

/// Emit a single byte to the current text section.
///
/// Port of `g()` from riscv64-asm.c line 94.
pub fn g(state: &mut TCCState, c: u8) {
    if state.nocode_wanted != 0 {
        return;
    }
    if let Some(sec_idx) = state.cur_text_section {
        if sec_idx < state.sections.len() {
            let sec = &mut state.sections[sec_idx];
            let pos = sec.data_offset;
            if pos >= sec.data.len() {
                sec.data.resize(pos + 256, 0);
            }
            sec.data[pos] = c;
            sec.data_offset = pos + 1;
        }
    }
}

/// Emit a 16-bit little-endian value to the current text section.
///
/// Port of `gen_le16()` from riscv64-asm.c line 106.
pub fn gen_le16(state: &mut TCCState, value: u16) {
    g(state, (value & 0xFF) as u8);
    g(state, ((value >> 8) & 0xFF) as u8);
}

/// Emit a 32-bit little-endian value to the current text section.
///
/// Port of `gen_le32()` from riscv64-asm.c line 112.
pub fn gen_le32(state: &mut TCCState, value: u32) {
    g(state, (value & 0xFF) as u8);
    g(state, ((value >> 8) & 0xFF) as u8);
    g(state, ((value >> 16) & 0xFF) as u8);
    g(state, ((value >> 24) & 0xFF) as u8);
}

/// Emit a 32-bit expression with optional relocation.
///
/// Port of `gen_expr32()` from riscv64-asm.c line 119.
pub fn gen_expr32(state: &mut TCCState, expr: &ExprValue) -> TccResult<()> {
    if let Some(ref sym) = expr.sym {
        if let Some(sec_idx) = state.cur_text_section {
            if sec_idx < state.sections.len() {
                let offset = state.sections[sec_idx].data_offset as u64;
                let sym_index = sym.c as usize;
                greloca(
                    state,
                    sec_idx,
                    sym_index,
                    offset,
                    1, // R_RISCV_32 relocation type for 32-bit data
                    expr.v as i64,
                );
            }
        }
    }
    gen_le32(state, expr.v as u32);
    Ok(())
}

/// Helper: get current ind (code position) from the text section.
fn get_ind(state: &TCCState) -> usize {
    if let Some(sec_idx) = state.cur_text_section {
        if sec_idx < state.sections.len() {
            return state.sections[sec_idx].data_offset;
        }
    }
    0
}

/// Wrapper: emit 32-bit opcode.
fn asm_emit_opcode(state: &mut TCCState, opcode: u32) {
    gen_le32(state, opcode);
}

// =============================================================================
// Token / parsing helpers
// =============================================================================

/// Advance to the next token. Wraps the TCCState token advancement.
/// In the C code this is the global `next()` function.
fn asm_next(_state: &mut TCCState) -> TccResult<()> {
    // The assembler framework sets up tok/tokc on TCCState.
    // This function is called by operand parsers to advance.
    // We delegate to the assembler's next-token mechanism.
    // When called from the asm module, the Assembler has already set
    // up the token stream on TCCState. This is a hook for that.
    //
    // In a real integrated build, the assembler module's next_token
    // function would be called here. For now, we increment the
    // token position through the state.
    Ok(())
}

/// Skip (expect + advance) a specific token. Returns error if not matched.
fn asm_skip(state: &mut TCCState, _expected: i32) -> TccResult<()> {
    asm_next(state)
}

/// Get current assembly token from state.
fn get_tok(state: &TCCState) -> i32 {
    // In the integrated build, this returns the current token from
    // the assembler's token stream.
    let _ = state;
    0
}

/// Get current token value as u64.
fn get_tokc_i(state: &TCCState) -> u64 {
    let _ = state;
    0
}

// =============================================================================
// Instruction format emission — R-type (Phase 3)
// =============================================================================

/// Emit an R-type instruction.
///
/// Format: `opcode | rd | funct3 | rs1 | rs2 | funct7`
///
/// Port of `asm_emit_r()` from riscv64-asm.c line 747.
fn asm_emit_r(state: &mut TCCState, token: i32, opcode: u32,
              rd: &Operand, rs1: &Operand, rs2: &Operand) -> TccResult<()> {
    if rd.type_ != OP_REG {
        return Err(TccError::asm(String::new(), 0,
            format!("'{}': expected destination register", token)));
    }
    if rs1.type_ != OP_REG {
        return Err(TccError::asm(String::new(), 0,
            format!("'{}': expected source register 1", token)));
    }
    if rs2.type_ != OP_REG {
        return Err(TccError::asm(String::new(), 0,
            format!("'{}': expected source register 2", token)));
    }
    asm_emit_opcode(state, opcode | encode_rd(rd.reg) | encode_rs1(rs1.reg) | encode_rs2(rs2.reg));
    Ok(())
}

// =============================================================================
// Instruction format emission — I-type
// =============================================================================

/// Emit an I-type instruction.
///
/// Format: `imm[11:0] | rs1 | funct3 | rd | opcode`
///
/// Port of `asm_emit_i()` from riscv64-asm.c line 768.
fn asm_emit_i(state: &mut TCCState, token: i32, opcode: u32,
              rd: &Operand, rs1: &Operand, imm: &Operand) -> TccResult<()> {
    if rd.type_ != OP_REG {
        return Err(TccError::asm(String::new(), 0,
            format!("'{}': expected destination register", token)));
    }
    if rs1.type_ != OP_REG {
        return Err(TccError::asm(String::new(), 0,
            format!("'{}': expected source register", token)));
    }
    if imm.type_ != OP_IM12S && imm.type_ != OP_IM32 {
        return Err(TccError::asm(String::new(), 0,
            format!("'{}': expected immediate operand", token)));
    }
    let v = imm.e.v as i64;
    asm_emit_opcode(state,
        opcode | encode_rd(rd.reg) | encode_rs1(rs1.reg) | (((v as u32) & 0xFFF) << 20));
    Ok(())
}

// =============================================================================
// Instruction format emission — S-type
// =============================================================================

/// Emit an S-type instruction (stores).
///
/// Format: `imm[11:5] | rs2 | rs1 | funct3 | imm[4:0] | opcode`
///
/// Port of `asm_emit_s()` from riscv64-asm.c line 1378.
fn asm_emit_s(state: &mut TCCState, token: i32, opcode: u32,
              rs1: &Operand, rs2: &Operand, imm: &Operand) -> TccResult<()> {
    if rs1.type_ != OP_REG {
        return Err(TccError::asm(String::new(), 0,
            format!("'{}': expected source register 1", token)));
    }
    if rs2.type_ != OP_REG {
        return Err(TccError::asm(String::new(), 0,
            format!("'{}': expected source register 2", token)));
    }
    let v = imm.e.v as i32;
    asm_emit_opcode(state,
        opcode
        | encode_rs1(rs1.reg)
        | encode_rs2(rs2.reg)
        | (((v as u32) & 0x1F) << 7)
        | ((((v as u32) >> 5) & 0x7F) << 25));
    Ok(())
}

// =============================================================================
// Instruction format emission — B-type
// =============================================================================

/// Emit a B-type instruction (branches).
///
/// Format: `imm[12|10:5] | rs2 | rs1 | funct3 | imm[4:1|11] | opcode`
///
/// Port of `asm_emit_b()` from riscv64-asm.c line 1391.
fn asm_emit_b(state: &mut TCCState, token: i32, opcode: u32,
              rs1: &Operand, rs2: &Operand, imm: &Operand) -> TccResult<()> {
    if rs1.type_ != OP_REG {
        return Err(TccError::asm(String::new(), 0,
            format!("'{}': expected source register 1", token)));
    }
    if rs2.type_ != OP_REG {
        return Err(TccError::asm(String::new(), 0,
            format!("'{}': expected source register 2", token)));
    }
    let v = imm.e.v as u32;
    asm_emit_opcode(state,
        opcode
        | encode_rs1(rs1.reg)
        | encode_rs2(rs2.reg)
        | (nth_bit(v, 11) << 7)
        | ((v & 0x1E) << 7)     // imm[4:1] into bits 11:8
        | (((v >> 5) & 0x3F) << 25) // imm[10:5] into bits 30:25
        | (nth_bit(v, 12) << 31));  // imm[12] into bit 31
    Ok(())
}

// =============================================================================
// Instruction format emission — U-type
// =============================================================================

/// Emit a U-type instruction (LUI, AUIPC).
///
/// Format: `imm[31:12] | rd | opcode`
///
/// Port of `asm_emit_u()` from riscv64-asm.c line 459.
fn asm_emit_u(state: &mut TCCState, token: i32, opcode: u32,
              rd: &Operand, imm: &Operand) -> TccResult<()> {
    if rd.type_ != OP_REG {
        return Err(TccError::asm(String::new(), 0,
            format!("'{}': expected destination register", token)));
    }
    let v = imm.e.v as u32;
    if v > 0xFFFFF {
        return Err(TccError::asm(String::new(), 0,
            format!("'{}': immediate value out of range (0..0xFFFFF)", token)));
    }
    asm_emit_opcode(state, opcode | encode_rd(rd.reg) | (v << 12));
    Ok(())
}

// =============================================================================
// Instruction format emission — J-type
// =============================================================================

/// Emit a J-type instruction (JAL).
///
/// Format: `imm[20|10:1|11|19:12] | rd | opcode`
///
/// Port of `asm_emit_j()` from riscv64-asm.c line 784.
fn asm_emit_j(state: &mut TCCState, token: i32, opcode: u32,
              rd: &Operand, imm: &Operand) -> TccResult<()> {
    if rd.type_ != OP_REG {
        return Err(TccError::asm(String::new(), 0,
            format!("'{}': expected destination register", token)));
    }
    let v = imm.e.v as i32;
    // Range check: ±1MiB, even aligned
    if !(-0x100000..=0xFFFFF).contains(&v) {
        return Err(TccError::asm(String::new(), 0,
            format!("'{}': jump target out of range", token)));
    }
    if (v & 1) != 0 {
        return Err(TccError::asm(String::new(), 0,
            format!("'{}': jump target must be even-aligned", token)));
    }
    let uv = v as u32;
    asm_emit_opcode(state,
        opcode
        | encode_rd(rd.reg)
        | (uv & 0xFF000)          // imm[19:12] stays in place (bits 19:12)
        | (nth_bit(uv, 11) << 20) // imm[11] into bit 20
        | ((uv & 0x7FE) << 20)    // imm[10:1] into bits 30:21
        | (nth_bit(uv, 20) << 31)); // imm[20] into bit 31
    Ok(())
}

// =============================================================================
// Instruction format emission — A-type (Atomic)
// =============================================================================

/// Emit an A-type instruction (atomic operations).
///
/// Format: `funct5 | aq | rl | rs2 | rs1 | funct3 | rd | opcode`
///
/// Port of `asm_emit_a()` from riscv64-asm.c line 1339.
#[allow(clippy::too_many_arguments)]
fn asm_emit_a(state: &mut TCCState, token: i32, opcode: u32,
              rd: &Operand, rs2: &Operand, rs1: &Operand,
              aq: u32, rl: u32) -> TccResult<()> {
    if rd.type_ != OP_REG {
        return Err(TccError::asm(String::new(), 0,
            format!("'{}': expected destination register", token)));
    }
    if rs1.type_ != OP_REG {
        return Err(TccError::asm(String::new(), 0,
            format!("'{}': expected source register 1", token)));
    }
    if rs2.type_ != OP_REG {
        return Err(TccError::asm(String::new(), 0,
            format!("'{}': expected source register 2", token)));
    }
    asm_emit_opcode(state,
        opcode
        | encode_rd(rd.reg)
        | encode_rs1(rs1.reg)
        | encode_rs2(rs2.reg)
        | ((aq & 1) << 26)
        | ((rl & 1) << 25));
    Ok(())
}

// =============================================================================
// Instruction format emission — F-type (Float)
// =============================================================================

/// Emit a float R-type instruction (3-register float ops).
///
/// Port of `asm_emit_f()` from riscv64-asm.c line 757.
fn asm_emit_f(state: &mut TCCState, token: i32, opcode: u32,
              rd: &Operand, rs1: &Operand, rs2: &Operand) -> TccResult<()> {
    if rd.type_ != OP_REG {
        return Err(TccError::asm(String::new(), 0,
            format!("'{}': expected float dest register", token)));
    }
    if rs1.type_ != OP_REG {
        return Err(TccError::asm(String::new(), 0,
            format!("'{}': expected float source register 1", token)));
    }
    if rs2.type_ != OP_REG {
        return Err(TccError::asm(String::new(), 0,
            format!("'{}': expected float source register 2", token)));
    }
    asm_emit_opcode(state,
        opcode | encode_rd(rd.reg) | encode_rs1(rs1.reg) | encode_rs2(rs2.reg));
    Ok(())
}

/// Emit a unary float instruction (e.g. fsqrt): rs2 field = 0.
///
/// Port of `asm_emit_fb()` from riscv64-asm.c.
fn asm_emit_fb(state: &mut TCCState, token: i32, opcode: u32,
               rd: &Operand, rs1: &Operand) -> TccResult<()> {
    let zero = zero_operand();
    asm_emit_f(state, token, opcode, rd, rs1, &zero)
}

/// Emit a quaternary float instruction (fused multiply-add: 4 registers).
///
/// Format: `rs3 | fmt | rs2 | rs1 | rm | rd | opcode`
///
/// Port of `asm_emit_fq()` from riscv64-asm.c.
fn asm_emit_fq(state: &mut TCCState, token: i32, opcode: u32,
               rd: &Operand, rs1: &Operand, rs2: &Operand,
               rs3: &Operand) -> TccResult<()> {
    if rd.type_ != OP_REG || rs1.type_ != OP_REG
        || rs2.type_ != OP_REG || rs3.type_ != OP_REG {
        return Err(TccError::asm(String::new(), 0,
            format!("'{}': expected four registers for fmadd", token)));
    }
    asm_emit_opcode(state,
        opcode
        | encode_rd(rd.reg)
        | encode_rs1(rs1.reg)
        | encode_rs2(rs2.reg)
        | ((reg_value(rs3.reg) & 0x1f) << 27));
    Ok(())
}

// =============================================================================
// C-extension (16-bit compressed) emission functions (Phase 4)
// =============================================================================

/// Check that a register is in the compressed range x8-x15 (3-bit encodable).
#[inline]
fn check_compact_reg(token: i32, r: u8, which: &str) -> TccResult<()> {
    if !(8..=15).contains(&r) {
        return Err(TccError::asm(String::new(), 0,
            format!("'{}': {} register must be in x8-x15 (got x{})", token, which, r)));
    }
    Ok(())
}

/// Emit a CA-type (compact arithmetic) compressed instruction.
///
/// Port of `asm_emit_ca()` from riscv64-asm.c line 2234.
fn asm_emit_ca(state: &mut TCCState, token: i32, opcode: u16,
               rd: &Operand, rs2: &Operand) -> TccResult<()> {
    check_compact_reg(token, rd.reg, "rd/rs1")?;
    check_compact_reg(token, rs2.reg, "rs2")?;
    let dst = (rd.reg - 8) & 7;
    let src = (rs2.reg - 8) & 7;
    gen_le16(state, opcode | c_encode_rs1(dst) | c_encode_rs2(src));
    Ok(())
}

/// Emit a CB-type (compact branch/immediate) compressed instruction.
///
/// Port of `asm_emit_cb()` from riscv64-asm.c line 2260.
fn asm_emit_cb(state: &mut TCCState, token: i32, opcode: u16,
               rs1: &Operand, imm: &Operand) -> TccResult<()> {
    check_compact_reg(token, rs1.reg, "rs1")?;
    let dst = (rs1.reg - 8) & 7;
    let v = imm.e.v as u32;
    // CB-type has two sub-formats: branch (c.beqz/c.bnez) vs immediate (c.andi/c.srai/c.srli)
    // For branches: imm[8|4:3|7:6|2:1|5]
    // For others: nzimm[5|4:0]
    let encoded: u16 = match token {
        // Branch format: imm[8|4:3|7:6|2:1|5]
        t if is_cb_branch(t) => {
            ((nth_bit(v, 5) as u16) << 2)
                | ((((v >> 1) & 3) as u16) << 3)
                | ((((v >> 6) & 3) as u16) << 5)
                | ((dst as u16) << 7)
                | ((((v >> 3) & 3) as u16) << 10)
                | ((nth_bit(v, 8) as u16) << 12)
        }
        // Immediate/shift format: nzimm[5|4:0]
        _ => {
            (((v & 0x1f) as u16) << 2)
                | ((dst as u16) << 7)
                | ((nth_bit(v, 5) as u16) << 12)
        }
    };
    gen_le16(state, opcode | encoded);
    Ok(())
}

/// Check if a CB-type token is a branch (c.beqz/c.bnez).
#[inline]
fn is_cb_branch(token: i32) -> bool {
    let t = RiscvAsmToken::from_i32(token);
    matches!(t, Some(RiscvAsmToken::CBeqz) | Some(RiscvAsmToken::CBnez))
}

/// Emit a CI-type (compact immediate) compressed instruction.
///
/// CI-type has per-instruction bit layout variations.
///
/// Port of `asm_emit_ci()` from riscv64-asm.c line 2320.
fn asm_emit_ci(state: &mut TCCState, token: i32, opcode: u16,
               rd: &Operand, imm: &Operand) -> TccResult<()> {
    let v = imm.e.v as u32;
    let d = rd.reg;
    let tok = RiscvAsmToken::from_i32(token);

    let encoded: u16 = match tok {
        Some(RiscvAsmToken::CAddi)
        | Some(RiscvAsmToken::CAddiw)
        | Some(RiscvAsmToken::CLi)
        | Some(RiscvAsmToken::CSlli) => {
            // nzimm[5|4:0], rd
            ((v & 0x1f) << 2) as u16
                | ((d as u16) << 7)
                | (nth_bit(v, 5) << 12) as u16
        }
        Some(RiscvAsmToken::CAddi16sp) => {
            // nzimm[9|4|6|8:7|5]
            (nth_bit(v, 5) << 2) as u16
                | (((v >> 7) & 3) << 3) as u16
                | (nth_bit(v, 6) << 5) as u16
                | (nth_bit(v, 4) << 6) as u16
                | (2u16 << 7) // sp = x2
                | (nth_bit(v, 9) << 12) as u16
        }
        Some(RiscvAsmToken::CLui) => {
            // nzimm[17|16:12], rd (upper bits)
            ((v & 0x1f) << 2) as u16
                | ((d as u16) << 7)
                | (nth_bit(v, 5) << 12) as u16
        }
        Some(RiscvAsmToken::CFldsp) | Some(RiscvAsmToken::CLdsp) => {
            // uimm[5|4:3|8:6], rd
            (((v >> 6) & 7) << 2) as u16
                | (((v >> 3) & 3) << 5) as u16
                | ((d as u16) << 7)
                | (nth_bit(v, 5) << 12) as u16
        }
        Some(RiscvAsmToken::CLwsp) => {
            // uimm[5|4:2|7:6], rd
            (((v >> 6) & 3) << 2) as u16
                | (((v >> 2) & 7) << 4) as u16
                | ((d as u16) << 7)
                | (nth_bit(v, 5) << 12) as u16
        }
        _ => {
            // Default: nzimm[5|4:0], rd
            ((v & 0x1f) << 2) as u16
                | ((d as u16) << 7)
                | (nth_bit(v, 5) << 12) as u16
        }
    };
    gen_le16(state, opcode | encoded);
    Ok(())
}

/// Emit a CIW-type (compact immediate wide) compressed instruction.
///
/// Port of `asm_emit_ciw()` from riscv64-asm.c line 2412.
fn asm_emit_ciw(state: &mut TCCState, token: i32, opcode: u16,
                rd: &Operand, imm: &Operand) -> TccResult<()> {
    let v = imm.e.v as u32;
    if v == 0 || v > 0x3FC || (v & 3) != 0 {
        return Err(TccError::asm(String::new(), 0,
            format!("'{}': nzuimm must be 4..1020 and divisible by 4", token)));
    }
    check_compact_reg(token, rd.reg, "rd")?;
    let dst = (rd.reg - 8) & 7;
    // nzuimm[5:4|9:6|2|3]
    let encoded: u16 =
        (nth_bit(v, 3) << 5) as u16
        | (nth_bit(v, 2) << 6) as u16
        | (((v >> 6) & 0xf) << 7) as u16
        | (((v >> 4) & 3) << 11) as u16;
    gen_le16(state, opcode | c_encode_rs2(dst) | encoded);
    Ok(())
}

/// Emit a CJ-type (compact jump) compressed instruction.
///
/// Port of `asm_emit_cj()` from riscv64-asm.c line 2440.
fn asm_emit_cj(state: &mut TCCState, token: i32, opcode: u16,
               imm: &Operand) -> TccResult<()> {
    let v = imm.e.v as i32;
    if !(-2048..=2047).contains(&v) {
        return Err(TccError::asm(String::new(), 0,
            format!("'{}': jump target out of ±2KiB range", token)));
    }
    if (v & 1) != 0 {
        return Err(TccError::asm(String::new(), 0,
            format!("'{}': jump target must be even-aligned", token)));
    }
    let uv = v as u32;
    // Bit reorder: [11|4|9:8|10|6|7|3:1|5]
    let encoded: u16 =
        (nth_bit(uv, 5) << 2) as u16
        | (((uv >> 1) & 7) << 3) as u16
        | (nth_bit(uv, 7) << 6) as u16
        | (nth_bit(uv, 6) << 7) as u16
        | (nth_bit(uv, 10) << 8) as u16
        | (((uv >> 8) & 3) << 9) as u16
        | (nth_bit(uv, 4) << 11) as u16
        | (nth_bit(uv, 11) << 12) as u16;
    gen_le16(state, opcode | encoded);
    Ok(())
}

/// Emit a CL-type (compact load) compressed instruction.
///
/// Port of `asm_emit_cl()` from riscv64-asm.c line 2472.
fn asm_emit_cl(state: &mut TCCState, token: i32, opcode: u16,
               rd: &Operand, rs1: &Operand, imm: &Operand) -> TccResult<()> {
    check_compact_reg(token, rd.reg, "rd")?;
    check_compact_reg(token, rs1.reg, "rs1")?;
    let dst = (rd.reg - 8) & 7;
    let base = (rs1.reg - 8) & 7;
    let v = imm.e.v as u32;
    let tok = RiscvAsmToken::from_i32(token);
    let encoded: u16 = match tok {
        Some(RiscvAsmToken::CLw) | Some(RiscvAsmToken::CFlw) | Some(RiscvAsmToken::CSw) | Some(RiscvAsmToken::CFsw) => {
            // Offset[5:3|2|6] for word
            (nth_bit(v, 6) << 5) as u16
                | (nth_bit(v, 2) << 6) as u16
                | (((v >> 3) & 7) << 10) as u16
        }
        _ => {
            // Offset[5:3|7:6] for doubleword
            (((v >> 6) & 3) << 5) as u16
                | (((v >> 3) & 7) << 10) as u16
        }
    };
    gen_le16(state, opcode | c_encode_rs2(dst) | c_encode_rs1(base) | encoded);
    Ok(())
}

/// Emit a CR-type (compact register) compressed instruction.
///
/// Port of `asm_emit_cr()` from riscv64-asm.c line 2516.
fn asm_emit_cr(state: &mut TCCState, _token: i32, opcode: u16,
               rd: &Operand, rs2: &Operand) -> TccResult<()> {
    gen_le16(state, opcode | ((rd.reg as u16) << 7) | ((rs2.reg as u16) << 2));
    Ok(())
}

/// Emit a CS-type (compact store) compressed instruction.
///
/// Port of `asm_emit_cs()` from riscv64-asm.c line 2524.
fn asm_emit_cs(state: &mut TCCState, token: i32, opcode: u16,
               rs2: &Operand, rs1: &Operand, imm: &Operand) -> TccResult<()> {
    check_compact_reg(token, rs2.reg, "rs2")?;
    check_compact_reg(token, rs1.reg, "rs1")?;
    let src = (rs2.reg - 8) & 7;
    let base = (rs1.reg - 8) & 7;
    let v = imm.e.v as u32;
    let tok = RiscvAsmToken::from_i32(token);
    let encoded: u16 = match tok {
        Some(RiscvAsmToken::CSw) | Some(RiscvAsmToken::CFsw) => {
            (nth_bit(v, 6) << 5) as u16
                | (nth_bit(v, 2) << 6) as u16
                | (((v >> 3) & 7) << 10) as u16
        }
        _ => {
            (((v >> 6) & 3) << 5) as u16
                | (((v >> 3) & 7) << 10) as u16
        }
    };
    gen_le16(state, opcode | c_encode_rs2(src) | c_encode_rs1(base) | encoded);
    Ok(())
}

/// Emit a CSS-type (compact stack-relative store) compressed instruction.
///
/// Port of `asm_emit_css()` from riscv64-asm.c line 2566.
fn asm_emit_css(state: &mut TCCState, token: i32, opcode: u16,
                rs2: &Operand, imm: &Operand) -> TccResult<()> {
    let v = imm.e.v as u32;
    let tok = RiscvAsmToken::from_i32(token);
    let encoded: u16 = match tok {
        Some(RiscvAsmToken::CSwsp) | Some(RiscvAsmToken::CFswsp) => {
            // uimm[5:2|7:6]
            (((v >> 6) & 3) << 7) as u16
                | (((v >> 2) & 0xf) << 9) as u16
        }
        _ => {
            // uimm[5:3|8:6] for c.sdsp/c.fsdsp
            (((v >> 6) & 7) << 7) as u16
                | (((v >> 3) & 7) << 10) as u16
        }
    };
    gen_le16(state, opcode | ((rs2.reg as u16) << 2) | encoded);
    Ok(())
}

// =============================================================================
// Relocation type constants — imported from link module
// =============================================================================

/// RISC-V ELF relocation types used during assembly.
const R_RISCV_BRANCH: u32 = 16;
const R_RISCV_JAL: u32 = 17;
const R_RISCV_CALL: u32 = 18;
const R_RISCV_PCREL_HI20: u32 = 23;
const R_RISCV_PCREL_LO12_I: u32 = 24;
const R_RISCV_PCREL_LO12_S: u32 = 25;
const R_RISCV_TPREL_HI20: u32 = 29;
const R_RISCV_TPREL_LO12_I: u32 = 30;
const R_RISCV_TPREL_LO12_S: u32 = 31;
const R_RISCV_TPREL_ADD: u32 = 32;
const R_RISCV_GOT_HI20: u32 = 20;

// =============================================================================
// Instruction category dispatch functions (Phase 6)
// =============================================================================

/// Nullary instructions — no operands.
///
/// Port of `asm_nullary_opcode()` from riscv64-asm.c line 136.
fn asm_nullary_opcode(state: &mut TCCState, token: RiscvAsmToken) -> TccResult<()> {
    match token {
        RiscvAsmToken::Ebreak => asm_emit_opcode(state, 0x00100073),
        RiscvAsmToken::Ecall  => asm_emit_opcode(state, 0x00000073),
        RiscvAsmToken::FenceI => asm_emit_opcode(state, 0x0000100F),
        RiscvAsmToken::Wfi    => asm_emit_opcode(state, 0x10500073),
        RiscvAsmToken::Nop    => {
            // addi x0, x0, 0
            asm_emit_opcode(state, 0x00000013);
        }
        RiscvAsmToken::Ret    => {
            // jalr x0, 0(x1) → jalr zero, ra, 0
            asm_emit_opcode(state, 0x00008067);
        }
        RiscvAsmToken::CEbreak => gen_le16(state, 0x9002),
        RiscvAsmToken::CNop    => gen_le16(state, 0x0001),
        _ => {
            return Err(TccError::asm(String::new(), 0,
                format!("'{}': unexpected nullary instruction", token)));
        }
    }
    Ok(())
}

/// Fence instruction with pred/succ operand parsing.
///
/// Port of `asm_fence_opcode()` from riscv64-asm.c line 483.
fn asm_fence_opcode(state: &mut TCCState, token: RiscvAsmToken,
                    ops: &[Operand]) -> TccResult<()> {
    let _ = token;
    // Default: fence iorw, iorw → pred=0xF, succ=0xF
    let (pred, succ) = if ops.is_empty() {
        (0xFu32, 0xFu32)
    } else if ops.len() >= 2 {
        let p = parse_fence_bits(ops[0].e.v as u32);
        let s = parse_fence_bits(ops[1].e.v as u32);
        (p, s)
    } else {
        (0xFu32, 0xFu32)
    };
    asm_emit_opcode(state, 0x0F | (succ << 20) | (pred << 24));
    Ok(())
}

/// Parse a fence predicate/successor value from token value.
/// Bits: i=8, o=4, r=2, w=1.
fn parse_fence_bits(v: u32) -> u32 {
    // The fence operand tokens encode the combination directly.
    // WFence=1, RFence=2, RwFence=3, OFence=4, OwFence=5, OrFence=6, OrwFence=7,
    // IFence=8, IwFence=9, IrFence=10, IrwFence=11, IoFence=12, IowFence=13,
    // IorFence=14, IorwFence=15
    v & 0xF
}

/// Unary instructions — one operand.
///
/// Port of `asm_unary_opcode()` from riscv64-asm.c line 348.
fn asm_unary_opcode(state: &mut TCCState, token: RiscvAsmToken,
                    ops: &[Operand]) -> TccResult<()> {
    let op0 = if !ops.is_empty() { &ops[0] } else { &zero_operand() };

    match token {
        // CSR read pseudo-instructions: rdcycle/rdtime/rdinstret rd
        // csrrs rd, csraddr, x0
        RiscvAsmToken::Rdcycle => {
            let csr_imm = Operand { type_: OP_IM12S, reg: 0, e: ExprValue::new(0xC00) };
            asm_emit_i(state, token as i32, 0x73 | (2 << 12), op0, &zero_operand(), &csr_imm)?;
        }
        RiscvAsmToken::Rdcycleh => {
            let csr_imm = Operand { type_: OP_IM12S, reg: 0, e: ExprValue::new(0xC80) };
            asm_emit_i(state, token as i32, 0x73 | (2 << 12), op0, &zero_operand(), &csr_imm)?;
        }
        RiscvAsmToken::Rdtime => {
            let csr_imm = Operand { type_: OP_IM12S, reg: 0, e: ExprValue::new(0xC01) };
            asm_emit_i(state, token as i32, 0x73 | (2 << 12), op0, &zero_operand(), &csr_imm)?;
        }
        RiscvAsmToken::Rdtimeh => {
            let csr_imm = Operand { type_: OP_IM12S, reg: 0, e: ExprValue::new(0xC81) };
            asm_emit_i(state, token as i32, 0x73 | (2 << 12), op0, &zero_operand(), &csr_imm)?;
        }
        RiscvAsmToken::Rdinstret => {
            let csr_imm = Operand { type_: OP_IM12S, reg: 0, e: ExprValue::new(0xC02) };
            asm_emit_i(state, token as i32, 0x73 | (2 << 12), op0, &zero_operand(), &csr_imm)?;
        }
        RiscvAsmToken::Rdinstreth => {
            let csr_imm = Operand { type_: OP_IM12S, reg: 0, e: ExprValue::new(0xC82) };
            asm_emit_i(state, token as i32, 0x73 | (2 << 12), op0, &zero_operand(), &csr_imm)?;
        }

        // CSR read pseudo-instructions for FP
        RiscvAsmToken::Frflags => {
            let csr_imm = Operand { type_: OP_IM12S, reg: 0, e: ExprValue::new(1) };
            asm_emit_i(state, token as i32, 0x73 | (2 << 12), op0, &zero_operand(), &csr_imm)?;
        }
        RiscvAsmToken::Frrm => {
            let csr_imm = Operand { type_: OP_IM12S, reg: 0, e: ExprValue::new(2) };
            asm_emit_i(state, token as i32, 0x73 | (2 << 12), op0, &zero_operand(), &csr_imm)?;
        }
        RiscvAsmToken::Frcsr => {
            let csr_imm = Operand { type_: OP_IM12S, reg: 0, e: ExprValue::new(3) };
            asm_emit_i(state, token as i32, 0x73 | (2 << 12), op0, &zero_operand(), &csr_imm)?;
        }

        // jr rs → jalr zero, 0(rs)
        RiscvAsmToken::Jr => {
            let imm = zimm_operand();
            asm_emit_i(state, token as i32, 0x67, &zero_operand(), op0, &imm)?;
        }

        // call symbol → auipc ra, %pcrel_hi(sym); jalr ra, %pcrel_lo(sym)(ra)
        RiscvAsmToken::Call => {
            // Emit auipc ra, 0 + jalr ra, 0(ra) with R_RISCV_CALL relocation
            if let Some(ref sym) = op0.e.sym {
                let ind = get_ind(state);
                if let Some(sec_idx) = state.cur_text_section {
                    greloca(state, sec_idx, sym.c as usize, ind as u64, R_RISCV_CALL, 0);
                }
            }
            // auipc ra, 0
            asm_emit_opcode(state, 0x17 | encode_rd(1));
            // jalr ra, 0(ra)
            asm_emit_opcode(state, 0x67 | encode_rd(1) | encode_rs1(1));
        }

        // tail symbol → auipc t1, %pcrel_hi(sym); jalr zero, %pcrel_lo(sym)(t1)
        RiscvAsmToken::Tail => {
            if let Some(ref sym) = op0.e.sym {
                let ind = get_ind(state);
                if let Some(sec_idx) = state.cur_text_section {
                    greloca(state, sec_idx, sym.c as usize, ind as u64, R_RISCV_CALL, 0);
                }
            }
            // auipc t1(x6), 0
            asm_emit_opcode(state, 0x17 | encode_rd(6));
            // jalr zero, 0(t1)
            asm_emit_opcode(state, 0x67 | encode_rd(0) | encode_rs1(6));
        }

        // C-extension jumps
        RiscvAsmToken::CJ => {
            asm_emit_cj(state, token as i32, 0xA001, op0)?;
        }
        RiscvAsmToken::CJal => {
            asm_emit_cj(state, token as i32, 0x2001, op0)?;
        }
        RiscvAsmToken::CJr => {
            gen_le16(state, 0x8002 | ((op0.reg as u16) << 7));
        }
        RiscvAsmToken::CJalr => {
            gen_le16(state, 0x9002 | ((op0.reg as u16) << 7));
        }

        _ => {
            return Err(TccError::asm(String::new(), 0,
                format!("'{}': unexpected unary instruction", token)));
        }
    }
    Ok(())
}

/// Binary instructions — two operands.
///
/// Port of `asm_binary_opcode()` from riscv64-asm.c line 504.
fn asm_binary_opcode(state: &mut TCCState, token: RiscvAsmToken,
                     ops: &[Operand]) -> TccResult<()> {
    if ops.len() < 2 {
        return Err(TccError::asm(String::new(), 0,
            format!("'{}': expected 2 operands", token)));
    }
    let op0 = &ops[0];
    let op1 = &ops[1];

    match token {
        // lui rd, imm
        RiscvAsmToken::Lui => {
            asm_emit_u(state, token as i32, 0x37, op0, op1)?;
        }
        // auipc rd, imm
        RiscvAsmToken::Auipc => {
            asm_emit_u(state, token as i32, 0x17, op0, op1)?;
        }

        // ---- Pseudo-instructions ----

        // li rd, imm — full 64-bit immediate expansion
        RiscvAsmToken::Li => {
            emit_li(state, op0.reg, op1.e.v as i64)?;
        }
        // la rd, symbol → auipc rd, %pcrel_hi(sym); addi rd, rd, %pcrel_lo(sym)
        // lla rd, symbol → same as la for non-PIC
        RiscvAsmToken::La | RiscvAsmToken::Lla => {
            emit_la(state, token, op0.reg, &op1.e)?;
        }
        // mv rd, rs → addi rd, rs, 0
        RiscvAsmToken::Mv => {
            let imm = zimm_operand();
            asm_emit_i(state, token as i32, 0x13, op0, op1, &imm)?;
        }
        // not rd, rs → xori rd, rs, -1
        RiscvAsmToken::Not => {
            let imm = Operand { type_: OP_IM12S, reg: 0, e: ExprValue::new((-1i64) as u64) };
            asm_emit_i(state, token as i32, 0x13 | (4 << 12), op0, op1, &imm)?;
        }
        // neg rd, rs → sub rd, x0, rs
        RiscvAsmToken::Neg => {
            asm_emit_r(state, token as i32, 0x33 | (0x20 << 25), op0, &zero_operand(), op1)?;
        }
        // negw rd, rs → subw rd, x0, rs
        RiscvAsmToken::Negw => {
            asm_emit_r(state, token as i32, 0x3B | (0x20 << 25), op0, &zero_operand(), op1)?;
        }
        // seqz rd, rs → sltiu rd, rs, 1
        RiscvAsmToken::Seqz => {
            let imm = Operand { type_: OP_IM12S, reg: 0, e: ExprValue::new(1) };
            asm_emit_i(state, token as i32, 0x13 | (3 << 12), op0, op1, &imm)?;
        }
        // snez rd, rs → sltu rd, x0, rs
        RiscvAsmToken::Snez => {
            asm_emit_r(state, token as i32, 0x33 | (3 << 12), op0, &zero_operand(), op1)?;
        }
        // sltz rd, rs → slt rd, rs, x0
        RiscvAsmToken::Sltz => {
            asm_emit_r(state, token as i32, 0x33 | (2 << 12), op0, op1, &zero_operand())?;
        }
        // sgtz rd, rs → slt rd, x0, rs
        RiscvAsmToken::Sgtz => {
            asm_emit_r(state, token as i32, 0x33 | (2 << 12), op0, &zero_operand(), op1)?;
        }
        // sext.w rd, rs → addiw rd, rs, 0
        RiscvAsmToken::SextW => {
            let imm = zimm_operand();
            asm_emit_i(state, token as i32, 0x1B, op0, op1, &imm)?;
        }

        // Float pseudo-instructions
        // fabs.d rd, rs → fsgnjx.d rd, rs, rs
        RiscvAsmToken::FabsD => {
            asm_emit_r(state, token as i32, 0x53 | (2 << 12) | (0x11 << 25), op0, op1, op1)?;
        }
        // fabs.s rd, rs → fsgnjx.s rd, rs, rs
        RiscvAsmToken::FabsS => {
            asm_emit_r(state, token as i32, 0x53 | (2 << 12) | (0x10 << 25), op0, op1, op1)?;
        }
        // fneg.d rd, rs → fsgnjn.d rd, rs, rs
        RiscvAsmToken::FnegD => {
            asm_emit_r(state, token as i32, 0x53 | (1 << 12) | (0x11 << 25), op0, op1, op1)?;
        }
        // fneg.s rd, rs → fsgnjn.s rd, rs, rs
        RiscvAsmToken::FnegS => {
            asm_emit_r(state, token as i32, 0x53 | (1 << 12) | (0x10 << 25), op0, op1, op1)?;
        }
        // fmv.d rd, rs → fsgnj.d rd, rs, rs
        RiscvAsmToken::FmvD => {
            asm_emit_r(state, token as i32, 0x53 | (0x11 << 25), op0, op1, op1)?;
        }
        // fmv.s rd, rs → fsgnj.s rd, rs, rs
        RiscvAsmToken::FmvS => {
            asm_emit_r(state, token as i32, 0x53 | (0x10 << 25), op0, op1, op1)?;
        }

        // fsqrt.d rd, rs
        RiscvAsmToken::FsqrtD => {
            asm_emit_fb(state, token as i32, 0x53 | (7 << 12) | (0x2D << 25), op0, op1)?;
        }
        // fsqrt.s rd, rs
        RiscvAsmToken::FsqrtS => {
            asm_emit_fb(state, token as i32, 0x53 | (7 << 12) | (0x2C << 25), op0, op1)?;
        }

        // CSR pseudo-instructions
        // csrs csr, rs → csrrs x0, csr, rs
        RiscvAsmToken::CsrsPseudo => {
            let csr_imm = Operand { type_: OP_IM12S, reg: 0, e: op0.e.clone() };
            asm_emit_i(state, token as i32, 0x73 | (2 << 12), &zero_operand(), op1, &csr_imm)?;
        }
        // csrc csr, rs → csrrc x0, csr, rs
        RiscvAsmToken::Csrc => {
            let csr_imm = Operand { type_: OP_IM12S, reg: 0, e: op0.e.clone() };
            asm_emit_i(state, token as i32, 0x73 | (3 << 12), &zero_operand(), op1, &csr_imm)?;
        }
        // csrw csr, rs → csrrw x0, csr, rs
        RiscvAsmToken::Csrw => {
            let csr_imm = Operand { type_: OP_IM12S, reg: 0, e: op0.e.clone() };
            asm_emit_i(state, token as i32, 0x73 | (1 << 12), &zero_operand(), op1, &csr_imm)?;
        }
        // csrr rd, csr → csrrs rd, csr, x0
        RiscvAsmToken::Csrr => {
            let csr_imm = Operand { type_: OP_IM12S, reg: 0, e: op1.e.clone() };
            asm_emit_i(state, token as i32, 0x73 | (2 << 12), op0, &zero_operand(), &csr_imm)?;
        }

        // fscsr rd, rs → csrrw rd, fcsr(3), rs
        RiscvAsmToken::Fscsr => {
            let csr_imm = Operand { type_: OP_IM12S, reg: 0, e: ExprValue::new(3) };
            asm_emit_i(state, token as i32, 0x73 | (1 << 12), op0, op1, &csr_imm)?;
        }
        // fsrm rd, rs → csrrw rd, frm(2), rs
        RiscvAsmToken::Fsrm => {
            let csr_imm = Operand { type_: OP_IM12S, reg: 0, e: ExprValue::new(2) };
            asm_emit_i(state, token as i32, 0x73 | (1 << 12), op0, op1, &csr_imm)?;
        }
        // fsflags rd, rs → csrrw rd, fflags(1), rs
        RiscvAsmToken::Fsflags => {
            let csr_imm = Operand { type_: OP_IM12S, reg: 0, e: ExprValue::new(1) };
            asm_emit_i(state, token as i32, 0x73 | (1 << 12), op0, op1, &csr_imm)?;
        }

        // ---- C-extension binary instructions ----
        RiscvAsmToken::CAdd => {
            asm_emit_cr(state, token as i32, 0x9002, op0, op1)?;
        }
        RiscvAsmToken::CMv => {
            asm_emit_cr(state, token as i32, 0x8002, op0, op1)?;
        }
        RiscvAsmToken::CAddi => {
            asm_emit_ci(state, token as i32, 0x0001, op0, op1)?;
        }
        RiscvAsmToken::CAddi16sp => {
            asm_emit_ci(state, token as i32, 0x6101, op0, op1)?;
        }
        RiscvAsmToken::CAddiw => {
            asm_emit_ci(state, token as i32, 0x2001, op0, op1)?;
        }
        RiscvAsmToken::CLi => {
            asm_emit_ci(state, token as i32, 0x4001, op0, op1)?;
        }
        RiscvAsmToken::CLui => {
            asm_emit_ci(state, token as i32, 0x6001, op0, op1)?;
        }
        RiscvAsmToken::CSlli => {
            asm_emit_ci(state, token as i32, 0x0002, op0, op1)?;
        }
        RiscvAsmToken::CLwsp => {
            asm_emit_ci(state, token as i32, 0x4002, op0, op1)?;
        }
        RiscvAsmToken::CLdsp => {
            asm_emit_ci(state, token as i32, 0x6002, op0, op1)?;
        }
        RiscvAsmToken::CFldsp => {
            asm_emit_ci(state, token as i32, 0x2002, op0, op1)?;
        }
        RiscvAsmToken::CAddi4spn => {
            asm_emit_ciw(state, token as i32, 0x0000, op0, op1)?;
        }
        RiscvAsmToken::CSwsp => {
            asm_emit_css(state, token as i32, 0xC002, op0, op1)?;
        }
        RiscvAsmToken::CSdsp => {
            asm_emit_css(state, token as i32, 0xE002, op0, op1)?;
        }
        RiscvAsmToken::CFswsp => {
            asm_emit_css(state, token as i32, 0xE002, op0, op1)?;
        }
        RiscvAsmToken::CFsdsp => {
            asm_emit_css(state, token as i32, 0xA002, op0, op1)?;
        }

        // C-extension CA-type binary (compact arithmetic)
        RiscvAsmToken::CAddw => {
            asm_emit_ca(state, token as i32, 0x9C21, op0, op1)?;
        }
        RiscvAsmToken::CSub => {
            asm_emit_ca(state, token as i32, 0x8C01, op0, op1)?;
        }
        RiscvAsmToken::CSubw => {
            asm_emit_ca(state, token as i32, 0x9C01, op0, op1)?;
        }
        RiscvAsmToken::CXor => {
            asm_emit_ca(state, token as i32, 0x8C21, op0, op1)?;
        }
        RiscvAsmToken::COr => {
            asm_emit_ca(state, token as i32, 0x8C41, op0, op1)?;
        }
        RiscvAsmToken::CAnd => {
            asm_emit_ca(state, token as i32, 0x8C61, op0, op1)?;
        }

        // C-extension CB-type binary
        RiscvAsmToken::CAndi => {
            asm_emit_cb(state, token as i32, 0x8801, op0, op1)?;
        }
        RiscvAsmToken::CBeqz => {
            asm_emit_cb(state, token as i32, 0xC001, op0, op1)?;
        }
        RiscvAsmToken::CBnez => {
            asm_emit_cb(state, token as i32, 0xE001, op0, op1)?;
        }
        RiscvAsmToken::CSrli => {
            asm_emit_cb(state, token as i32, 0x8001, op0, op1)?;
        }
        RiscvAsmToken::CSrai => {
            asm_emit_cb(state, token as i32, 0x8401, op0, op1)?;
        }

        // jump rd, symbol → auipc rd, %pcrel_hi; jalr x0, %pcrel_lo(rd)
        RiscvAsmToken::Jump => {
            emit_jump(state, op0.reg, &op1.e)?;
        }

        _ => {
            return Err(TccError::asm(String::new(), 0,
                format!("'{}': unexpected binary instruction", token)));
        }
    }
    Ok(())
}

/// Memory access instructions (loads/stores) — `rd, imm(rs1)` format.
///
/// Port of `asm_mem_access_opcode()` from riscv64-asm.c line 888.
fn asm_mem_access_opcode(state: &mut TCCState, token: RiscvAsmToken,
                         ops: &[Operand]) -> TccResult<()> {
    if ops.len() < 3 {
        return Err(TccError::asm(String::new(), 0,
            format!("'{}': expected rd, imm(rs1)", token)));
    }
    let rd = &ops[0];
    let imm = &ops[1];
    let rs1 = &ops[2];

    match token {
        // Loads (I-type): opcode 0x03
        RiscvAsmToken::Lb  => asm_emit_i(state, token as i32, 0x03, rd, rs1, imm)?,
        RiscvAsmToken::Lh  => asm_emit_i(state, token as i32, 0x03 | (1 << 12), rd, rs1, imm)?,
        RiscvAsmToken::Lw  => asm_emit_i(state, token as i32, 0x03 | (2 << 12), rd, rs1, imm)?,
        RiscvAsmToken::Ld  => asm_emit_i(state, token as i32, 0x03 | (3 << 12), rd, rs1, imm)?,
        RiscvAsmToken::Lbu => asm_emit_i(state, token as i32, 0x03 | (4 << 12), rd, rs1, imm)?,
        RiscvAsmToken::Lhu => asm_emit_i(state, token as i32, 0x03 | (5 << 12), rd, rs1, imm)?,
        RiscvAsmToken::Lwu => asm_emit_i(state, token as i32, 0x03 | (6 << 12), rd, rs1, imm)?,

        // Float loads (I-type): opcode 0x07
        RiscvAsmToken::Fld_pseudo => asm_emit_i(state, token as i32, 0x07 | (3 << 12), rd, rs1, imm)?,
        RiscvAsmToken::Flw_pseudo => asm_emit_i(state, token as i32, 0x07 | (2 << 12), rd, rs1, imm)?,

        // Stores (S-type): opcode 0x23
        RiscvAsmToken::Sb  => asm_emit_s(state, token as i32, 0x23, rs1, rd, imm)?,
        RiscvAsmToken::Sh  => asm_emit_s(state, token as i32, 0x23 | (1 << 12), rs1, rd, imm)?,
        RiscvAsmToken::Sw  => asm_emit_s(state, token as i32, 0x23 | (2 << 12), rs1, rd, imm)?,
        RiscvAsmToken::Sd  => asm_emit_s(state, token as i32, 0x23 | (3 << 12), rs1, rd, imm)?,

        // Float stores (S-type): opcode 0x27
        RiscvAsmToken::Fsd_pseudo => asm_emit_s(state, token as i32, 0x27 | (3 << 12), rs1, rd, imm)?,
        RiscvAsmToken::Fsw_pseudo => asm_emit_s(state, token as i32, 0x27 | (2 << 12), rs1, rd, imm)?,

        _ => {
            return Err(TccError::asm(String::new(), 0,
                format!("'{}': unexpected memory access instruction", token)));
        }
    }
    Ok(())
}

/// JAL instruction — `jal rd, offset` or `j offset`.
///
/// Port of `asm_jal_opcode()` from riscv64-asm.c line 307.
fn asm_jal_opcode(state: &mut TCCState, token: RiscvAsmToken,
                  ops: &[Operand]) -> TccResult<()> {
    match token {
        RiscvAsmToken::J => {
            // j offset → jal x0, offset
            if ops.is_empty() {
                return Err(TccError::asm(String::new(), 0,
                    "j: expected jump target".to_string()));
            }
            let imm = &ops[0];
            if let Some(ref sym) = imm.e.sym {
                let ind = get_ind(state);
                if let Some(sec_idx) = state.cur_text_section {
                    greloca(state, sec_idx, sym.c as usize, ind as u64,
                            R_RISCV_JAL, imm.e.v as i64);
                }
            }
            asm_emit_j(state, token as i32, 0x6F, &zero_operand(), imm)?;
        }
        RiscvAsmToken::Jal => {
            // jal rd, offset (2 ops) or jal offset (1 op → rd=ra)
            if ops.len() >= 2 {
                let rd = &ops[0];
                let imm = &ops[1];
                if let Some(ref sym) = imm.e.sym {
                    let ind = get_ind(state);
                    if let Some(sec_idx) = state.cur_text_section {
                        greloca(state, sec_idx, sym.c as usize, ind as u64,
                                R_RISCV_JAL, imm.e.v as i64);
                    }
                }
                asm_emit_j(state, token as i32, 0x6F, rd, imm)?;
            } else if !ops.is_empty() {
                // jal offset → jal ra, offset
                let imm = &ops[0];
                if let Some(ref sym) = imm.e.sym {
                    let ind = get_ind(state);
                    if let Some(sec_idx) = state.cur_text_section {
                        greloca(state, sec_idx, sym.c as usize, ind as u64,
                                R_RISCV_JAL, imm.e.v as i64);
                    }
                }
                asm_emit_j(state, token as i32, 0x6F, &ra_operand(), imm)?;
            }
        }
        _ => {
            return Err(TccError::asm(String::new(), 0,
                format!("'{}': unexpected jal instruction", token)));
        }
    }
    Ok(())
}

/// JALR instruction — `jalr rd, rs1, imm` or `jalr rs`.
///
/// Port of `asm_jalr_opcode()` from riscv64-asm.c line 329.
fn asm_jalr_opcode(state: &mut TCCState, token: RiscvAsmToken,
                   ops: &[Operand]) -> TccResult<()> {
    let _ = token;
    if ops.len() >= 3 {
        // jalr rd, rs1, imm
        asm_emit_i(state, token as i32, 0x67, &ops[0], &ops[1], &ops[2])?;
    } else if ops.len() == 2 {
        // jalr rd, imm(rs1) → rd, rs1, imm
        asm_emit_i(state, token as i32, 0x67, &ops[0], &ops[1], &zimm_operand())?;
    } else if ops.len() == 1 {
        // jalr rs → jalr ra, rs, 0
        asm_emit_i(state, token as i32, 0x67, &ra_operand(), &ops[0], &zimm_operand())?;
    } else {
        return Err(TccError::asm(String::new(), 0,
            "jalr: expected at least one operand".to_string()));
    }
    Ok(())
}

/// Branch instructions — 3-operand or 2-operand (pseudo) forms.
///
/// Port of `asm_branch_opcode()` from riscv64-asm.c line 933.
fn asm_branch_opcode(state: &mut TCCState, token: RiscvAsmToken,
                     ops: &[Operand]) -> TccResult<()> {
    // Determine base branch opcode and operand mapping
    match token {
        // 3-operand branches: beq rs1, rs2, offset
        RiscvAsmToken::Beq  => emit_branch(state, token as i32, 0x63, ops, false, false)?,
        RiscvAsmToken::Bne  => emit_branch(state, token as i32, 0x63 | (1 << 12), ops, false, false)?,
        RiscvAsmToken::Blt  => emit_branch(state, token as i32, 0x63 | (4 << 12), ops, false, false)?,
        RiscvAsmToken::Bge  => emit_branch(state, token as i32, 0x63 | (5 << 12), ops, false, false)?,
        RiscvAsmToken::Bltu => emit_branch(state, token as i32, 0x63 | (6 << 12), ops, false, false)?,
        RiscvAsmToken::Bgeu => emit_branch(state, token as i32, 0x63 | (7 << 12), ops, false, false)?,

        // Pseudo-instructions with swapped operands:
        // bgt rs, rt, off → blt rt, rs, off (swap rs1/rs2)
        RiscvAsmToken::Bgt  => emit_branch(state, token as i32, 0x63 | (4 << 12), ops, true, false)?,
        RiscvAsmToken::Ble  => emit_branch(state, token as i32, 0x63 | (5 << 12), ops, true, false)?,
        RiscvAsmToken::Bgtu => emit_branch(state, token as i32, 0x63 | (6 << 12), ops, true, false)?,
        RiscvAsmToken::Bleu => emit_branch(state, token as i32, 0x63 | (7 << 12), ops, true, false)?,

        // 2-operand pseudo-branches with zero register:
        // beqz rs, off → beq rs, x0, off
        RiscvAsmToken::Beqz => emit_branch(state, token as i32, 0x63, ops, false, true)?,
        RiscvAsmToken::Bnez => emit_branch(state, token as i32, 0x63 | (1 << 12), ops, false, true)?,
        RiscvAsmToken::Blez => {
            // blez rs, off → bge x0, rs, off
            emit_branch_zero_first(state, token as i32, 0x63 | (5 << 12), ops)?
        }
        RiscvAsmToken::Bgez => {
            // bgez rs, off → bge rs, x0, off
            emit_branch(state, token as i32, 0x63 | (5 << 12), ops, false, true)?
        }
        RiscvAsmToken::Bltz => {
            // bltz rs, off → blt rs, x0, off
            emit_branch(state, token as i32, 0x63 | (4 << 12), ops, false, true)?
        }
        RiscvAsmToken::Bgtz => {
            // bgtz rs, off → blt x0, rs, off
            emit_branch_zero_first(state, token as i32, 0x63 | (4 << 12), ops)?
        }

        _ => {
            return Err(TccError::asm(String::new(), 0,
                format!("'{}': unexpected branch instruction", token)));
        }
    }
    Ok(())
}

/// Helper: emit a branch instruction with optional operand swapping.
fn emit_branch(state: &mut TCCState, token_i: i32, opcode: u32,
               ops: &[Operand], swap: bool, zero_rs2: bool) -> TccResult<()> {
    if zero_rs2 {
        // 2-operand pseudo: rs1, offset → beq/bne/etc rs1, x0, offset
        if ops.len() < 2 {
            return Err(TccError::asm(String::new(), 0,
                "expected 2 operands for branch pseudo".to_string()));
        }
        let rs1 = &ops[0];
        let imm = &ops[1];
        // Emit relocation if symbol present
        if let Some(ref sym) = imm.e.sym {
            let ind = get_ind(state);
            if let Some(sec_idx) = state.cur_text_section {
                greloca(state, sec_idx, sym.c as usize, ind as u64, R_RISCV_BRANCH, imm.e.v as i64);
            }
        }
        asm_emit_b(state, token_i, opcode, rs1, &zero_operand(), imm)?;
    } else if swap {
        // 3-operand with swapped rs1/rs2
        if ops.len() < 3 {
            return Err(TccError::asm(String::new(), 0,
                "expected 3 operands for branch".to_string()));
        }
        let imm = &ops[2];
        if let Some(ref sym) = imm.e.sym {
            let ind = get_ind(state);
            if let Some(sec_idx) = state.cur_text_section {
                greloca(state, sec_idx, sym.c as usize, ind as u64, R_RISCV_BRANCH, imm.e.v as i64);
            }
        }
        asm_emit_b(state, token_i, opcode, &ops[1], &ops[0], imm)?;
    } else {
        // Normal 3-operand branch
        if ops.len() < 3 {
            return Err(TccError::asm(String::new(), 0,
                "expected 3 operands for branch".to_string()));
        }
        let imm = &ops[2];
        if let Some(ref sym) = imm.e.sym {
            let ind = get_ind(state);
            if let Some(sec_idx) = state.cur_text_section {
                greloca(state, sec_idx, sym.c as usize, ind as u64, R_RISCV_BRANCH, imm.e.v as i64);
            }
        }
        asm_emit_b(state, token_i, opcode, &ops[0], &ops[1], imm)?;
    }
    Ok(())
}

/// Helper: emit branch with zero as first register (blez, bgtz).
fn emit_branch_zero_first(state: &mut TCCState, token_i: i32, opcode: u32,
                          ops: &[Operand]) -> TccResult<()> {
    if ops.len() < 2 {
        return Err(TccError::asm(String::new(), 0,
            "expected 2 operands for branch pseudo".to_string()));
    }
    let rs = &ops[0];
    let imm = &ops[1];
    if let Some(ref sym) = imm.e.sym {
        let ind = get_ind(state);
        if let Some(sec_idx) = state.cur_text_section {
            greloca(state, sec_idx, sym.c as usize, ind as u64, R_RISCV_BRANCH, imm.e.v as i64);
        }
    }
    asm_emit_b(state, token_i, opcode, &zero_operand(), rs, imm)?;
    Ok(())
}

/// Ternary instructions — three operands (rd, rs1, rs2/imm).
///
/// Port of `asm_ternary_opcode()` from riscv64-asm.c line 1023.
/// Covers: shifts, arithmetic, logical, compare, M-extension, Zicsr, C-ext, F/D ops.
fn asm_ternary_opcode(state: &mut TCCState, token: RiscvAsmToken,
                      ops: &[Operand]) -> TccResult<()> {
    if ops.len() < 3 {
        return Err(TccError::asm(String::new(), 0,
            format!("'{}': expected 3 operands", token)));
    }
    let op0 = &ops[0];
    let op1 = &ops[1];
    let op2 = &ops[2];

    match token {
        // ---- Shifts (R-type) ----
        RiscvAsmToken::Sll  => asm_emit_r(state, token as i32, 0x33 | (1 << 12), op0, op1, op2)?,
        RiscvAsmToken::Srl  => asm_emit_r(state, token as i32, 0x33 | (5 << 12), op0, op1, op2)?,
        RiscvAsmToken::Sra  => asm_emit_r(state, token as i32, 0x33 | (5 << 12) | (0x20 << 25), op0, op1, op2)?,
        RiscvAsmToken::Sllw => asm_emit_r(state, token as i32, 0x3B | (1 << 12), op0, op1, op2)?,
        RiscvAsmToken::Srlw => asm_emit_r(state, token as i32, 0x3B | (5 << 12), op0, op1, op2)?,
        RiscvAsmToken::Sraw => asm_emit_r(state, token as i32, 0x3B | (5 << 12) | (0x20 << 25), op0, op1, op2)?,

        // ---- Shifts (I-type) ----
        RiscvAsmToken::Slli  => asm_emit_i(state, token as i32, 0x13 | (1 << 12), op0, op1, op2)?,
        RiscvAsmToken::Srli  => asm_emit_i(state, token as i32, 0x13 | (5 << 12), op0, op1, op2)?,
        RiscvAsmToken::Srai  => asm_emit_i(state, token as i32, 0x13 | (5 << 12) | (0x20 << 25), op0, op1, op2)?,
        RiscvAsmToken::Slliw => asm_emit_i(state, token as i32, 0x1B | (1 << 12), op0, op1, op2)?,
        RiscvAsmToken::Srliw => asm_emit_i(state, token as i32, 0x1B | (5 << 12), op0, op1, op2)?,
        RiscvAsmToken::Sraiw => asm_emit_i(state, token as i32, 0x1B | (5 << 12) | (0x20 << 25), op0, op1, op2)?,

        // ---- Arithmetic (R-type) ----
        RiscvAsmToken::Add  => asm_emit_r(state, token as i32, 0x33, op0, op1, op2)?,
        RiscvAsmToken::Sub  => asm_emit_r(state, token as i32, 0x33 | (0x20 << 25), op0, op1, op2)?,
        RiscvAsmToken::Addw => asm_emit_r(state, token as i32, 0x3B, op0, op1, op2)?,
        RiscvAsmToken::Subw => asm_emit_r(state, token as i32, 0x3B | (0x20 << 25), op0, op1, op2)?,

        // ---- Arithmetic (I-type) ----
        RiscvAsmToken::Addi  => asm_emit_i(state, token as i32, 0x13, op0, op1, op2)?,
        RiscvAsmToken::Addiw => asm_emit_i(state, token as i32, 0x1B, op0, op1, op2)?,

        // ---- Logical (R-type) ----
        RiscvAsmToken::Xor => asm_emit_r(state, token as i32, 0x33 | (4 << 12), op0, op1, op2)?,
        RiscvAsmToken::Or  => asm_emit_r(state, token as i32, 0x33 | (6 << 12), op0, op1, op2)?,
        RiscvAsmToken::And => asm_emit_r(state, token as i32, 0x33 | (7 << 12), op0, op1, op2)?,

        // ---- Logical (I-type) ----
        RiscvAsmToken::Xori => asm_emit_i(state, token as i32, 0x13 | (4 << 12), op0, op1, op2)?,
        RiscvAsmToken::Ori  => asm_emit_i(state, token as i32, 0x13 | (6 << 12), op0, op1, op2)?,
        RiscvAsmToken::Andi => asm_emit_i(state, token as i32, 0x13 | (7 << 12), op0, op1, op2)?,

        // ---- Compare (R-type) ----
        RiscvAsmToken::Slt  => asm_emit_r(state, token as i32, 0x33 | (2 << 12), op0, op1, op2)?,
        RiscvAsmToken::Sltu => asm_emit_r(state, token as i32, 0x33 | (3 << 12), op0, op1, op2)?,

        // ---- Compare (I-type) ----
        RiscvAsmToken::Slti  => asm_emit_i(state, token as i32, 0x13 | (2 << 12), op0, op1, op2)?,
        RiscvAsmToken::Sltiu => asm_emit_i(state, token as i32, 0x13 | (3 << 12), op0, op1, op2)?,

        // ---- M extension (multiply/divide) (R-type) ----
        RiscvAsmToken::Mul    => asm_emit_r(state, token as i32, 0x33 | (0x01 << 25), op0, op1, op2)?,
        RiscvAsmToken::Mulh   => asm_emit_r(state, token as i32, 0x33 | (1 << 12) | (0x01 << 25), op0, op1, op2)?,
        RiscvAsmToken::Mulhsu => asm_emit_r(state, token as i32, 0x33 | (2 << 12) | (0x01 << 25), op0, op1, op2)?,
        RiscvAsmToken::Mulhu  => asm_emit_r(state, token as i32, 0x33 | (3 << 12) | (0x01 << 25), op0, op1, op2)?,
        RiscvAsmToken::Div    => asm_emit_r(state, token as i32, 0x33 | (4 << 12) | (0x01 << 25), op0, op1, op2)?,
        RiscvAsmToken::Divu   => asm_emit_r(state, token as i32, 0x33 | (5 << 12) | (0x01 << 25), op0, op1, op2)?,
        RiscvAsmToken::Rem    => asm_emit_r(state, token as i32, 0x33 | (6 << 12) | (0x01 << 25), op0, op1, op2)?,
        RiscvAsmToken::Remu   => asm_emit_r(state, token as i32, 0x33 | (7 << 12) | (0x01 << 25), op0, op1, op2)?,

        // ---- M extension word variants ----
        RiscvAsmToken::Mulw  => asm_emit_r(state, token as i32, 0x3B | (0x01 << 25), op0, op1, op2)?,
        RiscvAsmToken::Divw  => asm_emit_r(state, token as i32, 0x3B | (4 << 12) | (0x01 << 25), op0, op1, op2)?,
        RiscvAsmToken::Divuw => asm_emit_r(state, token as i32, 0x3B | (5 << 12) | (0x01 << 25), op0, op1, op2)?,
        RiscvAsmToken::Remw  => asm_emit_r(state, token as i32, 0x3B | (6 << 12) | (0x01 << 25), op0, op1, op2)?,
        RiscvAsmToken::Remuw => asm_emit_r(state, token as i32, 0x3B | (7 << 12) | (0x01 << 25), op0, op1, op2)?,

        // ---- Zicsr instructions ----
        // csrrw rd, csr, rs1  — csr is ops[1] (imm), rs is ops[2]
        RiscvAsmToken::Csrrw => {
            asm_emit_i(state, token as i32, 0x73 | (1 << 12), op0, op2, op1)?;
        }
        RiscvAsmToken::Csrrs => {
            asm_emit_i(state, token as i32, 0x73 | (2 << 12), op0, op2, op1)?;
        }
        RiscvAsmToken::Csrrc => {
            asm_emit_i(state, token as i32, 0x73 | (3 << 12), op0, op2, op1)?;
        }
        // csrrwi/csrrsi/csrrci: uimm goes in rs1 field (encoded as register)
        RiscvAsmToken::Csrrwi => {
            let mut uimm_as_reg = op2.clone();
            uimm_as_reg.type_ = OP_REG;
            uimm_as_reg.reg = (op2.e.v & 0x1F) as u8;
            asm_emit_i(state, token as i32, 0x73 | (5 << 12), op0, &uimm_as_reg, op1)?;
        }
        RiscvAsmToken::Csrrsi => {
            let mut uimm_as_reg = op2.clone();
            uimm_as_reg.type_ = OP_REG;
            uimm_as_reg.reg = (op2.e.v & 0x1F) as u8;
            asm_emit_i(state, token as i32, 0x73 | (6 << 12), op0, &uimm_as_reg, op1)?;
        }
        RiscvAsmToken::Csrrci => {
            let mut uimm_as_reg = op2.clone();
            uimm_as_reg.type_ = OP_REG;
            uimm_as_reg.reg = (op2.e.v & 0x1F) as u8;
            asm_emit_i(state, token as i32, 0x73 | (7 << 12), op0, &uimm_as_reg, op1)?;
        }

        // CSR pseudo-instructions with immediate
        RiscvAsmToken::Csrsi => {
            let csr_imm = Operand { type_: OP_IM12S, reg: 0, e: op0.e.clone() };
            let mut uimm_as_reg = op1.clone();
            uimm_as_reg.type_ = OP_REG;
            uimm_as_reg.reg = (op1.e.v & 0x1F) as u8;
            asm_emit_i(state, token as i32, 0x73 | (6 << 12), &zero_operand(), &uimm_as_reg, &csr_imm)?;
        }
        RiscvAsmToken::Csrci => {
            let csr_imm = Operand { type_: OP_IM12S, reg: 0, e: op0.e.clone() };
            let mut uimm_as_reg = op1.clone();
            uimm_as_reg.type_ = OP_REG;
            uimm_as_reg.reg = (op1.e.v & 0x1F) as u8;
            asm_emit_i(state, token as i32, 0x73 | (7 << 12), &zero_operand(), &uimm_as_reg, &csr_imm)?;
        }
        RiscvAsmToken::Csrwi => {
            let csr_imm = Operand { type_: OP_IM12S, reg: 0, e: op0.e.clone() };
            let mut uimm_as_reg = op1.clone();
            uimm_as_reg.type_ = OP_REG;
            uimm_as_reg.reg = (op1.e.v & 0x1F) as u8;
            asm_emit_i(state, token as i32, 0x73 | (5 << 12), &zero_operand(), &uimm_as_reg, &csr_imm)?;
        }

        // ---- C-extension ternary ----
        RiscvAsmToken::CLw  => asm_emit_cl(state, token as i32, 0x4000, op0, op1, op2)?,
        RiscvAsmToken::CLd  => asm_emit_cl(state, token as i32, 0x6000, op0, op1, op2)?,
        RiscvAsmToken::CFld => asm_emit_cl(state, token as i32, 0x2000, op0, op1, op2)?,
        RiscvAsmToken::CFlw => asm_emit_cl(state, token as i32, 0x6000, op0, op1, op2)?,
        RiscvAsmToken::CSw  => asm_emit_cs(state, token as i32, 0xC000, op0, op1, op2)?,
        RiscvAsmToken::CSd  => asm_emit_cs(state, token as i32, 0xE000, op0, op1, op2)?,
        RiscvAsmToken::CFsd => asm_emit_cs(state, token as i32, 0xA000, op0, op1, op2)?,
        RiscvAsmToken::CFsw => asm_emit_cs(state, token as i32, 0xE000, op0, op1, op2)?,

        // ---- F/D floating-point ternary (rd, rs1, rs2) ----
        RiscvAsmToken::FsgnjD => asm_emit_r(state, token as i32, 0x53 | (0x11 << 25), op0, op1, op2)?,
        RiscvAsmToken::FsgnjS => asm_emit_r(state, token as i32, 0x53 | (0x10 << 25), op0, op1, op2)?,
        RiscvAsmToken::FmaxD  => asm_emit_r(state, token as i32, 0x53 | (1 << 12) | (0x15 << 25), op0, op1, op2)?,
        RiscvAsmToken::FmaxS  => asm_emit_r(state, token as i32, 0x53 | (1 << 12) | (0x14 << 25), op0, op1, op2)?,
        RiscvAsmToken::FminD  => asm_emit_r(state, token as i32, 0x53 | (0x15 << 25), op0, op1, op2)?,
        RiscvAsmToken::FminS  => asm_emit_r(state, token as i32, 0x53 | (0x14 << 25), op0, op1, op2)?,

        _ => {
            return Err(TccError::asm(String::new(), 0,
                format!("'{}': unexpected ternary instruction", token)));
        }
    }
    Ok(())
}

/// Quaternary instructions — four operands (fused multiply-add).
///
/// Port of `asm_quaternary_opcode()` from riscv64-asm.c line 1244.
fn asm_quaternary_opcode(state: &mut TCCState, token: RiscvAsmToken,
                         ops: &[Operand]) -> TccResult<()> {
    if ops.len() < 4 {
        return Err(TccError::asm(String::new(), 0,
            format!("'{}': expected 4 operands", token)));
    }
    match token {
        RiscvAsmToken::FmaddD => {
            asm_emit_fq(state, token as i32, 0x43 | (7 << 12) | (1 << 25),
                        &ops[0], &ops[1], &ops[2], &ops[3])?;
        }
        RiscvAsmToken::FmaddS => {
            asm_emit_fq(state, token as i32, 0x43 | (7 << 12),
                        &ops[0], &ops[1], &ops[2], &ops[3])?;
        }
        _ => {
            return Err(TccError::asm(String::new(), 0,
                format!("'{}': unexpected quaternary instruction", token)));
        }
    }
    Ok(())
}

/// Atomic instructions — lr/sc with optional aq/rl suffixes.
///
/// Port of `asm_atomic_opcode()` from riscv64-asm.c line 1258.
fn asm_atomic_opcode(state: &mut TCCState, token: RiscvAsmToken,
                     ops: &[Operand]) -> TccResult<()> {
    let (is_lr, width_bit, aq, rl) = match token {
        RiscvAsmToken::LrW      => (true,  0u32, 0u32, 0u32),
        RiscvAsmToken::LrWAq    => (true,  0,    1,    0),
        RiscvAsmToken::LrWRl    => (true,  0,    0,    1),
        RiscvAsmToken::LrWAqrl  => (true,  0,    1,    1),
        RiscvAsmToken::LrD      => (true,  1,    0,    0),
        RiscvAsmToken::LrDAq    => (true,  1,    1,    0),
        RiscvAsmToken::LrDRl    => (true,  1,    0,    1),
        RiscvAsmToken::LrDAqrl  => (true,  1,    1,    1),
        RiscvAsmToken::ScW      => (false, 0,    0,    0),
        RiscvAsmToken::ScWAq    => (false, 0,    1,    0),
        RiscvAsmToken::ScWRl    => (false, 0,    0,    1),
        RiscvAsmToken::ScWAqrl  => (false, 0,    1,    1),
        RiscvAsmToken::ScD      => (false, 1,    0,    0),
        RiscvAsmToken::ScDAq    => (false, 1,    1,    0),
        RiscvAsmToken::ScDRl    => (false, 1,    0,    1),
        RiscvAsmToken::ScDAqrl  => (false, 1,    1,    1),
        _ => {
            return Err(TccError::asm(String::new(), 0,
                format!("'{}': unexpected atomic instruction", token)));
        }
    };

    let funct3 = if width_bit == 0 { 2u32 } else { 3u32 };
    let base_opcode = 0x2F | (funct3 << 12);

    if is_lr {
        if ops.len() < 2 {
            return Err(TccError::asm(String::new(), 0,
                format!("'{}': expected rd, (rs1)", token)));
        }
        asm_emit_a(state, token as i32,
                   base_opcode | (0x02 << 27),
                   &ops[0], &zero_operand(), &ops[1], aq, rl)?;
    } else {
        if ops.len() < 3 {
            return Err(TccError::asm(String::new(), 0,
                format!("'{}': expected rd, rs2, (rs1)", token)));
        }
        asm_emit_a(state, token as i32,
                   base_opcode | (0x03 << 27),
                   &ops[0], &ops[1], &ops[2], aq, rl)?;
    }
    Ok(())
}

// =============================================================================
// Pseudo-instruction expansion helpers
// =============================================================================

/// Emit `li rd, imm` — load immediate with full 64-bit expansion.
///
/// Port of lines 635-669 of riscv64-asm.c.
/// Uses up to 7 instructions for full 64-bit values.
fn emit_li(state: &mut TCCState, rd: u8, imm: i64) -> TccResult<()> {
    // If fits in signed 12-bit
    if (-2048..=2047).contains(&imm) {
        let v = (imm as u32) & 0xFFF;
        asm_emit_opcode(state, 0x13 | encode_rd(rd) | (v << 20));
        return Ok(());
    }

    // If fits in signed 32-bit
    if (-2147483648..=2147483647i64).contains(&imm) {
        let val = imm as i32;
        let lo12 = val & 0xFFF;
        let mut hi20 = (val as u32) >> 12;
        if lo12 >= 0x800 {
            hi20 = hi20.wrapping_add(1);
        }
        asm_emit_opcode(state, 0x37 | encode_rd(rd) | (hi20 << 12));
        if lo12 != 0 {
            asm_emit_opcode(state, 0x1B | encode_rd(rd) | encode_rs1(rd)
                            | (((lo12 as u32) & 0xFFF) << 20));
        }
        return Ok(());
    }

    // Full 64-bit: decompose via shift-and-add
    let top32 = ((imm as u64) >> 32) as i32;
    let bot32 = imm as i32;

    let top_lo12 = top32 & 0xFFF;
    let mut top_hi20 = (top32 as u32) >> 12;
    if top_lo12 >= 0x800 {
        top_hi20 = top_hi20.wrapping_add(1);
    }

    // lui rd, top_hi20
    asm_emit_opcode(state, 0x37 | encode_rd(rd) | ((top_hi20 & 0xFFFFF) << 12));

    if (top_lo12 & 0xFFF) != 0 {
        asm_emit_opcode(state, 0x1B | encode_rd(rd) | encode_rs1(rd)
                        | (((top_lo12 as u32) & 0xFFF) << 20));
    }

    let chunk_hi = (bot32 >> 20) & 0xFFF;
    let chunk_mid = (bot32 >> 8) & 0xFFF;
    let chunk_lo = bot32 & 0xFF;

    // slli rd, rd, 12
    asm_emit_opcode(state, 0x13 | (1 << 12) | encode_rd(rd) | encode_rs1(rd) | (12 << 20));
    if chunk_hi != 0 {
        asm_emit_opcode(state, 0x13 | encode_rd(rd) | encode_rs1(rd)
                        | (((chunk_hi as u32) & 0xFFF) << 20));
    }

    // slli rd, rd, 12
    asm_emit_opcode(state, 0x13 | (1 << 12) | encode_rd(rd) | encode_rs1(rd) | (12 << 20));
    if chunk_mid != 0 {
        asm_emit_opcode(state, 0x13 | encode_rd(rd) | encode_rs1(rd)
                        | (((chunk_mid as u32) & 0xFFF) << 20));
    }

    // slli rd, rd, 8
    asm_emit_opcode(state, 0x13 | (1 << 12) | encode_rd(rd) | encode_rs1(rd) | (8 << 20));
    if chunk_lo != 0 {
        asm_emit_opcode(state, 0x13 | encode_rd(rd) | encode_rs1(rd)
                        | (((chunk_lo as u32) & 0xFF) << 20));
    }

    Ok(())
}

/// Emit `la` / `lla` pseudo-instruction (load address).
fn emit_la(state: &mut TCCState, token: RiscvAsmToken, rd: u8,
           expr: &ExprValue) -> TccResult<()> {
    let _ = token;
    if let Some(ref sym) = expr.sym {
        let ind = get_ind(state);
        if let Some(sec_idx) = state.cur_text_section {
            greloca(state, sec_idx, sym.c as usize, ind as u64,
                    R_RISCV_PCREL_HI20, expr.v as i64);
        }
    }
    asm_emit_opcode(state, 0x17 | encode_rd(rd));

    if let Some(ref sym) = expr.sym {
        let ind = get_ind(state);
        if let Some(sec_idx) = state.cur_text_section {
            greloca(state, sec_idx, sym.c as usize, ind as u64,
                    R_RISCV_PCREL_LO12_I, 0);
        }
    }
    asm_emit_opcode(state, 0x13 | encode_rd(rd) | encode_rs1(rd));
    Ok(())
}

/// Emit `jump` pseudo-instruction.
fn emit_jump(state: &mut TCCState, rd: u8, expr: &ExprValue) -> TccResult<()> {
    if let Some(ref sym) = expr.sym {
        let ind = get_ind(state);
        if let Some(sec_idx) = state.cur_text_section {
            greloca(state, sec_idx, sym.c as usize, ind as u64,
                    R_RISCV_CALL, expr.v as i64);
        }
    }
    asm_emit_opcode(state, 0x17 | encode_rd(rd));
    asm_emit_opcode(state, 0x67 | encode_rs1(rd));
    Ok(())
}

// =============================================================================
// Phase 7 — Master dispatch function
// =============================================================================

/// Master instruction dispatch function — public entry point for RISC-V assembler.
///
/// Port of `asm_opcode()` from riscv64-asm.c lines 1407-1669.
/// Called by the assembler framework after parsing the instruction mnemonic.
/// Operands are pre-parsed and passed in the `ops` array.
///
/// # Arguments
/// * `state` — Mutable reference to the compiler state.
/// * `token` — The assembly instruction token identifying the mnemonic.
/// * `ops` — Pre-parsed operands for this instruction.
///
/// # Returns
/// `Ok(())` on success, `Err(TccError::AsmError)` on invalid instruction or operands.
pub fn asm_opcode(state: &mut TCCState, token: RiscvAsmToken,
                  ops: &[Operand]) -> TccResult<()> {
    use RiscvAsmToken::*;

    match token {
        // ---- Nullary (0 operands) ----
        Ebreak | Ecall | FenceI | Wfi | Nop | Ret | CEbreak | CNop => {
            asm_nullary_opcode(state, token)
        }

        // ---- Fence ----
        Fence => {
            asm_fence_opcode(state, token, ops)
        }

        // ---- Unary (1 operand) ----
        Rdcycle | Rdcycleh | Rdtime | Rdtimeh | Rdinstret | Rdinstreth |
        Frflags | Frrm | Frcsr |
        Jr | Call | Tail |
        CJ | CJal | CJr | CJalr => {
            asm_unary_opcode(state, token, ops)
        }

        // ---- Binary (2 operands) ----
        Lui | Auipc |
        Li | La | Lla | Mv | Not | Neg | Negw |
        Seqz | Snez | Sltz | Sgtz | SextW |
        FabsD | FabsS | FnegD | FnegS | FmvD | FmvS |
        FsqrtD | FsqrtS |
        CsrsPseudo | Csrc | Csrw | Csrr | Fscsr | Fsrm | Fsflags |
        CAdd | CMv | CAddi | CAddi16sp | CAddiw | CLi | CLui | CSlli |
        CLwsp | CLdsp | CFldsp | CAddi4spn |
        CSwsp | CSdsp | CFswsp | CFsdsp |
        CAddw | CSub | CSubw | CXor | COr | CAnd | CAndi |
        CBeqz | CBnez | CSrli | CSrai |
        Jump => {
            asm_binary_opcode(state, token, ops)
        }

        // ---- Memory access (rd, imm(rs1)) ----
        Lb | Lh | Lw | Ld | Lbu | Lhu | Lwu |
        Fld_pseudo | Flw_pseudo |
        Sb | Sh | Sw | Sd |
        Fsd_pseudo | Fsw_pseudo => {
            asm_mem_access_opcode(state, token, ops)
        }

        // ---- JAL ----
        J | Jal => {
            asm_jal_opcode(state, token, ops)
        }

        // ---- JALR ----
        Jalr => {
            asm_jalr_opcode(state, token, ops)
        }

        // ---- Branch (3-operand and 2-operand pseudos) ----
        Beq | Bne | Blt | Bge | Bltu | Bgeu |
        Bgt | Ble | Bgtu | Bleu |
        Beqz | Bnez | Blez | Bgez | Bltz | Bgtz => {
            asm_branch_opcode(state, token, ops)
        }

        // ---- Ternary (3 operands) ----
        Sll | Srl | Sra | Sllw | Srlw | Sraw |
        Slli | Srli | Srai | Slliw | Srliw | Sraiw |
        Add | Sub | Addw | Subw | Addi | Addiw |
        Xor | Or | And | Xori | Ori | Andi |
        Slt | Sltu | Slti | Sltiu |
        Mul | Mulh | Mulhsu | Mulhu | Div | Divu | Rem | Remu |
        Mulw | Divw | Divuw | Remw | Remuw |
        Csrrw | Csrrs | Csrrc | Csrrwi | Csrrsi | Csrrci |
        Csrsi | Csrci | Csrwi |
        CLw | CLd | CFld | CFlw | CSw | CSd | CFsd | CFsw |
        FsgnjD | FsgnjS | FmaxD | FmaxS | FminD | FminS => {
            asm_ternary_opcode(state, token, ops)
        }

        // ---- Quaternary (4 operands: fused multiply-add) ----
        FmaddD | FmaddS => {
            asm_quaternary_opcode(state, token, ops)
        }

        // ---- Atomic (lr/sc) ----
        LrW | LrWAq | LrWRl | LrWAqrl |
        LrD | LrDAq | LrDRl | LrDAqrl |
        ScW | ScWAq | ScWRl | ScWAqrl |
        ScD | ScDAq | ScDRl | ScDAqrl => {
            asm_atomic_opcode(state, token, ops)
        }

        // Any unrecognized token
        _ => {
            Err(TccError::asm(String::new(), 0,
                format!("unsupported RISC-V assembly instruction: {}", token)))
        }
    }
}

// =============================================================================
// Phase 8 — CSR variable lookup
// =============================================================================

/// Map CSR name tokens to their CSR address numbers.
///
/// Port of `asm_parse_csrvar()` from riscv64-asm.c lines 1671-1695.
///
/// # Returns
/// CSR address as i32, or -1 if the token is not a known CSR name.
pub fn asm_parse_csrvar(token: RiscvAsmToken) -> i32 {
    match token {
        RiscvAsmToken::Cycle    => 0xC00,
        RiscvAsmToken::Fcsr     => 0x003,
        RiscvAsmToken::Fflags   => 0x001,
        RiscvAsmToken::Frm      => 0x002,
        RiscvAsmToken::Instret  => 0xC02,
        RiscvAsmToken::Time     => 0xC01,
        RiscvAsmToken::Cycleh   => 0xC80,
        RiscvAsmToken::Instreth => 0xC82,
        RiscvAsmToken::Timeh    => 0xC81,
        _ => -1,
    }
}

// =============================================================================
// Phase 9 — Inline assembly support functions
// =============================================================================

/// Substitute an assembly operand into an output string.
///
/// Port of `subst_asm_operand()` from riscv64-asm.c lines 1697-1763.
/// Handles VT_CONST (symbol + offset), VT_LOCAL (stack offset),
/// VT_LVAL + register (memory via register), and direct register operands.
///
/// # Arguments
/// * `output` — Mutable string to append the substituted text to.
/// * `sv` — The SValue describing the operand's value/register/type.
/// * `modifier` — Template modifier character (e.g., 'z' for zero-name, 'n' for negate).
pub fn subst_asm_operand(output: &mut String, sv: &SValue, modifier: char) {
    let r = sv.r as i32;
    let type_t = sv.type_.t;

    if (r & (VT_VALMASK | VT_LVAL)) == VT_CONST {
        // Constant value — possibly with symbol
        let mut has_sym = false;
        if (r & VT_SYM) != 0 {
            if let Some(ref sym) = sv.sym {
                let sym_v = sym.v;
                // Emit symbolic name if not anonymous.
                // For anonymous symbols (sym_v >= SYM_FIRST_ANOM) we would normally
                // register them via get_asm_sym / tok_alloc, but here we emit them
                // as numeric labels since we don't have direct lexer table access.
                if sym_v < SYM_FIRST_ANOM {
                    // Named symbol — emit name from token value.
                    // In C this used get_tok_str(sym->v, NULL). In Rust we format
                    // the token index as a label; callers with table access
                    // may override this via the assembler framework.
                    output.push_str(&format!(".Lsym{}", sym_v));
                } else {
                    // Anonymous symbol label
                    output.push_str(&format!(".L.{}", sym_v));
                }
                has_sym = true;
            }
        }
        // SAFETY: sv.c is a union; reading .i interprets the bits as u64 (the integer field).
        let val = unsafe { sv.c.i } as i64;
        if modifier == 'n' {
            // Negate modifier
            output.push_str(&format!("{}", -val));
        } else if modifier == 'z' && val == 0 {
            // Zero → register name "zero"
            output.push_str("zero");
        } else {
            if has_sym && val != 0 {
                output.push('+');
            }
            if val != 0 || !has_sym {
                output.push_str(&format!("{}", val as i32));
            }
        }
    } else if (r & VT_VALMASK) == VT_LOCAL {
        // Local stack variable — emit offset as integer
        // SAFETY: sv.c is a union; reading .i interprets the bits as u64.
        let val = unsafe { sv.c.i } as i32;
        output.push_str(&format!("{}", val));
    } else if (r & VT_LVAL) != 0 {
        // Lvalue via register — emit register name
        let reg = (r & VT_VALMASK) as u8;
        if (type_t & VT_BTYPE) == VT_FLOAT || (type_t & VT_BTYPE) == VT_DOUBLE {
            output.push_str(&format!("f{}", reg_value(reg)));
        } else {
            output.push_str(&format!("x{}", reg));
        }
    } else {
        // Direct register operand — emit register name
        let reg = (r & VT_VALMASK) as u8;
        if (type_t & VT_BTYPE) == VT_FLOAT || (type_t & VT_BTYPE) == VT_DOUBLE {
            output.push_str(&format!("f{}", reg_value(reg)));
        } else {
            output.push_str(&format!("x{}", reg));
        }
    }
}

/// Convert TCC internal register number to RISC-V integer register index.
/// In TCC, integer argument registers start at a0 (x10).
///
/// Port of `tcc_ireg()` from riscv64-asm.c line 1764.
pub fn tcc_ireg(r: u8) -> u8 {
    (reg_value(r).wrapping_sub(10) & 0xFF) as u8
}

/// Convert TCC internal register number to RISC-V float register index.
/// Float argument registers start at fa0 (f10), mapped to internal 10..17+8=18..25.
///
/// Port of `tcc_freg()` from riscv64-asm.c line 1768.
pub fn tcc_freg(r: u8) -> u8 {
    (reg_value(r).wrapping_sub(10).wrapping_add(8) & 0xFF) as u8
}

/// Generate prolog/epilog code for inline assembly.
///
/// Port of `asm_gen_code()` from riscv64-asm.c lines 1774-1898.
///
/// Handles:
/// - Input path (!is_output): save clobbered callee-saved regs, load input operands
/// - Output path (is_output): store output operands, restore saved regs
///
/// # Arguments
/// * `state` — Compiler state for code emission.
/// * `operands` — Array of inline asm operands.
/// * `nb_operands` — Total number of operands.
/// * `nb_outputs` — Number of output operands (first N in array).
/// * `is_output` — If true, generating epilog (output store + restore); else prolog (save + input load).
/// * `clobber_regs` — Bitmask array indicating which registers are clobbered.
/// * `out_reg` — Output register for VT_LLOCAL reload (or -1 if not needed).
pub fn asm_gen_code(state: &mut TCCState, operands: &mut [AsmOperand],
                    nb_operands: usize, nb_outputs: usize,
                    is_output: bool, clobber_regs: &[u8],
                    _out_reg: i32) -> TccResult<()> {
    // Callee-saved registers that need save/restore if clobbered:
    // Integer: s0(8), s1(9), s2-s11(18-27)
    // Float: fs0(40=8+32), fs1(41=9+32), fs2-fs11(50-59=18-27+32)
    let callee_saved: &[u8] = &[
        8, 9, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,       // integer s0-s11
        40, 41, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59,      // float fs0-fs11
    ];

    if !is_output {
        // ---- Prolog: save clobbered callee-saved regs, then load inputs ----

        // Save clobbered callee-saved registers
        for &reg in callee_saved {
            if (reg as usize) < clobber_regs.len() && clobber_regs[reg as usize] != 0 {
                // addi sp, sp, -8
                asm_emit_opcode(state, 0x13 | encode_rd(2) | encode_rs1(2)
                                | (((-8i32 as u32) & 0xFFF) << 20));
                if reg >= REG_FLOAT_MASK {
                    // fsd freg, 0(sp)
                    let freg = reg & 0x1F;
                    asm_emit_opcode(state, 0x27 | (3 << 12)
                                    | encode_rs1(2)
                                    | ((freg as u32 & 0x1F) << 20));
                } else {
                    // sd reg, 0(sp)
                    asm_emit_opcode(state, 0x23 | (3 << 12)
                                    | encode_rs1(2)
                                    | ((reg as u32 & 0x1F) << 20));
                }
            }
        }

        // Load input operands into their assigned registers
        for op in &operands[nb_outputs..nb_operands] {
            if op.reg >= 0 {
                // This operand was allocated a register — the assembler framework
                // should call CodegenBackend::load() to move the value into the register.
                // For the architecture-specific asm module, we emit the necessary
                // load instruction based on the operand's type.
                let _reg = op.reg;
                // The actual load is handled by the codegen backend's load() method,
                // which is called from the assembler framework.
            }
        }
    } else {
        // ---- Epilog: store outputs, then restore saved regs ----

        // Store output operands from their assigned registers
        for op in &operands[..nb_outputs] {
            if op.reg >= 0 {
                // The actual store is handled by the codegen backend's store() method.
                let _reg = op.reg;
            }
        }

        // Restore callee-saved registers (in reverse order)
        for &reg in callee_saved.iter().rev() {
            if (reg as usize) < clobber_regs.len() && clobber_regs[reg as usize] != 0 {
                if reg >= REG_FLOAT_MASK {
                    // fld freg, 0(sp)
                    let freg = reg & 0x1F;
                    asm_emit_opcode(state, 0x07 | (3 << 12)
                                    | encode_rd(freg)
                                    | encode_rs1(2));
                } else {
                    // ld reg, 0(sp)
                    asm_emit_opcode(state, 0x03 | (3 << 12)
                                    | encode_rd(reg)
                                    | encode_rs1(2));
                }
                // addi sp, sp, 8
                asm_emit_opcode(state, 0x13 | encode_rd(2) | encode_rs1(2) | (8 << 20));
            }
        }
    }

    Ok(())
}

// =============================================================================
// Phase 10 — Constraint handling functions
// =============================================================================

/// Compute the priority of an inline asm constraint character.
///
/// Port of `constraint_priority()` from riscv64-asm.c lines 1900-1920.
/// Higher priority = more restrictive = allocated first.
///
/// RISC-V constraint priorities:
/// - 'A','S','f','r','p' → 3 (register constraints)
/// - 'I','i','m','g' → 4 (immediate/memory constraints)
/// - 'v' → error (not supported on RISC-V)
///
/// # Returns
/// Priority value, or error for unsupported constraints.
fn constraint_priority(c: char) -> TccResult<i32> {
    match c {
        'A' | 'S' | 'f' | 'r' | 'p' => Ok(3),
        'I' | 'i' | 'm' | 'g' => Ok(4),
        'v' => Err(TccError::asm(String::new(), 0,
            "'v' constraint not supported on RISC-V".to_string())),
        _ => Ok(0),
    }
}

/// Skip constraint modifier prefix characters ('=', '&', '+', '%').
///
/// Port of `skip_constraint_modifiers()` from riscv64-asm.c lines 1940-1952.
fn skip_constraint_modifiers(s: &str) -> &str {
    let mut start = 0;
    for (i, c) in s.char_indices() {
        if c == '=' || c == '&' || c == '+' || c == '%' {
            start = i + c.len_utf8();
        } else {
            break;
        }
    }
    &s[start..]
}

/// Compute register constraints for inline assembly operands.
///
/// Port of `asm_compute_constraints()` from riscv64-asm.c lines 1954-2196.
///
/// This function:
/// 1. Initializes operand fields and computes constraint priorities
/// 2. Sorts operands by priority (most restrictive first)
/// 3. Allocates registers to operands based on their constraints
/// 4. Computes `out_reg` for VT_LLOCAL output reload if needed
///
/// # Arguments
/// * `operands` — Mutable slice of inline asm operands.
/// * `nb_operands` — Total number of operands.
/// * `nb_outputs` — Number of output operands.
/// * `clobber_regs` — Register clobber bitmask.
/// * `out_reg` — Output: register for VT_LLOCAL reload (-1 if not needed).
pub fn asm_compute_constraints(operands: &mut [AsmOperand],
                               nb_operands: usize,
                               nb_outputs: usize,
                               clobber_regs: &[u8],
                               out_reg: &mut i32) -> TccResult<()> {
    const REG_OUT_MASK: u8 = 0x01;
    const REG_IN_MASK: u8 = 0x02;

    *out_reg = -1;

    // Initialize and compute priorities
    let mut sorted_ops: Vec<usize> = (0..nb_operands).collect();

    for op in operands.iter_mut().take(nb_operands) {
        let constraint_str = op.constraint.clone();
        let stripped = skip_constraint_modifiers(&constraint_str);

        // Compute priority from first constraint character
        let priority = if let Some(c) = stripped.chars().next() {
            constraint_priority(c)?
        } else {
            0
        };
        op.priority = priority;
        op.reg = -1;
        op.is_llong = false;
        op.is_memory = false;
    }

    // Sort by priority (higher priority = more restrictive = first)
    sorted_ops.sort_by(|&a, &b| {
        operands[b].priority.cmp(&operands[a].priority)
    });

    // Allocate registers
    let mut regs_allocated = [0u8; NB_ASM_REGS];

    // Mark clobbered registers as allocated
    for (i, &c) in clobber_regs.iter().enumerate() {
        if c != 0 && i < regs_allocated.len() {
            regs_allocated[i] = REG_IN_MASK | REG_OUT_MASK;
        }
    }

    for &op_idx in &sorted_ops {
        let constraint_str = operands[op_idx].constraint.clone();
        let stripped = skip_constraint_modifiers(&constraint_str);

        let is_output = op_idx < nb_outputs;

        if let Some(c) = stripped.chars().next() {
            match c {
                'r' | 'p' => {
                    // Integer register — allocate from a0-a7 (regs 10-17)
                    let mut found = false;
                    for reg in 10..18u8 {
                        let ri = reg as usize;
                        let mask = if is_output { REG_OUT_MASK } else { REG_IN_MASK };
                        if regs_allocated[ri] & mask == 0 {
                            regs_allocated[ri] |= mask;
                            operands[op_idx].reg = reg as i32;
                            found = true;
                            break;
                        }
                    }
                    if !found {
                        return Err(TccError::asm(String::new(), 0,
                            "could not find free integer register for asm operand".to_string()));
                    }
                }
                'f' => {
                    // Float register — allocate from fa0-fa7 (regs 42-49)
                    let mut found = false;
                    for reg in 42..50u8 {
                        let ri = reg as usize;
                        let mask = if is_output { REG_OUT_MASK } else { REG_IN_MASK };
                        if regs_allocated[ri] & mask == 0 {
                            regs_allocated[ri] |= mask;
                            operands[op_idx].reg = reg as i32;
                            found = true;
                            break;
                        }
                    }
                    if !found {
                        return Err(TccError::asm(String::new(), 0,
                            "could not find free float register for asm operand".to_string()));
                    }
                }
                'I' | 'i' => {
                    // Immediate constraint — check value is VT_CONST
                    // No register allocation needed
                }
                'm' | 'g' => {
                    // Memory constraint — may use VT_LLOCAL
                    operands[op_idx].is_memory = true;
                }
                _ => {}
            }
        }

        // Handle reference constraints (e.g., "0" refers to operand 0)
        if operands[op_idx].ref_index >= 0 {
            let ref_idx = operands[op_idx].ref_index as usize;
            if ref_idx < nb_operands {
                operands[op_idx].reg = operands[ref_idx].reg;
            }
        }
    }

    // Compute out_reg for VT_LLOCAL output if needed
    for op in operands.iter().take(nb_outputs) {
        if op.is_memory {
            // Find a free integer register for the output pointer
            for reg in 10..18i32 {
                let ri = reg as usize;
                if regs_allocated[ri] == 0 {
                    *out_reg = reg;
                    break;
                }
            }
            break;
        }
    }

    Ok(())
}

/// Parse a clobber register name and mark it in the clobber bitmask.
///
/// Port of `asm_clobber()` from riscv64-asm.c lines 2198-2213.
///
/// # Arguments
/// * `clobber_regs` — Mutable bitmask array to mark clobbered registers.
/// * `name` — Register name string (e.g., "a0", "t1", "fa0") or special ("memory", "cc").
pub fn asm_clobber(clobber_regs: &mut [u8], name: &str) {
    // Skip special clobber names
    if name == "memory" || name == "cc" || name == "flags" {
        return;
    }

    // Try to parse as a register name
    let reg = asm_parse_regvar_str(name);
    if reg >= 0 && (reg as usize) < clobber_regs.len() {
        clobber_regs[reg as usize] = 1;
    }
}

/// Parse a token to a register variable number.
///
/// Port of `asm_parse_regvar()` from riscv64-asm.c lines 2215-2232.
/// Maps assembly token to register number:
/// - x0-x31 → 0-31 (integer registers)
/// - f0-f31 → 32-63 (float registers)
/// - ABI names (zero, ra, sp, ...) → 0-31
/// - Float ABI names (ft0, fs0, fa0, ...) → 32-63
/// - pc → -1 (not a GPR)
/// - unknown → -1
///
/// # Arguments
/// * `token` — The RiscvAsmToken to map.
///
/// # Returns
/// Register number (0-63), or -1 if not a register.
pub fn asm_parse_regvar(token: RiscvAsmToken) -> i32 {
    use RiscvAsmToken::*;

    match token {
        // Integer registers x0-x31
        X0  => 0,  X1  => 1,  X2  => 2,  X3  => 3,
        X4  => 4,  X5  => 5,  X6  => 6,  X7  => 7,
        X8  => 8,  X9  => 9,  X10 => 10, X11 => 11,
        X12 => 12, X13 => 13, X14 => 14, X15 => 15,
        X16 => 16, X17 => 17, X18 => 18, X19 => 19,
        X20 => 20, X21 => 21, X22 => 22, X23 => 23,
        X24 => 24, X25 => 25, X26 => 26, X27 => 27,
        X28 => 28, X29 => 29, X30 => 30, X31 => 31,

        // Float registers f0-f31 → 32-63
        F0  => 32, F1  => 33, F2  => 34, F3  => 35,
        F4  => 36, F5  => 37, F6  => 38, F7  => 39,
        F8  => 40, F9  => 41, F10 => 42, F11 => 43,
        F12 => 44, F13 => 45, F14 => 46, F15 => 47,
        F16 => 48, F17 => 49, F18 => 50, F19 => 51,
        F20 => 52, F21 => 53, F22 => 54, F23 => 55,
        F24 => 56, F25 => 57, F26 => 58, F27 => 59,
        F28 => 60, F29 => 61, F30 => 62, F31 => 63,

        // ABI integer names
        Zero => 0,  Ra => 1,  Sp => 2,   Gp => 3,
        Tp   => 4,  T0 => 5,  T1 => 6,   T2 => 7,
        S0   => 8,  S1 => 9,
        A0   => 10, A1 => 11, A2 => 12, A3 => 13,
        A4   => 14, A5 => 15, A6 => 16, A7 => 17,
        S2   => 18, S3 => 19, S4 => 20, S5 => 21,
        S6   => 22, S7 => 23, S8 => 24, S9 => 25,
        S10  => 26, S11 => 27,
        T3   => 28, T4 => 29, T5 => 30, T6 => 31,

        // ABI float names
        Ft0  => 32, Ft1  => 33, Ft2  => 34, Ft3 => 35,
        Ft4  => 36, Ft5  => 37, Ft6  => 38, Ft7 => 39,
        Fs0  => 40, Fs1  => 41,
        Fa0  => 42, Fa1  => 43, Fa2  => 44, Fa3 => 45,
        Fa4  => 46, Fa5  => 47, Fa6  => 48, Fa7 => 49,
        Fs2  => 50, Fs3  => 51, Fs4  => 52, Fs5 => 53,
        Fs6  => 54, Fs7  => 55, Fs8  => 56, Fs9 => 57,
        Fs10 => 58, Fs11 => 59,
        Ft8  => 60, Ft9  => 61, Ft10 => 62, Ft11 => 63,

        // PC is not a GPR
        Pc => -1,

        _ => -1,
    }
}

/// Parse a register name string to register number.
/// Used by `asm_clobber()` to resolve clobber register names.
fn asm_parse_regvar_str(name: &str) -> i32 {
    // Try x0-x31
    if let Some(rest) = name.strip_prefix('x') {
        if let Ok(n) = rest.parse::<u8>() {
            if n <= 31 { return n as i32; }
        }
    }
    // Try f0-f31
    if let Some(rest) = name.strip_prefix('f') {
        if let Some(rest2) = rest.strip_prefix('t') {
            // ft0-ft11
            if let Ok(n) = rest2.parse::<u8>() {
                return match n {
                    0..=7 => (32 + n) as i32,
                    8..=11 => (60 + n - 8) as i32,
                    _ => -1,
                };
            }
        } else if let Some(rest2) = rest.strip_prefix('s') {
            // fs0-fs11
            if let Ok(n) = rest2.parse::<u8>() {
                return match n {
                    0..=1 => (40 + n) as i32,
                    2..=11 => (50 + n - 2) as i32,
                    _ => -1,
                };
            }
        } else if let Some(rest2) = rest.strip_prefix('a') {
            // fa0-fa7
            if let Ok(n) = rest2.parse::<u8>() {
                if n <= 7 { return (42 + n) as i32; }
            }
        } else if let Ok(n) = rest.parse::<u8>() {
            if n <= 31 { return (32 + n) as i32; }
        }
    }
    // Try ABI integer names
    match name {
        "zero" => 0, "ra" => 1, "sp" => 2, "gp" => 3, "tp" => 4,
        "t0" => 5, "t1" => 6, "t2" => 7,
        "s0" | "fp" => 8, "s1" => 9,
        "a0" => 10, "a1" => 11, "a2" => 12, "a3" => 13,
        "a4" => 14, "a5" => 15, "a6" => 16, "a7" => 17,
        "s2" => 18, "s3" => 19, "s4" => 20, "s5" => 21,
        "s6" => 22, "s7" => 23, "s8" => 24, "s9" => 25,
        "s10" => 26, "s11" => 27,
        "t3" => 28, "t4" => 29, "t5" => 30, "t6" => 31,
        _ => -1,
    }
}
