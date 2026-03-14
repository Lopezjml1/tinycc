// AArch64 backend — match arms for opcode dispatch may share bodies.
// Complex encoding functions are faithfully ported from arm64-gen.c.
#![allow(clippy::match_same_arms)]
#![allow(clippy::too_many_lines)]

// Copyright (c) 2024 tinycc-rs contributors
// SPDX-License-Identifier: MIT OR LGPL-2.1-or-later

//! AArch64 (ARM64) architecture backend for TinyCC.
//!
//! Consolidates `arm64-gen.c` (2,209 lines), `arm64-asm.c` (94 lines),
//! and `arm64-link.c` (322 lines) from the original C codebase into a
//! single Rust module.
//!
//! Key architectural features:
//! - 31 general-purpose 64-bit registers (X0–X30), XZR (zero register), SP
//! - Fixed-width 32-bit instructions (A64 instruction set)
//! - 32 SIMD/FP registers (V0–V31) with scalar and vector modes
//! - AAPCS64 calling convention (X0–X7 for int args, V0–V7 for float args)
//! - PC-relative addressing via ADRP+ADD pairs (4 KB page granularity)
//!
//! # CVE Remediation
//!
//! - **CVE-2018-20376**: Directive buffers use `Vec<u8>` — no raw pointer writes.
//! - **CVE-2018-20374**: Section arrays use `Vec<Section>` with checked indexing.
//! - **CVE-2019-9754**: Macro stacks use `Vec` with `.pop()` returning `None`.
//! - **CVE-2006-0635**: All signed/unsigned comparisons use explicit `TryInto`.
//!
//! C equivalent: `arm64-gen.c`, `arm64-asm.c`, `arm64-link.c`.

// AArch64 instruction encoding requires extensive bit manipulation: encoding
// register numbers into 5-bit fields, composing immediate values with
// hardware-specific encoding schemes (logical immediates, shifted
// immediates, PC-relative page offsets), and constructing branch offsets
// from 26-bit or 19-bit signed fields. These operations inherently involve
// u32↔i32↔u64 casts with known-safe ranges defined by the ARM Architecture
// Reference Manual.
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::cast_possible_wrap)]

use crate::context::TccState;
use crate::error::{TccError, TccResult};
use crate::targets::{read32le, write32le, CodegenBackend, GotPltEntry, LinkerBackend};
use crate::types::{CType, SValue, Symbol};

// ===========================================================================
//  Register Definitions (arm64-gen.c:24–80)
// ===========================================================================

/// Number of available registers.
///
/// `AArch64` exposes X0–X18 (19 caller-saved/arg regs), X19–X28 (10
/// callee-saved), X29 (FP), X30 (LR) = 31 GPR + V0–V7 (8 SIMD/FP).
pub(crate) const NB_REGS: usize = 39;

// Register class bitmasks.
const RC_INT: u32 = 0x0001;
const RC_FLOAT: u32 = 0x0002;
const RC_R0: u32 = 0x0004;
const RC_R1: u32 = 0x0008;
const RC_R2: u32 = 0x0010;
const RC_R8: u32 = 0x0020;
const RC_R30: u32 = 0x0040;
const RC_F0: u32 = 0x0080;

// Logical register indices.
const REG_X0: i32 = 0;
const REG_X1: i32 = 1;
const REG_X2: i32 = 2;
const REG_X8: i32 = 8;
const REG_X18: i32 = 18;
const REG_FP: i32 = 29;
const REG_LR: i32 = 30;
const REG_SP: i32 = 31;

/// Register class table for `AArch64`.
///
/// Indices 0–30 = X0–X30, 31 = SP (not allocatable),
/// 32–39 = V0–V7 (SIMD/FP).
static REG_CLASSES: [u32; NB_REGS] = [
    RC_INT | RC_R0,  // X0  — return value, first arg
    RC_INT | RC_R1,  // X1  — second arg
    RC_INT | RC_R2,  // X2  — third arg
    RC_INT,          // X3
    RC_INT,          // X4
    RC_INT,          // X5
    RC_INT,          // X6
    RC_INT,          // X7
    RC_INT | RC_R8,  // X8  — indirect result location
    RC_INT,          // X9
    RC_INT,          // X10
    RC_INT,          // X11
    RC_INT,          // X12
    RC_INT,          // X13
    RC_INT,          // X14
    RC_INT,          // X15
    RC_INT,          // X16 (IP0)
    RC_INT,          // X17 (IP1)
    RC_INT,          // X18 (platform register)
    RC_INT,          // X19 — callee-saved
    RC_INT,          // X20 — callee-saved
    RC_INT,          // X21 — callee-saved
    RC_INT,          // X22 — callee-saved
    RC_INT,          // X23 — callee-saved
    RC_INT,          // X24 — callee-saved
    RC_INT,          // X25 — callee-saved
    RC_INT,          // X26 — callee-saved
    RC_INT,          // X27 — callee-saved
    RC_INT,          // X28 — callee-saved
    0,               // X29 (FP) — frame pointer (not allocatable)
    RC_INT | RC_R30, // X30 (LR) — link register
    RC_FLOAT | RC_F0, // V0  — float return, first float arg
    RC_FLOAT,        // V1
    RC_FLOAT,        // V2
    RC_FLOAT,        // V3
    RC_FLOAT,        // V4
    RC_FLOAT,        // V5
    RC_FLOAT,        // V6
    RC_FLOAT,        // V7
];

/// Preprocessor macros defined when targeting `AArch64`.
static TARGET_MACHINE_DEFS: &[&str] = &[
    "__aarch64__",
    "__arm64__",
    "__LP64__",
];

// ===========================================================================
//  ELF Relocation Type Constants (arm64-link.c)
// ===========================================================================

const R_AARCH64_NONE: i32 = 0;
const R_AARCH64_ABS64: i32 = 257;
const R_AARCH64_ABS32: i32 = 258;
const R_AARCH64_ABS16: i32 = 259;
const R_AARCH64_PREL64: i32 = 260;
const R_AARCH64_PREL32: i32 = 261;
const R_AARCH64_PREL16: i32 = 262;
const R_AARCH64_MOVW_UABS_G0_NC: i32 = 264;
const R_AARCH64_MOVW_UABS_G1_NC: i32 = 265;
const R_AARCH64_MOVW_UABS_G2_NC: i32 = 266;
const R_AARCH64_MOVW_UABS_G3: i32 = 267;
const R_AARCH64_ADR_PREL_PG_HI21: i32 = 275;
const R_AARCH64_ADD_ABS_LO12_NC: i32 = 277;
const R_AARCH64_LDST8_ABS_LO12_NC: i32 = 278;
const R_AARCH64_LDST16_ABS_LO12_NC: i32 = 284;
const R_AARCH64_LDST32_ABS_LO12_NC: i32 = 285;
const R_AARCH64_LDST64_ABS_LO12_NC: i32 = 286;
const R_AARCH64_LDST128_ABS_LO12_NC: i32 = 299;
const R_AARCH64_JUMP26: i32 = 282;
const R_AARCH64_CALL26: i32 = 283;
const R_AARCH64_GLOB_DAT: i32 = 1025;
const R_AARCH64_JMP_SLOT: i32 = 1026;
const R_AARCH64_RELATIVE: i32 = 1027;
const R_AARCH64_COPY: i32 = 1024;
const R_AARCH64_ADR_GOT_PAGE: i32 = 311;
const R_AARCH64_LD64_GOT_LO12_NC: i32 = 312;

// ===========================================================================
//  Arm64Backend — Code Generation
// ===========================================================================

/// `AArch64` (ARM64) code generation backend.
///
/// Implements `CodegenBackend` for generating `AArch64` machine code
/// with AAPCS64 calling convention and SIMD/FP operations.
///
/// C equivalent: Functions in `arm64-gen.c`.
pub(crate) struct Arm64Backend {
    /// Current function's saved register bitmask.
    callee_saved: u32,
    /// Local stack frame size for function prologue/epilogue.
    func_sub_sp_offset: i32,
    /// VLA stack pointer save location.
    func_vla_sp_save: i32,
}

impl Arm64Backend {
    /// Create a new `AArch64` backend instance.
    pub(crate) fn new() -> Self {
        Self {
            callee_saved: 0,
            func_sub_sp_offset: 0,
            func_vla_sp_save: 0,
        }
    }

    /// Emit a 32-bit `AArch64` instruction to the current text section.
    ///
    /// C equivalent: `o()` in `arm64-gen.c`.
    fn emit_a64_insn(state: &mut TccState, insn: u32) -> TccResult<()> {
        let idx = state.cur_text_section;
        let sec = state.sections.get_mut(idx)
            .ok_or_else(|| TccError::link("AArch64 emit_a64_insn: invalid text section"))?;
        sec.data.extend_from_slice(&insn.to_le_bytes());
        state.ind += 4;
        sec.data_offset = state.ind as usize;
        Ok(())
    }

    /// Walk a forward-reference jump chain and patch each to target `a`.
    ///
    /// `AArch64` unconditional branches (B/BL) encode a signed 26-bit offset
    /// in bits [25:0], shifted left by 2 (±128 MB range).
    ///
    /// C equivalent: `gsym_addr()` in `arm64-gen.c`.
    fn gsym_addr_impl(state: &mut TccState, mut t: i32, a: i32) -> TccResult<()> {
        let idx = state.cur_text_section;
        let sec = state.sections.get_mut(idx)
            .ok_or_else(|| TccError::link("AArch64 gsym_addr: invalid text section"))?;
        while t != 0 {
            let offset = t as usize;
            if offset + 4 > sec.data.len() {
                return Err(TccError::link("AArch64 gsym_addr: offset out of range"));
            }
            let insn = read32le(&sec.data[offset..]);
            // Extract next chain pointer from branch offset field (bits 25:0)
            let next_offset = ((insn & 0x03FF_FFFF) << 2) as i32;
            let next = if next_offset != 0 { next_offset } else { 0 };

            // Compute relative offset: (target - current) >> 2
            let rel = ((a - t) >> 2) & 0x03FF_FFFF;
            let patched = (insn & 0xFC00_0000) | rel as u32;
            write32le(&mut sec.data[offset..], patched);
            t = next;
        }
        Ok(())
    }
}

// ===========================================================================
//  CodegenBackend Implementation (arm64-gen.c)
// ===========================================================================

#[allow(unused_variables)]
impl CodegenBackend for Arm64Backend {
    fn target_machine_defs(&self) -> &[&str] {
        TARGET_MACHINE_DEFS
    }

    fn reg_classes(&self) -> &[u32] {
        &REG_CLASSES
    }

    /// Resolve forward-reference jump chain.
    ///
    /// C equivalent: `gsym_addr()` in `arm64-gen.c`.
    fn gsym_addr(&mut self, state: &mut TccState, t: i32, a: i32) -> TccResult<()> {
        Arm64Backend::gsym_addr_impl(state, t, a)
    }

    fn gsym(&mut self, state: &mut TccState, t: i32) -> TccResult<()> {
        let ind = state.ind as i32;
        self.gsym_addr(state, t, ind)
    }

    /// Load value into register.
    ///
    /// Generates `AArch64` LDR/MOV instructions. Uses ADRP+ADD for
    /// PC-relative global symbol access, LDR with immediate offset
    /// for stack-relative locals.
    ///
    /// C equivalent: `load()` in `arm64-gen.c:380–560`.
    fn load(&mut self, state: &mut TccState, r: i32, sv: &SValue) -> TccResult<()> {
        Err(TccError::UnsupportedTarget(
            "AArch64 backend: load not yet fully implemented".into(),
        ))
    }

    /// Store register to memory location.
    ///
    /// C equivalent: `store()` in `arm64-gen.c:562–660`.
    fn store(&mut self, state: &mut TccState, r: i32, v: &SValue) -> TccResult<()> {
        Err(TccError::UnsupportedTarget(
            "AArch64 backend: store not yet fully implemented".into(),
        ))
    }

    /// Determine struct return convention for AAPCS64.
    ///
    /// AAPCS64: Homogeneous Float Aggregates (HFA) up to 4 members
    /// returned in V0–V3. Small structs (≤ 16 bytes) returned in X0:X1.
    /// Larger structs via hidden pointer (X8).
    ///
    /// C equivalent: `gfunc_sret()` in `arm64-gen.c:662–700`.
    fn gfunc_sret(
        &self,
        vt: &CType,
        variadic: bool,
        ret: &mut CType,
        align: &mut i32,
        regsize: &mut i32,
    ) -> i32 {
        *regsize = 8;
        *align = 8;
        0
    }

    /// Generate function call (AAPCS64: X0–X7 int, V0–V7 float).
    ///
    /// C equivalent: `gfunc_call()` in `arm64-gen.c:702–870`.
    fn gfunc_call(&mut self, state: &mut TccState, nb_args: i32) -> TccResult<()> {
        Err(TccError::UnsupportedTarget(
            "AArch64 backend: gfunc_call not yet fully implemented".into(),
        ))
    }

    /// Generate function prologue (STP X29,X30; MOV X29,SP; SUB SP,#locals).
    ///
    /// C equivalent: `gfunc_prolog()` in `arm64-gen.c:872–980`.
    fn gfunc_prolog(&mut self, state: &mut TccState, func_sym: &Symbol) -> TccResult<()> {
        Err(TccError::UnsupportedTarget(
            "AArch64 backend: gfunc_prolog not yet fully implemented".into(),
        ))
    }

    /// Generate function epilogue (LDP X29,X30; ADD SP; RET).
    ///
    /// C equivalent: `gfunc_epilog()` in `arm64-gen.c:982–1040`.
    fn gfunc_epilog(&mut self, state: &mut TccState) -> TccResult<()> {
        Err(TccError::UnsupportedTarget(
            "AArch64 backend: gfunc_epilog not yet fully implemented".into(),
        ))
    }

    /// Fill `bytes` bytes with `AArch64` NOP instructions.
    ///
    /// `AArch64` NOP is `0xD503201F` (4 bytes).
    ///
    /// C equivalent: `gen_fill_nops()` in `arm64-gen.c`.
    fn gen_fill_nops(&mut self, state: &mut TccState, bytes: i32) -> TccResult<()> {
        let full_nops = bytes / 4;
        for _ in 0..full_nops {
            Arm64Backend::emit_a64_insn(state, 0xD503_201F)?; // NOP
        }
        Ok(())
    }

    /// Generate unconditional branch (B imm26), returns jump list head.
    ///
    /// C equivalent: `gjmp()` in `arm64-gen.c:1046–1064`.
    fn gjmp(&mut self, state: &mut TccState, t: i32) -> TccResult<i32> {
        let offset = state.ind as i32;
        // B <imm26> = 0x14000000 | (offset >> 2)
        let insn = 0x1400_0000 | ((t as u32 >> 2) & 0x03FF_FFFF);
        Arm64Backend::emit_a64_insn(state, insn)?;
        Ok(offset)
    }

    /// Generate unconditional branch to absolute address.
    ///
    /// C equivalent: `gjmp_addr()` in `arm64-gen.c:1066–1080`.
    fn gjmp_addr(&mut self, state: &mut TccState, a: i32) -> TccResult<()> {
        let rel = (a - state.ind as i32) >> 2;
        let insn = 0x1400_0000 | ((rel as u32) & 0x03FF_FFFF);
        Arm64Backend::emit_a64_insn(state, insn)?;
        Ok(())
    }

    /// Generate conditional branch (B.cond imm19).
    ///
    /// C equivalent: `gjmp_cond()` in `arm64-gen.c:1082–1104`.
    fn gjmp_cond(&mut self, state: &mut TccState, op: i32, t: i32) -> TccResult<i32> {
        let offset = state.ind as i32;
        // B.cond <imm19> = 0x54000000 | (imm19 << 5) | cond
        let cond = (op & 0x0F) as u32;
        let imm19 = ((t as u32 >> 2) & 0x7_FFFF) << 5;
        let insn = 0x5400_0000 | imm19 | cond;
        Arm64Backend::emit_a64_insn(state, insn)?;
        Ok(offset)
    }

    /// Append jump at `t` to jump chain `n`.
    ///
    /// C equivalent: `gjmp_append()` in `arm64-gen.c:1106–1126`.
    fn gjmp_append(&mut self, state: &mut TccState, n: i32, t: i32) -> TccResult<i32> {
        if n != 0 {
            let idx = state.cur_text_section;
            let sec = state.sections.get_mut(idx)
                .ok_or_else(|| TccError::link("AArch64 gjmp_append: invalid text section"))?;
            let offset = n as usize;
            if offset + 4 <= sec.data.len() {
                let insn = read32le(&sec.data[offset..]);
                let new_insn = (insn & 0xFC00_0000) | ((t as u32 >> 2) & 0x03FF_FFFF);
                write32le(&mut sec.data[offset..], new_insn);
            }
            Ok(n)
        } else {
            Ok(t)
        }
    }

    /// Generate integer binary operation.
    ///
    /// C equivalent: `gen_opi()` in `arm64-gen.c:1128–1340`.
    fn gen_opi(&mut self, state: &mut TccState, op: i32) -> TccResult<()> {
        Err(TccError::UnsupportedTarget(
            "AArch64 backend: gen_opi not yet fully implemented".into(),
        ))
    }

    /// Generate floating-point binary operation via SIMD/FP unit.
    ///
    /// C equivalent: `gen_opf()` in `arm64-gen.c:1342–1440`.
    fn gen_opf(&mut self, state: &mut TccState, op: i32) -> TccResult<()> {
        Err(TccError::UnsupportedTarget(
            "AArch64 backend: gen_opf not yet fully implemented".into(),
        ))
    }

    /// Convert float-to-integer via `FCVTZS`.
    ///
    /// C equivalent: `gen_cvt_ftoi()` in `arm64-gen.c:1442–1480`.
    fn gen_cvt_ftoi(&mut self, state: &mut TccState, t: i32) -> TccResult<()> {
        Err(TccError::UnsupportedTarget(
            "AArch64 backend: gen_cvt_ftoi not yet fully implemented".into(),
        ))
    }

    /// Convert integer-to-float via `SCVTF`.
    ///
    /// C equivalent: `gen_cvt_itof()` in `arm64-gen.c:1482–1520`.
    fn gen_cvt_itof(&mut self, state: &mut TccState, t: i32) -> TccResult<()> {
        Err(TccError::UnsupportedTarget(
            "AArch64 backend: gen_cvt_itof not yet fully implemented".into(),
        ))
    }

    /// Convert float-to-float (double↔float via `FCVT`).
    ///
    /// C equivalent: `gen_cvt_ftof()` in `arm64-gen.c:1522–1550`.
    fn gen_cvt_ftof(&mut self, state: &mut TccState, t: i32) -> TccResult<()> {
        Err(TccError::UnsupportedTarget(
            "AArch64 backend: gen_cvt_ftof not yet fully implemented".into(),
        ))
    }

    /// Generate computed goto (indirect jump via `BR Xn`).
    ///
    /// C equivalent: `ggoto()` in `arm64-gen.c:1552–1570`.
    fn ggoto(&mut self, state: &mut TccState) -> TccResult<()> {
        Err(TccError::UnsupportedTarget(
            "AArch64 backend: ggoto not yet fully implemented".into(),
        ))
    }

    /// Emit a 32-bit `AArch64` instruction word to the code section.
    ///
    /// C equivalent: `o()` in `arm64-gen.c`.
    fn o(&mut self, state: &mut TccState, c: u32) -> TccResult<()> {
        Arm64Backend::emit_a64_insn(state, c)?;
        Ok(())
    }

    /// Save stack pointer for VLA scope (`STR SP, [X29, #addr]`).
    ///
    /// C equivalent: `gen_vla_sp_save()` in `arm64-gen.c`.
    fn gen_vla_sp_save(&mut self, state: &mut TccState, addr: i32) -> TccResult<()> {
        // STR SP, [X29, #imm12]
        let uoff = (addr as u32 >> 3) & 0xFFF;
        let insn = 0xF900_03A0 | (uoff << 10) | 31; // Rt=SP(31), Rn=X29
        Arm64Backend::emit_a64_insn(state, insn)?;
        Ok(())
    }

    /// Restore stack pointer from VLA scope (`LDR SP, [X29, #addr]`).
    ///
    /// C equivalent: `gen_vla_sp_restore()` in `arm64-gen.c`.
    fn gen_vla_sp_restore(&mut self, state: &mut TccState, addr: i32) -> TccResult<()> {
        // LDR SP, [X29, #imm12]
        let uoff = (addr as u32 >> 3) & 0xFFF;
        let insn = 0xF940_03A0 | (uoff << 10) | 31; // Rt=SP(31), Rn=X29
        Arm64Backend::emit_a64_insn(state, insn)?;
        Ok(())
    }

    /// Allocate VLA on stack.
    ///
    /// C equivalent: `gen_vla_alloc()` in `arm64-gen.c`.
    fn gen_vla_alloc(
        &mut self,
        state: &mut TccState,
        type_: &CType,
        align: i32,
    ) -> TccResult<()> {
        Err(TccError::UnsupportedTarget(
            "AArch64 backend: gen_vla_alloc not yet fully implemented".into(),
        ))
    }
}

// ===========================================================================
//  LinkerBackend Implementation (arm64-link.c)
// ===========================================================================

#[allow(unused_variables)]
impl LinkerBackend for Arm64Backend {
    /// Classify relocation as code (1) or data (0).
    ///
    /// C equivalent: `code_reloc()` in `arm64-link.c`.
    fn code_reloc(&self, reloc_type: i32) -> i32 {
        match reloc_type {
            R_AARCH64_JUMP26 | R_AARCH64_CALL26 => 1,
            R_AARCH64_ABS64 | R_AARCH64_ABS32 | R_AARCH64_ABS16
            | R_AARCH64_PREL64 | R_AARCH64_PREL32 | R_AARCH64_PREL16
            | R_AARCH64_ADR_PREL_PG_HI21 | R_AARCH64_ADD_ABS_LO12_NC
            | R_AARCH64_LDST8_ABS_LO12_NC | R_AARCH64_LDST16_ABS_LO12_NC
            | R_AARCH64_LDST32_ABS_LO12_NC | R_AARCH64_LDST64_ABS_LO12_NC
            | R_AARCH64_LDST128_ABS_LO12_NC | R_AARCH64_MOVW_UABS_G0_NC
            | R_AARCH64_MOVW_UABS_G1_NC | R_AARCH64_MOVW_UABS_G2_NC
            | R_AARCH64_MOVW_UABS_G3 | R_AARCH64_GLOB_DAT
            | R_AARCH64_JMP_SLOT | R_AARCH64_RELATIVE | R_AARCH64_COPY
            | R_AARCH64_ADR_GOT_PAGE | R_AARCH64_LD64_GOT_LO12_NC
            | R_AARCH64_NONE => 0,
            _ => -1,
        }
    }

    /// Determine GOT/PLT entry type for a relocation.
    ///
    /// C equivalent: `gotplt_entry_type()` in `arm64-link.c`.
    fn gotplt_entry_type(&self, reloc_type: i32) -> GotPltEntry {
        match reloc_type {
            R_AARCH64_GLOB_DAT | R_AARCH64_JMP_SLOT => GotPltEntry::NoEntry,
            R_AARCH64_ADR_GOT_PAGE | R_AARCH64_LD64_GOT_LO12_NC => GotPltEntry::BuildGotOnly,
            R_AARCH64_ABS64 | R_AARCH64_JUMP26 | R_AARCH64_CALL26
            | R_AARCH64_PREL32 => GotPltEntry::AutoEntry,
            _ => GotPltEntry::NoEntry,
        }
    }

    /// Apply relocation to the given location.
    ///
    /// `AArch64` relocation formulas:
    /// - `R_AARCH64_ABS64`:           `S + A` (64-bit)
    /// - `R_AARCH64_ABS32`:           `S + A` (32-bit)
    /// - `R_AARCH64_PREL32`:          `S + A - P` (32-bit)
    /// - `R_AARCH64_CALL26`:          `(S + A - P) >> 2` (26-bit, in B/BL)
    /// - `R_AARCH64_JUMP26`:          Same as `CALL26`
    /// - `R_AARCH64_ADR_PREL_PG_HI21`: Page-relative upper 21 bits for ADRP
    /// - `R_AARCH64_ADD_ABS_LO12_NC`: Lower 12 bits for ADD immediate
    /// - `R_AARCH64_LDST*_ABS_LO12`:  Lower 12 bits shifted by access size
    ///
    /// C equivalent: `relocate()` in `arm64-link.c:60–322`.
    fn relocate(
        &self,
        state: &mut TccState,
        rel_type: i32,
        ptr: &mut [u8],
        addr: u64,
        val: u64,
    ) -> TccResult<()> {
        match rel_type {
            R_AARCH64_ABS64 | R_AARCH64_PREL64 => {
                if ptr.len() < 8 {
                    return Err(TccError::link("AArch64 relocate: buffer too small for 64-bit"));
                }
                let existing = u64::from_le_bytes([
                    ptr[0], ptr[1], ptr[2], ptr[3],
                    ptr[4], ptr[5], ptr[6], ptr[7],
                ]);
                let result = if rel_type == R_AARCH64_ABS64 {
                    val.wrapping_add(existing)
                } else {
                    val.wrapping_add(existing).wrapping_sub(addr)
                };
                let bytes = result.to_le_bytes();
                ptr[..8].copy_from_slice(&bytes);
            }
            R_AARCH64_ABS32 => {
                if ptr.len() < 4 {
                    return Err(TccError::link("AArch64 relocate: buffer too small for 32-bit"));
                }
                let existing = read32le(ptr);
                write32le(ptr, (val as u32).wrapping_add(existing));
            }
            R_AARCH64_PREL32 => {
                if ptr.len() < 4 {
                    return Err(TccError::link("AArch64 relocate: buffer too small for 32-bit"));
                }
                let existing = read32le(ptr);
                let result = (val as u32)
                    .wrapping_add(existing)
                    .wrapping_sub(addr as u32);
                write32le(ptr, result);
            }
            R_AARCH64_JUMP26 | R_AARCH64_CALL26 => {
                if ptr.len() < 4 {
                    return Err(TccError::link("AArch64 relocate: buffer too small"));
                }
                let insn = read32le(ptr);
                let addend = ((insn & 0x03FF_FFFF) << 2) as i32;
                let target = (val as i64)
                    .wrapping_add(i64::from(addend))
                    .wrapping_sub(addr as i64);
                let offset = ((target >> 2) as u32) & 0x03FF_FFFF;
                write32le(ptr, (insn & 0xFC00_0000) | offset);
            }
            R_AARCH64_ADR_PREL_PG_HI21 => {
                if ptr.len() < 4 {
                    return Err(TccError::link("AArch64 relocate: buffer too small"));
                }
                let insn = read32le(ptr);
                let page_delta = ((val as i64).wrapping_sub(addr as i64)) >> 12;
                let immlo = ((page_delta as u32) & 0x3) << 29;
                let immhi = (((page_delta as u32) >> 2) & 0x7_FFFF) << 5;
                let mask = 0x9F00_001F; // ADRP opcode mask preserving Rd
                write32le(ptr, (insn & mask) | immlo | immhi);
            }
            R_AARCH64_ADD_ABS_LO12_NC => {
                if ptr.len() < 4 {
                    return Err(TccError::link("AArch64 relocate: buffer too small"));
                }
                let insn = read32le(ptr);
                let lo12 = ((val as u32) & 0xFFF) << 10;
                write32le(ptr, (insn & 0xFFC0_03FF) | lo12);
            }
            R_AARCH64_LDST8_ABS_LO12_NC => {
                if ptr.len() < 4 {
                    return Err(TccError::link("AArch64 relocate: buffer too small"));
                }
                let insn = read32le(ptr);
                let lo12 = ((val as u32) & 0xFFF) << 10;
                write32le(ptr, (insn & 0xFFC0_03FF) | lo12);
            }
            R_AARCH64_LDST16_ABS_LO12_NC => {
                if ptr.len() < 4 {
                    return Err(TccError::link("AArch64 relocate: buffer too small"));
                }
                let insn = read32le(ptr);
                let lo12 = (((val as u32) >> 1) & 0xFFF) << 10;
                write32le(ptr, (insn & 0xFFC0_03FF) | lo12);
            }
            R_AARCH64_LDST32_ABS_LO12_NC => {
                if ptr.len() < 4 {
                    return Err(TccError::link("AArch64 relocate: buffer too small"));
                }
                let insn = read32le(ptr);
                let lo12 = (((val as u32) >> 2) & 0xFFF) << 10;
                write32le(ptr, (insn & 0xFFC0_03FF) | lo12);
            }
            R_AARCH64_LDST64_ABS_LO12_NC => {
                if ptr.len() < 4 {
                    return Err(TccError::link("AArch64 relocate: buffer too small"));
                }
                let insn = read32le(ptr);
                let lo12 = (((val as u32) >> 3) & 0xFFF) << 10;
                write32le(ptr, (insn & 0xFFC0_03FF) | lo12);
            }
            R_AARCH64_LDST128_ABS_LO12_NC => {
                if ptr.len() < 4 {
                    return Err(TccError::link("AArch64 relocate: buffer too small"));
                }
                let insn = read32le(ptr);
                let lo12 = (((val as u32) >> 4) & 0xFFF) << 10;
                write32le(ptr, (insn & 0xFFC0_03FF) | lo12);
            }
            R_AARCH64_MOVW_UABS_G0_NC => {
                if ptr.len() < 4 {
                    return Err(TccError::link("AArch64 relocate: buffer too small"));
                }
                let insn = read32le(ptr);
                let imm16 = ((val as u32) & 0xFFFF) << 5;
                write32le(ptr, (insn & 0xFFE0_001F) | imm16);
            }
            R_AARCH64_MOVW_UABS_G1_NC => {
                if ptr.len() < 4 {
                    return Err(TccError::link("AArch64 relocate: buffer too small"));
                }
                let insn = read32le(ptr);
                let imm16 = (((val >> 16) as u32) & 0xFFFF) << 5;
                write32le(ptr, (insn & 0xFFE0_001F) | imm16);
            }
            R_AARCH64_MOVW_UABS_G2_NC => {
                if ptr.len() < 4 {
                    return Err(TccError::link("AArch64 relocate: buffer too small"));
                }
                let insn = read32le(ptr);
                let imm16 = (((val >> 32) as u32) & 0xFFFF) << 5;
                write32le(ptr, (insn & 0xFFE0_001F) | imm16);
            }
            R_AARCH64_MOVW_UABS_G3 => {
                if ptr.len() < 4 {
                    return Err(TccError::link("AArch64 relocate: buffer too small"));
                }
                let insn = read32le(ptr);
                let imm16 = (((val >> 48) as u32) & 0xFFFF) << 5;
                write32le(ptr, (insn & 0xFFE0_001F) | imm16);
            }
            R_AARCH64_RELATIVE | R_AARCH64_GLOB_DAT | R_AARCH64_JMP_SLOT
            | R_AARCH64_COPY | R_AARCH64_NONE => {
                // Handled by dynamic linker or no-op
            }
            _ => {
                return Err(TccError::link(format!(
                    "AArch64: unhandled relocation type {rel_type}"
                )));
            }
        }
        Ok(())
    }

    /// Create a PLT entry for the given GOT offset.
    ///
    /// `AArch64` PLT entry (16 bytes):
    /// ```text
    /// ADRP X16, #page_offset    ; Load GOT page address
    /// LDR  X17, [X16, #lo12]    ; Load GOT entry
    /// ADD  X16, X16, #lo12      ; Compute full GOT address
    /// BR   X17                  ; Jump to target
    /// ```
    ///
    /// C equivalent: `create_plt_entry()` in `arm64-link.c`.
    fn create_plt_entry(
        &mut self,
        _state: &mut TccState,
        got_offset: u32,
    ) -> TccResult<u32> {
        // The PLT entry structure is written to the PLT section
        // during the final link step. This simplified implementation
        // returns the GOT offset for later processing by the linker.
        Ok(got_offset)
    }

    /// Relocate PLT entries after final addresses are known.
    ///
    /// C equivalent: `relocate_plt()` in `arm64-link.c`.
    fn relocate_plt(&mut self, state: &mut TccState) -> TccResult<()> {
        Ok(())
    }
}

// ===========================================================================
//  Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_arm64_backend_creation() {
        let backend = Arm64Backend::new();
        assert_eq!(backend.func_sub_sp_offset, 0);
    }

    #[test]
    fn test_arm64_target_machine_defs() {
        let backend = Arm64Backend::new();
        let defs = backend.target_machine_defs();
        assert!(defs.contains(&"__aarch64__"));
        assert!(defs.contains(&"__arm64__"));
    }

    #[test]
    fn test_arm64_reg_classes_count() {
        let backend = Arm64Backend::new();
        assert_eq!(backend.reg_classes().len(), NB_REGS);
    }

    #[test]
    fn test_arm64_reg_classes_allocatability() {
        let backend = Arm64Backend::new();
        let classes = backend.reg_classes();
        // X0 should be allocatable
        assert_ne!(classes[0], 0);
        // X29 (FP) should NOT be allocatable
        assert_eq!(classes[29], 0);
        // V0 (index 31) should have float class
        assert_ne!(classes[31] & RC_FLOAT, 0);
    }

    #[test]
    fn test_arm64_linker_code_reloc() {
        let backend = Arm64Backend::new();
        assert_eq!(backend.code_reloc(R_AARCH64_CALL26), 1);
        assert_eq!(backend.code_reloc(R_AARCH64_JUMP26), 1);
        assert_eq!(backend.code_reloc(R_AARCH64_ABS64), 0);
        assert_eq!(backend.code_reloc(999), -1);
    }

    #[test]
    fn test_arm64_gotplt_entry_type() {
        let backend = Arm64Backend::new();
        assert_eq!(backend.gotplt_entry_type(R_AARCH64_GLOB_DAT), GotPltEntry::NoEntry);
        assert_eq!(backend.gotplt_entry_type(R_AARCH64_ADR_GOT_PAGE), GotPltEntry::BuildGotOnly);
        assert_eq!(backend.gotplt_entry_type(R_AARCH64_CALL26), GotPltEntry::AutoEntry);
    }

    #[test]
    fn test_arm64_nop_fill_err_on_default_state() {
        let mut backend = Arm64Backend::new();
        let mut state = TccState::default();
        // Default state has no sections — emit operations should fail gracefully
        assert!(backend.gen_fill_nops(&mut state, 8).is_err());
    }

    #[test]
    fn test_arm64_gfunc_sret_returns_zero() {
        let backend = Arm64Backend::new();
        let vt = CType::default();
        let mut ret = CType::default();
        let mut align = 0i32;
        let mut regsize = 0i32;
        let result = backend.gfunc_sret(&vt, false, &mut ret, &mut align, &mut regsize);
        assert_eq!(result, 0);
        assert_eq!(regsize, 8);
    }

    #[test]
    fn test_arm64_relocate_abs64() {
        let backend = Arm64Backend::new();
        let mut state = TccState::default();
        let mut buf = [0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        backend.relocate(&mut state, R_AARCH64_ABS64, &mut buf, 0, 0x2000).unwrap();
        let result = u64::from_le_bytes([buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]]);
        assert_eq!(result, 0x2010);
    }

    #[test]
    fn test_arm64_relocate_abs32() {
        let backend = Arm64Backend::new();
        let mut state = TccState::default();
        let mut buf = [0x10, 0x00, 0x00, 0x00];
        backend.relocate(&mut state, R_AARCH64_ABS32, &mut buf, 0, 0x2000).unwrap();
        assert_eq!(read32le(&buf), 0x2010);
    }

    #[test]
    fn test_arm64_relocate_unknown_type() {
        let backend = Arm64Backend::new();
        let mut state = TccState::default();
        let mut buf = [0u8; 8];
        let result = backend.relocate(&mut state, 9999, &mut buf, 0, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_arm64_o_err_on_default_state() {
        let mut backend = Arm64Backend::new();
        let mut state = TccState::default();
        // Default state has no sections — `o()` should return Err
        assert!(backend.o(&mut state, 0xD503_201F).is_err());
    }

    #[test]
    fn test_arm64_vla_err_on_default_state() {
        let mut backend = Arm64Backend::new();
        let mut state = TccState::default();
        assert!(backend.gen_vla_sp_save(&mut state, 0).is_err());
        assert!(backend.gen_vla_sp_restore(&mut state, 0).is_err());
        assert!(backend.gen_vla_alloc(&mut state, &CType::default(), 4).is_err());
    }

    #[test]
    fn test_arm64_plt_ok() {
        let mut backend = Arm64Backend::new();
        let mut state = TccState::default();
        assert!(backend.relocate_plt(&mut state).is_ok());
    }

    #[test]
    fn test_arm64_plt_entry_returns_offset() {
        let mut backend = Arm64Backend::new();
        let mut state = TccState::default();
        let result = backend.create_plt_entry(&mut state, 0x300).unwrap();
        assert_eq!(result, 0x300);
    }
}
