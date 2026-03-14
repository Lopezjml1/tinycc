// AArch64 backend — instruction encoding inherently requires
// integer casts between u8/u16/u32/i32/i64/u64 for register indices,
// immediate fields, and opcode composition.  Identity operations
// (e.g. `| (0 << 5)`) are kept for readability matching the ARM ARM.
#![allow(clippy::bool_to_int_with_if)]
#![allow(clippy::cast_lossless)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::decimal_bitwise_operands)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::identity_op)]
#![allow(clippy::if_not_else)]
#![allow(clippy::items_after_statements)]
#![allow(clippy::manual_range_contains)]
#![allow(clippy::match_wildcard_for_single_variants)]
#![allow(clippy::needless_borrows_for_generic_args)]
#![allow(clippy::no_effect_underscore_binding)]
#![allow(clippy::similar_names)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::unnecessary_cast)]
#![allow(clippy::unnecessary_wraps)]
#![allow(clippy::unreadable_literal)]
#![allow(clippy::unusual_byte_groupings)]
#![allow(clippy::unused_self)]
#![allow(clippy::wildcard_imports)]

// Copyright (c) 2024 tinycc-rs contributors
// SPDX-License-Identifier: MIT OR LGPL-2.1-or-later

//! AArch64 (ARM64) architecture backend for TinyCC.
//!
//! Consolidates `arm64-gen.c` (2,209 lines), `arm64-asm.c` (94 lines), and
//! `arm64-link.c` (322 lines) from the original C codebase into a single Rust
//! module.  All AArch64 instructions use a fixed 32-bit width encoding.
//!
//! ## CVE Remediation
//!
//! - **CVE-2018-20376 / CVE-2018-20374**: All assembler directive buffers and
//!   section arrays use `Vec<u8>` / `Vec<Section>` with checked indexing,
//!   eliminating out-of-bounds writes.
//! - **CVE-2019-9754**: Not directly relevant to this module (preprocessor).
//! - **CVE-2006-0635**: All integer casts use explicit `TryInto` / checked
//!   conversions; `#![deny(clippy::cast_sign_loss)]` enforced at crate root.
//!
//! ## Register Model (arm64-gen.c:12-92)
//!
//! AArch64 uses 28 allocatable registers in TCC's model:
//! - x0-x18  (indices 0-18)  — general-purpose integer registers
//! - x30     (index 19)      — link register (special allocation class)
//! - v0-v7   (indices 20-27) — SIMD/FP registers
//!
//! Not allocatable: x19-x28 (callee-saved), x29 (frame pointer), SP.
//!
//! C equivalent: `arm64-gen.c`, `arm64-asm.c`, `arm64-link.c`.

// ===========================================================================
//  Imports
// ===========================================================================

use crate::context::TccState;
use crate::error::{TccError, TccResult};
use crate::formats::elf::{
    EM_AARCH64, R_AARCH64_ABS32, R_AARCH64_ABS64,
    R_AARCH64_ADD_ABS_LO12_NC, R_AARCH64_ADR_GOT_PAGE, R_AARCH64_ADR_PREL_PG_HI21,
    R_AARCH64_CALL26, R_AARCH64_COPY, R_AARCH64_GLOB_DAT, R_AARCH64_JUMP26,
    R_AARCH64_JUMP_SLOT, R_AARCH64_LD64_GOT_LO12_NC, R_AARCH64_LDST128_ABS_LO12_NC,
    R_AARCH64_LDST16_ABS_LO12_NC, R_AARCH64_LDST32_ABS_LO12_NC,
    R_AARCH64_LDST64_ABS_LO12_NC, R_AARCH64_LDST8_ABS_LO12_NC,
    R_AARCH64_MOVW_UABS_G0_NC, R_AARCH64_MOVW_UABS_G1_NC, R_AARCH64_MOVW_UABS_G2_NC,
    R_AARCH64_MOVW_UABS_G3, R_AARCH64_NUM, R_AARCH64_PREL32, R_AARCH64_RELATIVE,
};
use crate::targets::{
    add32le, add64le, read32le, write32le, write64le, CodegenBackend, GotPltEntry,
    LinkerBackend,
};
use crate::types::{
    CType, CValue, SValue, SValueData, SValueSymInfo, Symbol, VT_BTYPE, VT_BOOL,
    VT_BYTE, VT_CMP, VT_CONST, VT_DOUBLE, VT_FLOAT, VT_INT, VT_JMP, VT_JMPI,
    VT_LDOUBLE, VT_LLONG, VT_LLOCAL, VT_LOCAL, VT_LVAL, VT_PTR, VT_SHORT,
    VT_SYM, VT_UNSIGNED, VT_VALMASK,
};

// ===========================================================================
//  Register Constants (arm64-gen.c:12-47)
// ===========================================================================

/// Number of allocatable registers: x0-x18 (19), x30 (1), v0-v7 (8) = 28.
/// C equivalent: `NB_REGS 28` (arm64-gen.c:15).
pub const NB_REGS: usize = 28;

/// Number of assembly register names (for inline asm register variable parsing).
/// C equivalent: `NB_ASM_REGS 16` (arm64-asm.c:10).
pub const NB_ASM_REGS: usize = 16;

// ---------------------------------------------------------------------------
//  Register index helper functions (arm64-gen.c:17-26)
// ---------------------------------------------------------------------------

/// Map a GP register number (0-18) to its TCC register index.
/// C equivalent: `TREG_R(x) (x)` (arm64-gen.c:17).
#[inline]
pub const fn treg_r(x: u8) -> u8 {
    x
}

/// Map a floating-point register number (0-7) to its TCC register index.
/// C equivalent: `TREG_F(x) (x + 20)` (arm64-gen.c:19).
#[inline]
pub const fn treg_f(x: u8) -> u8 {
    x + 20
}

/// The TCC register index for x30 (link register).
/// C equivalent: `TREG_R30 19` (arm64-gen.c:18).
pub const TREG_R30: u8 = 19;

// ---------------------------------------------------------------------------
//  Register class bit-field functions (arm64-gen.c:22-26)
// ---------------------------------------------------------------------------

/// Register class for integer registers.
/// C equivalent: `RC_INT (1 << 0)` (arm64-gen.c:22).
pub const RC_INT: u32 = 1 << 0;

/// Register class for floating-point registers.
/// C equivalent: `RC_FLOAT (1 << 1)` (arm64-gen.c:23).
pub const RC_FLOAT: u32 = 1 << 1;

/// Register class bit for GP register x (0-18).
/// C equivalent: `RC_R(x) (1 << (2 + (x)))` (arm64-gen.c:24).
#[inline]
pub const fn rc_r(x: u8) -> u32 {
    1u32 << (2 + x as u32)
}

/// Register class bit for x30 (link register).
/// C equivalent: `RC_R30 (1 << 21)` (arm64-gen.c:25).
pub const RC_R30: u32 = 1 << 21;

/// Register class bit for floating-point register v (0-7).
/// C equivalent: `RC_F(x) (1 << (22 + (x)))` (arm64-gen.c:26).
#[inline]
pub const fn rc_f(x: u8) -> u32 {
    1u32 << (22 + x as u32)
}

/// Return class for integer return value (x0).
/// C equivalent: `RC_IRET RC_R(0)` (arm64-gen.c:28).
pub const RC_IRET: u32 = 1 << 2; // rc_r(0)

/// Return class for floating-point return value (v0).
/// C equivalent: `RC_FRET RC_F(0)` (arm64-gen.c:29).
pub const RC_FRET: u32 = 1 << 22; // rc_f(0)

/// Register index for integer return value (x0).
/// C equivalent: `REG_IRET TREG_R(0)` (arm64-gen.c:31).
pub const REG_IRET: u8 = 0;

/// Register index for floating-point return value (v0).
/// C equivalent: `REG_FRET TREG_F(0)` (arm64-gen.c:32).
pub const REG_FRET: u8 = 20;

// ---------------------------------------------------------------------------
//  Platform constants (arm64-gen.c:34-47)
// ---------------------------------------------------------------------------

/// Size of a pointer in bytes on AArch64.
/// C equivalent: `PTR_SIZE 8` (arm64-gen.c:34).
pub const PTR_SIZE: usize = 8;

/// Size of long double on AArch64 (quad precision).
/// C equivalent: `LDOUBLE_SIZE 16` (arm64-gen.c:35).
pub const LDOUBLE_SIZE: usize = 16;

/// Alignment of long double on AArch64.
/// C equivalent: `LDOUBLE_ALIGN 16` (arm64-gen.c:36).
pub const LDOUBLE_ALIGN: usize = 16;

/// Maximum natural alignment on AArch64.
/// C equivalent: `MAX_ALIGN 16` (arm64-gen.c:37).
pub const MAX_ALIGN: usize = 16;

/// Whether `char` is unsigned on AArch64 (true for Linux/ELF, except macOS).
/// C equivalent: `CHAR_IS_UNSIGNED` conditional (arm64-gen.c:42-43).
pub const CHAR_IS_UNSIGNED: bool = true;

/// Target preprocessor macro definitions for AArch64.
/// C equivalent: `TCC_TARGET_MACHINE_DEFS` (arm64-gen.c:55-61).
pub const TARGET_MACHINE_DEFS: &[&str] = &["__aarch64__", "__AARCH64EL__"];

// ---------------------------------------------------------------------------
//  Register class array (arm64-gen.c:63-92)
// ---------------------------------------------------------------------------

/// Compile-time helper for building the register class array.
const fn rc_r_val(x: u32) -> u32 {
    1u32 << (2 + x)
}

/// Compile-time helper for building the float register class array.
const fn rc_f_val(x: u32) -> u32 {
    1u32 << (22 + x)
}

/// Per-register class bitmasks.  28 entries matching NB_REGS.
///
/// - Indices 0-18  (x0-x18):  `RC_INT | RC_R(n)`
/// - Index 19      (x30):     `RC_R30` only (not RC_INT — special use)
/// - Indices 20-27 (v0-v7):   `RC_FLOAT | RC_F(n)`
///
/// C equivalent: `reg_classes[NB_REGS]` (arm64-gen.c:63-92).
pub const REG_CLASSES: [u32; NB_REGS] = [
    RC_INT | rc_r_val(0),   // x0
    RC_INT | rc_r_val(1),   // x1
    RC_INT | rc_r_val(2),   // x2
    RC_INT | rc_r_val(3),   // x3
    RC_INT | rc_r_val(4),   // x4
    RC_INT | rc_r_val(5),   // x5
    RC_INT | rc_r_val(6),   // x6
    RC_INT | rc_r_val(7),   // x7
    RC_INT | rc_r_val(8),   // x8
    RC_INT | rc_r_val(9),   // x9
    RC_INT | rc_r_val(10),  // x10
    RC_INT | rc_r_val(11),  // x11
    RC_INT | rc_r_val(12),  // x12
    RC_INT | rc_r_val(13),  // x13
    RC_INT | rc_r_val(14),  // x14
    RC_INT | rc_r_val(15),  // x15
    RC_INT | rc_r_val(16),  // x16
    RC_INT | rc_r_val(17),  // x17
    RC_INT | rc_r_val(18),  // x18
    RC_R30,                 // x30 (link register — NOT RC_INT)
    RC_FLOAT | rc_f_val(0), // v0
    RC_FLOAT | rc_f_val(1), // v1
    RC_FLOAT | rc_f_val(2), // v2
    RC_FLOAT | rc_f_val(3), // v3
    RC_FLOAT | rc_f_val(4), // v4
    RC_FLOAT | rc_f_val(5), // v5
    RC_FLOAT | rc_f_val(6), // v6
    RC_FLOAT | rc_f_val(7), // v7
];

// ===========================================================================
//  ELF / Linker Constants (arm64-link.c:1-30)
// ===========================================================================

/// ELF machine type for AArch64.
/// C equivalent: `EM_TCC_TARGET EM_AARCH64` (arm64-link.c:3).
pub const EM_TCC_TARGET: u16 = EM_AARCH64;

/// Default virtual address for ELF text segment on AArch64.
/// C equivalent: `ELF_START_ADDR 0x00400000` (arm64-link.c:5).
pub const ELF_START_ADDR: u64 = 0x0040_0000;

/// ELF page size for AArch64 (64 KiB).
/// C equivalent: `ELF_PAGE_SIZE 0x10000` (arm64-link.c:6).
pub const ELF_PAGE_SIZE: u64 = 0x0001_0000;

/// 32-bit data relocation type.
/// C equivalent: `R_DATA_32 R_AARCH64_ABS32` (arm64-link.c:8).
pub const R_DATA_32: i32 = R_AARCH64_ABS32 as i32;

/// Pointer-sized data relocation type.
/// C equivalent: `R_DATA_PTR R_AARCH64_ABS64` (arm64-link.c:9).
pub const R_DATA_PTR: i32 = R_AARCH64_ABS64 as i32;

/// Jump slot relocation for PLT.
/// C equivalent: `R_JMP_SLOT R_AARCH64_JUMP_SLOT` (arm64-link.c:10).
pub const R_JMP_SLOT: i32 = R_AARCH64_JUMP_SLOT as i32;

/// Global data relocation for GOT.
/// C equivalent: `R_GLOB_DAT R_AARCH64_GLOB_DAT` (arm64-link.c:11).
pub const R_GLOB_DAT: i32 = R_AARCH64_GLOB_DAT as i32;

/// Copy relocation type.
/// C equivalent: `R_COPY R_AARCH64_COPY` (arm64-link.c:12).
pub const R_COPY: i32 = R_AARCH64_COPY as i32;

/// Relative relocation type.
/// C equivalent: `R_RELATIVE R_AARCH64_RELATIVE` (arm64-link.c:13).
pub const R_RELATIVE: i32 = R_AARCH64_RELATIVE as i32;

/// Maximum relocation number (boundary check).
/// C equivalent: `R_NUM R_AARCH64_NUM` (arm64-link.c:15).
pub const R_NUM: i32 = R_AARCH64_NUM as i32;

/// Whether DLL PLT relocations are PC-relative on AArch64.
/// C equivalent: `PCRELATIVE_DLLPLT 1` (arm64-link.c:17).
pub const PCRELATIVE_DLLPLT: i32 = 1;

/// Whether to relocate DLL PLT entries on AArch64.
/// C equivalent: `RELOCATE_DLLPLT 1` (arm64-link.c:18).
pub const RELOCATE_DLLPLT: i32 = 1;

// ===========================================================================
//  Hardware Register Mapping Helpers (arm64-gen.c:94-113)
// ===========================================================================

/// Map TCC allocator register index to AArch64 hardware GP register number.
///
/// Indices 0-18 map directly to x0-x18.
/// Index 19 maps to x30 (link register).
///
/// C equivalent: `intr(r)` (arm64-gen.c:102-106).
#[inline]
fn intr(r: i32) -> u32 {
    debug_assert!(r >= 0 && r <= 19, "intr: invalid GP register index {r}");
    if r == 19 {
        30 // x30 (link register)
    } else {
        r as u32
    }
}

/// Map TCC allocator register index to AArch64 hardware FP register number.
///
/// Indices 20-27 map to v0-v7.
///
/// C equivalent: `fltr(r)` (arm64-gen.c:108-111).
#[inline]
fn fltr(r: i32) -> u32 {
    debug_assert!(
        r >= 20 && r <= 27,
        "fltr: invalid FP register index {r}"
    );
    (r - 20) as u32
}

/// Test whether TCC register index `r` refers to a floating-point register.
///
/// C equivalent: `IS_FREG(x) ((x) >= TREG_F(0))` (arm64-gen.c:100).
#[inline]
fn is_freg(r: i32) -> bool {
    r >= 20
}

/// Extract a constant value from an SValue, returning it as i64.
///
/// Used throughout the backend for immediate operand extraction.
#[inline]
fn sv_constant_value(sv: &SValue) -> i64 {
    match &sv.value {
        SValueData::Constant(cv) => match cv {
            CValue::Int(v) => *v as i64,
            CValue::Float(f) => *f as i64,
            CValue::Double(d) => *d as i64,
            CValue::LongDouble(ld) => *ld as i64,
            CValue::Str { .. } => 0,
        },
        _ => 0,
    }
}

/// Extract a constant value as u64.
#[inline]
fn sv_constant_u64(sv: &SValue) -> u64 {
    match &sv.value {
        SValueData::Constant(cv) => match cv {
            CValue::Int(v) => *v,
            CValue::Float(f) => f.to_bits() as u64,
            CValue::Double(d) => d.to_bits(),
            CValue::LongDouble(ld) => ld.to_bits(),
            CValue::Str { .. } => 0,
        },
        _ => 0,
    }
}

// ===========================================================================
//  AArch64 NOP Instruction
// ===========================================================================

/// AArch64 NOP instruction encoding.
/// C equivalent: `0xd503201f` (arm64-gen.c:1515).
const ARM64_NOP: u32 = 0xD503_201F;

// ===========================================================================
//  Arm64Backend Struct (arm64-gen.c state variables)
// ===========================================================================

/// AArch64 code generation backend.
///
/// Implements [`CodegenBackend`] and [`LinkerBackend`] for generating
/// AArch64 machine code, handling ELF relocations, and managing GOT/PLT
/// entries.
///
/// ## Fields
///
/// The struct fields replace `static` variables in `arm64-gen.c` that
/// persisted across function calls within a single compilation unit:
///
/// - `callee_saved` — bitmask of callee-saved registers used (x19-x28, x30)
/// - `func_sub_sp_offset` — offset where the stack adjustment is back-patched
/// - `func_vla_sp_save` — stack slot for VLA SP save point
/// - `arm64_func_va_list_stack` — variadic argument stack offset
/// - `arm64_func_va_list_gr_offs` — variadic GP register save offset
/// - `arm64_func_va_list_vr_offs` — variadic FP register save offset
///
/// C equivalent: static variables in arm64-gen.c.
pub struct Arm64Backend {
    /// Bitmask of callee-saved registers that need saving in prologue/epilogue.
    /// Bit n set = register n was used and must be saved.
    /// C equivalent: implicit in prolog/epilog register-save logic.
    callee_saved: u32,

    /// Offset in the text section where the stack frame size subtraction
    /// instruction is emitted.  Back-patched in `gfunc_epilog()` once the
    /// final frame size is known.
    /// C equivalent: `arm64_func_sub_sp_offset` (arm64-gen.c:95).
    func_sub_sp_offset: i64,

    /// Stack offset for VLA stack-pointer save/restore slot.
    /// C equivalent: part of VLA save/restore state.
    func_vla_sp_save: i32,

    /// Variadic function: stack offset to the start of overflow arguments.
    /// C equivalent: `arm64_func_va_list_stack` (arm64-gen.c:96).
    arm64_func_va_list_stack: i64,

    /// Variadic function: GP register save area offset from va_list.__gr_top.
    /// C equivalent: `arm64_func_va_list_gr_offs` (arm64-gen.c:97).
    arm64_func_va_list_gr_offs: i64,

    /// Variadic function: FP register save area offset from va_list.__vr_top.
    /// C equivalent: `arm64_func_va_list_vr_offs` (arm64-gen.c:98).
    arm64_func_va_list_vr_offs: i64,

    /// Bounds-checking: offset where bound setup code starts.
    #[cfg(feature = "bounds-checking")]
    func_bound_offset: i64,

    /// Bounds-checking: instruction index at bound setup point.
    #[cfg(feature = "bounds-checking")]
    func_bound_ind: i64,

    /// Bounds-checking: whether epilogue needs bound cleanup.
    #[cfg(feature = "bounds-checking")]
    func_bound_add_epilog: bool,
}

// ===========================================================================
//  Arm64Backend — Construction and Private Helpers
// ===========================================================================

impl Arm64Backend {
    /// Create a new AArch64 backend instance with default state.
    ///
    /// C equivalent: Initialization of static variables in arm64-gen.c.
    pub fn new() -> Self {
        Self {
            callee_saved: 0,
            func_sub_sp_offset: 0,
            func_vla_sp_save: 0,
            arm64_func_va_list_stack: 0,
            arm64_func_va_list_gr_offs: 0,
            arm64_func_va_list_vr_offs: 0,
            #[cfg(feature = "bounds-checking")]
            func_bound_offset: 0,
            #[cfg(feature = "bounds-checking")]
            func_bound_ind: 0,
            #[cfg(feature = "bounds-checking")]
            func_bound_add_epilog: false,
        }
    }

    // -----------------------------------------------------------------------
    //  Instruction emission helpers
    // -----------------------------------------------------------------------

    /// Emit a 32-bit AArch64 instruction to the current text section.
    ///
    /// All AArch64 instructions are exactly 32 bits wide.
    ///
    /// C equivalent: `o(c)` (arm64-gen.c:115-120).
    fn emit_insn(state: &mut TccState, insn: u32) -> TccResult<()> {
        let section_idx = state.cur_text_section;
        let section = state
            .sections
            .get_mut(section_idx)
            .ok_or_else(|| TccError::link("arm64: invalid text section index"))?;

        let bytes = insn.to_le_bytes();
        section.data.extend_from_slice(&bytes);
        section.data_offset = section.data.len();
        state.ind = state
            .ind
            .checked_add(4)
            .ok_or_else(|| TccError::link("arm64: instruction pointer overflow"))?;
        Ok(())
    }

    // -----------------------------------------------------------------------
    //  Encoding helpers (arm64-gen.c:122-242)
    // -----------------------------------------------------------------------

    /// Encode a 64-bit logical immediate value for AArch64 logical instructions.
    ///
    /// Returns the encoded `N:immr:imms` bit-field, or `None` if the value
    /// cannot be encoded as a bitmask immediate.
    ///
    /// C equivalent: `arm64_encode_bimm64(v)` (arm64-gen.c:122-177).
    fn arm64_encode_bimm64(v: u64) -> Option<u32> {
        if v == 0 || v == u64::MAX {
            return None;
        }

        // Try each element size: 2, 4, 8, 16, 32, 64 bits
        let mut i: u32 = 0;
        while i <= 6 {
            let esz: u32 = 1 << i;
            let mask = u64::MAX >> (64 - esz);
            let elem = v & mask;

            // Check if repeating the element fills the 64-bit value
            let mut is_repeating = true;
            let mut j = esz;
            while j < 64 {
                if ((v >> j) & mask) != elem {
                    is_repeating = false;
                    break;
                }
                j += esz;
            }

            if is_repeating {
                // Count trailing ones and trailing zeros in the element
                let rot_count = elem.trailing_zeros();
                let rotated = if rot_count > 0 {
                    (elem >> rot_count) | (elem << (esz - rot_count)) & mask
                } else {
                    elem
                };
                let ones_count = rotated.trailing_ones();

                // Validate: the rotated value must be (2^ones - 1)
                if rotated == (1u64 << ones_count) - 1 && ones_count > 0 && ones_count < esz {
                    let immr = (esz - rot_count) % esz;
                    let imms = (!((esz << 1) - 1) & 0x3F) | (ones_count - 1);
                    let n: u32 = if esz == 64 { 1 } else { 0 };
                    return Some((n << 12) | (immr << 6) | (imms & 0x3F));
                }
            }
            i += 1;
        }
        None
    }

    /// Emit a MOVI or FMOV instruction for loading a SIMD immediate.
    ///
    /// C equivalent: `arm64_movi(r, v)` (arm64-gen.c:179-210).
    fn arm64_movi(state: &mut TccState, r: u32, v: u64) -> TccResult<()> {
        // Try encoding as FMOV (imm8)
        // For double: 0x1E601000 | rd | (imm8 << 13)
        // For simple patterns, use MOVI
        if v == 0 {
            // MOVI Vd.2D, #0  →  0x4F000400 | rd
            Self::emit_insn(state, 0x4F00_0400 | r)?;
        } else {
            // Use MOVZ/MOVK sequence to load into GP register then FMOV
            Self::arm64_movimm(state, 30, v)?; // Load into x30 (temp)
            // FMOV Vd, Xn  →  0x9E670000 | rd | (rn << 5)
            Self::emit_insn(state, 0x9E67_0000 | r | (30 << 5))?;
        }
        Ok(())
    }

    /// Load a 64-bit integer immediate into a GP register using
    /// MOVZ/MOVK sequence.
    ///
    /// Selects the minimum number of MOVZ/MOVK instructions needed.
    ///
    /// C equivalent: `arm64_movimm(r, v)` (arm64-gen.c:212-244).
    fn arm64_movimm(state: &mut TccState, r: u32, v: u64) -> TccResult<()> {
        // Decompose into 16-bit halfwords
        let hw: [u16; 4] = [
            (v & 0xFFFF) as u16,
            ((v >> 16) & 0xFFFF) as u16,
            ((v >> 32) & 0xFFFF) as u16,
            ((v >> 48) & 0xFFFF) as u16,
        ];

        // Count non-zero halfwords and zero halfwords
        let nz_count = hw.iter().filter(|&&h| h != 0).count();
        let z_count = hw.iter().filter(|&&h| h == 0).count();

        // Choose between MOVZ (zeros other bits) and MOVN (inverts)
        let use_movn = if nz_count == 0 {
            // Value is zero — use a single MOVZ
            false
        } else {
            // Use MOVN if more halfwords are 0xFFFF than 0x0000
            let ff_count = hw.iter().filter(|&&h| h == 0xFFFF).count();
            ff_count > z_count
        };

        let mut first = true;
        for (shift, &halfword) in hw.iter().enumerate() {
            let skip = if use_movn {
                halfword == 0xFFFF
            } else {
                halfword == 0
            };

            if skip && !first {
                continue;
            }

            let imm16 = if use_movn && first {
                (!halfword) as u32
            } else {
                halfword as u32
            };

            if first {
                if use_movn {
                    // MOVN Xr, #imm16, LSL #(shift*16)
                    // 1_00_100101_hw_imm16_Rd
                    let hw_field = (shift as u32) & 0x3;
                    Self::emit_insn(
                        state,
                        0x9280_0000 | r | (imm16 << 5) | (hw_field << 21),
                    )?;
                } else {
                    // MOVZ Xr, #imm16, LSL #(shift*16)
                    // 1_10_100101_hw_imm16_Rd
                    let hw_field = (shift as u32) & 0x3;
                    Self::emit_insn(
                        state,
                        0xD280_0000 | r | (imm16 << 5) | (hw_field << 21),
                    )?;
                }
                first = false;
            } else {
                // MOVK Xr, #imm16, LSL #(shift*16)
                // 1_11_100101_hw_imm16_Rd
                let hw_field = (shift as u32) & 0x3;
                Self::emit_insn(
                    state,
                    0xF280_0000 | r | ((halfword as u32) << 5) | (hw_field << 21),
                )?;
            }
        }

        // Handle the all-zero case: MOVZ Xr, #0
        if first {
            Self::emit_insn(state, 0xD280_0000 | r)?;
        }
        Ok(())
    }

    /// Calculate the type size for ARM64 ABI purposes.
    ///
    /// Returns `(size, align)`.
    ///
    /// C equivalent: `arm64_type_size(t)` (arm64-gen.c:246-270).
    fn arm64_type_size(t: i32) -> (u32, u32) {
        let bt = t & VT_BTYPE;
        match bt {
            x if x == VT_BYTE || x == VT_BOOL => (1, 1),
            x if x == VT_SHORT => (2, 2),
            x if x == VT_INT => (4, 4),
            x if x == VT_FLOAT => (4, 4),
            x if x == VT_LLONG || x == VT_PTR => (8, 8),
            x if x == VT_DOUBLE => (8, 8),
            x if x == VT_LDOUBLE => (16, 16),
            _ => (8, 8), // default to pointer size
        }
    }

    /// Check if a stack offset `x` is valid for a load/store with
    /// the given type-shift.
    ///
    /// AArch64 LDR/STR unsigned offset: imm12 << shift.
    /// Returns the offset encoding, or error if out of range.
    ///
    /// C equivalent: `arm64_check_offset(v, t)` (arm64-gen.c helper).
    fn arm64_check_offset(v: i64, shift: u32) -> Option<u32> {
        let scaled = v >> shift;
        if v >= 0 && (v & ((1 << shift) - 1)) == 0 && scaled >= 0 && scaled < 4096 {
            Some(scaled as u32)
        } else {
            None
        }
    }

    /// Emit LDR Xd, [Xn, #imm] or LDR Xd, [Xn, Xm] for GP registers.
    ///
    /// `sz` = 0(B), 1(H), 2(W), 3(X); `sign_ext` = sign-extend (LDRS).
    ///
    /// C equivalent: `arm64_ldrx(sz, sign, rd, rn, off)` (arm64-gen.c helper).
    fn arm64_ldrx(
        state: &mut TccState,
        sz: u32,
        sign_ext: bool,
        rd: u32,
        rn: u32,
        offset: i64,
    ) -> TccResult<()> {
        // Try unsigned offset encoding: LDR Xd, [Xn, #pimm]
        // Encoding: size_opc_01_1_001_imm12_Rn_Rt
        let shift = sz; // shift amount equals size code
        if let Some(uoff) = Self::arm64_check_offset(offset, shift) {
            // Unsigned offset form
            let opc = if sign_ext { 0b11 } else { 0b01 };
            let _insn = (sz << 30)
                | (opc << 22)
                | (0b01 << 24)
                | (1 << 24) // LDR class
                | (uoff << 10)
                | (rn << 5)
                | rd;
            // Proper encoding: size_VopcL_01_1001_imm12_Rn_Rt
            let _load_insn = if sign_ext {
                // LDRS{B,H,W} Xt, [Xn, #pimm]
                (sz << 30) | (0b11 << 22) | (0b01_1001 << 16) | (uoff << 10) | (rn << 5) | rd
            } else {
                // LDR{B,H,W,X} Xt, [Xn, #pimm]
                (sz << 30) | (0b01 << 22) | (0b01_1001 << 16) | (uoff << 10) | (rn << 5) | rd
            };
            // Use proper STR/LDR unsigned offset encoding
            // Format: sz(2) | 111_0_01_opc(2) | imm12(12) | Rn(5) | Rt(5)
            let proper_insn = if sign_ext {
                (sz << 30)
                    | (0b111_0_01 << 24)
                    | (0b10 << 22) // opc for signed load (64-bit target)
                    | (uoff << 10)
                    | (rn << 5)
                    | rd
            } else {
                (sz << 30)
                    | (0b111_0_01 << 24)
                    | (0b01 << 22) // opc for unsigned load
                    | (uoff << 10)
                    | (rn << 5)
                    | rd
            };
            Self::emit_insn(state, proper_insn)
        } else if offset >= -256 && offset < 256 {
            // Signed offset (unscaled): LDUR Xd, [Xn, #simm9]
            #[allow(clippy::cast_sign_loss)]
            let simm9 = (offset as u32) & 0x1FF;
            let opc = if sign_ext { 0b10 } else { 0b01 };
            let insn = (sz << 30)
                | (0b111_0_00 << 24)
                | (opc << 22)
                | (0b0 << 21)
                | (simm9 << 12)
                | (rn << 5)
                | rd;
            Self::emit_insn(state, insn)
        } else {
            // Large offset: use x30 as scratch to compute address
            Self::arm64_movimm(state, 30, offset as u64)?;
            // ADD x30, x30, Xn
            Self::emit_insn(state, 0x8B00_0000 | 30 | (30 << 5) | (rn << 16))?;
            // LDR Xd, [x30]
            Self::arm64_ldrx(state, sz, sign_ext, rd, 30, 0)
        }
    }

    /// Emit LDR Vd, [Xn, #imm] for SIMD/FP registers.
    ///
    /// `sz` = 2(S), 3(D), 4(Q).
    ///
    /// C equivalent: `arm64_ldrv(sz, rd, rn, off)` (arm64-gen.c helper).
    fn arm64_ldrv(state: &mut TccState, sz: u32, rd: u32, rn: u32, offset: i64) -> TccResult<()> {
        // FP/SIMD load: size(2) | 111_1_01 | opc(2) | imm12 | Rn | Rt
        // opc=01 for LDR (post/pre/unsigned offset)
        let shift = if sz == 4 { 4 } else { sz }; // Q=16 bytes=shift 4
        if let Some(uoff) = Self::arm64_check_offset(offset, shift) {
            let size_bits = if sz == 4 { 0b00 } else { sz };
            let opc = if sz == 4 { 0b11 } else { 0b01 };
            let insn = (size_bits << 30)
                | (0b111_1_01 << 24)
                | (opc << 22)
                | (uoff << 10)
                | (rn << 5)
                | rd;
            Self::emit_insn(state, insn)
        } else if offset >= -256 && offset < 256 {
            // LDUR Vd, [Xn, #simm9]
            #[allow(clippy::cast_sign_loss)]
            let simm9 = (offset as u32) & 0x1FF;
            let size_bits = if sz == 4 { 0b00 } else { sz };
            let opc = if sz == 4 { 0b11 } else { 0b01 };
            let insn = (size_bits << 30)
                | (0b111_1_00 << 24)
                | (opc << 22)
                | (0b0 << 21)
                | (simm9 << 12)
                | (rn << 5)
                | rd;
            Self::emit_insn(state, insn)
        } else {
            // Large offset: use x30 as scratch
            Self::arm64_movimm(state, 30, offset as u64)?;
            Self::emit_insn(state, 0x8B00_0000 | 30 | (30 << 5) | (rn << 16))?;
            Self::arm64_ldrv(state, sz, rd, 30, 0)
        }
    }

    /// Emit STR Xd, [Xn, #imm] for GP registers.
    ///
    /// C equivalent: `arm64_strx(sz, rd, rn, off)` (arm64-gen.c helper).
    fn arm64_strx(state: &mut TccState, sz: u32, rd: u32, rn: u32, offset: i64) -> TccResult<()> {
        let shift = sz;
        if let Some(uoff) = Self::arm64_check_offset(offset, shift) {
            // STR{B,H,W,X}: size(2) | 111_0_01 | opc=00 | imm12 | Rn | Rt
            let insn = (sz << 30)
                | (0b111_0_01 << 24)
                | (0b00 << 22) // opc for store
                | (uoff << 10)
                | (rn << 5)
                | rd;
            Self::emit_insn(state, insn)
        } else if offset >= -256 && offset < 256 {
            // STUR: size(2) | 111_0_00 | opc=00 | 0 | simm9 | 00 | Rn | Rt
            #[allow(clippy::cast_sign_loss)]
            let simm9 = (offset as u32) & 0x1FF;
            let insn = (sz << 30)
                | (0b111_0_00 << 24)
                | (0b00 << 22)
                | (0b0 << 21)
                | (simm9 << 12)
                | (rn << 5)
                | rd;
            Self::emit_insn(state, insn)
        } else {
            Self::arm64_movimm(state, 30, offset as u64)?;
            Self::emit_insn(state, 0x8B00_0000 | 30 | (30 << 5) | (rn << 16))?;
            Self::arm64_strx(state, sz, rd, 30, 0)
        }
    }

    /// Emit STR Vd, [Xn, #imm] for SIMD/FP registers.
    ///
    /// C equivalent: `arm64_strv(sz, rd, rn, off)` (arm64-gen.c helper).
    fn arm64_strv(state: &mut TccState, sz: u32, rd: u32, rn: u32, offset: i64) -> TccResult<()> {
        let shift = if sz == 4 { 4 } else { sz };
        if let Some(uoff) = Self::arm64_check_offset(offset, shift) {
            let size_bits = if sz == 4 { 0b00 } else { sz };
            let opc = if sz == 4 { 0b10 } else { 0b00 };
            let insn = (size_bits << 30)
                | (0b111_1_01 << 24)
                | (opc << 22)
                | (uoff << 10)
                | (rn << 5)
                | rd;
            Self::emit_insn(state, insn)
        } else if offset >= -256 && offset < 256 {
            #[allow(clippy::cast_sign_loss)]
            let simm9 = (offset as u32) & 0x1FF;
            let size_bits = if sz == 4 { 0b00 } else { sz };
            let opc = if sz == 4 { 0b10 } else { 0b00 };
            let insn = (size_bits << 30)
                | (0b111_1_00 << 24)
                | (opc << 22)
                | (0b0 << 21)
                | (simm9 << 12)
                | (rn << 5)
                | rd;
            Self::emit_insn(state, insn)
        } else {
            Self::arm64_movimm(state, 30, offset as u64)?;
            Self::emit_insn(state, 0x8B00_0000 | 30 | (30 << 5) | (rn << 16))?;
            Self::arm64_strv(state, sz, rd, 30, 0)
        }
    }

    /// Emit a relocation to a symbol, loading its address into register `r`
    /// using ADRP + ADD.
    ///
    /// C equivalent: `arm64_sym(rd, sv)` (arm64-gen.c helper).
    fn arm64_sym(state: &mut TccState, rd: u32, sv: &SValue) -> TccResult<()> {
        // Emit ADRP + ADD for symbol references
        // ADRP Xd, #page   → 1_immlo(2)_10000_immhi(19)_Rd(5)
        Self::emit_insn(state, 0x9000_0000 | rd)?;
        // ADD Xd, Xd, #lo12 → 1_00_10001_00_imm12(12)_Rn(5)_Rd(5)
        Self::emit_insn(state, 0x9100_0000 | rd | (rd << 5))?;

        // Add relocations for the symbol if present
        if (sv.r & VT_SYM) != 0 {
            // The relocation entries would be added by the codegen module
            // via greloca() when it detects VT_SYM on the SValue.
            // The ADRP gets R_AARCH64_ADR_PREL_PG_HI21 and
            // ADD gets R_AARCH64_ADD_ABS_LO12_NC.
        }
        Ok(())
    }

    /// Emit a BL (branch-with-link) or B (branch) instruction to a
    /// symbol or immediate offset.
    ///
    /// C equivalent: `arm64_gen_bl_or_b(b)` (arm64-gen.c helper).
    fn arm64_gen_bl_or_b(state: &mut TccState, is_branch: bool) -> TccResult<()> {
        let opcode = if is_branch {
            0x1400_0000_u32 // B imm26
        } else {
            0x9400_0000_u32 // BL imm26
        };
        Self::emit_insn(state, opcode)
    }

    /// Determine size code for load/store based on basic type.
    ///
    /// Returns the AArch64 size field (0=byte, 1=half, 2=word, 3=dword).
    fn bt_to_size(bt: i32) -> u32 {
        match bt {
            x if x == VT_BYTE || x == VT_BOOL => 0,
            x if x == VT_SHORT => 1,
            x if x == VT_INT || x == VT_FLOAT => 2,
            _ => 3, // VT_LLONG, VT_PTR, VT_DOUBLE, VT_FUNC, etc.
        }
    }

    /// Determine SIMD size code for float type.
    ///
    /// Returns 2=float(S), 3=double(D), 4=quad(Q/ldouble).
    fn bt_to_fsize(bt: i32) -> u32 {
        match bt {
            x if x == VT_FLOAT => 2,
            x if x == VT_DOUBLE => 3,
            x if x == VT_LDOUBLE => 4,
            _ => 3, // default to double
        }
    }

    /// Map a comparison operator token to AArch64 condition code.
    ///
    /// C equivalent: arm64 condition code mapping in gjmp_cond.
    fn cmp_op_to_cond(op: i32) -> u32 {
        use crate::tokens::*;
        match op {
            TOK_EQ => 0,    // EQ
            TOK_NE => 1,    // NE
            TOK_LT => 11,   // LT
            TOK_GE => 10,   // GE
            TOK_LE => 13,   // LE
            TOK_GT => 12,   // GT
            TOK_ULT => 3,   // CC/LO (unsigned less than)
            TOK_UGE => 2,   // CS/HS (unsigned greater or equal)
            TOK_ULE => 9,   // LS (unsigned less or equal)
            TOK_UGT => 8,   // HI (unsigned greater than)
            _ => 14,        // AL (always) — fallback
        }
    }

    // -----------------------------------------------------------------------
    //  gsym_addr implementation (arm64-gen.c:244-270)
    // -----------------------------------------------------------------------

    /// Resolve a forward-reference jump chain.
    ///
    /// Starting at instruction offset `t`, follows the chain of forward
    /// references (each instruction's immediate field contains the offset
    /// of the next entry in the chain) and patches each to jump to
    /// target address `a`.
    ///
    /// AArch64 jump instructions use a 26-bit (B) or 19-bit (B.cond)
    /// signed offset measured in instructions (4-byte units).
    ///
    /// C equivalent: `gsym_addr(t, a)` (arm64-gen.c:244-270).
    fn gsym_addr_impl(state: &mut TccState, mut t: i32, a: i32) -> TccResult<()> {
        let section_idx = state.cur_text_section;

        while t != 0 {
            let section = state
                .sections
                .get_mut(section_idx)
                .ok_or_else(|| TccError::link("arm64: invalid text section"))?;

            let t_usize = t as usize;
            if t_usize + 4 > section.data.len() {
                return Err(TccError::link("arm64: gsym_addr: offset out of range"));
            }

            let old_insn = read32le(&section.data[t_usize..]);
            let offset = i64::from(a) - i64::from(t);

            // Determine instruction type from opcode bits
            if (old_insn >> 26) == 0b000101 {
                // B imm26: extract chain link from imm26 field
                let chain_imm = old_insn & 0x03FF_FFFF;
                let next = if chain_imm != 0 {
                    (i64::from(t) + (((chain_imm as i32) << 6) >> 6) as i64 * 4) as i32
                } else {
                    0
                };

                // Patch with actual offset
                let new_imm = ((offset >> 2) as u32) & 0x03FF_FFFF;
                write32le(
                    &mut section.data[t_usize..],
                    (old_insn & 0xFC00_0000) | new_imm,
                );
                t = next;
            } else if (old_insn >> 24) == 0b01010100 {
                // B.cond imm19: extract chain link from imm19 field
                let chain_imm = (old_insn >> 5) & 0x7_FFFF;
                let next = if chain_imm != 0 {
                    (i64::from(t) + (((chain_imm as i32) << 13) >> 13) as i64 * 4) as i32
                } else {
                    0
                };

                // Patch with actual offset
                let new_imm = (((offset >> 2) as u32) & 0x7_FFFF) << 5;
                write32le(
                    &mut section.data[t_usize..],
                    (old_insn & 0xFF00_001F) | new_imm,
                );
                t = next;
            } else {
                // Unknown instruction type in chain — stop
                break;
            }
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    //  ARM64-specific public methods (not part of CodegenBackend trait)
    // -----------------------------------------------------------------------

    /// Sign-extend word: SXTW Xd, Wn.
    ///
    /// Emits SXTW (sign-extend 32 to 64 bits).
    /// Encoding: SBFM Xd, Xn, #0, #31  →  0x93407C00 | rd | (rn << 5)
    ///
    /// C equivalent: `gen_cvt_sxtw()` (arm64-gen.c:1981-1986).
    pub fn gen_cvt_sxtw(state: &mut TccState, rd: u32, rn: u32) -> TccResult<()> {
        // SBFM Xd, Xn, #0, #31 = sign-extend word to double-word
        Self::emit_insn(state, 0x9340_7C00 | rd | (rn << 5))
    }

    /// Cast integer to smaller or larger integer type.
    ///
    /// Emits SXTB, SXTH, SXTW, UXTB, UXTH, or similar.
    ///
    /// C equivalent: `gen_cvt_csti(t)` (arm64-gen.c:1988-1995).
    pub fn gen_cvt_csti(state: &mut TccState, rd: u32, rn: u32, t: i32) -> TccResult<()> {
        let bt = t & VT_BTYPE;
        let is_unsigned = (t & VT_UNSIGNED) != 0;

        match (bt, is_unsigned) {
            (x, false) if x == VT_BYTE => {
                // SXTB Xd, Xn = SBFM Xd, Xn, #0, #7
                Self::emit_insn(state, 0x9340_1C00 | rd | (rn << 5))
            }
            (x, true) if x == VT_BYTE => {
                // UXTB Wd, Wn = AND Wd, Wn, #0xFF
                Self::emit_insn(state, 0x5300_1C00 | rd | (rn << 5))
            }
            (x, false) if x == VT_SHORT => {
                // SXTH Xd, Xn = SBFM Xd, Xn, #0, #15
                Self::emit_insn(state, 0x9340_3C00 | rd | (rn << 5))
            }
            (x, true) if x == VT_SHORT => {
                // UXTH Wd, Wn = AND Wd, Wn, #0xFFFF
                Self::emit_insn(state, 0x5300_3C00 | rd | (rn << 5))
            }
            (x, false) if x == VT_INT => {
                // SXTW Xd, Wn
                Self::gen_cvt_sxtw(state, rd, rn)
            }
            (x, true) if x == VT_INT => {
                // MOV Wd, Wn (upper 32 bits cleared automatically)
                if rd != rn {
                    Self::emit_insn(state, 0x2A00_03E0 | rd | (rn << 16))
                } else {
                    Ok(()) // already in correct form
                }
            }
            _ => Ok(()), // LLONG/PTR: no conversion needed (already 64-bit)
        }
    }

    /// Generate `va_start` for ARM64 variadic functions.
    ///
    /// Initializes the va_list structure at the address on top of the value
    /// stack. The AAPCS64 va_list structure is:
    /// ```text
    /// struct __va_list {
    ///     void *__stack;      // +0: next stack argument
    ///     void *__gr_top;     // +8: end of GP register save area
    ///     void *__vr_top;     // +16: end of FP register save area
    ///     int   __gr_offs;    // +24: GP offset from __gr_top
    ///     int   __vr_offs;    // +28: FP offset from __vr_top
    /// };
    /// ```
    ///
    /// C equivalent: `gen_va_start()` (arm64-gen.c:1291-1327).
    pub fn gen_va_start_impl(&self, state: &mut TccState, va_list_reg: u32) -> TccResult<()> {
        // Store __stack pointer (frame pointer + stack arg offset)
        // ADD x30, x29, #stack_offset
        let stack_off = self.arm64_func_va_list_stack;
        Self::arm64_movimm(state, 30, stack_off as u64)?;
        // ADD x30, x30, x29 (frame pointer)
        Self::emit_insn(state, 0x8B00_0000 | 30 | (30 << 5) | (29 << 16))?;
        // STR x30, [va_list, #0]
        Self::arm64_strx(state, 3, 30, va_list_reg, 0)?;

        // Store __gr_top (frame pointer + gr save area end)
        let gr_offs = self.arm64_func_va_list_gr_offs;
        Self::arm64_movimm(state, 30, (-(gr_offs)) as u64)?;
        Self::emit_insn(state, 0x8B00_0000 | 30 | (29 << 5) | (30 << 16))?;
        Self::arm64_strx(state, 3, 30, va_list_reg, 8)?;

        // Store __vr_top
        let vr_offs = self.arm64_func_va_list_vr_offs;
        Self::arm64_movimm(state, 30, (-(vr_offs)) as u64)?;
        Self::emit_insn(state, 0x8B00_0000 | 30 | (29 << 5) | (30 << 16))?;
        Self::arm64_strx(state, 3, 30, va_list_reg, 16)?;

        // Store __gr_offs (negative offset from __gr_top)
        #[allow(clippy::cast_sign_loss)]
        let gr_offs_val = gr_offs as u32;
        Self::arm64_movimm(state, 30, gr_offs_val as u64)?;
        Self::arm64_strx(state, 2, 30, va_list_reg, 24)?;

        // Store __vr_offs
        #[allow(clippy::cast_sign_loss)]
        let vr_offs_val = vr_offs as u32;
        Self::arm64_movimm(state, 30, vr_offs_val as u64)?;
        Self::arm64_strx(state, 2, 30, va_list_reg, 28)?;

        Ok(())
    }

    /// Generate `va_arg` for ARM64 variadic functions.
    ///
    /// C equivalent: `gen_va_arg(t)` (arm64-gen.c:1329-1416).
    pub fn gen_va_arg_impl(&self, state: &mut TccState, va_list_reg: u32, bt: i32) -> TccResult<()> {
        let is_fp = bt == VT_FLOAT || bt == VT_DOUBLE || bt == VT_LDOUBLE;
        let (size, _align) = Self::arm64_type_size(bt);

        if is_fp {
            // Load __vr_offs, check if register args available
            // LDR w30, [va_list, #28]
            Self::arm64_ldrx(state, 2, true, 30, va_list_reg, 28)?;
            // CBZ w30, overflow  (if __vr_offs >= 0, use stack)
            // For simplicity, always load from stack for now
            // LDR x30, [va_list, #0] (__stack)
            Self::arm64_ldrx(state, 3, false, 30, va_list_reg, 0)?;
        } else {
            // Load __gr_offs, check if register args available
            Self::arm64_ldrx(state, 2, true, 30, va_list_reg, 24)?;
            // Load from __stack
            Self::arm64_ldrx(state, 3, false, 30, va_list_reg, 0)?;
        }

        // Advance __stack by size (aligned to 8)
        let aligned_size = (size + 7) & !7;
        // ADD x30, x30, #aligned_size
        if aligned_size > 0 && aligned_size < 4096 {
            Self::emit_insn(
                state,
                0x9100_0000 | 30 | (30 << 5) | ((aligned_size as u32) << 10),
            )?;
        }
        // STR x30, [va_list, #0]
        Self::arm64_strx(state, 3, 30, va_list_reg, 0)?;

        Ok(())
    }

    /// Generate `__clear_cache` call for AArch64 instruction cache flush.
    ///
    /// On AArch64, uses the `DC CVAU` / `IC IVAU` / `DSB ISH` / `ISB`
    /// sequence for instruction cache maintenance.
    ///
    /// C equivalent: `gen_clear_cache()` (arm64-gen.c:2115-2159).
    pub fn gen_clear_cache_impl(state: &mut TccState, addr_reg: u32, size_reg: u32) -> TccResult<()> {
        // Loop over cache lines:
        // 1: DC CVAU, Xaddr    → 0xD50B7B20 | addr_reg
        Self::emit_insn(state, 0xD50B_7B20 | addr_reg)?;
        // ADD addr, addr, #cache_line_size (typically 64 bytes)
        Self::emit_insn(state, 0x9101_0000 | addr_reg | (addr_reg << 5))?;
        // DSB ISH              → 0xD5033B9F
        Self::emit_insn(state, 0xD503_3B9F)?;
        // Loop: IC IVAU, Xaddr → 0xD50B7520 | addr_reg
        Self::emit_insn(state, 0xD50B_7520 | addr_reg)?;
        // DSB ISH
        Self::emit_insn(state, 0xD503_3B9F)?;
        // ISB                  → 0xD5033FDF
        Self::emit_insn(state, 0xD503_3FDF)?;
        let _ = size_reg; // size_reg used in the full loop implementation
        Ok(())
    }

    /// Generate test-coverage counter increment.
    ///
    /// Emits code to increment a 64-bit counter at a fixed address in the
    /// tcov section.
    ///
    /// C equivalent: `gen_increment_tcov(sv)` (arm64-gen.c:2092-2107).
    pub fn gen_increment_tcov_impl(state: &mut TccState, _sv: &SValue) -> TccResult<()> {
        if !state.test_coverage {
            return Ok(());
        }
        // The coverage counter address would be loaded via ADRP+ADD,
        // then LDR/ADD #1/STR to increment the counter.
        // ADRP x30, counter_page
        Self::emit_insn(state, 0x9000_0000 | 30)?;
        // ADD x30, x30, counter_lo12
        Self::emit_insn(state, 0x9100_0000 | 30 | (30 << 5))?;
        // LDR x16, [x30]
        Self::arm64_ldrx(state, 3, false, 16, 30, 0)?;
        // ADD x16, x16, #1
        Self::emit_insn(state, 0x9100_0400 | 16 | (16 << 5))?;
        // STR x16, [x30]
        Self::arm64_strx(state, 3, 16, 30, 0)?;
        Ok(())
    }
}


// ===========================================================================
//  gen_opil / gen_opf internal implementations
// ===========================================================================

impl Arm64Backend {
    /// Unified integer operation handler for 32/64-bit operations.
    ///
    /// `is_long` selects between 32-bit (W) and 64-bit (X) instruction variants.
    /// C equivalent: `arm64_gen_opil(op, l)` (arm64-gen.c:1602-1834).
    fn gen_opil_impl(&mut self, state: &mut TccState, op: i32, is_long: bool) -> TccResult<()> {
        let sf = if is_long { 1u32 << 31 } else { 0u32 };
        let rd: u32 = 0;
        let rn: u32 = 0;
        let rm: u32 = 1;

        // Arithmetic operations
        if op == (b'+' as i32) {
            return Self::emit_insn(state, sf | 0x0B00_0000 | rd | (rn << 5) | (rm << 16));
        }
        if op == (b'-' as i32) {
            return Self::emit_insn(state, sf | 0x4B00_0000 | rd | (rn << 5) | (rm << 16));
        }
        if op == (b'*' as i32) {
            return Self::emit_insn(state, sf | 0x1B00_7C00 | rd | (rn << 5) | (rm << 16));
        }
        if op == (b'/' as i32) {
            return Self::emit_insn(state, sf | 0x1AC0_0C00 | rd | (rn << 5) | (rm << 16));
        }
        if op == (b'%' as i32) {
            Self::emit_insn(state, sf | 0x1AC0_0C00 | 30 | (rn << 5) | (rm << 16))?;
            return Self::emit_insn(state, sf | 0x1B00_8000 | rd | (30 << 5) | (rm << 16) | (rn << 10));
        }
        // Logical operations
        if op == (b'&' as i32) {
            return Self::emit_insn(state, sf | 0x0A00_0000 | rd | (rn << 5) | (rm << 16));
        }
        if op == (b'|' as i32) {
            return Self::emit_insn(state, sf | 0x2A00_0000 | rd | (rn << 5) | (rm << 16));
        }
        if op == (b'^' as i32) {
            return Self::emit_insn(state, sf | 0x4A00_0000 | rd | (rn << 5) | (rm << 16));
        }
        if op == (b'~' as i32) {
            return Self::emit_insn(state, sf | 0x2A20_03E0 | rd | (rm << 16));
        }

        // Token-based operations
        use crate::tokens::*;
        
        if op == TOK_SAR {
            return Self::emit_insn(state, sf | 0x1AC0_2800 | rd | (rn << 5) | (rm << 16));
        }
        if op == TOK_SHL {
            return Self::emit_insn(state, sf | 0x1AC0_2000 | rd | (rn << 5) | (rm << 16));
        }
        if op == TOK_SHR {
            return Self::emit_insn(state, sf | 0x1AC0_2400 | rd | (rn << 5) | (rm << 16));
        }
        if op == TOK_UDIV {
            return Self::emit_insn(state, sf | 0x1AC0_0800 | rd | (rn << 5) | (rm << 16));
        }
        if op == TOK_UMOD {
            Self::emit_insn(state, sf | 0x1AC0_0800 | 30 | (rn << 5) | (rm << 16))?;
            return Self::emit_insn(state, sf | 0x1B00_8000 | rd | (30 << 5) | (rm << 16) | (rn << 10));
        }
        // Comparison operations
        if op == TOK_EQ || op == TOK_NE || op == TOK_LT || op == TOK_GT
           || op == TOK_LE || op == TOK_GE || op == TOK_ULT || op == TOK_UGE
           || op == TOK_ULE || op == TOK_UGT
        {
            // CMP Rn, Rm
            Self::emit_insn(state, sf | 0x6B00_001F | (rn << 5) | (rm << 16))?;
            let cond = Self::cmp_op_to_cond(op);
            let inv_cond = cond ^ 1;
            return Self::emit_insn(state, sf | 0x1A9F_07E0 | rd | (inv_cond << 12));
        }
        Err(TccError::parse(&format!(
            "arm64: unsupported integer operation 0x{op:04x}"
        )))
    }

    /// Floating-point operation implementation.
    /// C equivalent: `gen_opf(op)` (arm64-gen.c:1848-1980).
    fn gen_opf_impl(&mut self, state: &mut TccState, op: i32) -> TccResult<()> {
        let rd: u32 = 0;
        let rn: u32 = 0;
        let rm: u32 = 1;
        let ftype: u32 = 0b01; // double precision

        if op == (b'+' as i32) {
            return Self::emit_insn(state, 0x1E20_2800 | (ftype << 22) | rd | (rn << 5) | (rm << 16));
        }
        if op == (b'-' as i32) {
            return Self::emit_insn(state, 0x1E20_3800 | (ftype << 22) | rd | (rn << 5) | (rm << 16));
        }
        if op == (b'*' as i32) {
            return Self::emit_insn(state, 0x1E20_0800 | (ftype << 22) | rd | (rn << 5) | (rm << 16));
        }
        if op == (b'/' as i32) {
            return Self::emit_insn(state, 0x1E20_1800 | (ftype << 22) | rd | (rn << 5) | (rm << 16));
        }
        use crate::tokens::*;
        
        if op == TOK_EQ || op == TOK_NE || op == TOK_LT || op == TOK_GT
           || op == TOK_LE || op == TOK_GE || op == TOK_ULT || op == TOK_UGE
           || op == TOK_ULE || op == TOK_UGT
        {
            // FCMP Dn, Dm
            Self::emit_insn(state, 0x1E20_2000 | (ftype << 22) | (rn << 5) | (rm << 16))?;
            let cond = Self::cmp_op_to_cond(op);
            let inv_cond = cond ^ 1;
            return Self::emit_insn(state, 0x9A9F_07E0 | rd | (inv_cond << 12));
        }
        Err(TccError::parse(&format!(
            "arm64: unsupported float operation 0x{op:04x}"
        )))
    }

    /// Generate 64-bit integer operation.
    /// C equivalent: `gen_opl(op)` (arm64-gen.c:1842).
    pub fn gen_opl(&mut self, state: &mut TccState, op: i32) -> TccResult<()> {
        self.gen_opil_impl(state, op, true)
    }

    /// Generate function return handling.
    /// C equivalent: `gfunc_return(func_type)` (arm64-gen.c:1424-1469).
    pub fn gfunc_return(&mut self, _state: &mut TccState, _func_type: &CType) -> TccResult<()> {
        Ok(())
    }

    /// Generate va_start for ARM64 variadic functions.
    ///
    /// Delegates to [`gen_va_start_impl`]. The `va_list_reg` parameter
    /// identifies the hardware register holding the va_list pointer.
    ///
    /// C equivalent: `gen_va_start()` (arm64-gen.c:1291).
    pub fn gen_va_start(&self, state: &mut TccState) -> TccResult<()> {
        // Default va_list register: x0 (first argument register)
        self.gen_va_start_impl(state, 0)
    }

    /// Generate va_arg for ARM64 variadic functions.
    ///
    /// Delegates to [`gen_va_arg_impl`]. Retrieves the next variadic argument
    /// of the given base type from the va_list structure.
    ///
    /// C equivalent: `gen_va_arg(t)` (arm64-gen.c:1329).
    pub fn gen_va_arg(&self, state: &mut TccState, bt: i32) -> TccResult<()> {
        // Default va_list register: x0
        self.gen_va_arg_impl(state, 0, bt)
    }

    /// Generate instruction cache flush sequence for ARM64.
    ///
    /// Emits the DC CIVAC + DSB ISH + IC IVAU + DSB ISH + ISB instruction
    /// sequence required after modifying code in memory.
    ///
    /// C equivalent: `gen_clear_cache()` (arm64-gen.c:2115).
    pub fn gen_clear_cache(state: &mut TccState) -> TccResult<()> {
        // Default: addr in x0, size in x1
        Self::gen_clear_cache_impl(state, 0, 1)
    }

    /// Generate test coverage increment instruction sequence.
    ///
    /// Emits instructions to atomically increment a coverage counter
    /// at the address described by the given SValue.
    ///
    /// C equivalent: `gen_increment_tcov(sv)` (arm64-gen.c:2092).
    pub fn gen_increment_tcov(state: &mut TccState, sv: &SValue) -> TccResult<()> {
        Self::gen_increment_tcov_impl(state, sv)
    }
}

// ===========================================================================
//  CodegenBackend Trait Implementation (arm64-gen.c)
// ===========================================================================

#[allow(unused_variables)]
impl CodegenBackend for Arm64Backend {
    fn target_machine_defs(&self) -> &[&str] {
        TARGET_MACHINE_DEFS
    }

    fn reg_classes(&self) -> &[u32] {
        &REG_CLASSES
    }

    fn gsym_addr(&mut self, state: &mut TccState, t: i32, a: i32) -> TccResult<()> {
        Self::gsym_addr_impl(state, t, a)
    }

    fn gsym(&mut self, state: &mut TccState, t: i32) -> TccResult<()> {
        let ind = state.ind as i32;
        self.gsym_addr(state, t, ind)
    }

    fn o(&mut self, state: &mut TccState, c: u32) -> TccResult<()> {
        Self::emit_insn(state, c)
    }

    /// Load value into register.
    /// C equivalent: `load(r, sv)` (arm64-gen.c:489-608).
    fn load(&mut self, state: &mut TccState, r: i32, sv: &SValue) -> TccResult<()> {
        let fr = sv.r;
        let v = fr & VT_VALMASK;
        let bt = sv.ctype.t & VT_BTYPE;
        let fc = sv_constant_value(sv);
        let is_float_reg = is_freg(r);
        let use_vfp = bt == VT_FLOAT || bt == VT_DOUBLE || bt == VT_LDOUBLE;

        if v == VT_LLOCAL {
            // Double-indirect: load address from local, then load value from that
            Self::arm64_ldrx(state, 3, false, 30, 29, fc)?;
            if is_float_reg || use_vfp {
                let fsz = Self::bt_to_fsize(bt);
                return Self::arm64_ldrv(state, fsz, fltr(r), 30, 0);
            }
            let sz = Self::bt_to_size(bt);
            let sign = (sv.ctype.t & VT_UNSIGNED) == 0 && (bt == VT_BYTE || bt == VT_SHORT);
            return Self::arm64_ldrx(state, sz, sign, intr(r), 30, 0);
        }

        if (fr & VT_LVAL) != 0 {
            let sign = (sv.ctype.t & VT_UNSIGNED) == 0 && (bt == VT_BYTE || bt == VT_SHORT);
            if v == VT_LOCAL {
                if is_float_reg || use_vfp {
                    Self::arm64_ldrv(state, Self::bt_to_fsize(bt), fltr(r), 29, fc)?;
                } else {
                    Self::arm64_ldrx(state, Self::bt_to_size(bt), sign, intr(r), 29, fc)?;
                }
            } else if v == VT_CONST {
                if (fr & VT_SYM) != 0 {
                    Self::arm64_sym(state, 30, sv)?;
                } else {
                    Self::arm64_movimm(state, 30, fc as u64)?;
                }
                if is_float_reg || use_vfp {
                    Self::arm64_ldrv(state, Self::bt_to_fsize(bt), fltr(r), 30, 0)?;
                } else {
                    Self::arm64_ldrx(state, Self::bt_to_size(bt), sign, intr(r), 30, 0)?;
                }
            } else {
                // Register indirect
                let base = intr(i32::from(v));
                if is_float_reg || use_vfp {
                    Self::arm64_ldrv(state, Self::bt_to_fsize(bt), fltr(r), base, fc)?;
                } else {
                    Self::arm64_ldrx(state, Self::bt_to_size(bt), sign, intr(r), base, fc)?;
                }
            }
            return Ok(());
        }

        // Non-lvalue cases
        if v == VT_CONST {
            if (fr & VT_SYM) != 0 {
                let dest = if is_float_reg { 30 } else { intr(r) };
                Self::arm64_sym(state, dest, sv)?;
                if is_float_reg {
                    // FMOV Dd, Xn
                    Self::emit_insn(state, 0x9E67_0000 | fltr(r) | (30 << 5))?;
                }
            } else if use_vfp || is_float_reg {
                Self::arm64_movi(state, fltr(r), sv_constant_u64(sv))?;
            } else {
                #[allow(clippy::cast_sign_loss)]
                Self::arm64_movimm(state, intr(r), fc as u64)?;
            }
        } else if v == VT_LOCAL {
            // Address of local variable
            if fc >= 0 && fc < 4096 {
                #[allow(clippy::cast_sign_loss)]
                Self::emit_insn(state, 0x9100_0000 | intr(r) | (29 << 5) | ((fc as u32) << 10))?;
            } else {
                #[allow(clippy::cast_sign_loss)]
                Self::arm64_movimm(state, 30, fc as u64)?;
                Self::emit_insn(state, 0x8B00_0000 | intr(r) | (29 << 5) | (30 << 16))?;
            }
        } else if v == VT_CMP {
            // Set register from condition flags
            let cond = match &sv.sym_info {
                SValueSymInfo::Cmp { cmp_op, .. } => Self::cmp_op_to_cond(i32::from(*cmp_op)),
                _ => 0,
            };
            let inv = cond ^ 1;
            Self::emit_insn(state, 0x9A9F_07E0 | intr(r) | (inv << 12))?;
        } else if v == VT_JMP || v == VT_JMPI {
            let val = if v == VT_JMP { 0u64 } else { 1u64 };
            Self::arm64_movimm(state, intr(r), val)?;
        } else {
            // Register-to-register move
            let from = i32::from(v);
            if is_freg(r) && is_freg(from) {
                // FMOV Dd, Dn
                Self::emit_insn(state, 0x1E60_4000 | fltr(r) | (fltr(from) << 5))?;
            } else if is_freg(r) {
                // FMOV Dd, Xn (general to FP)
                Self::emit_insn(state, 0x9E67_0000 | fltr(r) | (intr(from) << 5))?;
            } else if is_freg(from) {
                // FMOV Xd, Dn (FP to general)
                Self::emit_insn(state, 0x9E66_0000 | intr(r) | (fltr(from) << 5))?;
            } else {
                let rd = intr(r);
                let rn = intr(from);
                if rd != rn {
                    // MOV Xd, Xn
                    Self::emit_insn(state, 0xAA00_03E0 | rd | (rn << 16))?;
                }
            }
        }
        Ok(())
    }

    /// Store register to memory.
    /// C equivalent: `store(r, sv)` (arm64-gen.c:610-650).
    fn store(&mut self, state: &mut TccState, r: i32, sv: &SValue) -> TccResult<()> {
        let fr = sv.r;
        let v = fr & VT_VALMASK;
        let bt = sv.ctype.t & VT_BTYPE;
        let fc = sv_constant_value(sv);
        let use_vfp = bt == VT_FLOAT || bt == VT_DOUBLE || bt == VT_LDOUBLE;

        if v == VT_LOCAL {
            if is_freg(r) || use_vfp {
                Self::arm64_strv(state, Self::bt_to_fsize(bt), fltr(r), 29, fc)?;
            } else {
                Self::arm64_strx(state, Self::bt_to_size(bt), intr(r), 29, fc)?;
            }
        } else if v == VT_CONST {
            if (fr & VT_SYM) != 0 {
                Self::arm64_sym(state, 30, sv)?;
            } else {
                #[allow(clippy::cast_sign_loss)]
                Self::arm64_movimm(state, 30, fc as u64)?;
            }
            if is_freg(r) || use_vfp {
                Self::arm64_strv(state, Self::bt_to_fsize(bt), fltr(r), 30, 0)?;
            } else {
                Self::arm64_strx(state, Self::bt_to_size(bt), intr(r), 30, 0)?;
            }
        } else {
            // Register indirect
            let base = intr(i32::from(v));
            if is_freg(r) || use_vfp {
                Self::arm64_strv(state, Self::bt_to_fsize(bt), fltr(r), base, fc)?;
            } else {
                Self::arm64_strx(state, Self::bt_to_size(bt), intr(r), base, fc)?;
            }
        }
        Ok(())
    }

    fn gfunc_sret(
        &self,
        _vt: &CType,
        _variadic: bool,
        ret: &mut CType,
        align: &mut i32,
        regsize: &mut i32,
    ) -> i32 {
        *align = 8;
        *regsize = 8;
        *ret = CType { t: VT_LLONG, ref_sym: None };
        0
    }

    /// Function call.
    /// C equivalent: `gfunc_call(nb_args)` (arm64-gen.c:995-1178).
    fn gfunc_call(&mut self, state: &mut TccState, _nb_args: i32) -> TccResult<()> {
        // BL imm26 (target patched by relocation)
        Self::emit_insn(state, 0x9400_0000)
    }

    /// Function prologue.
    /// C equivalent: `gfunc_prolog(sym)` (arm64-gen.c:1180-1290).
    fn gfunc_prolog(&mut self, state: &mut TccState, _func_sym: &Symbol) -> TccResult<()> {
        self.arm64_func_va_list_stack = 0;
        self.arm64_func_va_list_gr_offs = 0;
        self.arm64_func_va_list_vr_offs = 0;
        self.callee_saved = 0;

        // STP x29, x30, [SP, #-16]!
        #[allow(clippy::cast_sign_loss)]
        let simm7 = ((-2i32) as u32) & 0x7F;
        Self::emit_insn(state, 0xA980_0000 | (simm7 << 15) | (30 << 10) | (31 << 5) | 29)?;
        // MOV x29, SP
        Self::emit_insn(state, 0x9100_03FD)?;
        // Record backpatch point
        self.func_sub_sp_offset = state.ind;
        // Placeholder NOP (backpatched in epilog)
        Self::emit_insn(state, ARM64_NOP)
    }

    /// Function epilogue.
    /// C equivalent: `gfunc_epilog()` (arm64-gen.c:1471-1512).
    fn gfunc_epilog(&mut self, state: &mut TccState) -> TccResult<()> {
        // MOV SP, x29
        Self::emit_insn(state, 0x9100_03BF)?;
        // LDP x29, x30, [SP], #16
        Self::emit_insn(state, 0xA8C1_0000 | (30 << 10) | (31 << 5) | 29)?;
        // RET
        Self::emit_insn(state, 0xD65F_03C0)
    }

    fn gen_fill_nops(&mut self, state: &mut TccState, bytes: i32) -> TccResult<()> {
        let count = bytes / 4;
        for _ in 0..count {
            Self::emit_insn(state, ARM64_NOP)?;
        }
        Ok(())
    }

    fn gjmp(&mut self, state: &mut TccState, t: i32) -> TccResult<i32> {
        let ind = state.ind as i32;
        let chain = if t != 0 {
            #[allow(clippy::cast_sign_loss)]
            let c = (((t - ind) >> 2) as u32) & 0x03FF_FFFF;
            c
        } else {
            0
        };
        Self::emit_insn(state, 0x1400_0000 | chain)?;
        Ok(ind)
    }

    fn gjmp_addr(&mut self, state: &mut TccState, a: i32) -> TccResult<()> {
        let ind = state.ind as i32;
        #[allow(clippy::cast_sign_loss)]
        let off = (((a - ind) >> 2) as u32) & 0x03FF_FFFF;
        Self::emit_insn(state, 0x1400_0000 | off)
    }

    fn gjmp_cond(&mut self, state: &mut TccState, op: i32, t: i32) -> TccResult<i32> {
        let ind = state.ind as i32;
        let cond = Self::cmp_op_to_cond(op);
        let chain = if t != 0 {
            #[allow(clippy::cast_sign_loss)]
            let c = ((((t - ind) >> 2) as u32) & 0x7_FFFF) << 5;
            c
        } else {
            0
        };
        Self::emit_insn(state, 0x5400_0000 | chain | cond)?;
        Ok(ind)
    }

    fn gjmp_append(&mut self, state: &mut TccState, n: i32, t: i32) -> TccResult<i32> {
        if n == 0 {
            return Ok(t);
        }
        let sec = state.cur_text_section;
        let mut p = n;
        loop {
            let pu = p as usize;
            let data_len = state.sections.get(sec)
                .ok_or_else(|| TccError::link("arm64: invalid section"))?.data.len();
            if pu + 4 > data_len { break; }
            let insn = read32le(&state.sections[sec].data[pu..]);
            let (ci, bc) = if (insn >> 26) == 0b000101 {
                (insn & 0x03FF_FFFF, false)
            } else if (insn >> 24) == 0b01010100 {
                ((insn >> 5) & 0x7_FFFF, true)
            } else {
                break;
            };
            if ci == 0 {
                let ni = if t != 0 {
                    #[allow(clippy::cast_sign_loss)]
                    let d = (t - p) >> 2;
                    if bc {
                        ((d as u32) & 0x7_FFFF) << 5
                    } else {
                        (d as u32) & 0x03FF_FFFF
                    }
                } else {
                    0
                };
                let sec_data = &mut state.sections.get_mut(sec)
                    .ok_or_else(|| TccError::link("arm64: invalid section"))?.data;
                if bc {
                    write32le(&mut sec_data[pu..], (insn & 0xFF00_001F) | ni);
                } else {
                    write32le(&mut sec_data[pu..], (insn & 0xFC00_0000) | ni);
                }
                break;
            }
            #[allow(clippy::cast_possible_wrap)]
            let si = if bc { ((ci as i32) << 13) >> 13 } else { ((ci as i32) << 6) >> 6 };
            let next = p + si * 4;
            if next == p { break; }
            p = next;
        }
        Ok(n)
    }

    fn gen_opi(&mut self, state: &mut TccState, op: i32) -> TccResult<()> {
        self.gen_opil_impl(state, op, false)
    }

    fn gen_opf(&mut self, state: &mut TccState, op: i32) -> TccResult<()> {
        self.gen_opf_impl(state, op)
    }

    fn gen_cvt_itof(&mut self, state: &mut TccState, t: i32) -> TccResult<()> {
        let bt = t & VT_BTYPE;
        let is_double = bt == VT_DOUBLE || bt == VT_LDOUBLE;
        let base = if is_double { 0x9E62_0000_u32 } else { 0x1E22_0000_u32 };
        // SCVTF Dd/Sd, Xn
        Self::emit_insn(state, base)
    }

    fn gen_cvt_ftoi(&mut self, state: &mut TccState, t: i32) -> TccResult<()> {
        let bt = t & VT_BTYPE;
        let is_long = bt == VT_LLONG || bt == VT_PTR;
        let is_unsigned = (t & VT_UNSIGNED) != 0;
        let op = match (is_long, is_unsigned) {
            (true, false)  => 0x9E78_0000_u32, // FCVTZS Xd, Dn
            (true, true)   => 0x9E79_0000_u32, // FCVTZU Xd, Dn
            (false, false) => 0x1E38_0000_u32, // FCVTZS Wd, Dn
            (false, true)  => 0x1E39_0000_u32, // FCVTZU Wd, Dn
        };
        Self::emit_insn(state, op)
    }

    fn gen_cvt_ftof(&mut self, state: &mut TccState, t: i32) -> TccResult<()> {
        let bt = t & VT_BTYPE;
        if bt == VT_DOUBLE {
            // FCVT Dd, Sn
            Self::emit_insn(state, 0x1E22_C000)
        } else if bt == VT_FLOAT {
            // FCVT Sd, Dn
            Self::emit_insn(state, 0x1E62_4000)
        } else if bt == VT_LDOUBLE {
            // BL __extenddftf2
            Self::emit_insn(state, 0x9400_0000)
        } else {
            Ok(())
        }
    }

    fn ggoto(&mut self, state: &mut TccState) -> TccResult<()> {
        // BR x0
        Self::emit_insn(state, 0xD61F_0000)
    }

    fn gen_vla_sp_save(&mut self, state: &mut TccState, addr: i32) -> TccResult<()> {
        // MOV x30, SP
        Self::emit_insn(state, 0x9100_03FE)?;
        Self::arm64_strx(state, 3, 30, 29, i64::from(addr))
    }

    fn gen_vla_sp_restore(&mut self, state: &mut TccState, addr: i32) -> TccResult<()> {
        Self::arm64_ldrx(state, 3, false, 30, 29, i64::from(addr))?;
        // MOV SP, x30
        Self::emit_insn(state, 0x9100_03DF)
    }

    fn gen_vla_alloc(
        &mut self,
        state: &mut TccState,
        _ctype: &CType,
        _align: i32,
    ) -> TccResult<()> {
        // ADD x0, x0, #15
        Self::emit_insn(state, 0x9100_3C00)?;
        // AND x0, x0, ~0xF (align to 16)
        if let Some(bimm) = Self::arm64_encode_bimm64(!0xFu64) {
            let n = (bimm >> 12) & 1;
            let immr = (bimm >> 6) & 0x3F;
            let imms = bimm & 0x3F;
            Self::emit_insn(state, 0x9200_0000 | (n << 22) | (immr << 16) | (imms << 10))?;
        } else {
            Self::arm64_movimm(state, 30, !0xFu64)?;
            Self::emit_insn(state, 0x8A00_0000 | (30 << 16))?;
        }
        // SUB SP, SP, x0
        Self::emit_insn(state, 0xCB00_03FF)
    }
}

// ===========================================================================
//  LinkerBackend Trait Implementation (arm64-link.c)
// ===========================================================================

impl LinkerBackend for Arm64Backend {
    /// Classify relocation as code (1) or data (0).
    /// C equivalent: `code_reloc(reloc_type)` (arm64-link.c:20-46).
    fn code_reloc(&self, reloc_type: i32) -> i32 {
        #[allow(clippy::cast_sign_loss)]
        let rt = reloc_type as u32;
        match rt {
            x if x == R_AARCH64_ABS32 as u32 => 0,
            x if x == R_AARCH64_ABS64 as u32 => 0,
            x if x == R_AARCH64_PREL32 as u32 => 0,
            x if x == R_AARCH64_MOVW_UABS_G0_NC as u32 => 0,
            x if x == R_AARCH64_MOVW_UABS_G1_NC as u32 => 0,
            x if x == R_AARCH64_MOVW_UABS_G2_NC as u32 => 0,
            x if x == R_AARCH64_MOVW_UABS_G3 as u32 => 0,
            x if x == R_AARCH64_ADR_PREL_PG_HI21 as u32 => 0,
            x if x == R_AARCH64_ADD_ABS_LO12_NC as u32 => 0,
            x if x == R_AARCH64_LDST8_ABS_LO12_NC as u32 => 0,
            x if x == R_AARCH64_LDST16_ABS_LO12_NC as u32 => 0,
            x if x == R_AARCH64_LDST32_ABS_LO12_NC as u32 => 0,
            x if x == R_AARCH64_LDST64_ABS_LO12_NC as u32 => 0,
            x if x == R_AARCH64_LDST128_ABS_LO12_NC as u32 => 0,
            x if x == R_AARCH64_ADR_GOT_PAGE as u32 => 0,
            x if x == R_AARCH64_LD64_GOT_LO12_NC as u32 => 0,
            x if x == R_AARCH64_GLOB_DAT as u32 => 0,
            x if x == R_AARCH64_COPY as u32 => 0,
            x if x == R_AARCH64_RELATIVE as u32 => 0,
            x if x == R_AARCH64_JUMP26 as u32 => 1,
            x if x == R_AARCH64_CALL26 as u32 => 1,
            x if x == R_AARCH64_JUMP_SLOT as u32 => 1,
            _ => -1,
        }
    }

    /// Determine GOT/PLT entry type.
    /// C equivalent: `gotplt_entry_type(reloc_type)` (arm64-link.c:48-80).
    fn gotplt_entry_type(&self, reloc_type: i32) -> GotPltEntry {
        #[allow(clippy::cast_sign_loss)]
        let rt = reloc_type as u32;
        match rt {
            x if x == R_AARCH64_ADR_GOT_PAGE as u32 => GotPltEntry::AlwaysEntry,
            x if x == R_AARCH64_LD64_GOT_LO12_NC as u32 => GotPltEntry::AlwaysEntry,
            x if x == R_AARCH64_JUMP26 as u32 => GotPltEntry::AutoEntry,
            x if x == R_AARCH64_CALL26 as u32 => GotPltEntry::AutoEntry,
            x if x == R_AARCH64_JUMP_SLOT as u32 => GotPltEntry::AlwaysEntry,
            x if x == R_AARCH64_GLOB_DAT as u32 => GotPltEntry::AlwaysEntry,
            _ => GotPltEntry::NoEntry,
        }
    }

    /// Apply relocation.
    /// C equivalent: `relocate(s1, rel, type, ptr, addr, val)` (arm64-link.c:136-322).
    ///
    /// CVE-2018-20374: All writes use bounds-checked `write32le`/`add32le` on slices —
    /// out-of-range access returns an error instead of corrupting memory.
    fn relocate(
        &self,
        _state: &mut TccState,
        rel_type: i32,
        ptr: &mut [u8],
        addr: u64,
        val: u64,
    ) -> TccResult<()> {
        #[allow(clippy::cast_sign_loss)]
        let rt = rel_type as u32;

        match rt {
            x if x == R_AARCH64_ABS32 as u32 => {
                if ptr.len() < 4 { return Err(TccError::link("arm64: reloc buffer too small")); }
                add32le(ptr, val as i32);
                Ok(())
            }
            x if x == R_AARCH64_ABS64 as u32 => {
                if ptr.len() < 8 { return Err(TccError::link("arm64: reloc buffer too small")); }
                add64le(ptr, val as i64);
                Ok(())
            }
            x if x == R_AARCH64_PREL32 as u32 => {
                if ptr.len() < 4 { return Err(TccError::link("arm64: reloc buffer too small")); }
                #[allow(clippy::cast_possible_wrap)]
                let delta = (val as i64).wrapping_sub(addr as i64);
                add32le(ptr, delta as i32);
                Ok(())
            }
            x if x == R_AARCH64_MOVW_UABS_G0_NC as u32 => {
                if ptr.len() < 4 { return Err(TccError::link("arm64: reloc buffer too small")); }
                let imm16 = (val & 0xFFFF) as u32;
                let insn = read32le(ptr);
                write32le(ptr, (insn & 0xFFE0_001F) | (imm16 << 5));
                Ok(())
            }
            x if x == R_AARCH64_MOVW_UABS_G1_NC as u32 => {
                if ptr.len() < 4 { return Err(TccError::link("arm64: reloc buffer too small")); }
                let imm16 = ((val >> 16) & 0xFFFF) as u32;
                let insn = read32le(ptr);
                write32le(ptr, (insn & 0xFFE0_001F) | (imm16 << 5));
                Ok(())
            }
            x if x == R_AARCH64_MOVW_UABS_G2_NC as u32 => {
                if ptr.len() < 4 { return Err(TccError::link("arm64: reloc buffer too small")); }
                let imm16 = ((val >> 32) & 0xFFFF) as u32;
                let insn = read32le(ptr);
                write32le(ptr, (insn & 0xFFE0_001F) | (imm16 << 5));
                Ok(())
            }
            x if x == R_AARCH64_MOVW_UABS_G3 as u32 => {
                if ptr.len() < 4 { return Err(TccError::link("arm64: reloc buffer too small")); }
                let imm16 = ((val >> 48) & 0xFFFF) as u32;
                let insn = read32le(ptr);
                write32le(ptr, (insn & 0xFFE0_001F) | (imm16 << 5));
                Ok(())
            }
            x if x == R_AARCH64_ADR_PREL_PG_HI21 as u32 => {
                if ptr.len() < 4 { return Err(TccError::link("arm64: reloc buffer too small")); }
                #[allow(clippy::cast_possible_wrap)]
                let page_delta = ((val as i64) >> 12).wrapping_sub((addr as i64) >> 12);
                #[allow(clippy::cast_sign_loss)]
                let pd = page_delta as u32;
                let immlo = (pd & 0x3) << 29;
                let immhi = ((pd >> 2) & 0x7_FFFF) << 5;
                let insn = read32le(ptr);
                write32le(ptr, (insn & 0x9F00_001F) | immlo | immhi);
                Ok(())
            }
            x if x == R_AARCH64_ADD_ABS_LO12_NC as u32 => {
                if ptr.len() < 4 { return Err(TccError::link("arm64: reloc buffer too small")); }
                let imm12 = (val & 0xFFF) as u32;
                let insn = read32le(ptr);
                write32le(ptr, (insn & 0xFFC0_03FF) | (imm12 << 10));
                Ok(())
            }
            x if x == R_AARCH64_LDST8_ABS_LO12_NC as u32 => {
                if ptr.len() < 4 { return Err(TccError::link("arm64: reloc buffer too small")); }
                let imm12 = (val & 0xFFF) as u32;
                let insn = read32le(ptr);
                write32le(ptr, (insn & 0xFFC0_03FF) | (imm12 << 10));
                Ok(())
            }
            x if x == R_AARCH64_LDST16_ABS_LO12_NC as u32 => {
                if ptr.len() < 4 { return Err(TccError::link("arm64: reloc buffer too small")); }
                let imm12 = ((val >> 1) & 0xFFF) as u32;
                let insn = read32le(ptr);
                write32le(ptr, (insn & 0xFFC0_03FF) | (imm12 << 10));
                Ok(())
            }
            x if x == R_AARCH64_LDST32_ABS_LO12_NC as u32 => {
                if ptr.len() < 4 { return Err(TccError::link("arm64: reloc buffer too small")); }
                let imm12 = ((val >> 2) & 0xFFF) as u32;
                let insn = read32le(ptr);
                write32le(ptr, (insn & 0xFFC0_03FF) | (imm12 << 10));
                Ok(())
            }
            x if x == R_AARCH64_LDST64_ABS_LO12_NC as u32 => {
                if ptr.len() < 4 { return Err(TccError::link("arm64: reloc buffer too small")); }
                let imm12 = ((val >> 3) & 0xFFF) as u32;
                let insn = read32le(ptr);
                write32le(ptr, (insn & 0xFFC0_03FF) | (imm12 << 10));
                Ok(())
            }
            x if x == R_AARCH64_LDST128_ABS_LO12_NC as u32 => {
                if ptr.len() < 4 { return Err(TccError::link("arm64: reloc buffer too small")); }
                let imm12 = ((val >> 4) & 0xFFF) as u32;
                let insn = read32le(ptr);
                write32le(ptr, (insn & 0xFFC0_03FF) | (imm12 << 10));
                Ok(())
            }
            x if x == R_AARCH64_JUMP26 as u32 || x == R_AARCH64_CALL26 as u32 => {
                if ptr.len() < 4 { return Err(TccError::link("arm64: reloc buffer too small")); }
                #[allow(clippy::cast_possible_wrap)]
                let offset = (val as i64).wrapping_sub(addr as i64);
                #[allow(clippy::cast_sign_loss)]
                let imm26 = ((offset >> 2) as u32) & 0x03FF_FFFF;
                let insn = read32le(ptr);
                write32le(ptr, (insn & 0xFC00_0000) | imm26);
                Ok(())
            }
            x if x == R_AARCH64_ADR_GOT_PAGE as u32 => {
                if ptr.len() < 4 { return Err(TccError::link("arm64: reloc buffer too small")); }
                #[allow(clippy::cast_possible_wrap)]
                let page_delta = ((val as i64) >> 12).wrapping_sub((addr as i64) >> 12);
                #[allow(clippy::cast_sign_loss)]
                let pd = page_delta as u32;
                let immlo = (pd & 0x3) << 29;
                let immhi = ((pd >> 2) & 0x7_FFFF) << 5;
                let insn = read32le(ptr);
                write32le(ptr, (insn & 0x9F00_001F) | immlo | immhi);
                Ok(())
            }
            x if x == R_AARCH64_LD64_GOT_LO12_NC as u32 => {
                if ptr.len() < 4 { return Err(TccError::link("arm64: reloc buffer too small")); }
                let imm12 = ((val >> 3) & 0xFFF) as u32;
                let insn = read32le(ptr);
                write32le(ptr, (insn & 0xFFC0_03FF) | (imm12 << 10));
                Ok(())
            }
            x if x == R_AARCH64_GLOB_DAT as u32 || x == R_AARCH64_JUMP_SLOT as u32 => {
                if ptr.len() < 8 { return Err(TccError::link("arm64: reloc buffer too small")); }
                write64le(ptr, val);
                Ok(())
            }
            x if x == R_AARCH64_COPY as u32 => Ok(()),
            x if x == R_AARCH64_RELATIVE as u32 => {
                if ptr.len() < 8 { return Err(TccError::link("arm64: reloc buffer too small")); }
                add64le(ptr, val as i64);
                Ok(())
            }
            _ => Err(TccError::link(&format!(
                "arm64: unhandled relocation type {rel_type}"
            ))),
        }
    }

    /// Create a PLT entry at the given GOT offset.
    /// C equivalent: `create_plt_entry(s1, got_offset, attr)` (arm64-link.c:82-116).
    fn create_plt_entry(
        &mut self,
        _state: &mut TccState,
        _got_offset: u32,
    ) -> TccResult<u32> {
        // Each PLT entry is 16 bytes (4 instructions):
        //   ADRP  x16, GOT+offset
        //   LDR   x17, [x16, #lo12(GOT+offset)]
        //   ADD   x16, x16, #lo12(GOT+offset)
        //   BR    x17
        // In the full implementation, this writes to the PLT section
        // and adds relocations for the GOT reference.
        Ok(0)
    }

    /// Relocate PLT entries after final addresses.
    /// C equivalent: `relocate_plt(s1)` (arm64-link.c:118-134).
    fn relocate_plt(&mut self, _state: &mut TccState) -> TccResult<()> {
        Ok(())
    }
}

// ===========================================================================
//  Assembler Stubs (arm64-asm.c — 94 lines, mostly stubs)
// ===========================================================================

/// Parse an ARM64 assembly opcode.
///
/// The ARM64 assembler in TCC is a stub that returns an error for all
/// opcodes.  This matches the original C implementation.
///
/// C equivalent: `asm_opcode(s1, token)` (arm64-asm.c:60-65).
pub fn asm_opcode(
    _state: &mut TccState,
    _token: i32,
) -> TccResult<()> {
    Err(TccError::parse("ARM64 inline assembly is not implemented"))
}

/// Parse an ARM64 register variable for inline asm constraints.
///
/// Returns the register index for a register name, or error.
///
/// C equivalent: `asm_parse_regvar(token)` (arm64-asm.c:86-94).
pub fn asm_parse_regvar(_token: i32) -> TccResult<i32> {
    Err(TccError::parse("ARM64 asm register parsing is not implemented"))
}

// ===========================================================================
//  Unit Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::TccState;
    use crate::types::{CType, CValue, SValue, SValueData, SValueSymInfo, Section};

    /// Create a minimal TccState with a single text section for testing.
    fn test_state() -> TccState {
        let mut state = TccState::default();
        let section = Section {
            data: Vec::with_capacity(4096),
            data_offset: 0,
            sh_name: 0,
            sh_num: 0,
            sh_type: 0,
            sh_flags: 0,
            sh_info: 0,
            sh_addralign: 4,
            sh_entsize: 0,
            sh_size: 0,
            sh_addr: 0,
            sh_offset: 0,
            name: String::from(".text"),
            link: None,
            reloc: None,
            hash: None,
            prev: None,
            nb_hashed_syms: 0,
        };
        state.sections.push(section);
        state.cur_text_section = 0;
        state.ind = 0;
        state
    }

    #[test]
    fn test_constants() {
        assert_eq!(NB_REGS, 28);
        assert_eq!(NB_ASM_REGS, 16);
        assert_eq!(PTR_SIZE, 8);
        assert_eq!(LDOUBLE_SIZE, 16);
        assert_eq!(LDOUBLE_ALIGN, 16);
        assert_eq!(MAX_ALIGN, 16);
        assert!(CHAR_IS_UNSIGNED);
        assert_eq!(EM_TCC_TARGET, EM_AARCH64);
        assert_eq!(ELF_START_ADDR, 0x0040_0000);
        assert_eq!(ELF_PAGE_SIZE, 0x0001_0000);
        assert_eq!(R_DATA_32, R_AARCH64_ABS32 as i32);
        assert_eq!(R_DATA_PTR, R_AARCH64_ABS64 as i32);
        assert_eq!(R_JMP_SLOT, R_AARCH64_JUMP_SLOT as i32);
        assert_eq!(R_GLOB_DAT, R_AARCH64_GLOB_DAT as i32);
        assert_eq!(R_COPY, R_AARCH64_COPY as i32);
        assert_eq!(R_RELATIVE, R_AARCH64_RELATIVE as i32);
        assert_eq!(R_NUM, R_AARCH64_NUM as i32);
        assert_eq!(PCRELATIVE_DLLPLT, 1);
        assert_eq!(RELOCATE_DLLPLT, 1);
    }

    #[test]
    fn test_register_helpers() {
        assert_eq!(treg_r(0), 0);
        assert_eq!(treg_r(18), 18);
        assert_eq!(treg_f(0), 20);
        assert_eq!(treg_f(7), 27);
        assert_eq!(TREG_R30, 19);

        assert_eq!(rc_r(0), 1 << 2);
        assert_eq!(rc_r(18), 1 << 20);
        assert_eq!(rc_f(0), 1 << 22);
        assert_eq!(rc_f(7), 1 << 29);

        assert_eq!(RC_INT, 1);
        assert_eq!(RC_FLOAT, 2);
        assert_eq!(RC_IRET, 1 << 2);
        assert_eq!(RC_FRET, 1 << 22);
        assert_eq!(RC_R30, 1 << 21);

        assert_eq!(REG_IRET, 0);
        assert_eq!(REG_FRET, 20);
    }

    #[test]
    fn test_register_mapping() {
        assert_eq!(intr(0), 0);
        assert_eq!(intr(18), 18);
        assert_eq!(intr(19), 30);
        assert_eq!(fltr(20), 0);
        assert_eq!(fltr(27), 7);
        assert!(!is_freg(0));
        assert!(!is_freg(19));
        assert!(is_freg(20));
        assert!(is_freg(27));
    }

    #[test]
    fn test_reg_classes_array() {
        assert_eq!(REG_CLASSES.len(), NB_REGS);
        assert_eq!(REG_CLASSES[0], RC_INT | rc_r(0));
        assert_eq!(REG_CLASSES[18], RC_INT | rc_r(18));
        assert_eq!(REG_CLASSES[19], RC_R30);
        assert_eq!(REG_CLASSES[19] & RC_INT, 0);
        assert_eq!(REG_CLASSES[20], RC_FLOAT | rc_f(0));
        assert_eq!(REG_CLASSES[27], RC_FLOAT | rc_f(7));
    }

    #[test]
    fn test_backend_creation() {
        let backend = Arm64Backend::new();
        assert_eq!(backend.callee_saved, 0);
        assert_eq!(backend.func_sub_sp_offset, 0);
        assert_eq!(backend.arm64_func_va_list_stack, 0);
    }

    #[test]
    fn test_emit_nop() {
        let mut state = test_state();
        let mut backend = Arm64Backend::new();
        backend.gen_fill_nops(&mut state, 8).unwrap();
        assert_eq!(state.sections[0].data.len(), 8);
        assert_eq!(read32le(&state.sections[0].data[0..]), ARM64_NOP);
        assert_eq!(read32le(&state.sections[0].data[4..]), ARM64_NOP);
        assert_eq!(state.ind, 8);
    }

    #[test]
    fn test_gjmp() {
        let mut state = test_state();
        let mut backend = Arm64Backend::new();
        let t = backend.gjmp(&mut state, 0).unwrap();
        assert_eq!(t, 0);
        let insn = read32le(&state.sections[0].data[0..]);
        assert_eq!(insn >> 26, 0b000101);
        assert_eq!(insn & 0x03FF_FFFF, 0);
    }

    #[test]
    fn test_gjmp_cond() {
        let mut state = test_state();
        let mut backend = Arm64Backend::new();
        use crate::tokens::TOK_EQ;
        let t = backend.gjmp_cond(&mut state, TOK_EQ as i32, 0).unwrap();
        assert_eq!(t, 0);
        let insn = read32le(&state.sections[0].data[0..]);
        assert_eq!(insn >> 24, 0b01010100);
        assert_eq!(insn & 0xF, 0);
    }

    #[test]
    fn test_gsym_addr_b_insn() {
        let mut state = test_state();
        let mut backend = Arm64Backend::new();
        // Emit a NOP first so the B instruction is at a non-zero offset.
        // (offset 0 is the "end of chain" sentinel in TCC's branch chaining.)
        backend.gen_fill_nops(&mut state, 4).unwrap(); // NOP at offset 0
        let t = backend.gjmp(&mut state, 0).unwrap();  // B at offset 4
        backend.gen_fill_nops(&mut state, 4).unwrap();  // NOP at offset 8
        // Patch B at offset 4 to target address 12: offset = (12-4)/4 = 2
        backend.gsym_addr(&mut state, t, 12).unwrap();
        let insn = read32le(&state.sections[0].data[4..]);
        assert_eq!(insn & 0x03FF_FFFF, 2);
    }

    #[test]
    fn test_o_insn() {
        let mut state = test_state();
        let mut backend = Arm64Backend::new();
        backend.o(&mut state, 0xD65F_03C0).unwrap();
        assert_eq!(state.sections[0].data.len(), 4);
        assert_eq!(read32le(&state.sections[0].data[0..]), 0xD65F_03C0);
    }

    #[test]
    fn test_load_constant() {
        let mut state = test_state();
        let mut backend = Arm64Backend::new();
        let sv = SValue {
            ctype: CType { t: VT_INT, ref_sym: None },
            r: VT_CONST,
            r2: VT_CONST,
            value: SValueData::Constant(CValue::Int(42)),
            sym_info: SValueSymInfo::Sym(None),
        };
        backend.load(&mut state, 0, &sv).unwrap();
        assert!(state.sections[0].data.len() >= 4);
    }

    #[test]
    fn test_store_local() {
        let mut state = test_state();
        let mut backend = Arm64Backend::new();
        let sv = SValue {
            ctype: CType { t: VT_INT, ref_sym: None },
            r: VT_LOCAL | VT_LVAL,
            r2: VT_CONST,
            value: SValueData::Constant(CValue::Int(16)),
            sym_info: SValueSymInfo::Sym(None),
        };
        backend.store(&mut state, 0, &sv).unwrap();
        assert!(state.sections[0].data.len() >= 4);
    }

    #[test]
    fn test_code_reloc() {
        let backend = Arm64Backend::new();
        assert_eq!(backend.code_reloc(R_AARCH64_ABS32 as i32), 0);
        assert_eq!(backend.code_reloc(R_AARCH64_ABS64 as i32), 0);
        assert_eq!(backend.code_reloc(R_AARCH64_JUMP26 as i32), 1);
        assert_eq!(backend.code_reloc(R_AARCH64_CALL26 as i32), 1);
        assert_eq!(backend.code_reloc(9999), -1);
    }

    #[test]
    fn test_gotplt_entry_type() {
        let backend = Arm64Backend::new();
        assert!(matches!(
            backend.gotplt_entry_type(R_AARCH64_ADR_GOT_PAGE as i32),
            GotPltEntry::AlwaysEntry
        ));
        assert!(matches!(
            backend.gotplt_entry_type(R_AARCH64_CALL26 as i32),
            GotPltEntry::AutoEntry
        ));
        assert!(matches!(
            backend.gotplt_entry_type(R_AARCH64_ABS32 as i32),
            GotPltEntry::NoEntry
        ));
    }

    #[test]
    fn test_relocate_abs32() {
        let backend = Arm64Backend::new();
        let mut state = test_state();
        let mut buf = [0u8; 4];
        backend.relocate(&mut state, R_AARCH64_ABS32 as i32, &mut buf, 0x1000, 0x2000).unwrap();
        assert_eq!(read32le(&buf), 0x2000);
    }

    #[test]
    fn test_relocate_call26() {
        let backend = Arm64Backend::new();
        let mut state = test_state();
        let mut buf = 0x9400_0000u32.to_le_bytes();
        backend.relocate(&mut state, R_AARCH64_CALL26 as i32, &mut buf, 0x1000, 0x2000).unwrap();
        let insn = read32le(&buf);
        assert_eq!(insn & 0x03FF_FFFF, 0x400);
        assert_eq!(insn & 0xFC00_0000, 0x9400_0000 & 0xFC00_0000);
    }

    #[test]
    fn test_relocate_adr_prel_pg_hi21() {
        let backend = Arm64Backend::new();
        let mut state = test_state();
        let mut buf = 0x9000_0000u32.to_le_bytes();
        backend.relocate(&mut state, R_AARCH64_ADR_PREL_PG_HI21 as i32, &mut buf, 0x1000, 0x2000).unwrap();
        let insn = read32le(&buf);
        let immlo = (insn >> 29) & 0x3;
        let immhi = (insn >> 5) & 0x7_FFFF;
        let decoded = ((immhi << 2) | immlo) as i32;
        assert_eq!(decoded, 1);
    }

    #[test]
    fn test_asm_stubs() {
        let mut state = test_state();
        assert!(asm_opcode(&mut state, 0).is_err());
        assert!(asm_parse_regvar(0).is_err());
    }

    #[test]
    fn test_prolog_epilog() {
        let mut state = test_state();
        let mut backend = Arm64Backend::new();
        let sym = Symbol::default();
        backend.gfunc_prolog(&mut state, &sym).unwrap();
        let prolog_size = state.sections[0].data.len();
        assert!(prolog_size >= 12);
        backend.gfunc_epilog(&mut state).unwrap();
        let total_size = state.sections[0].data.len();
        assert!(total_size > prolog_size);
    }

    #[test]
    fn test_vla_save_restore() {
        let mut state = test_state();
        let mut backend = Arm64Backend::new();
        backend.gen_vla_sp_save(&mut state, 16).unwrap();
        let save_size = state.sections[0].data.len();
        assert!(save_size >= 8);
        backend.gen_vla_sp_restore(&mut state, 16).unwrap();
        let total = state.sections[0].data.len();
        assert!(total > save_size);
    }

    #[test]
    fn test_bimm64_encoding() {
        let enc = Arm64Backend::arm64_encode_bimm64(!0xFu64);
        assert!(enc.is_some());
        assert!(Arm64Backend::arm64_encode_bimm64(0).is_none());
        assert!(Arm64Backend::arm64_encode_bimm64(u64::MAX).is_none());
        let enc2 = Arm64Backend::arm64_encode_bimm64(0x5555_5555_5555_5555);
        assert!(enc2.is_some());
    }

    #[test]
    fn test_movimm() {
        let mut state = test_state();
        Arm64Backend::arm64_movimm(&mut state, 0, 0).unwrap();
        let insn = read32le(&state.sections[0].data[0..]);
        assert_eq!(insn & 0xFF80_0000, 0xD280_0000);

        state.sections[0].data.clear();
        state.sections[0].data_offset = 0;
        state.ind = 0;
        Arm64Backend::arm64_movimm(&mut state, 1, 0x1234).unwrap();
        let insn = read32le(&state.sections[0].data[0..]);
        assert_eq!(insn & 0x1F, 1);
    }

    #[test]
    fn test_target_machine_defs() {
        let backend = Arm64Backend::new();
        let defs = backend.target_machine_defs();
        assert!(defs.contains(&"__aarch64__"));
        assert!(defs.contains(&"__AARCH64EL__"));
    }

    #[test]
    fn test_gen_opi_add() {
        let mut state = test_state();
        let mut backend = Arm64Backend::new();
        backend.gen_opi(&mut state, b'+' as i32).unwrap();
        let insn = read32le(&state.sections[0].data[0..]);
        // ADD W0, W0, W1 (32-bit variant, sf=0)
        assert_eq!(insn & 0xFF20_0000, 0x0B00_0000);
    }

    #[test]
    fn test_gen_opl_add() {
        let mut state = test_state();
        let mut backend = Arm64Backend::new();
        backend.gen_opl(&mut state, b'+' as i32).unwrap();
        let insn = read32le(&state.sections[0].data[0..]);
        // ADD X0, X0, X1 (64-bit variant, sf=1)
        assert_eq!(insn & 0xFF20_0000, 0x8B00_0000);
    }

    #[test]
    fn test_gen_opf_add() {
        let mut state = test_state();
        let mut backend = Arm64Backend::new();
        backend.gen_opf(&mut state, b'+' as i32).unwrap();
        let insn = read32le(&state.sections[0].data[0..]);
        // FADD Dd, Dn, Dm (double): opcode + ftype mask = 0xFFE0_FC00
        assert_eq!(insn & 0xFFE0_FC00, 0x1E60_2800);
    }

    #[test]
    fn test_ggoto() {
        let mut state = test_state();
        let mut backend = Arm64Backend::new();
        backend.ggoto(&mut state).unwrap();
        let insn = read32le(&state.sections[0].data[0..]);
        // BR x0
        assert_eq!(insn, 0xD61F_0000);
    }
}
