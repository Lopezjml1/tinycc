// Copyright (c) TinyCC contributors. LGPL licensed.
// Ported from riscv64-gen.c, riscv64-link.c, riscv64-asm.c, riscv64-tok.h to Rust.
//
//! # RISC-V 64-bit (RV64GC) Architecture Backend — Module Root
//!
//! Module root for the RISC-V 64-bit code generation backend.  Defines the
//! [`Riscv64Backend`] struct that implements the [`CodegenBackend`] trait,
//! all architecture constants, register definitions, and submodule declarations.
//!
//! This file collects:
//! - `TARGET_DEFS_ONLY` sections from `riscv64-gen.c` (lines 1-33)
//! - `TARGET_DEFS_ONLY` sections from `riscv64-link.c` (lines 1-19)
//! - `TARGET_DEFS_ONLY` sections from `riscv64-asm.c` (lines 7-16)
//! - Register class array from `riscv64-gen.c` (lines 59-79)
//! - Helper functions from `riscv64-gen.c` (lines 87-111)
//! - Target machine defs from `riscv64-gen.c` (lines 43-52)
//!
//! ## Feature Gate
//!
//! This entire module is gated behind `#[cfg(feature = "riscv64")]` in the
//! parent `arch/mod.rs`. No additional gating is needed inside this file.
//!
//! ## Architecture Overview
//!
//! RISC-V 64-bit (RV64GC) uses:
//! - 8 integer argument/return registers: a0-a7 (x10-x17)
//! - 8 floating-point argument/return registers: fa0-fa7 (f10-f17)
//! - 1 placeholder register (xxx, not allocatable)
//! - 1 return address register: ra (x1)
//! - 1 stack pointer register: sp (x2)
//! - Total allocatable registers: 19 (NB_REGS)
//!
//! ## Register Numbering
//!
//! TCC-internal register numbers 0-18 map to RISC-V architectural registers
//! via the [`ireg()`] and [`freg()`] helper functions:
//!
//! | TCC reg | ABI name | Arch reg | Class |
//! |---------|----------|----------|-------|
//! | 0-7     | a0-a7    | x10-x17  | INT   |
//! | 8-15    | fa0-fa7  | f10-f17  | FLOAT |
//! | 16      | xxx      | —        | None  |
//! | 17      | ra       | x1       | Special |
//! | 18      | sp       | x2       | Special |

// ---------------------------------------------------------------------------
// Submodule declarations
// ---------------------------------------------------------------------------

/// RISC-V 64-bit assembly token definitions — register names, instruction
/// mnemonics, CSRs, pseudo-instructions.  Ported from `riscv64-tok.h`.
pub mod tokens;

/// RISC-V 64-bit code generation — instruction emission, register allocation,
/// calling convention, stack frame management.  Ported from `riscv64-gen.c`.
pub mod gen;

/// RISC-V 64-bit linker support — relocation processing, PLT/GOT generation,
/// symbol binding.  Ported from `riscv64-link.c`.
pub mod link;

/// RISC-V 64-bit assembler — instruction encoding, operand parsing, directive
/// handling.  Ported from `riscv64-asm.c`.
pub mod asm;

// ---------------------------------------------------------------------------
// Imports from within tcc-core (verified against depends_on_files whitelist)
// ---------------------------------------------------------------------------

use crate::arch::{CodegenBackend, RC_INT, RC_FLOAT};
use crate::error::TccResult;
use crate::types::{CType, SValue, Sym};

// ============================================================================
// Architecture Constants — from riscv64-gen.c TARGET_DEFS_ONLY (lines 1-33)
// ============================================================================

/// Total number of registers available to the register allocator.
///
/// 8 integer (a0-a7) + 8 float (fa0-fa7) + 1 placeholder (xxx) + ra + sp = 19.
///
/// Corresponds to: `#define NB_REGS 19` in `riscv64-gen.c` line 3.
pub const NB_REGS: usize = 19;

/// Total number of assembler registers: 32 integer (x0-x31) + 32 float (f0-f31).
///
/// Corresponds to: `#define NB_ASM_REGS 64` in `riscv64-asm.c` line 11.
pub const NB_ASM_REGS: usize = 64;

// ---------------------------------------------------------------------------
// Register index macros — from riscv64-gen.c lines 7-8
// These map TCC-internal register indices to semantic groups.
// ---------------------------------------------------------------------------

/// Returns the TCC-internal register number for integer argument register `x`.
///
/// `x` ranges from 0 to 7, mapping to a0-a7 (TCC regs 0-7).
///
/// Corresponds to: `#define TREG_R(x) (x)` in `riscv64-gen.c` line 7.
#[inline]
pub const fn treg_r(x: usize) -> usize {
    x
}

/// Returns the TCC-internal register number for floating-point argument register `x`.
///
/// `x` ranges from 0 to 7, mapping to fa0-fa7 (TCC regs 8-15).
///
/// Corresponds to: `#define TREG_F(x) (x + 8)` in `riscv64-gen.c` line 8.
#[inline]
pub const fn treg_f(x: usize) -> usize {
    x + 8
}

/// TCC-internal register number for the return address register (ra = x1).
///
/// Corresponds to: `#define TREG_RA 17` in `riscv64-gen.c` line 56.
pub const TREG_RA: usize = 17;

/// TCC-internal register number for the stack pointer register (sp = x2).
///
/// Corresponds to: `#define TREG_SP 18` in `riscv64-gen.c` line 57.
pub const TREG_SP: usize = 18;

// ---------------------------------------------------------------------------
// Register class bit-flag functions — from riscv64-gen.c lines 11-14
// ---------------------------------------------------------------------------

/// Returns the register class bitmask for integer register `x` (0-7).
///
/// Each integer register has its own class bit at position `2 + x`.
///
/// Corresponds to: `#define RC_R(x) (1 << (2 + (x)))` in `riscv64-gen.c` line 13.
#[inline]
pub const fn rc_r(x: usize) -> i32 {
    1i32 << (2 + x)
}

/// Returns the register class bitmask for floating-point register `x` (0-7).
///
/// Each float register has its own class bit at position `10 + x`.
///
/// Corresponds to: `#define RC_F(x) (1 << (10 + (x)))` in `riscv64-gen.c` line 14.
#[inline]
pub const fn rc_f(x: usize) -> i32 {
    1i32 << (10 + x)
}

// ---------------------------------------------------------------------------
// Return register class constants — from riscv64-gen.c lines 16-18
// ---------------------------------------------------------------------------

/// Register class for integer return value register (a0, class bit at position 2).
///
/// Corresponds to: `#define RC_IRET (RC_R(0))` → `1 << 2` = 4.
pub const RC_IRET: i32 = 1i32 << 2; // rc_r(0)

/// Register class for second integer return register (a1, class bit at position 3).
///
/// Used for 128-bit return values.
///
/// Corresponds to: `#define RC_IRE2 (RC_R(1))` → `1 << 3` = 8.
pub const RC_IRE2: i32 = 1i32 << 3; // rc_r(1)

/// Register class for floating-point return value register (fa0, class bit at position 10).
///
/// Corresponds to: `#define RC_FRET (RC_F(0))` → `1 << 10` = 1024.
pub const RC_FRET: i32 = 1i32 << 10; // rc_f(0)

// ---------------------------------------------------------------------------
// Return register number constants — from riscv64-gen.c lines 20-22
// ---------------------------------------------------------------------------

/// TCC-internal register number for the integer return value register (a0).
///
/// Corresponds to: `#define REG_IRET (TREG_R(0))` → 0.
pub const REG_IRET: usize = 0; // treg_r(0)

/// TCC-internal register number for the second integer return register (a1).
///
/// Used for returning 128-bit values or struct-in-registers.
///
/// Corresponds to: `#define REG_IRE2 (TREG_R(1))` → 1.
pub const REG_IRE2: usize = 1; // treg_r(1)

/// TCC-internal register number for the floating-point return register (fa0).
///
/// Corresponds to: `#define REG_FRET (TREG_F(0))` → 8.
pub const REG_FRET: usize = 8; // treg_f(0)

// ---------------------------------------------------------------------------
// Size and alignment constants — from riscv64-gen.c lines 24-31
// ---------------------------------------------------------------------------

/// Pointer size in bytes for RISC-V 64-bit targets.
///
/// Corresponds to: `#define PTR_SIZE 8` in `riscv64-gen.c` line 24.
pub const PTR_SIZE: usize = 8;

/// Size of `long double` in bytes.  RISC-V uses 128-bit (quad precision) in
/// software, stored as 16 bytes.
///
/// Corresponds to: `#define LDOUBLE_SIZE 16` in `riscv64-gen.c` line 26.
pub const LDOUBLE_SIZE: usize = 16;

/// Alignment of `long double` in bytes.
///
/// Corresponds to: `#define LDOUBLE_ALIGN 16` in `riscv64-gen.c` line 27.
pub const LDOUBLE_ALIGN: usize = 16;

/// Maximum alignment requirement for this target.
///
/// Corresponds to: `#define MAX_ALIGN 16` in `riscv64-gen.c` line 29.
pub const MAX_ALIGN: usize = 16;

/// Whether `char` is unsigned on this target.
///
/// RISC-V convention: `char` is unsigned by default (unlike x86 which is signed).
///
/// Corresponds to: `#define CHAR_IS_UNSIGNED` in `riscv64-gen.c` line 31.
pub const CHAR_IS_UNSIGNED: bool = true;

// ============================================================================
// Register Classes Array — from riscv64-gen.c lines 59-79
// ============================================================================

/// Register class bitmasks for all 19 TCC-internal registers.
///
/// Each entry is a bitmask of register classes the register belongs to.
/// The register allocator uses this to find a register matching a requested
/// class (e.g., `RC_INT`, `RC_FLOAT`, `RC_IRET`).
///
/// Layout:
/// - `[0..8]`  — a0-a7:  `RC_INT | RC_R(x)` — general integer + individual class
/// - `[8..16]` — fa0-fa7: `RC_FLOAT | RC_F(x)` — general float + individual class
/// - `[16]`    — xxx:     `0` — placeholder, not allocatable
/// - `[17]`    — ra:      `1 << 17` — return address, special-purpose only
/// - `[18]`    — sp:      `1 << 18` — stack pointer, special-purpose only
///
/// Note: ra and sp have unique class bits but are NOT part of RC_INT —
/// they are special-purpose registers that can only be explicitly selected.
///
/// Corresponds to: `ST_DATA const int reg_classes[NB_REGS]` in `riscv64-gen.c`.
pub const REG_CLASSES: [i32; NB_REGS] = [
    // Integer argument registers a0-a7 (TCC regs 0-7)
    RC_INT | (1i32 << 2),   // r0  = a0: RC_INT | RC_R(0)
    RC_INT | (1i32 << 3),   // r1  = a1: RC_INT | RC_R(1)
    RC_INT | (1i32 << 4),   // r2  = a2: RC_INT | RC_R(2)
    RC_INT | (1i32 << 5),   // r3  = a3: RC_INT | RC_R(3)
    RC_INT | (1i32 << 6),   // r4  = a4: RC_INT | RC_R(4)
    RC_INT | (1i32 << 7),   // r5  = a5: RC_INT | RC_R(5)
    RC_INT | (1i32 << 8),   // r6  = a6: RC_INT | RC_R(6)
    RC_INT | (1i32 << 9),   // r7  = a7: RC_INT | RC_R(7)
    // Floating-point argument registers fa0-fa7 (TCC regs 8-15)
    RC_FLOAT | (1i32 << 10), // r8  = fa0: RC_FLOAT | RC_F(0)
    RC_FLOAT | (1i32 << 11), // r9  = fa1: RC_FLOAT | RC_F(1)
    RC_FLOAT | (1i32 << 12), // r10 = fa2: RC_FLOAT | RC_F(2)
    RC_FLOAT | (1i32 << 13), // r11 = fa3: RC_FLOAT | RC_F(3)
    RC_FLOAT | (1i32 << 14), // r12 = fa4: RC_FLOAT | RC_F(4)
    RC_FLOAT | (1i32 << 15), // r13 = fa5: RC_FLOAT | RC_F(5)
    RC_FLOAT | (1i32 << 16), // r14 = fa6: RC_FLOAT | RC_F(6)
    RC_FLOAT | (1i32 << 17), // r15 = fa7: RC_FLOAT | RC_F(7)
    // Placeholder (not allocatable)
    0,                        // r16 = xxx: no class
    // Special-purpose registers
    1i32 << (TREG_RA as u32), // r17 = ra:  1 << 17
    1i32 << (TREG_SP as u32), // r18 = sp:  1 << 18
];

// ============================================================================
// ELF Constants — from riscv64-link.c TARGET_DEFS_ONLY (lines 1-19)
// ============================================================================

/// ELF machine type constant for RISC-V targets.
///
/// Corresponds to: `#define EM_TCC_TARGET EM_RISCV` → 243 in `elf.h`.
pub const EM_TCC_TARGET: u16 = 243;

/// Generic relocation alias for 32-bit absolute data.
///
/// Corresponds to: `#define R_DATA_32 R_RISCV_32` → 1 in `elf.h`.
pub const R_DATA_32: i32 = 1;

/// Generic relocation alias for pointer-sized (64-bit) absolute data.
///
/// Corresponds to: `#define R_DATA_PTR R_RISCV_64` → 2 in `elf.h`.
pub const R_DATA_PTR: i32 = 2;

/// Generic relocation alias for PLT jump slot entries.
///
/// Corresponds to: `#define R_JMP_SLOT R_RISCV_JUMP_SLOT` → 5 in `elf.h`.
pub const R_JMP_SLOT: i32 = 5;

/// Generic relocation alias for GOT data entries.
///
/// RISC-V uses the same relocation type as R_DATA_PTR for GOT entries.
///
/// Corresponds to: `#define R_GLOB_DAT R_RISCV_64` → 2 in `elf.h`.
pub const R_GLOB_DAT: i32 = 2;

/// Generic relocation alias for copy relocations.
///
/// Corresponds to: `#define R_COPY R_RISCV_COPY` → 4 in `elf.h`.
pub const R_COPY: i32 = 4;

/// Generic relocation alias for relative relocations (base address adjustment).
///
/// Corresponds to: `#define R_RELATIVE R_RISCV_RELATIVE` → 3 in `elf.h`.
pub const R_RELATIVE: i32 = 3;

/// Total number of defined RISC-V relocation types.
///
/// Corresponds to: `#define R_NUM R_RISCV_NUM` → 62 in `elf.h`.
pub const R_NUM: i32 = 62;

/// Default ELF entry point address for RISC-V 64-bit executables.
///
/// Corresponds to: `#define ELF_START_ADDR 0x00010000` in `riscv64-link.c` line 14.
pub const ELF_START_ADDR: u64 = 0x0001_0000;

/// Default ELF page size for RISC-V 64-bit targets (4 KiB).
///
/// Corresponds to: `#define ELF_PAGE_SIZE 0x1000` in `riscv64-link.c` line 15.
pub const ELF_PAGE_SIZE: u64 = 0x1000;

/// Whether this target uses PC-relative addressing for DLL PLT entries.
///
/// Corresponds to: `#define PCRELATIVE_DLLPLT 1` in `riscv64-link.c` line 17.
pub const PCRELATIVE_DLLPLT: bool = true;

/// Whether this target requires DLL PLT entry relocation.
///
/// Corresponds to: `#define RELOCATE_DLLPLT 1` in `riscv64-link.c` line 18.
pub const RELOCATE_DLLPLT: bool = true;

// ============================================================================
// Target Machine Definitions String
// From riscv64-gen.c lines 43-52
// ============================================================================

/// Null-separated list of predefined macros for RISC-V 64-bit targets.
///
/// The preprocessor defines each of these automatically when targeting RISC-V 64.
/// The format is `"name\0"` for object-like macros and `"name value\0"` for
/// macros with a replacement value.
///
/// Corresponds to: `ST_DATA const char * const target_machine_defs` in `riscv64-gen.c`.
pub const TARGET_MACHINE_DEFS: &str =
    "__riscv\0\
     __riscv_xlen 64\0\
     __riscv_flen 64\0\
     __riscv_div\0\
     __riscv_mul\0\
     __riscv_fdiv\0\
     __riscv_fsqrt\0\
     __riscv_float_abi_double\0";

// ============================================================================
// Helper Functions — from riscv64-gen.c lines 87-111
// ============================================================================

/// Maps a TCC-internal register number to its RISC-V architectural integer
/// register number.
///
/// - `r == TREG_RA` (17) → 1 (ra = x1)
/// - `r == TREG_SP` (18) → 2 (sp = x2)
/// - `r` in 0..8 → `r + 10` (a0-a7 = x10-x17)
///
/// # Panics
///
/// Panics if `r` is not a valid integer register index (i.e., not 0-7, 17, or 18).
///
/// Corresponds to: `static int ireg(int r)` in `riscv64-gen.c` lines 87-95.
#[inline]
pub fn ireg(r: usize) -> u8 {
    if r == TREG_RA {
        return 1; // ra = x1
    }
    if r == TREG_SP {
        return 2; // sp = x2
    }
    assert!(r < 8, "ireg: invalid integer register index {}", r);
    (r + 10) as u8 // a0-a7 = x10-x17
}

/// Maps a TCC-internal register number to its RISC-V architectural
/// floating-point register number.
///
/// - `r` in 8..16 → `r - 8 + 10` (fa0-fa7 = f10-f17)
///
/// # Panics
///
/// Panics if `r` is not a valid floating-point register index (i.e., not 8-15).
///
/// Corresponds to: `static int freg(int r)` in `riscv64-gen.c` lines 102-106.
#[inline]
pub fn freg(r: usize) -> u8 {
    assert!((8..16).contains(&r), "freg: invalid float register index {}", r);
    (r - 8 + 10) as u8 // fa0-fa7 = f10-f17
}

/// Returns `true` if TCC-internal register `r` is an integer register.
///
/// Integer registers are indices 0-7 (a0-a7), 17 (ra), and 18 (sp).
///
/// Corresponds to: `static int is_ireg(int r)` in `riscv64-gen.c` lines 97-100.
#[inline]
pub fn is_ireg(r: usize) -> bool {
    r < 8 || r == TREG_RA || r == TREG_SP
}

/// Returns `true` if TCC-internal register `r` is a floating-point register.
///
/// Floating-point registers are indices 8-15 (fa0-fa7).
///
/// Corresponds to: `static int is_freg(int r)` in `riscv64-gen.c` lines 108-111.
#[inline]
pub fn is_freg(r: usize) -> bool {
    (8..16).contains(&r)
}

// ============================================================================
// RISC-V Architecture-specific Constants
// From riscv64-gen.c lines 38-41, 54
// ============================================================================

/// XLEN in bytes (8 for RV64).
///
/// Corresponds to: `#define XLEN 8` in `riscv64-gen.c` line 54.
pub const XLEN: usize = 8;

/// Computes the upper 20 bits adjusted for sign extension of the low 12 bits.
///
/// Used in HI20/LO12 instruction pair construction for RISC-V.
/// Adding 0x800 before masking handles the sign extension of the lower 12 bits
/// in the subsequent ADDI/LW/etc. instruction.
///
/// Corresponds to: `#define UPPER(x) (((unsigned)(x) + 0x800u) & 0xfffff000)` in
/// `riscv64-gen.c` line 38.
#[inline]
pub const fn upper(x: i32) -> u32 {
    ((x as u32).wrapping_add(0x800)) & 0xffff_f000
}

/// Checks if a value overflows when used as a sign-extended 12-bit immediate.
///
/// Returns the upper portion — if non-zero, the value needs a LUI+ADDI pair.
///
/// Corresponds to: `#define LOW_OVERFLOW(x) UPPER(x)` in `riscv64-gen.c` line 39.
#[inline]
pub const fn low_overflow(x: i32) -> u32 {
    upper(x)
}

/// Sign-extends a 7-bit value (for compressed instruction immediates).
///
/// Corresponds to: `#define SIGN7(x) ((((x) & 0xff) ^ 0x80) - 0x80)` in
/// `riscv64-gen.c` line 40.
#[inline]
pub const fn sign7(x: i32) -> i32 {
    ((x & 0xff) ^ 0x80) - 0x80
}

/// Sign-extends an 11-bit value (for compressed jump offsets).
///
/// Corresponds to: `#define SIGN11(x) ((((x) & 0xfff) ^ 0x800) - 0x800)` in
/// `riscv64-gen.c` line 41.
#[inline]
pub const fn sign11(x: i32) -> i32 {
    ((x & 0xfff) ^ 0x800) - 0x800
}

// ============================================================================
// RISC-V Relocation Type Constants — used by link.rs
// From elf.h and riscv64-link.c
// ============================================================================

/// RISC-V relocation types used by the linker module.
///
/// These constants mirror the `R_RISCV_*` definitions from `elf.h` and are
/// used in `code_reloc()`, `gotplt_entry_type()`, and `relocate()`.
pub mod reloc {
    /// No relocation.
    pub const R_RISCV_NONE: i32 = 0;
    /// Direct 32-bit absolute address.
    pub const R_RISCV_32: i32 = 1;
    /// Direct 64-bit absolute address.
    pub const R_RISCV_64: i32 = 2;
    /// Relative address adjustment (base relocation).
    pub const R_RISCV_RELATIVE: i32 = 3;
    /// Copy relocation.
    pub const R_RISCV_COPY: i32 = 4;
    /// PLT jump slot entry.
    pub const R_RISCV_JUMP_SLOT: i32 = 5;
    /// TLS module ID (32-bit).
    pub const R_RISCV_TLS_DTPMOD32: i32 = 6;
    /// TLS module ID (64-bit).
    pub const R_RISCV_TLS_DTPMOD64: i32 = 7;
    /// TLS offset (32-bit).
    pub const R_RISCV_TLS_DTPREL32: i32 = 8;
    /// TLS offset (64-bit).
    pub const R_RISCV_TLS_DTPREL64: i32 = 9;
    /// TLS TP-relative offset (32-bit).
    pub const R_RISCV_TLS_TPREL32: i32 = 10;
    /// TLS TP-relative offset (64-bit).
    pub const R_RISCV_TLS_TPREL64: i32 = 11;
    /// Conditional branch (12-bit signed offset).
    pub const R_RISCV_BRANCH: i32 = 16;
    /// JAL instruction (20-bit signed offset).
    pub const R_RISCV_JAL: i32 = 17;
    /// AUIPC+JALR pair (32-bit PC-relative call).
    pub const R_RISCV_CALL: i32 = 18;
    /// AUIPC+JALR pair through PLT.
    pub const R_RISCV_CALL_PLT: i32 = 19;
    /// GOT-relative HI20 (for global variable access).
    pub const R_RISCV_GOT_HI20: i32 = 20;
    /// TLS GOT HI20.
    pub const R_RISCV_TLS_GOT_HI20: i32 = 21;
    /// TLS GD HI20.
    pub const R_RISCV_TLS_GD_HI20: i32 = 22;
    /// PC-relative HI20 (upper 20 bits of PC-relative offset).
    pub const R_RISCV_PCREL_HI20: i32 = 23;
    /// PC-relative LO12 for I-type instructions.
    pub const R_RISCV_PCREL_LO12_I: i32 = 24;
    /// PC-relative LO12 for S-type instructions.
    pub const R_RISCV_PCREL_LO12_S: i32 = 25;
    /// Absolute HI20 (upper 20 bits).
    pub const R_RISCV_HI20: i32 = 26;
    /// Absolute LO12 for I-type instructions.
    pub const R_RISCV_LO12_I: i32 = 27;
    /// Absolute LO12 for S-type instructions.
    pub const R_RISCV_LO12_S: i32 = 28;
    /// TLS TP-relative HI20.
    pub const R_RISCV_TPREL_HI20: i32 = 29;
    /// TLS TP-relative LO12 I-type.
    pub const R_RISCV_TPREL_LO12_I: i32 = 30;
    /// TLS TP-relative LO12 S-type.
    pub const R_RISCV_TPREL_LO12_S: i32 = 31;
    /// TLS TP-relative ADD.
    pub const R_RISCV_TPREL_ADD: i32 = 32;
    /// 8-bit addition.
    pub const R_RISCV_ADD8: i32 = 33;
    /// 16-bit addition.
    pub const R_RISCV_ADD16: i32 = 34;
    /// 32-bit addition.
    pub const R_RISCV_ADD32: i32 = 35;
    /// 64-bit addition.
    pub const R_RISCV_ADD64: i32 = 36;
    /// 8-bit subtraction.
    pub const R_RISCV_SUB8: i32 = 37;
    /// 16-bit subtraction.
    pub const R_RISCV_SUB16: i32 = 38;
    /// 32-bit subtraction.
    pub const R_RISCV_SUB32: i32 = 39;
    /// 64-bit subtraction.
    pub const R_RISCV_SUB64: i32 = 40;
    /// Alignment directive.
    pub const R_RISCV_ALIGN: i32 = 43;
    /// Compressed branch (RVC).
    pub const R_RISCV_RVC_BRANCH: i32 = 44;
    /// Compressed jump (RVC).
    pub const R_RISCV_RVC_JUMP: i32 = 45;
    /// 6-bit subtraction.
    pub const R_RISCV_SUB6: i32 = 52;
    /// 6-bit set.
    pub const R_RISCV_SET6: i32 = 53;
    /// 8-bit set.
    pub const R_RISCV_SET8: i32 = 54;
    /// 16-bit set.
    pub const R_RISCV_SET16: i32 = 55;
    /// 32-bit set.
    pub const R_RISCV_SET32: i32 = 56;
    /// 32-bit PC-relative.
    pub const R_RISCV_32_PCREL: i32 = 57;
}

// ============================================================================
// Riscv64Backend Struct
// ============================================================================

/// RISC-V 64-bit (RV64GC) code generation backend.
///
/// Implements the [`CodegenBackend`] trait for RISC-V 64-bit targets,
/// providing all architecture-specific code generation, linking, relocation,
/// and assembly functionality.
///
/// # Fields
///
/// - `loc` — Current local variable allocation offset from the frame pointer.
///   Decremented as locals are allocated on the stack. Used by `gfunc_prolog`
///   and `gfunc_epilog` to track stack frame size.
///
/// - `func_ret_sub` — Tracks whether the function epilogue needs to restore
///   additional state for struct returns (non-zero if struct return via memory pointer).
///
/// # Construction
///
/// ```
/// use tcc_core::arch::riscv64::Riscv64Backend;
///
/// let backend = Riscv64Backend::new();
/// assert_eq!(backend.loc, 0);
/// ```
pub struct Riscv64Backend {
    /// Current local variable offset from the frame pointer.
    ///
    /// Starts at 0 for each new function and decreases as local variables are
    /// allocated. The absolute value represents the total local variable area
    /// size in the stack frame.
    pub loc: i32,

    /// Function return adjustment value.
    ///
    /// Non-zero when the current function returns a struct via a hidden pointer
    /// parameter. The epilogue uses this to adjust the stack pointer or return
    /// sequence accordingly.
    pub func_ret_sub: i32,

    /// Bounds checking function offset (when bounds checking is enabled).
    ///
    /// Tracks the code offset for bounds-checking instrumentation in the
    /// current function. Only meaningful when `CONFIG_TCC_BCHECK` is active.
    pub func_bound_offset: u64,

    /// Bounds checking instruction index.
    ///
    /// The instruction counter at the bounds-checking call site, used to
    /// back-patch the bounds check after the function frame size is known.
    pub func_bound_ind: u64,

    /// Whether bounds-checking epilogue code needs to be added.
    ///
    /// Set during function prolog generation when bounds checking is active;
    /// consulted during epilog generation.
    pub func_bound_add_epilog: bool,
}

impl Riscv64Backend {
    /// Creates a new RISC-V 64-bit backend with default-initialized state.
    ///
    /// All fields are zero-initialized, ready for a new compilation unit.
    pub fn new() -> Self {
        Riscv64Backend {
            loc: 0,
            func_ret_sub: 0,
            func_bound_offset: 0,
            func_bound_ind: 0,
            func_bound_add_epilog: false,
        }
    }
}

impl Default for Riscv64Backend {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// CodegenBackend Trait Implementation
// ============================================================================

impl CodegenBackend for Riscv64Backend {
    // -----------------------------------------------------------------------
    // Target information methods
    // -----------------------------------------------------------------------

    fn target_machine_defs(&self) -> &'static str {
        TARGET_MACHINE_DEFS
    }

    fn reg_classes(&self) -> &[i32] {
        &REG_CLASSES
    }

    fn nb_regs(&self) -> usize {
        NB_REGS
    }

    fn ptr_size(&self) -> usize {
        PTR_SIZE
    }

    // -----------------------------------------------------------------------
    // Code emission methods — delegated to gen submodule
    // -----------------------------------------------------------------------

    fn gsym_addr(&mut self, t: i32, a: i32) -> TccResult<()> {
        gen::gsym_addr(self, t, a)
    }

    fn gsym(&mut self, t: i32) -> TccResult<()> {
        gen::gsym(self, t)
    }

    fn load(&mut self, r: i32, sv: &SValue) -> TccResult<()> {
        gen::load(self, r, sv)
    }

    fn store(&mut self, r: i32, sv: &SValue) -> TccResult<()> {
        gen::store(self, r, sv)
    }

    fn gfunc_sret(&self, vt: &CType, variadic: bool) -> (bool, CType, i32, i32) {
        gen::gfunc_sret(vt, variadic)
    }

    fn gfunc_call(&mut self, nb_args: i32) -> TccResult<()> {
        gen::gfunc_call(self, nb_args)
    }

    fn gfunc_prolog(&mut self, func_sym: &Sym) -> TccResult<()> {
        gen::gfunc_prolog(self, func_sym)
    }

    fn gfunc_epilog(&mut self) -> TccResult<()> {
        gen::gfunc_epilog(self)
    }

    fn gen_fill_nops(&mut self, n: i32) -> TccResult<()> {
        gen::gen_fill_nops(self, n)
    }

    fn gjmp(&mut self, t: i32) -> TccResult<i32> {
        gen::gjmp(self, t)
    }

    fn gjmp_addr(&mut self, a: i32) -> TccResult<()> {
        gen::gjmp_addr(self, a)
    }

    fn gjmp_cond(&mut self, op: i32, t: i32) -> TccResult<i32> {
        gen::gjmp_cond(self, op, t)
    }

    fn gjmp_append(&mut self, n: i32, t: i32) -> TccResult<i32> {
        gen::gjmp_append(self, n, t)
    }

    fn gen_opi(&mut self, op: i32) -> TccResult<()> {
        gen::gen_opi(self, op)
    }

    fn gen_opf(&mut self, op: i32) -> TccResult<()> {
        gen::gen_opf(self, op)
    }

    fn gen_cvt_ftoi(&mut self, t: i32) -> TccResult<()> {
        gen::gen_cvt_ftoi(self, t)
    }

    fn gen_cvt_itof(&mut self, t: i32) -> TccResult<()> {
        gen::gen_cvt_itof(self, t)
    }

    fn gen_cvt_ftof(&mut self, t: i32) -> TccResult<()> {
        gen::gen_cvt_ftof(self, t)
    }

    fn ggoto(&mut self) -> TccResult<()> {
        gen::ggoto(self)
    }

    fn emit_opcode(&mut self, c: u32) -> TccResult<()> {
        gen::emit_opcode(self, c)
    }

    fn gen_vla_sp_save(&mut self, addr: i32) -> TccResult<()> {
        gen::gen_vla_sp_save(self, addr)
    }

    fn gen_vla_sp_restore(&mut self, addr: i32) -> TccResult<()> {
        gen::gen_vla_sp_restore(self, addr)
    }

    fn gen_vla_alloc(&mut self, typ: &CType, align: i32) -> TccResult<()> {
        gen::gen_vla_alloc(self, typ, align)
    }

    fn gen_increment_tcov(&mut self, sv: &SValue) -> TccResult<()> {
        gen::gen_increment_tcov(self, sv)
    }

    // -----------------------------------------------------------------------
    // Linker interface methods — delegated to link submodule
    // -----------------------------------------------------------------------

    fn code_reloc(&self, reloc_type: i32) -> i32 {
        link::code_reloc(reloc_type)
    }

    fn gotplt_entry_type(&self, reloc_type: i32) -> i32 {
        link::gotplt_entry_type(reloc_type)
    }

    fn relocate(&mut self, rel_type: i32, ptr: &mut [u8], addr: u64, val: u64) -> TccResult<()> {
        link::relocate(self, rel_type, ptr, addr, val)
    }

    // -----------------------------------------------------------------------
    // ELF constants
    // -----------------------------------------------------------------------

    fn elf_machine(&self) -> u16 {
        EM_TCC_TARGET
    }

    fn elf_start_addr(&self) -> u64 {
        ELF_START_ADDR
    }

    fn elf_page_size(&self) -> u64 {
        ELF_PAGE_SIZE
    }

    fn pcrelative_dllplt(&self) -> bool {
        PCRELATIVE_DLLPLT
    }

    fn relocate_dllplt(&self) -> bool {
        RELOCATE_DLLPLT
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nb_regs() {
        assert_eq!(NB_REGS, 19);
    }

    #[test]
    fn test_nb_asm_regs() {
        assert_eq!(NB_ASM_REGS, 64);
    }

    #[test]
    fn test_reg_classes_length() {
        assert_eq!(REG_CLASSES.len(), NB_REGS);
    }

    #[test]
    fn test_int_reg_classes() {
        // a0-a7 (indices 0-7) must have RC_INT set
        for i in 0..8 {
            assert_ne!(
                REG_CLASSES[i] & RC_INT,
                0,
                "Register {} should be RC_INT",
                i
            );
        }
    }

    #[test]
    fn test_float_reg_classes() {
        // fa0-fa7 (indices 8-15) must have RC_FLOAT set
        for i in 8..16 {
            assert_ne!(
                REG_CLASSES[i] & RC_FLOAT,
                0,
                "Register {} should be RC_FLOAT",
                i
            );
        }
    }

    #[test]
    fn test_placeholder_not_allocatable() {
        assert_eq!(REG_CLASSES[16], 0, "xxx register should have class 0");
    }

    #[test]
    fn test_ra_sp_classes() {
        // ra has its own class bit at position 17
        assert_eq!(REG_CLASSES[17], 1i32 << 17);
        // sp has its own class bit at position 18
        assert_eq!(REG_CLASSES[18], 1i32 << 18);
    }

    #[test]
    fn test_ra_sp_not_general_int() {
        // ra and sp should NOT have RC_INT set
        assert_eq!(REG_CLASSES[17] & RC_INT, 0);
        assert_eq!(REG_CLASSES[18] & RC_INT, 0);
    }

    #[test]
    fn test_rc_iret_matches() {
        assert_eq!(RC_IRET, rc_r(0));
        assert_eq!(RC_IRET, 1 << 2);
    }

    #[test]
    fn test_rc_ire2_matches() {
        assert_eq!(RC_IRE2, rc_r(1));
        assert_eq!(RC_IRE2, 1 << 3);
    }

    #[test]
    fn test_rc_fret_matches() {
        assert_eq!(RC_FRET, rc_f(0));
        assert_eq!(RC_FRET, 1 << 10);
    }

    #[test]
    fn test_return_registers() {
        assert_eq!(REG_IRET, 0);
        assert_eq!(REG_IRE2, 1);
        assert_eq!(REG_FRET, 8);
    }

    #[test]
    fn test_size_constants() {
        assert_eq!(PTR_SIZE, 8);
        assert_eq!(LDOUBLE_SIZE, 16);
        assert_eq!(LDOUBLE_ALIGN, 16);
        assert_eq!(MAX_ALIGN, 16);
        assert!(CHAR_IS_UNSIGNED);
    }

    #[test]
    fn test_elf_constants() {
        assert_eq!(EM_TCC_TARGET, 243);
        assert_eq!(R_DATA_32, 1);
        assert_eq!(R_DATA_PTR, 2);
        assert_eq!(R_JMP_SLOT, 5);
        assert_eq!(R_GLOB_DAT, 2);
        assert_eq!(R_COPY, 4);
        assert_eq!(R_RELATIVE, 3);
        assert_eq!(R_NUM, 62);
        assert_eq!(ELF_START_ADDR, 0x0001_0000);
        assert_eq!(ELF_PAGE_SIZE, 0x1000);
        assert!(PCRELATIVE_DLLPLT);
        assert!(RELOCATE_DLLPLT);
    }

    #[test]
    fn test_ireg_mapping() {
        // a0-a7 → x10-x17
        for i in 0..8u8 {
            assert_eq!(ireg(i as usize), i + 10);
        }
        // ra → x1
        assert_eq!(ireg(TREG_RA), 1);
        // sp → x2
        assert_eq!(ireg(TREG_SP), 2);
    }

    #[test]
    fn test_freg_mapping() {
        // fa0-fa7 → f10-f17
        for i in 0..8u8 {
            assert_eq!(freg((i + 8) as usize), i + 10);
        }
    }

    #[test]
    fn test_is_ireg() {
        for i in 0..8 {
            assert!(is_ireg(i), "Register {} should be ireg", i);
        }
        assert!(!is_ireg(8)); // fa0 is not ireg
        assert!(!is_ireg(15)); // fa7 is not ireg
        assert!(!is_ireg(16)); // xxx is not ireg
        assert!(is_ireg(TREG_RA));
        assert!(is_ireg(TREG_SP));
    }

    #[test]
    fn test_is_freg() {
        for i in 0..8 {
            assert!(!is_freg(i), "Register {} should not be freg", i);
        }
        for i in 8..16 {
            assert!(is_freg(i), "Register {} should be freg", i);
        }
        assert!(!is_freg(16));
        assert!(!is_freg(TREG_RA));
        assert!(!is_freg(TREG_SP));
    }

    #[test]
    fn test_treg_r_and_f() {
        assert_eq!(treg_r(0), 0);
        assert_eq!(treg_r(7), 7);
        assert_eq!(treg_f(0), 8);
        assert_eq!(treg_f(7), 15);
    }

    #[test]
    fn test_upper() {
        // UPPER(0) = (0 + 0x800) & 0xFFFFF000 = 0x800 & 0xFFFFF000 = 0
        assert_eq!(upper(0), 0);
        // UPPER(0x800) = (0x800 + 0x800) & 0xFFFFF000 = 0x1000 & 0xFFFFF000 = 0x1000
        assert_eq!(upper(0x800), 0x1000);
        // UPPER(-1) = (0xFFFFFFFF + 0x800) & 0xFFFFF000 = 0x7FF & 0xFFFFF000 = 0
        assert_eq!(upper(-1), 0);
    }

    #[test]
    fn test_sign7() {
        // SIGN7 sign-extends an 8-bit value where bit 7 is the sign bit.
        // Range: -128 to +127
        assert_eq!(sign7(0), 0);
        assert_eq!(sign7(1), 1);
        // 0x7F = 127: highest positive value in 8-bit signed range
        assert_eq!(sign7(0x7F), 127);
        // 0x80: first negative value → -128
        assert_eq!(sign7(0x80), -128);
        // 0xFF: all bits set → -1
        assert_eq!(sign7(0xFF), -1);
        // 0x100: wraps around (0x100 & 0xFF = 0x00) → 0
        assert_eq!(sign7(0x100), 0);
    }

    #[test]
    fn test_sign11() {
        // SIGN11 sign-extends a 12-bit value where bit 11 is the sign bit.
        // Range: -2048 to +2047
        assert_eq!(sign11(0), 0);
        assert_eq!(sign11(1), 1);
        // 0x7FF = 2047: highest positive value in 12-bit signed range
        assert_eq!(sign11(0x7FF), 2047);
        // 0x800: first negative value → -2048
        assert_eq!(sign11(0x800), -2048);
        // 0xFFF: all bits set → -1
        assert_eq!(sign11(0xFFF), -1);
    }

    #[test]
    fn test_low_overflow() {
        // low_overflow is identical to upper
        assert_eq!(low_overflow(0), upper(0));
        assert_eq!(low_overflow(100), upper(100));
    }

    #[test]
    fn test_target_machine_defs() {
        let defs = TARGET_MACHINE_DEFS;
        assert!(defs.contains("__riscv\0"));
        assert!(defs.contains("__riscv_xlen 64\0"));
        assert!(defs.contains("__riscv_flen 64\0"));
        assert!(defs.contains("__riscv_div\0"));
        assert!(defs.contains("__riscv_mul\0"));
        assert!(defs.contains("__riscv_fdiv\0"));
        assert!(defs.contains("__riscv_fsqrt\0"));
        assert!(defs.contains("__riscv_float_abi_double\0"));
    }

    #[test]
    fn test_backend_construction() {
        let backend = Riscv64Backend::new();
        assert_eq!(backend.loc, 0);
        assert_eq!(backend.func_ret_sub, 0);
        assert!(!backend.func_bound_add_epilog);
    }

    #[test]
    fn test_backend_default() {
        let backend = Riscv64Backend::default();
        assert_eq!(backend.loc, 0);
    }

    #[test]
    fn test_backend_trait_constants() {
        let backend = Riscv64Backend::new();
        assert_eq!(backend.nb_regs(), NB_REGS);
        assert_eq!(backend.ptr_size(), PTR_SIZE);
        assert_eq!(backend.reg_classes().len(), NB_REGS);
        assert_eq!(backend.elf_machine(), EM_TCC_TARGET);
        assert_eq!(backend.elf_start_addr(), ELF_START_ADDR);
        assert_eq!(backend.elf_page_size(), ELF_PAGE_SIZE);
        assert!(backend.pcrelative_dllplt());
        assert!(backend.relocate_dllplt());
        assert_eq!(backend.target_machine_defs(), TARGET_MACHINE_DEFS);
    }

    #[test]
    fn test_reg_class_individual_bits() {
        // Verify each register has its unique individual class bit
        assert_eq!(REG_CLASSES[0] & rc_r(0), rc_r(0));
        assert_eq!(REG_CLASSES[1] & rc_r(1), rc_r(1));
        assert_eq!(REG_CLASSES[7] & rc_r(7), rc_r(7));
        assert_eq!(REG_CLASSES[8] & rc_f(0), rc_f(0));
        assert_eq!(REG_CLASSES[15] & rc_f(7), rc_f(7));
    }

    #[test]
    fn test_xlen() {
        assert_eq!(XLEN, 8);
    }

    #[test]
    fn test_reloc_constants() {
        assert_eq!(reloc::R_RISCV_NONE, 0);
        assert_eq!(reloc::R_RISCV_32, 1);
        assert_eq!(reloc::R_RISCV_64, 2);
        assert_eq!(reloc::R_RISCV_RELATIVE, 3);
        assert_eq!(reloc::R_RISCV_COPY, 4);
        assert_eq!(reloc::R_RISCV_JUMP_SLOT, 5);
        assert_eq!(reloc::R_RISCV_BRANCH, 16);
        assert_eq!(reloc::R_RISCV_JAL, 17);
        assert_eq!(reloc::R_RISCV_CALL, 18);
        assert_eq!(reloc::R_RISCV_PCREL_HI20, 23);
        assert_eq!(reloc::R_RISCV_PCREL_LO12_I, 24);
        assert_eq!(reloc::R_RISCV_HI20, 26);
        assert_eq!(reloc::R_RISCV_LO12_I, 27);
    }

    #[test]
    #[should_panic(expected = "ireg: invalid integer register index")]
    fn test_ireg_panic_on_invalid() {
        ireg(8); // 8 is a float register
    }

    #[test]
    #[should_panic(expected = "freg: invalid float register index")]
    fn test_freg_panic_on_invalid() {
        freg(0); // 0 is an integer register
    }
}
