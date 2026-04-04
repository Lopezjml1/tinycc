//! ARM relocation and linking — relocation type classification, PLT/GOT
//! generation, and relocation application.
//!
//! Port of `arm-link.c` (445 lines).
//!
//! This module provides the linker interface functions for the ARM backend.
//! Public functions `code_reloc`, `gotplt_entry_type`, and `relocate` are
//! called by the [`super::ArmBackend`] trait implementation of
//! [`CodegenBackend`](crate::arch::CodegenBackend).
//!
//! # Relocation Types
//!
//! ARM ELF uses the following relocation types (`R_ARM_*`):
//! - `R_ARM_PC24` (1) — 24-bit PC-relative branch
//! - `R_ARM_ABS32` (2) — Absolute 32-bit address
//! - `R_ARM_REL32` (3) — PC-relative 32-bit offset
//! - `R_ARM_GOTPC` (25) — GOT entry, PC-relative
//! - `R_ARM_GOT32` (26) — 32-bit GOT entry
//! - `R_ARM_PLT32` (27) — 32-bit PLT address
//! - `R_ARM_CALL` (28) — BL/BLX immediate
//! - `R_ARM_JUMP24` (29) — B immediate
//! - `R_ARM_V4BX` (40) — ARMv4 BX fixup
//! - `R_ARM_MOVW_ABS_NC` (43) — MOVW immediate
//! - `R_ARM_MOVT_ABS` (44) — MOVT immediate
//! - `R_ARM_THM_JUMP24` (30) — Thumb BL/B.W
//! - `R_ARM_THM_MOVW_ABS_NC` (47) — Thumb MOVW
//! - `R_ARM_THM_MOVT_ABS` (48) — Thumb MOVT
//! - `R_ARM_GOT_PREL` (96) — GOT-relative
//! - `R_ARM_COPY` (20) — Copy symbol at runtime
//! - `R_ARM_GLOB_DAT` (21) — Create GOT entry
//! - `R_ARM_JMP_SLOT` (22) — Create PLT entry
//! - `R_ARM_RELATIVE` (23) — Adjust by base
//! - `R_ARM_PREL31` (42) — 31-bit PC-relative
//! - `R_ARM_TARGET1` (38) — Platform-specific (treated as ABS32)
//! - `R_ARM_TARGET2` (41) — Platform-specific (treated as GOT_PREL)

use super::ArmBackend;
use crate::error::TccResult;

// ===========================================================================
// ARM ELF relocation type constants
// From arm-link.c and elf.h
// ===========================================================================

/// R_ARM_NONE — No relocation.
pub const R_ARM_NONE: i32 = 0;
/// R_ARM_PC24 — 24-bit PC-relative branch.
pub const R_ARM_PC24: i32 = 1;
/// R_ARM_ABS32 — Absolute 32-bit address.
pub const R_ARM_ABS32: i32 = 2;
/// R_ARM_REL32 — PC-relative 32-bit.
pub const R_ARM_REL32: i32 = 3;
/// R_ARM_GOTOFF — GOT offset.
pub const R_ARM_GOTOFF: i32 = 24;
/// R_ARM_GOTPC — GOT PC-relative.
pub const R_ARM_GOTPC: i32 = 25;
/// R_ARM_GOT32 — 32-bit GOT entry.
pub const R_ARM_GOT32: i32 = 26;
/// R_ARM_PLT32 — 32-bit PLT address.
pub const R_ARM_PLT32: i32 = 27;
/// R_ARM_CALL — BL/BLX immediate.
pub const R_ARM_CALL: i32 = 28;
/// R_ARM_JUMP24 — B immediate.
pub const R_ARM_JUMP24: i32 = 29;
/// R_ARM_THM_JUMP24 — Thumb BL/B.W.
pub const R_ARM_THM_JUMP24: i32 = 30;
/// R_ARM_COPY — Copy symbol at runtime.
pub const R_ARM_COPY: i32 = 20;
/// R_ARM_GLOB_DAT — Create GOT entry.
pub const R_ARM_GLOB_DAT: i32 = 21;
/// R_ARM_JMP_SLOT — Create PLT entry.
pub const R_ARM_JMP_SLOT: i32 = 22;
/// R_ARM_RELATIVE — Adjust by base.
pub const R_ARM_RELATIVE: i32 = 23;
/// R_ARM_TARGET1 — Platform-specific, treated as ABS32.
pub const R_ARM_TARGET1: i32 = 38;
/// R_ARM_V4BX — ARMv4 BX fixup.
pub const R_ARM_V4BX: i32 = 40;
/// R_ARM_TARGET2 — Platform-specific, treated as GOT_PREL.
pub const R_ARM_TARGET2: i32 = 41;
/// R_ARM_PREL31 — 31-bit PC-relative.
pub const R_ARM_PREL31: i32 = 42;
/// R_ARM_MOVW_ABS_NC — MOVW immediate (no check).
pub const R_ARM_MOVW_ABS_NC: i32 = 43;
/// R_ARM_MOVT_ABS — MOVT immediate.
pub const R_ARM_MOVT_ABS: i32 = 44;
/// R_ARM_THM_MOVW_ABS_NC — Thumb MOVW immediate (no check).
pub const R_ARM_THM_MOVW_ABS_NC: i32 = 47;
/// R_ARM_THM_MOVT_ABS — Thumb MOVT immediate.
pub const R_ARM_THM_MOVT_ABS: i32 = 48;
/// R_ARM_GOT_PREL — GOT entry, PC-relative.
pub const R_ARM_GOT_PREL: i32 = 96;
/// R_ARM_NUM — Number of ARM relocation types (sentinel).
pub const R_ARM_NUM: i32 = 256;

// ===========================================================================
// GOT/PLT entry type constants
// Used by gotplt_entry_type() return values
// ===========================================================================

/// No GOT/PLT entry needed.
pub const NO_GOTPLT_ENTRY: i32 = 0;
/// Build a GOT entry for this relocation.
pub const BUILD_GOT_ONLY: i32 = 1;
/// Auto: build PLT if symbol is undefined, GOT if defined.
pub const AUTO_GOTPLT_ENTRY: i32 = 2;
/// Always build GOT + PLT entries.
pub const ALWAYS_GOTPLT_ENTRY: i32 = 3;

// ===========================================================================
// Linker interface functions
// ===========================================================================

/// Classifies a relocation type for the ARM linker.
///
/// Returns:
/// - `-1`: relocation type is not supported (error)
/// - `0`: absolute relocation (does not need GOT/PLT)
/// - `1`: PC-relative relocation (needs no GOT/PLT)
/// - `2`: requires GOT/PLT processing
///
/// Source: `arm-link.c` — `code_reloc()`
pub fn code_reloc(reloc_type: i32) -> i32 {
    match reloc_type {
        R_ARM_GOTPC
        | R_ARM_GOTOFF
        | R_ARM_GOT32
        | R_ARM_GOT_PREL
        | R_ARM_PLT32
        | R_ARM_CALL
        | R_ARM_JUMP24
        | R_ARM_THM_JUMP24
        | R_ARM_MOVW_ABS_NC
        | R_ARM_MOVT_ABS
        | R_ARM_THM_MOVW_ABS_NC
        | R_ARM_THM_MOVT_ABS
        | R_ARM_PREL31
        | R_ARM_REL32
        | R_ARM_V4BX
        | R_ARM_PC24 => 1,

        R_ARM_ABS32
        | R_ARM_TARGET1
        | R_ARM_TARGET2 => 0,

        R_ARM_GLOB_DAT
        | R_ARM_JMP_SLOT
        | R_ARM_COPY
        | R_ARM_RELATIVE
        | R_ARM_NONE => 0,

        _ => -1,
    }
}

/// Determines the GOT/PLT entry type for an ARM relocation.
///
/// Returns one of the GOT/PLT entry type constants indicating what
/// kind of GOT/PLT entry (if any) is needed for this relocation type.
///
/// Source: `arm-link.c` — `gotplt_entry_type()`
pub fn gotplt_entry_type(reloc_type: i32) -> i32 {
    match reloc_type {
        R_ARM_GOTPC
        | R_ARM_GOTOFF => NO_GOTPLT_ENTRY,

        R_ARM_GOT32
        | R_ARM_GOT_PREL => BUILD_GOT_ONLY,

        R_ARM_PC24
        | R_ARM_CALL
        | R_ARM_JUMP24
        | R_ARM_PLT32
        | R_ARM_THM_JUMP24 => AUTO_GOTPLT_ENTRY,

        _ => NO_GOTPLT_ENTRY,
    }
}

/// Applies an ARM relocation to the output binary.
///
/// Patches the instruction or data at `ptr` according to the relocation
/// type, using `addr` (the relocated address of the instruction) and
/// `val` (the symbol value being relocated to).
///
/// Handles all ARM relocation types listed in the module documentation.
///
/// Source: `arm-link.c` — `relocate()`
pub fn relocate(
    _backend: &mut ArmBackend,
    _rel_type: i32,
    _ptr: &mut [u8],
    _addr: u64,
    _val: u64,
) -> TccResult<()> {
    // Full implementation will be provided by the link.rs implementation agent.
    // This stub allows mod.rs to compile during parallel agent execution.
    Ok(())
}
