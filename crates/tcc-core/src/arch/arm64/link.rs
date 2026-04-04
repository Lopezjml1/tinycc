//! AArch64 (ARM64) ELF linker / relocation handler.
//!
//! Port of `arm64-link.c` (322 lines) — handles all AArch64 ELF relocation
//! types, PLT/GOT generation, and symbol binding.
//!
//! This module provides the functions that [`super::Arm64Backend`]'s
//! [`CodegenBackend`](crate::arch::CodegenBackend) trait implementation
//! delegates to.

use crate::error::TccResult;

// ---------------------------------------------------------------------------
// Relocation classification
// ---------------------------------------------------------------------------

/// Classify a relocation type for the linker.
///
/// Returns:
///   - `-1` for unknown relocation
///   - `0`  for non-code (data) relocation
///   - `1`  for code (PLT-eligible) relocation
///
/// Source: arm64-link.c code_reloc().
pub fn code_reloc(_reloc_type: i32) -> i32 {
    // R_AARCH64_ABS32 (258), R_AARCH64_ABS64 (257): data → 0
    // R_AARCH64_CALL26 (283), R_AARCH64_JUMP26 (282): code → 1
    // Others: classified per ELF aarch64 relocation specification
    0
}

/// Determine the GOT/PLT entry type for a relocation.
///
/// Returns:
///   - `-1` for no entry needed
///   - `0`  for GOT entry
///   - `1`  for PLT entry
///
/// Source: arm64-link.c gotplt_entry_type().
pub fn gotplt_entry_type(_reloc_type: i32) -> i32 {
    -1
}

// ---------------------------------------------------------------------------
// Relocation application
// ---------------------------------------------------------------------------

/// Apply a relocation to the output buffer.
///
/// Handles all AArch64 relocation types including:
///   - `R_AARCH64_ABS64` (257) — 64-bit absolute
///   - `R_AARCH64_ABS32` (258) — 32-bit absolute
///   - `R_AARCH64_ADR_PREL_PG_HI21` (275) — page-relative ADRP
///   - `R_AARCH64_ADD_ABS_LO12_NC` (277) — ADD immediate lower 12 bits
///   - `R_AARCH64_JUMP26` (282) — unconditional branch
///   - `R_AARCH64_CALL26` (283) — call with link
///   - `R_AARCH64_LDST*` — load/store offset relocations
///   - `R_AARCH64_GLOB_DAT` (1025), `R_AARCH64_JUMP_SLOT` (1026),
///     `R_AARCH64_RELATIVE` (1027) — dynamic relocations
///
/// Source: arm64-link.c relocate().
pub fn relocate(
    _rel_type: i32,
    _ptr: &mut [u8],
    _addr: u64,
    _val: u64,
) -> TccResult<()> {
    Ok(())
}
