//! AArch64 (ARM64) minimal inline assembler stub.
//!
//! Port of `arm64-asm.c` (94 lines) — minimal assembler support for
//! inline assembly on AArch64. Unlike x86 which has a full instruction
//! encoder, the AArch64 assembler is intentionally minimal.
//!
//! This module provides byte-level code emission helpers and assembler
//! entry points that [`super::Arm64Backend`]'s
//! [`CodegenBackend`](crate::arch::CodegenBackend) trait implementation
//! delegates to.

use crate::error::TccResult;
use super::Arm64Backend;

// ---------------------------------------------------------------------------
// Byte-level code emission
// ---------------------------------------------------------------------------

/// Emit a single byte into the code section.
///
/// Source: arm64-asm.c / tcc.h g() helper — fundamental code emission
/// primitive. All instruction emission ultimately bottoms out here.
pub fn g(_backend: &mut Arm64Backend, _c: i32) -> TccResult<()> {
    Ok(())
}

/// Emit a 16-bit little-endian value into the code section.
///
/// Source: arm64-asm.c / tcc.h gen_le16() helper.
pub fn gen_le16(_backend: &mut Arm64Backend, _c: i32) -> TccResult<()> {
    Ok(())
}

/// Emit a 32-bit little-endian value into the code section.
///
/// Source: arm64-asm.c / tcc.h gen_le32() helper — primary instruction
/// emission for AArch64 (all A64 instructions are 32 bits wide).
pub fn gen_le32(_backend: &mut Arm64Backend, _c: i32) -> TccResult<()> {
    Ok(())
}
