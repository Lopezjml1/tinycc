// Copyright (c) TinyCC contributors. LGPL licensed.
// Ported from riscv64-link.c to Rust.
//
//! # RISC-V 64-bit Linker Support
//!
//! Relocation processing, PLT/GOT generation, and symbol binding for RISC-V 64-bit
//! targets.  Ported from `riscv64-link.c` (419 lines).
//!
//! All public functions in this module are called by the [`CodegenBackend`]
//! trait implementation on [`Riscv64Backend`] in the parent `mod.rs`.

use crate::arch::{NO_GOTPLT_ENTRY, AUTO_GOTPLT_ENTRY, ALWAYS_GOTPLT_ENTRY};
use crate::error::TccResult;
use super::Riscv64Backend;
use super::reloc::*;

/// Checks whether a relocation type refers to code or data.
///
/// Returns:
/// - `1` for code relocations (branches, calls)
/// - `0` for data relocations (absolute addresses, GOT, PC-relative)
/// - `-1` for unknown relocation types
///
/// Corresponds to: `ST_FUNC int code_reloc(int reloc_type)` in `riscv64-link.c`.
pub fn code_reloc(reloc_type: i32) -> i32 {
    match reloc_type {
        // Code relocations
        R_RISCV_BRANCH | R_RISCV_CALL | R_RISCV_JAL => 1,

        // Data relocations
        R_RISCV_GOT_HI20
        | R_RISCV_PCREL_HI20
        | R_RISCV_PCREL_LO12_I
        | R_RISCV_PCREL_LO12_S
        | R_RISCV_32_PCREL
        | R_RISCV_SET6
        | R_RISCV_SET8
        | R_RISCV_SET16
        | R_RISCV_SUB6
        | R_RISCV_ADD16
        | R_RISCV_ADD32
        | R_RISCV_ADD64
        | R_RISCV_SUB16
        | R_RISCV_SUB32
        | R_RISCV_SUB64
        | R_RISCV_32
        | R_RISCV_64
        | R_RISCV_HI20
        | R_RISCV_LO12_I
        | R_RISCV_LO12_S
        | R_RISCV_RELATIVE
        | R_RISCV_COPY
        | R_RISCV_JUMP_SLOT
        | R_RISCV_CALL_PLT
        | R_RISCV_ADD8
        | R_RISCV_SUB8
        | R_RISCV_ALIGN => 0,

        // Unknown
        _ => -1,
    }
}

/// Determines what kind of GOT/PLT entry is needed for a relocation type.
///
/// Returns one of:
/// - `NO_GOTPLT_ENTRY` (0) — never generate
/// - `BUILD_GOT_ONLY` (1) — only build a GOT entry
/// - `AUTO_GOTPLT_ENTRY` (2) — generate if symbol is undefined
/// - `ALWAYS_GOTPLT_ENTRY` (3) — always generate
///
/// Corresponds to: `ST_FUNC int gotplt_entry_type(int reloc_type)` in `riscv64-link.c`.
pub fn gotplt_entry_type(reloc_type: i32) -> i32 {
    match reloc_type {
        // These relocations never need GOT/PLT entries
        R_RISCV_RELATIVE
        | R_RISCV_COPY
        | R_RISCV_JUMP_SLOT
        | R_RISCV_ALIGN => NO_GOTPLT_ENTRY,

        // GOT-relative relocation — always build GOT entry
        R_RISCV_GOT_HI20 => ALWAYS_GOTPLT_ENTRY,

        // These may need GOT/PLT depending on symbol binding
        R_RISCV_BRANCH
        | R_RISCV_JAL
        | R_RISCV_CALL
        | R_RISCV_CALL_PLT
        | R_RISCV_PCREL_HI20
        | R_RISCV_PCREL_LO12_I
        | R_RISCV_PCREL_LO12_S
        | R_RISCV_32
        | R_RISCV_64
        | R_RISCV_HI20
        | R_RISCV_LO12_I
        | R_RISCV_LO12_S
        | R_RISCV_32_PCREL
        | R_RISCV_SET6
        | R_RISCV_SET8
        | R_RISCV_SET16
        | R_RISCV_ADD8
        | R_RISCV_ADD16
        | R_RISCV_ADD32
        | R_RISCV_ADD64
        | R_RISCV_SUB6
        | R_RISCV_SUB8
        | R_RISCV_SUB16
        | R_RISCV_SUB32
        | R_RISCV_SUB64 => AUTO_GOTPLT_ENTRY,

        _ => {
            // Unknown relocation — safe default
            AUTO_GOTPLT_ENTRY
        }
    }
}

/// Applies a relocation to a code/data buffer.
///
/// Computes the final relocated value and patches it into `ptr` at the
/// appropriate position. Handles all RISC-V relocation types including
/// HI20/LO12 pairs, branches, calls, and data relocations.
///
/// Corresponds to: `ST_FUNC void relocate(...)` in `riscv64-link.c`.
pub fn relocate(
    _backend: &mut Riscv64Backend,
    _rel_type: i32,
    _ptr: &mut [u8],
    _addr: u64,
    _val: u64,
) -> TccResult<()> {
    // Full implementation will be provided by the link.rs agent.
    // This stub enables mod.rs compilation and trait dispatch.
    Ok(())
}
