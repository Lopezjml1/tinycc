//! i386 relocation and linking — relocation type classification, PLT/GOT
//! generation, and relocation application.
//!
//! Port of `i386-link.c` (329 lines).
//!
//! This module provides the linker interface functions for the i386 backend.
//! All public functions are called by the [`super::I386Backend`] trait
//! implementation of [`CodegenBackend`](crate::arch::CodegenBackend).
//!
//! # Relocation Types
//!
//! i386 ELF uses the following relocation types (`R_386_*`):
//! - `R_386_32` (1) — Absolute 32-bit address
//! - `R_386_PC32` (2) — PC-relative 32-bit offset
//! - `R_386_COPY` (5) — Copy symbol value at runtime
//! - `R_386_GLOB_DAT` (6) — GOT entry for global data
//! - `R_386_JMP_SLOT` (7) — PLT jump slot
//! - `R_386_RELATIVE` (8) — Relative address adjustment
//! - `R_386_PLT32` (11) — PLT-relative 32-bit offset
//! - And various TLS relocation types

use crate::error::TccResult;

// i386 ELF relocation type constants (from elf.h)
// These are the raw values, separate from the aliases in mod.rs.

/// R_386_NONE — No relocation.
pub const R_386_NONE: i32 = 0;
/// R_386_32 — Direct 32-bit absolute.
pub const R_386_32: i32 = 1;
/// R_386_PC32 — PC relative 32-bit.
pub const R_386_PC32: i32 = 2;
/// R_386_GOT32 — 32-bit GOT entry.
pub const R_386_GOT32: i32 = 3;
/// R_386_PLT32 — 32-bit PLT address.
pub const R_386_PLT32: i32 = 4;
/// R_386_COPY — Copy symbol at runtime.
pub const R_386_COPY: i32 = 5;
/// R_386_GLOB_DAT — Create GOT entry.
pub const R_386_GLOB_DAT: i32 = 6;
/// R_386_JMP_SLOT — Create PLT entry.
pub const R_386_JMP_SLOT: i32 = 7;
/// R_386_RELATIVE — Adjust by base address.
pub const R_386_RELATIVE: i32 = 8;
/// R_386_GOTOFF — 32-bit offset to GOT.
pub const R_386_GOTOFF: i32 = 9;
/// R_386_GOTPC — 32-bit PC relative offset to GOT.
pub const R_386_GOTPC: i32 = 10;
/// R_386_GOT32X — 32-bit GOT entry with relaxation.
pub const R_386_GOT32X: i32 = 43;
/// R_386_16 — Direct 16-bit absolute.
pub const R_386_16: i32 = 20;
/// R_386_PC16 — 16-bit PC relative.
pub const R_386_PC16: i32 = 21;

/// Checks whether a relocation type refers to code or data.
///
/// # Returns
/// - `1` if the relocation is for code (branch/call relocations)
/// - `0` if the relocation is for data (absolute address relocations)
/// - `-1` if the relocation type is unknown
///
/// Source: `i386-link.c` — `ST_FUNC int code_reloc(int reloc_type)`
pub fn code_reloc(reloc_type: i32) -> i32 {
    match reloc_type {
        R_386_RELATIVE
        | R_386_16
        | R_386_32
        | R_386_GOTPC
        | R_386_GOTOFF
        | R_386_GOT32
        | R_386_GOT32X
        | R_386_GLOB_DAT
        | R_386_COPY
        | R_386_NONE => 0,  // data relocation

        R_386_PC32
        | R_386_PC16
        | R_386_PLT32
        | R_386_JMP_SLOT => 1,  // code relocation

        _ => -1,  // unknown relocation type
    }
}

/// Determines what kind of GOT/PLT entry is needed for a relocation type.
///
/// # Returns
/// One of the `*_GOTPLT_ENTRY` constants from `arch/mod.rs`:
/// - `0` (NO_GOTPLT_ENTRY) — Never generate
/// - `1` (BUILD_GOT_ONLY) — Only build GOT entry
/// - `2` (AUTO_GOTPLT_ENTRY) — Generate if symbol is undefined
/// - `3` (ALWAYS_GOTPLT_ENTRY) — Always generate
///
/// Source: `i386-link.c` — `ST_FUNC int gotplt_entry_type(int reloc_type)`
pub fn gotplt_entry_type(reloc_type: i32) -> i32 {
    use crate::arch::{
        NO_GOTPLT_ENTRY, BUILD_GOT_ONLY, AUTO_GOTPLT_ENTRY, ALWAYS_GOTPLT_ENTRY,
    };

    match reloc_type {
        R_386_RELATIVE
        | R_386_16
        | R_386_32
        | R_386_GOTPC
        | R_386_GOTOFF
        | R_386_NONE => NO_GOTPLT_ENTRY,

        R_386_GOT32
        | R_386_GOT32X => ALWAYS_GOTPLT_ENTRY,

        R_386_GLOB_DAT
        | R_386_JMP_SLOT
        | R_386_COPY => NO_GOTPLT_ENTRY,

        R_386_PC32
        | R_386_PC16
        | R_386_PLT32 => AUTO_GOTPLT_ENTRY,

        _ => {
            // Unknown relocation type — build GOT only as safe default
            BUILD_GOT_ONLY
        }
    }
}

/// Applies a relocation to a code/data buffer.
///
/// Computes the final relocated value and patches it into the byte buffer
/// at the relocation site.
///
/// # Arguments
/// * `rel_type` — i386 relocation type (`R_386_*`)
/// * `ptr` — Mutable byte slice at the relocation site
/// * `addr` — Address of the relocation site in the output
/// * `val` — Resolved symbol value (target address)
///
/// Source: `i386-link.c` — `ST_FUNC void relocate(...)`
pub fn relocate(rel_type: i32, ptr: &mut [u8], addr: u64, val: u64) -> TccResult<()> {
    if ptr.len() < 4 {
        return Err(crate::error::TccError::CodegenError {
            message: format!(
                "Relocation buffer too small: need 4 bytes, got {}",
                ptr.len()
            ),
        });
    }

    match rel_type {
        R_386_32 => {
            // Absolute 32-bit: add symbol value to existing content
            let existing = u32::from_le_bytes([ptr[0], ptr[1], ptr[2], ptr[3]]);
            let result = existing.wrapping_add(val as u32);
            ptr[..4].copy_from_slice(&result.to_le_bytes());
        }
        R_386_PC32 | R_386_PLT32 => {
            // PC-relative 32-bit: add (symbol_value - relocation_address) to existing
            let existing = u32::from_le_bytes([ptr[0], ptr[1], ptr[2], ptr[3]]);
            let result = existing.wrapping_add((val.wrapping_sub(addr)) as u32);
            ptr[..4].copy_from_slice(&result.to_le_bytes());
        }
        R_386_GLOB_DAT | R_386_JMP_SLOT => {
            // Direct symbol address write
            ptr[..4].copy_from_slice(&(val as u32).to_le_bytes());
        }
        R_386_RELATIVE => {
            // Base + existing addend
            let existing = u32::from_le_bytes([ptr[0], ptr[1], ptr[2], ptr[3]]);
            let result = existing.wrapping_add(val as u32);
            ptr[..4].copy_from_slice(&result.to_le_bytes());
        }
        R_386_GOT32 | R_386_GOT32X | R_386_GOTOFF | R_386_GOTPC => {
            // GOT-relative: add (symbol_value - relocation_address) to existing
            let existing = u32::from_le_bytes([ptr[0], ptr[1], ptr[2], ptr[3]]);
            let result = existing.wrapping_add((val.wrapping_sub(addr)) as u32);
            ptr[..4].copy_from_slice(&result.to_le_bytes());
        }
        R_386_16 => {
            // 16-bit absolute
            if ptr.len() < 2 {
                return Err(crate::error::TccError::CodegenError {
                    message: "Relocation buffer too small for R_386_16".to_string(),
                });
            }
            let existing = u16::from_le_bytes([ptr[0], ptr[1]]);
            let result = existing.wrapping_add(val as u16);
            ptr[..2].copy_from_slice(&result.to_le_bytes());
        }
        R_386_PC16 => {
            // 16-bit PC-relative
            if ptr.len() < 2 {
                return Err(crate::error::TccError::CodegenError {
                    message: "Relocation buffer too small for R_386_PC16".to_string(),
                });
            }
            let existing = u16::from_le_bytes([ptr[0], ptr[1]]);
            let result = existing.wrapping_add((val.wrapping_sub(addr)) as u16);
            ptr[..2].copy_from_slice(&result.to_le_bytes());
        }
        R_386_COPY | R_386_NONE => {
            // No patching needed
        }
        _ => {
            return Err(crate::error::TccError::CodegenError {
                message: format!("Unsupported i386 relocation type: {}", rel_type),
            });
        }
    }

    Ok(())
}
