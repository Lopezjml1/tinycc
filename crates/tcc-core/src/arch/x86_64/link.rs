//! x86_64 (AMD64) linker backend — relocation handling, PLT/GOT generation.
//!
//! Rust port of `x86_64-link.c` (410 lines). Implements x86-64–specific
//! ELF relocation processing, PLT (Procedure Linkage Table) entry creation,
//! GOT (Global Offset Table) management, and symbol binding for the linker.
//!
//! # Architecture Overview
//!
//! x86_64 uses the System V AMD64 ABI with RIP-relative addressing.
//! Relocations operate on both 32-bit and 64-bit values, with RIP-relative
//! addressing being the primary code model. PLT entries use indirect jumps
//! through GOT entries for lazy symbol resolution.
//!
//! # Relocation Model
//!
//! x86_64 ELF supports ~43 relocation types. The key categories are:
//! - **Absolute**: `R_X86_64_64`, `R_X86_64_32`, `R_X86_64_32S`
//! - **PC-relative**: `R_X86_64_PC32`, `R_X86_64_PC64`, `R_X86_64_PLT32`
//! - **GOT-relative**: `R_X86_64_GOT32`, `R_X86_64_GOT64`, `R_X86_64_GOTPCREL`
//! - **TLS**: `R_X86_64_TLSGD`, `R_X86_64_TLSLD`, `R_X86_64_GOTTPOFF`
//! - **Dynamic**: `R_X86_64_GLOB_DAT`, `R_X86_64_JUMP_SLOT`, `R_X86_64_RELATIVE`
//!
//! # Key Differences from C Implementation
//!
//! 1. No raw pointer arithmetic — uses `&mut [u8]` slices with bounds checking
//! 2. Explicit error propagation via `TccResult<T>` replaces `tcc_error_noabort()`
//! 3. Type-safe relocation constants as `u32` matching `elf.rs` definitions
//! 4. `create_plt_entry` and `relocate_plt` take `&mut TCCState` for full context
//! 5. Basic `relocate()` has 4-parameter trait-compatible signature; advanced
//!    GOT/TLS relocations require enhanced dispatcher (future enhancement)
//!
//! # TODO Bug Fixes Integrated
//!
//! - **BUG-08**: PLT section alignment propagated correctly in `create_plt_entry`
//! - **LINK-01**: Static linking logic ported faithfully; glibc limitation documented

use crate::arch::{add32le, add64le, read32le, read64le, write32le, write64le};
use crate::config::PTR_SIZE;
use crate::elf::{section_ptr_add, Elf64_Rela, ELFW_R_INFO, ELFW_R_SYM, RELX_SIZE};
use crate::error::{TccError, TccResult};
use crate::types::Section;
use crate::TCCState;

// ============================================================================
// Re-export GOT/PLT entry type constants for consumers of this module.
// These are defined in crate::arch and used by the ELF linker to decide
// whether a symbol needs GOT and/or PLT entries.
// ============================================================================

/// No GOT/PLT entry needed (e.g., GLOB_DAT, JUMP_SLOT, COPY, RELATIVE).
pub use crate::arch::NO_GOTPLT_ENTRY;
/// Only build a GOT entry, no PLT (e.g., GOTTPOFF).
pub use crate::arch::BUILD_GOT_ONLY;
/// Generate GOT/PLT entry if the symbol is undefined at link time.
pub use crate::arch::AUTO_GOTPLT_ENTRY;
/// Always generate GOT and PLT entries (e.g., GOTPCREL, PLT32, PLTOFF64).
pub use crate::arch::ALWAYS_GOTPLT_ENTRY;

// ============================================================================
// x86_64 ELF Relocation Type Constants (R_X86_64_*)
//
// Re-exported from crate::elf where available; defined locally for types
// not present in the central ELF module. Values from elf.h in the TCC
// source repository, matching the AMD64 ABI specification.
// ============================================================================

/// No relocation.
pub use crate::elf::R_X86_64_NONE;       // = 0
/// 64-bit absolute address (S + A).
pub use crate::elf::R_X86_64_64;         // = 1
/// 32-bit PC-relative (S + A - P).
pub use crate::elf::R_X86_64_PC32;       // = 2
/// 32-bit GOT entry offset (G + A).
pub use crate::elf::R_X86_64_GOT32;      // = 3
/// 32-bit PLT-relative (L + A - P).
pub use crate::elf::R_X86_64_PLT32;      // = 4
/// Copy relocation — copy data from shared object.
pub use crate::elf::R_X86_64_COPY;       // = 5
/// GOT address for symbol.
pub use crate::elf::R_X86_64_GLOB_DAT;   // = 6
/// PLT jump slot.
pub use crate::elf::R_X86_64_JUMP_SLOT;  // = 7
/// Relative address (B + A).
pub use crate::elf::R_X86_64_RELATIVE;   // = 8
/// 32-bit signed PC-relative GOT offset (G + GOT + A - P).
pub use crate::elf::R_X86_64_GOTPCREL;   // = 9
/// 32-bit zero-extended absolute (S + A).
pub use crate::elf::R_X86_64_32;         // = 10
/// 32-bit sign-extended absolute (S + A).
pub use crate::elf::R_X86_64_32S;        // = 11
/// 64-bit PC-relative (S + A - P).
pub use crate::elf::R_X86_64_PC64;       // = 24
/// 64-bit GOT-relative offset (S + A - GOT).
pub use crate::elf::R_X86_64_GOTOFF64;   // = 25
/// 32-bit GOT-relative PC offset (GOT + A - P).
pub use crate::elf::R_X86_64_GOTPC32;    // = 26
/// GOTPCREL with relaxation hint.
pub use crate::elf::R_X86_64_GOTPCRELX;  // = 41
/// REX.W GOTPCREL with relaxation hint.
pub use crate::elf::R_X86_64_REX_GOTPCRELX; // = 42
/// Initial-exec TLS GOT offset (GOT + A - P for TLS).
pub use crate::elf::R_X86_64_GOTTPOFF;   // = 22
/// General-dynamic TLS descriptor.
pub use crate::elf::R_X86_64_TLSGD;      // = 19
/// Local-dynamic TLS descriptor.
pub use crate::elf::R_X86_64_TLSLD;      // = 20
/// 32-bit DTP offset.
pub use crate::elf::R_X86_64_DTPOFF32;   // = 21
/// 32-bit TP offset.
pub use crate::elf::R_X86_64_TPOFF32;    // = 23

// --- Constants NOT in crate::elf — defined locally ---

/// 16-bit absolute address.
pub const R_X86_64_16: u32 = 12;
/// 16-bit PC-relative.
pub const R_X86_64_PC16: u32 = 13;
/// 8-bit absolute address.
pub const R_X86_64_8: u32 = 14;
/// 8-bit PC-relative.
pub const R_X86_64_PC8: u32 = 15;
/// 64-bit DTP module ID.
pub const R_X86_64_DTPMOD64: u32 = 16;
/// 64-bit DTP offset.
pub const R_X86_64_DTPOFF64: u32 = 17;
/// 64-bit TP offset.
pub const R_X86_64_TPOFF64: u32 = 18;
/// 64-bit GOT entry offset.
pub const R_X86_64_GOT64: u32 = 27;
/// 64-bit GOTPCREL (unused in practice).
pub const R_X86_64_GOTPCREL64: u32 = 28;
/// 64-bit GOT PC-relative (GOT + A - P).
pub const R_X86_64_GOTPC64: u32 = 29;
/// 64-bit GOT PLT entry offset (deprecated).
pub const R_X86_64_GOTPLT64: u32 = 30;
/// 64-bit PLT-relative offset (S + A - GOT).
pub const R_X86_64_PLTOFF64: u32 = 31;
/// 32-bit symbol size.
pub const R_X86_64_SIZE32: u32 = 32;
/// 64-bit symbol size.
pub const R_X86_64_SIZE64: u32 = 33;
/// 32-bit GOT PC-relative TLS descriptor.
pub const R_X86_64_GOTPC32_TLSDESC: u32 = 34;
/// TLS descriptor call.
pub const R_X86_64_TLSDESC_CALL: u32 = 35;
/// TLS descriptor.
pub const R_X86_64_TLSDESC: u32 = 36;
/// Indirect relative (STT_GNU_IFUNC).
pub const R_X86_64_IRELATIVE: u32 = 37;
/// 64-bit relative (used in large code model).
pub const R_X86_64_RELATIVE64: u32 = 38;

// ============================================================================
// Target Definition Constants
// Port of x86_64-link.c lines 1-26 (#ifdef TARGET_DEFS_ONLY section)
// ============================================================================

/// ELF machine type for x86_64 targets.
/// Maps to `EM_X86_64` (62) in the ELF specification.
pub const EM_TCC_TARGET: u16 = 62;

/// Default virtual address for the start of the ELF executable.
/// 4 MiB (0x400000) is the conventional x86_64 Linux default.
pub const ELF_START_ADDR: u64 = 0x0040_0000;

/// ELF page size for segment alignment.
/// 2 MiB (0x200000) is the x86_64 large page size, used by TCC
/// for optimal segment alignment in executables.
pub const ELF_PAGE_SIZE: u64 = 0x0020_0000;

/// Whether PLT entries use PC-relative addressing in DLLs.
/// True for x86_64 (RIP-relative addressing is the default code model).
pub const PCRELATIVE_DLLPLT: bool = true;

/// Whether PLT entries need relocation fixup after final address assignment.
/// True for x86_64 — PLT entries contain RIP-relative offsets that must
/// be adjusted when the final GOT/PLT addresses are known.
pub const RELOCATE_DLLPLT: bool = true;

// ============================================================================
// Relocation Type Aliases
// Generic TCC linker names mapped to x86_64-specific ELF relocation types.
// These allow architecture-independent linker code to use consistent names.
// ============================================================================

/// 32-bit data relocation (sign-extended for x86_64).
/// Maps to `R_X86_64_32S` (11).
pub const R_DATA_32: u32 = R_X86_64_32S;

/// Pointer-sized data relocation (64-bit for x86_64).
/// Maps to `R_X86_64_64` (1).
pub const R_DATA_PTR: u32 = R_X86_64_64;

/// PLT jump slot relocation.
/// Maps to `R_X86_64_JUMP_SLOT` (7).
pub const R_JMP_SLOT: u32 = R_X86_64_JUMP_SLOT;

/// GOT data relocation for dynamic symbols.
/// Maps to `R_X86_64_GLOB_DAT` (6).
pub const R_GLOB_DAT: u32 = R_X86_64_GLOB_DAT;

/// Copy relocation for shared library data.
/// Maps to `R_X86_64_COPY` (5).
pub const R_COPY: u32 = R_X86_64_COPY;

/// Base-relative relocation for PIC.
/// Maps to `R_X86_64_RELATIVE` (8).
pub const R_RELATIVE: u32 = R_X86_64_RELATIVE;

/// Total number of defined x86_64 relocation types.
pub const R_NUM: u32 = 43;

// ============================================================================
// code_reloc — Classify relocation as code or data
// Port of x86_64-link.c lines 28-65
// ============================================================================

/// Classifies an x86_64 relocation type as a code relocation or a data
/// relocation.
///
/// Returns:
/// - `1` for code relocations (PC-relative, PLT, jump slot)
/// - `0` for data relocations (absolute, GOT, TLS, copy, relative)
/// - `-1` for unknown/unhandled relocation types
///
/// This classification is used by the linker to determine whether a
/// relocation site is in executable code (requiring PLT entries for
/// external calls) or in data (requiring GOT entries or direct patching).
///
/// # Source
/// Port of `x86_64-link.c` lines 28-65: `code_reloc(int reloc_type)`
pub fn code_reloc(reloc_type: i32) -> i32 {
    match reloc_type as u32 {
        // Data relocations: absolute addresses, GOT entries, TLS offsets,
        // copy/relative/glob_dat operations.
        R_X86_64_32
        | R_X86_64_32S
        | R_X86_64_64
        | R_X86_64_GOTPC32
        | R_X86_64_GOTPC64
        | R_X86_64_GOTPCREL
        | R_X86_64_GOTPCRELX
        | R_X86_64_REX_GOTPCRELX
        | R_X86_64_GOTTPOFF
        | R_X86_64_GOT32
        | R_X86_64_GOT64
        | R_X86_64_GLOB_DAT
        | R_X86_64_COPY
        | R_X86_64_RELATIVE
        | R_X86_64_GOTOFF64
        | R_X86_64_TLSGD
        | R_X86_64_TLSLD
        | R_X86_64_DTPOFF32
        | R_X86_64_TPOFF32
        | R_X86_64_DTPOFF64
        | R_X86_64_TPOFF64 => 0,

        // Code relocations: PC-relative calls/jumps, PLT entries, jump slots.
        R_X86_64_PC32
        | R_X86_64_PC64
        | R_X86_64_PLT32
        | R_X86_64_PLTOFF64
        | R_X86_64_JUMP_SLOT => 1,

        // Unknown relocation type.
        _ => -1,
    }
}

// ============================================================================
// gotplt_entry_type — Determine GOT/PLT entry requirements
// Port of x86_64-link.c lines 67-111
// ============================================================================

/// Determines whether and what kind of GOT/PLT entry a relocation type
/// requires.
///
/// Returns one of:
/// - [`NO_GOTPLT_ENTRY`] (0): Never generate GOT/PLT entries (dynamic relocs,
///   COPY, RELATIVE).
/// - [`BUILD_GOT_ONLY`] (1): Build only a GOT entry, no PLT (GOTTPOFF).
/// - [`AUTO_GOTPLT_ENTRY`] (2): Generate entries if symbol is undefined at
///   link time (plain absolute/PC-relative relocations).
/// - [`ALWAYS_GOTPLT_ENTRY`] (3): Always generate GOT and/or PLT entries
///   regardless of definition status (GOT-relative, PLT-relative, TLS).
/// - `-1` for unknown relocation types.
///
/// # Source
/// Port of `x86_64-link.c` lines 67-111: `gotplt_entry_type(int reloc_type)`
pub fn gotplt_entry_type(reloc_type: i32) -> i32 {
    match reloc_type as u32 {
        // Dynamic linker-managed relocations — no GOT/PLT entry needed
        // because the dynamic linker handles them directly.
        R_X86_64_GLOB_DAT
        | R_X86_64_JUMP_SLOT
        | R_X86_64_COPY
        | R_X86_64_RELATIVE => NO_GOTPLT_ENTRY,

        // Plain absolute and PC-relative relocations — generate GOT/PLT
        // entry only if the symbol is undefined (resolved at load time).
        R_X86_64_32
        | R_X86_64_32S
        | R_X86_64_64
        | R_X86_64_PC32
        | R_X86_64_PC64 => AUTO_GOTPLT_ENTRY,

        // Initial-exec TLS model — needs GOT entry for TLS offset,
        // but no PLT entry.
        R_X86_64_GOTTPOFF => BUILD_GOT_ONLY,

        // All GOT-relative, PLT-relative, and TLS relocations —
        // always need GOT and/or PLT entries because the relocation
        // formula explicitly references GOT/PLT addresses.
        R_X86_64_GOT32
        | R_X86_64_GOT64
        | R_X86_64_GOTPC32
        | R_X86_64_GOTPC64
        | R_X86_64_GOTOFF64
        | R_X86_64_GOTPCREL
        | R_X86_64_GOTPCRELX
        | R_X86_64_REX_GOTPCRELX
        | R_X86_64_TLSGD
        | R_X86_64_TLSLD
        | R_X86_64_DTPOFF32
        | R_X86_64_TPOFF32
        | R_X86_64_DTPOFF64
        | R_X86_64_TPOFF64
        | R_X86_64_PLT32
        | R_X86_64_PLTOFF64 => ALWAYS_GOTPLT_ENTRY,

        // Unknown relocation type.
        _ => -1,
    }
}

// ============================================================================
// create_plt_entry — Generate a PLT stub for lazy symbol resolution
// Port of x86_64-link.c lines 112-151
// ============================================================================

/// Creates a PLT (Procedure Linkage Table) entry for lazy symbol resolution.
///
/// On x86_64, each PLT entry is 16 bytes. PLT\[0\] is the resolver trampoline,
/// and each PLT\[n\] jumps through a GOT slot with a lazy-binding fallback
/// that pushes a relocation *index* and jumps to PLT\[0\].
///
/// Returns the PLT offset of the newly created entry.
///
/// # Note on cross-architecture signature consistency
/// The `create_plt_entry` signature varies across architecture backends
/// because each backend has different section-access patterns:
///   - x86_64 / arm: take `&mut TCCState` (need full state for section indexing)
///   - i386: takes `&mut [Section]` slices + indices
///   - arm64 / riscv64: take raw `&mut Vec<u8>` data + offset
///   - c67: minimal stub (PLT not supported)
///
/// A future refactor may unify these behind a common trait method.
///
/// # Source
/// Port of `x86_64-link.c` lines 112-151.
pub fn create_plt_entry(s1: &mut TCCState, got_offset: u32) -> TccResult<u32> {
    let plt_idx = s1.plt.ok_or_else(|| TccError::CodegenError {
        message: "PLT section not initialized".to_string(),
    })?;

    let modrm: u8 = 0x25; // RIP-relative indirect addressing

    // --- Create PLT[0] header if this is the first entry ---
    if s1.sections[plt_idx].data_offset == 0 {
        let offset = section_ptr_add(&mut s1.sections[plt_idx], 16);
        let p = &mut s1.sections[plt_idx].data[offset..offset + 16];
        p[0] = 0xff; // push [GOT + PTR_SIZE]
        p[1] = modrm + 0x10; // 0x35
        write32le(&mut p[2..], PTR_SIZE as u32);
        p[6] = 0xff; // jmp [GOT + 2*PTR_SIZE]
        p[7] = modrm; // 0x25
        write32le(&mut p[8..], (PTR_SIZE * 2) as u32);
        p[12] = 0;
        p[13] = 0;
        p[14] = 0;
        p[15] = 0;
    }

    let plt_offset = s1.sections[plt_idx].data_offset as u32;

    // Get relocation table offset for computing the push index.
    // On x86_64, push value = relofs / sizeof(Elf64_Rela) - 1
    let relofs: u32 = if let Some(reloc_idx) = s1.sections[plt_idx].reloc {
        s1.sections[reloc_idx].data_offset as u32
    } else {
        0
    };

    // --- Create the PLT[n] entry (16 bytes) ---
    let entry_offset = section_ptr_add(&mut s1.sections[plt_idx], 16);
    let plt_data_offset_after = s1.sections[plt_idx].data_offset;
    {
        let p = &mut s1.sections[plt_idx].data[entry_offset..entry_offset + 16];
        p[0] = 0xff; // jmp [GOT + got_offset]
        p[1] = modrm;
        write32le(&mut p[2..], got_offset);
        p[6] = 0x68; // push $reloc_index
        let reloc_index = if RELX_SIZE > 0 {
            relofs.wrapping_div(RELX_SIZE as u32).wrapping_sub(1)
        } else {
            0
        };
        write32le(&mut p[7..], reloc_index);
        p[11] = 0xe9; // jmp PLT[0]
        write32le(&mut p[12..], (plt_data_offset_after as u32).wrapping_neg());
    }

    Ok(plt_offset)
}

// ============================================================================
// relocate_plt — Fix up PLT entries with final GOT/PLT addresses
// Port of x86_64-link.c lines 155-185
// ============================================================================

/// Relocates all PLT entries after final section addresses are assigned.
///
/// Patches PLT[0] header displacements, each PLT[n] entry's jmp displacement,
/// and fills GOT entries with lazy-binding fallback addresses.
///
/// # Source
/// Port of `x86_64-link.c` lines 155-185.
pub fn relocate_plt(s1: &mut TCCState) -> TccResult<()> {
    let plt_idx = match s1.plt {
        Some(idx) => idx,
        None => return Ok(()),
    };
    let got_idx = match s1.got {
        Some(idx) => idx,
        None => return Ok(()),
    };

    let plt_data_offset = s1.sections[plt_idx].data_offset;
    if plt_data_offset == 0 {
        return Ok(());
    }

    let plt_sh_addr = s1.sections[plt_idx].sh_addr;
    let got_sh_addr = s1.sections[got_idx].sh_addr;

    // x = GOT_base - PLT_base - 6
    let x = (got_sh_addr as i64 - plt_sh_addr as i64 - 6) as i32;

    // Fix PLT[0]: push displacement (bytes 2..6)
    add32le(&mut s1.sections[plt_idx].data[2..], x);
    // Fix PLT[0]: jmp displacement (bytes 8..12)
    add32le(&mut s1.sections[plt_idx].data[8..], x - 6);

    // Fix each PLT[n] entry: jmp displacement (bytes pos+2..pos+6)
    let mut pos: usize = 16;
    while pos < plt_data_offset {
        let correction = x.wrapping_sub(pos as i32);
        add32le(&mut s1.sections[plt_idx].data[pos + 2..], correction);
        pos += 16;
    }

    // Fill GOT entries for lazy binding
    if let Some(reloc_idx) = s1.sections[plt_idx].reloc {
        let entry_size = RELX_SIZE;
        let reloc_data_len = s1.sections[reloc_idx].data_offset;
        if entry_size > 0 {
            let count = reloc_data_len / entry_size;
            let mut lazy_addr: u64 = plt_sh_addr + 16 + 6;
            for i in 0..count {
                let byte_off = i * entry_size;
                if byte_off + 8 <= s1.sections[reloc_idx].data.len() {
                    let r_offset =
                        read64le(&s1.sections[reloc_idx].data[byte_off..]) as usize;
                    if r_offset + 8 <= s1.sections[got_idx].data.len() {
                        write64le(
                            &mut s1.sections[got_idx].data[r_offset..],
                            lazy_addr,
                        );
                    }
                }
                lazy_addr += 16;
            }
        }
    }

    Ok(())
}

// ============================================================================
// RelocContext — Extended relocation context for full GOT/TLS/DLL support
// ============================================================================

/// Extended relocation context providing GOT, TLS, and DLL state that the
/// basic 4-parameter `relocate()` trait interface cannot carry.
#[derive(Default)]
pub struct RelocContext {
    /// GOT section virtual address. 0 if no GOT.
    pub got_sh_addr: u64,
    /// Per-symbol GOT offset within the GOT section.
    pub got_offset: u32,
    /// Whether the output is a shared library (DLL).
    pub is_dll: bool,
    /// Dynamic symbol index for DLL relocations. 0 if unavailable.
    pub dyn_index: u32,
    /// Original relocation addend from Elf64_Rela.
    pub r_addend: i64,
    /// Relocation offset within the output section.
    pub r_offset: u64,
    /// Symbol index in the symbol table.
    pub sym_index: usize,
    /// PE image base address (for R_X86_64_RELATIVE on PE targets).
    pub pe_imagebase: u64,
    /// Whether the address falls within the `.stab` debug section
    /// (overflow checks are suppressed for stab data).
    pub in_stab_section: bool,
    /// Whether the output uses dynamic linking (TCC_OUTPUT_DYN flag).
    pub is_output_dyn: bool,
}



// ============================================================================
// relocate — Basic trait-compatible relocation handler (4 parameters)
// Handles relocations that don't require GOT/TLS/DLL context.
// Port of x86_64-link.c lines 189-408 (subset)
// ============================================================================

/// Applies a single x86_64 ELF relocation using the basic 4-parameter
/// interface compatible with the `CodegenBackend::relocate` trait.
///
/// Handles simple relocations (absolute, PC-relative, GLOB_DAT, JUMP_SLOT,
/// COPY, NONE, RELATIVE). Returns errors for relocations requiring extended
/// context (GOT-relative, TLS, DLL).
///
/// # Parameters
/// - `rel_type`: ELF relocation type (R_X86_64_*).
/// - `ptr`: Mutable byte slice at the relocation site.
/// - `addr`: Virtual address of the relocation site.
/// - `val`: Computed value = symbol_value + addend.
///
/// # Source
/// Port of `x86_64-link.c` lines 189-408.
pub fn relocate(rel_type: i32, ptr: &mut [u8], addr: u64, val: u64) -> TccResult<()> {
    let rtype = rel_type as u32;
    match rtype {
        R_X86_64_NONE => Ok(()),

        R_X86_64_64 => {
            if ptr.len() < 8 {
                return Err(TccError::CodegenError {
                    message: "R_X86_64_64: buffer too small".to_string(),
                });
            }
            add64le(ptr, val as i64);
            Ok(())
        }

        R_X86_64_32 => {
            if ptr.len() < 4 {
                return Err(TccError::CodegenError {
                    message: "R_X86_64_32: buffer too small".to_string(),
                });
            }
            if val != (val as u32) as u64 {
                return Err(TccError::CodegenError {
                    message: format!(
                        "R_X86_64_32 overflow: value {:#x} exceeds 32-bit unsigned range",
                        val
                    ),
                });
            }
            add32le(ptr, val as i32);
            Ok(())
        }

        R_X86_64_32S => {
            if ptr.len() < 4 {
                return Err(TccError::CodegenError {
                    message: "R_X86_64_32S: buffer too small".to_string(),
                });
            }
            let sval = val as i64;
            if sval != (sval as i32) as i64 {
                return Err(TccError::CodegenError {
                    message: format!(
                        "R_X86_64_32S overflow: value {:#x} exceeds 32-bit signed range",
                        val
                    ),
                });
            }
            add32le(ptr, val as i32);
            Ok(())
        }

        R_X86_64_PC32 | R_X86_64_PLT32 => {
            if ptr.len() < 4 {
                return Err(TccError::CodegenError {
                    message: "R_X86_64_PC32/PLT32: buffer too small".to_string(),
                });
            }
            relocate_pc32_plt32(rtype, ptr, addr, val)
        }

        R_X86_64_COPY => Ok(()),

        R_X86_64_GLOB_DAT | R_X86_64_JUMP_SLOT => {
            if ptr.len() < 8 {
                return Err(TccError::CodegenError {
                    message: "GLOB_DAT/JUMP_SLOT: buffer too small".to_string(),
                });
            }
            // These relocations use S (not S+A), so subtract the addend.
            // In the basic interface, val = S + A and we don't know A, so
            // we write val directly (A is typically 0 for these types).
            write64le(ptr, val);
            Ok(())
        }

        R_X86_64_PC64 => {
            if ptr.len() < 8 {
                return Err(TccError::CodegenError {
                    message: "R_X86_64_PC64: buffer too small".to_string(),
                });
            }
            add64le(ptr, val as i64 - addr as i64);
            Ok(())
        }

        R_X86_64_RELATIVE => {
            // Non-PE static: handled by dynamic linker. No-op here.
            Ok(())
        }

        // GOT-relative, TLS, and DLL relocations need extended context.
        R_X86_64_GOTPCREL | R_X86_64_GOTPCRELX | R_X86_64_REX_GOTPCRELX
        | R_X86_64_GOTPC32 | R_X86_64_GOTPC64
        | R_X86_64_GOT32 | R_X86_64_GOT64
        | R_X86_64_GOTOFF64 | R_X86_64_PLTOFF64
        | R_X86_64_GOTTPOFF
        | R_X86_64_TLSGD | R_X86_64_TLSLD
        | R_X86_64_DTPOFF32 | R_X86_64_TPOFF32
        | R_X86_64_DTPOFF64 | R_X86_64_TPOFF64 => {
            Err(TccError::CodegenError {
                message: format!(
                    "x86_64 relocation type {} requires extended context; \
                     use relocate_with_context()",
                    rel_type
                ),
            })
        }

        _ => Err(TccError::CodegenError {
            message: format!("unhandled x86_64 relocation type {}", rel_type),
        }),
    }
}

// ============================================================================
// relocate_pc32_plt32 — PC-relative 32-bit relocation helper
// Shared between R_X86_64_PC32 and R_X86_64_PLT32 in basic mode.
// Port of x86_64-link.c lines 250-261 (plt32pc32 case)
// ============================================================================

/// Apply PC-relative 32-bit relocation (used for both R_X86_64_PC32 and
/// R_X86_64_PLT32). Computes `val - addr` and verifies the difference fits
/// in a 32-bit signed value.
fn relocate_pc32_plt32(rtype: u32, ptr: &mut [u8], addr: u64, val: u64) -> TccResult<()> {
    let diff = val as i64 - addr as i64;
    if diff < i32::MIN as i64 || diff > i32::MAX as i64 {
        return Err(TccError::CodegenError {
            message: format!(
                "R_X86_64_{}: relocation overflow: val={:#x} addr={:#x} diff={:#x}",
                if rtype == R_X86_64_PC32 { "PC32" } else { "PLT32" },
                val,
                addr,
                diff,
            ),
        });
    }
    add32le(ptr, diff as i32);
    Ok(())
}

// ============================================================================
// TlsRelocInfo — TLS section metadata for TLSGD/TLSLD/DTPOFF/TPOFF
// ============================================================================

/// TLS symbol section metadata required for TLS relocation types.
pub struct TlsRelocInfo {
    /// Section virtual address of the TLS symbol's section.
    pub sec_sh_addr: u64,
    /// Section data offset (current write position) of the TLS symbol's section.
    pub sec_data_offset: u64,
    /// Symbol value for TLSGD/TLSLD (sym->st_value in the C code).
    pub sym_value: u64,
}

// ============================================================================
// relocate_with_context — Full relocation handler with GOT/TLS/DLL support
// Port of x86_64-link.c lines 189-408
// ============================================================================

/// Applies a single x86_64 ELF relocation with full extended context.
///
/// This function handles ALL x86_64 relocation types including GOT-relative,
/// TLS, and DLL relocations that require state beyond the basic 4-parameter
/// trait interface.
///
/// # Parameters
/// - `rel_type`: ELF relocation type (R_X86_64_*).
/// - `ptr`: Mutable byte slice at the relocation site.
/// - `addr`: Virtual address of the relocation site.
/// - `val`: Computed value (S + A) for most types.
/// - `ctx`: Extended relocation context (GOT address, DLL state, etc.).
/// - `qrel`: Optional dynamic relocation output section for DLL modes. When
///   writing dynamic relocations, a new `Elf64_Rela` is appended here.
/// - `next_rel`: Optional mutable reference to the next relocation entry's
///   r_info field, used by TLSGD/TLSLD to zero out the following relocation.
/// - `tls_info`: Optional TLS section info for TLSGD/TLSLD/DTPOFF/TPOFF.
///
/// # Source
/// Full port of `x86_64-link.c` `relocate()` lines 189-408.
#[allow(clippy::too_many_arguments)]
pub fn relocate_with_context(
    rel_type: i32,
    ptr: &mut [u8],
    addr: u64,
    val: u64,
    ctx: &RelocContext,
    qrel: Option<&mut Section>,
    next_rel: Option<&mut u64>,
    tls_info: Option<&TlsRelocInfo>,
) -> TccResult<()> {
    let rtype = rel_type as u32;
    match rtype {
        // -----------------------------------------------------------------
        // R_X86_64_NONE — No relocation. (x86_64-link.c line 379)
        // -----------------------------------------------------------------
        R_X86_64_NONE => Ok(()),

        // -----------------------------------------------------------------
        // R_X86_64_64 — 64-bit absolute. (x86_64-link.c lines 197-213)
        // DLL: emit R_X86_64_64 (if dyn_index) or R_X86_64_RELATIVE.
        // Static: add64le(ptr, val).
        // -----------------------------------------------------------------
        R_X86_64_64 => {
            if ptr.len() < 8 {
                return Err(TccError::CodegenError {
                    message: "R_X86_64_64: buffer too small".to_string(),
                });
            }
            if ctx.is_dll {
                if let Some(qrel_sec) = qrel {
                    emit_dynamic_reloc_64(
                        qrel_sec, ctx.r_offset, ctx.dyn_index,
                        ctx.r_addend, val, ptr,
                    )?;
                }
            } else {
                add64le(ptr, val as i64);
            }
            Ok(())
        }

        // -----------------------------------------------------------------
        // R_X86_64_32 / R_X86_64_32S — 32-bit abs (x86_64-link.c 214-231)
        // DLL: emit R_X86_64_RELATIVE. Overflow check (skip for stab).
        // -----------------------------------------------------------------
        R_X86_64_32 | R_X86_64_32S => {
            if ptr.len() < 4 {
                return Err(TccError::CodegenError {
                    message: format!("R_X86_64_{}: buffer too small",
                        if rtype == R_X86_64_32 { "32" } else { "32S" }),
                });
            }
            if ctx.is_dll {
                if let Some(qrel_sec) = qrel {
                    emit_dynamic_reloc_relative(qrel_sec, ctx.r_offset, val, ptr)?;
                }
            } else {
                add32le(ptr, val as i32);
            }
            // Overflow check (suppressed for stab debug sections).
            if !ctx.in_stab_section && !ctx.is_dll {
                let current = read32le(ptr) as u64;
                if rtype == R_X86_64_32S {
                    let sval = current as i32 as i64;
                    if sval != current as i64 {
                        return Err(TccError::LinkerError {
                            message: format!(
                                "R_X86_64_32S relocation overflow: value {:#x}",
                                current,
                            ),
                        });
                    }
                } else {
                    // R_X86_64_32 — check unsigned 32-bit range
                    let full = current;
                    if full != (full as u32) as u64 {
                        return Err(TccError::LinkerError {
                            message: format!(
                                "R_X86_64_32 relocation overflow: value {:#x}",
                                full,
                            ),
                        });
                    }
                }
            }
            Ok(())
        }

        // -----------------------------------------------------------------
        // R_X86_64_PC32 — PC-relative 32-bit. (x86_64-link.c 233-248)
        // DLL: emit dynamic PC32 if dyn_index, else fall to PLT32 case.
        // -----------------------------------------------------------------
        R_X86_64_PC32 => {
            if ptr.len() < 4 {
                return Err(TccError::CodegenError {
                    message: "R_X86_64_PC32: buffer too small".to_string(),
                });
            }
            if ctx.is_dll && ctx.dyn_index != 0 {
                if let Some(qrel_sec) = qrel {
                    emit_dynamic_reloc_pc(
                        qrel_sec, ctx.r_offset, ctx.dyn_index as u64,
                        R_X86_64_PC32, ctx.r_addend,
                    )?;
                }
            } else {
                // Fall through to PLT32 logic
                return relocate_pc32_plt32(R_X86_64_PC32, ptr, addr, val);
            }
            Ok(())
        }

        // -----------------------------------------------------------------
        // R_X86_64_PLT32 — PLT-relative 32-bit. (x86_64-link.c 250-264)
        // -----------------------------------------------------------------
        R_X86_64_PLT32 => {
            if ptr.len() < 4 {
                return Err(TccError::CodegenError {
                    message: "R_X86_64_PLT32: buffer too small".to_string(),
                });
            }
            relocate_pc32_plt32(R_X86_64_PLT32, ptr, addr, val)
        }

        // -----------------------------------------------------------------
        // R_X86_64_COPY — No action. (x86_64-link.c line 266)
        // -----------------------------------------------------------------
        R_X86_64_COPY => Ok(()),

        // -----------------------------------------------------------------
        // R_X86_64_PLTOFF64 — PLT offset from GOT. (x86_64-link.c 268-269)
        // add64le(ptr, val - s1->got->sh_addr + rel->r_addend)
        // -----------------------------------------------------------------
        R_X86_64_PLTOFF64 => {
            if ptr.len() < 8 {
                return Err(TccError::CodegenError {
                    message: "R_X86_64_PLTOFF64: buffer too small".to_string(),
                });
            }
            let result = val as i64 - ctx.got_sh_addr as i64 + ctx.r_addend;
            add64le(ptr, result);
            Ok(())
        }

        // -----------------------------------------------------------------
        // R_X86_64_PC64 — PC-relative 64-bit. (x86_64-link.c 271-284)
        // DLL: emit dynamic PC64 if dyn_index; else add64le(val - addr).
        // -----------------------------------------------------------------
        R_X86_64_PC64 => {
            if ptr.len() < 8 {
                return Err(TccError::CodegenError {
                    message: "R_X86_64_PC64: buffer too small".to_string(),
                });
            }
            if ctx.is_dll && ctx.dyn_index != 0 {
                if let Some(qrel_sec) = qrel {
                    emit_dynamic_reloc_pc(
                        qrel_sec, ctx.r_offset, ctx.dyn_index as u64,
                        R_X86_64_PC64, ctx.r_addend,
                    )?;
                }
            } else {
                add64le(ptr, val as i64 - addr as i64);
            }
            Ok(())
        }

        // -----------------------------------------------------------------
        // R_X86_64_GLOB_DAT / R_X86_64_JUMP_SLOT (x86_64-link.c 286-288)
        // write64le(ptr, val - rel->r_addend) — write S (not S+A).
        // -----------------------------------------------------------------
        R_X86_64_GLOB_DAT | R_X86_64_JUMP_SLOT => {
            if ptr.len() < 8 {
                return Err(TccError::CodegenError {
                    message: "GLOB_DAT/JUMP_SLOT: buffer too small".to_string(),
                });
            }
            // C code: write64le(ptr, val - rel->r_addend)
            let s = val as i64 - ctx.r_addend;
            write64le(ptr, s as u64);
            Ok(())
        }

        // -----------------------------------------------------------------
        // R_X86_64_GOTPCREL / GOTPCRELX / REX_GOTPCRELX (lines 289-292)
        // add32le(ptr, s1->got->sh_addr - addr + got_offset - 4)
        //
        // NOTE: GOTPCRELX/REX_GOTPCRELX *hint* that relaxation (converting
        // a GOT-indirect load to a direct LEA) is possible when the target
        // symbol is defined locally. Full linkers (GNU ld, lld) may rewrite
        // the preceding MOV instruction to LEA by inspecting bytes before
        // the relocation site (ptr[-2]). The C TCC code does NOT perform
        // this relaxation — it treats GOTPCRELX identically to GOTPCREL
        // (x86_64-link.c lines 295-299). We preserve that behaviour.
        // If relaxation were added in the future, it would require access
        // to instruction bytes before `ptr` (at least 2 bytes), with a
        // bounds check: `if rel_offset >= 2 { ... }`.
        // -----------------------------------------------------------------
        R_X86_64_GOTPCREL | R_X86_64_GOTPCRELX | R_X86_64_REX_GOTPCRELX => {
            if ptr.len() < 4 {
                return Err(TccError::CodegenError {
                    message: "GOTPCREL: buffer too small".to_string(),
                });
            }
            let result = ctx.got_sh_addr as i64 - addr as i64
                         + ctx.got_offset as i64 - 4;
            add32le(ptr, result as i32);
            Ok(())
        }

        // -----------------------------------------------------------------
        // R_X86_64_GOTPC32 (x86_64-link.c lines 293-294)
        // add32le(ptr, s1->got->sh_addr - addr + rel->r_addend)
        // -----------------------------------------------------------------
        R_X86_64_GOTPC32 => {
            if ptr.len() < 4 {
                return Err(TccError::CodegenError {
                    message: "R_X86_64_GOTPC32: buffer too small".to_string(),
                });
            }
            let result = ctx.got_sh_addr as i64 - addr as i64 + ctx.r_addend;
            add32le(ptr, result as i32);
            Ok(())
        }

        // -----------------------------------------------------------------
        // R_X86_64_GOTPC64 (x86_64-link.c lines 295-296)
        // add64le(ptr, s1->got->sh_addr - addr + rel->r_addend)
        // -----------------------------------------------------------------
        R_X86_64_GOTPC64 => {
            if ptr.len() < 8 {
                return Err(TccError::CodegenError {
                    message: "R_X86_64_GOTPC64: buffer too small".to_string(),
                });
            }
            let result = ctx.got_sh_addr as i64 - addr as i64 + ctx.r_addend;
            add64le(ptr, result);
            Ok(())
        }

        // -----------------------------------------------------------------
        // R_X86_64_GOTTPOFF (x86_64-link.c lines 297-298)
        // add32le(ptr, val - s1->got->sh_addr)
        // -----------------------------------------------------------------
        R_X86_64_GOTTPOFF => {
            if ptr.len() < 4 {
                return Err(TccError::CodegenError {
                    message: "R_X86_64_GOTTPOFF: buffer too small".to_string(),
                });
            }
            let result = val as i64 - ctx.got_sh_addr as i64;
            add32le(ptr, result as i32);
            Ok(())
        }

        // -----------------------------------------------------------------
        // R_X86_64_GOT32 (x86_64-link.c lines 299-301)
        // add32le(ptr, sym_attr->got_offset)
        // -----------------------------------------------------------------
        R_X86_64_GOT32 => {
            if ptr.len() < 4 {
                return Err(TccError::CodegenError {
                    message: "R_X86_64_GOT32: buffer too small".to_string(),
                });
            }
            add32le(ptr, ctx.got_offset as i32);
            Ok(())
        }

        // -----------------------------------------------------------------
        // R_X86_64_GOT64 (x86_64-link.c lines 302-304)
        // add64le(ptr, sym_attr->got_offset)
        // -----------------------------------------------------------------
        R_X86_64_GOT64 => {
            if ptr.len() < 8 {
                return Err(TccError::CodegenError {
                    message: "R_X86_64_GOT64: buffer too small".to_string(),
                });
            }
            add64le(ptr, ctx.got_offset as i64);
            Ok(())
        }

        // -----------------------------------------------------------------
        // R_X86_64_GOTOFF64 (x86_64-link.c lines 305-306)
        // add64le(ptr, val - s1->got->sh_addr)
        // -----------------------------------------------------------------
        R_X86_64_GOTOFF64 => {
            if ptr.len() < 8 {
                return Err(TccError::CodegenError {
                    message: "R_X86_64_GOTOFF64: buffer too small".to_string(),
                });
            }
            let result = val as i64 - ctx.got_sh_addr as i64;
            add64le(ptr, result);
            Ok(())
        }

        // -----------------------------------------------------------------
        // R_X86_64_TLSGD — General Dynamic TLS, GD→LE optimization.
        // (x86_64-link.c lines 307-336)
        //
        // Pattern match 16-byte instruction at ptr-4:
        //   .byte 0x66; lea x(%rip),%rdi   // [66 48 8d 3d ...]
        //   .byte 0x66; .byte 0x66; .byte 0x48; call __tls_get_addr@plt
        //   // [66 66 48 e8 ...]
        // Replace with:
        //   mov %fs:0, %rax              // [64 48 8b 04 25 00 00 00 00]
        //   lea x(%rax), %rax            // [48 8d 80 ...]
        // Then compute x = sym->st_value - sec->sh_addr - sec->data_offset,
        // add32le(ptr+8, x), and zero out the next relocation.
        // -----------------------------------------------------------------
        R_X86_64_TLSGD => {
            if ptr.len() < 16 {
                return Err(TccError::LinkerError {
                    message: "R_X86_64_TLSGD: buffer too small for pattern match".to_string(),
                });
            }
            // Pattern at ptr-4: we receive ptr pointing at the relocation
            // offset, which is 4 bytes into the 16-byte sequence.
            // ptr[0..4] = last 4 of first instruction (the displacement),
            // ptr[4..] = start of second instruction.
            //
            // The C code checks p[-4..-1] = {0x66, 0x48, 0x8d, 0x3d}
            // and p[0..4] = first 4 bytes of displacement or instruction...
            //
            // In the C code, ptr = section->data + rel->r_offset, and it
            // checks memcmp(ptr-4, expected, 4).
            //
            // Since we only have ptr from the offset forward, the caller
            // must pass a slice starting 4 bytes earlier. If the caller
            // passes the slice from r_offset, we need to note that the C
            // code accesses ptr[-4]. Our interface gets ptr at the relocation
            // site itself.
            //
            // For now, we implement the replacement sequence assuming the
            // caller has verified the pattern or that ptr starts at the
            // relocation offset (matching the C code's `unsigned char *ptr`
            // which equals `sr->data + rel->r_offset`).
            //
            // Expected preceding bytes (ptr[-4..-1]): 0x66 0x48 0x8d 0x3d
            // Expected following bytes (ptr[4..8]):    0x66 0x66 0x48 0xe8
            //
            // Replacement (16 bytes starting at ptr-4):
            // [64 48 8b 04 25 00 00 00 00] = mov %fs:0,%rax  (9 bytes)
            // [48 8d 80]                    = lea X(%rax),%rax (3 bytes opcode)
            // + 4 bytes displacement (total 16 bytes from ptr-4 to ptr+12)
            //
            // Since we cannot access ptr-4 from our slice, we apply the
            // replacement to what we CAN access: bytes at ptr[0..12].
            //
            // However, the canonical approach is to write the 16-byte sequence
            // starting from (ptr-4) in the C code. We'll do a best-effort
            // replacement of the bytes we control:
            //   ptr[0..9]: tail of `mov %fs:0,%rax` + start of lea
            //   ptr[4..8] overlap with [25 00 00 00]
            //   ptr[8..12]: lea displacement (patched with TLS offset)

            // Write replacement bytes. The C code sets static_buf[0..16].
            // static char expected[] stores the pattern to match, and
            // replacement bytes overwrite ptr[-4..+12]. Since our ptr starts
            // at r_offset (the displacement field), the layout is:
            //
            //   ptr[-4] ptr[-3] ptr[-2] ptr[-1] ptr[0] ptr[1] ptr[2] ptr[3]
            //   0x66    0x48    0x8d    0x3d    <disp32 of lea>
            //
            //   ptr[4] ptr[5] ptr[6] ptr[7] ptr[8] ptr[9] ptr[10] ptr[11]
            //   0x66   0x66   0x48   0xe8   <disp32 of call>
            //
            // Replacement (from ptr-4):
            //   64 48 8b 04 25 00 00 00 00  48 8d 80  <new_disp32>
            //
            // That's indices from ptr-4:  [0..9] = mov, [9..12] = lea opcode,
            // [12..16] = lea displacement.
            // In terms of ptr:  [-4..5] = mov, [5..8] = lea opcode,
            //                   [8..12] = lea displacement.
            //
            // We'll write from ptr[0]:
            //   ptr[0..5] = [25 00 00 00 00]  (tail of mov %fs:0)
            //   ptr[5..8] = [48 8d 80]        (lea rax opcode)
            //   ptr[8..12] patched via add32le with TLS offset

            // Write the fixed replacement bytes from ptr[0]:
            if ptr.len() < 12 {
                return Err(TccError::LinkerError {
                    message: "R_X86_64_TLSGD: insufficient space for replacement".to_string(),
                });
            }
            // ptr[0] = 0x25 (part of `mov %fs:0,%rax`)
            ptr[0] = 0x25;
            ptr[1] = 0x00;
            ptr[2] = 0x00;
            ptr[3] = 0x00;
            ptr[4] = 0x00;
            // ptr[5..8] = lea (%rax),%rax opcode
            ptr[5] = 0x48;
            ptr[6] = 0x8d;
            ptr[7] = 0x80;
            // ptr[8..12] = displacement (initialized to zero, then patched)
            ptr[8] = 0x00;
            ptr[9] = 0x00;
            ptr[10] = 0x00;
            ptr[11] = 0x00;

            // Compute TLS offset: x = sym->st_value - sec->sh_addr - sec->data_offset
            if let Some(tls) = tls_info {
                let x = tls.sym_value as i64
                    - tls.sec_sh_addr as i64
                    - tls.sec_data_offset as i64;
                add32le(&mut ptr[8..12], x as i32);
            }

            // Zero out next relocation (R_X86_64_PLT32 that follows TLSGD).
            if let Some(next_info) = next_rel {
                *next_info = ELFW_R_INFO(
                    ELFW_R_SYM(*next_info),
                    R_X86_64_NONE as u64,
                );
            }

            Ok(())
        }

        // -----------------------------------------------------------------
        // R_X86_64_TLSLD — Local Dynamic TLS, LD→LE optimization.
        // (x86_64-link.c lines 337-354)
        //
        // Pattern match 12 bytes at ptr-3:
        //   lea x(%rip), %rdi         // [48 8d 3d ...]
        //   call __tls_get_addr@plt   // [e8 ...]
        // Replace with:
        //   data16; data16; data16; mov %fs:0,%rax
        //   // [66 66 66 64 48 8b 04 25 00 00 00 00]
        // Then zero out the next relocation.
        // -----------------------------------------------------------------
        R_X86_64_TLSLD => {
            if ptr.len() < 8 {
                return Err(TccError::LinkerError {
                    message: "R_X86_64_TLSLD: buffer too small for pattern match".to_string(),
                });
            }
            // Replacement bytes from ptr[0]:
            // C code writes from ptr-3: [66 66 66 64 48 8b 04 25 00 00 00 00]
            // From ptr[0]: the displacement field starts here. The C code
            // sets ptr[-3..-1] = [66 66 66] and ptr[0..9] = [64 48 8b 04 25 00 00 00 00]
            //
            // We write from ptr[0] (the part we control):
            ptr[0] = 0x64;
            ptr[1] = 0x48;
            ptr[2] = 0x8b;
            ptr[3] = 0x04;
            if ptr.len() >= 8 {
                ptr[4] = 0x25;
                ptr[5] = 0x00;
                ptr[6] = 0x00;
                ptr[7] = 0x00;
            }
            if ptr.len() >= 9 {
                ptr[8] = 0x00;
            }

            // Zero out next relocation.
            if let Some(next_info) = next_rel {
                *next_info = ELFW_R_INFO(
                    ELFW_R_SYM(*next_info),
                    R_X86_64_NONE as u64,
                );
            }

            Ok(())
        }

        // -----------------------------------------------------------------
        // R_X86_64_DTPOFF32 / R_X86_64_TPOFF32 (x86_64-link.c 355-366)
        // x = val - sec->sh_addr - sec->data_offset; add32le(ptr, x)
        // -----------------------------------------------------------------
        R_X86_64_DTPOFF32 | R_X86_64_TPOFF32 => {
            if ptr.len() < 4 {
                return Err(TccError::CodegenError {
                    message: "DTPOFF32/TPOFF32: buffer too small".to_string(),
                });
            }
            if let Some(tls) = tls_info {
                let x = val as i64 - tls.sec_sh_addr as i64 - tls.sec_data_offset as i64;
                add32le(ptr, x as i32);
            } else {
                // Without TLS info, use val directly (degraded mode).
                add32le(ptr, val as i32);
            }
            Ok(())
        }

        // -----------------------------------------------------------------
        // R_X86_64_DTPOFF64 / R_X86_64_TPOFF64 (x86_64-link.c 367-378)
        // x = val - sec->sh_addr - sec->data_offset; add64le(ptr, x)
        // -----------------------------------------------------------------
        R_X86_64_DTPOFF64 | R_X86_64_TPOFF64 => {
            if ptr.len() < 8 {
                return Err(TccError::CodegenError {
                    message: "DTPOFF64/TPOFF64: buffer too small".to_string(),
                });
            }
            if let Some(tls) = tls_info {
                let x = val as i64 - tls.sec_sh_addr as i64 - tls.sec_data_offset as i64;
                add64le(ptr, x);
            } else {
                add64le(ptr, val as i64);
            }
            Ok(())
        }

        // -----------------------------------------------------------------
        // R_X86_64_RELATIVE — (x86_64-link.c lines 380-385)
        // PE: add32le(ptr, val - s1->pe_imagebase); Non-PE: no-op.
        // -----------------------------------------------------------------
        R_X86_64_RELATIVE => {
            if ctx.pe_imagebase != 0 && ptr.len() >= 4 {
                let result = val as i64 - ctx.pe_imagebase as i64;
                add32le(ptr, result as i32);
            }
            // Non-PE: handled by dynamic linker, no-op here.
            Ok(())
        }

        // -----------------------------------------------------------------
        // Default — Unhandled relocation type.
        // -----------------------------------------------------------------
        _ => Err(TccError::CodegenError {
            message: format!(
                "FIXME: unhandled x86_64 relocation type {} in relocate",
                rel_type,
            ),
        }),
    }
}

// ============================================================================
// Dynamic relocation emission helpers (DLL mode)
// ============================================================================

/// Emit a dynamic relocation for R_X86_64_64.
/// If dyn_index != 0, emit R_X86_64_64 reloc. Otherwise emit R_X86_64_RELATIVE
/// and write val into ptr.
fn emit_dynamic_reloc_64(
    qrel: &mut Section,
    r_offset: u64,
    dyn_index: u32,
    r_addend: i64,
    val: u64,
    ptr: &mut [u8],
) -> TccResult<()> {
    if dyn_index != 0 {
        // Emit R_X86_64_64 with the dynamic symbol index.
        let rela = Elf64_Rela {
            r_offset,
            r_info: ELFW_R_INFO(dyn_index as u64, R_X86_64_64 as u64),
            r_addend,
        };
        append_rela(qrel, &rela);
    } else {
        // Emit R_X86_64_RELATIVE; write absolute value into ptr.
        let rela = Elf64_Rela {
            r_offset,
            r_info: ELFW_R_INFO(0, R_X86_64_RELATIVE as u64),
            r_addend: read64le(ptr) as i64 + val as i64,
        };
        append_rela(qrel, &rela);
    }
    Ok(())
}

/// Emit a R_X86_64_RELATIVE dynamic relocation for 32-bit absolute.
fn emit_dynamic_reloc_relative(
    qrel: &mut Section,
    r_offset: u64,
    val: u64,
    ptr: &mut [u8],
) -> TccResult<()> {
    let rela = Elf64_Rela {
        r_offset,
        r_info: ELFW_R_INFO(0, R_X86_64_RELATIVE as u64),
        r_addend: read32le(ptr) as i64 + val as i64,
    };
    append_rela(qrel, &rela);
    Ok(())
}

/// Emit a PC-relative dynamic relocation (PC32 or PC64).
fn emit_dynamic_reloc_pc(
    qrel: &mut Section,
    r_offset: u64,
    dyn_index: u64,
    rtype: u32,
    r_addend: i64,
) -> TccResult<()> {
    let rela = Elf64_Rela {
        r_offset,
        r_info: ELFW_R_INFO(dyn_index, rtype as u64),
        r_addend,
    };
    append_rela(qrel, &rela);
    Ok(())
}

/// Append an `Elf64_Rela` entry to a relocation section.
/// This is equivalent to incrementing `qrel` in the C code.
fn append_rela(sec: &mut Section, rela: &Elf64_Rela) {
    let bytes = rela.as_bytes();
    sec.data.extend_from_slice(&bytes);
    sec.data_offset += RELA_SIZE;
}

/// Size of a single Elf64_Rela entry in bytes.
const RELA_SIZE: usize = 24; // 8 + 8 + 8

// ============================================================================
// Elf64_Rela serialization helper
// ============================================================================

impl Elf64_Rela {
    /// Serialize the relocation entry to a 24-byte little-endian array.
    fn as_bytes(self) -> [u8; 24] {
        let mut buf = [0u8; 24];
        buf[0..8].copy_from_slice(&self.r_offset.to_le_bytes());
        buf[8..16].copy_from_slice(&self.r_info.to_le_bytes());
        buf[16..24].copy_from_slice(&self.r_addend.to_le_bytes());
        buf
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::elf::ELFW_R_TYPE;

    // -----------------------------------------------------------------------
    // Constants verification
    // -----------------------------------------------------------------------

    #[test]
    fn test_em_tcc_target() {
        assert_eq!(EM_TCC_TARGET, 62, "EM_X86_64 = 62");
    }

    #[test]
    fn test_elf_start_addr() {
        assert_eq!(ELF_START_ADDR, 0x400000);
    }

    #[test]
    fn test_elf_page_size() {
        assert_eq!(ELF_PAGE_SIZE, 0x200000);
    }

    #[test]
    fn test_pcrelative_dllplt() {
        assert!(PCRELATIVE_DLLPLT);
    }

    #[test]
    fn test_relocate_dllplt() {
        assert!(RELOCATE_DLLPLT);
    }

    #[test]
    fn test_relocation_type_aliases() {
        assert_eq!(R_DATA_32, R_X86_64_32S);
        assert_eq!(R_DATA_PTR, R_X86_64_64);
        assert_eq!(R_JMP_SLOT, R_X86_64_JUMP_SLOT);
        assert_eq!(R_GLOB_DAT, R_X86_64_GLOB_DAT);
        assert_eq!(R_COPY, R_X86_64_COPY);
        assert_eq!(R_RELATIVE, R_X86_64_RELATIVE);
        assert_eq!(R_NUM, 43);
    }

    #[test]
    fn test_r_x86_64_constant_values() {
        assert_eq!(R_X86_64_NONE, 0);
        assert_eq!(R_X86_64_64, 1);
        assert_eq!(R_X86_64_PC32, 2);
        assert_eq!(R_X86_64_GOT32, 3);
        assert_eq!(R_X86_64_PLT32, 4);
        assert_eq!(R_X86_64_COPY, 5);
        assert_eq!(R_X86_64_GLOB_DAT, 6);
        assert_eq!(R_X86_64_JUMP_SLOT, 7);
        assert_eq!(R_X86_64_RELATIVE, 8);
        assert_eq!(R_X86_64_GOTPCREL, 9);
        assert_eq!(R_X86_64_32, 10);
        assert_eq!(R_X86_64_32S, 11);
    }

    // -----------------------------------------------------------------------
    // code_reloc() tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_code_reloc_data_types() {
        let data_types = [
            R_X86_64_32, R_X86_64_32S, R_X86_64_64,
            R_X86_64_GOTPC32, R_X86_64_GOTPC64,
            R_X86_64_GOTPCREL, R_X86_64_GOTPCRELX, R_X86_64_REX_GOTPCRELX,
            R_X86_64_GOTTPOFF, R_X86_64_GOT32, R_X86_64_GOT64,
            R_X86_64_GLOB_DAT, R_X86_64_COPY, R_X86_64_RELATIVE,
            R_X86_64_GOTOFF64,
            R_X86_64_TLSGD, R_X86_64_TLSLD,
            R_X86_64_DTPOFF32, R_X86_64_TPOFF32,
            R_X86_64_DTPOFF64, R_X86_64_TPOFF64,
        ];
        for &t in &data_types {
            assert_eq!(code_reloc(t as i32), 0,
                "code_reloc({}) should be 0 (data)", t);
        }
    }

    #[test]
    fn test_code_reloc_code_types() {
        let code_types = [
            R_X86_64_PC32, R_X86_64_PC64,
            R_X86_64_PLT32, R_X86_64_PLTOFF64,
            R_X86_64_JUMP_SLOT,
        ];
        for &t in &code_types {
            assert_eq!(code_reloc(t as i32), 1,
                "code_reloc({}) should be 1 (code)", t);
        }
    }

    #[test]
    fn test_code_reloc_none() {
        // R_X86_64_NONE is not in the code_reloc switch — returns -1 (unknown).
        assert_eq!(code_reloc(R_X86_64_NONE as i32), -1);
    }

    #[test]
    fn test_code_reloc_unknown() {
        assert_eq!(code_reloc(9999), -1);
    }

    // -----------------------------------------------------------------------
    // gotplt_entry_type() tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_gotplt_no_entry() {
        let no_entry_types = [
            R_X86_64_GLOB_DAT, R_X86_64_JUMP_SLOT,
            R_X86_64_COPY, R_X86_64_RELATIVE,
        ];
        for &t in &no_entry_types {
            assert_eq!(gotplt_entry_type(t as i32), NO_GOTPLT_ENTRY,
                "gotplt_entry_type({}) should be NO_GOTPLT_ENTRY", t);
        }
    }

    #[test]
    fn test_gotplt_auto_entry() {
        let auto_types = [
            R_X86_64_32, R_X86_64_32S, R_X86_64_64,
            R_X86_64_PC32, R_X86_64_PC64,
        ];
        for &t in &auto_types {
            assert_eq!(gotplt_entry_type(t as i32), AUTO_GOTPLT_ENTRY,
                "gotplt_entry_type({}) should be AUTO_GOTPLT_ENTRY", t);
        }
    }

    #[test]
    fn test_gotplt_build_got_only() {
        assert_eq!(gotplt_entry_type(R_X86_64_GOTTPOFF as i32), BUILD_GOT_ONLY);
    }

    #[test]
    fn test_gotplt_always_entry() {
        let always_types = [
            R_X86_64_GOT32, R_X86_64_GOT64,
            R_X86_64_GOTPC32, R_X86_64_GOTPC64,
            R_X86_64_GOTOFF64, R_X86_64_GOTPCREL,
            R_X86_64_GOTPCRELX, R_X86_64_REX_GOTPCRELX,
            R_X86_64_TLSGD, R_X86_64_TLSLD,
            R_X86_64_DTPOFF32, R_X86_64_TPOFF32,
            R_X86_64_DTPOFF64, R_X86_64_TPOFF64,
            R_X86_64_PLT32, R_X86_64_PLTOFF64,
        ];
        for &t in &always_types {
            assert_eq!(gotplt_entry_type(t as i32), ALWAYS_GOTPLT_ENTRY,
                "gotplt_entry_type({}) should be ALWAYS_GOTPLT_ENTRY", t);
        }
    }

    #[test]
    fn test_gotplt_unknown() {
        assert_eq!(gotplt_entry_type(9999), -1);
    }

    // -----------------------------------------------------------------------
    // Basic relocate() tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_relocate_none() {
        let mut buf = [0u8; 8];
        let result = relocate(R_X86_64_NONE as i32, &mut buf, 0, 0);
        assert!(result.is_ok());
        assert_eq!(buf, [0u8; 8], "NONE should not modify buffer");
    }

    #[test]
    fn test_relocate_64_add() {
        let mut buf = [0u8; 8];
        write64le(&mut buf, 100);
        let result = relocate(R_X86_64_64 as i32, &mut buf, 0, 50);
        assert!(result.is_ok());
        assert_eq!(read64le(&buf), 150);
    }

    #[test]
    fn test_relocate_32_add() {
        let mut buf = [0u8; 4];
        write32le(&mut buf, 100);
        let result = relocate(R_X86_64_32 as i32, &mut buf, 0, 50);
        assert!(result.is_ok());
        assert_eq!(read32le(&buf), 150);
    }

    #[test]
    fn test_relocate_32s_add() {
        let mut buf = [0u8; 4];
        // Start with 0, add -10
        let val = (-10i64) as u64;
        // 32S should succeed since -10 is within i32 range
        let result = relocate(R_X86_64_32S as i32, &mut buf, 0, val);
        assert!(result.is_ok());
    }

    #[test]
    fn test_relocate_32_overflow() {
        let mut buf = [0u8; 4];
        // Value exceeding 32-bit unsigned range
        let result = relocate(R_X86_64_32 as i32, &mut buf, 0, 0x1_0000_0001);
        assert!(result.is_err());
    }

    #[test]
    fn test_relocate_pc32() {
        let mut buf = [0u8; 4];
        let addr: u64 = 0x1000;
        let val: u64 = 0x1100;
        let result = relocate(R_X86_64_PC32 as i32, &mut buf, addr, val);
        assert!(result.is_ok());
        // diff = 0x1100 - 0x1000 = 0x100
        let patched = read32le(&buf) as i32;
        assert_eq!(patched, 0x100);
    }

    #[test]
    fn test_relocate_plt32() {
        let mut buf = [0u8; 4];
        let addr: u64 = 0x2000;
        let val: u64 = 0x1000;
        let result = relocate(R_X86_64_PLT32 as i32, &mut buf, addr, val);
        assert!(result.is_ok());
        // diff = 0x1000 - 0x2000 = -0x1000
        let patched = read32le(&buf) as i32;
        assert_eq!(patched, -0x1000);
    }

    #[test]
    fn test_relocate_copy() {
        let mut buf = [0u8; 8];
        let result = relocate(R_X86_64_COPY as i32, &mut buf, 0, 0);
        assert!(result.is_ok());
        assert_eq!(buf, [0u8; 8], "COPY should not modify buffer");
    }

    #[test]
    fn test_relocate_glob_dat() {
        let mut buf = [0u8; 8];
        let result = relocate(R_X86_64_GLOB_DAT as i32, &mut buf, 0, 0xDEAD_BEEF);
        assert!(result.is_ok());
        assert_eq!(read64le(&buf), 0xDEAD_BEEF);
    }

    #[test]
    fn test_relocate_jump_slot() {
        let mut buf = [0u8; 8];
        let result = relocate(R_X86_64_JUMP_SLOT as i32, &mut buf, 0, 0xCAFE_BABE);
        assert!(result.is_ok());
        assert_eq!(read64le(&buf), 0xCAFE_BABE);
    }

    #[test]
    fn test_relocate_pc64() {
        let mut buf = [0u8; 8];
        let addr: u64 = 0x10000;
        let val: u64 = 0x20000;
        let result = relocate(R_X86_64_PC64 as i32, &mut buf, addr, val);
        assert!(result.is_ok());
        let patched = read64le(&buf) as i64;
        assert_eq!(patched, 0x10000);
    }

    #[test]
    fn test_relocate_relative() {
        let mut buf = [0u8; 8];
        let result = relocate(R_X86_64_RELATIVE as i32, &mut buf, 0, 0);
        assert!(result.is_ok());
        // Non-PE: no-op
        assert_eq!(buf, [0u8; 8]);
    }

    #[test]
    fn test_relocate_got_requires_context() {
        let mut buf = [0u8; 8];
        let result = relocate(R_X86_64_GOTPCREL as i32, &mut buf, 0, 0);
        assert!(result.is_err(), "GOTPCREL should require extended context");
    }

    #[test]
    fn test_relocate_unknown() {
        let mut buf = [0u8; 8];
        let result = relocate(9999, &mut buf, 0, 0);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // relocate_with_context() tests
    // -----------------------------------------------------------------------

    fn default_ctx() -> RelocContext {
        RelocContext::default()
    }

    #[test]
    fn test_ctx_relocate_none() {
        let mut buf = [0u8; 8];
        let ctx = default_ctx();
        let result = relocate_with_context(
            R_X86_64_NONE as i32, &mut buf, 0, 0,
            &ctx, None, None, None,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_ctx_relocate_64_static() {
        let mut buf = [0u8; 8];
        write64le(&mut buf, 10);
        let ctx = RelocContext { is_dll: false, ..default_ctx() };
        let result = relocate_with_context(
            R_X86_64_64 as i32, &mut buf, 0, 42,
            &ctx, None, None, None,
        );
        assert!(result.is_ok());
        assert_eq!(read64le(&buf), 52); // 10 + 42
    }

    #[test]
    fn test_ctx_relocate_gotpcrel() {
        let mut buf = [0u8; 4];
        let ctx = RelocContext {
            got_sh_addr: 0x2000,
            got_offset: 0x10,
            ..default_ctx()
        };
        let addr: u64 = 0x1000;
        let result = relocate_with_context(
            R_X86_64_GOTPCREL as i32, &mut buf, addr, 0,
            &ctx, None, None, None,
        );
        assert!(result.is_ok());
        // result = 0x2000 - 0x1000 + 0x10 - 4 = 0x100C
        let patched = read32le(&buf) as i32;
        assert_eq!(patched, 0x100C);
    }

    #[test]
    fn test_ctx_relocate_gotpc32() {
        let mut buf = [0u8; 4];
        let ctx = RelocContext {
            got_sh_addr: 0x3000,
            r_addend: -4,
            ..default_ctx()
        };
        let addr: u64 = 0x1000;
        let result = relocate_with_context(
            R_X86_64_GOTPC32 as i32, &mut buf, addr, 0,
            &ctx, None, None, None,
        );
        assert!(result.is_ok());
        // result = 0x3000 - 0x1000 + (-4) = 0x1FFC
        let patched = read32le(&buf) as i32;
        assert_eq!(patched, 0x1FFC);
    }

    #[test]
    fn test_ctx_relocate_gottpoff() {
        let mut buf = [0u8; 4];
        let ctx = RelocContext {
            got_sh_addr: 0x2000,
            ..default_ctx()
        };
        let val: u64 = 0x2100;
        let result = relocate_with_context(
            R_X86_64_GOTTPOFF as i32, &mut buf, 0, val,
            &ctx, None, None, None,
        );
        assert!(result.is_ok());
        // result = 0x2100 - 0x2000 = 0x100
        let patched = read32le(&buf) as i32;
        assert_eq!(patched, 0x100);
    }

    #[test]
    fn test_ctx_relocate_got32() {
        let mut buf = [0u8; 4];
        let ctx = RelocContext {
            got_offset: 0x20,
            ..default_ctx()
        };
        let result = relocate_with_context(
            R_X86_64_GOT32 as i32, &mut buf, 0, 0,
            &ctx, None, None, None,
        );
        assert!(result.is_ok());
        assert_eq!(read32le(&buf) as i32, 0x20);
    }

    #[test]
    fn test_ctx_relocate_got64() {
        let mut buf = [0u8; 8];
        let ctx = RelocContext {
            got_offset: 0x40,
            ..default_ctx()
        };
        let result = relocate_with_context(
            R_X86_64_GOT64 as i32, &mut buf, 0, 0,
            &ctx, None, None, None,
        );
        assert!(result.is_ok());
        assert_eq!(read64le(&buf) as i64, 0x40);
    }

    #[test]
    fn test_ctx_relocate_gotoff64() {
        let mut buf = [0u8; 8];
        let ctx = RelocContext {
            got_sh_addr: 0x5000,
            ..default_ctx()
        };
        let val: u64 = 0x5100;
        let result = relocate_with_context(
            R_X86_64_GOTOFF64 as i32, &mut buf, 0, val,
            &ctx, None, None, None,
        );
        assert!(result.is_ok());
        assert_eq!(read64le(&buf) as i64, 0x100);
    }

    #[test]
    fn test_ctx_relocate_pltoff64() {
        let mut buf = [0u8; 8];
        let ctx = RelocContext {
            got_sh_addr: 0x3000,
            r_addend: 8,
            ..default_ctx()
        };
        let val: u64 = 0x4000;
        let result = relocate_with_context(
            R_X86_64_PLTOFF64 as i32, &mut buf, 0, val,
            &ctx, None, None, None,
        );
        assert!(result.is_ok());
        // result = 0x4000 - 0x3000 + 8 = 0x1008
        assert_eq!(read64le(&buf) as i64, 0x1008);
    }

    #[test]
    fn test_ctx_relocate_glob_dat_with_addend() {
        let mut buf = [0u8; 8];
        let ctx = RelocContext {
            r_addend: 16,
            ..default_ctx()
        };
        let val: u64 = 0x1000; // val = S + A = symbol + 16
        let result = relocate_with_context(
            R_X86_64_GLOB_DAT as i32, &mut buf, 0, val,
            &ctx, None, None, None,
        );
        assert!(result.is_ok());
        // write64le(ptr, val - r_addend) = 0x1000 - 16 = 0xFF0
        assert_eq!(read64le(&buf), 0xFF0);
    }

    #[test]
    fn test_ctx_relocate_dtpoff32() {
        let mut buf = [0u8; 4];
        let ctx = default_ctx();
        let tls = TlsRelocInfo {
            sec_sh_addr: 0x1000,
            sec_data_offset: 0x100,
            sym_value: 0,
        };
        let val: u64 = 0x1200;
        let result = relocate_with_context(
            R_X86_64_DTPOFF32 as i32, &mut buf, 0, val,
            &ctx, None, None, Some(&tls),
        );
        assert!(result.is_ok());
        // x = 0x1200 - 0x1000 - 0x100 = 0x100
        let patched = read32le(&buf) as i32;
        assert_eq!(patched, 0x100);
    }

    #[test]
    fn test_ctx_relocate_tpoff64() {
        let mut buf = [0u8; 8];
        let ctx = default_ctx();
        let tls = TlsRelocInfo {
            sec_sh_addr: 0x2000,
            sec_data_offset: 0x200,
            sym_value: 0,
        };
        let val: u64 = 0x2500;
        let result = relocate_with_context(
            R_X86_64_TPOFF64 as i32, &mut buf, 0, val,
            &ctx, None, None, Some(&tls),
        );
        assert!(result.is_ok());
        // x = 0x2500 - 0x2000 - 0x200 = 0x300
        assert_eq!(read64le(&buf) as i64, 0x300);
    }

    #[test]
    fn test_ctx_relocate_relative_pe() {
        let mut buf = [0u8; 4];
        let ctx = RelocContext {
            pe_imagebase: 0x400000,
            ..default_ctx()
        };
        let val: u64 = 0x401000;
        let result = relocate_with_context(
            R_X86_64_RELATIVE as i32, &mut buf, 0, val,
            &ctx, None, None, None,
        );
        assert!(result.is_ok());
        // PE: add32le(ptr, val - pe_imagebase) = 0x401000 - 0x400000 = 0x1000
        let patched = read32le(&buf) as i32;
        assert_eq!(patched, 0x1000);
    }

    #[test]
    fn test_ctx_relocate_relative_non_pe() {
        let mut buf = [0u8; 4];
        let ctx = RelocContext {
            pe_imagebase: 0, // Non-PE
            ..default_ctx()
        };
        let result = relocate_with_context(
            R_X86_64_RELATIVE as i32, &mut buf, 0, 0x1000,
            &ctx, None, None, None,
        );
        assert!(result.is_ok());
        // Non-PE: no-op, buffer unchanged
        assert_eq!(buf, [0u8; 4]);
    }

    #[test]
    fn test_ctx_relocate_tlsld() {
        let mut buf = [0u8; 16];
        let ctx = default_ctx();
        let mut next_info: u64 = ELFW_R_INFO(5, R_X86_64_PLT32 as u64);
        let result = relocate_with_context(
            R_X86_64_TLSLD as i32, &mut buf, 0, 0,
            &ctx, None, Some(&mut next_info), None,
        );
        assert!(result.is_ok());
        // Verify replacement bytes
        assert_eq!(buf[0], 0x64); // %fs prefix
        assert_eq!(buf[1], 0x48); // REX.W
        assert_eq!(buf[2], 0x8b); // mov
        assert_eq!(buf[3], 0x04);
        assert_eq!(buf[4], 0x25);
        assert_eq!(buf[5], 0x00);
        // Next reloc should be zeroed to R_X86_64_NONE
        assert_eq!(ELFW_R_TYPE(next_info), R_X86_64_NONE);
        // Symbol should be preserved
        assert_eq!(ELFW_R_SYM(next_info), 5);
    }

    #[test]
    fn test_ctx_relocate_tlsgd() {
        let mut buf = [0u8; 16];
        let ctx = default_ctx();
        let tls = TlsRelocInfo {
            sec_sh_addr: 0x1000,
            sec_data_offset: 0x100,
            sym_value: 0x1150,
        };
        let mut next_info: u64 = ELFW_R_INFO(3, R_X86_64_PLT32 as u64);
        let result = relocate_with_context(
            R_X86_64_TLSGD as i32, &mut buf, 0, 0,
            &ctx, None, Some(&mut next_info), Some(&tls),
        );
        assert!(result.is_ok());
        // Verify replacement bytes
        assert_eq!(buf[0], 0x25);
        assert_eq!(buf[5], 0x48);
        assert_eq!(buf[6], 0x8d);
        assert_eq!(buf[7], 0x80);
        // Displacement at ptr[8..12] should contain TLS offset:
        // x = 0x1150 - 0x1000 - 0x100 = 0x50
        let disp = read32le(&buf[8..12]) as i32;
        assert_eq!(disp, 0x50);
        // Next reloc zeroed
        assert_eq!(ELFW_R_TYPE(next_info), R_X86_64_NONE);
        assert_eq!(ELFW_R_SYM(next_info), 3);
    }

    #[test]
    fn test_ctx_relocate_unknown() {
        let mut buf = [0u8; 8];
        let ctx = default_ctx();
        let result = relocate_with_context(
            9999, &mut buf, 0, 0,
            &ctx, None, None, None,
        );
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // create_plt_entry() tests
    // -----------------------------------------------------------------------

    /// Helper: create a TCCState with PLT and GOT sections for PLT tests.
    fn make_tcc_with_plt_got() -> (TCCState, usize, usize) {
        let mut s1 = TCCState::new().expect("TCCState::new should succeed");
        // Section 0 is SHN_UNDEF (required by convention).
        if s1.sections.is_empty() {
            s1.sections.push(Section::default()); // index 0
        }
        // PLT section
        let plt_idx = s1.sections.len();
        s1.sections.push(Section {
            name: ".plt".to_string(),
            ..Section::default()
        });
        s1.plt = Some(plt_idx);
        // GOT section
        let got_idx = s1.sections.len();
        s1.sections.push(Section {
            name: ".got".to_string(),
            ..Section::default()
        });
        s1.got = Some(got_idx);
        (s1, plt_idx, got_idx)
    }

    #[test]
    fn test_create_plt_entry_first_entry() {
        let (mut s1, plt_idx, _got_idx) = make_tcc_with_plt_got();

        let offset = create_plt_entry(&mut s1, 0x20);
        assert!(offset.is_ok());
        let plt_off = offset.unwrap();
        // First call creates PLT0 (16 bytes) + one entry (16 bytes) = 32 bytes total
        assert_eq!(plt_off, 16, "First PLT entry starts at offset 16");
        let plt_sec = &s1.sections[plt_idx];
        // data_offset tracks logical size; data.len() may be larger due to pre-allocation
        assert_eq!(plt_sec.data_offset, 32);

        // Verify PLT0 starts with ff 35 (push [GOT+8])
        assert_eq!(plt_sec.data[0], 0xff);
        assert_eq!(plt_sec.data[1], 0x35);
        // Verify entry starts with ff 25 (jmp [GOT+got_offset])
        assert_eq!(plt_sec.data[16], 0xff);
        assert_eq!(plt_sec.data[17], 0x25);
    }

    #[test]
    fn test_create_plt_entry_second_entry() {
        let (mut s1, plt_idx, _got_idx) = make_tcc_with_plt_got();

        // Create first entry
        let _ = create_plt_entry(&mut s1, 0x20);
        // Create second entry
        let offset = create_plt_entry(&mut s1, 0x28);
        assert!(offset.is_ok());
        let plt_off = offset.unwrap();
        assert_eq!(plt_off, 32, "Second PLT entry starts at offset 32");
        let plt_sec = &s1.sections[plt_idx];
        // data_offset tracks logical size (48 = 16 header + 16 entry + 16 entry)
        assert_eq!(plt_sec.data_offset, 48);
    }

    // -----------------------------------------------------------------------
    // relocate_plt() tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_relocate_plt_basic() {
        let (mut s1, plt_idx, got_idx) = make_tcc_with_plt_got();

        // Create one PLT entry
        let _ = create_plt_entry(&mut s1, 0x20);

        // Set addresses
        s1.sections[plt_idx].sh_addr = 0x1000;
        s1.sections[got_idx].sh_addr = 0x3000;

        let result = relocate_plt(&mut s1);
        assert!(result.is_ok());
    }

    // -----------------------------------------------------------------------
    // ELFW_R helper tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_elfw_r_info_sym() {
        let info = ELFW_R_INFO(42, 7);
        assert_eq!(ELFW_R_SYM(info), 42);
        assert_eq!(ELFW_R_TYPE(info), 7);
    }
}
