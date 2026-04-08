//! C67 (TMS320C67xx) relocation types and linker support.
//!
//! Port of `c67-link.c` (125 lines) to idiomatic Rust. This module implements
//! C67 (TMS320C67xx DSP) relocation processing, GOT/PLT entry determination,
//! and symbol binding for the COFF-based C67 target.
//!
//! # Architecture Overview
//!
//! The TMS320C67xx is a VLIW digital signal processor from Texas Instruments.
//! It uses a custom instruction encoding with 16-bit immediate fields embedded
//! in MVKL (Move Constant Low) and MVKH (Move Constant High) instruction pairs
//! to construct 32-bit addresses.
//!
//! # Relocation Model
//!
//! C67 relocations handle:
//! - **R_C60_32**: Standard 32-bit absolute address patching
//! - **R_C60LO16/R_C60HI16**: Paired instruction patching for MVKL/MVKH pairs
//!   where the 16-bit immediate field occupies bits [22:7] of each 32-bit instruction
//! - GOT/PLT entries are defined but GOT support is **not implemented** for C67
//!
//! # Key Differences from C Implementation
//!
//! 1. No raw pointer arithmetic — uses `&mut [u8]` slices with bounds checking
//! 2. Explicit little-endian byte ordering via `from_le_bytes`/`to_le_bytes`
//! 3. Result-based error propagation replaces `fprintf(stderr, ...)`
//! 4. No global `TCCState` parameter — explicit parameters only
//! 5. Stub functions (`create_plt_entry`, `relocate_plt`) preserved as in original

use crate::error::{TccError, TccResult};

// ============================================================================
// C67-specific relocation type constants (R_C60_*)
// Values from elf.h in the TCC source repository.
// These match the TI TMS320C6000 COFF/ELF ABI specification.
// ============================================================================

/// 32-bit absolute relocation.
///
/// Adds the symbol value to the 32-bit word at the relocation site.
/// From `elf.h` line 2559: `#define R_C60_32 1`
pub const R_C60_32: u32 = 1;

/// 32-bit GOT entry relocation.
///
/// References a 32-bit entry in the Global Offset Table.
/// From `elf.h` line 2560: `#define R_C60_GOT32 3`
pub const R_C60_GOT32: u32 = 3;

/// 32-bit PLT address relocation.
///
/// References the Procedure Linkage Table for function calls.
/// From `elf.h` line 2561: `#define R_C60_PLT32 4`
pub const R_C60_PLT32: u32 = 4;

/// Copy relocation.
///
/// Copies data from a shared object into the executable's data segment.
/// From `elf.h` line 2562: `#define R_C60_COPY 5`
pub const R_C60_COPY: u32 = 5;

/// Global data relocation.
///
/// Creates a GOT entry for global data symbols.
/// From `elf.h` line 2563: `#define R_C60_GLOB_DAT 6`
pub const R_C60_GLOB_DAT: u32 = 6;

/// Jump slot relocation.
///
/// Creates a PLT entry for lazy binding of function calls.
/// From `elf.h` line 2564: `#define R_C60_JMP_SLOT 7`
pub const R_C60_JMP_SLOT: u32 = 7;

/// Relative relocation.
///
/// Adjusts a value by the program's base address (for PIC/PIE).
/// From `elf.h` line 2565: `#define R_C60_RELATIVE 8`
pub const R_C60_RELATIVE: u32 = 8;

/// 32-bit offset from GOT base.
///
/// Computes the offset of a symbol relative to the GOT base address.
/// From `elf.h` line 2566: `#define R_C60_GOTOFF 9`
pub const R_C60_GOTOFF: u32 = 9;

/// 32-bit PC-relative offset to GOT.
///
/// Computes the PC-relative distance to the GOT base.
/// From `elf.h` line 2567: `#define R_C60_GOTPC 10`
pub const R_C60_GOTPC: u32 = 10;

/// Low 16-bit relocation for MVKL instruction.
///
/// Patches the 16-bit immediate field (bits [22:7]) of a MVKL instruction
/// with the low 16 bits of the symbol address. Always paired with R_C60HI16
/// which patches the MVKH instruction at offset+4.
///
/// The R_C60LO16 handler patches **both** MVKL and MVKH instructions at once,
/// so R_C60HI16 is handled as a no-op.
///
/// From `elf.h` line 2569: `#define R_C60LO16 0x54`
pub const R_C60LO16: u32 = 0x54;

/// High 16-bit relocation for MVKH instruction.
///
/// Always paired with R_C60LO16. The actual patching of both instructions
/// is performed by the R_C60LO16 handler, so this relocation type is a no-op.
///
/// From `elf.h` line 2570: `#define R_C60HI16 0x55`
pub const R_C60HI16: u32 = 0x55;

/// Number of defined C60 relocation types (sentinel value).
///
/// From `elf.h` line 2572: `#define R_C60_NUM 0x56`
pub const R_C60_NUM: u32 = 0x56;

// ============================================================================
// Generic relocation type aliases
// From c67-link.c lines 5-13 (TARGET_DEFS_ONLY section)
// These map architecture-neutral names to C67-specific relocation constants.
// ============================================================================

/// Generic alias for 32-bit data relocation.
/// Maps to `R_C60_32` for the C67 target.
/// From `c67-link.c` line 6: `#define R_DATA_32 R_C60_32`
pub const R_DATA_32: u32 = R_C60_32;

/// Generic alias for pointer-sized data relocation.
/// Maps to `R_C60_32` (C67 is a 32-bit architecture).
/// From `c67-link.c` line 7: `#define R_DATA_PTR R_C60_32`
pub const R_DATA_PTR: u32 = R_C60_32;

/// Generic alias for jump slot relocation.
/// From `c67-link.c` line 8: `#define R_JMP_SLOT R_C60_JMP_SLOT`
pub const R_JMP_SLOT: u32 = R_C60_JMP_SLOT;

/// Generic alias for global data relocation.
/// From `c67-link.c` line 9: `#define R_GLOB_DAT R_C60_GLOB_DAT`
pub const R_GLOB_DAT: u32 = R_C60_GLOB_DAT;

/// Generic alias for copy relocation.
/// From `c67-link.c` line 10: `#define R_COPY R_C60_COPY`
pub const R_COPY: u32 = R_C60_COPY;

/// Generic alias for relative relocation.
/// From `c67-link.c` line 11: `#define R_RELATIVE R_C60_RELATIVE`
pub const R_RELATIVE: u32 = R_C60_RELATIVE;

/// Generic alias for number of relocation types.
/// From `c67-link.c` line 13: `#define R_NUM R_C60_NUM`
pub const R_NUM: u32 = R_C60_NUM;

// ============================================================================
// ELF/target configuration constants
// From c67-link.c lines 3, 15-19
// ============================================================================

/// ELF machine type identifier for TMS320C60.
///
/// This is a non-standard machine type ID used by TCC for the C67 target.
/// The official ELF specification uses `EM_TI_C6000 = 140` but TCC defines
/// its own value for historical reasons.
///
/// From `elf.h` line 278: `#define EM_C60 0x9c60`
/// From `c67-link.c` line 3: `#define EM_TCC_TARGET EM_C60`
pub const EM_TCC_TARGET: u16 = 0x9c60;

/// Default ELF start address for C67 executables.
///
/// This is the virtual address at which the executable's text segment is loaded.
/// From `c67-link.c` line 15: `#define ELF_START_ADDR 0x00000400`
pub const ELF_START_ADDR: u64 = 0x0000_0400;

/// Default ELF page size for C67 targets.
///
/// Used for segment alignment in the ELF output.
/// From `c67-link.c` line 16: `#define ELF_PAGE_SIZE 0x1000`
pub const ELF_PAGE_SIZE: u64 = 0x1000;

/// C67 does **not** use PC-relative DLL PLT entries.
///
/// From `c67-link.c` line 18: `#define PCRELATIVE_DLLPLT 0`
pub const PCRELATIVE_DLLPLT: bool = false;

/// C67 does **not** need to relocate DLL PLT entries.
///
/// From `c67-link.c` line 19: `#define RELOCATE_DLLPLT 0`
pub const RELOCATE_DLLPLT: bool = false;

// ============================================================================
// GOT/PLT entry type constants
// From tcc.h lines 1600-1607 (enum gotplt_entry)
// Used by gotplt_entry_type() to communicate what the linker should create.
// ============================================================================

/// No GOT or PLT entry needed for this relocation type.
const NO_GOTPLT_ENTRY: i32 = 0;

/// Only a GOT entry is needed (no PLT entry).
const BUILD_GOT_ONLY: i32 = 1;

/// Always generate both GOT and PLT entries.
/// Value is 3 because `AUTO_GOTPLT_ENTRY = 2` sits between in the C enum.
const ALWAYS_GOTPLT_ENTRY: i32 = 3;

// ============================================================================
// Linker functions
// ============================================================================

/// Classify a relocation type as code (1), data (0), or unknown (-1).
///
/// This function is used by the linker to determine whether a relocation
/// references code or data, which affects PLT entry generation decisions.
///
/// # Arguments
/// * `reloc_type` — One of the `R_C60_*` relocation type constants
///
/// # Returns
/// * `0` — Data relocation (R_C60_32, R_C60LO16, R_C60HI16, R_C60_GOT32,
///   R_C60_GOTOFF, R_C60_GOTPC, R_C60_COPY)
/// * `1` — Code relocation (R_C60_PLT32)
/// * `-1` — Unknown/unhandled relocation type
///
/// # Source
/// Port of `c67-link.c` lines 27-43: `ST_FUNC int code_reloc(int reloc_type)`
pub fn code_reloc(reloc_type: i32) -> i32 {
    match reloc_type as u32 {
        R_C60_32
        | R_C60LO16
        | R_C60HI16
        | R_C60_GOT32
        | R_C60_GOTOFF
        | R_C60_GOTPC
        | R_C60_COPY => 0, // data relocations
        R_C60_PLT32 => 1,  // code relocation
        _ => -1,            // unknown relocation type
    }
}

/// Determine whether a relocation type requires GOT and/or PLT entries.
///
/// Returns an enumerator describing when the linker should create GOT/PLT
/// entries for the given relocation type.
///
/// # Arguments
/// * `reloc_type` — One of the `R_C60_*` relocation type constants
///
/// # Returns
/// * `NO_GOTPLT_ENTRY` (0) — Never generate GOT/PLT entries
/// * `BUILD_GOT_ONLY` (1) — Only build a GOT entry (no PLT)
/// * `ALWAYS_GOTPLT_ENTRY` (3) — Always generate both GOT and PLT entries
/// * `-1` — Unknown/unhandled relocation type
///
/// # Source
/// Port of `c67-link.c` lines 48-66: `ST_FUNC int gotplt_entry_type(int reloc_type)`
pub fn gotplt_entry_type(reloc_type: i32) -> i32 {
    match reloc_type as u32 {
        R_C60_32 | R_C60LO16 | R_C60HI16 | R_C60_COPY => {
            NO_GOTPLT_ENTRY
        }
        R_C60_GOTOFF | R_C60_GOTPC => {
            BUILD_GOT_ONLY
        }
        R_C60_PLT32 | R_C60_GOT32 => {
            ALWAYS_GOTPLT_ENTRY
        }
        _ => -1, // unknown relocation type
    }
}

/// Create a PLT entry for the given GOT offset.
///
/// **NOTE**: C67 GOT is not implemented. This function always returns an error,
/// matching the original C implementation which calls `tcc_error_noabort()`.
///
/// # Arguments
/// * `_got_offset` — Offset into the GOT (unused — GOT not implemented)
/// * `_attr` — Symbol attributes (unused — GOT not implemented)
///
/// # Returns
/// Always returns `Err(TccError::CodegenError)` with a descriptive message.
///
/// # Source
/// Port of `c67-link.c` lines 68-72:
/// ```c
/// ST_FUNC unsigned create_plt_entry(TCCState *s1, unsigned got_offset, struct sym_attr *attr)
/// {
///     tcc_error_noabort("C67 got not implemented");
///     return 0;
/// }
/// ```
pub fn create_plt_entry(_got_offset: u32, _attr: u32) -> TccResult<u32> {
    Err(TccError::CodegenError {
        message: "C67 got not implemented".to_string(),
    })
}

/// Relocate the PLT: compute addresses and offsets now that final addresses
/// are known (see `fill_program_header` in the linker).
///
/// **NOTE**: PLT relocation is not fully implemented for C67. The original C
/// code contains empty loops with `XXX: TODO` comments. This implementation
/// faithfully preserves that behavior — if PLT data is present and non-empty,
/// no patching is performed (matching the original empty loop).
///
/// # Arguments
/// * `plt_data` — Optional mutable reference to the PLT section data.
///   `None` indicates no PLT section exists.
/// * `_plt_data_offset` — Length of valid data in the PLT section (unused).
///
/// # Returns
/// Always returns `Ok(())` — the function is effectively a no-op.
///
/// # Source
/// Port of `c67-link.c` lines 76-92:
/// ```c
/// ST_FUNC void relocate_plt(TCCState *s1)
/// {
///     uint8_t *p, *p_end;
///     if (!s1->plt)
///       return;
///     p = s1->plt->data;
///     p_end = p + s1->plt->data_offset;
///     if (p < p_end) {
///         /* XXX: TODO */
///         while (p < p_end) {
///             /* XXX: TODO */
///         }
///    }
/// }
/// ```
pub fn relocate_plt(plt_data: Option<&mut [u8]>, _plt_data_offset: usize) -> TccResult<()> {
    if let Some(data) = plt_data {
        if !data.is_empty() {
            // The original C code has empty loops with XXX: TODO comments.
            // PLT relocation is not fully implemented for C67.
            // No patching is performed, matching the original behavior.
        }
    }
    Ok(())
}

/// Apply a relocation to the given memory location.
///
/// Patches the instruction or data at `ptr` based on the relocation type.
/// This is the core relocation processing function called by the linker
/// for each relocation entry in the C67 output.
///
/// # Arguments
/// * `rel_type` — Relocation type (one of the `R_C60_*` constants)
/// * `ptr` — Mutable byte slice at the relocation site. Must be at least
///   4 bytes for `R_C60_32` and at least 8 bytes for `R_C60LO16`.
/// * `addr` — Virtual address of the relocation site
/// * `val` — Symbol value plus addend (the value to relocate to)
///
/// # Relocation Types Handled
///
/// ## R_C60_32
/// Adds `val` to the 32-bit little-endian word at `ptr`:
/// ```text
/// *(int32_t *)ptr += val;
/// ```
///
/// ## R_C60LO16
/// Patches a MVKL/MVKH instruction pair. Both instructions are consecutive
/// 32-bit words where the 16-bit immediate field occupies bits [22:7]:
/// ```text
/// Instruction format: [31:23][22:7 = imm16][6:0]
///
/// Original value extracted:
///   orig_lo = (inst0 >> 7) & 0xFFFF
///   orig_hi = (inst1 >> 7) & 0xFFFF
///   orig = orig_lo | (orig_hi << 16)
///
/// New value = val + orig (32-bit wrapping):
///   inst0[22:7] = new_val[15:0]   (MVKL — low 16 bits)
///   inst1[22:7] = new_val[31:16]  (MVKH — high 16 bits)
/// ```
///
/// ## R_C60HI16
/// No-op. Always paired with R_C60LO16 which handles both instructions.
///
/// ## Default
/// Returns an error for unhandled relocation types.
///
/// # Errors
/// * `TccError::CodegenError` — If `ptr` is too short for the relocation type
///   or an unknown relocation type is encountered.
///
/// # Source
/// Port of `c67-link.c` lines 94-123:
/// `ST_FUNC void relocate(TCCState *s1, ElfW_Rel *rel, int type, unsigned char *ptr, addr_t addr, addr_t val)`
pub fn relocate(rel_type: i32, ptr: &mut [u8], addr: u64, val: u64) -> TccResult<()> {
    match rel_type as u32 {
        R_C60_32 => {
            // *(int *)ptr += val;
            // Add val to the 32-bit little-endian word at ptr.
            if ptr.len() < 4 {
                return Err(TccError::CodegenError {
                    message: format!(
                        "R_C60_32 relocation requires at least 4 bytes, got {}",
                        ptr.len()
                    ),
                });
            }
            let current = i32::from_le_bytes([ptr[0], ptr[1], ptr[2], ptr[3]]);
            let new_val = current.wrapping_add(val as i32);
            ptr[0..4].copy_from_slice(&new_val.to_le_bytes());
            Ok(())
        }
        R_C60LO16 => {
            // This relocation patches BOTH a MVKL and MVKH instruction pair.
            // The low 16 bits go into the MVKL at ptr, high 16 bits into MVKH at ptr+4.
            //
            // TMS320C67xx instruction format: bits [22:7] contain the 16-bit immediate.
            //
            // Extract original 32-bit value from the two instructions:
            //   orig = ((*(int*)(ptr) >> 7) & 0xffff) | (((*(int*)(ptr+4) >> 7) & 0xffff) << 16)
            // Then patch both with (val + orig).
            if ptr.len() < 8 {
                return Err(TccError::CodegenError {
                    message: format!(
                        "R_C60LO16 relocation requires at least 8 bytes, got {}",
                        ptr.len()
                    ),
                });
            }

            // Read the two 32-bit instruction words
            let inst0 = i32::from_le_bytes([ptr[0], ptr[1], ptr[2], ptr[3]]);
            let inst1 = i32::from_le_bytes([ptr[4], ptr[5], ptr[6], ptr[7]]);

            // Extract the 16-bit immediate fields from bits [22:7]
            let orig_lo = ((inst0 >> 7) & 0xffff) as u32;
            let orig_hi = ((inst1 >> 7) & 0xffff) as u32;
            let orig = orig_lo | (orig_hi << 16);

            // Compute new value: val + orig with 32-bit wrapping arithmetic
            // (matches C behavior where addr_t is typically uint32_t on C67)
            let result = (val as u32).wrapping_add(orig);

            // Bit mask to clear the 16-bit immediate field (bits [22:7]):
            // ~(0xffff << 7) = ~0x007FFF80 = 0xFF80007F (as i32)
            let mask: i32 = !(0xffffi32 << 7);

            // Patch MVKL instruction with low 16 bits of result
            let new_inst0 = (inst0 & mask) | (((result & 0xffff) as i32) << 7);
            ptr[0..4].copy_from_slice(&new_inst0.to_le_bytes());

            // Patch MVKH instruction with high 16 bits of result
            let new_inst1 = (inst1 & mask) | ((((result >> 16) & 0xffff) as i32) << 7);
            ptr[4..8].copy_from_slice(&new_inst1.to_le_bytes());

            Ok(())
        }
        R_C60HI16 => {
            // R_C60HI16 is always paired with R_C60LO16 and handled there.
            // The original C code does nothing for this case (empty case + break).
            Ok(())
        }
        _ => {
            // Original C code:
            //   fprintf(stderr, "FIXME: handle reloc type %x at %x [%p] to %x\n",
            //           type, (unsigned)addr, ptr, (unsigned)val);
            Err(TccError::CodegenError {
                message: format!(
                    "FIXME: unhandled C67 relocation type 0x{:x} at 0x{:x} to 0x{:x}",
                    rel_type, addr, val
                ),
            })
        }
    }
}

// ============================================================================
// Unit tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // --- Constant value verification ---

    #[test]
    fn test_relocation_constants_match_elf_h() {
        assert_eq!(R_C60_32, 1);
        assert_eq!(R_C60_GOT32, 3);
        assert_eq!(R_C60_PLT32, 4);
        assert_eq!(R_C60_COPY, 5);
        assert_eq!(R_C60_GLOB_DAT, 6);
        assert_eq!(R_C60_JMP_SLOT, 7);
        assert_eq!(R_C60_RELATIVE, 8);
        assert_eq!(R_C60_GOTOFF, 9);
        assert_eq!(R_C60_GOTPC, 10);
        assert_eq!(R_C60LO16, 0x54);
        assert_eq!(R_C60HI16, 0x55);
        assert_eq!(R_C60_NUM, 0x56);
    }

    #[test]
    fn test_generic_aliases() {
        assert_eq!(R_DATA_32, R_C60_32);
        assert_eq!(R_DATA_PTR, R_C60_32);
        assert_eq!(R_JMP_SLOT, R_C60_JMP_SLOT);
        assert_eq!(R_GLOB_DAT, R_C60_GLOB_DAT);
        assert_eq!(R_COPY, R_C60_COPY);
        assert_eq!(R_RELATIVE, R_C60_RELATIVE);
        assert_eq!(R_NUM, R_C60_NUM);
    }

    #[test]
    fn test_elf_constants() {
        assert_eq!(EM_TCC_TARGET, 0x9c60);
        assert_eq!(ELF_START_ADDR, 0x0000_0400);
        assert_eq!(ELF_PAGE_SIZE, 0x1000);
        assert!(!PCRELATIVE_DLLPLT);
        assert!(!RELOCATE_DLLPLT);
    }

    // --- code_reloc tests ---

    #[test]
    fn test_code_reloc_data_relocations() {
        assert_eq!(code_reloc(R_C60_32 as i32), 0);
        assert_eq!(code_reloc(R_C60LO16 as i32), 0);
        assert_eq!(code_reloc(R_C60HI16 as i32), 0);
        assert_eq!(code_reloc(R_C60_GOT32 as i32), 0);
        assert_eq!(code_reloc(R_C60_GOTOFF as i32), 0);
        assert_eq!(code_reloc(R_C60_GOTPC as i32), 0);
        assert_eq!(code_reloc(R_C60_COPY as i32), 0);
    }

    #[test]
    fn test_code_reloc_code_relocation() {
        assert_eq!(code_reloc(R_C60_PLT32 as i32), 1);
    }

    #[test]
    fn test_code_reloc_unknown() {
        assert_eq!(code_reloc(0), -1);
        assert_eq!(code_reloc(255), -1);
        assert_eq!(code_reloc(-1), -1);
        assert_eq!(code_reloc(999), -1);
    }

    // --- gotplt_entry_type tests ---

    #[test]
    fn test_gotplt_no_entry() {
        assert_eq!(gotplt_entry_type(R_C60_32 as i32), NO_GOTPLT_ENTRY);
        assert_eq!(gotplt_entry_type(R_C60LO16 as i32), NO_GOTPLT_ENTRY);
        assert_eq!(gotplt_entry_type(R_C60HI16 as i32), NO_GOTPLT_ENTRY);
        assert_eq!(gotplt_entry_type(R_C60_COPY as i32), NO_GOTPLT_ENTRY);
    }

    #[test]
    fn test_gotplt_got_only() {
        assert_eq!(gotplt_entry_type(R_C60_GOTOFF as i32), BUILD_GOT_ONLY);
        assert_eq!(gotplt_entry_type(R_C60_GOTPC as i32), BUILD_GOT_ONLY);
    }

    #[test]
    fn test_gotplt_always_entry() {
        assert_eq!(gotplt_entry_type(R_C60_PLT32 as i32), ALWAYS_GOTPLT_ENTRY);
        assert_eq!(gotplt_entry_type(R_C60_GOT32 as i32), ALWAYS_GOTPLT_ENTRY);
    }

    #[test]
    fn test_gotplt_unknown() {
        assert_eq!(gotplt_entry_type(0), -1);
        assert_eq!(gotplt_entry_type(255), -1);
        assert_eq!(gotplt_entry_type(-1), -1);
    }

    // --- create_plt_entry tests ---

    #[test]
    fn test_create_plt_entry_always_errors() {
        let result = create_plt_entry(0, 0);
        assert!(result.is_err());
        let err = result.unwrap_err();
        let msg = format!("{}", err);
        assert!(msg.contains("C67 got not implemented"), "Error message was: {}", msg);
    }

    // --- relocate_plt tests ---

    #[test]
    fn test_relocate_plt_no_data() {
        assert!(relocate_plt(None, 0).is_ok());
    }

    #[test]
    fn test_relocate_plt_empty_data() {
        let mut data: Vec<u8> = vec![];
        assert!(relocate_plt(Some(&mut data), 0).is_ok());
    }

    #[test]
    fn test_relocate_plt_with_data() {
        let mut data: Vec<u8> = vec![0u8; 32];
        assert!(relocate_plt(Some(&mut data), 32).is_ok());
    }

    // --- relocate R_C60_32 tests ---

    #[test]
    fn test_relocate_r_c60_32_simple_add() {
        // Start with a 32-bit value of 100, add 50
        let mut ptr = 100i32.to_le_bytes().to_vec();
        let result = relocate(R_C60_32 as i32, &mut ptr, 0x1000, 50);
        assert!(result.is_ok());
        let patched = i32::from_le_bytes([ptr[0], ptr[1], ptr[2], ptr[3]]);
        assert_eq!(patched, 150);
    }

    #[test]
    fn test_relocate_r_c60_32_zero_val() {
        // Adding zero should leave the value unchanged
        let mut ptr = 42i32.to_le_bytes().to_vec();
        let result = relocate(R_C60_32 as i32, &mut ptr, 0x2000, 0);
        assert!(result.is_ok());
        let patched = i32::from_le_bytes([ptr[0], ptr[1], ptr[2], ptr[3]]);
        assert_eq!(patched, 42);
    }

    #[test]
    fn test_relocate_r_c60_32_wrapping() {
        // Test wrapping behavior: 0x7FFFFFFF + 1 should wrap to -2147483648
        let mut ptr = 0x7FFFFFFFi32.to_le_bytes().to_vec();
        let result = relocate(R_C60_32 as i32, &mut ptr, 0, 1);
        assert!(result.is_ok());
        let patched = i32::from_le_bytes([ptr[0], ptr[1], ptr[2], ptr[3]]);
        assert_eq!(patched, -2147483648i32); // 0x80000000 as i32
    }

    #[test]
    fn test_relocate_r_c60_32_too_short() {
        let mut ptr = vec![0u8; 3]; // only 3 bytes, need 4
        let result = relocate(R_C60_32 as i32, &mut ptr, 0, 0);
        assert!(result.is_err());
    }

    // --- relocate R_C60LO16 tests ---

    #[test]
    fn test_relocate_r_c60lo16_simple() {
        // Create two instruction words with zero immediate fields
        // Instruction format: [31:23][22:7 = imm16][6:0]
        // Zero immediate means bits [22:7] = 0x0000
        let inst0: i32 = 0x00000001; // some opcode bits, zero imm
        let inst1: i32 = 0x00000001; // some opcode bits, zero imm
        let mut ptr = Vec::new();
        ptr.extend_from_slice(&inst0.to_le_bytes());
        ptr.extend_from_slice(&inst1.to_le_bytes());

        // Relocate with val = 0x12345678
        let result = relocate(R_C60LO16 as i32, &mut ptr, 0, 0x12345678);
        assert!(result.is_ok());

        let patched0 = i32::from_le_bytes([ptr[0], ptr[1], ptr[2], ptr[3]]);
        let patched1 = i32::from_le_bytes([ptr[4], ptr[5], ptr[6], ptr[7]]);

        // Verify low 16 bits (0x5678) are in inst0 bits [22:7]
        let lo_imm = ((patched0 >> 7) & 0xffff) as u32;
        assert_eq!(lo_imm, 0x5678);

        // Verify high 16 bits (0x1234) are in inst1 bits [22:7]
        let hi_imm = ((patched1 >> 7) & 0xffff) as u32;
        assert_eq!(hi_imm, 0x1234);

        // Verify non-immediate bits are preserved
        assert_eq!(patched0 & 0x7F, 0x01);       // bits [6:0] preserved
        assert_eq!(patched0 & !0x007FFF80u32 as i32, 0x01); // non-imm bits preserved
    }

    #[test]
    fn test_relocate_r_c60lo16_with_existing_value() {
        // Create instructions with existing immediate value 0x00010002
        // inst0 imm = 0x0002 (low), inst1 imm = 0x0001 (high)
        let inst0: i32 = (0x0002i32 << 7) | 0x01; // low 16 bits = 0x0002
        let inst1: i32 = (0x0001i32 << 7) | 0x01; // high 16 bits = 0x0001
        let mut ptr = Vec::new();
        ptr.extend_from_slice(&inst0.to_le_bytes());
        ptr.extend_from_slice(&inst1.to_le_bytes());

        // Relocate with val = 0x00030004, existing orig = 0x00010002
        // Expected result = 0x00030004 + 0x00010002 = 0x00040006
        let result = relocate(R_C60LO16 as i32, &mut ptr, 0, 0x00030004);
        assert!(result.is_ok());

        let patched0 = i32::from_le_bytes([ptr[0], ptr[1], ptr[2], ptr[3]]);
        let patched1 = i32::from_le_bytes([ptr[4], ptr[5], ptr[6], ptr[7]]);

        let lo_imm = ((patched0 >> 7) & 0xffff) as u32;
        let hi_imm = ((patched1 >> 7) & 0xffff) as u32;
        let reconstructed = lo_imm | (hi_imm << 16);
        assert_eq!(reconstructed, 0x00040006);
    }

    #[test]
    fn test_relocate_r_c60lo16_too_short() {
        let mut ptr = vec![0u8; 7]; // only 7 bytes, need 8
        let result = relocate(R_C60LO16 as i32, &mut ptr, 0, 0);
        assert!(result.is_err());
    }

    // --- relocate R_C60HI16 tests ---

    #[test]
    fn test_relocate_r_c60hi16_is_noop() {
        let mut ptr = vec![0xAA, 0xBB, 0xCC, 0xDD];
        let original = ptr.clone();
        let result = relocate(R_C60HI16 as i32, &mut ptr, 0x1000, 0x5678);
        assert!(result.is_ok());
        // Verify nothing was modified
        assert_eq!(ptr, original);
    }

    // --- relocate unknown type tests ---

    #[test]
    fn test_relocate_unknown_type() {
        let mut ptr = vec![0u8; 8];
        let result = relocate(0xFF, &mut ptr, 0x4000, 0x8000);
        assert!(result.is_err());
        let err = result.unwrap_err();
        let msg = format!("{}", err);
        assert!(msg.contains("FIXME"), "Error message was: {}", msg);
        assert!(msg.contains("0xff"), "Error message was: {}", msg);
    }

    #[test]
    fn test_relocate_glob_dat_is_unknown() {
        // R_C60_GLOB_DAT is not handled by the relocate function
        // (it's used by the dynamic linker, not the static linker)
        let mut ptr = vec![0u8; 8];
        let result = relocate(R_C60_GLOB_DAT as i32, &mut ptr, 0, 0);
        assert!(result.is_err());
    }
}
