//! AArch64 (ARM64) ELF relocation handling and PLT/GOT generation.
//!
//! Port of `arm64-link.c` (322 lines) from the TCC C codebase.
//! Implements all AArch64-specific ELF relocation types including:
//! - Page-based addressing (ADRP+ADD/LDR patterns)
//! - MOVW/MOVT wide immediate relocations (G0-G3)
//! - Load/store offset relocations (LDST8/16/32/64/128)
//! - Branch relocations (JUMP26, CALL26)
//! - GOT-relative addressing (ADR_GOT_PAGE, LD64_GOT_LO12_NC)
//! - Dynamic relocations (ABS64, ABS32, RELATIVE, COPY, GLOB_DAT, JUMP_SLOT)
//!
//! # Architecture
//!
//! This module provides the functions that [`super::Arm64Backend`]'s
//! [`CodegenBackend`](crate::arch::CodegenBackend) trait implementation
//! delegates to for linker operations. The core functions are:
//!
//! - [`code_reloc`]: Classifies relocations as code (1), data (0), or unknown (-1).
//! - [`gotplt_entry_type`]: Determines GOT/PLT entry requirements per relocation type.
//! - [`create_plt_entry`]: Generates PLT stub entries for lazy symbol resolution.
//! - [`relocate_plt`]: Fixes up PLT entries with final GOT/PLT virtual addresses.
//! - [`relocate`]: Applies a single AArch64 relocation to instruction/data bytes.

use crate::error::{TccError, TccResult};
use crate::arch::{read32le, write32le, add32le, read64le, write64le, add64le};

// Re-export GOT/PLT entry type constants from the shared arch module.
// These values are: NO_GOTPLT_ENTRY=0, AUTO_GOTPLT_ENTRY=2, ALWAYS_GOTPLT_ENTRY=3.
pub use crate::arch::NO_GOTPLT_ENTRY;
pub use crate::arch::AUTO_GOTPLT_ENTRY;
pub use crate::arch::ALWAYS_GOTPLT_ENTRY;

// ===========================================================================
// AArch64 ELF Relocation Type Constants
// ===========================================================================
// Values from the ELF specification for AArch64 (elf.h R_AARCH64_* macros).

/// 64-bit absolute data relocation (S + A).
pub const R_AARCH64_ABS64: i32 = 257;

/// 32-bit absolute data relocation (S + A), truncated to 32 bits.
pub const R_AARCH64_ABS32: i32 = 258;

/// 32-bit PC-relative data relocation (S + A - P).
pub const R_AARCH64_PREL32: i32 = 261;

/// MOVW immediate for bits [15:0] of absolute address, no overflow check.
pub const R_AARCH64_MOVW_UABS_G0_NC: i32 = 263;

/// MOVW immediate for bits [31:16] of absolute address, no overflow check.
pub const R_AARCH64_MOVW_UABS_G1_NC: i32 = 264;

/// MOVW immediate for bits [47:32] of absolute address, no overflow check.
pub const R_AARCH64_MOVW_UABS_G2_NC: i32 = 265;

/// MOVW immediate for bits [63:48] of absolute address.
pub const R_AARCH64_MOVW_UABS_G3: i32 = 266;

/// Page-relative ADRP: computes (page(S+A) - page(P)), ±4GB range.
pub const R_AARCH64_ADR_PREL_PG_HI21: i32 = 275;

/// ADD immediate — low 12 bits of absolute address, no overflow check.
pub const R_AARCH64_ADD_ABS_LO12_NC: i32 = 277;

/// Load/store 8-bit — low 12 bits of absolute address (byte-aligned).
pub const R_AARCH64_LDST8_ABS_LO12_NC: i32 = 278;

/// Branch with link (26-bit signed offset × 4 = ±128MB range).
pub const R_AARCH64_JUMP26: i32 = 282;

/// Unconditional branch (26-bit signed offset × 4 = ±128MB range).
pub const R_AARCH64_CALL26: i32 = 283;

/// Load/store 16-bit — low 12 bits, 2-byte aligned.
pub const R_AARCH64_LDST16_ABS_LO12_NC: i32 = 284;

/// Load/store 32-bit — low 12 bits, 4-byte aligned.
pub const R_AARCH64_LDST32_ABS_LO12_NC: i32 = 285;

/// Load/store 64-bit — low 12 bits, 8-byte aligned.
pub const R_AARCH64_LDST64_ABS_LO12_NC: i32 = 286;

/// Load/store 128-bit — low 12 bits, 16-byte aligned.
pub const R_AARCH64_LDST128_ABS_LO12_NC: i32 = 299;

/// GOT-relative page offset for ADRP: page(GOT(S)) - page(P).
pub const R_AARCH64_ADR_GOT_PAGE: i32 = 311;

/// GOT-relative LDR offset: low 12 bits of GOT entry address (8-byte aligned).
pub const R_AARCH64_LD64_GOT_LO12_NC: i32 = 312;

/// Dynamic: copy symbol at runtime.
pub const R_AARCH64_COPY: i32 = 1024;

/// Dynamic: create GOT entry pointing to symbol address.
pub const R_AARCH64_GLOB_DAT: i32 = 1025;

/// Dynamic: set GOT entry to PLT entry address at runtime.
pub const R_AARCH64_JUMP_SLOT: i32 = 1026;

/// Dynamic: base address + addend (for PIC/PIE relocations).
pub const R_AARCH64_RELATIVE: i32 = 1027;

/// Sentinel: total count of AArch64 relocation types.
pub const R_AARCH64_NUM: i32 = 1028;

// ===========================================================================
// PLT Section Size Constants
// ===========================================================================

/// Size of PLT[0] resolver stub in bytes (8 AArch64 instructions × 4 bytes).
const PLT0_SIZE: usize = 32;

/// Size of each PLT[n] entry in bytes (4 AArch64 instructions × 4 bytes).
const PLT_ENTRY_SIZE: usize = 16;

// ===========================================================================
// Relocation Classification
// ===========================================================================

/// Classify a relocation type as code, data, or unknown.
///
/// Returns:
/// - `0` for data relocations (addresses embedded in data or instruction immediates)
/// - `1` for code relocations (branch targets eligible for PLT interposition)
/// - `-1` for unknown/unsupported relocation types
///
/// Source: `arm64-link.c` lines 27–56, `code_reloc()`.
///
/// # Data Relocations (return 0)
///
/// These encode addresses into data words or instruction immediate fields:
/// `ABS32`, `ABS64`, `PREL32`, `MOVW_UABS_G0–G3_NC`,
/// `ADR_PREL_PG_HI21`, `ADD_ABS_LO12_NC`, `ADR_GOT_PAGE`,
/// `LD64_GOT_LO12_NC`, `LDST8/16/32/64/128_ABS_LO12_NC`,
/// `GLOB_DAT`, `COPY`.
///
/// # Code Relocations (return 1)
///
/// These target branch instructions and may be redirected through PLT:
/// `JUMP26`, `CALL26`, `JUMP_SLOT`.
pub fn code_reloc(reloc_type: i32) -> i32 {
    match reloc_type {
        // Data relocations: absolute/PC-relative address encodings
        R_AARCH64_ABS32
        | R_AARCH64_ABS64
        | R_AARCH64_PREL32
        // Wide immediate move instructions (MOVW G0–G3)
        | R_AARCH64_MOVW_UABS_G0_NC
        | R_AARCH64_MOVW_UABS_G1_NC
        | R_AARCH64_MOVW_UABS_G2_NC
        | R_AARCH64_MOVW_UABS_G3
        // Page-relative addressing (ADRP + ADD/LDR patterns)
        | R_AARCH64_ADR_PREL_PG_HI21
        | R_AARCH64_ADD_ABS_LO12_NC
        // GOT-relative addressing
        | R_AARCH64_ADR_GOT_PAGE
        | R_AARCH64_LD64_GOT_LO12_NC
        // Load/store offset relocations (byte/half/word/double/quad)
        | R_AARCH64_LDST128_ABS_LO12_NC
        | R_AARCH64_LDST64_ABS_LO12_NC
        | R_AARCH64_LDST32_ABS_LO12_NC
        | R_AARCH64_LDST16_ABS_LO12_NC
        | R_AARCH64_LDST8_ABS_LO12_NC
        // Dynamic data relocations
        | R_AARCH64_GLOB_DAT
        | R_AARCH64_COPY => 0,

        // Code relocations: branch instructions
        R_AARCH64_JUMP26
        | R_AARCH64_CALL26
        | R_AARCH64_JUMP_SLOT => 1,

        // Unknown relocation type
        _ => -1,
    }
}

// ===========================================================================
// GOT/PLT Entry Type Classification
// ===========================================================================

/// Determine GOT/PLT entry requirements for a given relocation type.
///
/// Returns one of the GOT/PLT entry type constants:
/// - [`NO_GOTPLT_ENTRY`] — No GOT or PLT entry needed.
/// - [`AUTO_GOTPLT_ENTRY`] — Generate entry only if symbol is undefined.
/// - [`ALWAYS_GOTPLT_ENTRY`] — Always generate a GOT entry.
/// - `-1` — Unknown relocation type.
///
/// Source: `arm64-link.c` lines 61–92, `gotplt_entry_type()`.
///
/// # Entry Requirements by Relocation Type
///
/// **NO_GOTPLT_ENTRY**: PC-relative and load/store relocations that encode
/// the symbol address directly into the instruction:
/// `PREL32`, `MOVW_UABS_G0–G3`, `ADR_PREL_PG_HI21`, `ADD_ABS_LO12_NC`,
/// `LDST8/16/32/64/128_ABS_LO12_NC`, `GLOB_DAT`, `JUMP_SLOT`, `COPY`.
///
/// **AUTO_GOTPLT_ENTRY**: Absolute data and branch relocations where a
/// PLT stub may be needed for undefined symbols in shared libraries:
/// `ABS32`, `ABS64`, `JUMP26`, `CALL26`.
///
/// **ALWAYS_GOTPLT_ENTRY**: GOT-relative addressing that *always*
/// requires a GOT entry to hold the symbol's resolved address:
/// `ADR_GOT_PAGE`, `LD64_GOT_LO12_NC`.
pub fn gotplt_entry_type(reloc_type: i32) -> i32 {
    match reloc_type {
        // No GOT/PLT entry — address encoded directly
        R_AARCH64_PREL32
        | R_AARCH64_MOVW_UABS_G0_NC
        | R_AARCH64_MOVW_UABS_G1_NC
        | R_AARCH64_MOVW_UABS_G2_NC
        | R_AARCH64_MOVW_UABS_G3
        | R_AARCH64_ADR_PREL_PG_HI21
        | R_AARCH64_ADD_ABS_LO12_NC
        | R_AARCH64_LDST128_ABS_LO12_NC
        | R_AARCH64_LDST64_ABS_LO12_NC
        | R_AARCH64_LDST32_ABS_LO12_NC
        | R_AARCH64_LDST16_ABS_LO12_NC
        | R_AARCH64_LDST8_ABS_LO12_NC
        | R_AARCH64_GLOB_DAT
        | R_AARCH64_JUMP_SLOT
        | R_AARCH64_COPY => NO_GOTPLT_ENTRY,

        // Auto-detect: generate entry if symbol is undefined
        R_AARCH64_ABS32
        | R_AARCH64_ABS64
        | R_AARCH64_JUMP26
        | R_AARCH64_CALL26 => AUTO_GOTPLT_ENTRY,

        // Always generate GOT entry for indirect addressing
        R_AARCH64_ADR_GOT_PAGE
        | R_AARCH64_LD64_GOT_LO12_NC => ALWAYS_GOTPLT_ENTRY,

        // Unknown relocation type
        _ => -1,
    }
}

// ===========================================================================
// PLT Entry Generation
// ===========================================================================

/// Create a PLT entry for dynamic symbol resolution.
///
/// Allocates PLT\[0\] (32 bytes, resolver stub) on the first call, then
/// allocates a 16-byte PLT\[n\] entry. The GOT offset is stored as a
/// 64-bit little-endian value in the entry; the actual ADRP+LDR+ADD+BR
/// instruction sequence is written later by [`relocate_plt`] once final
/// virtual addresses are known.
///
/// # Arguments
/// * `plt_data` — Mutable reference to PLT section data buffer.
/// * `plt_data_offset` — Current size of PLT data; updated on return.
/// * `got_offset` — GOT offset for this symbol's entry.
///
/// # Returns
/// The byte offset of the newly created PLT entry within the PLT section.
///
/// Source: `arm64-link.c` lines 95–110, `create_plt_entry()`.
pub fn create_plt_entry(
    plt_data: &mut Vec<u8>,
    plt_data_offset: &mut usize,
    got_offset: u32,
) -> u32 {
    // Reserve PLT[0] resolver stub (32 bytes) on first call.
    // The actual instructions are filled in by relocate_plt().
    if *plt_data_offset == 0 {
        plt_data.resize(PLT0_SIZE, 0);
        *plt_data_offset = PLT0_SIZE;
    }

    // Record the offset of this new entry
    let plt_offset = *plt_data_offset;

    // Allocate 16 bytes for PLT[n]
    plt_data.resize(plt_offset + PLT_ENTRY_SIZE, 0);
    *plt_data_offset = plt_offset + PLT_ENTRY_SIZE;

    // Store the GOT offset as a 64-bit little-endian value.
    // relocate_plt() reads this back to compute the absolute GOT address.
    write64le(&mut plt_data[plt_offset..], got_offset as u64);

    plt_offset as u32
}

// ===========================================================================
// PLT Fixup
// ===========================================================================

/// Encode an ADRP immediate offset into instruction bits.
///
/// The ADRP instruction encodes a 21-bit signed page offset as:
/// - `immhi` (bits\[23:5\]) = offset bits\[20:2\] shifted left by 3
/// - `immlo` (bits\[30:29\]) = offset bits\[1:0\] shifted left by 29
///
/// The mask `0x9f00001f` preserves sf(31), op(28:24=10000), Rd(4:0)
/// and clears the immediate fields for replacement.
#[inline]
fn encode_adrp_imm(base_insn: u32, page_off: u64) -> u32 {
    let off = page_off as u32;
    (base_insn & 0x9f00_001f)
        | ((off & 0x1f_fffc) << 3)
        | ((off & 0x3) << 29)
}

/// Fix up all PLT entries with actual AArch64 instruction sequences.
///
/// Called during the output phase once section virtual addresses are assigned.
/// Writes the resolver stub into PLT\[0\] and per-symbol stubs into PLT\[n\].
///
/// # PLT\[0\] Layout (32 bytes, 8 instructions)
///
/// ```text
/// +0:  stp   x16, x30, [sp, #-16]!    // 0xa9bf7bf0
/// +4:  adrp  x16, GOT+16@page         // page(GOT+16) - page(PLT)
/// +8:  ldr   x17, [x16, #GOT+16@lo12] // GOT[2] = resolver address
/// +12: add   x16, x16, #GOT+16@lo12   // GOT[2] page-offset
/// +16: br    x17                       // jump to resolver
/// +20: nop
/// +24: nop
/// +28: nop
/// ```
///
/// # PLT\[n\] Layout (16 bytes, 4 instructions)
///
/// ```text
/// +0:  adrp  x16, GOT_entry@page      // page(GOT[sym]) - page(PC)
/// +4:  ldr   x17, [x16, #GOT_entry@lo12]
/// +8:  add   x16, x16, #GOT_entry@lo12
/// +12: br    x17
/// ```
///
/// # GOT-to-PLT Fixup
///
/// If the PLT section has an associated relocation section, each
/// relocation's `r_offset` in the GOT is set to `plt_sh_addr`
/// (the PLT base) for lazy resolution.
///
/// Source: `arm64-link.c` lines 114-167, `relocate_plt()`.
pub fn relocate_plt(
    plt_data: &mut [u8],
    plt_data_offset: usize,
    plt_sh_addr: u64,
    got_sh_addr: u64,
    got_data: Option<&mut [u8]>,
    plt_reloc_data: Option<&[u8]>,
    plt_reloc_data_offset: usize,
) -> TccResult<()> {
    // Nothing to do if PLT is empty
    if plt_data_offset == 0 {
        return Ok(());
    }

    // ---- PLT[0]: Resolver stub (32 bytes) ----
    //
    // GOT+16 points to the third GOT entry (GOT[2]), which the dynamic
    // linker fills with the address of its resolver function.
    let plt_base = plt_sh_addr;
    let got_resolver = got_sh_addr.wrapping_add(16); // GOT[2]

    // Page-relative offset: page(GOT+16) - page(PLT)
    let off = (got_resolver >> 12).wrapping_sub(plt_base >> 12);

    // Range check: ADRP has a +/-1MB page range (21-bit signed)
    if off.wrapping_add(1u64 << 20) >> 21 != 0 {
        return Err(TccError::LinkerError {
            message: "Failed relocating PLT (PLT0 ADRP out of range)".to_string(),
        });
    }

    // Low 12 bits of the GOT+16 address (for LDR and ADD offsets)
    let got_lo = got_resolver & 0xfff;

    // stp x16, x30, [sp, #-16]!   -- save x16 and link register
    write32le(&mut plt_data[0..], 0xa9bf_7bf0);

    // adrp x16, GOT+16@page       -- load page address of GOT[2]
    write32le(&mut plt_data[4..], encode_adrp_imm(0x9000_0010, off));

    // ldr x17, [x16, #GOT+16@lo12] -- load resolver from GOT[2]
    // LDR X encoding: imm12 at bits[21:10], 8-byte aligned -> (lo & 0xff8) << 7
    write32le(
        &mut plt_data[8..],
        0xf940_0211 | (((got_lo & 0xff8) as u32) << 7),
    );

    // add x16, x16, #GOT+16@lo12  -- full address of GOT[2]
    // ADD X encoding: imm12 at bits[21:10] -> (lo & 0xfff) << 10
    write32le(
        &mut plt_data[12..],
        0x9100_0210 | (((got_lo & 0xfff) as u32) << 10),
    );

    // br x17                       -- jump to resolver
    write32le(&mut plt_data[16..], 0xd61f_0220);

    // Three NOPs to pad PLT[0] to 32 bytes
    write32le(&mut plt_data[20..], 0xd503_201f);
    write32le(&mut plt_data[24..], 0xd503_201f);
    write32le(&mut plt_data[28..], 0xd503_201f);

    // ---- PLT[n]: Per-symbol stubs (16 bytes each) ----
    //
    // For each entry, read the stored 64-bit GOT offset, compute the
    // absolute GOT entry address, and write the ADRP+LDR+ADD+BR sequence.
    // NOTE: got_sh_addr is used directly (NOT got_sh_addr+16).
    let mut p = PLT0_SIZE;
    while p < plt_data_offset {
        let pc = plt_base.wrapping_add(p as u64);

        // Read the stored GOT offset (written by create_plt_entry)
        let stored_got_offset = read64le(&plt_data[p..]);
        let addr_got = got_sh_addr.wrapping_add(stored_got_offset);

        // Page-relative offset for ADRP
        let entry_off = (addr_got >> 12).wrapping_sub(pc >> 12);

        // Range check: +/-1MB page offset (21-bit signed)
        if entry_off.wrapping_add(1u64 << 20) >> 21 != 0 {
            return Err(TccError::LinkerError {
                message: format!(
                    "Failed relocating PLT (entry at offset {} ADRP out of range)",
                    p
                ),
            });
        }

        let addr_lo = addr_got & 0xfff;

        // adrp x16, GOT_entry@page
        write32le(&mut plt_data[p..], encode_adrp_imm(0x9000_0010, entry_off));

        // ldr x17, [x16, #GOT_entry@lo12]  (8-byte aligned)
        write32le(
            &mut plt_data[p + 4..],
            0xf940_0211 | (((addr_lo & 0xff8) as u32) << 7),
        );

        // add x16, x16, #GOT_entry@lo12
        write32le(
            &mut plt_data[p + 8..],
            0x9100_0210 | (((addr_lo & 0xfff) as u32) << 10),
        );

        // br x17
        write32le(&mut plt_data[p + 12..], 0xd61f_0220);

        p += PLT_ENTRY_SIZE;
    }

    // ---- GOT->PLT fixup ----
    //
    // If the PLT has relocation entries (from .rela.plt), write the PLT
    // base address into each referenced GOT slot for lazy binding.
    // Source: arm64-link.c lines 160-166.
    if let (Some(got_d), Some(reloc_d)) = (got_data, plt_reloc_data) {
        let rela_size: usize = 24; // sizeof(Elf64_Rela) = 8 + 8 + 8
        let mut i = 0;
        while i + rela_size <= plt_reloc_data_offset {
            // Read r_offset (first 8 bytes of Elf64_Rela)
            let r_offset = u64::from_le_bytes([
                reloc_d[i],
                reloc_d[i + 1],
                reloc_d[i + 2],
                reloc_d[i + 3],
                reloc_d[i + 4],
                reloc_d[i + 5],
                reloc_d[i + 6],
                reloc_d[i + 7],
            ]) as usize;

            // Write PLT base address into the GOT slot
            if r_offset + 8 <= got_d.len() {
                write64le(&mut got_d[r_offset..], plt_sh_addr);
            }

            i += rela_size;
        }
    }

    Ok(())
}

// ===========================================================================
// Main Relocation Application
// ===========================================================================

/// Apply a single AArch64 relocation to instruction or data bytes.
///
/// This handles the "basic" relocation types that can be resolved with
/// only the relocation type, the target byte slice, the relocation site
/// virtual address, and the resolved symbol value. GOT-relative types
/// (`ADR_GOT_PAGE`, `LD64_GOT_LO12_NC`) and dynamic relocation emission
/// (`ABS64` in DLL/PIE mode) require extended context — see the linker
/// integration in `elf.rs` for how those are handled.
///
/// # Arguments
/// * `rel_type` — AArch64 relocation type (one of the `R_AARCH64_*` constants).
/// * `ptr` — Mutable byte slice at the relocation site (instruction or data).
/// * `addr` — Virtual address of the relocation site.
/// * `val` — Fully resolved symbol value: symbol_address + addend.
///
/// # Relocation Types Handled
///
/// | Type | Encoding | Formula |
/// |------|----------|---------|
/// | `ABS64` | 64-bit data | `*ptr += val` |
/// | `ABS32` | 32-bit data | `*ptr += val` (truncated) |
/// | `PREL32` | 32-bit data | `*ptr += val - addr` |
/// | `MOVW_UABS_G0_NC` | imm16\[15:0\] | `val[15:0] << 5` |
/// | `MOVW_UABS_G1_NC` | imm16\[31:16\] | `(val>>16)[15:0] << 5` |
/// | `MOVW_UABS_G2_NC` | imm16\[47:32\] | `(val>>32)[15:0] << 5` |
/// | `MOVW_UABS_G3` | imm16\[63:48\] | `(val>>48)[15:0] << 5` |
/// | `ADR_PREL_PG_HI21` | ADRP imm21 | page offset, ±4GB |
/// | `ADD_ABS_LO12_NC` | imm12 | `val[11:0] << 10` |
/// | `LDST8_ABS_LO12_NC` | imm12 | `val[11:0] << 10` |
/// | `LDST16_ABS_LO12_NC` | imm12 | `val[11:1] << 9` |
/// | `LDST32_ABS_LO12_NC` | imm12 | `val[11:2] << 8` |
/// | `LDST64_ABS_LO12_NC` | imm12 | `val[11:3] << 7` |
/// | `LDST128_ABS_LO12_NC` | imm12 | `val[11:4] << 6` |
/// | `JUMP26` | 26-bit offset | B `(val-addr)>>2`, ±128MB |
/// | `CALL26` | 26-bit offset | BL `(val-addr)>>2`, ±128MB |
/// | `COPY` | none | no-op |
/// | `GLOB_DAT` | 64-bit data | `val - addend` |
/// | `JUMP_SLOT` | 64-bit data | `val - addend` |
/// | `RELATIVE` | platform-dependent | ELF no-op, PE adjusts by imagebase |
///
/// Source: `arm64-link.c` lines 171-320, `relocate()`.
pub fn relocate(
    rel_type: i32,
    ptr: &mut [u8],
    addr: u64,
    val: u64,
    addend: i64,
) -> TccResult<()> {
    match rel_type {
        // =================================================================
        // 64-bit absolute data relocation: *ptr += val
        // For dynamic output, the ELF module handles emission of dynamic
        // R_AARCH64_ABS64 / R_AARCH64_RELATIVE relocations before calling
        // this function, so the static fixup is always applied.
        // Source: arm64-link.c lines 179-195.
        // =================================================================
        R_AARCH64_ABS64 => {
            add64le(ptr, val as i64);
            Ok(())
        }

        // =================================================================
        // 32-bit absolute data relocation: *ptr += val (truncated)
        // Source: arm64-link.c lines 196-207.
        // =================================================================
        R_AARCH64_ABS32 => {
            add32le(ptr, val as i32);
            Ok(())
        }

        // =================================================================
        // 32-bit PC-relative data relocation: *ptr += (val - addr)
        // Source: arm64-link.c lines 208-222.
        // =================================================================
        R_AARCH64_PREL32 => {
            add32le(ptr, val.wrapping_sub(addr) as i32);
            Ok(())
        }

        // =================================================================
        // MOVW wide immediate relocations (G0-G3)
        //
        // Each extracts a 16-bit slice of the 64-bit value and encodes it
        // into the MOVZ/MOVK instruction's imm16 field (bits[20:5]).
        // Mask 0xffe0001f preserves: sf(31), opc(30:29), op(28:23=100101),
        // hw(22:21), Rd(4:0) — clears imm16.
        //
        // Source: arm64-link.c lines 223-238.
        // =================================================================
        R_AARCH64_MOVW_UABS_G0_NC => {
            // Bits [15:0] of val
            write32le(
                ptr,
                (read32le(ptr) & 0xffe0_001f) | (((val & 0xffff) as u32) << 5),
            );
            Ok(())
        }

        R_AARCH64_MOVW_UABS_G1_NC => {
            // Bits [31:16] of val
            write32le(
                ptr,
                (read32le(ptr) & 0xffe0_001f) | ((((val >> 16) & 0xffff) as u32) << 5),
            );
            Ok(())
        }

        R_AARCH64_MOVW_UABS_G2_NC => {
            // Bits [47:32] of val
            write32le(
                ptr,
                (read32le(ptr) & 0xffe0_001f) | ((((val >> 32) & 0xffff) as u32) << 5),
            );
            Ok(())
        }

        R_AARCH64_MOVW_UABS_G3 => {
            // Bits [63:48] of val
            write32le(
                ptr,
                (read32le(ptr) & 0xffe0_001f) | ((((val >> 48) & 0xffff) as u32) << 5),
            );
            Ok(())
        }

        // =================================================================
        // ADRP: Page-relative addressing
        //
        // Computes the 4KB-page-aligned offset from the relocation site to
        // the target: off = page(val) - page(addr).
        // The 21-bit signed page offset is encoded as:
        //   immhi = off[20:2] at instruction bits[23:5]
        //   immlo = off[1:0] at instruction bits[30:29]
        // Range: +/-4GB (2^21 * 4096 bytes).
        //
        // Source: arm64-link.c lines 239-246.
        // =================================================================
        R_AARCH64_ADR_PREL_PG_HI21 => {
            let off = (val >> 12).wrapping_sub(addr >> 12);
            // Range check: 21-bit signed offset
            if off.wrapping_add(1u64 << 20) >> 21 != 0 {
                return Err(TccError::LinkerError {
                    message: format!(
                        "R_AARCH64_ADR_PREL_PG_HI21 relocation failed: \
                         offset {:#x} out of +/-1MB page range (addr={:#x}, val={:#x})",
                        off, addr, val
                    ),
                });
            }
            write32le(ptr, encode_adrp_imm(read32le(ptr), off));
            Ok(())
        }

        // =================================================================
        // ADD/LDST immediate relocations: low 12 bits of address
        //
        // ADD_ABS_LO12_NC and LDST8_ABS_LO12_NC both encode the full
        // 12-bit offset in the imm12 field (bits[21:10]) — no implicit
        // shift because byte-sized access has no alignment requirement.
        // Mask 0xffc003ff preserves opcode, Rn, Rd and clears imm12.
        //
        // Source: arm64-link.c lines 247-251.
        // =================================================================
        R_AARCH64_ADD_ABS_LO12_NC | R_AARCH64_LDST8_ABS_LO12_NC => {
            write32le(
                ptr,
                (read32le(ptr) & 0xffc0_03ff) | (((val & 0xfff) as u32) << 10),
            );
            Ok(())
        }

        // =================================================================
        // LDST16: 16-bit load/store, 2-byte aligned
        //
        // Implicit 1-bit right shift: bit[0] of offset is guaranteed zero
        // by alignment. Extract val[11:1] and place at bits[21:10].
        // val & 0xffe masks to 2-byte-aligned, shift 9 = 10 - 1.
        //
        // Source: arm64-link.c lines 252-255.
        // =================================================================
        R_AARCH64_LDST16_ABS_LO12_NC => {
            write32le(
                ptr,
                (read32le(ptr) & 0xffc0_03ff) | (((val & 0xffe) as u32) << 9),
            );
            Ok(())
        }

        // =================================================================
        // LDST32: 32-bit load/store, 4-byte aligned
        //
        // Implicit 2-bit right shift: val[11:2] placed at bits[21:10].
        // val & 0xffc masks to 4-byte-aligned, shift 8 = 10 - 2.
        //
        // Source: arm64-link.c lines 256-259.
        // =================================================================
        R_AARCH64_LDST32_ABS_LO12_NC => {
            write32le(
                ptr,
                (read32le(ptr) & 0xffc0_03ff) | (((val & 0xffc) as u32) << 8),
            );
            Ok(())
        }

        // =================================================================
        // LDST64: 64-bit load/store, 8-byte aligned
        //
        // Implicit 3-bit right shift: val[11:3] placed at bits[21:10].
        // val & 0xff8 masks to 8-byte-aligned, shift 7 = 10 - 3.
        //
        // Source: arm64-link.c lines 260-263.
        // =================================================================
        R_AARCH64_LDST64_ABS_LO12_NC => {
            write32le(
                ptr,
                (read32le(ptr) & 0xffc0_03ff) | (((val & 0xff8) as u32) << 7),
            );
            Ok(())
        }

        // =================================================================
        // LDST128: 128-bit load/store (SIMD), 16-byte aligned
        //
        // Implicit 4-bit right shift: val[11:4] placed at bits[21:10].
        // val & 0xff0 masks to 16-byte-aligned, shift 6 = 10 - 4.
        //
        // Source: arm64-link.c lines 264-267.
        // =================================================================
        R_AARCH64_LDST128_ABS_LO12_NC => {
            write32le(
                ptr,
                (read32le(ptr) & 0xffc0_03ff) | (((val & 0xff0) as u32) << 6),
            );
            Ok(())
        }

        // =================================================================
        // Branch relocations: B (JUMP26) and BL (CALL26)
        //
        // Both encode a 26-bit signed word offset for +/-128MB range.
        // The offset is (val - addr) >> 2 (word-aligned).
        //
        // IMPORTANT: Unlike most relocations, this writes the ENTIRE
        // instruction word, not a read-modify-write. The opcode base is
        // 0x14000000 (B unconditional), with bit[31] set for BL (CALL26).
        //
        // Source: arm64-link.c lines 268-280.
        // =================================================================
        R_AARCH64_JUMP26 | R_AARCH64_CALL26 => {
            let diff = val.wrapping_sub(addr);
            // Range check: +/-128MB (28-bit signed, but encoded as 26 bits * 4)
            if diff.wrapping_add(1u64 << 27) & !0x0fff_fffc_u64 != 0 {
                return Err(TccError::LinkerError {
                    message: format!(
                        "R_AARCH64_{} relocation failed: \
                         branch offset {:#x} out of +/-128MB range (addr={:#x}, val={:#x})",
                        if rel_type == R_AARCH64_CALL26 { "CALL26" } else { "JUMP26" },
                        diff,
                        addr,
                        val
                    ),
                });
            }
            // bit[31] = 1 for BL (CALL26), 0 for B (JUMP26)
            let is_call = if rel_type == R_AARCH64_CALL26 { 1u32 } else { 0u32 };
            write32le(
                ptr,
                0x1400_0000
                    | (is_call << 31)
                    | ((diff >> 2) as u32 & 0x03ff_ffff),
            );
            Ok(())
        }

        // =================================================================
        // GOT-relative relocations: require extended context (GOT address,
        // symbol GOT offset). The ELF linker module handles these by
        // computing the correct val before calling relocate(), or by using
        // an extended relocation path. When called directly, treat them
        // as the same ADRP / LDR pattern but with val being the GOT entry
        // address already computed by the caller.
        //
        // ADR_GOT_PAGE: same ADRP encoding as ADR_PREL_PG_HI21 but
        //   targeting the GOT entry address instead of the symbol itself.
        //
        // Source: arm64-link.c lines 281-296.
        // =================================================================
        R_AARCH64_ADR_GOT_PAGE => {
            // val is expected to be the GOT entry address when this path
            // is reached through the basic interface. Compute page offset.
            let off = (val >> 12).wrapping_sub(addr >> 12);
            if off.wrapping_add(1u64 << 20) >> 21 != 0 {
                return Err(TccError::LinkerError {
                    message: format!(
                        "R_AARCH64_ADR_GOT_PAGE relocation failed: \
                         page offset {:#x} out of range (addr={:#x}, val={:#x})",
                        off, addr, val
                    ),
                });
            }
            write32le(ptr, encode_adrp_imm(read32le(ptr), off));
            Ok(())
        }

        R_AARCH64_LD64_GOT_LO12_NC => {
            // val is the GOT entry address. Encode low 12 bits for LDR X.
            // Note: mask is 0xfff803ff (NOT 0xffc003ff) — this is the LDR
            // register format which has a narrower immediate field encoding
            // for 8-byte-aligned access.
            write32le(
                ptr,
                (read32le(ptr) & 0xfff8_03ff) | (((val & 0xff8) as u32) << 7),
            );
            Ok(())
        }

        // =================================================================
        // COPY: No action needed. The dynamic linker handles this at
        // runtime by copying the symbol data.
        // Source: arm64-link.c lines 297-298.
        // =================================================================
        R_AARCH64_COPY => Ok(()),

        // =================================================================
        // GLOB_DAT and JUMP_SLOT: Write the symbol address directly.
        //
        // These dynamic relocations set GOT entries to the resolved symbol
        // address. The caller passes `val = sym_value + addend`, but the GOT
        // entry should store just the symbol address. The C code
        // (`arm64-link.c` lines 299-308) computes `write64le(ptr, val -
        // rel->r_addend)` to strip the addend. For typical GLOB_DAT/
        // JUMP_SLOT the addend is 0, so `val - 0 = val`, but addend-bearing
        // relocations require the subtraction.
        //
        // Source: arm64-link.c lines 299-308.
        // =================================================================
        R_AARCH64_GLOB_DAT | R_AARCH64_JUMP_SLOT => {
            // Write `val - addend` = raw symbol address.
            write64le(ptr, (val as i64 - addend) as u64);
            Ok(())
        }

        // =================================================================
        // RELATIVE: Base address adjustment.
        //
        // For ELF targets, this is a no-op at static link time (the dynamic
        // linker applies the base adjustment at load time).
        //
        // For PE targets, the adjustment would be val - pe_imagebase, but
        // PE/COFF handling is in a separate module.
        //
        // Source: arm64-link.c lines 309-314.
        // =================================================================
        R_AARCH64_RELATIVE => {
            // ELF: no-op — dynamic linker handles at load time
            Ok(())
        }

        // =================================================================
        // Unknown relocation type: log a warning and continue.
        //
        // The C code uses fprintf + return (non-fatal), matching TCC's
        // tolerant approach to unrecognized relocations.
        //
        // Source: arm64-link.c lines 315-318.
        // =================================================================
        _ => {
            // Non-fatal: log and continue (matching C behavior)
            #[cfg(debug_assertions)]
            eprintln!(
                "arm64 link: unhandled reloc type {:#x} at addr {:#x}, val {:#x}",
                rel_type, addr, val
            );
            Ok(())
        }
    }
}

// ===========================================================================
// Unit Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // code_reloc tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_code_reloc_data_types() {
        // All data relocation types must return 0
        let data_types = [
            R_AARCH64_ABS32,
            R_AARCH64_ABS64,
            R_AARCH64_PREL32,
            R_AARCH64_MOVW_UABS_G0_NC,
            R_AARCH64_MOVW_UABS_G1_NC,
            R_AARCH64_MOVW_UABS_G2_NC,
            R_AARCH64_MOVW_UABS_G3,
            R_AARCH64_ADR_PREL_PG_HI21,
            R_AARCH64_ADD_ABS_LO12_NC,
            R_AARCH64_ADR_GOT_PAGE,
            R_AARCH64_LD64_GOT_LO12_NC,
            R_AARCH64_LDST128_ABS_LO12_NC,
            R_AARCH64_LDST64_ABS_LO12_NC,
            R_AARCH64_LDST32_ABS_LO12_NC,
            R_AARCH64_LDST16_ABS_LO12_NC,
            R_AARCH64_LDST8_ABS_LO12_NC,
            R_AARCH64_GLOB_DAT,
            R_AARCH64_COPY,
        ];
        for t in &data_types {
            assert_eq!(
                code_reloc(*t),
                0,
                "code_reloc({}) should be 0 (data)",
                t
            );
        }
    }

    #[test]
    fn test_code_reloc_code_types() {
        // All code relocation types must return 1
        let code_types = [
            R_AARCH64_JUMP26,
            R_AARCH64_CALL26,
            R_AARCH64_JUMP_SLOT,
        ];
        for t in &code_types {
            assert_eq!(
                code_reloc(*t),
                1,
                "code_reloc({}) should be 1 (code)",
                t
            );
        }
    }

    #[test]
    fn test_code_reloc_unknown() {
        assert_eq!(code_reloc(0), -1);
        assert_eq!(code_reloc(9999), -1);
        assert_eq!(code_reloc(-1), -1);
    }

    // -----------------------------------------------------------------------
    // gotplt_entry_type tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_gotplt_no_entry_types() {
        let no_entry_types = [
            R_AARCH64_PREL32,
            R_AARCH64_MOVW_UABS_G0_NC,
            R_AARCH64_MOVW_UABS_G1_NC,
            R_AARCH64_MOVW_UABS_G2_NC,
            R_AARCH64_MOVW_UABS_G3,
            R_AARCH64_ADR_PREL_PG_HI21,
            R_AARCH64_ADD_ABS_LO12_NC,
            R_AARCH64_LDST128_ABS_LO12_NC,
            R_AARCH64_LDST64_ABS_LO12_NC,
            R_AARCH64_LDST32_ABS_LO12_NC,
            R_AARCH64_LDST16_ABS_LO12_NC,
            R_AARCH64_LDST8_ABS_LO12_NC,
            R_AARCH64_GLOB_DAT,
            R_AARCH64_JUMP_SLOT,
            R_AARCH64_COPY,
        ];
        for t in &no_entry_types {
            assert_eq!(
                gotplt_entry_type(*t),
                NO_GOTPLT_ENTRY,
                "gotplt_entry_type({}) should be NO_GOTPLT_ENTRY",
                t
            );
        }
    }

    #[test]
    fn test_gotplt_auto_entry_types() {
        let auto_types = [
            R_AARCH64_ABS32,
            R_AARCH64_ABS64,
            R_AARCH64_JUMP26,
            R_AARCH64_CALL26,
        ];
        for t in &auto_types {
            assert_eq!(
                gotplt_entry_type(*t),
                AUTO_GOTPLT_ENTRY,
                "gotplt_entry_type({}) should be AUTO_GOTPLT_ENTRY",
                t
            );
        }
    }

    #[test]
    fn test_gotplt_always_entry_types() {
        let always_types = [
            R_AARCH64_ADR_GOT_PAGE,
            R_AARCH64_LD64_GOT_LO12_NC,
        ];
        for t in &always_types {
            assert_eq!(
                gotplt_entry_type(*t),
                ALWAYS_GOTPLT_ENTRY,
                "gotplt_entry_type({}) should be ALWAYS_GOTPLT_ENTRY",
                t
            );
        }
    }

    #[test]
    fn test_gotplt_unknown() {
        assert_eq!(gotplt_entry_type(0), -1);
        assert_eq!(gotplt_entry_type(9999), -1);
    }

    // -----------------------------------------------------------------------
    // create_plt_entry tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_create_plt_entry_first() {
        let mut data = Vec::new();
        let mut offset = 0usize;
        let plt_off = create_plt_entry(&mut data, &mut offset, 0x100);

        // First entry should be at PLT0_SIZE (32)
        assert_eq!(plt_off, 32);
        // Total size should be PLT0 (32) + entry (16) = 48
        assert_eq!(offset, 48);
        assert_eq!(data.len(), 48);

        // Verify stored GOT offset
        assert_eq!(read64le(&data[32..]), 0x100);
    }

    #[test]
    fn test_create_plt_entry_second() {
        let mut data = Vec::new();
        let mut offset = 0usize;
        let first = create_plt_entry(&mut data, &mut offset, 0x100);
        let second = create_plt_entry(&mut data, &mut offset, 0x200);

        assert_eq!(first, 32);
        assert_eq!(second, 48);
        assert_eq!(offset, 64);
        assert_eq!(read64le(&data[32..]), 0x100);
        assert_eq!(read64le(&data[48..]), 0x200);
    }

    #[test]
    fn test_create_plt_entry_plt0_reserved() {
        let mut data = Vec::new();
        let mut offset = 0usize;
        let _ = create_plt_entry(&mut data, &mut offset, 0x20);

        // PLT[0] should be all zeros (reserved for relocate_plt to fill)
        for i in 0..32 {
            assert_eq!(data[i], 0, "PLT0 byte {} should be zero", i);
        }
    }

    // -----------------------------------------------------------------------
    // relocate_plt tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_relocate_plt_empty() {
        let result = relocate_plt(&mut [], 0, 0, 0, None, None, 0);
        assert!(result.is_ok());
    }

    #[test]
    fn test_relocate_plt_basic() {
        // Create a PLT with one entry
        let mut data = Vec::new();
        let mut offset = 0usize;
        let _ = create_plt_entry(&mut data, &mut offset, 0x18); // GOT offset 24

        // PLT at 0x401000, GOT at 0x403000 (same page distance)
        let plt_addr: u64 = 0x401000;
        let got_addr: u64 = 0x403000;

        let result = relocate_plt(
            &mut data,
            offset,
            plt_addr,
            got_addr,
            None,
            None,
            0,
        );
        assert!(result.is_ok());

        // Verify PLT[0] first instruction: stp x16, x30, [sp, #-16]!
        assert_eq!(read32le(&data[0..]), 0xa9bf_7bf0);

        // Verify PLT[0] br x17 at offset 16
        assert_eq!(read32le(&data[16..]), 0xd61f_0220);

        // Verify PLT[0] NOPs at offsets 20, 24, 28
        assert_eq!(read32le(&data[20..]), 0xd503_201f);
        assert_eq!(read32le(&data[24..]), 0xd503_201f);
        assert_eq!(read32le(&data[28..]), 0xd503_201f);

        // Verify PLT[n] br x17 at entry offset + 12
        assert_eq!(read32le(&data[32 + 12..]), 0xd61f_0220);
    }

    #[test]
    fn test_relocate_plt_got_fixup() {
        // Create a PLT entry
        let mut plt_data = Vec::new();
        let mut plt_offset = 0usize;
        let _ = create_plt_entry(&mut plt_data, &mut plt_offset, 0x18);

        let plt_addr: u64 = 0x401000;
        let got_addr: u64 = 0x403000;

        // Create GOT data (big enough)
        let mut got_data = vec![0u8; 0x100];

        // Create relocation entry pointing to GOT offset 0x18
        let mut reloc_data = vec![0u8; 24]; // sizeof(Elf64_Rela)
        // r_offset = 0x18 (where in GOT to write)
        write64le(&mut reloc_data[0..], 0x18);

        let result = relocate_plt(
            &mut plt_data,
            plt_offset,
            plt_addr,
            got_addr,
            Some(&mut got_data),
            Some(&reloc_data),
            24,
        );
        assert!(result.is_ok());

        // Verify GOT[0x18] was set to plt_addr
        assert_eq!(read64le(&got_data[0x18..]), plt_addr);
    }

    // -----------------------------------------------------------------------
    // encode_adrp_imm tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_encode_adrp_zero_offset() {
        // ADRP x16 with zero offset should preserve only Rd and opcode bits
        let insn = encode_adrp_imm(0x9000_0010, 0);
        // Rd=x16=0x10, sf=1, op=10000, zero immediate
        assert_eq!(insn & 0x9f00_001f, 0x9000_0010);
        // Immediate fields should be zero
        assert_eq!(insn & !0x9f00_001f, 0);
    }

    #[test]
    fn test_encode_adrp_positive_offset() {
        // page offset = 1 -> immlo=1, immhi=0
        let insn = encode_adrp_imm(0x9000_0010, 1);
        // immlo (bits[30:29]) should be 1 << 29
        assert_eq!(insn & (0x3 << 29), 1 << 29);
    }

    #[test]
    fn test_encode_adrp_offset_2() {
        // page offset = 2 -> immlo=2, immhi=0
        let insn = encode_adrp_imm(0x9000_0010, 2);
        assert_eq!(insn & (0x3 << 29), 2 << 29);
    }

    #[test]
    fn test_encode_adrp_offset_4() {
        // page offset = 4 -> immlo=0, immhi=1
        let insn = encode_adrp_imm(0x9000_0010, 4);
        // immhi bits start at bit 5, value 1 -> 0x4 << 3 = 0x20
        assert_eq!(insn & (0x1f_fffc << 3), 4 << 3);
        assert_eq!(insn & (0x3 << 29), 0);
    }

    // -----------------------------------------------------------------------
    // relocate tests — individual relocation types
    // -----------------------------------------------------------------------

    #[test]
    fn test_relocate_abs64() {
        let mut buf = [0u8; 8];
        write64le(&mut buf, 100);
        relocate(R_AARCH64_ABS64, &mut buf, 0, 42, 0).unwrap();
        assert_eq!(read64le(&buf), 142); // 100 + 42
    }

    #[test]
    fn test_relocate_abs64_wrapping() {
        let mut buf = [0u8; 8];
        write64le(&mut buf, u64::MAX);
        relocate(R_AARCH64_ABS64, &mut buf, 0, 1, 0).unwrap();
        assert_eq!(read64le(&buf), 0); // wrapping
    }

    #[test]
    fn test_relocate_abs32() {
        let mut buf = [0u8; 4];
        write32le(&mut buf, 100);
        relocate(R_AARCH64_ABS32, &mut buf, 0, 42, 0).unwrap();
        assert_eq!(read32le(&buf), 142);
    }

    #[test]
    fn test_relocate_prel32() {
        let mut buf = [0u8; 4];
        write32le(&mut buf, 0);
        // val=0x2000, addr=0x1000 => offset = 0x1000
        relocate(R_AARCH64_PREL32, &mut buf, 0x1000, 0x2000, 0).unwrap();
        assert_eq!(read32le(&buf), 0x1000);
    }

    #[test]
    fn test_relocate_movw_g0() {
        // NOP instruction (all zeros except valid encoding)
        let mut buf = [0u8; 4];
        write32le(&mut buf, 0xd280_0000); // movz x0, #0
        relocate(R_AARCH64_MOVW_UABS_G0_NC, &mut buf, 0, 0xABCD, 0).unwrap();
        let insn = read32le(&buf);
        // Check that imm16 field (bits[20:5]) = 0xABCD
        assert_eq!((insn >> 5) & 0xffff, 0xABCD);
    }

    #[test]
    fn test_relocate_movw_g1() {
        let mut buf = [0u8; 4];
        write32le(&mut buf, 0xd2a0_0000); // movz x0, #0, lsl #16
        relocate(R_AARCH64_MOVW_UABS_G1_NC, &mut buf, 0, 0xDEAD_0000, 0).unwrap();
        let insn = read32le(&buf);
        assert_eq!((insn >> 5) & 0xffff, 0xDEAD);
    }

    #[test]
    fn test_relocate_movw_g2() {
        let mut buf = [0u8; 4];
        write32le(&mut buf, 0xd2c0_0000); // movz x0, #0, lsl #32
        relocate(R_AARCH64_MOVW_UABS_G2_NC, &mut buf, 0, 0xBEEF_0000_0000, 0).unwrap();
        let insn = read32le(&buf);
        assert_eq!((insn >> 5) & 0xffff, 0xBEEF);
    }

    #[test]
    fn test_relocate_movw_g3() {
        let mut buf = [0u8; 4];
        write32le(&mut buf, 0xd2e0_0000); // movz x0, #0, lsl #48
        relocate(R_AARCH64_MOVW_UABS_G3, &mut buf, 0, 0xCAFE_0000_0000_0000, 0).unwrap();
        let insn = read32le(&buf);
        assert_eq!((insn >> 5) & 0xffff, 0xCAFE);
    }

    #[test]
    fn test_relocate_adrp_same_page() {
        // ADRP x0, #0 (same page -> offset 0)
        let mut buf = [0u8; 4];
        write32le(&mut buf, 0x9000_0000); // adrp x0, #0
        relocate(
            R_AARCH64_ADR_PREL_PG_HI21,
            &mut buf,
            0x1000, // addr on page 1
            0x1234, // val on page 1 -> same page, offset 0
            0,
        )
        .unwrap();
        let insn = read32le(&buf);
        // Offset is 0, so both immhi and immlo should be 0
        // Only Rd (x0 = 0) and opcode (0x90000000) preserved
        assert_eq!(insn & 0x9f00_001f, 0x9000_0000);
    }

    #[test]
    fn test_relocate_adrp_next_page() {
        let mut buf = [0u8; 4];
        write32le(&mut buf, 0x9000_0000); // adrp x0
        // addr on page 0x1, val on page 0x2 -> offset = 1
        relocate(
            R_AARCH64_ADR_PREL_PG_HI21,
            &mut buf,
            0x1000, // page 1
            0x2000, // page 2
            0,
        )
        .unwrap();
        let insn = read32le(&buf);
        // offset = 1, immlo=1<<29, immhi=0
        assert_eq!(insn & (0x3 << 29), 1 << 29);
    }

    #[test]
    fn test_relocate_adrp_out_of_range() {
        let mut buf = [0u8; 4];
        write32le(&mut buf, 0x9000_0000);
        // +/-1MB page range = 2^20 pages. Create offset > 2^20
        let result = relocate(
            R_AARCH64_ADR_PREL_PG_HI21,
            &mut buf,
            0x0000_0000,
            0x0001_0000_0000, // 4GB away -> page offset = 0x100000, exceeds 20-bit signed
            0,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_relocate_add_lo12() {
        let mut buf = [0u8; 4];
        write32le(&mut buf, 0x9100_0000); // add x0, x0, #0
        relocate(R_AARCH64_ADD_ABS_LO12_NC, &mut buf, 0, 0x123, 0).unwrap();
        let insn = read32le(&buf);
        // imm12 at bits[21:10] should be 0x123
        assert_eq!((insn >> 10) & 0xfff, 0x123);
    }

    #[test]
    fn test_relocate_ldst8_lo12() {
        let mut buf = [0u8; 4];
        write32le(&mut buf, 0x3940_0000); // ldrb w0, [x0]
        relocate(R_AARCH64_LDST8_ABS_LO12_NC, &mut buf, 0, 0x55, 0).unwrap();
        let insn = read32le(&buf);
        assert_eq!((insn >> 10) & 0xfff, 0x55);
    }

    #[test]
    fn test_relocate_ldst16_lo12() {
        let mut buf = [0u8; 4];
        write32le(&mut buf, 0x7940_0000); // ldrh w0, [x0]
        // val=0x10 (16-byte offset, 2-byte aligned)
        relocate(R_AARCH64_LDST16_ABS_LO12_NC, &mut buf, 0, 0x10, 0).unwrap();
        let insn = read32le(&buf);
        // (0x10 & 0xffe) << 9 = 0x10 << 9 = 0x2000, placed at bits[21:10]
        assert_eq!((insn >> 10) & 0xfff, 0x10 >> 1);
    }

    #[test]
    fn test_relocate_ldst32_lo12() {
        let mut buf = [0u8; 4];
        write32le(&mut buf, 0xb940_0000); // ldr w0, [x0]
        // val=0x20 (32-byte offset, 4-byte aligned)
        relocate(R_AARCH64_LDST32_ABS_LO12_NC, &mut buf, 0, 0x20, 0).unwrap();
        let insn = read32le(&buf);
        // (0x20 & 0xffc) << 8 = 0x20 << 8 = 0x2000
        assert_eq!((insn >> 10) & 0xfff, 0x20 >> 2);
    }

    #[test]
    fn test_relocate_ldst64_lo12() {
        let mut buf = [0u8; 4];
        write32le(&mut buf, 0xf940_0000); // ldr x0, [x0]
        // val=0x40 (64-byte offset, 8-byte aligned)
        relocate(R_AARCH64_LDST64_ABS_LO12_NC, &mut buf, 0, 0x40, 0).unwrap();
        let insn = read32le(&buf);
        assert_eq!((insn >> 10) & 0xfff, 0x40 >> 3);
    }

    #[test]
    fn test_relocate_ldst128_lo12() {
        let mut buf = [0u8; 4];
        write32le(&mut buf, 0x3dc0_0000); // ldr q0, [x0]
        // val=0x80 (128-byte offset, 16-byte aligned)
        relocate(R_AARCH64_LDST128_ABS_LO12_NC, &mut buf, 0, 0x80, 0).unwrap();
        let insn = read32le(&buf);
        assert_eq!((insn >> 10) & 0xfff, 0x80 >> 4);
    }

    #[test]
    fn test_relocate_jump26() {
        let mut buf = [0u8; 4];
        write32le(&mut buf, 0x1400_0000); // b #0
        // Branch forward by 16 bytes: offset = 16, word offset = 4
        relocate(R_AARCH64_JUMP26, &mut buf, 0x1000, 0x1010, 0).unwrap();
        let insn = read32le(&buf);
        // bit[31] = 0 (B not BL), lower 26 bits = 4
        assert_eq!(insn >> 31, 0); // B instruction
        assert_eq!(insn & 0x03ff_ffff, 4);
    }

    #[test]
    fn test_relocate_call26() {
        let mut buf = [0u8; 4];
        write32le(&mut buf, 0x9400_0000); // bl #0
        // BL forward by 8 bytes: offset = 8, word offset = 2
        relocate(R_AARCH64_CALL26, &mut buf, 0x1000, 0x1008, 0).unwrap();
        let insn = read32le(&buf);
        // bit[31] = 1 (BL), lower 26 bits = 2
        assert_eq!(insn >> 31, 1); // BL instruction
        assert_eq!(insn & 0x03ff_ffff, 2);
    }

    #[test]
    fn test_relocate_call26_backward() {
        let mut buf = [0u8; 4];
        write32le(&mut buf, 0x9400_0000); // bl #0
        // BL backward by 16 bytes
        relocate(R_AARCH64_CALL26, &mut buf, 0x1010, 0x1000, 0).unwrap();
        let insn = read32le(&buf);
        assert_eq!(insn >> 31, 1); // BL instruction
        // Offset = -16 / 4 = -4, in 26-bit signed = 0x03ff_fffc
        let off_26 = insn & 0x03ff_ffff;
        // Sign-extend 26-bit to 32-bit
        let soff = if off_26 & (1 << 25) != 0 {
            off_26 | 0xfc00_0000
        } else {
            off_26
        };
        assert_eq!(soff as i32, -4);
    }

    #[test]
    fn test_relocate_call26_out_of_range() {
        let mut buf = [0u8; 4];
        write32le(&mut buf, 0x9400_0000);
        // +/-128MB range: try 256MB forward
        let result = relocate(
            R_AARCH64_CALL26,
            &mut buf,
            0x0000_0000,
            0x1000_0000, // 256MB
            0,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_relocate_copy() {
        let mut buf = [0u8; 4];
        write32le(&mut buf, 0xDEAD_BEEF);
        relocate(R_AARCH64_COPY, &mut buf, 0, 0, 0).unwrap();
        // COPY is a no-op: buffer unchanged
        assert_eq!(read32le(&buf), 0xDEAD_BEEF);
    }

    #[test]
    fn test_relocate_glob_dat() {
        let mut buf = [0u8; 8];
        write64le(&mut buf, 0);
        relocate(R_AARCH64_GLOB_DAT, &mut buf, 0, 0xDEAD_BEEF_CAFE_BABE, 0).unwrap();
        assert_eq!(read64le(&buf), 0xDEAD_BEEF_CAFE_BABE);

        // Test with non-zero addend: val - addend should be written
        let mut buf2 = [0u8; 8];
        write64le(&mut buf2, 0);
        relocate(R_AARCH64_GLOB_DAT, &mut buf2, 0, 0x1000, 0x100).unwrap();
        assert_eq!(read64le(&buf2), 0x1000_u64.wrapping_sub(0x100));
    }

    #[test]
    fn test_relocate_jump_slot() {
        let mut buf = [0u8; 8];
        write64le(&mut buf, 0);
        relocate(R_AARCH64_JUMP_SLOT, &mut buf, 0, 0x1234_5678_9ABC_DEF0, 0).unwrap();
        assert_eq!(read64le(&buf), 0x1234_5678_9ABC_DEF0);

        // Test with non-zero addend: val - addend should be written
        let mut buf2 = [0u8; 8];
        write64le(&mut buf2, 0);
        relocate(R_AARCH64_JUMP_SLOT, &mut buf2, 0, 0x2000, 0x200).unwrap();
        assert_eq!(read64le(&buf2), 0x2000_u64.wrapping_sub(0x200));
    }

    #[test]
    fn test_relocate_relative_noop() {
        let mut buf = [0u8; 8];
        write64le(&mut buf, 0xDEAD);
        relocate(R_AARCH64_RELATIVE, &mut buf, 0, 42, 0).unwrap();
        // ELF RELATIVE is a no-op at static link time
        assert_eq!(read64le(&buf), 0xDEAD);
    }

    #[test]
    fn test_relocate_unknown_nonfatal() {
        let mut buf = [0u8; 4];
        write32le(&mut buf, 0xDEAD_BEEF);
        // Unknown type should succeed (non-fatal)
        let result = relocate(9999, &mut buf, 0, 0, 0);
        assert!(result.is_ok());
        // Buffer should be unchanged
        assert_eq!(read32le(&buf), 0xDEAD_BEEF);
    }

    // -----------------------------------------------------------------------
    // Relocation constant value tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_relocation_constant_values() {
        // Verify constants match the ELF AArch64 specification
        assert_eq!(R_AARCH64_ABS64, 257);
        assert_eq!(R_AARCH64_ABS32, 258);
        assert_eq!(R_AARCH64_PREL32, 261);
        assert_eq!(R_AARCH64_MOVW_UABS_G0_NC, 263);
        assert_eq!(R_AARCH64_MOVW_UABS_G1_NC, 264);
        assert_eq!(R_AARCH64_MOVW_UABS_G2_NC, 265);
        assert_eq!(R_AARCH64_MOVW_UABS_G3, 266);
        assert_eq!(R_AARCH64_ADR_PREL_PG_HI21, 275);
        assert_eq!(R_AARCH64_ADD_ABS_LO12_NC, 277);
        assert_eq!(R_AARCH64_LDST8_ABS_LO12_NC, 278);
        assert_eq!(R_AARCH64_JUMP26, 282);
        assert_eq!(R_AARCH64_CALL26, 283);
        assert_eq!(R_AARCH64_LDST16_ABS_LO12_NC, 284);
        assert_eq!(R_AARCH64_LDST32_ABS_LO12_NC, 285);
        assert_eq!(R_AARCH64_LDST64_ABS_LO12_NC, 286);
        assert_eq!(R_AARCH64_LDST128_ABS_LO12_NC, 299);
        assert_eq!(R_AARCH64_ADR_GOT_PAGE, 311);
        assert_eq!(R_AARCH64_LD64_GOT_LO12_NC, 312);
        assert_eq!(R_AARCH64_COPY, 1024);
        assert_eq!(R_AARCH64_GLOB_DAT, 1025);
        assert_eq!(R_AARCH64_JUMP_SLOT, 1026);
        assert_eq!(R_AARCH64_RELATIVE, 1027);
        assert_eq!(R_AARCH64_NUM, 1028);
    }

    // -----------------------------------------------------------------------
    // GOT-relative relocation tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_relocate_adr_got_page() {
        let mut buf = [0u8; 4];
        write32le(&mut buf, 0x9000_0010); // adrp x16
        // GOT entry on next page
        relocate(
            R_AARCH64_ADR_GOT_PAGE,
            &mut buf,
            0x1000,
            0x2000,
            0,
        )
        .unwrap();
        let insn = read32le(&buf);
        // Page offset = 1 -> immlo = 1
        assert_eq!(insn & (0x3 << 29), 1 << 29);
        // Rd should still be x16 = 0x10
        assert_eq!(insn & 0x1f, 0x10);
    }

    #[test]
    fn test_relocate_ld64_got_lo12() {
        let mut buf = [0u8; 4];
        write32le(&mut buf, 0xf940_0211); // ldr x17, [x16]
        // GOT entry at offset 0x18 (24 bytes, 8-byte aligned)
        relocate(
            R_AARCH64_LD64_GOT_LO12_NC,
            &mut buf,
            0,
            0x3018, // low 12 bits: 0x018
            0,
        )
        .unwrap();
        let insn = read32le(&buf);
        // (0x18 & 0xff8) << 7 = 0x18 << 7 = 0xC00, placed at bits[21:10]
        // Note: mask 0xfff803ff, so bits[21:10] = 0x18 >> 3 = 3
        assert_eq!((insn >> 10) & 0x1ff, 0x18 >> 3);
    }
}
