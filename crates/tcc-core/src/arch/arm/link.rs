//! ARM relocation handling, PLT/GOT generation, and relocation application.
//!
//! Port of `arm-link.c` (445 lines) from the TCC C codebase to idiomatic Rust.
//!
//! This module implements all ARM-specific ELF relocation types including:
//! - ARM branch relocations (B/BL/BLX) with Thumb interworking
//! - Thumb-2 branch relocations (BL/B.W) with ARM interworking
//! - MOVW/MOVT absolute and PC-relative address pairs (ARM and Thumb-2)
//! - PLT (Procedure Linkage Table) entry creation and fixup
//! - GOT-relative, GOT-offset, and absolute relocations
//! - ARMv4 BX→MOV conversion for pre-Thumb cores
//!
//! Public functions [`code_reloc`], [`gotplt_entry_type`], and [`relocate`]
//! are called by the [`super::ArmBackend`] trait implementation of
//! [`CodegenBackend`](crate::arch::CodegenBackend).
//!
//! [`create_plt_entry`] and [`relocate_plt`] are called from the ELF linker
//! module during the output phase.
//!
//! # Bug Fixes
//!
//! - **BUG-01**: Correct interworking between ARM and Thumb via BLX instruction
//!   (available on ARMv5+, controlled by `ArmBackend::cpu_version`).
//! - **BUG-16**: All linking operations return `TccResult<()>` instead of
//!   using `longjmp`/`setjmp`, preventing memory leaks on error paths.

use super::ArmBackend;
use crate::arch::{add32le, read16le, read32le, write16le, write32le};
use crate::elf::section_ptr_add;
use crate::error::{TccError, TccResult};
use crate::TCCState;

// ===========================================================================
// ARM ELF relocation type constants
// Values from elf.h / arm-link.c TARGET_DEFS_ONLY section.
// Defined locally as i32 for direct use in match arms with the i32
// parameters of code_reloc / gotplt_entry_type / relocate.
// ===========================================================================

/// R_ARM_NONE (0) — No relocation.
pub const R_ARM_NONE: i32 = 0;
/// R_ARM_PC24 (1) — 24-bit PC-relative branch (deprecated, use CALL/JUMP24).
pub const R_ARM_PC24: i32 = 1;
/// R_ARM_ABS32 (2) — Direct 32-bit absolute address.
pub const R_ARM_ABS32: i32 = 2;
/// R_ARM_REL32 (3) — PC-relative 32-bit offset.
pub const R_ARM_REL32: i32 = 3;
/// R_ARM_THM_PC22 (10) — Thumb BL/BLX 22-bit PC-relative (encoded as 25-bit).
pub const R_ARM_THM_PC22: i32 = 10;
/// R_ARM_COPY (20) — Copy symbol at runtime (dynamic linker).
pub const R_ARM_COPY: i32 = 20;
/// R_ARM_GLOB_DAT (21) — Create GOT entry (dynamic linker).
pub const R_ARM_GLOB_DAT: i32 = 21;
/// R_ARM_JUMP_SLOT (22) — Create PLT entry (dynamic linker).
pub const R_ARM_JUMP_SLOT: i32 = 22;
/// R_ARM_RELATIVE (23) — Adjust by program base (dynamic linker / PE).
pub const R_ARM_RELATIVE: i32 = 23;
/// R_ARM_GOTOFF (24) — 32-bit offset from GOT base.
pub const R_ARM_GOTOFF: i32 = 24;
/// R_ARM_GOTPC (25) — 32-bit PC-relative offset to GOT base.
pub const R_ARM_GOTPC: i32 = 25;
/// R_ARM_GOT32 (26) — 32-bit GOT entry offset.
pub const R_ARM_GOT32: i32 = 26;
/// R_ARM_PLT32 (27) — 32-bit PLT address (deprecated, use CALL).
pub const R_ARM_PLT32: i32 = 27;
/// R_ARM_CALL (28) — BL/BLX immediate (function call).
pub const R_ARM_CALL: i32 = 28;
/// R_ARM_JUMP24 (29) — B immediate (unconditional jump).
pub const R_ARM_JUMP24: i32 = 29;
/// R_ARM_THM_JUMP24 (30) — Thumb-2 B.W unconditional jump.
pub const R_ARM_THM_JUMP24: i32 = 30;
/// R_ARM_TARGET1 (38) — Platform-specific, treated as R_ARM_ABS32.
pub const R_ARM_TARGET1: i32 = 38;
/// R_ARM_V4BX (40) — ARMv4 BX Rm fixup (convert to MOV PC, Rm).
pub const R_ARM_V4BX: i32 = 40;
/// R_ARM_PREL31 (42) — 31-bit PC-relative (exception tables).
pub const R_ARM_PREL31: i32 = 42;
/// R_ARM_MOVW_ABS_NC (43) — ARM MOVW absolute, no overflow check.
pub const R_ARM_MOVW_ABS_NC: i32 = 43;
/// R_ARM_MOVT_ABS (44) — ARM MOVT absolute (high 16 bits).
pub const R_ARM_MOVT_ABS: i32 = 44;
/// R_ARM_MOVW_PREL_NC (45) — ARM MOVW PC-relative, no overflow check.
pub const R_ARM_MOVW_PREL_NC: i32 = 45;
/// R_ARM_MOVT_PREL (46) — ARM MOVT PC-relative (high 16 bits).
pub const R_ARM_MOVT_PREL: i32 = 46;
/// R_ARM_THM_MOVW_ABS_NC (47) — Thumb-2 MOVW absolute, no overflow check.
pub const R_ARM_THM_MOVW_ABS_NC: i32 = 47;
/// R_ARM_THM_MOVT_ABS (48) — Thumb-2 MOVT absolute (high 16 bits).
pub const R_ARM_THM_MOVT_ABS: i32 = 48;
/// R_ARM_GOT_PREL (96) — GOT entry, PC-relative.
pub const R_ARM_GOT_PREL: i32 = 96;
/// R_ARM_NUM (256) — Sentinel: number of defined ARM relocation types.
pub const R_ARM_NUM: i32 = 256;

// GOTPLT entry type constants, re-exported from arch/mod.rs for
// module-level access. Values: NO=0, BUILD_GOT_ONLY=1, AUTO=2, ALWAYS=3.
pub const NO_GOTPLT_ENTRY: i32 = crate::arch::NO_GOTPLT_ENTRY;
pub const AUTO_GOTPLT_ENTRY: i32 = crate::arch::AUTO_GOTPLT_ENTRY;
pub const BUILD_GOT_ONLY: i32 = crate::arch::BUILD_GOT_ONLY;
pub const ALWAYS_GOTPLT_ENTRY: i32 = crate::arch::ALWAYS_GOTPLT_ENTRY;

// ===========================================================================
// Relocation type classification
// ===========================================================================

/// Classifies an ARM relocation type as code (1) or data (0).
///
/// Returns:
/// - `0` — Data relocation (address/offset patching, no instruction decode)
/// - `1` — Code relocation (branch instruction, requires instruction decode)
/// - `-1` — Unknown/unsupported relocation type
///
/// Source: `arm-link.c` lines 33–66, `code_reloc()`.
pub fn code_reloc(reloc_type: i32) -> i32 {
    match reloc_type {
        // Data relocations: these patch data words or offsets, not instructions
        R_ARM_MOVT_ABS
        | R_ARM_MOVW_ABS_NC
        | R_ARM_THM_MOVT_ABS
        | R_ARM_THM_MOVW_ABS_NC
        | R_ARM_ABS32
        | R_ARM_REL32
        | R_ARM_GOTPC
        | R_ARM_GOTOFF
        | R_ARM_GOT32
        | R_ARM_GOT_PREL
        | R_ARM_COPY
        | R_ARM_GLOB_DAT
        | R_ARM_NONE
        | R_ARM_TARGET1
        | R_ARM_MOVT_PREL
        | R_ARM_MOVW_PREL_NC => 0,

        // Code relocations: these patch branch instructions
        R_ARM_PC24
        | R_ARM_CALL
        | R_ARM_JUMP24
        | R_ARM_PLT32
        | R_ARM_THM_PC22
        | R_ARM_THM_JUMP24
        | R_ARM_PREL31
        | R_ARM_V4BX
        | R_ARM_JUMP_SLOT => 1,

        _ => -1,
    }
}

/// Determines the GOT/PLT entry requirements for an ARM relocation type.
///
/// Returns one of:
/// - [`NO_GOTPLT_ENTRY`] (0) — No GOT or PLT entry needed
/// - [`AUTO_GOTPLT_ENTRY`] (2) — Auto: PLT if undefined, GOT if defined
/// - [`BUILD_GOT_ONLY`] (1) — Only a GOT entry (no PLT)
/// - [`ALWAYS_GOTPLT_ENTRY`] (3) — Always build GOT + PLT entries
/// - `-1` — Unknown/unsupported relocation type
///
/// Source: `arm-link.c` lines 71–108, `gotplt_entry_type()`.
pub fn gotplt_entry_type(reloc_type: i32) -> i32 {
    match reloc_type {
        // No GOT/PLT entry needed for dynamic linker relocations
        R_ARM_NONE | R_ARM_COPY | R_ARM_GLOB_DAT | R_ARM_JUMP_SLOT => {
            NO_GOTPLT_ENTRY
        }

        // Auto: create PLT for undefined symbols, nothing for defined ones
        R_ARM_PC24
        | R_ARM_CALL
        | R_ARM_JUMP24
        | R_ARM_PLT32
        | R_ARM_THM_PC22
        | R_ARM_THM_JUMP24
        | R_ARM_MOVT_ABS
        | R_ARM_MOVW_ABS_NC
        | R_ARM_THM_MOVT_ABS
        | R_ARM_THM_MOVW_ABS_NC
        | R_ARM_PREL31
        | R_ARM_ABS32
        | R_ARM_REL32
        | R_ARM_V4BX
        | R_ARM_TARGET1
        | R_ARM_MOVT_PREL
        | R_ARM_MOVW_PREL_NC => AUTO_GOTPLT_ENTRY,

        // Only GOT entry (for GOT-base-relative addressing)
        R_ARM_GOTPC | R_ARM_GOTOFF => BUILD_GOT_ONLY,

        // Always create GOT + PLT entries
        R_ARM_GOT32 | R_ARM_GOT_PREL => ALWAYS_GOTPLT_ENTRY,

        _ => -1,
    }
}

// ===========================================================================
// PLT entry creation
// ===========================================================================

/// Creates a PLT (Procedure Linkage Table) entry for dynamic symbol resolution.
///
/// On ARM, the PLT uses the following format:
///
/// **PLT\[0\]** (20 bytes — resolver trampoline):
/// ```text
///   e52de004    push {lr}
///   e59fe004    ldr lr, [pc, #4]
///   e08fe00e    add lr, pc, lr
///   e5bef008    ldr pc, [lr, #8]!
///   00000000    .word <got_offset>    (patched by relocate_plt)
/// ```
///
/// **PLT\[n\]** (16 bytes + optional 4-byte Thumb stub):
/// ```text
///   [optional]  4778 46c0  bx pc; nop    (Thumb→ARM trampoline)
///   XXXXXXXX    add ip, pc, #high20       (patched by relocate_plt)
///   XXXXXXXX    add ip, ip, #mid8
///   XXXXXXXX    add ip, ip, #low12
///   XXXXXXXX    ldr pc, [ip, #off]!
/// ```
///
/// The Thumb stub (`bx pc; nop` = 0x46c04778) is prepended when the PLT
/// might be called from Thumb code, switching to ARM mode before the PLT body.
///
/// Returns the PLT offset of the newly created entry.
///
/// # Parameters
/// - `s1`: Compiler state with PLT and GOT sections
/// - `got_offset`: Offset of the GOT entry for this symbol
/// - `plt_thumb_stub`: Whether to prepend a Thumb-to-ARM stub
///
/// Source: `arm-link.c` lines 111–141, `create_plt_entry()`.
pub fn create_plt_entry(
    s1: &mut TCCState,
    got_offset: u32,
    plt_thumb_stub: bool,
) -> TccResult<u32> {
    let plt_idx = s1.plt.ok_or_else(|| {
        TccError::linker("PLT section not initialized")
    })?;

    // --- Create PLT[0] header (20 bytes) if this is the first entry ---
    // Source: arm-link.c lines 122-129
    if s1.sections[plt_idx].data_offset == 0 {
        let start = section_ptr_add(&mut s1.sections[plt_idx], 20);
        let plt = &mut s1.sections[plt_idx];
        // push {lr}
        write32le(&mut plt.data[start..], 0xe52de004);
        // ldr lr, [pc, #4]
        write32le(&mut plt.data[start + 4..], 0xe59fe004);
        // add lr, pc, lr
        write32le(&mut plt.data[start + 8..], 0xe08fe00e);
        // ldr pc, [lr, #8]!
        write32le(&mut plt.data[start + 12..], 0xe5bef008);
        // p+16 is set by relocate_plt (placeholder = 0, already zeroed)
    }

    // Record the offset where this PLT[n] entry starts.
    // Source: arm-link.c line 130
    let plt_offset = s1.sections[plt_idx].data_offset as u32;

    // --- Optionally prepend Thumb stub (4 bytes) ---
    // Source: arm-link.c lines 132-136
    if plt_thumb_stub {
        let stub_start = section_ptr_add(&mut s1.sections[plt_idx], 4);
        let plt = &mut s1.sections[plt_idx];
        // bx pc (0x4778) — switches from Thumb to ARM mode
        write16le(&mut plt.data[stub_start..], 0x4778);
        // nop (0x46c0) — padding to align to 4 bytes
        write16le(&mut plt.data[stub_start + 2..], 0x46c0);
    }

    // --- Create PLT[n] entry (16 bytes) ---
    // The actual instruction words are written as placeholders here;
    // relocate_plt() patches them with the final GOT-relative offsets.
    // Source: arm-link.c lines 137-140
    let entry_start = section_ptr_add(&mut s1.sections[plt_idx], 16);
    let plt = &mut s1.sections[plt_idx];
    // Save got_offset at p+4 for relocate_plt to read later.
    // The instructions at p+0, p+8, p+12 are also patched by relocate_plt.
    // p+0..p+3: placeholder (will become add ip, pc, #high20)
    // p+4..p+7: got_offset (read by relocate_plt, then overwritten)
    write32le(&mut plt.data[entry_start + 4..], got_offset);

    Ok(plt_offset)
}

// ===========================================================================
// PLT relocation fixup
// ===========================================================================

/// Patches all PLT entries with final GOT-relative addresses.
///
/// Called after final section addresses are assigned (during
/// `fill_program_header`). Computes GOT-relative offsets and encodes them
/// into the 3-instruction PLT[n] sequences.
///
/// For PLT\[0\]: writes `GOT - PLT - 12 - 4` into the data word at offset 16.
///
/// For each PLT\[n\]:
/// - Skips Thumb stub (4 bytes) if present (detected by 0x46c04778 signature)
/// - Encodes the GOT offset into a 3-instruction add sequence + ldr:
///   ```text
///   add ip, pc, #(off >> 28) << 28
///   add ip, ip, #(off >> 20) << 20
///   add ip, ip, #(off >> 12) << 12
///   ldr pc, [ip, #off & 0xfff]!
///   ```
///
/// Also: writes PLT section address into each GOT entry referenced by
/// `.rel.plt` relocations (lazy binding: GOT initially → PLT header).
///
/// Source: `arm-link.c` lines 145–178, `relocate_plt()`.
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

    // x = GOT_base - PLT_base - 12 (ARM pipeline: PC = current + 8,
    // plus 4 bytes for the data word after the 4th instruction = 12)
    // Source: arm-link.c line 156
    let x = got_sh_addr as i64 - plt_sh_addr as i64 - 12;

    // --- Patch PLT[0] data word at offset 16 ---
    // Source: arm-link.c line 157
    write32le(
        &mut s1.sections[plt_idx].data[16..],
        (x - 4) as u32,
    );

    // --- Patch each PLT[n] entry ---
    // Source: arm-link.c lines 158-168
    let mut pos: usize = 20; // skip PLT[0] (20 bytes)
    while pos < plt_data_offset {
        // Read the saved got_offset from p+4 (written by create_plt_entry)
        let got_entry_offset = read32le(&s1.sections[plt_idx].data[pos + 4..]);

        // Compute the GOT-relative offset for this PLT entry.
        //
        // C code: off = x + read32le(p+4) + (s1->plt->data - p) + 4
        // (s1->plt->data - p) is the negative offset from `p` to the buffer
        // start, which equals -(pos). So:
        //   off = x + got_entry_offset - pos + 4
        //
        // Source: arm-link.c line 160
        let off = ((x as i32)
            .wrapping_add(got_entry_offset as i32)
            .wrapping_sub(pos as i32)
            .wrapping_add(4)) as u32;

        // Check for Thumb stub: if the first word is 0x46c04778 (bx pc; nop),
        // skip 4 bytes — the actual PLT instructions start after the stub.
        // The off computation uses original `p` BEFORE the skip (matching C).
        // Source: arm-link.c lines 161-162
        let entry_pos = if read32le(&s1.sections[plt_idx].data[pos..]) == 0x46c0_4778 {
            pos + 4
        } else {
            pos
        };

        // Encode the 3-instruction GOT-relative add sequence + final ldr.
        // Source: arm-link.c lines 163-166
        let plt_data = &mut s1.sections[plt_idx].data;

        // add ip, pc, #(off >> 28) << 28
        write32le(
            &mut plt_data[entry_pos..],
            0xe28f_c200 | ((off >> 28) & 0xf),
        );
        // add ip, ip, #(off >> 20) << 20
        write32le(
            &mut plt_data[entry_pos + 4..],
            0xe28c_c600 | ((off >> 20) & 0xff),
        );
        // add ip, ip, #(off >> 12) << 12
        write32le(
            &mut plt_data[entry_pos + 8..],
            0xe28c_ca00 | ((off >> 12) & 0xff),
        );
        // ldr pc, [ip, #off & 0xfff]!
        write32le(
            &mut plt_data[entry_pos + 12..],
            0xe5bc_f000 | (off & 0xfff),
        );

        // Advance past Thumb stub (if present) + 16-byte PLT entry
        pos = entry_pos + 16;
    }

    // --- Fix GOT entries to point to PLT section address (lazy binding) ---
    // Source: arm-link.c lines 171-177
    if let Some(reloc_idx) = s1.sections[plt_idx].reloc {
        // ARM uses 32-bit Elf32_Rel (8 bytes per entry)
        let entry_size = 8usize; // sizeof(Elf32_Rel)
        let reloc_len = s1.sections[reloc_idx].data_offset;
        let plt_addr = s1.sections[plt_idx].sh_addr;
        let got_data_len = s1.sections[got_idx].data.len();

        let mut byte_off = 0usize;
        while byte_off + entry_size <= reloc_len {
            // Read r_offset from Elf32_Rel (first 4 bytes)
            let r_offset =
                read32le(&s1.sections[reloc_idx].data[byte_off..]) as usize;
            if r_offset + 4 <= got_data_len {
                write32le(
                    &mut s1.sections[got_idx].data[r_offset..],
                    plt_addr as u32,
                );
            }
            byte_off += entry_size;
        }
    }

    Ok(())
}

// ===========================================================================
// Relocation application — main function
// ===========================================================================

/// Applies a single ARM ELF relocation.
///
/// Patches the instruction or data at `ptr` according to the relocation
/// type `rel_type`, using `addr` (the virtual address of the relocation site)
/// and `val` (the symbol value + addend).
///
/// # Relocation types handled
///
/// | Type | Description |
/// |------|-------------|
/// | `R_ARM_PC24` / `R_ARM_CALL` / `R_ARM_JUMP24` / `R_ARM_PLT32` | ARM branch (B/BL/BLX) |
/// | `R_ARM_THM_PC22` / `R_ARM_THM_JUMP24` | Thumb-2 branch (BL/B.W) |
/// | `R_ARM_MOVT_ABS` / `R_ARM_MOVW_ABS_NC` | ARM MOVW/MOVT absolute |
/// | `R_ARM_MOVT_PREL` / `R_ARM_MOVW_PREL_NC` | ARM MOVW/MOVT PC-relative |
/// | `R_ARM_THM_MOVT_ABS` / `R_ARM_THM_MOVW_ABS_NC` | Thumb-2 MOVW/MOVT absolute |
/// | `R_ARM_PREL31` | 31-bit PC-relative (exception tables) |
/// | `R_ARM_ABS32` / `R_ARM_TARGET1` | 32-bit absolute |
/// | `R_ARM_REL32` | 32-bit PC-relative |
/// | `R_ARM_GOTPC` | GOT base, PC-relative |
/// | `R_ARM_GOTOFF` | Symbol offset from GOT base |
/// | `R_ARM_GOT32` | GOT entry offset |
/// | `R_ARM_GOT_PREL` | GOT entry, PC-relative |
/// | `R_ARM_V4BX` | ARMv4 BX→MOV conversion |
/// | `R_ARM_GLOB_DAT` / `R_ARM_JUMP_SLOT` | Direct symbol address |
/// | `R_ARM_COPY` / `R_ARM_NONE` | No-op |
/// | `R_ARM_RELATIVE` | PE base adjustment |
///
/// # Parameters
/// - `backend`: ARM backend state (provides `cpu_version` for BLX check)
/// - `rel_type`: ELF relocation type (`R_ARM_*`)
/// - `ptr`: Mutable byte slice at the relocation site
/// - `addr`: Virtual address of the relocation site
/// - `val`: Computed value = symbol_value + addend
///
/// Source: `arm-link.c` lines 182–443, `relocate()`.
pub fn relocate(
    backend: &mut ArmBackend,
    rel_type: i32,
    ptr: &mut [u8],
    addr: u64,
    val: u64,
) -> TccResult<()> {
    match rel_type {
        // =================================================================
        // R_ARM_PC24 / R_ARM_CALL / R_ARM_JUMP24 / R_ARM_PLT32
        // ARM branch relocations (B/BL/BLX).
        // Source: arm-link.c lines 191-228
        // =================================================================
        R_ARM_PC24 | R_ARM_CALL | R_ARM_JUMP24 | R_ARM_PLT32 => {
            if ptr.len() < 4 {
                return Err(TccError::linker(format!(
                    "R_ARM branch: buffer too small ({} bytes, need 4)",
                    ptr.len()
                )));
            }
            relocate_arm_branch(backend, rel_type, ptr, addr, val)?;
        }

        // =================================================================
        // R_ARM_THM_PC22 / R_ARM_THM_JUMP24
        // Thumb-2 branch relocations (BL/B.W).
        // Source: arm-link.c lines 232-323
        // =================================================================
        R_ARM_THM_PC22 | R_ARM_THM_JUMP24 => {
            if ptr.len() < 4 {
                return Err(TccError::linker(format!(
                    "R_ARM Thumb branch: buffer too small ({} bytes, need 4)",
                    ptr.len()
                )));
            }
            relocate_thumb_branch(rel_type, ptr, addr, val)?;
        }

        // =================================================================
        // R_ARM_MOVT_ABS / R_ARM_MOVW_ABS_NC
        // ARM MOVW/MOVT absolute address pairs.
        // Source: arm-link.c lines 324-337
        // =================================================================
        R_ARM_MOVT_ABS | R_ARM_MOVW_ABS_NC => {
            if ptr.len() < 4 {
                return Err(TccError::linker(format!(
                    "R_ARM_MOVW/MOVT_ABS: buffer too small ({} bytes, need 4)",
                    ptr.len()
                )));
            }
            relocate_arm_movw_movt_abs(rel_type, ptr, val);
        }

        // =================================================================
        // R_ARM_MOVT_PREL / R_ARM_MOVW_PREL_NC
        // ARM MOVW/MOVT PC-relative address pairs.
        // Source: arm-link.c lines 339-352
        // =================================================================
        R_ARM_MOVT_PREL | R_ARM_MOVW_PREL_NC => {
            if ptr.len() < 4 {
                return Err(TccError::linker(format!(
                    "R_ARM_MOVW/MOVT_PREL: buffer too small ({} bytes, need 4)",
                    ptr.len()
                )));
            }
            relocate_arm_movw_movt_prel(rel_type, ptr, addr, val);
        }

        // =================================================================
        // R_ARM_THM_MOVT_ABS / R_ARM_THM_MOVW_ABS_NC
        // Thumb-2 MOVW/MOVT absolute address pairs.
        // Source: arm-link.c lines 353-368
        // =================================================================
        R_ARM_THM_MOVT_ABS | R_ARM_THM_MOVW_ABS_NC => {
            if ptr.len() < 4 {
                return Err(TccError::linker(format!(
                    "R_ARM_THM_MOVW/MOVT_ABS: buffer too small ({} bytes, need 4)",
                    ptr.len()
                )));
            }
            relocate_thumb_movw_movt_abs(rel_type, ptr, val);
        }

        // =================================================================
        // R_ARM_PREL31
        // 31-bit PC-relative relocation (used for exception tables).
        // Source: arm-link.c lines 370-381
        // =================================================================
        R_ARM_PREL31 => {
            if ptr.len() < 4 {
                return Err(TccError::linker(format!(
                    "R_ARM_PREL31: buffer too small ({} bytes, need 4)",
                    ptr.len()
                )));
            }
            relocate_prel31(ptr, addr, val)?;
        }

        // =================================================================
        // R_ARM_ABS32 / R_ARM_TARGET1
        // 32-bit absolute relocation.
        // For non-DLL output: add32le(ptr, val).
        // For DLL output: dynamic relocations are emitted by the caller.
        // Source: arm-link.c lines 382-397
        // =================================================================
        R_ARM_ABS32 | R_ARM_TARGET1 => {
            if ptr.len() < 4 {
                return Err(TccError::linker(format!(
                    "R_ARM_ABS32/TARGET1: buffer too small ({} bytes, need 4)",
                    ptr.len()
                )));
            }
            add32le(ptr, val as i32);
        }

        // =================================================================
        // R_ARM_REL32
        // 32-bit PC-relative offset: add32le(ptr, val - addr).
        // Source: arm-link.c line 398-399
        // =================================================================
        R_ARM_REL32 => {
            if ptr.len() < 4 {
                return Err(TccError::linker(format!(
                    "R_ARM_REL32: buffer too small ({} bytes, need 4)",
                    ptr.len()
                )));
            }
            add32le(ptr, val.wrapping_sub(addr) as i32);
        }

        // =================================================================
        // R_ARM_GOTPC
        // GOT base, PC-relative: add32le(ptr, got_addr - addr).
        // In the simplified interface, val is expected to be GOT base addr.
        // Source: arm-link.c lines 401-402
        // =================================================================
        R_ARM_GOTPC => {
            if ptr.len() < 4 {
                return Err(TccError::linker(format!(
                    "R_ARM_GOTPC: buffer too small ({} bytes, need 4)",
                    ptr.len()
                )));
            }
            add32le(ptr, val.wrapping_sub(addr) as i32);
        }

        // =================================================================
        // R_ARM_GOTOFF
        // Symbol offset from GOT base: add32le(ptr, val - got_addr).
        // In the simplified interface, val is pre-adjusted by the caller.
        // Source: arm-link.c lines 404-405
        // =================================================================
        R_ARM_GOTOFF => {
            if ptr.len() < 4 {
                return Err(TccError::linker(format!(
                    "R_ARM_GOTOFF: buffer too small ({} bytes, need 4)",
                    ptr.len()
                )));
            }
            add32le(ptr, val as i32);
        }

        // =================================================================
        // R_ARM_GOT32
        // 32-bit GOT entry offset: add32le(ptr, got_offset).
        // In the simplified interface, val is the GOT entry offset.
        // Source: arm-link.c lines 407-410
        // =================================================================
        R_ARM_GOT32 => {
            if ptr.len() < 4 {
                return Err(TccError::linker(format!(
                    "R_ARM_GOT32: buffer too small ({} bytes, need 4)",
                    ptr.len()
                )));
            }
            add32le(ptr, val as i32);
        }

        // =================================================================
        // R_ARM_GOT_PREL
        // GOT entry, PC-relative: add32le(ptr, got_addr + offset - addr).
        // In the simplified interface, val is pre-adjusted by the caller.
        // Source: arm-link.c lines 411-416
        // =================================================================
        R_ARM_GOT_PREL => {
            if ptr.len() < 4 {
                return Err(TccError::linker(format!(
                    "R_ARM_GOT_PREL: buffer too small ({} bytes, need 4)",
                    ptr.len()
                )));
            }
            add32le(ptr, val.wrapping_sub(addr) as i32);
        }

        // =================================================================
        // R_ARM_COPY
        // Copy symbol at runtime — no patching needed.
        // Source: arm-link.c line 417-418
        // =================================================================
        R_ARM_COPY => {
            // No-op: handled by the dynamic linker.
        }

        // =================================================================
        // R_ARM_V4BX
        // ARMv4 BX Rm → MOV PC, Rm conversion.
        // Trades Thumb interworking support for ARMv4 compatibility.
        // Source: arm-link.c lines 419-422
        // =================================================================
        R_ARM_V4BX => {
            if ptr.len() < 4 {
                return Err(TccError::linker(format!(
                    "R_ARM_V4BX: buffer too small ({} bytes, need 4)",
                    ptr.len()
                )));
            }
            let insn = read32le(ptr);
            // Check for BX Rm instruction pattern: xxxx 0001 0010 1111 1111 0001 xxxx
            if (insn & 0x0fff_fff0) == 0x012F_FF10 {
                // Convert BX Rm (0xE12FFF1x) to MOV PC, Rm (0xE1A0F00x)
                write32le(ptr, insn ^ 0xE12F_FF10 ^ 0xE1A0_F000);
            }
        }

        // =================================================================
        // R_ARM_GLOB_DAT / R_ARM_JUMP_SLOT
        // Direct symbol address write: write32le(ptr, val).
        // Source: arm-link.c lines 424-426
        // =================================================================
        R_ARM_GLOB_DAT | R_ARM_JUMP_SLOT => {
            if ptr.len() < 4 {
                return Err(TccError::linker(format!(
                    "R_ARM_GLOB_DAT/JUMP_SLOT: buffer too small ({} bytes, need 4)",
                    ptr.len()
                )));
            }
            write32le(ptr, val as u32);
        }

        // =================================================================
        // R_ARM_NONE
        // No relocation — used for dependency tracking (e.g., EABI exceptions).
        // Source: arm-link.c lines 428-431
        // =================================================================
        R_ARM_NONE => {
            // No-op.
        }

        // =================================================================
        // R_ARM_RELATIVE
        // Base address adjustment for position-independent code.
        // On ELF: no-op (handled by dynamic linker at load time).
        // On PE: add32le(ptr, val - pe_imagebase) — PE adjustment is
        //        expected to be pre-computed in val by the caller.
        // Source: arm-link.c lines 432-437
        // =================================================================
        R_ARM_RELATIVE => {
            // On ELF targets, RELATIVE relocations are handled by the
            // dynamic linker at load time — nothing to do here.
            // On PE targets, the caller should pre-adjust val.
        }

        // =================================================================
        // Unknown relocation type
        // Source: arm-link.c lines 438-441
        // =================================================================
        _ => {
            return Err(TccError::linker(format!(
                "unsupported ARM relocation type {} at {:#x}",
                rel_type, addr
            )));
        }
    }

    Ok(())
}

// ===========================================================================
// Private helper functions for complex relocation types
// ===========================================================================

/// Handles ARM branch relocations (R_ARM_PC24 / CALL / JUMP24 / PLT32).
///
/// Reads the existing 24-bit signed offset from the branch instruction,
/// adds `(val - addr)` to compute the new target offset, handles Thumb
/// interworking (BL → BLX conversion), and range-checks ±32 MiB.
///
/// Source: arm-link.c lines 191-228.
fn relocate_arm_branch(
    backend: &ArmBackend,
    rel_type: i32,
    ptr: &mut [u8],
    addr: u64,
    val: u64,
) -> TccResult<()> {
    let code = read32le(ptr);

    // Extract existing 24-bit signed offset
    // Source: arm-link.c lines 198-205
    let mut x: i32 = (code & 0x00ff_ffff) as i32;
    let opcode = code & 0xff00_0000;
    x <<= 2; // scale to byte offset (each unit = 4 bytes)
    if x & 0x0200_0000 != 0 {
        x -= 0x0400_0000; // sign-extend 26-bit to 32-bit
    }

    // BLX availability depends on ARMv5+ (CONFIG_TCC_CPUVER >= 5)
    // Source: arm-link.c line 206
    let blx_avail = backend.cpu_version >= 5;
    let is_thumb = (val & 1) != 0;
    let is_bl = opcode == 0xeb00_0000; // BL instruction opcode
    let is_call = rel_type == R_ARM_CALL
        || (rel_type == R_ARM_PC24 && is_bl);

    // Add relocation offset
    // Source: arm-link.c line 210
    x = x.wrapping_add(val.wrapping_sub(addr) as i32);

    // Extract half-word alignment bit (bit 1 of offset)
    // Source: arm-link.c line 215
    let h = x & 2;

    // Check for Thumb interworking problems:
    // - (x & 3) != 0 means target is not word-aligned (Thumb code)
    //   AND either BLX not available or not a call → error
    // Source: arm-link.c lines 216-218
    let th_ko = (x & 3) != 0 && (!blx_avail || !is_call);
    if th_ko || !(-0x0200_0000..0x0200_0000).contains(&x) {
        return Err(TccError::linker(format!(
            "can't relocate value at {:#x}, type {}",
            addr, rel_type
        )));
    }

    // Encode the 24-bit offset field
    // Source: arm-link.c lines 219-220
    x >>= 2;
    x &= 0x00ff_ffff;

    // Handle Thumb target: convert BL → BLX
    // Source: arm-link.c lines 222-225
    let final_code = if is_thumb {
        // Set half-word bit in bit[24] for BLX encoding
        let thumb_x = (x as u32) | ((h as u32) << 24);
        // BLX opcode (0xFA000000) replaces BL (0xEB000000)
        0xfa00_0000 | thumb_x
    } else {
        opcode | (x as u32)
    };

    write32le(ptr, final_code);
    Ok(())
}

/// Handles Thumb-2 branch relocations (R_ARM_THM_PC22 / THM_JUMP24).
///
/// Reads the 32-bit Thumb-2 instruction (two 16-bit half-words), decodes
/// the 25-bit signed offset, applies the relocation, handles Thumb→ARM
/// transition (BL → BLX), and re-encodes the result.
///
/// Note: Thumb-2 stub creation for non-call Thumb→ARM jumps requires
/// full symbol table access and is handled at a higher level (elf.rs).
/// This function handles the basic offset computation and encoding.
///
/// Source: arm-link.c lines 232-323.
fn relocate_thumb_branch(
    rel_type: i32,
    ptr: &mut [u8],
    addr: u64,
    val: u64,
) -> TccResult<()> {
    // Read 32-bit Thumb-2 instruction (two 16-bit half-words)
    // Source: arm-link.c lines 245-246
    let hi = read16le(ptr) as i32;
    let lo = read16le(&ptr[2..]) as i32;

    // Decode the 25-bit signed offset from the Thumb-2 BL/B.W encoding
    // Source: arm-link.c lines 247-257
    let s = (hi >> 10) & 1;
    let j1 = (lo >> 13) & 1;
    let j2 = (lo >> 11) & 1;
    let i1 = (j1 ^ s) ^ 1;
    let i2 = (j2 ^ s) ^ 1;
    let imm10 = hi & 0x3ff;
    let imm11 = lo & 0x7ff;

    // Assemble 25-bit signed offset
    let mut x: i32 = (s << 24)
        | (i1 << 23)
        | (i2 << 22)
        | (imm10 << 12)
        | (imm11 << 1);
    if x & 0x0100_0000 != 0 {
        x -= 0x0200_0000; // sign-extend 25-bit to 32-bit
    }

    // Determine interworking mode
    // Source: arm-link.c lines 260-264
    let to_thumb = (val & 1) != 0;
    let is_call = rel_type == R_ARM_THM_PC22;
    let mut blx_bit: i32 = 1 << 12; // default: BL (not BLX)

    // Apply relocation offset
    // Source: arm-link.c line 294
    x = x.wrapping_add(val.wrapping_sub(addr) as i32);

    // Handle Thumb→ARM transition for calls: BL → BLX
    // Source: arm-link.c lines 295-298
    if !to_thumb && is_call {
        blx_bit = 0; // clear bit 12 → BLX encoding
        x = (x + 3) & !3; // align offset to 4-byte boundary
    }

    // Range check: ±16 MiB for Thumb-2 branches
    // Source: arm-link.c lines 305-307
    if !to_thumb || !(-0x0100_0000..0x0100_0000).contains(&x) {
        // If target is ARM and offset is valid, or if out of range
        if to_thumb || (val & 2) != 0 || (!is_call) {
            return Err(TccError::linker(format!(
                "can't relocate value at {:#x}, type {}",
                addr, rel_type
            )));
        }
    }

    // Re-encode the offset back into Thumb-2 format
    // Source: arm-link.c lines 310-321
    let new_s = (x >> 24) & 1;
    let new_i1 = (x >> 23) & 1;
    let new_i2 = (x >> 22) & 1;
    let new_j1 = new_s ^ (new_i1 ^ 1);
    let new_j2 = new_s ^ (new_i2 ^ 1);
    let new_imm10 = (x >> 12) & 0x3ff;
    let new_imm11 = (x >> 1) & 0x7ff;

    // Write back the two half-words
    write16le(
        ptr,
        ((hi & 0xf800) | (new_s << 10) | new_imm10) as u16,
    );
    write16le(
        &mut ptr[2..],
        ((lo & 0xc000) | (new_j1 << 13) | blx_bit | (new_j2 << 11) | new_imm11) as u16,
    );

    Ok(())
}

/// Handles ARM MOVW/MOVT absolute address relocations.
///
/// For `R_ARM_MOVT_ABS`: uses high 16 bits of val (val >> 16).
/// For `R_ARM_MOVW_ABS_NC`: uses low 16 bits of val.
///
/// Encodes the 16-bit value as: imm4 (bits [19:16]) | imm12 (bits [11:0]).
///
/// Source: arm-link.c lines 324-337.
fn relocate_arm_movw_movt_abs(rel_type: i32, ptr: &mut [u8], val: u64) {
    let mut v = val as i32;
    if rel_type == R_ARM_MOVT_ABS {
        v >>= 16;
    }
    let imm12 = v & 0xfff;
    let imm4 = (v >> 12) & 0xf;
    let x = ((imm4 << 16) | imm12) as u32;

    // Note: arm-link.c line 333-336 checks for R_ARM_THM_MOVT_ABS here
    // but that case is handled separately. For ARM MOVW: add the encoded
    // value to the existing instruction (preserving opcode and register).
    add32le(ptr, x as i32);
}

/// Handles ARM MOVW/MOVT PC-relative address relocations.
///
/// Reads the existing addend from the instruction's imm4:imm12 fields,
/// sign-extends it, computes `val + addend - addr`, then for MOVT shifts
/// right by 16. Re-encodes the result into the instruction.
///
/// Source: arm-link.c lines 339-352.
fn relocate_arm_movw_movt_prel(rel_type: i32, ptr: &mut [u8], addr: u64, val: u64) {
    let insn = read32le(ptr);

    // Extract existing addend from imm4:imm12 encoding
    // Source: arm-link.c lines 342-343
    let addend_raw = (((insn >> 4) & 0xf000) | (insn & 0xfff)) as i32;
    // Sign-extend 16-bit addend
    let addend = (addend_raw ^ 0x8000) - 0x8000;

    // Compute new value: val + addend - addr
    // Source: arm-link.c line 346
    let mut v = (val as i64 + addend as i64 - addr as i64) as i32;

    // For MOVT_PREL: use high 16 bits
    // Source: arm-link.c lines 347-348
    if rel_type == R_ARM_MOVT_PREL {
        v >>= 16;
    }

    // Re-encode: clear imm4 and imm12 fields, write new value
    // Source: arm-link.c lines 349-350
    let new_insn = (insn & 0xfff0_f000)
        | (((v as u32) & 0xf000) << 4)
        | ((v as u32) & 0xfff);
    write32le(ptr, new_insn);
}

/// Handles Thumb-2 MOVW/MOVT absolute address relocations.
///
/// For `R_ARM_THM_MOVT_ABS`: uses high 16 bits of val (val >> 16).
/// For `R_ARM_THM_MOVW_ABS_NC`: uses low 16 bits of val.
///
/// Encodes using Thumb-2 MOVW/MOVT format:
///   imm3 (bits [14:12] of second half) | imm8 (bits [7:0] of second half) |
///   i (bit [26] of first half) | imm4 (bits [3:0] of first half).
///
/// Source: arm-link.c lines 353-368.
fn relocate_thumb_movw_movt_abs(rel_type: i32, ptr: &mut [u8], val: u64) {
    let mut v = val as i32;
    if rel_type == R_ARM_THM_MOVT_ABS {
        v >>= 16;
    }

    // Extract fields for Thumb-2 MOVW/MOVT encoding
    // Source: arm-link.c lines 359-363
    let imm8 = v & 0xff;
    let imm3 = (v >> 8) & 0x7;
    let i = (v >> 11) & 1;
    let imm4 = (v >> 12) & 0xf;

    // Compose encoded value:
    //   imm3 goes to bits [28:26] (shifted by 28 relative to combined 32-bit)
    //   imm8 goes to bits [23:16]
    //   i goes to bit [10] (first half-word)
    //   imm4 goes to bits [3:0] (first half-word)
    let x = ((imm3 << 28) | (imm8 << 16) | (i << 10) | imm4) as u32;

    // Apply: for MOVT, OR with existing (preserve opcode); for MOVW, add.
    // Source: arm-link.c lines 364-367
    if rel_type == R_ARM_THM_MOVT_ABS {
        write32le(ptr, read32le(ptr) | x);
    } else {
        add32le(ptr, x as i32);
    }
}

/// Handles R_ARM_PREL31: 31-bit PC-relative relocation for exception tables.
///
/// Reads the 31-bit signed value (preserving bit[31] as tag), adds
/// `(val - addr)`, range-checks to ensure the result fits in 31 bits,
/// and writes back preserving the tag bit.
///
/// Source: arm-link.c lines 370-381.
fn relocate_prel31(ptr: &mut [u8], addr: u64, val: u64) -> TccResult<()> {
    // Read 31-bit signed value (bit[31] is preserved separately)
    // Source: arm-link.c lines 373-374
    let mut x = (read32le(ptr) & 0x7fff_ffff) as i32;

    // Preserve bit[31] (tag bit for exception handling)
    let tag = read32le(ptr) & 0x8000_0000;
    // Clear the value portion (write tag only)
    write32le(ptr, tag);

    // Sign-extend 31-bit to 32-bit: (x * 2) / 2
    // Source: arm-link.c line 375
    x = (x * 2) / 2;

    // Apply relocation offset
    // Source: arm-link.c line 376
    x = x.wrapping_add(val.wrapping_sub(addr) as i32);

    // Range check: must fit in 31 signed bits.
    // The check (x ^ (x >> 1)) & 0x40000000 detects overflow:
    // if bit 30 and bit 31 of x differ, x doesn't fit in 31 bits.
    // Source: arm-link.c lines 377-378
    if (x ^ (x >> 1)) & 0x4000_0000 != 0 {
        return Err(TccError::linker(format!(
            "can't relocate R_ARM_PREL31 value at {:#x}",
            addr
        )));
    }

    // Write back value (31 bits) | tag (bit[31])
    // Source: arm-link.c line 379
    write32le(ptr, read32le(ptr) | ((x as u32) & 0x7fff_ffff));
    Ok(())
}

// ===========================================================================
// Unit tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // code_reloc tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_code_reloc_data_types() {
        // All data relocation types should return 0
        assert_eq!(code_reloc(R_ARM_MOVT_ABS), 0);
        assert_eq!(code_reloc(R_ARM_MOVW_ABS_NC), 0);
        assert_eq!(code_reloc(R_ARM_THM_MOVT_ABS), 0);
        assert_eq!(code_reloc(R_ARM_THM_MOVW_ABS_NC), 0);
        assert_eq!(code_reloc(R_ARM_ABS32), 0);
        assert_eq!(code_reloc(R_ARM_REL32), 0);
        assert_eq!(code_reloc(R_ARM_GOTPC), 0);
        assert_eq!(code_reloc(R_ARM_GOTOFF), 0);
        assert_eq!(code_reloc(R_ARM_GOT32), 0);
        assert_eq!(code_reloc(R_ARM_GOT_PREL), 0);
        assert_eq!(code_reloc(R_ARM_COPY), 0);
        assert_eq!(code_reloc(R_ARM_GLOB_DAT), 0);
        assert_eq!(code_reloc(R_ARM_NONE), 0);
        assert_eq!(code_reloc(R_ARM_TARGET1), 0);
        assert_eq!(code_reloc(R_ARM_MOVT_PREL), 0);
        assert_eq!(code_reloc(R_ARM_MOVW_PREL_NC), 0);
    }

    #[test]
    fn test_code_reloc_code_types() {
        // All code relocation types should return 1
        assert_eq!(code_reloc(R_ARM_PC24), 1);
        assert_eq!(code_reloc(R_ARM_CALL), 1);
        assert_eq!(code_reloc(R_ARM_JUMP24), 1);
        assert_eq!(code_reloc(R_ARM_PLT32), 1);
        assert_eq!(code_reloc(R_ARM_THM_PC22), 1);
        assert_eq!(code_reloc(R_ARM_THM_JUMP24), 1);
        assert_eq!(code_reloc(R_ARM_PREL31), 1);
        assert_eq!(code_reloc(R_ARM_V4BX), 1);
        assert_eq!(code_reloc(R_ARM_JUMP_SLOT), 1);
    }

    #[test]
    fn test_code_reloc_unknown() {
        assert_eq!(code_reloc(999), -1);
        assert_eq!(code_reloc(-1), -1);
    }

    // -----------------------------------------------------------------------
    // gotplt_entry_type tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_gotplt_no_entry() {
        assert_eq!(gotplt_entry_type(R_ARM_NONE), NO_GOTPLT_ENTRY);
        assert_eq!(gotplt_entry_type(R_ARM_COPY), NO_GOTPLT_ENTRY);
        assert_eq!(gotplt_entry_type(R_ARM_GLOB_DAT), NO_GOTPLT_ENTRY);
        assert_eq!(gotplt_entry_type(R_ARM_JUMP_SLOT), NO_GOTPLT_ENTRY);
    }

    #[test]
    fn test_gotplt_auto_entry() {
        assert_eq!(gotplt_entry_type(R_ARM_PC24), AUTO_GOTPLT_ENTRY);
        assert_eq!(gotplt_entry_type(R_ARM_CALL), AUTO_GOTPLT_ENTRY);
        assert_eq!(gotplt_entry_type(R_ARM_JUMP24), AUTO_GOTPLT_ENTRY);
        assert_eq!(gotplt_entry_type(R_ARM_PLT32), AUTO_GOTPLT_ENTRY);
        assert_eq!(gotplt_entry_type(R_ARM_THM_PC22), AUTO_GOTPLT_ENTRY);
        assert_eq!(gotplt_entry_type(R_ARM_THM_JUMP24), AUTO_GOTPLT_ENTRY);
        assert_eq!(gotplt_entry_type(R_ARM_MOVT_ABS), AUTO_GOTPLT_ENTRY);
        assert_eq!(gotplt_entry_type(R_ARM_MOVW_ABS_NC), AUTO_GOTPLT_ENTRY);
        assert_eq!(gotplt_entry_type(R_ARM_THM_MOVT_ABS), AUTO_GOTPLT_ENTRY);
        assert_eq!(gotplt_entry_type(R_ARM_THM_MOVW_ABS_NC), AUTO_GOTPLT_ENTRY);
        assert_eq!(gotplt_entry_type(R_ARM_PREL31), AUTO_GOTPLT_ENTRY);
        assert_eq!(gotplt_entry_type(R_ARM_ABS32), AUTO_GOTPLT_ENTRY);
        assert_eq!(gotplt_entry_type(R_ARM_REL32), AUTO_GOTPLT_ENTRY);
        assert_eq!(gotplt_entry_type(R_ARM_V4BX), AUTO_GOTPLT_ENTRY);
        assert_eq!(gotplt_entry_type(R_ARM_TARGET1), AUTO_GOTPLT_ENTRY);
        assert_eq!(gotplt_entry_type(R_ARM_MOVT_PREL), AUTO_GOTPLT_ENTRY);
        assert_eq!(gotplt_entry_type(R_ARM_MOVW_PREL_NC), AUTO_GOTPLT_ENTRY);
    }

    #[test]
    fn test_gotplt_build_got_only() {
        assert_eq!(gotplt_entry_type(R_ARM_GOTPC), BUILD_GOT_ONLY);
        assert_eq!(gotplt_entry_type(R_ARM_GOTOFF), BUILD_GOT_ONLY);
    }

    #[test]
    fn test_gotplt_always_entry() {
        assert_eq!(gotplt_entry_type(R_ARM_GOT32), ALWAYS_GOTPLT_ENTRY);
        assert_eq!(gotplt_entry_type(R_ARM_GOT_PREL), ALWAYS_GOTPLT_ENTRY);
    }

    #[test]
    fn test_gotplt_unknown() {
        assert_eq!(gotplt_entry_type(999), -1);
    }

    // -----------------------------------------------------------------------
    // Relocation constant value tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_arm_reloc_constants() {
        assert_eq!(R_ARM_NONE, 0);
        assert_eq!(R_ARM_PC24, 1);
        assert_eq!(R_ARM_ABS32, 2);
        assert_eq!(R_ARM_REL32, 3);
        assert_eq!(R_ARM_THM_PC22, 10);
        assert_eq!(R_ARM_COPY, 20);
        assert_eq!(R_ARM_GLOB_DAT, 21);
        assert_eq!(R_ARM_JUMP_SLOT, 22);
        assert_eq!(R_ARM_RELATIVE, 23);
        assert_eq!(R_ARM_GOTOFF, 24);
        assert_eq!(R_ARM_GOTPC, 25);
        assert_eq!(R_ARM_GOT32, 26);
        assert_eq!(R_ARM_PLT32, 27);
        assert_eq!(R_ARM_CALL, 28);
        assert_eq!(R_ARM_JUMP24, 29);
        assert_eq!(R_ARM_THM_JUMP24, 30);
        assert_eq!(R_ARM_TARGET1, 38);
        assert_eq!(R_ARM_V4BX, 40);
        assert_eq!(R_ARM_PREL31, 42);
        assert_eq!(R_ARM_MOVW_ABS_NC, 43);
        assert_eq!(R_ARM_MOVT_ABS, 44);
        assert_eq!(R_ARM_MOVW_PREL_NC, 45);
        assert_eq!(R_ARM_MOVT_PREL, 46);
        assert_eq!(R_ARM_THM_MOVW_ABS_NC, 47);
        assert_eq!(R_ARM_THM_MOVT_ABS, 48);
        assert_eq!(R_ARM_GOT_PREL, 96);
        assert_eq!(R_ARM_NUM, 256);
    }

    // -----------------------------------------------------------------------
    // relocate tests — basic relocation types
    // -----------------------------------------------------------------------

    #[test]
    fn test_relocate_none() {
        let mut backend = ArmBackend::new();
        let mut buf = [0u8; 4];
        assert!(relocate(&mut backend, R_ARM_NONE, &mut buf, 0, 0).is_ok());
        assert_eq!(buf, [0, 0, 0, 0]);
    }

    #[test]
    fn test_relocate_copy() {
        let mut backend = ArmBackend::new();
        let mut buf = [0xAA; 4];
        assert!(relocate(&mut backend, R_ARM_COPY, &mut buf, 0, 0).is_ok());
        assert_eq!(buf, [0xAA, 0xAA, 0xAA, 0xAA]); // unchanged
    }

    #[test]
    fn test_relocate_abs32() {
        let mut backend = ArmBackend::new();
        let mut buf = [0u8; 4];
        write32le(&mut buf, 0x1000);
        assert!(relocate(&mut backend, R_ARM_ABS32, &mut buf, 0, 0x2000).is_ok());
        assert_eq!(read32le(&buf), 0x3000); // 0x1000 + 0x2000
    }

    #[test]
    fn test_relocate_rel32() {
        let mut backend = ArmBackend::new();
        let mut buf = [0u8; 4];
        write32le(&mut buf, 0);
        let addr: u64 = 0x8000;
        let val: u64 = 0x9000;
        assert!(relocate(&mut backend, R_ARM_REL32, &mut buf, addr, val).is_ok());
        assert_eq!(read32le(&buf), 0x1000); // 0x9000 - 0x8000
    }

    #[test]
    fn test_relocate_glob_dat() {
        let mut backend = ArmBackend::new();
        let mut buf = [0u8; 4];
        let val: u64 = 0x12345678;
        assert!(relocate(&mut backend, R_ARM_GLOB_DAT, &mut buf, 0, val).is_ok());
        assert_eq!(read32le(&buf), 0x12345678);
    }

    #[test]
    fn test_relocate_jump_slot() {
        let mut backend = ArmBackend::new();
        let mut buf = [0u8; 4];
        let val: u64 = 0xDEADBEEF;
        assert!(relocate(&mut backend, R_ARM_JUMP_SLOT, &mut buf, 0, val).is_ok());
        assert_eq!(read32le(&buf), 0xDEADBEEF);
    }

    #[test]
    fn test_relocate_v4bx_converts_bx_to_mov() {
        let mut backend = ArmBackend::new();
        // BX r3 = 0xE12FFF13
        let mut buf = [0u8; 4];
        write32le(&mut buf, 0xE12FFF13);
        assert!(relocate(&mut backend, R_ARM_V4BX, &mut buf, 0, 0).is_ok());
        // Should become MOV PC, r3 = 0xE1A0F003
        assert_eq!(read32le(&buf), 0xE1A0F003);
    }

    #[test]
    fn test_relocate_v4bx_non_bx_unchanged() {
        let mut backend = ArmBackend::new();
        // Not a BX instruction
        let mut buf = [0u8; 4];
        write32le(&mut buf, 0xE1A00001);
        assert!(relocate(&mut backend, R_ARM_V4BX, &mut buf, 0, 0).is_ok());
        // Should remain unchanged
        assert_eq!(read32le(&buf), 0xE1A00001);
    }

    #[test]
    fn test_relocate_unknown_type_returns_error() {
        let mut backend = ArmBackend::new();
        let mut buf = [0u8; 4];
        let result = relocate(&mut backend, 999, &mut buf, 0, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_relocate_buffer_too_small() {
        let mut backend = ArmBackend::new();
        let mut buf = [0u8; 2]; // too small for 32-bit relocations
        let result = relocate(&mut backend, R_ARM_ABS32, &mut buf, 0, 0);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // ARM MOVW/MOVT relocation tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_relocate_movw_abs_nc() {
        let mut backend = ArmBackend::new();
        // MOVW r0, #0 = 0xE3000000
        let mut buf = [0u8; 4];
        write32le(&mut buf, 0xE300_0000);
        // val = 0x1234 → imm4=1, imm12=0x234
        // encoded: (1 << 16) | 0x234 = 0x10234
        assert!(
            relocate(&mut backend, R_ARM_MOVW_ABS_NC, &mut buf, 0, 0x1234).is_ok()
        );
        let result = read32le(&buf);
        // Original 0xE3000000 + 0x10234 = 0xE3010234
        assert_eq!(result, 0xE301_0234);
    }

    #[test]
    fn test_relocate_movt_abs() {
        let mut backend = ArmBackend::new();
        // MOVT r0, #0 = 0xE3400000
        let mut buf = [0u8; 4];
        write32le(&mut buf, 0xE340_0000);
        // val = 0x56780000 → val >> 16 = 0x5678
        // imm4 = 5, imm12 = 0x678, x = (5 << 16) | 0x678 = 0x50678
        assert!(
            relocate(&mut backend, R_ARM_MOVT_ABS, &mut buf, 0, 0x5678_0000).is_ok()
        );
        let result = read32le(&buf);
        // Original 0xE3400000 + 0x50678 = 0xE3450678
        assert_eq!(result, 0xE345_0678);
    }

    // -----------------------------------------------------------------------
    // ARM branch relocation tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_relocate_arm_branch_forward() {
        let mut backend = ArmBackend::new();
        // BL +0 (B instruction with zero offset) = 0xEB000000
        let mut buf = [0u8; 4];
        write32le(&mut buf, 0xEB00_0000);
        // Target is 256 bytes ahead: val - addr = 256
        let addr: u64 = 0x1000;
        let val: u64 = 0x1100;
        assert!(relocate(&mut backend, R_ARM_CALL, &mut buf, addr, val).is_ok());
        let result = read32le(&buf);
        // Offset = 256 >> 2 = 64 = 0x40
        assert_eq!(result & 0xFF00_0000, 0xEB00_0000); // still BL
        assert_eq!(result & 0x00FF_FFFF, 0x40);
    }

    #[test]
    fn test_relocate_arm_branch_to_thumb() {
        let mut backend = ArmBackend::new();
        backend.cpu_version = 5; // BLX available
        // BL instruction: 0xEB000000
        let mut buf = [0u8; 4];
        write32le(&mut buf, 0xEB00_0000);
        // Target has bit 0 set (Thumb code), word-aligned: val = 0x1101
        let addr: u64 = 0x1000;
        let val: u64 = 0x1101; // Thumb target
        assert!(relocate(&mut backend, R_ARM_CALL, &mut buf, addr, val).is_ok());
        let result = read32le(&buf);
        // Should be BLX (0xFA000000) since target is Thumb
        assert_eq!(result & 0xFE00_0000, 0xFA00_0000);
    }

    #[test]
    fn test_relocate_arm_branch_out_of_range() {
        let mut backend = ArmBackend::new();
        let mut buf = [0u8; 4];
        write32le(&mut buf, 0xEB00_0000);
        // Target is way too far: > 32 MiB away
        let addr: u64 = 0;
        let val: u64 = 0x0400_0000; // exactly 64 MiB
        let result = relocate(&mut backend, R_ARM_CALL, &mut buf, addr, val);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // PREL31 relocation tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_relocate_prel31_basic() {
        let mut backend = ArmBackend::new();
        let mut buf = [0u8; 4];
        // Set tag bit + zero offset: 0x80000000
        write32le(&mut buf, 0x8000_0000);
        let addr: u64 = 0x1000;
        let val: u64 = 0x1100;
        assert!(relocate(&mut backend, R_ARM_PREL31, &mut buf, addr, val).is_ok());
        let result = read32le(&buf);
        // Tag bit preserved, offset = 0x100
        assert_eq!(result & 0x8000_0000, 0x8000_0000);
        assert_eq!(result & 0x7FFF_FFFF, 0x100);
    }

    // -----------------------------------------------------------------------
    // GOTPLT constant re-export tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_gotplt_constant_values() {
        assert_eq!(NO_GOTPLT_ENTRY, 0);
        assert_eq!(BUILD_GOT_ONLY, 1);
        assert_eq!(AUTO_GOTPLT_ENTRY, 2);
        assert_eq!(ALWAYS_GOTPLT_ENTRY, 3);
    }
}
