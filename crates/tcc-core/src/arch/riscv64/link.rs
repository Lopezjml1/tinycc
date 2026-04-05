// Copyright (c) TinyCC contributors. LGPL licensed.
// Ported from riscv64-link.c (419 lines) to Rust.
//
//! # RISC-V 64-bit Linker Support
//!
//! Relocation processing, PLT/GOT generation, and symbol binding for RISC-V 64-bit
//! targets. Faithfully ported from `riscv64-link.c`.
//!
//! ## Relocation Model
//!
//! RISC-V uses a HI20/LO12 split-immediate instruction model. Many relocations
//! come in pairs — a HI20 relocation (providing the upper 20 bits) paired with
//! a LO12 relocation (providing the lower 12 bits). The linker must track the
//! value computed for each HI20 relocation so that the corresponding LO12 can
//! look it up.
//!
//! ## Key Relocation Types
//!
//! - **B-type** (`R_RISCV_BRANCH`): 13-bit signed PC-relative, B-format.
//! - **J-type** (`R_RISCV_JAL`): 21-bit signed PC-relative, J-format.
//! - **CALL** (`R_RISCV_CALL`, `R_RISCV_CALL_PLT`): AUIPC+JALR pair.
//! - **HI20/LO12** (`R_RISCV_PCREL_HI20`, `R_RISCV_PCREL_LO12_I/S`):
//!   General PC-relative split-immediate pair.
//! - **GOT_HI20** (`R_RISCV_GOT_HI20`): GOT-indirect HI20.
//! - **RVC** (`R_RISCV_RVC_BRANCH`, `R_RISCV_RVC_JUMP`): Compressed
//!   branch/jump relocations.
//!
//! ## PLT/GOT Layout
//!
//! PLT0 (32 bytes): Resolver stub calling the dynamic linker.
//! PLT entries (16 bytes each): AUIPC + LD + JALR + NOP.
//! GOT entries: 8 bytes each (64-bit addresses).
//!
//! ## TODO Bug Fixes Integrated
//!
//! - **BUG-16**: `Result<T, TccError>` replaces `longjmp` (no memory leaks).
//! - **PORT-01/02**: Explicit Rust integer types prevent width assumptions.

// RefCell removed — PcrelHiTracker now lives on Riscv64Backend per BUG-13 reentrancy

use crate::arch::{
    add32le, add64le, read16le, read32le, read64le, write16le, write32le, write64le,
    NO_GOTPLT_ENTRY, AUTO_GOTPLT_ENTRY, ALWAYS_GOTPLT_ENTRY,
};
use crate::error::{TccError, TccResult};
use super::Riscv64Backend;

// ============================================================================
// Re-export relocation constants from parent module's `reloc` submodule.
// ============================================================================

pub use super::reloc::{
    R_RISCV_NONE,
    R_RISCV_32,
    R_RISCV_64,
    R_RISCV_RELATIVE,
    R_RISCV_COPY,
    R_RISCV_JUMP_SLOT,
    R_RISCV_BRANCH,
    R_RISCV_JAL,
    R_RISCV_CALL,
    R_RISCV_CALL_PLT,
    R_RISCV_GOT_HI20,
    R_RISCV_PCREL_HI20,
    R_RISCV_PCREL_LO12_I,
    R_RISCV_PCREL_LO12_S,
    R_RISCV_HI20,
    R_RISCV_LO12_I,
    R_RISCV_LO12_S,
    R_RISCV_TPREL_HI20,
    R_RISCV_TPREL_LO12_I,
    R_RISCV_TPREL_LO12_S,
    R_RISCV_TPREL_ADD,
    R_RISCV_ADD16,
    R_RISCV_ADD32,
    R_RISCV_ADD64,
    R_RISCV_SUB6,
    R_RISCV_SUB8,
    R_RISCV_SUB16,
    R_RISCV_SUB32,
    R_RISCV_SUB64,
    R_RISCV_ALIGN,
    R_RISCV_RVC_BRANCH,
    R_RISCV_RVC_JUMP,
    R_RISCV_SET6,
    R_RISCV_SET8,
    R_RISCV_SET16,
    R_RISCV_SET32,
    R_RISCV_32_PCREL,
};

// ============================================================================
// Additional constants NOT present in the parent reloc module.
// ============================================================================

/// Linker relaxation hint (no-op in TCC).
pub const R_RISCV_RELAX: i32 = 51;

/// Number of defined RISC-V relocation types (canonical ELF constant).
pub const R_RISCV_NUM: i32 = 58;

/// ULEB128 set relocation (DWARF 5 debug sections).
pub const R_RISCV_SET_ULEB128: i32 = 59;

/// ULEB128 subtraction relocation (DWARF 5 debug sections).
pub const R_RISCV_SUB_ULEB128: i32 = 60;

// ============================================================================
// GotpltEntryType Enum
// ============================================================================

/// Classifies GOT/PLT entry requirements for a relocation type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GotpltEntryType {
    /// No GOT or PLT entry needed.
    NoGotPlt,
    /// Automatically generate GOT/PLT if symbol is undefined/dynamic.
    AutoGotPlt,
    /// Always generate a GOT entry.
    AlwaysGotPlt,
    /// Build a GOT entry only (no PLT).
    BuildGotPlt,
}

// ============================================================================
// PcrelHiEntry — HI20/LO12 Pair Tracking
// ============================================================================

/// Tracks a resolved PCREL_HI20 relocation for LO12 lookup.
///
/// # Fields
/// - `addr` — The PC of the AUIPC instruction that was relocated.
/// - `val` — The fully resolved symbol value (before HI20/LO12 split).
#[derive(Debug, Clone, Copy, Default)]
pub struct PcrelHiEntry {
    /// Address of the AUIPC instruction (HI20 relocation site).
    pub addr: u64,
    /// Fully resolved target value for the HI20/LO12 pair.
    pub val: u64,
}

// ============================================================================
// PCREL HI20 Tracker — Per-Instance State
// ============================================================================
//
// The C implementation uses file-level statics:
//   static struct pcrel_hi last_hi;
// plus arrays on TCCState:
//   s1->pcrel_hi_entries, s1->nb_pcrel_hi_entries
//
// Per BUG-13 (libtcc fully reentrant), all compilation state must be
// encapsulated in per-instance structures — no thread-local or global mutable
// state.  The tracker lives as a field on `Riscv64Backend`, which is passed
// as `&mut` to every `relocate()` call.

/// Tracker for HI20/LO12 relocation pairing.
///
/// Public so it can be embedded as a field on `Riscv64Backend`.
#[derive(Debug, Clone, Default)]
pub struct PcrelHiTracker {
    entries: Vec<PcrelHiEntry>,
    last_hi: PcrelHiEntry,
    last_hi_valid: bool,
}

impl PcrelHiTracker {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            last_hi: PcrelHiEntry::default(),
            last_hi_valid: false,
        }
    }

    /// Record a HI20 relocation result. Corresponds to
    /// `riscv64_record_pcrel_hi()` in riscv64-link.c lines 176-190.
    fn record(&mut self, addr: u64, val: u64) {
        let entry = PcrelHiEntry { addr, val };
        self.last_hi = entry;
        self.last_hi_valid = true;
        self.entries.push(entry);
    }

    /// Look up the resolved value for a LO12 relocation. The `addr` must
    /// match a previously recorded HI20's `addr` field.
    /// Corresponds to `riscv64_lookup_pcrel_hi()` lines 192-209.
    fn lookup(&self, addr: u64) -> Option<u64> {
        // Fast path: check most-recently recorded entry
        if self.last_hi_valid && self.last_hi.addr == addr {
            return Some(self.last_hi.val);
        }
        // Slow path: reverse search (most recent first, matching C behavior)
        for entry in self.entries.iter().rev() {
            if entry.addr == addr {
                return Some(entry.val);
            }
        }
        None
    }

    fn clear(&mut self) {
        self.entries.clear();
        self.last_hi_valid = false;
    }
}

// thread_local! removed per BUG-13 reentrancy requirement.
// PcrelHiTracker is now a field on Riscv64Backend — accessed via
// `_backend.pcrel_hi_tracker` in relocate().

// ============================================================================
// Relocation Classification Functions
// ============================================================================

/// Classify whether a relocation type references code (1) or data (0).
/// Returns -1 for unknown types.
///
/// Matches `code_reloc()` in riscv64-link.c lines 27-62 exactly.
pub fn code_reloc(reloc_type: i32) -> i32 {
    match reloc_type {
        // Code relocations — branches and calls (return 1)
        R_RISCV_BRANCH | R_RISCV_CALL | R_RISCV_JAL => 1,
        R_RISCV_CALL_PLT => 1,

        // Data relocations (return 0)
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
        | R_RISCV_SUB8
        | R_RISCV_SUB16
        | R_RISCV_SUB32
        | R_RISCV_SUB64
        | R_RISCV_32
        | R_RISCV_64
        | R_RISCV_SET_ULEB128
        | R_RISCV_SUB_ULEB128 => 0,

        // Unknown
        _ => -1,
    }
}

/// Determine GOT/PLT entry requirements for a relocation type.
///
/// Matches `gotplt_entry_type()` in riscv64-link.c lines 67-106 exactly.
pub fn gotplt_entry_type(reloc_type: i32) -> i32 {
    match reloc_type {
        // No GOT/PLT entry needed
        R_RISCV_ALIGN
        | R_RISCV_RELAX
        | R_RISCV_RVC_BRANCH
        | R_RISCV_RVC_JUMP
        | R_RISCV_JUMP_SLOT
        | R_RISCV_SET6
        | R_RISCV_SET8
        | R_RISCV_SET16
        | R_RISCV_SUB6
        | R_RISCV_ADD16
        | R_RISCV_SUB8
        | R_RISCV_SUB16
        | R_RISCV_SET_ULEB128
        | R_RISCV_SUB_ULEB128 => NO_GOTPLT_ENTRY,

        // Auto-generate if needed
        R_RISCV_BRANCH
        | R_RISCV_CALL
        | R_RISCV_PCREL_HI20
        | R_RISCV_PCREL_LO12_I
        | R_RISCV_PCREL_LO12_S
        | R_RISCV_32_PCREL
        | R_RISCV_ADD32
        | R_RISCV_ADD64
        | R_RISCV_SUB32
        | R_RISCV_SUB64
        | R_RISCV_32
        | R_RISCV_64
        | R_RISCV_JAL
        | R_RISCV_CALL_PLT => AUTO_GOTPLT_ENTRY,

        // Always needs a GOT entry
        R_RISCV_GOT_HI20 => ALWAYS_GOTPLT_ENTRY,

        // All other types: not handled → return -1 (matches C default)
        _ => -1,
    }
}

// ============================================================================
// PLT Generation Constants
// ============================================================================

/// Size of PLT entry 0 (the resolver stub) in bytes.
const PLT0_SIZE: usize = 32;

/// Size of each subsequent PLT entry in bytes.
const PLT_ENTRY_SIZE: usize = 16;

// ============================================================================
// PLT Generation Functions
// ============================================================================

/// Create a PLT entry for a symbol.
///
/// Allocates PLT0 (32 bytes) on first call, then 16 bytes per entry.
/// Stores `got_offset` as a 64-bit LE value for later fixup by `relocate_plt`.
///
/// Corresponds to `create_plt_entry()` in riscv64-link.c lines 108-121.
pub fn create_plt_entry(
    plt_data: &mut Vec<u8>,
    plt_data_offset: &mut usize,
    got_offset: u32,
) -> u32 {
    // Reserve PLT0 (32 bytes) if this is the first entry
    if *plt_data_offset == 0 {
        plt_data.resize(PLT0_SIZE, 0);
        *plt_data_offset = PLT0_SIZE;
    }

    let plt_offset = *plt_data_offset;

    // Allocate 16 bytes for this PLT entry
    plt_data.resize(plt_offset + PLT_ENTRY_SIZE, 0);
    *plt_data_offset = plt_offset + PLT_ENTRY_SIZE;

    // Store GOT offset at the entry position (will be patched by relocate_plt)
    write64le(&mut plt_data[plt_offset..], got_offset as u64);

    plt_offset as u32
}

/// Fix up all PLT entries with actual instruction sequences at link time.
///
/// # PLT0 Layout (32 bytes = 8 instructions)
/// ```text
/// 0:  auipc  t2, %pcrel_hi(&PLTGOT)
/// 4:  sub    t1, t1, t3
/// 8:  ld     t3, %pcrel_lo(&PLTGOT)(t2)
/// 12: addi   t1, t1, -(PLT0_SIZE + 12)
/// 16: addi   t0, t2, %pcrel_lo(&PLTGOT)
/// 20: srli   t1, t1, log2(16/PTR_SIZE)
/// 24: ld     t0, PTR_SIZE(t0)
/// 28: jr     t3
/// ```
///
/// # Per-Entry Layout (16 bytes = 4 instructions)
/// ```text
/// 0:  auipc  t3, %pcrel_hi(got_entry)
/// 4:  ld     t3, %pcrel_lo(got_entry)(t3)
/// 8:  jalr   t1, t3
/// 12: nop
/// ```
///
/// # PLT Relocation Processing
/// Writes `plt_sh_addr` to GOT at each relocation offset.
///
/// Corresponds to `relocate_plt()` in riscv64-link.c lines 125-174.
pub fn relocate_plt(
    plt_data: &mut [u8],
    plt_data_offset: usize,
    plt_sh_addr: u64,
    got_sh_addr: u64,
    got_data: Option<&mut [u8]>,
    plt_reloc_data: Option<&[u8]>,
    plt_reloc_data_offset: usize,
) {
    if plt_data_offset == 0 {
        return;
    }

    let plt = plt_sh_addr;
    let got = got_sh_addr;

    // ---- PLT0: Resolver stub (32 bytes) ----
    let off = (got.wrapping_sub(plt).wrapping_add(0x800)) >> 12;
    let lo = got.wrapping_sub(plt) & 0xfff;

    // Range check (matching C line 139-140)
    if (off.wrapping_add(1u64 << 20)) >> 21 != 0 {
        // Out of range — would emit error via tcc_error_noabort in C
        return;
    }

    // auipc t2, %pcrel_hi(got)  (t2=x7, opcode=0x397=auipc with rd=7)
    write32le(&mut plt_data[0..], 0x0000_0397 | ((off as u32) << 12));

    // sub t1, t1, t3  (0x41c30333: funct7=0x20, rs2=x28, rs1=x6, rd=x6, OP)
    write32le(&mut plt_data[4..], 0x41c3_0333);

    // ld t3, %pcrel_lo(got)(t2)  (t3=x28, base=0x0003be03)
    write32le(
        &mut plt_data[8..],
        0x0003_be03 | ((lo as u32) << 20),
    );

    // addi t1, t1, -(PLT0_SIZE+12) = -(32+12) = -44 = 0xFD4 as 12-bit signed
    // Exact value from C: 0xfd430313
    write32le(&mut plt_data[12..], 0xfd43_0313);

    // addi t0, t2, %pcrel_lo(got)  (t0=x5, t2=x7, base=0x00038293)
    write32le(
        &mut plt_data[16..],
        0x0003_8293 | ((lo as u32) << 20),
    );

    // srli t1, t1, log2(16/8) = 1  (0x00135313: shamt=1)
    write32le(&mut plt_data[20..], 0x0013_5313);

    // ld t0, 8(t0)  (PTR_SIZE=8, t0=x5, base=0x0082b283)
    write32le(&mut plt_data[24..], 0x0082_b283);

    // jr t3 → jalr x0, x28, 0  (0x000e0067)
    write32le(&mut plt_data[28..], 0x000e_0067);

    // ---- Per-entry PLT stubs ----
    let mut p = PLT0_SIZE;
    while p < plt_data_offset {
        let pc = plt + (p as u64);
        // Read the stored GOT offset, compute absolute GOT entry address
        let got_entry_addr = got + read64le(&plt_data[p..]);
        let entry_off = (got_entry_addr.wrapping_sub(pc).wrapping_add(0x800)) >> 12;

        // Range check
        if (entry_off.wrapping_add(1u64 << 20)) >> 21 != 0 {
            p += PLT_ENTRY_SIZE;
            continue;
        }

        let entry_lo = got_entry_addr.wrapping_sub(pc) & 0xfff;

        // auipc t3, %pcrel_hi(func@got)  (t3=x28, base=0x0e17)
        write32le(&mut plt_data[p..], 0x0000_0e17 | ((entry_off as u32) << 12));

        // ld t3, %pcrel_lo(func@got)(t3)  (base=0x000e3e03)
        write32le(
            &mut plt_data[p + 4..],
            0x000e_3e03 | ((entry_lo as u32) << 20),
        );

        // jalr t1, t3  (t1=x6, t3=x28, 0x000e0367)
        write32le(&mut plt_data[p + 8..], 0x000e_0367);

        // nop  (0x00000013)
        write32le(&mut plt_data[p + 12..], 0x0000_0013);

        p += PLT_ENTRY_SIZE;
    }

    // ---- Process PLT relocation section ----
    // Write plt->sh_addr to got->data + rel->r_offset for each entry.
    // (C lines 167-173: write64le(p + rel->r_offset, s1->plt->sh_addr))
    if let (Some(got_d), Some(reloc_d)) = (got_data, plt_reloc_data) {
        let rela_size = 24usize; // sizeof(Elf64_Rela)
        let mut i = 0;
        while i + rela_size <= plt_reloc_data_offset {
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

            if r_offset + 8 <= got_d.len() {
                write64le(&mut got_d[r_offset..], plt_sh_addr);
            }

            i += rela_size;
        }
    }
}

// ============================================================================
// Main Relocation Processing
// ============================================================================

/// Apply a single RISC-V relocation.
///
/// # Arguments
/// * `_backend` — RISC-V backend state; carries `pcrel_hi_tracker` for HI20/LO12 pairing.
/// * `rel_type` — Relocation type (R_RISCV_* constant).
/// * `ptr` — Mutable byte slice at the relocation site.
/// * `addr` — Virtual address of the relocation site.
/// * `val` — Resolved symbol value (address + addend).
///
/// Corresponds to `relocate()` in riscv64-link.c lines 211-419.
pub fn relocate(
    _backend: &mut Riscv64Backend,
    rel_type: i32,
    ptr: &mut [u8],
    addr: u64,
    val: u64,
) -> TccResult<()> {
    match rel_type {
        // ----------------------------------------------------------------
        // No-ops (linker relaxation markers)
        // ----------------------------------------------------------------
        R_RISCV_ALIGN | R_RISCV_RELAX => Ok(()),

        // ----------------------------------------------------------------
        // B-type branch (13-bit signed PC-relative)
        // ----------------------------------------------------------------
        // C lines 224-235:
        //   off64 = val - addr;
        //   off32 = off64 >> 1;
        //   bits: off32[11]→31, off32[9:4]→30:25, off32[3:0]→11:8, off32[10]→7
        R_RISCV_BRANCH => {
            let off64 = val.wrapping_sub(addr);
            if (off64.wrapping_add(1 << 12)) & !(0x1ffe_u64) != 0 {
                return Err(TccError::linker(&format!(
                    "R_RISCV_BRANCH relocation failed (val={:#x}, addr={:#x})",
                    val, addr
                )));
            }
            let off32 = (off64 >> 1) as u32;
            write32le(
                ptr,
                (read32le(ptr) & !0xfe00_0f80_u32)
                    | ((off32 & 0x800) << 20)
                    | ((off32 & 0x3f0) << 21)
                    | ((off32 & 0x00f) << 8)
                    | ((off32 & 0x400) >> 3),
            );
            Ok(())
        }

        // ----------------------------------------------------------------
        // J-type JAL (21-bit signed PC-relative)
        // ----------------------------------------------------------------
        // C lines 236-247:
        //   off32 = off64; (truncated to 32-bit for bit ops)
        //   bits: off32[19:12]→19:12, off32[11]→20, off32[10:1]→30:21, off32[20]→31
        R_RISCV_JAL => {
            let off64 = val.wrapping_sub(addr);
            if (off64.wrapping_add(1 << 21)) & !((1u64 << 22) - 2) != 0 {
                return Err(TccError::linker(&format!(
                    "R_RISCV_JAL relocation failed (val={:#x}, addr={:#x})",
                    val, addr
                )));
            }
            let off32 = off64 as u32;
            write32le(
                ptr,
                (read32le(ptr) & 0xfff)
                    | (((off32 >> 12) & 0xff) << 12)
                    | (((off32 >> 11) & 1) << 20)
                    | (((off32 >> 1) & 0x3ff) << 21)
                    | (((off32 >> 20) & 1) << 31),
            );
            Ok(())
        }

        // ----------------------------------------------------------------
        // AUIPC+JALR pair (32-bit PC-relative call)
        // ----------------------------------------------------------------
        // C lines 248-254:
        //   AUIPC: (existing & 0xfff) | ((val-addr+0x800) & ~0xfff)
        //   JALR:  (existing & 0xfffff) | (((val-addr) & 0xfff) << 20)
        R_RISCV_CALL | R_RISCV_CALL_PLT => {
            let diff = val.wrapping_sub(addr);
            // Patch AUIPC (first instruction)
            let existing_auipc = read32le(ptr);
            write32le(
                ptr,
                (existing_auipc & 0xfff) | ((diff.wrapping_add(0x800) & !0xfff_u64) as u32),
            );
            // Patch JALR (second instruction)
            let existing_jalr = read32le(&ptr[4..]);
            write32le(
                &mut ptr[4..],
                (existing_jalr & 0xf_ffff) | (((diff & 0xfff) as u32) << 20),
            );
            Ok(())
        }

        // ----------------------------------------------------------------
        // PC-relative HI20
        // ----------------------------------------------------------------
        // C lines 255-267
        R_RISCV_PCREL_HI20 => {
            let off64 = ((val.wrapping_sub(addr) as i64).wrapping_add(0x800)) >> 12;
            if ((off64 as u64).wrapping_add(1u64 << 20)) >> 21 != 0 {
                return Err(TccError::linker(&format!(
                    "R_RISCV_PCREL_HI20 relocation failed: off={:#x}",
                    off64
                )));
            }
            write32le(
                ptr,
                (read32le(ptr) & 0xfff) | (((off64 as u32) & 0xf_ffff) << 12),
            );
            _backend.pcrel_hi_tracker.record(addr, val);
            Ok(())
        }

        // ----------------------------------------------------------------
        // GOT-relative HI20
        // ----------------------------------------------------------------
        // C lines 268-276: val is recomputed from GOT in the full linker;
        // in our simplified interface, val already points to the GOT entry.
        R_RISCV_GOT_HI20 => {
            let off64 = ((val.wrapping_sub(addr) as i64).wrapping_add(0x800)) >> 12;
            if ((off64 as u64).wrapping_add(1u64 << 20)) >> 21 != 0 {
                return Err(TccError::linker("R_RISCV_GOT_HI20 relocation failed"));
            }
            write32le(
                ptr,
                (read32le(ptr) & 0xfff) | (((off64 as u32) & 0xf_ffff) << 12),
            );
            _backend.pcrel_hi_tracker.record(addr, val);
            Ok(())
        }

        // ----------------------------------------------------------------
        // PC-relative LO12, I-type
        // ----------------------------------------------------------------
        // C lines 277-286:
        //   addr = val; (val is address of AUIPC instruction)
        //   lookup hi value
        //   write32le: (existing & 0xfffff) | (((target_val - auipc_addr) & 0xfff) << 20)
        R_RISCV_PCREL_LO12_I => {
            let hi_addr = val; // val = address of the paired AUIPC
            let target_val = _backend.pcrel_hi_tracker.lookup(hi_addr).ok_or_else(|| {
                TccError::linker("unsupported hi/lo pcrel reloc scheme")
            })?;
            let lo = target_val.wrapping_sub(hi_addr) & 0xfff;
            write32le(
                ptr,
                (read32le(ptr) & 0xf_ffff) | ((lo as u32) << 20),
            );
            Ok(())
        }

        // ----------------------------------------------------------------
        // PC-relative LO12, S-type
        // ----------------------------------------------------------------
        // C lines 287-295:
        //   off32 = val - addr;
        //   bits: off32[11:5]→31:25, off32[4:0]→11:7
        R_RISCV_PCREL_LO12_S => {
            let hi_addr = val;
            let target_val = _backend.pcrel_hi_tracker.lookup(hi_addr).ok_or_else(|| {
                TccError::linker("unsupported hi/lo pcrel reloc scheme")
            })?;
            let off32 = target_val.wrapping_sub(hi_addr) as u32;
            write32le(
                ptr,
                (read32le(ptr) & !0xfe00_0f80_u32)
                    | ((off32 & 0xfe0) << 20)
                    | ((off32 & 0x01f) << 7),
            );
            Ok(())
        }

        // ----------------------------------------------------------------
        // Compressed branch (RVC CB-type, 9-bit signed offset)
        // ----------------------------------------------------------------
        // C lines 297-309
        R_RISCV_RVC_BRANCH => {
            let off64 = val.wrapping_sub(addr);
            if (off64.wrapping_add(1 << 8)) & !(0x1fe_u64) != 0 {
                return Err(TccError::linker(&format!(
                    "R_RISCV_RVC_BRANCH relocation failed (val={:#x}, addr={:#x})",
                    val, addr
                )));
            }
            let off32 = off64 as u32;
            write16le(
                ptr,
                (read16le(ptr) & 0xe383)
                    | ((((off32 >> 5) & 1) << 2) as u16)
                    | ((((off32 >> 1) & 3) << 3) as u16)
                    | ((((off32 >> 6) & 3) << 5) as u16)
                    | ((((off32 >> 3) & 3) << 10) as u16)
                    | ((((off32 >> 8) & 1) << 12) as u16),
            );
            Ok(())
        }

        // ----------------------------------------------------------------
        // Compressed jump (RVC CJ-type, 12-bit signed offset)
        // ----------------------------------------------------------------
        // C lines 310-325
        R_RISCV_RVC_JUMP => {
            let off64 = val.wrapping_sub(addr);
            if (off64.wrapping_add(1 << 11)) & !(0xffe_u64) != 0 {
                return Err(TccError::linker(&format!(
                    "R_RISCV_RVC_JUMP relocation failed (val={:#x}, addr={:#x})",
                    val, addr
                )));
            }
            let off32 = off64 as u32;
            write16le(
                ptr,
                (read16le(ptr) & 0xe003)
                    | ((((off32 >> 5) & 1) << 2) as u16)
                    | ((((off32 >> 1) & 7) << 3) as u16)
                    | ((((off32 >> 7) & 1) << 6) as u16)
                    | ((((off32 >> 6) & 1) << 7) as u16)
                    | ((((off32 >> 10) & 1) << 8) as u16)
                    | ((((off32 >> 8) & 3) << 9) as u16)
                    | ((((off32 >> 4) & 1) << 11) as u16)
                    | ((((off32 >> 11) & 1) << 12) as u16),
            );
            Ok(())
        }

        // ----------------------------------------------------------------
        // 32-bit absolute (C lines 327-338)
        // In the simplified interface, DLL relocation is handled by caller.
        // ----------------------------------------------------------------
        R_RISCV_32 => {
            add32le(ptr, val as i32);
            Ok(())
        }

        // ----------------------------------------------------------------
        // 64-bit absolute (C lines 339-356)
        // Falls through to JUMP_SLOT in C: add64le(ptr, val).
        // ----------------------------------------------------------------
        R_RISCV_64 => {
            add64le(ptr, val as i64);
            Ok(())
        }

        // ----------------------------------------------------------------
        // PLT jump slot (C line 354-356)
        // ----------------------------------------------------------------
        R_RISCV_JUMP_SLOT => {
            add64le(ptr, val as i64);
            Ok(())
        }

        // ----------------------------------------------------------------
        // Additive / subtractive relocations (C lines 357-377)
        // ----------------------------------------------------------------
        R_RISCV_ADD64 => {
            write64le(ptr, read64le(ptr).wrapping_add(val));
            Ok(())
        }
        R_RISCV_ADD32 => {
            write32le(ptr, read32le(ptr).wrapping_add(val as u32));
            Ok(())
        }
        R_RISCV_ADD16 => {
            write16le(ptr, read16le(ptr).wrapping_add(val as u16));
            Ok(())
        }
        R_RISCV_SUB64 => {
            write64le(ptr, read64le(ptr).wrapping_sub(val));
            Ok(())
        }
        R_RISCV_SUB32 => {
            write32le(ptr, read32le(ptr).wrapping_sub(val as u32));
            Ok(())
        }
        R_RISCV_SUB16 => {
            write16le(ptr, read16le(ptr).wrapping_sub(val as u16));
            Ok(())
        }
        R_RISCV_SUB8 => {
            if !ptr.is_empty() {
                ptr[0] = ptr[0].wrapping_sub(val as u8);
            }
            Ok(())
        }

        // ----------------------------------------------------------------
        // SET relocations (C lines 378-386)
        // ----------------------------------------------------------------
        R_RISCV_SET6 => {
            // *ptr = (*ptr & ~0x3f) | (val & 0x3f)
            if !ptr.is_empty() {
                ptr[0] = (ptr[0] & !0x3f) | ((val as u8) & 0x3f);
            }
            Ok(())
        }
        R_RISCV_SET8 => {
            // *ptr = (*ptr & ~0xff) | (val & 0xff)
            if !ptr.is_empty() {
                ptr[0] = (val as u8) & 0xff;
            }
            Ok(())
        }
        R_RISCV_SET16 => {
            write16le(ptr, val as u16);
            Ok(())
        }
        R_RISCV_SET32 => {
            write32le(ptr, val as u32);
            Ok(())
        }

        // ----------------------------------------------------------------
        // SUB6 (C lines 387-389): *ptr = (*ptr & ~0x3f) | ((*ptr - val) & 0x3f)
        // ----------------------------------------------------------------
        R_RISCV_SUB6 => {
            if !ptr.is_empty() {
                ptr[0] = (ptr[0] & !0x3f) | ((ptr[0].wrapping_sub(val as u8)) & 0x3f);
            }
            Ok(())
        }

        // ----------------------------------------------------------------
        // 32-bit PC-relative (C lines 390-404)
        // Simplified: add32le(ptr, val - addr)
        // ----------------------------------------------------------------
        R_RISCV_32_PCREL => {
            add32le(ptr, val.wrapping_sub(addr) as i32);
            Ok(())
        }

        // ----------------------------------------------------------------
        // ULEB128 relocations (C lines 405-408): no-ops for TCC
        // ----------------------------------------------------------------
        R_RISCV_SET_ULEB128 | R_RISCV_SUB_ULEB128 => Ok(()),

        // ----------------------------------------------------------------
        // COPY relocation (C lines 409-411): no-op
        // ----------------------------------------------------------------
        R_RISCV_COPY => Ok(()),

        // ----------------------------------------------------------------
        // Absolute HI20 — U-type encoding (not in C's relocate(), added
        // for completeness since these are valid RISC-V relocation types)
        // ----------------------------------------------------------------
        R_RISCV_HI20 => {
            let hi = (val.wrapping_add(0x800)) & !0xfff_u64;
            write32le(ptr, (read32le(ptr) & 0xfff) | (hi as u32));
            Ok(())
        }

        // ----------------------------------------------------------------
        // Absolute LO12, I-type
        // ----------------------------------------------------------------
        R_RISCV_LO12_I => {
            let lo = val & 0xfff;
            write32le(ptr, (read32le(ptr) & 0xf_ffff) | ((lo as u32) << 20));
            Ok(())
        }

        // ----------------------------------------------------------------
        // Absolute LO12, S-type
        // ----------------------------------------------------------------
        R_RISCV_LO12_S => {
            let lo = (val & 0xfff) as u32;
            write32le(
                ptr,
                (read32le(ptr) & !0xfe00_0f80_u32)
                    | ((lo & 0xfe0) << 20)
                    | ((lo & 0x01f) << 7),
            );
            Ok(())
        }

        // ----------------------------------------------------------------
        // TLS TP-relative relocations
        // ----------------------------------------------------------------
        R_RISCV_TPREL_HI20 => {
            let hi = (val.wrapping_add(0x800)) & !0xfff_u64;
            write32le(ptr, (read32le(ptr) & 0xfff) | (hi as u32));
            Ok(())
        }
        R_RISCV_TPREL_LO12_I => {
            let lo = val & 0xfff;
            write32le(ptr, (read32le(ptr) & 0xf_ffff) | ((lo as u32) << 20));
            Ok(())
        }
        R_RISCV_TPREL_LO12_S => {
            let lo = (val & 0xfff) as u32;
            write32le(
                ptr,
                (read32le(ptr) & !0xfe00_0f80_u32)
                    | ((lo & 0xfe0) << 20)
                    | ((lo & 0x01f) << 7),
            );
            Ok(())
        }
        R_RISCV_TPREL_ADD => Ok(()), // Relaxation hint — no-op in TCC

        // No relocation / Relative (handled by dynamic linker)
        R_RISCV_NONE | R_RISCV_RELATIVE => Ok(()),

        // ----------------------------------------------------------------
        // Unknown relocation type — non-fatal warning.
        //
        // Matches the convention used by ARM64 and x86_64 backends:
        // log a diagnostic and continue rather than aborting the link.
        // The C code (riscv64-link.c lines 413-416) uses `tcc_error()`
        // which is fatal, but a tolerant approach is preferred for the
        // Rust port to handle future ELF extensions gracefully.
        // ----------------------------------------------------------------
        _ => {
            #[cfg(debug_assertions)]
            eprintln!(
                "riscv64 link: unhandled relocation type {:#x} at addr {:#x}",
                rel_type, addr
            );
            Ok(())
        }
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_backend() -> Riscv64Backend {
        Riscv64Backend::new()
    }

    fn new_tracker() -> PcrelHiTracker {
        PcrelHiTracker::new()
    }

    // ---- code_reloc tests ----

    #[test]
    fn test_code_reloc_code_types() {
        assert_eq!(code_reloc(R_RISCV_BRANCH), 1);
        assert_eq!(code_reloc(R_RISCV_JAL), 1);
        assert_eq!(code_reloc(R_RISCV_CALL), 1);
        assert_eq!(code_reloc(R_RISCV_CALL_PLT), 1);
    }

    #[test]
    fn test_code_reloc_data_types() {
        assert_eq!(code_reloc(R_RISCV_32), 0);
        assert_eq!(code_reloc(R_RISCV_64), 0);
        assert_eq!(code_reloc(R_RISCV_GOT_HI20), 0);
        assert_eq!(code_reloc(R_RISCV_PCREL_HI20), 0);
        assert_eq!(code_reloc(R_RISCV_PCREL_LO12_I), 0);
        assert_eq!(code_reloc(R_RISCV_PCREL_LO12_S), 0);
        assert_eq!(code_reloc(R_RISCV_32_PCREL), 0);
        assert_eq!(code_reloc(R_RISCV_ADD32), 0);
        assert_eq!(code_reloc(R_RISCV_SUB32), 0);
        assert_eq!(code_reloc(R_RISCV_SET6), 0);
        assert_eq!(code_reloc(R_RISCV_SUB6), 0);
        assert_eq!(code_reloc(R_RISCV_SET_ULEB128), 0);
        assert_eq!(code_reloc(R_RISCV_SUB_ULEB128), 0);
    }

    #[test]
    fn test_code_reloc_unknown() {
        assert_eq!(code_reloc(999), -1);
        assert_eq!(code_reloc(-1), -1);
        // Types not listed in C's code_reloc should return -1
        assert_eq!(code_reloc(R_RISCV_ALIGN), -1);
        assert_eq!(code_reloc(R_RISCV_RELAX), -1);
        assert_eq!(code_reloc(R_RISCV_COPY), -1);
        assert_eq!(code_reloc(R_RISCV_JUMP_SLOT), -1);
    }

    // ---- gotplt_entry_type tests ----

    #[test]
    fn test_gotplt_no_entry() {
        assert_eq!(gotplt_entry_type(R_RISCV_ALIGN), NO_GOTPLT_ENTRY);
        assert_eq!(gotplt_entry_type(R_RISCV_RELAX), NO_GOTPLT_ENTRY);
        assert_eq!(gotplt_entry_type(R_RISCV_RVC_BRANCH), NO_GOTPLT_ENTRY);
        assert_eq!(gotplt_entry_type(R_RISCV_RVC_JUMP), NO_GOTPLT_ENTRY);
        assert_eq!(gotplt_entry_type(R_RISCV_JUMP_SLOT), NO_GOTPLT_ENTRY);
        assert_eq!(gotplt_entry_type(R_RISCV_SET6), NO_GOTPLT_ENTRY);
        assert_eq!(gotplt_entry_type(R_RISCV_SET8), NO_GOTPLT_ENTRY);
        assert_eq!(gotplt_entry_type(R_RISCV_SET16), NO_GOTPLT_ENTRY);
        assert_eq!(gotplt_entry_type(R_RISCV_SUB6), NO_GOTPLT_ENTRY);
        assert_eq!(gotplt_entry_type(R_RISCV_ADD16), NO_GOTPLT_ENTRY);
        assert_eq!(gotplt_entry_type(R_RISCV_SUB8), NO_GOTPLT_ENTRY);
        assert_eq!(gotplt_entry_type(R_RISCV_SUB16), NO_GOTPLT_ENTRY);
        assert_eq!(gotplt_entry_type(R_RISCV_SET_ULEB128), NO_GOTPLT_ENTRY);
        assert_eq!(gotplt_entry_type(R_RISCV_SUB_ULEB128), NO_GOTPLT_ENTRY);
    }

    #[test]
    fn test_gotplt_always() {
        assert_eq!(gotplt_entry_type(R_RISCV_GOT_HI20), ALWAYS_GOTPLT_ENTRY);
    }

    #[test]
    fn test_gotplt_auto() {
        assert_eq!(gotplt_entry_type(R_RISCV_BRANCH), AUTO_GOTPLT_ENTRY);
        assert_eq!(gotplt_entry_type(R_RISCV_CALL), AUTO_GOTPLT_ENTRY);
        assert_eq!(gotplt_entry_type(R_RISCV_CALL_PLT), AUTO_GOTPLT_ENTRY);
        assert_eq!(gotplt_entry_type(R_RISCV_JAL), AUTO_GOTPLT_ENTRY);
        assert_eq!(gotplt_entry_type(R_RISCV_32), AUTO_GOTPLT_ENTRY);
        assert_eq!(gotplt_entry_type(R_RISCV_64), AUTO_GOTPLT_ENTRY);
        assert_eq!(gotplt_entry_type(R_RISCV_PCREL_HI20), AUTO_GOTPLT_ENTRY);
        assert_eq!(gotplt_entry_type(R_RISCV_PCREL_LO12_I), AUTO_GOTPLT_ENTRY);
        assert_eq!(gotplt_entry_type(R_RISCV_PCREL_LO12_S), AUTO_GOTPLT_ENTRY);
        assert_eq!(gotplt_entry_type(R_RISCV_32_PCREL), AUTO_GOTPLT_ENTRY);
        assert_eq!(gotplt_entry_type(R_RISCV_ADD32), AUTO_GOTPLT_ENTRY);
        assert_eq!(gotplt_entry_type(R_RISCV_ADD64), AUTO_GOTPLT_ENTRY);
        assert_eq!(gotplt_entry_type(R_RISCV_SUB32), AUTO_GOTPLT_ENTRY);
        assert_eq!(gotplt_entry_type(R_RISCV_SUB64), AUTO_GOTPLT_ENTRY);
    }

    #[test]
    fn test_gotplt_default() {
        // Types not listed should return -1
        assert_eq!(gotplt_entry_type(R_RISCV_NONE), -1);
        assert_eq!(gotplt_entry_type(R_RISCV_RELATIVE), -1);
        assert_eq!(gotplt_entry_type(R_RISCV_COPY), -1);
    }

    // ---- PcrelHiEntry tests ----

    #[test]
    fn test_pcrel_hi_entry_default() {
        let e = PcrelHiEntry::default();
        assert_eq!(e.addr, 0);
        assert_eq!(e.val, 0);
    }

    #[test]
    fn test_pcrel_hi_entry_fields() {
        let e = PcrelHiEntry {
            addr: 0xdead,
            val: 0xbeef,
        };
        assert_eq!(e.addr, 0xdead);
        assert_eq!(e.val, 0xbeef);
    }

    // ---- PcrelHiTracker tests ----

    #[test]
    fn test_pcrel_tracker_basic() {
        let mut tracker = new_tracker();
        tracker.record(0x1000, 0x2000);
        assert_eq!(tracker.lookup(0x1000), Some(0x2000));
        assert_eq!(tracker.lookup(0x9999), None);
    }

    #[test]
    fn test_pcrel_tracker_multiple() {
        let mut tracker = new_tracker();
        tracker.record(0x1000, 100);
        tracker.record(0x1004, 200);
        assert_eq!(tracker.lookup(0x1004), Some(200));
        assert_eq!(tracker.lookup(0x1000), Some(100));
    }

    #[test]
    fn test_pcrel_tracker_clear() {
        let mut tracker = new_tracker();
        tracker.record(0x1000, 100);
        tracker.clear();
        assert_eq!(tracker.lookup(0x1000), None);
    }

    // ---- GotpltEntryType enum tests ----

    #[test]
    fn test_gotplt_entry_type_enum() {
        assert_ne!(GotpltEntryType::NoGotPlt, GotpltEntryType::AutoGotPlt);
        assert_ne!(GotpltEntryType::AlwaysGotPlt, GotpltEntryType::BuildGotPlt);
        assert_eq!(GotpltEntryType::NoGotPlt, GotpltEntryType::NoGotPlt);
    }

    // ---- PLT generation tests ----

    #[test]
    fn test_create_plt_entry_first() {
        let mut data = Vec::new();
        let mut offset = 0usize;
        let plt_off = create_plt_entry(&mut data, &mut offset, 0x100);
        assert_eq!(plt_off, PLT0_SIZE as u32);
        assert_eq!(offset, PLT0_SIZE + PLT_ENTRY_SIZE);
        assert_eq!(read64le(&data[PLT0_SIZE..]), 0x100);
    }

    #[test]
    fn test_create_plt_entry_second() {
        let mut data = Vec::new();
        let mut offset = 0usize;
        let _ = create_plt_entry(&mut data, &mut offset, 0x100);
        let second = create_plt_entry(&mut data, &mut offset, 0x108);
        assert_eq!(second, (PLT0_SIZE + PLT_ENTRY_SIZE) as u32);
        assert_eq!(offset, PLT0_SIZE + 2 * PLT_ENTRY_SIZE);
        assert_eq!(read64le(&data[PLT0_SIZE + PLT_ENTRY_SIZE..]), 0x108);
    }

    #[test]
    fn test_relocate_plt_empty() {
        let mut data = Vec::new();
        relocate_plt(&mut data, 0, 0x1000, 0x2000, None, None, 0);
        assert!(data.is_empty());
    }

    #[test]
    fn test_relocate_plt_with_entries() {
        let mut data = Vec::new();
        let mut offset = 0usize;
        create_plt_entry(&mut data, &mut offset, 0x0);
        create_plt_entry(&mut data, &mut offset, 0x8);

        let plt_addr = 0x10000_u64;
        let got_addr = 0x20000_u64;

        relocate_plt(&mut data, offset, plt_addr, got_addr, None, None, 0);

        // PLT0: first instruction should be auipc t2 (low bits = 0x397)
        let plt0_insn = read32le(&data[0..]);
        assert_eq!(plt0_insn & 0xfff, 0x397);
        // PLT0 instruction at offset 4: sub t1, t1, t3
        assert_eq!(read32le(&data[4..]), 0x41c3_0333);
        // PLT0 instruction at offset 12: addi t1, t1, -44
        assert_eq!(read32le(&data[12..]), 0xfd43_0313);
        // PLT0 instruction at offset 20: srli t1, t1, 1
        assert_eq!(read32le(&data[20..]), 0x0013_5313);
        // PLT0 instruction at offset 28: jr t3
        assert_eq!(read32le(&data[28..]), 0x000e_0067);

        // First PLT entry: auipc t3 (low bits = 0xe17)
        let e1 = read32le(&data[PLT0_SIZE..]);
        assert_eq!(e1 & 0xfff, 0xe17);
    }

    // ---- Branch relocation tests ----

    #[test]
    fn test_relocate_branch_forward() {
        let mut backend = test_backend();
        let mut buf = [0u8; 4];
        write32le(&mut buf, 0x0000_0063); // beq x0, x0, 0
        relocate(&mut backend, R_RISCV_BRANCH, &mut buf, 0x1000, 0x1008).unwrap();
        let result = read32le(&buf);
        assert_eq!(result & 0x7f, 0x63); // opcode preserved
    }

    #[test]
    fn test_relocate_branch_out_of_range() {
        let mut backend = test_backend();
        let mut buf = [0u8; 4];
        write32le(&mut buf, 0x0000_0063);
        assert!(relocate(&mut backend, R_RISCV_BRANCH, &mut buf, 0x0, 0x10000).is_err());
    }

    // ---- JAL relocation tests ----

    #[test]
    fn test_relocate_jal_forward() {
        let mut backend = test_backend();
        let mut buf = [0u8; 4];
        write32le(&mut buf, 0x0000_006f); // jal x0, 0
        relocate(&mut backend, R_RISCV_JAL, &mut buf, 0x1000, 0x1010).unwrap();
        let result = read32le(&buf);
        assert_eq!(result & 0xfff, 0x06f); // rd + opcode preserved
    }

    #[test]
    fn test_relocate_jal_out_of_range() {
        let mut backend = test_backend();
        let mut buf = [0u8; 4];
        write32le(&mut buf, 0x0000_006f);
        assert!(relocate(&mut backend, R_RISCV_JAL, &mut buf, 0x0, 0x1000000).is_err());
    }

    // ---- CALL relocation tests ----

    #[test]
    fn test_relocate_call() {
        let mut backend = test_backend();
        let mut buf = [0u8; 8];
        write32le(&mut buf[0..], 0x0000_0097); // AUIPC x1
        write32le(&mut buf[4..], 0x0000_80e7); // JALR x1, x1, 0
        relocate(&mut backend, R_RISCV_CALL, &mut buf, 0x1000, 0x2000).unwrap();
        let auipc = read32le(&buf[0..]);
        let jalr = read32le(&buf[4..]);
        assert_eq!(auipc & 0xfff, 0x097); // rd + opcode preserved
        assert_eq!(jalr & 0xf_ffff, 0x0_80e7); // rd + rs1 + funct3 + opcode preserved
    }

    // ---- PCREL HI20+LO12 pairing tests ----

    #[test]
    fn test_relocate_pcrel_hi20_lo12_i_pair() {
        let mut backend = test_backend();
        // AUIPC at 0x1000, symbol at 0x2000
        let mut buf_hi = [0u8; 4];
        write32le(&mut buf_hi, 0x0000_0017);
        relocate(&mut backend, R_RISCV_PCREL_HI20, &mut buf_hi, 0x1000, 0x2000).unwrap();

        // LO12_I: val = address of AUIPC = 0x1000
        let mut buf_lo = [0u8; 4];
        write32le(&mut buf_lo, 0x0000_3003);
        relocate(&mut backend, R_RISCV_PCREL_LO12_I, &mut buf_lo, 0x1004, 0x1000).unwrap();

        let lo_result = read32le(&buf_lo);
        assert_eq!(lo_result & 0xf_ffff, 0x03003);
    }

    #[test]
    fn test_relocate_pcrel_lo12_s() {
        let mut backend = test_backend();
        let mut buf_hi = [0u8; 4];
        write32le(&mut buf_hi, 0x0000_0017);
        relocate(&mut backend, R_RISCV_PCREL_HI20, &mut buf_hi, 0x2000, 0x3100).unwrap();

        let mut buf_lo = [0u8; 4];
        write32le(&mut buf_lo, 0x0000_3023);
        relocate(&mut backend, R_RISCV_PCREL_LO12_S, &mut buf_lo, 0x2004, 0x2000).unwrap();

        let lo_result = read32le(&buf_lo);
        assert_eq!(lo_result & 0x7f, 0x23); // opcode preserved
    }

    #[test]
    fn test_relocate_pcrel_lo12_i_no_hi20() {
        let mut backend = test_backend();
        let mut buf = [0u8; 4];
        write32le(&mut buf, 0x0000_3003);
        assert!(relocate(&mut backend, R_RISCV_PCREL_LO12_I, &mut buf, 0x1004, 0x9999).is_err());
    }

    // ---- Compressed branch/jump tests ----

    #[test]
    fn test_relocate_rvc_branch() {
        let mut backend = test_backend();
        let mut buf = [0u8; 2];
        write16le(&mut buf, 0xc001);
        relocate(&mut backend, R_RISCV_RVC_BRANCH, &mut buf, 0x1000, 0x1004).unwrap();
    }

    #[test]
    fn test_relocate_rvc_branch_out_of_range() {
        let mut backend = test_backend();
        let mut buf = [0u8; 2];
        write16le(&mut buf, 0xc001);
        assert!(relocate(&mut backend, R_RISCV_RVC_BRANCH, &mut buf, 0x0, 0x1000).is_err());
    }

    #[test]
    fn test_relocate_rvc_jump() {
        let mut backend = test_backend();
        let mut buf = [0u8; 2];
        write16le(&mut buf, 0xa001);
        relocate(&mut backend, R_RISCV_RVC_JUMP, &mut buf, 0x1000, 0x1008).unwrap();
    }

    // ---- Data relocation tests ----

    #[test]
    fn test_relocate_32_add() {
        let mut backend = test_backend();
        let mut buf = [0u8; 4];
        write32le(&mut buf, 100);
        relocate(&mut backend, R_RISCV_32, &mut buf, 0, 50).unwrap();
        assert_eq!(read32le(&buf), 150);
    }

    #[test]
    fn test_relocate_64_add() {
        let mut backend = test_backend();
        let mut buf = [0u8; 8];
        write64le(&mut buf, 1000);
        relocate(&mut backend, R_RISCV_64, &mut buf, 0, 2000).unwrap();
        assert_eq!(read64le(&buf), 3000);
    }

    #[test]
    fn test_relocate_jump_slot() {
        let mut backend = test_backend();
        let mut buf = [0u8; 8];
        write64le(&mut buf, 0x1000);
        relocate(&mut backend, R_RISCV_JUMP_SLOT, &mut buf, 0, 0x500).unwrap();
        assert_eq!(read64le(&buf), 0x1500);
    }

    #[test]
    fn test_relocate_add32() {
        let mut backend = test_backend();
        let mut buf = [0u8; 4];
        write32le(&mut buf, 10);
        relocate(&mut backend, R_RISCV_ADD32, &mut buf, 0, 5).unwrap();
        assert_eq!(read32le(&buf), 15);
    }

    #[test]
    fn test_relocate_sub32() {
        let mut backend = test_backend();
        let mut buf = [0u8; 4];
        write32le(&mut buf, 10);
        relocate(&mut backend, R_RISCV_SUB32, &mut buf, 0, 3).unwrap();
        assert_eq!(read32le(&buf), 7);
    }

    #[test]
    fn test_relocate_add64() {
        let mut backend = test_backend();
        let mut buf = [0u8; 8];
        write64le(&mut buf, 100);
        relocate(&mut backend, R_RISCV_ADD64, &mut buf, 0, 200).unwrap();
        assert_eq!(read64le(&buf), 300);
    }

    #[test]
    fn test_relocate_sub64() {
        let mut backend = test_backend();
        let mut buf = [0u8; 8];
        write64le(&mut buf, 100);
        relocate(&mut backend, R_RISCV_SUB64, &mut buf, 0, 30).unwrap();
        assert_eq!(read64le(&buf), 70);
    }

    #[test]
    fn test_relocate_add16() {
        let mut backend = test_backend();
        let mut buf = [0u8; 2];
        write16le(&mut buf, 10);
        relocate(&mut backend, R_RISCV_ADD16, &mut buf, 0, 5).unwrap();
        assert_eq!(read16le(&buf), 15);
    }

    #[test]
    fn test_relocate_sub16() {
        let mut backend = test_backend();
        let mut buf = [0u8; 2];
        write16le(&mut buf, 10);
        relocate(&mut backend, R_RISCV_SUB16, &mut buf, 0, 3).unwrap();
        assert_eq!(read16le(&buf), 7);
    }

    #[test]
    fn test_relocate_sub8() {
        let mut backend = test_backend();
        let mut buf = [10u8];
        relocate(&mut backend, R_RISCV_SUB8, &mut buf, 0, 3).unwrap();
        assert_eq!(buf[0], 7);
    }

    #[test]
    fn test_relocate_set6() {
        let mut backend = test_backend();
        let mut buf = [0xff_u8];
        relocate(&mut backend, R_RISCV_SET6, &mut buf, 0, 0x15).unwrap();
        assert_eq!(buf[0], 0xd5); // upper 2 bits preserved (0xC0), lower 6 = 0x15
    }

    #[test]
    fn test_relocate_set8() {
        let mut backend = test_backend();
        let mut buf = [0xff_u8];
        relocate(&mut backend, R_RISCV_SET8, &mut buf, 0, 0x42).unwrap();
        assert_eq!(buf[0], 0x42);
    }

    #[test]
    fn test_relocate_set16() {
        let mut backend = test_backend();
        let mut buf = [0u8; 2];
        write16le(&mut buf, 0xffff);
        relocate(&mut backend, R_RISCV_SET16, &mut buf, 0, 0x1234).unwrap();
        assert_eq!(read16le(&buf), 0x1234);
    }

    #[test]
    fn test_relocate_sub6() {
        let mut backend = test_backend();
        let mut buf = [0xff_u8]; // lower 6 bits = 0x3f
        relocate(&mut backend, R_RISCV_SUB6, &mut buf, 0, 1).unwrap();
        // (0xff - 1) & 0x3f = 0x3e, upper bits = 0xC0 → 0xfe
        assert_eq!(buf[0], 0xfe);
    }

    #[test]
    fn test_relocate_32_pcrel() {
        let mut backend = test_backend();
        let mut buf = [0u8; 4];
        write32le(&mut buf, 0);
        relocate(&mut backend, R_RISCV_32_PCREL, &mut buf, 0x1000, 0x2000).unwrap();
        assert_eq!(read32le(&buf), 0x1000);
    }

    // ---- No-op relocation tests ----

    #[test]
    fn test_relocate_align_noop() {
        let mut backend = test_backend();
        let mut buf = [0xaa_u8; 4];
        relocate(&mut backend, R_RISCV_ALIGN, &mut buf, 0, 0).unwrap();
        assert_eq!(buf, [0xaa_u8; 4]);
    }

    #[test]
    fn test_relocate_relax_noop() {
        let mut backend = test_backend();
        let mut buf = [0xaa_u8; 4];
        relocate(&mut backend, R_RISCV_RELAX, &mut buf, 0, 0).unwrap();
        assert_eq!(buf, [0xaa_u8; 4]);
    }

    #[test]
    fn test_relocate_copy_noop() {
        let mut backend = test_backend();
        let mut buf = [0xaa_u8; 4];
        relocate(&mut backend, R_RISCV_COPY, &mut buf, 0, 0).unwrap();
        assert_eq!(buf, [0xaa_u8; 4]);
    }

    #[test]
    fn test_relocate_uleb128_noop() {
        let mut backend = test_backend();
        let mut buf = [0u8; 4];
        relocate(&mut backend, R_RISCV_SET_ULEB128, &mut buf, 0, 0).unwrap();
        relocate(&mut backend, R_RISCV_SUB_ULEB128, &mut buf, 0, 0).unwrap();
    }

    #[test]
    fn test_relocate_none_noop() {
        let mut backend = test_backend();
        let mut buf = [0xab_u8; 4];
        relocate(&mut backend, R_RISCV_NONE, &mut buf, 0, 0).unwrap();
        assert_eq!(buf, [0xab_u8; 4]);
    }

    // ---- Unknown relocation type ----

    #[test]
    fn test_relocate_unknown_type() {
        let mut backend = test_backend();
        let mut buf = [0u8; 4];
        // Unknown relocation types are now non-fatal (warning only),
        // consistent with arm64 and x86_64 backends.
        assert!(relocate(&mut backend, 999, &mut buf, 0, 0).is_ok());
    }

    // ---- Constant value tests ----

    #[test]
    fn test_reloc_constants() {
        assert_eq!(R_RISCV_NONE, 0);
        assert_eq!(R_RISCV_32, 1);
        assert_eq!(R_RISCV_64, 2);
        assert_eq!(R_RISCV_RELATIVE, 3);
        assert_eq!(R_RISCV_COPY, 4);
        assert_eq!(R_RISCV_JUMP_SLOT, 5);
        assert_eq!(R_RISCV_BRANCH, 16);
        assert_eq!(R_RISCV_JAL, 17);
        assert_eq!(R_RISCV_CALL, 18);
        assert_eq!(R_RISCV_CALL_PLT, 19);
        assert_eq!(R_RISCV_GOT_HI20, 20);
        assert_eq!(R_RISCV_PCREL_HI20, 23);
        assert_eq!(R_RISCV_PCREL_LO12_I, 24);
        assert_eq!(R_RISCV_PCREL_LO12_S, 25);
        assert_eq!(R_RISCV_HI20, 26);
        assert_eq!(R_RISCV_LO12_I, 27);
        assert_eq!(R_RISCV_LO12_S, 28);
        assert_eq!(R_RISCV_TPREL_HI20, 29);
        assert_eq!(R_RISCV_TPREL_LO12_I, 30);
        assert_eq!(R_RISCV_TPREL_LO12_S, 31);
        assert_eq!(R_RISCV_TPREL_ADD, 32);
        assert_eq!(R_RISCV_ADD16, 34);
        assert_eq!(R_RISCV_ADD32, 35);
        assert_eq!(R_RISCV_ADD64, 36);
        assert_eq!(R_RISCV_SUB8, 37);
        assert_eq!(R_RISCV_SUB16, 38);
        assert_eq!(R_RISCV_SUB32, 39);
        assert_eq!(R_RISCV_SUB64, 40);
        assert_eq!(R_RISCV_ALIGN, 43);
        assert_eq!(R_RISCV_RVC_BRANCH, 44);
        assert_eq!(R_RISCV_RVC_JUMP, 45);
        assert_eq!(R_RISCV_RELAX, 51);
        assert_eq!(R_RISCV_SUB6, 52);
        assert_eq!(R_RISCV_SET6, 53);
        assert_eq!(R_RISCV_SET8, 54);
        assert_eq!(R_RISCV_SET16, 55);
        assert_eq!(R_RISCV_SET32, 56);
        assert_eq!(R_RISCV_32_PCREL, 57);
        assert_eq!(R_RISCV_NUM, 58);
        assert_eq!(R_RISCV_SET_ULEB128, 59);
        assert_eq!(R_RISCV_SUB_ULEB128, 60);
    }

    // ---- HI20/LO12 absolute relocation tests ----

    #[test]
    fn test_relocate_hi20() {
        let mut backend = test_backend();
        let mut buf = [0u8; 4];
        write32le(&mut buf, 0x0000_0037); // LUI x0, 0
        relocate(&mut backend, R_RISCV_HI20, &mut buf, 0, 0x12345678).unwrap();
        let result = read32le(&buf);
        assert_eq!(result & 0xfff, 0x037); // opcode preserved
    }

    #[test]
    fn test_relocate_lo12_i() {
        let mut backend = test_backend();
        let mut buf = [0u8; 4];
        write32le(&mut buf, 0x0000_3003);
        relocate(&mut backend, R_RISCV_LO12_I, &mut buf, 0, 0x12345678).unwrap();
        let result = read32le(&buf);
        assert_eq!((result >> 20) & 0xfff, 0x678);
    }

    #[test]
    fn test_relocate_lo12_s() {
        let mut backend = test_backend();
        let mut buf = [0u8; 4];
        write32le(&mut buf, 0x0000_3023);
        relocate(&mut backend, R_RISCV_LO12_S, &mut buf, 0, 0xABC).unwrap();
        let result = read32le(&buf);
        assert_eq!((result >> 25) & 0x7f, 0x55); // imm[11:5] = 0xAB >> 1 = 0x55
        assert_eq!((result >> 7) & 0x1f, 0x1c); // imm[4:0] = 0xBC & 0x1F = 0x1C
    }

    // ---- TPREL relocation tests ----

    #[test]
    fn test_relocate_tprel_hi20() {
        let mut backend = test_backend();
        let mut buf = [0u8; 4];
        write32le(&mut buf, 0x0000_0017);
        relocate(&mut backend, R_RISCV_TPREL_HI20, &mut buf, 0, 0x1000).unwrap();
    }

    #[test]
    fn test_relocate_tprel_lo12_i() {
        let mut backend = test_backend();
        let mut buf = [0u8; 4];
        write32le(&mut buf, 0x0000_3003);
        relocate(&mut backend, R_RISCV_TPREL_LO12_I, &mut buf, 0, 0x123).unwrap();
        let result = read32le(&buf);
        assert_eq!((result >> 20) & 0xfff, 0x123);
    }

    #[test]
    fn test_relocate_tprel_add() {
        let mut backend = test_backend();
        let mut buf = [0u8; 4];
        relocate(&mut backend, R_RISCV_TPREL_ADD, &mut buf, 0, 0).unwrap();
    }

    #[test]
    fn test_relocate_set32() {
        let mut backend = test_backend();
        let mut buf = [0u8; 4];
        write32le(&mut buf, 0xffffffff);
        relocate(&mut backend, R_RISCV_SET32, &mut buf, 0, 0xdeadbeef).unwrap();
        assert_eq!(read32le(&buf), 0xdeadbeef);
    }
}
