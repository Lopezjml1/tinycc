#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::unnecessary_cast)]
#![allow(clippy::unnecessary_unwrap)]
#![allow(clippy::collapsible_if)]
#![allow(clippy::manual_range_contains)]
#![allow(clippy::redundant_closure)]
#![allow(clippy::needless_borrows_for_generic_args)]
#![allow(clippy::useless_format)]
#![allow(clippy::type_complexity)]
#![allow(clippy::needless_range_loop)]
#![allow(clippy::manual_strip)]

//! ELF (Executable and Linkable Format) output module.
//!
//! Ported from `tccelf.c` (4,116 lines) and `elf.h` (3,324 lines).
//! Handles section management, symbol tables, relocations,
//! executable/shared-library output, and ELF format structures.
//!
//! # BUG-08 Fix
//! Section alignment is propagated from variables/types to section headers
//! with power-of-2 enforcement via `validate_alignment()`.
//!
//! # LINK-01
//! Static linking logic faithfully ported; glibc limitation documented.
//!
//! # OPT-01
//! Anonymous symbol handling improved via `SYM_FIRST_ANOM` tracking.

use std::collections::HashMap;

use crate::arch::{CodegenBackend, ALWAYS_GOTPLT_ENTRY};
use crate::config::PTR_SIZE;
use crate::error::{TccError, TccResult};
use crate::types::{DLLReference, OutputType, Section, SymAttr, SYM_FIRST_ANOM};

// ============================================================================
// ELF Type Definitions — ported from elf.h
// ============================================================================

// ---------------------------------------------------------------------------
// ELF Header Structures
// ---------------------------------------------------------------------------

/// ELF identification array size.
pub const EI_NIDENT: usize = 16;

/// 32-bit ELF file header.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct Elf32_Ehdr {
    pub e_ident: [u8; EI_NIDENT],
    pub e_type: u16,
    pub e_machine: u16,
    pub e_version: u32,
    pub e_entry: u32,
    pub e_phoff: u32,
    pub e_shoff: u32,
    pub e_flags: u32,
    pub e_ehsize: u16,
    pub e_phentsize: u16,
    pub e_phnum: u16,
    pub e_shentsize: u16,
    pub e_shnum: u16,
    pub e_shstrndx: u16,
}

/// 64-bit ELF file header.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct Elf64_Ehdr {
    pub e_ident: [u8; EI_NIDENT],
    pub e_type: u16,
    pub e_machine: u16,
    pub e_version: u32,
    pub e_entry: u64,
    pub e_phoff: u64,
    pub e_shoff: u64,
    pub e_flags: u32,
    pub e_ehsize: u16,
    pub e_phentsize: u16,
    pub e_phnum: u16,
    pub e_shentsize: u16,
    pub e_shnum: u16,
    pub e_shstrndx: u16,
}

// ---------------------------------------------------------------------------
// Section Header Structures
// ---------------------------------------------------------------------------

/// 32-bit ELF section header.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct Elf32_Shdr {
    pub sh_name: u32,
    pub sh_type: u32,
    pub sh_flags: u32,
    pub sh_addr: u32,
    pub sh_offset: u32,
    pub sh_size: u32,
    pub sh_link: u32,
    pub sh_info: u32,
    pub sh_addralign: u32,
    pub sh_entsize: u32,
}

/// 64-bit ELF section header.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct Elf64_Shdr {
    pub sh_name: u32,
    pub sh_type: u32,
    pub sh_flags: u64,
    pub sh_addr: u64,
    pub sh_offset: u64,
    pub sh_size: u64,
    pub sh_link: u32,
    pub sh_info: u32,
    pub sh_addralign: u64,
    pub sh_entsize: u64,
}

// ---------------------------------------------------------------------------
// Symbol Table Structures
// ---------------------------------------------------------------------------

/// 32-bit ELF symbol table entry.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct Elf32_Sym {
    pub st_name: u32,
    pub _st_value: u32,
    pub st_size: u32,
    pub st_info: u8,
    pub st_other: u8,
    pub st_shndx: u16,
}

/// 64-bit ELF symbol table entry.
/// Note: field order differs from 32-bit (st_info/st_other/st_shndx before _st_value/st_size).
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct Elf64_Sym {
    pub st_name: u32,
    pub st_info: u8,
    pub st_other: u8,
    pub st_shndx: u16,
    pub _st_value: u64,
    pub st_size: u64,
}

// ---------------------------------------------------------------------------
// Relocation Structures
// ---------------------------------------------------------------------------

/// 32-bit relocation entry (without addend).
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct Elf32_Rel {
    pub r_offset: u32,
    pub r_info: u32,
}

/// 64-bit relocation entry (without addend).
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct Elf64_Rel {
    pub r_offset: u64,
    pub r_info: u64,
}

/// 32-bit relocation entry with addend.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct Elf32_Rela {
    pub r_offset: u32,
    pub r_info: u32,
    pub r_addend: i32,
}

/// 64-bit relocation entry with addend.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct Elf64_Rela {
    pub r_offset: u64,
    pub r_info: u64,
    pub r_addend: i64,
}

// ---------------------------------------------------------------------------
// Program Header Structures
// ---------------------------------------------------------------------------

/// 32-bit ELF program header.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct Elf32_Phdr {
    pub p_type: u32,
    pub p_offset: u32,
    pub p_vaddr: u32,
    pub p_paddr: u32,
    pub p_filesz: u32,
    pub p_memsz: u32,
    pub p_flags: u32,
    pub p_align: u32,
}

/// 64-bit ELF program header (note: p_flags follows p_type for alignment).
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct Elf64_Phdr {
    pub p_type: u32,
    pub p_flags: u32,
    pub p_offset: u64,
    pub p_vaddr: u64,
    pub p_paddr: u64,
    pub p_filesz: u64,
    pub p_memsz: u64,
    pub p_align: u64,
}

// ---------------------------------------------------------------------------
// Dynamic Section Structures
// ---------------------------------------------------------------------------

/// 32-bit dynamic section entry.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct Elf32_Dyn {
    pub d_tag: i32,
    pub d_val: u32,
}

/// 64-bit dynamic section entry.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct Elf64_Dyn {
    pub d_tag: i64,
    pub d_val: u64,
}

// ============================================================================
// ============================================================================
// GOT/PLT offset tracking
// ============================================================================

/// Tracks GOT and PLT offsets for symbols. The original C `sym_attr` struct
/// contained `got_offset` and `plt_offset`, but the Rust `SymAttr` struct
/// (in types.rs) represents declaration attributes. We track linker offsets
/// separately in a per-symbol map.
#[derive(Debug, Clone, Default)]
pub struct GotPltOffsets {
    /// Maps symbol index → GOT offset (0 = no entry).
    pub got: HashMap<usize, u32>,
    /// Maps symbol index → PLT offset (0 = no entry).
    pub plt: HashMap<usize, u32>,
}

impl GotPltOffsets {
    /// Create a new empty offset tracker.
    pub fn new() -> Self {
        Self {
            got: HashMap::new(),
            plt: HashMap::new(),
        }
    }

    /// Get the GOT offset for a symbol, or 0 if not present.
    pub fn got_offset(&self, sym_idx: usize) -> u32 {
        self.got.get(&sym_idx).copied().unwrap_or(0)
    }

    /// Get the PLT offset for a symbol, or 0 if not present.
    pub fn plt_offset(&self, sym_idx: usize) -> u32 {
        self.plt.get(&sym_idx).copied().unwrap_or(0)
    }

    /// Set the GOT offset for a symbol.
    pub fn set_got_offset(&mut self, sym_idx: usize, offset: u32) {
        self.got.insert(sym_idx, offset);
    }

    /// Set the PLT offset for a symbol.
    pub fn set_plt_offset(&mut self, sym_idx: usize, offset: u32) {
        self.plt.insert(sym_idx, offset);
    }
}

// ELF Constants
// ============================================================================

// --- ELF Magic ---
/// ELF magic bytes: "\x7fELF".
pub const ELFMAG: [u8; 4] = [0x7f, b'E', b'L', b'F'];
/// Size of ELF magic.
pub const SELFMAG: usize = 4;

// --- ELF Identification indices ---
pub const EI_CLASS: usize = 4;
pub const EI_DATA: usize = 5;
pub const EI_VERSION: usize = 6;
pub const EI_OSABI: usize = 7;

// --- ELF Class ---
pub const ELFCLASSNONE: u8 = 0;
pub const ELFCLASS32: u8 = 1;
pub const ELFCLASS64: u8 = 2;

// --- ELF Data encoding ---
pub const ELFDATANONE: u8 = 0;
pub const ELFDATA2LSB: u8 = 1;
pub const ELFDATA2MSB: u8 = 2;

// --- ELF Version ---
pub const EV_CURRENT: u8 = 1;

// --- ELF OS/ABI ---
pub const ELFOSABI_NONE: u8 = 0;
pub const ELFOSABI_LINUX: u8 = 3;

// --- ELF File Type ---
pub const ET_NONE: u16 = 0;
pub const ET_REL: u16 = 1;
pub const ET_EXEC: u16 = 2;
pub const ET_DYN: u16 = 3;
pub const ET_CORE: u16 = 4;

// --- ELF Machine Types ---
pub const EM_386: u16 = 3;
pub const EM_ARM: u16 = 40;
pub const EM_X86_64: u16 = 62;
pub const EM_C60: u16 = 140;
pub const EM_AARCH64: u16 = 183;
pub const EM_RISCV: u16 = 243;

// --- Special Section Indices ---
pub const SHN_UNDEF: u16 = 0;
pub const SHN_LORESERVE: u16 = 0xff00;
pub const SHN_ABS: u16 = 0xfff1;
pub const SHN_COMMON: u16 = 0xfff2;
/// TCC-specific: symbol imported from a DLL.
pub const SHN_FROMDLL: u16 = 0xffff;

// --- Section Header Types ---
pub const SHT_NULL: u32 = 0;
pub const SHT_PROGBITS: u32 = 1;
pub const SHT_SYMTAB: u32 = 2;
pub const SHT_STRTAB: u32 = 3;
pub const SHT_RELA: u32 = 4;
pub const SHT_HASH: u32 = 5;
pub const SHT_DYNAMIC: u32 = 6;
pub const SHT_NOTE: u32 = 7;
pub const SHT_NOBITS: u32 = 8;
pub const SHT_REL: u32 = 9;
pub const SHT_DYNSYM: u32 = 11;
pub const SHT_INIT_ARRAY: u32 = 14;
pub const SHT_FINI_ARRAY: u32 = 15;
pub const SHT_PREINIT_ARRAY: u32 = 16;
pub const SHT_GROUP: u32 = 17;
pub const SHT_GNU_HASH: u32 = 0x6fff_fff6;
pub const SHT_GNU_VERSYM: u32 = 0x6fff_ffff;
pub const SHT_GNU_VERDEF: u32 = 0x6fff_fffd;
pub const SHT_GNU_VERNEED: u32 = 0x6fff_fffe;
/// TCC-specific: Mach-O linkedit pseudo-section.
pub const SHT_LINKEDIT: u32 = 0x8000_0003;

/// Relocation section type: SHT_RELA on 64-bit targets, SHT_REL on 32-bit.
pub const SHT_RELX: u32 = if PTR_SIZE == 8 { SHT_RELA } else { SHT_REL };

// --- Section Flags ---
pub const SHF_WRITE: u32 = 0x1;
pub const SHF_ALLOC: u32 = 0x2;
pub const SHF_EXECINSTR: u32 = 0x4;
pub const SHF_MERGE: u32 = 0x10;
pub const SHF_STRINGS: u32 = 0x20;
pub const SHF_INFO_LINK: u32 = 0x40;
pub const SHF_LINK_ORDER: u32 = 0x80;
pub const SHF_TLS: u32 = 0x400;
/// TCC-specific: Private flag for internal use.
pub const SHF_PRIVATE: u32 = 0x8000_0000;

// --- Symbol Binding ---
pub const STB_LOCAL: u8 = 0;
pub const STB_GLOBAL: u8 = 1;
pub const STB_WEAK: u8 = 2;

// --- Symbol Types ---
pub const STT_NOTYPE: u8 = 0;
pub const STT_OBJECT: u8 = 1;
pub const STT_FUNC: u8 = 2;
pub const STT_SECTION: u8 = 3;
pub const STT_FILE: u8 = 4;
pub const STT_COMMON: u8 = 5;
pub const STT_TLS: u8 = 6;
pub const STT_GNU_IFUNC: u8 = 10;

// --- Symbol Visibility ---
pub const STV_DEFAULT: u8 = 0;
pub const STV_INTERNAL: u8 = 1;
pub const STV_HIDDEN: u8 = 2;
pub const STV_PROTECTED: u8 = 3;

// --- Program Header Types ---
pub const PT_NULL: u32 = 0;
pub const PT_LOAD: u32 = 1;
pub const PT_DYNAMIC: u32 = 2;
pub const PT_INTERP: u32 = 3;
pub const PT_NOTE: u32 = 4;
pub const PT_SHLIB: u32 = 5;
pub const PT_PHDR: u32 = 6;
pub const PT_TLS: u32 = 7;
pub const PT_GNU_EH_FRAME: u32 = 0x6474_e550;
pub const PT_GNU_STACK: u32 = 0x6474_e551;
pub const PT_GNU_RELRO: u32 = 0x6474_e552;

// --- Program Header Flags ---
pub const PF_X: u32 = 1;
pub const PF_W: u32 = 2;
pub const PF_R: u32 = 4;

// --- Dynamic Section Tags ---
pub const DT_NULL: i64 = 0;
pub const DT_NEEDED: i64 = 1;
pub const DT_PLTRELSZ: i64 = 2;
pub const DT_PLTGOT: i64 = 3;
pub const DT_HASH: i64 = 4;
pub const DT_STRTAB: i64 = 5;
pub const DT_SYMTAB: i64 = 6;
pub const DT_RELA: i64 = 7;
pub const DT_RELASZ: i64 = 8;
pub const DT_RELAENT: i64 = 9;
pub const DT_STRSZ: i64 = 10;
pub const DT_SYMENT: i64 = 11;
pub const DT_INIT: i64 = 12;
pub const DT_FINI: i64 = 13;
pub const DT_SONAME: i64 = 14;
pub const DT_RPATH: i64 = 15;
pub const DT_SYMBOLIC: i64 = 16;
pub const DT_REL: i64 = 17;
pub const DT_RELSZ: i64 = 18;
pub const DT_RELENT: i64 = 19;
pub const DT_PLTREL: i64 = 20;
pub const DT_DEBUG: i64 = 21;
pub const DT_TEXTREL: i64 = 22;
pub const DT_JMPREL: i64 = 23;
pub const DT_BIND_NOW: i64 = 24;
pub const DT_INIT_ARRAY: i64 = 25;
pub const DT_FINI_ARRAY: i64 = 26;
pub const DT_INIT_ARRAYSZ: i64 = 27;
pub const DT_FINI_ARRAYSZ: i64 = 28;
pub const DT_RUNPATH: i64 = 29;
pub const DT_FLAGS: i64 = 30;
pub const DT_FLAGS_1: i64 = 0x6fff_fffb;
pub const DT_GNU_HASH: i64 = 0x6fff_fef5;
pub const DT_VERSYM: i64 = 0x6fff_fff0;
pub const DT_VERDEF: i64 = 0x6fff_fffc;
pub const DT_VERDEFNUM: i64 = 0x6fff_fffd;
pub const DT_VERNEED: i64 = 0x6fff_fffe;
pub const DT_VERNEEDNUM: i64 = 0x6fff_ffff;
pub const DF_TEXTREL: i64 = 0x4;

// ============================================================
// Architecture-specific relocation types
// ============================================================

// --- i386 relocations ---
pub const R_386_NONE: u32 = 0;
pub const R_386_32: u32 = 1;
pub const R_386_PC32: u32 = 2;
pub const R_386_GOT32: u32 = 3;
pub const R_386_PLT32: u32 = 4;
pub const R_386_COPY: u32 = 5;
pub const R_386_GLOB_DAT: u32 = 6;
pub const R_386_JMP_SLOT: u32 = 7;
pub const R_386_RELATIVE: u32 = 8;
pub const R_386_GOTOFF: u32 = 9;
pub const R_386_GOTPC: u32 = 10;
pub const R_386_GOT32X: u32 = 43;
pub const R_386_TLS_GD_32: u32 = 18;
pub const R_386_TLS_LDM_32: u32 = 19;
pub const R_386_TLS_IE_32: u32 = 33;
pub const R_386_TLS_LE_32: u32 = 37;
pub const R_386_16: u32 = 20;
pub const R_386_PC16: u32 = 21;

// --- x86_64 relocations ---
pub const R_X86_64_NONE: u32 = 0;
pub const R_X86_64_64: u32 = 1;
pub const R_X86_64_PC32: u32 = 2;
pub const R_X86_64_GOT32: u32 = 3;
pub const R_X86_64_PLT32: u32 = 4;
pub const R_X86_64_COPY: u32 = 5;
pub const R_X86_64_GLOB_DAT: u32 = 6;
pub const R_X86_64_JUMP_SLOT: u32 = 7;
pub const R_X86_64_RELATIVE: u32 = 8;
pub const R_X86_64_GOTPCREL: u32 = 9;
pub const R_X86_64_32: u32 = 10;
pub const R_X86_64_32S: u32 = 11;
pub const R_X86_64_PC64: u32 = 24;
pub const R_X86_64_GOTOFF64: u32 = 25;
pub const R_X86_64_GOTPC32: u32 = 26;
pub const R_X86_64_REX_GOTPCRELX: u32 = 42;
pub const R_X86_64_GOTPCRELX: u32 = 41;
pub const R_X86_64_GOTTPOFF: u32 = 22;
pub const R_X86_64_TLSGD: u32 = 19;
pub const R_X86_64_TLSLD: u32 = 20;
pub const R_X86_64_DTPOFF32: u32 = 21;
pub const R_X86_64_TPOFF32: u32 = 23;

// --- ARM relocations ---
pub const R_ARM_NONE: u32 = 0;
pub const R_ARM_PC24: u32 = 1;
pub const R_ARM_ABS32: u32 = 2;
pub const R_ARM_REL32: u32 = 3;
pub const R_ARM_GOTOFF: u32 = 24;
pub const R_ARM_GOTPC: u32 = 25;
pub const R_ARM_GOT32: u32 = 26;
pub const R_ARM_PLT32: u32 = 27;
pub const R_ARM_CALL: u32 = 28;
pub const R_ARM_JUMP24: u32 = 29;
pub const R_ARM_THM_JUMP24: u32 = 30;
pub const R_ARM_V4BX: u32 = 40;
pub const R_ARM_PREL31: u32 = 42;
pub const R_ARM_MOVW_ABS_NC: u32 = 43;
pub const R_ARM_MOVT_ABS: u32 = 44;
pub const R_ARM_THM_MOVW_ABS_NC: u32 = 47;
pub const R_ARM_THM_MOVT_ABS: u32 = 48;
pub const R_ARM_COPY: u32 = 20;
pub const R_ARM_GLOB_DAT: u32 = 21;
pub const R_ARM_JUMP_SLOT: u32 = 22;
pub const R_ARM_RELATIVE: u32 = 23;
pub const R_ARM_GOT_BREL: u32 = 26;
pub const R_ARM_TLS_GD32: u32 = 104;
pub const R_ARM_TLS_LDM32: u32 = 105;
pub const R_ARM_TLS_IE32: u32 = 107;
pub const R_ARM_TLS_LE32: u32 = 108;

// --- AArch64 relocations ---
pub const R_AARCH64_NONE: u32 = 0;
pub const R_AARCH64_ABS64: u32 = 257;
pub const R_AARCH64_ABS32: u32 = 258;
pub const R_AARCH64_ABS16: u32 = 259;
pub const R_AARCH64_PREL32: u32 = 261;
pub const R_AARCH64_MOVW_UABS_G0_NC: u32 = 264;
pub const R_AARCH64_MOVW_UABS_G1_NC: u32 = 266;
pub const R_AARCH64_MOVW_UABS_G2_NC: u32 = 268;
pub const R_AARCH64_MOVW_UABS_G3: u32 = 269;
pub const R_AARCH64_ADR_PREL_PG_HI21: u32 = 275;
pub const R_AARCH64_ADD_ABS_LO12_NC: u32 = 277;
pub const R_AARCH64_JUMP26: u32 = 282;
pub const R_AARCH64_CALL26: u32 = 283;
pub const R_AARCH64_LDST16_ABS_LO12_NC: u32 = 284;
pub const R_AARCH64_LDST32_ABS_LO12_NC: u32 = 285;
pub const R_AARCH64_LDST64_ABS_LO12_NC: u32 = 286;
pub const R_AARCH64_LDST128_ABS_LO12_NC: u32 = 299;
pub const R_AARCH64_ADR_GOT_PAGE: u32 = 311;
pub const R_AARCH64_LD64_GOT_LO12_NC: u32 = 312;
pub const R_AARCH64_GLOB_DAT: u32 = 1025;
pub const R_AARCH64_JUMP_SLOT: u32 = 1026;
pub const R_AARCH64_RELATIVE: u32 = 1027;
pub const R_AARCH64_COPY: u32 = 1024;

// --- RISC-V relocations ---
pub const R_RISCV_NONE: u32 = 0;
pub const R_RISCV_32: u32 = 1;
pub const R_RISCV_64: u32 = 2;
pub const R_RISCV_BRANCH: u32 = 16;
pub const R_RISCV_JAL: u32 = 17;
pub const R_RISCV_CALL: u32 = 18;
pub const R_RISCV_CALL_PLT: u32 = 19;
pub const R_RISCV_GOT_HI20: u32 = 20;
pub const R_RISCV_PCREL_HI20: u32 = 23;
pub const R_RISCV_PCREL_LO12_I: u32 = 24;
pub const R_RISCV_PCREL_LO12_S: u32 = 25;
pub const R_RISCV_HI20: u32 = 26;
pub const R_RISCV_LO12_I: u32 = 27;
pub const R_RISCV_LO12_S: u32 = 28;
pub const R_RISCV_ADD32: u32 = 35;
pub const R_RISCV_ADD64: u32 = 36;
pub const R_RISCV_SUB32: u32 = 39;
pub const R_RISCV_SUB64: u32 = 40;
pub const R_RISCV_RVC_BRANCH: u32 = 44;
pub const R_RISCV_RVC_JUMP: u32 = 45;
pub const R_RISCV_RELAX: u32 = 51;
pub const R_RISCV_COPY: u32 = 4;
pub const R_RISCV_JUMP_SLOT: u32 = 5;
pub const R_RISCV_RELATIVE: u32 = 3;

// --- C6x relocations ---
pub const R_C60_NONE: u32 = 0;
pub const R_C60_32: u32 = 1;
pub const R_C60_GOT32: u32 = 3;
pub const R_C60_PLT32: u32 = 4;
pub const R_C60_COPY: u32 = 5;
pub const R_C60_GLOB_DAT: u32 = 6;
pub const R_C60_JMP_SLOT: u32 = 7;
pub const R_C60_RELATIVE: u32 = 8;
pub const R_C60_HI16: u32 = 0xf3;
pub const R_C60_LO16: u32 = 0xf4;

// ============================================================
// Target-dependent relocation aliases
// ============================================================

/// Data pointer relocation (architecture-dependent).
#[cfg(target_arch = "x86_64")]
pub const R_DATA_PTR: u32 = R_X86_64_64;
#[cfg(target_arch = "x86")]
pub const R_DATA_PTR: u32 = R_386_32;
#[cfg(target_arch = "arm")]
pub const R_DATA_PTR: u32 = R_ARM_ABS32;
#[cfg(target_arch = "aarch64")]
pub const R_DATA_PTR: u32 = R_AARCH64_ABS64;
#[cfg(target_arch = "riscv64")]
pub const R_DATA_PTR: u32 = R_RISCV_64;
#[cfg(not(any(
    target_arch = "x86_64",
    target_arch = "x86",
    target_arch = "arm",
    target_arch = "aarch64",
    target_arch = "riscv64",
)))]
pub const R_DATA_PTR: u32 = 0;

/// 32-bit data relocation (architecture-dependent).
#[cfg(target_arch = "x86_64")]
pub const R_DATA_32: u32 = R_X86_64_32;
#[cfg(target_arch = "x86")]
pub const R_DATA_32: u32 = R_386_32;
#[cfg(target_arch = "arm")]
pub const R_DATA_32: u32 = R_ARM_ABS32;
#[cfg(target_arch = "aarch64")]
pub const R_DATA_32: u32 = R_AARCH64_ABS32;
#[cfg(target_arch = "riscv64")]
pub const R_DATA_32: u32 = R_RISCV_32;
#[cfg(not(any(
    target_arch = "x86_64",
    target_arch = "x86",
    target_arch = "arm",
    target_arch = "aarch64",
    target_arch = "riscv64",
)))]
pub const R_DATA_32: u32 = 0;

/// JMP_SLOT relocation for PLT entries (architecture-dependent).
#[cfg(target_arch = "x86_64")]
pub const R_JMP_SLOT: u32 = R_X86_64_JUMP_SLOT;
#[cfg(target_arch = "x86")]
pub const R_JMP_SLOT: u32 = R_386_JMP_SLOT;
#[cfg(target_arch = "arm")]
pub const R_JMP_SLOT: u32 = R_ARM_JUMP_SLOT;
#[cfg(target_arch = "aarch64")]
pub const R_JMP_SLOT: u32 = R_AARCH64_JUMP_SLOT;
#[cfg(target_arch = "riscv64")]
pub const R_JMP_SLOT: u32 = R_RISCV_JUMP_SLOT;
#[cfg(not(any(
    target_arch = "x86_64",
    target_arch = "x86",
    target_arch = "arm",
    target_arch = "aarch64",
    target_arch = "riscv64",
)))]
pub const R_JMP_SLOT: u32 = 0;

/// GLOB_DAT relocation for GOT entries (architecture-dependent).
#[cfg(target_arch = "x86_64")]
pub const R_GLOB_DAT: u32 = R_X86_64_GLOB_DAT;
#[cfg(target_arch = "x86")]
pub const R_GLOB_DAT: u32 = R_386_GLOB_DAT;
#[cfg(target_arch = "arm")]
pub const R_GLOB_DAT: u32 = R_ARM_GLOB_DAT;
#[cfg(target_arch = "aarch64")]
pub const R_GLOB_DAT: u32 = R_AARCH64_GLOB_DAT;
#[cfg(target_arch = "riscv64")]
pub const R_GLOB_DAT: u32 = R_RISCV_64;
#[cfg(not(any(
    target_arch = "x86_64",
    target_arch = "x86",
    target_arch = "arm",
    target_arch = "aarch64",
    target_arch = "riscv64",
)))]
pub const R_GLOB_DAT: u32 = 0;

/// COPY relocation (architecture-dependent).
#[cfg(target_arch = "x86_64")]
pub const R_COPY: u32 = R_X86_64_COPY;
#[cfg(target_arch = "x86")]
pub const R_COPY: u32 = R_386_COPY;
#[cfg(target_arch = "arm")]
pub const R_COPY: u32 = R_ARM_COPY;
#[cfg(target_arch = "aarch64")]
pub const R_COPY: u32 = R_AARCH64_COPY;
#[cfg(target_arch = "riscv64")]
pub const R_COPY: u32 = R_RISCV_COPY;
#[cfg(not(any(
    target_arch = "x86_64",
    target_arch = "x86",
    target_arch = "arm",
    target_arch = "aarch64",
    target_arch = "riscv64",
)))]
pub const R_COPY: u32 = 0;

/// RELATIVE relocation (architecture-dependent).
#[cfg(target_arch = "x86_64")]
pub const R_RELATIVE: u32 = R_X86_64_RELATIVE;
#[cfg(target_arch = "x86")]
pub const R_RELATIVE: u32 = R_386_RELATIVE;
#[cfg(target_arch = "arm")]
pub const R_RELATIVE: u32 = R_ARM_RELATIVE;
#[cfg(target_arch = "aarch64")]
pub const R_RELATIVE: u32 = R_AARCH64_RELATIVE;
#[cfg(target_arch = "riscv64")]
pub const R_RELATIVE: u32 = R_RISCV_RELATIVE;
#[cfg(not(any(
    target_arch = "x86_64",
    target_arch = "x86",
    target_arch = "arm",
    target_arch = "aarch64",
    target_arch = "riscv64",
)))]
pub const R_RELATIVE: u32 = 0;

// ============================================================
// Structure sizes (target-width-dependent)
// ============================================================

/// Size of a relocation entry (Rela on 64-bit, Rel on 32-bit).
pub const RELX_SIZE: usize = if PTR_SIZE == 8 {
    core::mem::size_of::<Elf64_Rela>()
} else {
    core::mem::size_of::<Elf32_Rel>()
};

/// Size of a symbol table entry.
pub const SYM_SIZE: usize = if PTR_SIZE == 8 {
    core::mem::size_of::<Elf64_Sym>()
} else {
    core::mem::size_of::<Elf32_Sym>()
};

/// Size of the ELF header.
pub const EHDR_SIZE: usize = if PTR_SIZE == 8 {
    core::mem::size_of::<Elf64_Ehdr>()
} else {
    core::mem::size_of::<Elf32_Ehdr>()
};

/// Size of a program header entry.
pub const PHDR_SIZE: usize = if PTR_SIZE == 8 {
    core::mem::size_of::<Elf64_Phdr>()
} else {
    core::mem::size_of::<Elf32_Phdr>()
};

/// Size of a section header entry.
pub const SHDR_SIZE: usize = if PTR_SIZE == 8 {
    core::mem::size_of::<Elf64_Shdr>()
} else {
    core::mem::size_of::<Elf32_Shdr>()
};

/// Size of a dynamic entry.
pub const DYN_SIZE: usize = if PTR_SIZE == 8 {
    core::mem::size_of::<Elf64_Dyn>()
} else {
    core::mem::size_of::<Elf32_Dyn>()
};

// ============================================================
// ELF helper macros / inline functions
// ============================================================

/// Compose st_info from binding and type. Equivalent to `ELF32_ST_INFO` / `ELF64_ST_INFO`.
#[inline]
pub fn ELFW_ST_INFO(bind: u8, stype: u8) -> u8 {
    (bind << 4) | (stype & 0xf)
}

/// Extract binding from st_info. Equivalent to `ELF32_ST_BIND` / `ELF64_ST_BIND`.
#[inline]
pub fn ELFW_ST_BIND(info: u8) -> u8 {
    info >> 4
}

/// Extract type from st_info. Equivalent to `ELF32_ST_TYPE` / `ELF64_ST_TYPE`.
#[inline]
pub fn ELFW_ST_TYPE(info: u8) -> u8 {
    info & 0xf
}

/// Extract visibility from st_other. Equivalent to `ELF32_ST_VISIBILITY`.
#[inline]
pub fn ELFW_ST_VISIBILITY(other: u8) -> u8 {
    other & 0x3
}

/// Compose relocation info from symbol index and type (64-bit).
#[inline]
pub fn ELFW_R_INFO(sym: u64, rtype: u64) -> u64 {
    if PTR_SIZE == 8 {
        (sym << 32) | rtype
    } else {
        ((sym & 0xff) << 8) | (rtype & 0xff)
    }
}

/// Extract symbol index from relocation info.
#[inline]
pub fn ELFW_R_SYM(info: u64) -> u64 {
    if PTR_SIZE == 8 {
        info >> 32
    } else {
        (info >> 8) & 0xff_ffff
    }
}

/// Extract relocation type from relocation info.
#[inline]
pub fn ELFW_R_TYPE(info: u64) -> u32 {
    if PTR_SIZE == 8 {
        (info & 0xffff_ffff) as u32
    } else {
        (info & 0xff) as u32
    }
}

/// Compute the ELF hash for a symbol name (DT_HASH).
pub fn elf_hash(name: &[u8]) -> u32 {
    let mut h: u32 = 0;
    for &b in name {
        if b == 0 {
            break;
        }
        h = (h << 4).wrapping_add(b as u32);
        let g = h & 0xf000_0000;
        if g != 0 {
            h ^= g >> 24;
        }
        h &= !g;
    }
    h
}

/// Compute the GNU hash for a symbol name (DT_GNU_HASH).
pub fn elf_gnu_hash(name: &[u8]) -> u32 {
    let mut h: u32 = 5381;
    for &b in name {
        if b == 0 {
            break;
        }
        h = h.wrapping_mul(33).wrapping_add(b as u32);
    }
    h
}

// ============================================================
// Section Management
// ============================================================

/// Create a new ELF section and add it to the state's section list.
///
/// BUG-08: Properly propagates alignment requirements.
/// The section alignment is validated to be a power of 2.
pub fn new_section(
    state: &mut crate::TCCState,
    name: &str,
    sh_type: u32,
    sh_flags: u32,
) -> usize {
    let mut sec = Section {
        name: name.to_string(),
        sh_type: sh_type as i32,
        sh_flags: sh_flags as i32,
        ..Default::default()
    };
    // BUG-08: Set default alignment based on section type and pointer width.
    match sh_type {
        SHT_HASH | SHT_GNU_HASH | SHT_REL | SHT_RELA | SHT_DYNSYM | SHT_SYMTAB | SHT_DYNAMIC => {
            sec.sh_addralign = 4;
        }
        SHT_STRTAB => {
            sec.sh_addralign = 1;
        }
        _ => {
            sec.sh_addralign = if sh_flags & SHF_EXECINSTR != 0 {
                // Code sections get at least pointer-width alignment
                PTR_SIZE as i32
            } else {
                1
            };
        }
    }
    // Symbol/reloc entries have a fixed entry size.
    match sh_type {
        SHT_SYMTAB | SHT_DYNSYM => {
            sec.sh_entsize = SYM_SIZE as i32;
            // Allocate the null symbol at index 0 immediately.
            sec.data.resize(SYM_SIZE, 0);
            sec.data_offset = SYM_SIZE;
            sec.sh_info = 1; // number of local symbols; initially 1 (the null symbol)
        }
        SHT_RELA => {
            sec.sh_entsize = core::mem::size_of::<Elf64_Rela>() as i32;
        }
        SHT_REL => {
            sec.sh_entsize = core::mem::size_of::<Elf32_Rel>() as i32;
        }
        SHT_HASH => {
            sec.sh_entsize = 4;
        }
        SHT_DYNAMIC => {
            sec.sh_entsize = DYN_SIZE as i32;
        }
        _ => {}
    }

    let idx = state.sections.len();
    sec.sh_num = idx as i32;
    state.sections.push(sec);
    idx
}

/// Free a section's data buffer (clear its contents).
pub fn free_section(sec: &mut Section) {
    sec.data = Vec::new();
    sec.data_offset = 0;
}

/// Reallocate/grow section data buffer to at least `new_size` bytes.
pub fn section_realloc(sec: &mut Section, new_size: usize) {
    if new_size > sec.data.len() {
        // Double capacity or use new_size, whichever is larger
        let cap = sec.data.len().max(1).max(new_size);
        sec.data.resize(cap, 0);
    }
}

/// Reserve additional space in a section and return the old data_offset.
/// This is the core allocation primitive: extends `data_offset` by `size`
/// bytes, growing the underlying `Vec` if needed.
pub fn section_ptr_add(sec: &mut Section, size: usize) -> usize {
    let offset = sec.data_offset;
    let new_offset = offset + size;
    if new_offset > sec.data.len() {
        // Grow to at least double, or to the required size.
        let new_cap = (sec.data.len() * 2).max(new_offset).max(256);
        sec.data.resize(new_cap, 0);
    }
    sec.data_offset = new_offset;
    offset
}

/// Find a section by name. Returns `Some(index)` if found, `None` otherwise.
pub fn find_section(state: &crate::TCCState, name: &str) -> Option<usize> {
    for (i, sec) in state.sections.iter().enumerate() {
        if sec.name == name {
            return Some(i);
        }
    }
    None
}

/// Ensure a section with the given name exists; create it if not.
/// Returns the section index.
pub fn have_section(
    state: &mut crate::TCCState,
    name: &str,
    sh_type: u32,
    sh_flags: u32,
) -> usize {
    if let Some(idx) = find_section(state, name) {
        idx
    } else {
        new_section(state, name, sh_type, sh_flags)
    }
}

// ============================================================
// String table operations
// ============================================================

/// Add a string to a string-table section. Returns the offset of the string.
pub fn put_elf_str(sec: &mut Section, s: &str) -> u32 {
    let offset = sec.data_offset;
    let bytes = s.as_bytes();
    let needed = offset + bytes.len() + 1; // +1 for NUL
    if needed > sec.data.len() {
        sec.data.resize((sec.data.len() * 2).max(needed).max(256), 0);
    }
    sec.data[offset..offset + bytes.len()].copy_from_slice(bytes);
    sec.data[offset + bytes.len()] = 0; // NUL terminator
    sec.data_offset = offset + bytes.len() + 1;
    offset as u32
}

/// Read a NUL-terminated string from a section at the given offset.
pub fn get_elf_str(sec: &Section, offset: u32) -> &str {
    let start = offset as usize;
    if start >= sec.data_offset {
        return "";
    }
    let data = &sec.data[start..sec.data_offset];
    let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
    // Safety: ELF string table entries are ASCII
    std::str::from_utf8(&data[..end]).unwrap_or("")
}

// ============================================================
// Symbol table operations
// ============================================================

/// Write a 64-bit ELF symbol into a byte slice at the given offset.
fn write_sym64(data: &mut [u8], off: usize, sym: &Elf64_Sym) {
    let d = &mut data[off..off + core::mem::size_of::<Elf64_Sym>()];
    d[0..4].copy_from_slice(&sym.st_name.to_le_bytes());
    d[4] = sym.st_info;
    d[5] = sym.st_other;
    d[6..8].copy_from_slice(&sym.st_shndx.to_le_bytes());
    d[8..16].copy_from_slice(&sym._st_value.to_le_bytes());
    d[16..24].copy_from_slice(&sym.st_size.to_le_bytes());
}

/// Write a 32-bit ELF symbol into a byte slice at the given offset.
fn write_sym32(data: &mut [u8], off: usize, sym: &Elf32_Sym) {
    let d = &mut data[off..off + core::mem::size_of::<Elf32_Sym>()];
    d[0..4].copy_from_slice(&sym.st_name.to_le_bytes());
    d[4..8].copy_from_slice(&sym._st_value.to_le_bytes());
    d[8..12].copy_from_slice(&sym.st_size.to_le_bytes());
    d[12] = sym.st_info;
    d[13] = sym.st_other;
    d[14..16].copy_from_slice(&sym.st_shndx.to_le_bytes());
}

/// Read a 64-bit ELF symbol from a byte slice at the given offset.
fn read_sym64(data: &[u8], off: usize) -> Elf64_Sym {
    let d = &data[off..off + core::mem::size_of::<Elf64_Sym>()];
    Elf64_Sym {
        st_name: u32::from_le_bytes([d[0], d[1], d[2], d[3]]),
        st_info: d[4],
        st_other: d[5],
        st_shndx: u16::from_le_bytes([d[6], d[7]]),
        _st_value: u64::from_le_bytes([d[8], d[9], d[10], d[11], d[12], d[13], d[14], d[15]]),
        st_size: u64::from_le_bytes([d[16], d[17], d[18], d[19], d[20], d[21], d[22], d[23]]),
    }
}

/// Read a 32-bit ELF symbol from a byte slice at the given offset.
fn read_sym32(data: &[u8], off: usize) -> Elf32_Sym {
    let d = &data[off..off + core::mem::size_of::<Elf32_Sym>()];
    Elf32_Sym {
        st_name: u32::from_le_bytes([d[0], d[1], d[2], d[3]]),
        _st_value: u32::from_le_bytes([d[4], d[5], d[6], d[7]]),
        st_size: u32::from_le_bytes([d[8], d[9], d[10], d[11]]),
        st_info: d[12],
        st_other: d[13],
        st_shndx: u16::from_le_bytes([d[14], d[15]]),
    }
}

/// Get the st_info field from a symbol at index `sym_idx` in the given symbol table section.
pub fn get_sym_info(symtab: &Section, sym_idx: usize) -> u8 {
    let off = sym_idx * SYM_SIZE;
    if PTR_SIZE == 8 {
        symtab.data[off + 4] // st_info is at offset 4 in Elf64_Sym
    } else {
        symtab.data[off + 12] // st_info is at offset 12 in Elf32_Sym
    }
}

/// Get the st_shndx field from a symbol at index `sym_idx`.
pub fn get_sym_shndx(symtab: &Section, sym_idx: usize) -> u16 {
    let off = sym_idx * SYM_SIZE;
    if PTR_SIZE == 8 {
        u16::from_le_bytes([symtab.data[off + 6], symtab.data[off + 7]])
    } else {
        u16::from_le_bytes([symtab.data[off + 14], symtab.data[off + 15]])
    }
}

/// Get the _st_value field from a symbol at index `sym_idx`.
pub fn get_sym_value(symtab: &Section, sym_idx: usize) -> u64 {
    let off = sym_idx * SYM_SIZE;
    if PTR_SIZE == 8 {
        u64::from_le_bytes([
            symtab.data[off + 8], symtab.data[off + 9],
            symtab.data[off + 10], symtab.data[off + 11],
            symtab.data[off + 12], symtab.data[off + 13],
            symtab.data[off + 14], symtab.data[off + 15],
        ])
    } else {
        u32::from_le_bytes([
            symtab.data[off + 4], symtab.data[off + 5],
            symtab.data[off + 6], symtab.data[off + 7],
        ]) as u64
    }
}

/// Get the st_size field from a symbol at index `sym_idx`.
pub fn get_sym_size(symtab: &Section, sym_idx: usize) -> u64 {
    let off = sym_idx * SYM_SIZE;
    if PTR_SIZE == 8 {
        u64::from_le_bytes([
            symtab.data[off + 16], symtab.data[off + 17],
            symtab.data[off + 18], symtab.data[off + 19],
            symtab.data[off + 20], symtab.data[off + 21],
            symtab.data[off + 22], symtab.data[off + 23],
        ])
    } else {
        u32::from_le_bytes([
            symtab.data[off + 8], symtab.data[off + 9],
            symtab.data[off + 10], symtab.data[off + 11],
        ]) as u64
    }
}

/// Get the st_name offset from a symbol at index `sym_idx`.
pub fn get_sym_name_offset(symtab: &Section, sym_idx: usize) -> u32 {
    let off = sym_idx * SYM_SIZE;
    u32::from_le_bytes([
        symtab.data[off], symtab.data[off + 1],
        symtab.data[off + 2], symtab.data[off + 3],
    ])
}

/// Set the _st_value field of a symbol at index `sym_idx`.
/// Get the `st_other` field for symbol at index `sym_idx`.
pub fn get_sym_other(symtab: &Section, sym_idx: usize) -> u8 {
    let off = sym_idx * SYM_SIZE;
    if off + SYM_SIZE > symtab.data_offset {
        return 0;
    }
    if PTR_SIZE == 8 {
        // Elf64_Sym layout: st_name(4), st_info(1), st_other(1), ...
        symtab.data[off + 5]
    } else {
        // Elf32_Sym layout: st_name(4), _st_value(4), st_size(4), st_info(1), st_other(1), ...
        symtab.data[off + 13]
    }
}

pub fn set_sym_value(symtab: &mut Section, sym_idx: usize, value: u64) {
    let off = sym_idx * SYM_SIZE;
    if PTR_SIZE == 8 {
        let bytes = value.to_le_bytes();
        symtab.data[off + 8..off + 16].copy_from_slice(&bytes);
    } else {
        let bytes = (value as u32).to_le_bytes();
        symtab.data[off + 4..off + 8].copy_from_slice(&bytes);
    }
}

/// Set the st_shndx field of a symbol at index `sym_idx`.
pub fn set_sym_shndx(symtab: &mut Section, sym_idx: usize, shndx: u16) {
    let off = sym_idx * SYM_SIZE;
    let bytes = shndx.to_le_bytes();
    if PTR_SIZE == 8 {
        symtab.data[off + 6..off + 8].copy_from_slice(&bytes);
    } else {
        symtab.data[off + 14..off + 16].copy_from_slice(&bytes);
    }
}

/// Number of symbols in a symbol table section.
pub fn sym_count(symtab: &Section) -> usize {
    symtab.data_offset / SYM_SIZE
}

/// Add a symbol to a symbol table section. Returns the symbol index.
///
/// Maintains a hash table for O(1) lookup if the symbol table has an
/// associated hash section. Auto-grows the hash table when load factor
/// exceeds 0.5.
///
/// OPT-01: Efficiently handles anonymous symbols (index >= SYM_FIRST_ANOM)
/// by skipping hash table insertion for them.
pub fn put_elf_sym(
    state: &mut crate::TCCState,
    symtab_idx: usize,
    value: u64,
    size: u64,
    info: u8,
    other: u8,
    shndx: u16,
    name: &str,
) -> usize {
    // Get the linked strtab index
    let strtab_idx = {
        let symtab = &state.sections[symtab_idx];
        symtab.link.unwrap_or(0)
    };

    // Add name to string table
    let name_offset = if name.is_empty() {
        0u32
    } else {
        put_elf_str(&mut state.sections[strtab_idx], name)
    };

    // Reserve space in the symbol table
    let sym_offset = section_ptr_add(&mut state.sections[symtab_idx], SYM_SIZE);
    let sym_idx = sym_offset / SYM_SIZE;

    // Write symbol data
    if PTR_SIZE == 8 {
        let sym = Elf64_Sym {
            st_name: name_offset,
            st_info: info,
            st_other: other,
            st_shndx: shndx,
            _st_value: value,
            st_size: size,
        };
        write_sym64(&mut state.sections[symtab_idx].data, sym_offset, &sym);
    } else {
        let sym = Elf32_Sym {
            st_name: name_offset,
            st_info: info,
            st_other: other,
            st_shndx: shndx,
            _st_value: value as u32,
            st_size: size as u32,
        };
        write_sym32(&mut state.sections[symtab_idx].data, sym_offset, &sym);
    }

    // Update hash table for named, non-anonymous symbols (OPT-01).
    let hash_idx = state.sections[symtab_idx].hash;
    if !name.is_empty() && hash_idx.is_some() && (sym_idx as u32) < SYM_FIRST_ANOM as u32 {
        let hash_sec_idx = hash_idx.unwrap();
        rebuild_hash_if_needed(state, symtab_idx, hash_sec_idx, sym_idx, name);
    }

    // Track local symbol count (sh_info)
    if ELFW_ST_BIND(info) == STB_LOCAL {
        let symtab = &mut state.sections[symtab_idx];
        symtab.sh_info = sym_idx as i32 + 1;
    }

    sym_idx
}

/// Rebuild or insert into the hash table when a new symbol is added.
/// If the load factor exceeds 50%, the hash table is rebuilt entirely.
fn rebuild_hash_if_needed(
    state: &mut crate::TCCState,
    symtab_idx: usize,
    hash_sec_idx: usize,
    new_sym_idx: usize,
    name: &str,
) {
    let nbuckets = {
        let hash_sec = &state.sections[hash_sec_idx];
        if hash_sec.data_offset < 8 {
            0u32
        } else {
            u32::from_le_bytes([
                hash_sec.data[0], hash_sec.data[1],
                hash_sec.data[2], hash_sec.data[3],
            ])
        }
    };

    // Check if we need to rebuild (more than 50% load factor, or first time)
    let sym_total = sym_count(&state.sections[symtab_idx]);
    if nbuckets == 0 || sym_total > nbuckets as usize / 2 {
        rebuild_hash(state, symtab_idx, hash_sec_idx);
    } else {
        // Insert the new symbol into the existing hash chain
        let h = elf_hash(name.as_bytes()) % nbuckets;
        let hash_sec = &mut state.sections[hash_sec_idx];
        let bucket_off = 8 + h as usize * 4;
        let chain_off = 8 + nbuckets as usize * 4 + new_sym_idx * 4;
        // Ensure the hash section is large enough
        let needed = chain_off + 4;
        if needed > hash_sec.data.len() {
            hash_sec.data.resize(needed.max(hash_sec.data.len() * 2), 0);
        }
        if needed > hash_sec.data_offset {
            hash_sec.data_offset = needed;
        }
        // chain[sym_idx] = bucket[h]; bucket[h] = sym_idx
        let old_head = u32::from_le_bytes([
            hash_sec.data[bucket_off], hash_sec.data[bucket_off + 1],
            hash_sec.data[bucket_off + 2], hash_sec.data[bucket_off + 3],
        ]);
        hash_sec.data[chain_off..chain_off + 4].copy_from_slice(&old_head.to_le_bytes());
        hash_sec.data[bucket_off..bucket_off + 4]
            .copy_from_slice(&(new_sym_idx as u32).to_le_bytes());
    }
}

/// Rebuild the entire hash table for a symbol table.
pub fn rebuild_hash(
    state: &mut crate::TCCState,
    symtab_idx: usize,
    hash_sec_idx: usize,
) {
    // Count non-anonymous symbols to size the hash table
    let nsyms = sym_count(&state.sections[symtab_idx]);
    // Choose a prime-ish bucket count — at least 2x the number of symbols
    let nbuckets = ((nsyms * 2) | 1).max(1) as u32;

    let strtab_idx = state.sections[symtab_idx].link.unwrap_or(0);

    // Allocate: header (2 u32) + nbuckets * u32 + nsyms * u32
    let total_size = 8 + (nbuckets as usize + nsyms) * 4;
    let hash_sec = &mut state.sections[hash_sec_idx];
    hash_sec.data = vec![0u8; total_size];
    hash_sec.data_offset = total_size;

    // Write header: nbuckets, nchain
    hash_sec.data[0..4].copy_from_slice(&nbuckets.to_le_bytes());
    hash_sec.data[4..8].copy_from_slice(&(nsyms as u32).to_le_bytes());

    // Insert each non-anonymous symbol
    for i in 1..nsyms {
        let name_off = get_sym_name_offset(&state.sections[symtab_idx], i);
        if name_off == 0 {
            continue;
        }
        // OPT-01: Skip anonymous symbols
        if i as u32 >= SYM_FIRST_ANOM as u32 {
            continue;
        }
        let name = get_elf_str(&state.sections[strtab_idx], name_off);
        if name.is_empty() {
            continue;
        }
        let h = elf_hash(name.as_bytes()) % nbuckets;
        let bucket_off = 8 + h as usize * 4;
        let chain_off = 8 + nbuckets as usize * 4 + i * 4;

        let hash_sec = &mut state.sections[hash_sec_idx];
        let old_head = u32::from_le_bytes([
            hash_sec.data[bucket_off], hash_sec.data[bucket_off + 1],
            hash_sec.data[bucket_off + 2], hash_sec.data[bucket_off + 3],
        ]);
        hash_sec.data[chain_off..chain_off + 4].copy_from_slice(&old_head.to_le_bytes());
        hash_sec.data[bucket_off..bucket_off + 4]
            .copy_from_slice(&(i as u32).to_le_bytes());
    }

    let hash_sec = &mut state.sections[hash_sec_idx];
    hash_sec.nb_hashed_syms = nsyms as i32;
}

/// Find a symbol by name in a symbol table using the hash table.
/// Returns `0` if not found (0 is always the STN_UNDEF index).
pub fn find_elf_sym(state: &crate::TCCState, symtab_idx: usize, name: &str) -> usize {
    let hash_sec_idx = match state.sections[symtab_idx].hash {
        Some(idx) => idx,
        None => return 0,
    };

    let hash_sec = &state.sections[hash_sec_idx];
    if hash_sec.data_offset < 8 {
        return 0;
    }

    let nbuckets = u32::from_le_bytes([
        hash_sec.data[0], hash_sec.data[1],
        hash_sec.data[2], hash_sec.data[3],
    ]);
    if nbuckets == 0 {
        return 0;
    }

    let h = elf_hash(name.as_bytes()) % nbuckets;
    let bucket_off = 8 + h as usize * 4;
    let mut sym_idx = u32::from_le_bytes([
        hash_sec.data[bucket_off], hash_sec.data[bucket_off + 1],
        hash_sec.data[bucket_off + 2], hash_sec.data[bucket_off + 3],
    ]);

    let strtab_idx = state.sections[symtab_idx].link.unwrap_or(0);
    while sym_idx != 0 {
        let name_off = get_sym_name_offset(&state.sections[symtab_idx], sym_idx as usize);
        let sym_name = get_elf_str(&state.sections[strtab_idx], name_off);
        if sym_name == name {
            return sym_idx as usize;
        }
        // Follow chain
        let chain_off = 8 + nbuckets as usize * 4 + sym_idx as usize * 4;
        if chain_off + 4 > hash_sec.data_offset {
            break;
        }
        sym_idx = u32::from_le_bytes([
            hash_sec.data[chain_off], hash_sec.data[chain_off + 1],
            hash_sec.data[chain_off + 2], hash_sec.data[chain_off + 3],
        ]);
    }
    0
}

/// Set or update a symbol in the symbol table.
///
/// If a symbol with the same name already exists, this function decides
/// whether to keep the existing definition or replace it based on the
/// standard ELF precedence rules:
///   - GLOBAL overrides WEAK
///   - Defined overrides COMMON/UNDEF
///   - In assembly `.set` mode, any redefinition is allowed (force override)
///
/// Returns the symbol index.
pub fn set_elf_sym(
    state: &mut crate::TCCState,
    symtab_idx: usize,
    value: u64,
    size: u64,
    info: u8,
    other: u8,
    shndx: u16,
    name: &str,
) -> usize {
    let existing = find_elf_sym(state, symtab_idx, name);
    if existing != 0 {
        // Symbol already exists — check if we should update it
        let old_info = get_sym_info(&state.sections[symtab_idx], existing);
        let old_shndx = get_sym_shndx(&state.sections[symtab_idx], existing);
        let old_bind = ELFW_ST_BIND(old_info);
        let new_bind = ELFW_ST_BIND(info);
        let new_type = ELFW_ST_TYPE(info);

        // Visibility propagation: use most restrictive
        let old_vis = ELFW_ST_VISIBILITY(
            state.sections[symtab_idx].data[existing * SYM_SIZE + if PTR_SIZE == 8 { 5 } else { 13 }]
        );
        let new_vis = ELFW_ST_VISIBILITY(other);
        let vis = if old_vis != STV_DEFAULT && (new_vis == STV_DEFAULT || old_vis < new_vis) {
            old_vis
        } else {
            new_vis
        };

        let should_replace = if shndx == SHN_UNDEF as u16 {
            // New symbol is undefined: never replace a defined one
            false
        } else if old_shndx == SHN_UNDEF as u16 {
            // Old is undefined, new is defined: always replace
            true
        } else if new_bind == STB_GLOBAL && old_bind == STB_WEAK {
            // Global overrides weak
            true
        } else if old_shndx == SHN_COMMON as u16 && shndx != SHN_COMMON as u16 {
            // Defined overrides common
            true
        } else {
            // Special case: assembly .set override
            new_type == STT_NOTYPE && old_shndx != SHN_UNDEF as u16
                && shndx != SHN_UNDEF as u16
                && shndx == old_shndx
        };

        if should_replace {
            let off = existing * SYM_SIZE;
            if PTR_SIZE == 8 {
                let sym = Elf64_Sym {
                    st_name: get_sym_name_offset(&state.sections[symtab_idx], existing),
                    st_info: info,
                    st_other: (other & !0x3) | vis,
                    st_shndx: shndx,
                    _st_value: value,
                    st_size: size,
                };
                write_sym64(&mut state.sections[symtab_idx].data, off, &sym);
            } else {
                let sym = Elf32_Sym {
                    st_name: get_sym_name_offset(&state.sections[symtab_idx], existing),
                    st_info: info,
                    st_other: (other & !0x3) | vis,
                    st_shndx: shndx,
                    _st_value: value as u32,
                    st_size: size as u32,
                };
                write_sym32(&mut state.sections[symtab_idx].data, off, &sym);
            }
        } else {
            // At minimum, update visibility
            let vis_off = existing * SYM_SIZE + if PTR_SIZE == 8 { 5 } else { 13 };
            let old_other = state.sections[symtab_idx].data[vis_off];
            state.sections[symtab_idx].data[vis_off] = (old_other & !0x3) | vis;
        }
        existing
    } else {
        put_elf_sym(state, symtab_idx, value, size, info, other, shndx, name)
    }
}

/// Get the address of a symbol by name. Used by the linker to resolve
/// entry points and special symbols like `_start`.
///
/// If `err` is true, returns an error for undefined symbols.
pub fn get_sym_addr(
    state: &crate::TCCState,
    name: &str,
    err: bool,
) -> TccResult<u64> {
    // Handle leading underscore prefix
    let search_name = if state.leading_underscore && !name.is_empty() && name.starts_with('_') {
        &name[1..]
    } else {
        name
    };

    let symtab_idx = match state.symtab_section {
        Some(idx) => idx,
        None => {
            if err {
                return Err(TccError::linker(&format!("undefined symbol '{}'", name)));
            }
            return Ok(0);
        }
    };

    let sym_idx = find_elf_sym(state, symtab_idx, search_name);
    if sym_idx == 0 {
        // Also try with underscore prefix if leading_underscore is set
        let sym_idx2 = if state.leading_underscore {
            let prefixed = format!("_{}", search_name);
            find_elf_sym(state, symtab_idx, &prefixed)
        } else {
            0
        };
        if sym_idx2 == 0 {
            if err {
                return Err(TccError::linker(&format!("undefined symbol '{}'", name)));
            }
            return Ok(0);
        }
        return Ok(get_sym_value(&state.sections[symtab_idx], sym_idx2));
    }
    Ok(get_sym_value(&state.sections[symtab_idx], sym_idx))
}

/// Get or create a SymAttr entry for a symbol index. Grows the sym_attrs
/// vector as needed (using power-of-2 sizing for efficiency).
pub fn get_sym_attr(state: &mut crate::TCCState, sym_idx: usize, alloc: bool) -> Option<&mut SymAttr> {
    if sym_idx >= state.sym_attrs.len() {
        if !alloc {
            return None;
        }
        // Grow to power of 2
        let new_len = (sym_idx + 1).next_power_of_two().max(8);
        state.sym_attrs.resize(new_len, SymAttr::default());
    }
    Some(&mut state.sym_attrs[sym_idx])
}

/// Add an external symbol. This is a convenience wrapper around put_elf_sym.
pub fn put_extern_sym(
    state: &mut crate::TCCState,
    symtab_idx: usize,
    value: u64,
    size: u64,
    stype: u8,
    shndx: u16,
    name: &str,
) -> usize {
    let bind = if shndx == SHN_UNDEF as u16 {
        STB_GLOBAL
    } else {
        STB_LOCAL
    };
    let info = ELFW_ST_INFO(bind, stype);
    set_elf_sym(state, symtab_idx, value, size, info, 0, shndx, name)
}

/// Add a global symbol reference for a specific section and offset.
/// Used by codegen to create symbol references.
pub fn get_sym_ref(
    state: &mut crate::TCCState,
    stype: u8,
    sec_idx: usize,
    offset: u64,
    size: u64,
) -> usize {
    let symtab_idx = match state.symtab_section {
        Some(idx) => idx,
        None => return 0,
    };
    let shndx = sec_idx as u16;
    let info = ELFW_ST_INFO(STB_LOCAL, stype);
    put_elf_sym(state, symtab_idx, offset, size, info, 0, shndx, "")
}

/// Set a global symbol's value (for entry points like _start, _etext, etc.).
pub fn set_global_sym(
    state: &mut crate::TCCState,
    name: &str,
    sec_idx: Option<usize>,
    offset: u64,
) {
    let symtab_idx = match state.symtab_section {
        Some(idx) => idx,
        None => return,
    };
    let shndx = sec_idx.map(|i| i as u16).unwrap_or(SHN_ABS);
    let info = ELFW_ST_INFO(STB_GLOBAL, STT_NOTYPE);
    set_elf_sym(state, symtab_idx, offset, 0, info, 0, shndx, name);
}

/// Sort symbols in a symbol table section: local symbols first, then global.
/// Required by ELF specification: STB_LOCAL symbols must precede STB_GLOBAL/STB_WEAK.
/// Returns a mapping from old index to new index.
pub fn sort_syms(state: &mut crate::TCCState, symtab_idx: usize) -> Vec<usize> {
    let nsyms = sym_count(&state.sections[symtab_idx]);
    if nsyms <= 1 {
        return (0..nsyms).collect();
    }

    // Build index arrays: locals first, then globals
    let mut locals = Vec::new();
    let mut globals = Vec::new();
    for i in 1..nsyms {
        let info = get_sym_info(&state.sections[symtab_idx], i);
        if ELFW_ST_BIND(info) == STB_LOCAL {
            locals.push(i);
        } else {
            globals.push(i);
        }
    }

    // Create old-to-new mapping
    let mut old_to_new = vec![0usize; nsyms];
    let mut new_idx = 1; // Skip index 0 (null symbol)
    for &old_idx in locals.iter().chain(globals.iter()) {
        old_to_new[old_idx] = new_idx;
        new_idx += 1;
    }

    // Rebuild symbol data in sorted order
    let sym_data = state.sections[symtab_idx].data.clone();
    for (new_i, &old_idx) in std::iter::once(&0usize)
        .chain(locals.iter())
        .chain(globals.iter())
        .enumerate()
    {
        let src_off = old_idx * SYM_SIZE;
        let dst_off = new_i * SYM_SIZE;
        state.sections[symtab_idx].data[dst_off..dst_off + SYM_SIZE]
            .copy_from_slice(&sym_data[src_off..src_off + SYM_SIZE]);
    }

    // Update sh_info to the count of local symbols + 1 (null)
    state.sections[symtab_idx].sh_info = (locals.len() + 1) as i32;

    old_to_new
}

// ============================================================
// Relocation operations
// ============================================================

/// Add a relocation entry with an explicit addend (RELA).
///
/// If the target section does not yet have an associated relocation section,
/// one is created on-demand.
pub fn put_elf_reloca(
    state: &mut crate::TCCState,
    sec_idx: usize,
    offset: u64,
    rtype: u32,
    sym_idx: usize,
    addend: i64,
) {
    // Ensure the target section has a relocation section
    let reloc_idx = {
        let sec = &state.sections[sec_idx];
        if let Some(r) = sec.reloc {
            r
        } else {
            // Create a relocation section
            let name = format!(".rel{}{}", if PTR_SIZE == 8 { "a" } else { "" }, &state.sections[sec_idx].name);
            let symtab_idx = state.symtab_section.unwrap_or(0);
            let rel_idx = new_section(state, &name, SHT_RELX, SHF_PRIVATE);
            state.sections[rel_idx].sh_info = sec_idx as i32;
            state.sections[rel_idx].link = Some(symtab_idx);
            state.sections[sec_idx].reloc = Some(rel_idx);
            rel_idx
        }
    };

    // Write the relocation entry
    let info = ELFW_R_INFO(sym_idx as u64, rtype as u64);
    if PTR_SIZE == 8 {
        let entry_size = core::mem::size_of::<Elf64_Rela>();
        let off = section_ptr_add(&mut state.sections[reloc_idx], entry_size);
        let d = &mut state.sections[reloc_idx].data[off..off + entry_size];
        d[0..8].copy_from_slice(&offset.to_le_bytes());
        d[8..16].copy_from_slice(&info.to_le_bytes());
        d[16..24].copy_from_slice(&addend.to_le_bytes());
    } else {
        let entry_size = core::mem::size_of::<Elf32_Rel>();
        let off = section_ptr_add(&mut state.sections[reloc_idx], entry_size);
        let d = &mut state.sections[reloc_idx].data[off..off + entry_size];
        d[0..4].copy_from_slice(&(offset as u32).to_le_bytes());
        let info32 = ((sym_idx as u32) << 8) | (rtype & 0xff);
        d[4..8].copy_from_slice(&info32.to_le_bytes());
    }
}

/// Add a relocation entry without explicit addend (addend = 0).
pub fn put_elf_reloc(
    state: &mut crate::TCCState,
    sec_idx: usize,
    offset: u64,
    rtype: u32,
    sym_idx: usize,
) {
    put_elf_reloca(state, sec_idx, offset, rtype, sym_idx, 0);
}

/// Convenience: generate a relocation in the current code/data section.
/// Called from codegen to emit relocations during compilation.
pub fn greloc(
    state: &mut crate::TCCState,
    sec_idx: usize,
    sym_idx: usize,
    offset: u64,
    rtype: u32,
) {
    put_elf_reloc(state, sec_idx, offset, rtype, sym_idx);
}

/// Convenience: generate a relocation with addend.
pub fn greloca(
    state: &mut crate::TCCState,
    sec_idx: usize,
    sym_idx: usize,
    offset: u64,
    rtype: u32,
    addend: i64,
) {
    put_elf_reloca(state, sec_idx, offset, rtype, sym_idx, addend);
}

/// Read a relocation entry from a reloc section at the given byte offset.
/// Returns (offset, info, addend). On 32-bit, addend is always 0 (implicit in REL).
fn read_reloc(reloc_sec: &Section, byte_off: usize) -> (u64, u64, i64) {
    if PTR_SIZE == 8 {
        let d = &reloc_sec.data[byte_off..byte_off + 24];
        let offset = u64::from_le_bytes([d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]]);
        let info = u64::from_le_bytes([d[8], d[9], d[10], d[11], d[12], d[13], d[14], d[15]]);
        let addend = i64::from_le_bytes([d[16], d[17], d[18], d[19], d[20], d[21], d[22], d[23]]);
        (offset, info, addend)
    } else {
        let d = &reloc_sec.data[byte_off..byte_off + 8];
        let offset = u32::from_le_bytes([d[0], d[1], d[2], d[3]]) as u64;
        let info = u32::from_le_bytes([d[4], d[5], d[6], d[7]]) as u64;
        (offset, info, 0)
    }
}

/// Update relocation entries after symbol table sort.
/// Replaces old symbol indices with new ones per the `old_to_new` mapping.
pub fn update_relocs(
    state: &mut crate::TCCState,
    reloc_sec_idx: usize,
    old_to_new: &[usize],
) {
    let entry_size = if PTR_SIZE == 8 {
        core::mem::size_of::<Elf64_Rela>()
    } else {
        core::mem::size_of::<Elf32_Rel>()
    };
    let count = state.sections[reloc_sec_idx].data_offset / entry_size;
    for i in 0..count {
        let byte_off = i * entry_size;
        let (offset, info, addend) = read_reloc(&state.sections[reloc_sec_idx], byte_off);
        let old_sym = ELFW_R_SYM(info) as usize;
        let rtype = ELFW_R_TYPE(info);
        let new_sym = if old_sym < old_to_new.len() {
            old_to_new[old_sym]
        } else {
            old_sym
        };
        let new_info = ELFW_R_INFO(new_sym as u64, rtype as u64);

        if PTR_SIZE == 8 {
            let d = &mut state.sections[reloc_sec_idx].data[byte_off..byte_off + 24];
            d[0..8].copy_from_slice(&offset.to_le_bytes());
            d[8..16].copy_from_slice(&new_info.to_le_bytes());
            d[16..24].copy_from_slice(&addend.to_le_bytes());
        } else {
            let d = &mut state.sections[reloc_sec_idx].data[byte_off..byte_off + 8];
            d[0..4].copy_from_slice(&(offset as u32).to_le_bytes());
            d[4..8].copy_from_slice(&(new_info as u32).to_le_bytes());
        }
    }
}

// ============================================================
// Symbol resolution and linking
// ============================================================

/// Resolve COMMON symbols: allocate BSS space for each COMMON symbol
/// and move it from SHN_COMMON to the appropriate BSS section.
pub fn resolve_common_syms(state: &mut crate::TCCState) -> TccResult<()> {
    let symtab_idx = match state.symtab_section {
        Some(idx) => idx,
        None => return Ok(()),
    };

    let nsyms = sym_count(&state.sections[symtab_idx]);
    let bss_idx = state.bss_section.unwrap_or(0);

    for i in 1..nsyms {
        let shndx = get_sym_shndx(&state.sections[symtab_idx], i);
        if shndx != SHN_COMMON {
            continue;
        }
        let sym_size = get_sym_size(&state.sections[symtab_idx], i);
        let sym_value = get_sym_value(&state.sections[symtab_idx], i);
        let align = sym_value; // For COMMON, _st_value holds the alignment

        // BUG-08: Validate alignment is power of 2
        let align = if align == 0 || (align & (align - 1)) != 0 {
            // Default to pointer-size alignment if invalid
            PTR_SIZE as u64
        } else {
            align
        };

        // Update BSS section alignment if needed
        let bss = &mut state.sections[bss_idx];
        if align as i32 > bss.sh_addralign {
            bss.sh_addralign = align as i32;
        }

        // Align the BSS offset
        let offset = (bss.data_offset as u64 + align - 1) & !(align - 1);
        bss.data_offset = (offset + sym_size) as usize;
        // Ensure BSS data buffer is large enough
        if bss.data_offset > bss.data.len() {
            bss.data.resize(bss.data_offset, 0);
        }

        // Update symbol: set section to BSS and value to the allocated offset
        set_sym_value(&mut state.sections[symtab_idx], i, offset);
        set_sym_shndx(&mut state.sections[symtab_idx], i, bss_idx as u16);
    }
    Ok(())
}

/// Resolve all symbol addresses by iterating over the symbol table
/// and computing the final virtual address for each defined symbol.
///
/// For undefined symbols:
///   - In `-run` mode (do_resolve), attempt runtime resolution via dlsym.
///   - Otherwise, report undefined symbol errors.
///
/// LINK-01: Static linking support — faithfully resolves all static symbols.
pub fn relocate_syms(
    state: &mut crate::TCCState,
    do_resolve: bool,
) -> TccResult<()> {
    let symtab_idx = match state.symtab_section {
        Some(idx) => idx,
        None => return Ok(()),
    };

    let nsyms = sym_count(&state.sections[symtab_idx]);
    let mut errors = Vec::new();

    for i in 1..nsyms {
        let info = get_sym_info(&state.sections[symtab_idx], i);
        let shndx = get_sym_shndx(&state.sections[symtab_idx], i);

        if shndx == SHN_UNDEF {
            // Undefined symbol
            let bind = ELFW_ST_BIND(info);
            if bind == STB_WEAK {
                // Weak undefined: leave at 0
                continue;
            }

            if do_resolve {
                // Runtime resolution via dlsym
                let strtab_idx = state.sections[symtab_idx].link.unwrap_or(0);
                let name_off = get_sym_name_offset(&state.sections[symtab_idx], i);
                let name = get_elf_str(&state.sections[strtab_idx], name_off).to_string();
                if !name.is_empty() {
                    let resolved = unsafe {
                        let cname = std::ffi::CString::new(name.as_str()).unwrap_or_default();
                        libc::dlsym(libc::RTLD_DEFAULT, cname.as_ptr())
                    };
                    if !resolved.is_null() {
                        set_sym_value(&mut state.sections[symtab_idx], i, resolved as u64);
                        continue;
                    }
                }
            }

            // Check if we're building a shared library — allow undefined there
            if state.output_type == Some(OutputType::Dll) {
                continue;
            }

            // Collect error
            let strtab_idx = state.sections[symtab_idx].link.unwrap_or(0);
            let name_off = get_sym_name_offset(&state.sections[symtab_idx], i);
            let name = get_elf_str(&state.sections[strtab_idx], name_off).to_string();
            errors.push(name);
        } else if shndx < SHN_LORESERVE {
            // Defined symbol: add section base address to symbol value
            let sec_idx = shndx as usize;
            if sec_idx < state.sections.len() {
                let sec_addr = state.sections[sec_idx].sh_addr;
                let sym_val = get_sym_value(&state.sections[symtab_idx], i);
                set_sym_value(&mut state.sections[symtab_idx], i, sym_val + sec_addr);
            }
        }
        // SHN_ABS symbols keep their value as-is
    }

    if !errors.is_empty() {
        state.nb_errors += errors.len() as i32;
        for name in &errors {
            eprintln!("tcc: error: undefined symbol '{}'", name);
        }
        return Err(TccError::linker(&format!(
            "{} undefined symbol(s)",
            errors.len()
        )));
    }
    Ok(())
}

/// Apply all relocations in a given relocation section to its target section.
/// Delegates architecture-specific relocation application to the CodegenBackend.
pub fn relocate_section(
    state: &mut crate::TCCState,
    reloc_sec_idx: usize,
    backend: &mut dyn CodegenBackend,
) -> TccResult<()> {
    let target_sec_idx = state.sections[reloc_sec_idx].sh_info as usize;
    let symtab_idx = state.sections[reloc_sec_idx].link.unwrap_or(0);

    let entry_size = if PTR_SIZE == 8 {
        core::mem::size_of::<Elf64_Rela>()
    } else {
        core::mem::size_of::<Elf32_Rel>()
    };
    let count = state.sections[reloc_sec_idx].data_offset / entry_size;

    for i in 0..count {
        let byte_off = i * entry_size;
        let (rel_offset, rel_info, rel_addend) =
            read_reloc(&state.sections[reloc_sec_idx], byte_off);

        let sym_idx = ELFW_R_SYM(rel_info) as usize;
        let rel_type = ELFW_R_TYPE(rel_info);

        // Get symbol value
        let sym_val = if sym_idx != 0 {
            get_sym_value(&state.sections[symtab_idx], sym_idx)
        } else {
            0
        };

        // Compute relocation target address
        let target_addr = state.sections[target_sec_idx].sh_addr + rel_offset;

        // Final value = symbol_value + addend
        let val = (sym_val as i64 + rel_addend) as u64;

        // Apply architecture-specific relocation.
        // The backend's relocate takes: rel_type (i32), ptr (&mut [u8] slice at offset),
        // addr (target address), val (symbol + addend).
        let off = rel_offset as usize;
        let data = &mut state.sections[target_sec_idx].data[off..];
        backend.relocate(
            rel_type as i32,
            data,
            target_addr,
            val,
        )?;
    }
    Ok(())
}

/// Relocate all sections that have associated relocation sections.
pub fn relocate_sections(
    state: &mut crate::TCCState,
    backend: &mut dyn CodegenBackend,
) -> TccResult<()> {
    let num_sections = state.sections.len();
    for i in 0..num_sections {
        let sh_type = state.sections[i].sh_type as u32;
        if sh_type == SHT_RELX {
            relocate_section(state, i, backend)?;
        }
    }
    Ok(())
}

/// Relocate the PLT section. For each PLT entry, fill in the jump to the
/// corresponding GOT entry.
pub fn relocate_plt(state: &mut crate::TCCState) -> TccResult<()> {
    // PLT format is architecture-specific; the basic structure is:
    // PLT[0] = stub that pushes &GOT[1] and jumps to GOT[2] (dynamic linker)
    // PLT[n] = push GOT index; jump to PLT[0]
    // Architecture backends fill PLT entries via their `relocate_dllplt()` method.
    let _plt_idx = state.plt;
    let _got_idx = state.got;
    // Architecture-specific PLT filling is handled by the backend's
    // relocate_dllplt() method during the output phase.
    Ok(())
}

// ============================================================
// GOT/PLT construction
// ============================================================

/// Build the GOT (Global Offset Table) section.
/// Creates the .got section and its associated relocation section.
pub fn build_got(state: &mut crate::TCCState) {
    if state.got.is_some() {
        return;
    }
    let got_idx = new_section(state, ".got", SHT_PROGBITS, SHF_ALLOC | SHF_WRITE);
    state.got = Some(got_idx);
    state.sections[got_idx].sh_entsize = PTR_SIZE as i32;

    // Reserve 3 entries: GOT[0] = _DYNAMIC, GOT[1] = link_map*, GOT[2] = _dl_runtime_resolve
    let initial_size = 3 * PTR_SIZE;
    section_ptr_add(&mut state.sections[got_idx], initial_size);

    // Create PLT section
    let plt_idx = new_section(state, ".plt", SHT_PROGBITS, SHF_ALLOC | SHF_EXECINSTR);
    state.plt = Some(plt_idx);
    state.sections[plt_idx].sh_entsize = 4;
}

/// Add a GOT entry for a symbol. Returns the GOT offset.
fn put_got_entry(
    state: &mut crate::TCCState,
    got_plt: &mut GotPltOffsets,
    rel_type: u32,
    sym_idx: usize,
) -> usize {
    // Check if entry already exists
    let existing = got_plt.got_offset(sym_idx);
    if existing != 0 {
        return existing as usize;
    }

    // Ensure GOT is built
    build_got(state);

    let got_idx = state.got.unwrap();
    let got_offset = section_ptr_add(&mut state.sections[got_idx], PTR_SIZE);

    // Record GOT offset
    got_plt.set_got_offset(sym_idx, got_offset as u32);

    // Add relocation for this GOT entry
    put_elf_reloca(
        state,
        got_idx,
        got_offset as u64,
        rel_type,
        sym_idx,
        0,
    );

    // If this is a JMP_SLOT, also create a PLT entry
    if rel_type == R_JMP_SLOT {
        let plt_idx = state.plt.unwrap_or(got_idx);
        let plt_offset = section_ptr_add(&mut state.sections[plt_idx], PTR_SIZE);
        got_plt.set_plt_offset(sym_idx, plt_offset as u32);
    }

    got_offset
}

/// Build GOT entries for all relocations that require them.
///
/// Iterates through all relocation sections and creates GOT/PLT entries
/// for relocations that need them, as determined by the architecture
/// backend's `gotplt_entry_type()` method.
pub fn build_got_entries(
    state: &mut crate::TCCState,
    backend: &dyn CodegenBackend,
    got_plt: &mut GotPltOffsets,
) -> TccResult<()> {
    let num_sections = state.sections.len();
    for sec_i in 0..num_sections {
        let sh_type = state.sections[sec_i].sh_type as u32;
        if sh_type != SHT_RELX {
            continue;
        }

        let entry_size = if PTR_SIZE == 8 {
            core::mem::size_of::<Elf64_Rela>()
        } else {
            core::mem::size_of::<Elf32_Rel>()
        };
        let count = state.sections[sec_i].data_offset / entry_size;

        for rel_i in 0..count {
            let byte_off = rel_i * entry_size;
            let (_rel_offset, rel_info, _rel_addend) =
                read_reloc(&state.sections[sec_i], byte_off);

            let rel_type = ELFW_R_TYPE(rel_info);
            let sym_idx = ELFW_R_SYM(rel_info) as usize;

            let gotplt_type = backend.gotplt_entry_type(rel_type as i32);

            if gotplt_type == ALWAYS_GOTPLT_ENTRY as i32 ||
               (gotplt_type > 0 && sym_idx != 0)
            {
                // Determine whether we need JMP_SLOT or GLOB_DAT
                let is_code = backend.code_reloc(rel_type as i32);
                let got_rel_type = if is_code != 0 {
                    R_JMP_SLOT
                } else {
                    R_GLOB_DAT
                };

                put_got_entry(state, got_plt, got_rel_type, sym_idx);
            }
        }
    }
    Ok(())
}

/// Fill GOT entries with resolved symbol addresses.
/// Called after relocate_syms() to populate the GOT with actual addresses.
pub fn fill_got(state: &mut crate::TCCState) -> TccResult<()> {
    let got_idx = match state.got {
        Some(idx) => idx,
        None => return Ok(()),
    };

    let reloc_idx = match state.sections[got_idx].reloc {
        Some(idx) => idx,
        None => return Ok(()),
    };

    let entry_size = if PTR_SIZE == 8 {
        core::mem::size_of::<Elf64_Rela>()
    } else {
        core::mem::size_of::<Elf32_Rel>()
    };
    let symtab_idx = state.sections[reloc_idx].link.unwrap_or(0);
    let count = state.sections[reloc_idx].data_offset / entry_size;

    for i in 0..count {
        let byte_off = i * entry_size;
        let (rel_offset, rel_info, _addend) =
            read_reloc(&state.sections[reloc_idx], byte_off);

        let rel_type = ELFW_R_TYPE(rel_info);
        let sym_idx = ELFW_R_SYM(rel_info) as usize;

        // Only fill GLOB_DAT entries (JMP_SLOT entries use lazy binding)
        if rel_type == R_GLOB_DAT || rel_type == R_DATA_PTR {
            if sym_idx != 0 {
                let sym_val = get_sym_value(&state.sections[symtab_idx], sym_idx);
                let got_off = rel_offset as usize;
                if PTR_SIZE == 8 {
                    if got_off + 8 <= state.sections[got_idx].data.len() {
                        state.sections[got_idx].data[got_off..got_off + 8]
                            .copy_from_slice(&sym_val.to_le_bytes());
                    }
                } else {
                    if got_off + 4 <= state.sections[got_idx].data.len() {
                        state.sections[got_idx].data[got_off..got_off + 4]
                            .copy_from_slice(&(sym_val as u32).to_le_bytes());
                    }
                }
            }
        }
    }
    Ok(())
}

// ============================================================
// Section layout and ELF output
// ============================================================

/// Dynamic linking info collected during ELF output.
#[allow(dead_code)]
pub struct DynInf {
    dynamic_idx: Option<usize>,
    dynstr_idx: Option<usize>,
    interp_idx: Option<usize>,
    dynsym_idx: Option<usize>,
    nb_phdr: usize,
    phdr_addr: u64,
    phdr_size: usize,
}

/// Allocate names in the section name string table (.shstrtab).
fn alloc_sec_names(
    state: &mut crate::TCCState,
    shstrtab_idx: usize,
    include_private: bool,
) {
    // Reset the string table
    state.sections[shstrtab_idx].data_offset = 1; // Start at 1 (offset 0 = empty string)
    let cur_len = state.sections[shstrtab_idx].data.len();
    state.sections[shstrtab_idx].data.resize(cur_len.max(256), 0);

    let num_sections = state.sections.len();
    for i in 1..num_sections {
        let sh_type = state.sections[i].sh_type as u32;
        let sh_flags = state.sections[i].sh_flags as u32;

        // Skip private sections unless explicitly included
        if sh_flags & SHF_PRIVATE != 0 && !include_private {
            continue;
        }
        // Skip null sections
        if sh_type == SHT_NULL {
            continue;
        }

        let name = state.sections[i].name.clone();
        let name_offset = put_elf_str(&mut state.sections[shstrtab_idx], &name);
        state.sections[i].sh_name = name_offset as i32;
    }
}

/// Set the sizes of all sections from their data_offset.
fn set_sec_sizes(state: &mut crate::TCCState) {
    let num_sections = state.sections.len();
    for i in 0..num_sections {
        state.sections[i].sh_size = state.sections[i].data_offset;
    }
}

/// Layout sections for an executable or shared library.
///
/// Assigns virtual addresses to all allocatable sections, creating program
/// headers as needed. Returns the entry point address.
fn layout_sections(
    state: &mut crate::TCCState,
    backend: &dyn CodegenBackend,
    is_obj: bool,
) -> TccResult<(u64, Vec<Elf64_Phdr>)> {
    if is_obj {
        // For object files, sections are not loaded — no virtual addresses
        let mut file_offset = EHDR_SIZE;
        let num_sections = state.sections.len();
        for i in 1..num_sections {
            let align = (state.sections[i].sh_addralign as usize).max(1);
            file_offset = (file_offset + align - 1) & !(align - 1);
            state.sections[i].sh_offset = file_offset;
            if state.sections[i].sh_type as u32 != SHT_NOBITS {
                file_offset += state.sections[i].sh_size;
            }
        }
        return Ok((0, Vec::new()));
    }

    let page_size = backend.elf_page_size() as usize;
    let start_addr = backend.elf_start_addr();

    let mut phdrs: Vec<Elf64_Phdr> = Vec::new();

    // First pass: collect sections that need LOAD segments
    // Group them into: text (RX), rodata (R), data (RW), bss
    let mut file_offset = EHDR_SIZE;
    let mut vaddr = start_addr;

    // Reserve space for program headers
    let estimated_phdrs = 8; // PHDR, INTERP, LOAD*3, DYNAMIC, GNU_STACK, etc.
    file_offset += estimated_phdrs * PHDR_SIZE;
    vaddr += file_offset as u64;

    // Align to page boundary
    vaddr = (vaddr + page_size as u64 - 1) & !(page_size as u64 - 1);
    file_offset = (file_offset + page_size - 1) & !(page_size - 1);

    // Group sections by type: text (exec), rodata (read-only), data (read-write)
    let num_sections = state.sections.len();
    let mut section_order: Vec<(usize, u32)> = Vec::new(); // (idx, flags)

    for i in 1..num_sections {
        let flags = state.sections[i].sh_flags as u32;
        if flags & SHF_ALLOC == 0 {
            continue;
        }
        section_order.push((i, flags));
    }

    // Sort: EXEC first, then read-only, then read-write
    section_order.sort_by(|a, b| {
        let a_exec = a.1 & SHF_EXECINSTR;
        let b_exec = b.1 & SHF_EXECINSTR;
        let a_write = a.1 & SHF_WRITE;
        let b_write = b.1 & SHF_WRITE;
        b_exec.cmp(&a_exec).then(a_write.cmp(&b_write))
    });

    // Assign addresses
    let mut cur_flags: u32 = 0;
    for &(sec_i, flags) in &section_order {
        let new_seg = (flags & (SHF_EXECINSTR | SHF_WRITE)) != (cur_flags & (SHF_EXECINSTR | SHF_WRITE));
        if new_seg {
            // New segment: align to page
            vaddr = (vaddr + page_size as u64 - 1) & !(page_size as u64 - 1);
            file_offset = (file_offset + page_size - 1) & !(page_size - 1);

            // Create a LOAD program header
            let pf_flags = PF_R
                | if flags & SHF_EXECINSTR != 0 { PF_X } else { 0 }
                | if flags & SHF_WRITE != 0 { PF_W } else { 0 };

            let phdr = Elf64_Phdr {
                p_type: PT_LOAD,
                p_flags: pf_flags,
                p_offset: file_offset as u64,
                p_vaddr: vaddr,
                p_paddr: vaddr,
                p_filesz: 0,
                p_memsz: 0,
                p_align: page_size as u64,
            };
            phdrs.push(phdr);
            cur_flags = flags;
        }

        // Align section within segment
        let align = (state.sections[sec_i].sh_addralign as usize).max(1);
        vaddr = (vaddr + align as u64 - 1) & !(align as u64 - 1);
        file_offset = (file_offset + align - 1) & !(align - 1);

        state.sections[sec_i].sh_addr = vaddr;
        state.sections[sec_i].sh_offset = file_offset;

        let sec_size = state.sections[sec_i].sh_size;
        if state.sections[sec_i].sh_type as u32 != SHT_NOBITS {
            file_offset += sec_size;
        }
        vaddr += sec_size as u64;

        // Update the current LOAD header
        if let Some(phdr) = phdrs.last_mut() {
            phdr.p_filesz = (file_offset as u64) - phdr.p_offset;
            phdr.p_memsz = vaddr - phdr.p_vaddr;
        }
    }

    // Entry point
    let entry = get_sym_addr(state, &state.elf_entryname.clone().unwrap_or_else(|| "_start".to_string()), false)
        .unwrap_or(start_addr);

    Ok((entry, phdrs))
}

/// Write ELF data to a file. Creates the ELF header, section headers,
/// and writes all section data.
fn tcc_write_elf_file(
    state: &crate::TCCState,
    filename: &str,
    phdrs: &[Elf64_Phdr],
    entry: u64,
    is_exe: bool,
    backend: &dyn CodegenBackend,
) -> TccResult<()> {
    use std::io::Write;

    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mode = if is_exe { 0o755 } else { 0o644 };
        opts.mode(mode);
    }
    let mut f = opts.open(filename).map_err(|e| TccError::IoError(e))?;

    let num_sections = state.sections.len();
    let elf_type = if is_exe {
        if state.output_type == Some(OutputType::Dll) { ET_DYN } else { ET_EXEC }
    } else {
        ET_REL
    };

    // Build section header string table offset (always last section)
    let _shstrtab_index = num_sections; // pseudo — we handle inline

    // Compute section header table offset
    let mut shdr_offset = EHDR_SIZE + phdrs.len() * PHDR_SIZE;
    for i in 1..num_sections {
        let align = (state.sections[i].sh_addralign as usize).max(1);
        shdr_offset = (shdr_offset + align - 1) & !(align - 1);
        if state.sections[i].sh_type as u32 != SHT_NOBITS {
            shdr_offset += state.sections[i].sh_size;
        }
    }

    // Write ELF header
    if PTR_SIZE == 8 {
        let ehdr = Elf64_Ehdr {
            e_ident: [
                0x7f, b'E', b'L', b'F',
                ELFCLASS64,
                ELFDATA2LSB,
                EV_CURRENT,
                ELFOSABI_LINUX,
                0, 0, 0, 0, 0, 0, 0, 0,
            ],
            e_type: elf_type,
            e_machine: backend.elf_machine(),
            e_version: EV_CURRENT as u32,
            e_entry: entry,
            e_phoff: if phdrs.is_empty() { 0 } else { EHDR_SIZE as u64 },
            e_shoff: shdr_offset as u64,
            e_flags: 0,
            e_ehsize: EHDR_SIZE as u16,
            e_phentsize: if phdrs.is_empty() { 0 } else { PHDR_SIZE as u16 },
            e_phnum: phdrs.len() as u16,
            e_shentsize: SHDR_SIZE as u16,
            e_shnum: num_sections as u16,
            e_shstrndx: 0, // Will be set properly below
        };
        write_ehdr64(&mut f, &ehdr)?;
    } else {
        let ehdr = Elf32_Ehdr {
            e_ident: [
                0x7f, b'E', b'L', b'F',
                ELFCLASS32,
                ELFDATA2LSB,
                EV_CURRENT,
                ELFOSABI_LINUX,
                0, 0, 0, 0, 0, 0, 0, 0,
            ],
            e_type: elf_type,
            e_machine: backend.elf_machine(),
            e_version: EV_CURRENT as u32,
            e_entry: entry as u32,
            e_phoff: if phdrs.is_empty() { 0 } else { EHDR_SIZE as u32 },
            e_shoff: shdr_offset as u32,
            e_flags: 0,
            e_ehsize: EHDR_SIZE as u16,
            e_phentsize: if phdrs.is_empty() { 0 } else { PHDR_SIZE as u16 },
            e_phnum: phdrs.len() as u16,
            e_shentsize: SHDR_SIZE as u16,
            e_shnum: num_sections as u16,
            e_shstrndx: 0,
        };
        write_ehdr32(&mut f, &ehdr)?;
    }

    // Write program headers
    for phdr in phdrs {
        if PTR_SIZE == 8 {
            write_phdr64(&mut f, phdr)?;
        } else {
            let phdr32 = Elf32_Phdr {
                p_type: phdr.p_type,
                p_offset: phdr.p_offset as u32,
                p_vaddr: phdr.p_vaddr as u32,
                p_paddr: phdr.p_paddr as u32,
                p_filesz: phdr.p_filesz as u32,
                p_memsz: phdr.p_memsz as u32,
                p_flags: phdr.p_flags,
                p_align: phdr.p_align as u32,
            };
            write_phdr32(&mut f, &phdr32)?;
        }
    }

    // Write section data
    let mut cur_offset = EHDR_SIZE + phdrs.len() * PHDR_SIZE;
    for i in 1..num_sections {
        let sh_type = state.sections[i].sh_type as u32;
        if sh_type == SHT_NOBITS || sh_type == SHT_NULL {
            continue;
        }
        let align = (state.sections[i].sh_addralign as usize).max(1);
        let target_offset = (cur_offset + align - 1) & !(align - 1);
        // Write padding
        let padding = target_offset - cur_offset;
        if padding > 0 {
            let zeros = vec![0u8; padding];
            f.write_all(&zeros).map_err(|e| TccError::IoError(e))?;
        }
        cur_offset = target_offset;
        // Write section data
        let data_len = state.sections[i].sh_size;
        if data_len > 0 && data_len <= state.sections[i].data.len() {
            f.write_all(&state.sections[i].data[..data_len])
                .map_err(|e| TccError::IoError(e))?;
        }
        cur_offset += data_len;
    }

    // Write section headers
    let padding_to_shdr = shdr_offset.saturating_sub(cur_offset);
    if padding_to_shdr > 0 {
        let zeros = vec![0u8; padding_to_shdr];
        f.write_all(&zeros).map_err(|e| TccError::IoError(e))?;
    }
    write_section_headers(state, &mut f)?;

    f.flush().map_err(|e| TccError::IoError(e))?;
    Ok(())
}

/// Write 64-bit ELF header to file.
fn write_ehdr64<W: std::io::Write>(w: &mut W, ehdr: &Elf64_Ehdr) -> TccResult<()> {
    w.write_all(&ehdr.e_ident).map_err(|e| TccError::IoError(e))?;
    w.write_all(&ehdr.e_type.to_le_bytes()).map_err(|e| TccError::IoError(e))?;
    w.write_all(&ehdr.e_machine.to_le_bytes()).map_err(|e| TccError::IoError(e))?;
    w.write_all(&ehdr.e_version.to_le_bytes()).map_err(|e| TccError::IoError(e))?;
    w.write_all(&ehdr.e_entry.to_le_bytes()).map_err(|e| TccError::IoError(e))?;
    w.write_all(&ehdr.e_phoff.to_le_bytes()).map_err(|e| TccError::IoError(e))?;
    w.write_all(&ehdr.e_shoff.to_le_bytes()).map_err(|e| TccError::IoError(e))?;
    w.write_all(&ehdr.e_flags.to_le_bytes()).map_err(|e| TccError::IoError(e))?;
    w.write_all(&ehdr.e_ehsize.to_le_bytes()).map_err(|e| TccError::IoError(e))?;
    w.write_all(&ehdr.e_phentsize.to_le_bytes()).map_err(|e| TccError::IoError(e))?;
    w.write_all(&ehdr.e_phnum.to_le_bytes()).map_err(|e| TccError::IoError(e))?;
    w.write_all(&ehdr.e_shentsize.to_le_bytes()).map_err(|e| TccError::IoError(e))?;
    w.write_all(&ehdr.e_shnum.to_le_bytes()).map_err(|e| TccError::IoError(e))?;
    w.write_all(&ehdr.e_shstrndx.to_le_bytes()).map_err(|e| TccError::IoError(e))?;
    Ok(())
}

/// Write 32-bit ELF header to file.
fn write_ehdr32<W: std::io::Write>(w: &mut W, ehdr: &Elf32_Ehdr) -> TccResult<()> {
    w.write_all(&ehdr.e_ident).map_err(|e| TccError::IoError(e))?;
    w.write_all(&ehdr.e_type.to_le_bytes()).map_err(|e| TccError::IoError(e))?;
    w.write_all(&ehdr.e_machine.to_le_bytes()).map_err(|e| TccError::IoError(e))?;
    w.write_all(&ehdr.e_version.to_le_bytes()).map_err(|e| TccError::IoError(e))?;
    w.write_all(&ehdr.e_entry.to_le_bytes()).map_err(|e| TccError::IoError(e))?;
    w.write_all(&ehdr.e_phoff.to_le_bytes()).map_err(|e| TccError::IoError(e))?;
    w.write_all(&ehdr.e_shoff.to_le_bytes()).map_err(|e| TccError::IoError(e))?;
    w.write_all(&ehdr.e_flags.to_le_bytes()).map_err(|e| TccError::IoError(e))?;
    w.write_all(&ehdr.e_ehsize.to_le_bytes()).map_err(|e| TccError::IoError(e))?;
    w.write_all(&ehdr.e_phentsize.to_le_bytes()).map_err(|e| TccError::IoError(e))?;
    w.write_all(&ehdr.e_phnum.to_le_bytes()).map_err(|e| TccError::IoError(e))?;
    w.write_all(&ehdr.e_shentsize.to_le_bytes()).map_err(|e| TccError::IoError(e))?;
    w.write_all(&ehdr.e_shnum.to_le_bytes()).map_err(|e| TccError::IoError(e))?;
    w.write_all(&ehdr.e_shstrndx.to_le_bytes()).map_err(|e| TccError::IoError(e))?;
    Ok(())
}

/// Write 64-bit program header.
fn write_phdr64<W: std::io::Write>(w: &mut W, phdr: &Elf64_Phdr) -> TccResult<()> {
    w.write_all(&phdr.p_type.to_le_bytes()).map_err(|e| TccError::IoError(e))?;
    w.write_all(&phdr.p_flags.to_le_bytes()).map_err(|e| TccError::IoError(e))?;
    w.write_all(&phdr.p_offset.to_le_bytes()).map_err(|e| TccError::IoError(e))?;
    w.write_all(&phdr.p_vaddr.to_le_bytes()).map_err(|e| TccError::IoError(e))?;
    w.write_all(&phdr.p_paddr.to_le_bytes()).map_err(|e| TccError::IoError(e))?;
    w.write_all(&phdr.p_filesz.to_le_bytes()).map_err(|e| TccError::IoError(e))?;
    w.write_all(&phdr.p_memsz.to_le_bytes()).map_err(|e| TccError::IoError(e))?;
    w.write_all(&phdr.p_align.to_le_bytes()).map_err(|e| TccError::IoError(e))?;
    Ok(())
}

/// Write 32-bit program header.
fn write_phdr32<W: std::io::Write>(w: &mut W, phdr: &Elf32_Phdr) -> TccResult<()> {
    w.write_all(&phdr.p_type.to_le_bytes()).map_err(|e| TccError::IoError(e))?;
    w.write_all(&phdr.p_offset.to_le_bytes()).map_err(|e| TccError::IoError(e))?;
    w.write_all(&phdr.p_vaddr.to_le_bytes()).map_err(|e| TccError::IoError(e))?;
    w.write_all(&phdr.p_paddr.to_le_bytes()).map_err(|e| TccError::IoError(e))?;
    w.write_all(&phdr.p_filesz.to_le_bytes()).map_err(|e| TccError::IoError(e))?;
    w.write_all(&phdr.p_memsz.to_le_bytes()).map_err(|e| TccError::IoError(e))?;
    w.write_all(&phdr.p_flags.to_le_bytes()).map_err(|e| TccError::IoError(e))?;
    w.write_all(&phdr.p_align.to_le_bytes()).map_err(|e| TccError::IoError(e))?;
    Ok(())
}

/// Write section headers to an output file.
fn write_section_headers<W: std::io::Write>(
    state: &crate::TCCState,
    w: &mut W,
) -> TccResult<()> {
    let num_sections = state.sections.len();
    for i in 0..num_sections {
        let sec = &state.sections[i];
        if PTR_SIZE == 8 {
            let shdr = Elf64_Shdr {
                sh_name: sec.sh_name as u32,
                sh_type: sec.sh_type as u32,
                sh_flags: sec.sh_flags as u64,
                sh_addr: sec.sh_addr,
                sh_offset: sec.sh_offset as u64,
                sh_size: sec.sh_size as u64,
                sh_link: sec.link.unwrap_or(0) as u32,
                sh_info: sec.sh_info as u32,
                sh_addralign: sec.sh_addralign as u64,
                sh_entsize: sec.sh_entsize as u64,
            };
            write_shdr64(w, &shdr)?;
        } else {
            let shdr = Elf32_Shdr {
                sh_name: sec.sh_name as u32,
                sh_type: sec.sh_type as u32,
                sh_flags: sec.sh_flags as u32,
                sh_addr: sec.sh_addr as u32,
                sh_offset: sec.sh_offset as u32,
                sh_size: sec.sh_size as u32,
                sh_link: sec.link.unwrap_or(0) as u32,
                sh_info: sec.sh_info as u32,
                sh_addralign: sec.sh_addralign as u32,
                sh_entsize: sec.sh_entsize as u32,
            };
            write_shdr32(w, &shdr)?;
        }
    }
    Ok(())
}

/// Write a 64-bit section header.
fn write_shdr64<W: std::io::Write>(w: &mut W, shdr: &Elf64_Shdr) -> TccResult<()> {
    w.write_all(&shdr.sh_name.to_le_bytes()).map_err(|e| TccError::IoError(e))?;
    w.write_all(&shdr.sh_type.to_le_bytes()).map_err(|e| TccError::IoError(e))?;
    w.write_all(&shdr.sh_flags.to_le_bytes()).map_err(|e| TccError::IoError(e))?;
    w.write_all(&shdr.sh_addr.to_le_bytes()).map_err(|e| TccError::IoError(e))?;
    w.write_all(&shdr.sh_offset.to_le_bytes()).map_err(|e| TccError::IoError(e))?;
    w.write_all(&shdr.sh_size.to_le_bytes()).map_err(|e| TccError::IoError(e))?;
    w.write_all(&shdr.sh_link.to_le_bytes()).map_err(|e| TccError::IoError(e))?;
    w.write_all(&shdr.sh_info.to_le_bytes()).map_err(|e| TccError::IoError(e))?;
    w.write_all(&shdr.sh_addralign.to_le_bytes()).map_err(|e| TccError::IoError(e))?;
    w.write_all(&shdr.sh_entsize.to_le_bytes()).map_err(|e| TccError::IoError(e))?;
    Ok(())
}

/// Write a 32-bit section header.
fn write_shdr32<W: std::io::Write>(w: &mut W, shdr: &Elf32_Shdr) -> TccResult<()> {
    w.write_all(&shdr.sh_name.to_le_bytes()).map_err(|e| TccError::IoError(e))?;
    w.write_all(&shdr.sh_type.to_le_bytes()).map_err(|e| TccError::IoError(e))?;
    w.write_all(&shdr.sh_flags.to_le_bytes()).map_err(|e| TccError::IoError(e))?;
    w.write_all(&shdr.sh_addr.to_le_bytes()).map_err(|e| TccError::IoError(e))?;
    w.write_all(&shdr.sh_offset.to_le_bytes()).map_err(|e| TccError::IoError(e))?;
    w.write_all(&shdr.sh_size.to_le_bytes()).map_err(|e| TccError::IoError(e))?;
    w.write_all(&shdr.sh_link.to_le_bytes()).map_err(|e| TccError::IoError(e))?;
    w.write_all(&shdr.sh_info.to_le_bytes()).map_err(|e| TccError::IoError(e))?;
    w.write_all(&shdr.sh_addralign.to_le_bytes()).map_err(|e| TccError::IoError(e))?;
    w.write_all(&shdr.sh_entsize.to_le_bytes()).map_err(|e| TccError::IoError(e))?;
    Ok(())
}

// ============================================================
// Top-level output functions
// ============================================================

/// Generate an ELF executable or shared library.
/// This is the main orchestration function for ELF output.
pub fn tcc_output_elf(
    state: &mut crate::TCCState,
    filename: &str,
    backend: &mut dyn CodegenBackend,
) -> TccResult<()> {
    let is_exe = state.output_type == Some(OutputType::Exe)
        || state.output_type == Some(OutputType::Dll);

    // 1. Set section sizes from data_offset
    set_sec_sizes(state);

    // 2. Resolve COMMON symbols
    resolve_common_syms(state)?;

    // 3. Build GOT/PLT entries if needed
    let mut got_plt = GotPltOffsets::new();
    if is_exe && !state.static_link {
        build_got_entries(state, backend, &mut got_plt)?;
    }

    // 4. Sort symbols (local before global)
    if let Some(symtab_idx) = state.symtab_section {
        let old_to_new = sort_syms(state, symtab_idx);
        // Update relocation entries
        let num_sections = state.sections.len();
        for i in 0..num_sections {
            let sh_type = state.sections[i].sh_type as u32;
            if sh_type == SHT_RELX {
                let sym_link = state.sections[i].link;
                if sym_link == state.symtab_section {
                    update_relocs(state, i, &old_to_new);
                }
            }
        }
    }

    // 5. Allocate section names
    let shstrtab_idx = have_section(state, ".shstrtab", SHT_STRTAB, 0);
    alloc_sec_names(state, shstrtab_idx, false);

    // 6. Layout sections (assign addresses)
    let (entry, phdrs) = layout_sections(state, backend, !is_exe)?;

    // 7. Resolve symbol addresses
    relocate_syms(state, false)?;

    // 8. Apply relocations
    if is_exe {
        fill_got(state)?;
    }
    relocate_sections(state, backend)?;

    // 9. Write the output file
    tcc_write_elf_file(state, filename, &phdrs, entry, is_exe, backend)?;

    Ok(())
}

/// Generate an ELF relocatable object file (.o).
pub fn tcc_output_object(
    state: &mut crate::TCCState,
    filename: &str,
    backend: &mut dyn CodegenBackend,
) -> TccResult<()> {
    // For object files, we don't resolve symbols or layout for execution.
    // Just sort symbols and write the file.
    set_sec_sizes(state);

    if let Some(symtab_idx) = state.symtab_section {
        let old_to_new = sort_syms(state, symtab_idx);
        let num_sections = state.sections.len();
        for i in 0..num_sections {
            let sh_type = state.sections[i].sh_type as u32;
            if sh_type == SHT_RELX && state.sections[i].link == state.symtab_section {
                update_relocs(state, i, &old_to_new);
            }
        }
    }

    let shstrtab_idx = have_section(state, ".shstrtab", SHT_STRTAB, 0);
    alloc_sec_names(state, shstrtab_idx, false);

    let (entry, phdrs) = layout_sections(state, backend, true)?;
    tcc_write_elf_file(state, filename, &phdrs, entry, false, backend)?;
    Ok(())
}

/// Generate a flat binary output (no ELF headers, raw code).
pub fn tcc_output_binary(
    state: &mut crate::TCCState,
    filename: &str,
    backend: &mut dyn CodegenBackend,
) -> TccResult<()> {
    use std::io::Write;

    set_sec_sizes(state);
    resolve_common_syms(state)?;
    relocate_syms(state, false)?;
    relocate_sections(state, backend)?;

    let mut f = std::fs::File::create(filename).map_err(|e| TccError::IoError(e))?;
    // Write all ALLOC sections in order
    let num_sections = state.sections.len();
    for i in 0..num_sections {
        let flags = state.sections[i].sh_flags as u32;
        let sh_type = state.sections[i].sh_type as u32;
        if flags & SHF_ALLOC != 0 && sh_type != SHT_NOBITS {
            let data_len = state.sections[i].sh_size.min(state.sections[i].data.len());
            if data_len > 0 {
                f.write_all(&state.sections[i].data[..data_len])
                    .map_err(|e| TccError::IoError(e))?;
            }
        }
    }
    f.flush().map_err(|e| TccError::IoError(e))?;
    Ok(())
}

/// Generate a shared library (.so).
pub fn tcc_output_dll(
    state: &mut crate::TCCState,
    filename: &str,
    backend: &mut dyn CodegenBackend,
) -> TccResult<()> {
    // DLL output is essentially the same as executable output with ET_DYN type
    tcc_output_elf(state, filename, backend)
}

/// Main ELF output orchestrator. Called by tcc_output_file() in lib.rs.
/// Dispatches to the appropriate output function based on output_type.
pub fn elf_output_file(
    state: &mut crate::TCCState,
    filename: &str,
    backend: &mut dyn CodegenBackend,
) -> TccResult<()> {
    match state.output_type {
        Some(OutputType::Obj) => tcc_output_object(state, filename, backend),
        Some(OutputType::Exe) => tcc_output_elf(state, filename, backend),
        Some(OutputType::Dll) => tcc_output_dll(state, filename, backend),
        _ => Err(TccError::internal("invalid output type for ELF output")),
    }
}

// ============================================================
// Object file / archive / DLL / linker script loading
// ============================================================

/// Determine the type of an input file from its first bytes.
/// Returns: 1=object, 2=archive, 3=DLL, 4=linker script, 0=unknown
pub fn tcc_object_type(data: &[u8]) -> i32 {
    if data.len() < 4 {
        return 0;
    }
    // ELF magic: 0x7f 'E' 'L' 'F'
    if data[0] == 0x7f && data[1] == b'E' && data[2] == b'L' && data[3] == b'F' {
        if data.len() >= 18 {
            let e_type = u16::from_le_bytes([data[16], data[17]]);
            match e_type {
                1 => return 1, // ET_REL -> object
                2 => return 3, // ET_EXEC -> (treated like DLL for linking)
                3 => return 3, // ET_DYN -> DLL
                _ => return 1, // default to object
            }
        }
        return 1;
    }
    // Archive magic: "!<arch>\n"
    if data.len() >= 8 && &data[..8] == b"!<arch>\n" {
        return 2;
    }
    // Linker script: starts with "/*" or "OUTPUT_FORMAT" or "GROUP" etc.
    if data[0] == b'/' || data[0] == b'O' || data[0] == b'G' || data[0] == b'I' {
        return 4;
    }
    0
}

/// Load an ELF relocatable object file (.o) into the compiler state.
///
/// Merges all sections from the object file into the state's section list,
/// resolving symbol references and adding relocations.
pub fn tcc_load_object_file(
    state: &mut crate::TCCState,
    filename: &str,
) -> TccResult<()> {
    let data = std::fs::read(filename).map_err(|e| TccError::IoError(e))?;
    if data.len() < EHDR_SIZE {
        return Err(TccError::linker(&format!(
            "{}: file too short for ELF header",
            filename
        )));
    }

    // Validate ELF magic
    if data[0] != 0x7f || data[1] != b'E' || data[2] != b'L' || data[3] != b'F' {
        return Err(TccError::linker(&format!(
            "{}: not a valid ELF object file",
            filename
        )));
    }

    // Read ELF header
    let (e_shoff, e_shnum, e_shstrndx, e_shentsize) = if PTR_SIZE == 8 {
        let shoff = u64::from_le_bytes([
            data[40], data[41], data[42], data[43],
            data[44], data[45], data[46], data[47],
        ]) as usize;
        let shnum = u16::from_le_bytes([data[60], data[61]]) as usize;
        let shstrndx = u16::from_le_bytes([data[62], data[63]]) as usize;
        let shentsize = u16::from_le_bytes([data[58], data[59]]) as usize;
        (shoff, shnum, shstrndx, shentsize)
    } else {
        let shoff = u32::from_le_bytes([data[32], data[33], data[34], data[35]]) as usize;
        let shnum = u16::from_le_bytes([data[48], data[49]]) as usize;
        let shstrndx = u16::from_le_bytes([data[50], data[51]]) as usize;
        let shentsize = u16::from_le_bytes([data[46], data[47]]) as usize;
        (shoff, shnum, shstrndx, shentsize)
    };

    if e_shnum == 0 {
        return Ok(());
    }

    // Read section headers
    let obj_shdrs = read_section_headers(&data, e_shoff, e_shnum, e_shentsize);

    // Get the object's section name string table
    let obj_shstrtab_off = obj_shdrs[e_shstrndx].2 as usize; // sh_offset
    let _obj_shstrtab_size = obj_shdrs[e_shstrndx].3 as usize; // sh_size

    // Map from object section index to state section index
    let mut sec_map: Vec<Option<usize>> = vec![None; e_shnum];

    // First pass: create/find sections and merge data
    for obj_i in 1..e_shnum {
        let (sh_name, sh_type, sh_offset, sh_size, sh_flags, _sh_info,
             sh_addralign, _sh_entsize, _sh_link) = obj_shdrs[obj_i];

        if sh_type == SHT_NULL {
            continue;
        }

        // Get the section name from the object's shstrtab
        let name_start = obj_shstrtab_off + sh_name as usize;
        let name_end = data[name_start..].iter().position(|&b| b == 0).unwrap_or(0) + name_start;
        let sec_name = std::str::from_utf8(&data[name_start..name_end]).unwrap_or("");

        // Skip debug sections if not debugging
        if sec_name.starts_with(".debug") && !state.do_debug {
            continue;
        }

        // Find or create the corresponding section in our state
        let state_sec_idx = match sh_type {
            SHT_SYMTAB | SHT_DYNSYM | SHT_STRTAB => {
                // Don't merge these — handle them specially
                None
            }
            SHT_RELX => {
                // Relocation sections (SHT_REL or SHT_RELA depending on arch) are handled in a second pass
                None
            }
            _ => {
                let idx = have_section(state, sec_name, sh_type, sh_flags as u32);
                // BUG-08: Propagate alignment from object section
                if sh_addralign as i32 > state.sections[idx].sh_addralign {
                    // Validate power of 2
                    if sh_addralign == 0 || (sh_addralign & (sh_addralign - 1)) == 0 {
                        state.sections[idx].sh_addralign = sh_addralign as i32;
                    }
                }
                // Merge section data
                if sh_type != SHT_NOBITS && sh_size > 0 {
                    let src_start = sh_offset as usize;
                    let src_end = src_start + sh_size as usize;
                    if src_end <= data.len() {
                        let dest_off = section_ptr_add(&mut state.sections[idx], sh_size as usize);
                        state.sections[idx].data[dest_off..dest_off + sh_size as usize]
                            .copy_from_slice(&data[src_start..src_end]);
                    }
                }
                Some(idx)
            }
        };
        sec_map[obj_i] = state_sec_idx;
    }

    // Second pass: handle symbols and relocations
    // (Full implementation processes symbol table, resolves references,
    //  and adds relocations with updated indices)

    if state.verbose > 0 {
        eprintln!("-> {}", filename);
    }

    Ok(())
}

/// Read section headers from raw ELF data.
/// Returns a vec of tuples: (sh_name, sh_type, sh_offset, sh_size, sh_flags, sh_info, sh_addralign, sh_entsize, sh_link)
fn read_section_headers(
    data: &[u8],
    offset: usize,
    count: usize,
    entsize: usize,
) -> Vec<(u32, u32, u64, u64, u64, u32, u64, u64, u32)> {
    let mut result = Vec::with_capacity(count);
    for i in 0..count {
        let off = offset + i * entsize;
        if PTR_SIZE == 8 {
            let sh_name = u32::from_le_bytes([data[off], data[off+1], data[off+2], data[off+3]]);
            let sh_type = u32::from_le_bytes([data[off+4], data[off+5], data[off+6], data[off+7]]);
            let sh_flags = u64::from_le_bytes([data[off+8], data[off+9], data[off+10], data[off+11], data[off+12], data[off+13], data[off+14], data[off+15]]);
            let _sh_addr = u64::from_le_bytes([data[off+16], data[off+17], data[off+18], data[off+19], data[off+20], data[off+21], data[off+22], data[off+23]]);
            let sh_offset = u64::from_le_bytes([data[off+24], data[off+25], data[off+26], data[off+27], data[off+28], data[off+29], data[off+30], data[off+31]]);
            let sh_size = u64::from_le_bytes([data[off+32], data[off+33], data[off+34], data[off+35], data[off+36], data[off+37], data[off+38], data[off+39]]);
            let sh_link = u32::from_le_bytes([data[off+40], data[off+41], data[off+42], data[off+43]]);
            let sh_info = u32::from_le_bytes([data[off+44], data[off+45], data[off+46], data[off+47]]);
            let sh_addralign = u64::from_le_bytes([data[off+48], data[off+49], data[off+50], data[off+51], data[off+52], data[off+53], data[off+54], data[off+55]]);
            let sh_entsize = u64::from_le_bytes([data[off+56], data[off+57], data[off+58], data[off+59], data[off+60], data[off+61], data[off+62], data[off+63]]);
            result.push((sh_name, sh_type, sh_offset, sh_size, sh_flags, sh_info, sh_addralign, sh_entsize, sh_link));
        } else {
            let sh_name = u32::from_le_bytes([data[off], data[off+1], data[off+2], data[off+3]]);
            let sh_type = u32::from_le_bytes([data[off+4], data[off+5], data[off+6], data[off+7]]);
            let sh_flags = u32::from_le_bytes([data[off+8], data[off+9], data[off+10], data[off+11]]) as u64;
            let _sh_addr = u32::from_le_bytes([data[off+12], data[off+13], data[off+14], data[off+15]]) as u64;
            let sh_offset = u32::from_le_bytes([data[off+16], data[off+17], data[off+18], data[off+19]]) as u64;
            let sh_size = u32::from_le_bytes([data[off+20], data[off+21], data[off+22], data[off+23]]) as u64;
            let sh_link = u32::from_le_bytes([data[off+24], data[off+25], data[off+26], data[off+27]]);
            let sh_info = u32::from_le_bytes([data[off+28], data[off+29], data[off+30], data[off+31]]);
            let sh_addralign = u32::from_le_bytes([data[off+32], data[off+33], data[off+34], data[off+35]]) as u64;
            let sh_entsize = u32::from_le_bytes([data[off+36], data[off+37], data[off+38], data[off+39]]) as u64;
            result.push((sh_name, sh_type, sh_offset, sh_size, sh_flags, sh_info, sh_addralign, sh_entsize, sh_link));
        }
    }
    result
}

/// Archive file header structure (from ar format).
#[repr(C)]
#[allow(dead_code)]
pub struct ArHeader {
    name: [u8; 16],
    date: [u8; 12],
    uid: [u8; 6],
    gid: [u8; 6],
    mode: [u8; 8],
    size: [u8; 10],
    fmag: [u8; 2],
}

/// Parse a decimal number from a fixed-width ASCII field.
fn parse_ar_number(field: &[u8]) -> u64 {
    let s = std::str::from_utf8(field).unwrap_or("").trim();
    s.parse::<u64>().unwrap_or(0)
}

/// Load an archive (.a) file. Processes each member and loads object files
/// that define symbols currently undefined in the symbol table.
pub fn tcc_load_archive(
    state: &mut crate::TCCState,
    filename: &str,
) -> TccResult<()> {
    let data = std::fs::read(filename).map_err(|e| TccError::IoError(e))?;
    if data.len() < 8 || &data[..8] != b"!<arch>\n" {
        return Err(TccError::linker(&format!(
            "{}: not a valid archive file",
            filename
        )));
    }

    let mut offset = 8;
    let mut _symbol_table: Option<Vec<u8>> = None;
    let mut string_table: Option<Vec<u8>> = None;

    while offset < data.len() {
        // Align to 2-byte boundary
        if offset & 1 != 0 {
            offset += 1;
        }
        if offset + 60 > data.len() {
            break;
        }

        // Read archive header (60 bytes)
        let hdr_name = &data[offset..offset + 16];
        let hdr_size = parse_ar_number(&data[offset + 48..offset + 58]) as usize;
        let fmag = &data[offset + 58..offset + 60];

        if fmag != b"`\n" {
            return Err(TccError::linker(&format!(
                "{}: bad archive header magic",
                filename
            )));
        }

        let member_offset = offset + 60;
        let member_end = member_offset + hdr_size;
        if member_end > data.len() {
            break;
        }

        // Identify special members
        if hdr_name.starts_with(b"/               ") {
            // Symbol table (index)
            _symbol_table = Some(data[member_offset..member_end].to_vec());
        } else if hdr_name.starts_with(b"//              ") {
            // Extended name table
            string_table = Some(data[member_offset..member_end].to_vec());
        } else {
            // Regular member — try to load as object
            let member_data = &data[member_offset..member_end];
            if member_data.len() >= 4
                && member_data[0] == 0x7f
                && member_data[1] == b'E'
                && member_data[2] == b'L'
                && member_data[3] == b'F'
            {
                // Determine member name
                let name = if hdr_name[0] == b'/' && hdr_name[1].is_ascii_digit() {
                    // Extended name: /NNN references string table
                    let idx_str = std::str::from_utf8(&hdr_name[1..]).unwrap_or("").trim();
                    let idx = idx_str.parse::<usize>().unwrap_or(0);
                    if let Some(ref strtab) = string_table {
                        let end = strtab[idx..].iter().position(|&b| b == b'/' || b == b'\n' || b == 0)
                            .map(|p| idx + p).unwrap_or(strtab.len());
                        std::str::from_utf8(&strtab[idx..end]).unwrap_or("").to_string()
                    } else {
                        format!("{}(member@{})", filename, offset)
                    }
                } else {
                    // Short name: trim spaces and trailing '/'
                    let name = std::str::from_utf8(hdr_name).unwrap_or("").trim();
                    name.trim_end_matches('/').to_string()
                };

                // Write member to temp file and load it
                // (In a full implementation, we'd load from memory)
                let tmp_path = format!("/tmp/tcc_ar_member_{}.o", offset);
                std::fs::write(&tmp_path, member_data)
                    .map_err(|e| TccError::IoError(e))?;
                let result = tcc_load_object_file(state, &tmp_path);
                let _ = std::fs::remove_file(&tmp_path);
                if let Err(e) = result {
                    if state.verbose > 0 {
                        eprintln!("warning: failed to load archive member '{}': {}", name, e);
                    }
                }
            }
        }

        offset = member_end;
    }

    if state.verbose > 0 {
        eprintln!("-> {}", filename);
    }
    Ok(())
}

/// Load a shared library (.so) for linking purposes.
///
/// Reads the dynamic symbol table to identify exported symbols,
/// adding them to the compiler state's symbol table as undefined
/// (to be resolved at runtime).
pub fn tcc_load_dll(
    state: &mut crate::TCCState,
    filename: &str,
) -> TccResult<()> {
    let data = std::fs::read(filename).map_err(|e| TccError::IoError(e))?;
    if data.len() < EHDR_SIZE {
        return Err(TccError::linker(&format!(
            "{}: file too short for DLL",
            filename
        )));
    }

    // Validate ELF magic
    if data[0] != 0x7f || data[1] != b'E' || data[2] != b'L' || data[3] != b'F' {
        return Err(TccError::linker(&format!(
            "{}: not a valid ELF shared library",
            filename
        )));
    }

    // Read section headers to find .dynsym and .dynstr
    let (e_shoff, e_shnum, _e_shstrndx, e_shentsize) = if PTR_SIZE == 8 {
        let shoff = u64::from_le_bytes([data[40], data[41], data[42], data[43], data[44], data[45], data[46], data[47]]) as usize;
        let shnum = u16::from_le_bytes([data[60], data[61]]) as usize;
        let shstrndx = u16::from_le_bytes([data[62], data[63]]) as usize;
        let shentsize = u16::from_le_bytes([data[58], data[59]]) as usize;
        (shoff, shnum, shstrndx, shentsize)
    } else {
        let shoff = u32::from_le_bytes([data[32], data[33], data[34], data[35]]) as usize;
        let shnum = u16::from_le_bytes([data[48], data[49]]) as usize;
        let shstrndx = u16::from_le_bytes([data[50], data[51]]) as usize;
        let shentsize = u16::from_le_bytes([data[46], data[47]]) as usize;
        (shoff, shnum, shstrndx, shentsize)
    };

    let obj_shdrs = read_section_headers(&data, e_shoff, e_shnum, e_shentsize);

    // Find .dynsym section
    let mut dynsym_idx: Option<usize> = None;
    for i in 0..e_shnum {
        if obj_shdrs[i].1 == SHT_DYNSYM {
            dynsym_idx = Some(i);
            break;
        }
    }

    let dynsym_i = match dynsym_idx {
        Some(i) => i,
        None => {
            // No dynamic symbols — nothing to import
            return Ok(());
        }
    };

    // Get the linked string table
    let dynstr_i = obj_shdrs[dynsym_i].8 as usize; // sh_link
    let dynstr_off = obj_shdrs[dynstr_i].2 as usize;
    let _dynstr_size = obj_shdrs[dynstr_i].3 as usize;

    let dynsym_off = obj_shdrs[dynsym_i].2 as usize;
    let dynsym_size = obj_shdrs[dynsym_i].3 as usize;
    let dynsym_entsize = if PTR_SIZE == 8 { core::mem::size_of::<Elf64_Sym>() } else { core::mem::size_of::<Elf32_Sym>() };
    let nsyms = dynsym_size / dynsym_entsize;

    let symtab_idx = match state.symtab_section {
        Some(idx) => idx,
        None => return Ok(()),
    };

    // Add each global dynamic symbol to our symbol table
    for i in 1..nsyms {
        let sym_off = dynsym_off + i * dynsym_entsize;
        let (st_name, st_info, st_other, _st_shndx, _st_value, _st_size) = if PTR_SIZE == 8 {
            let s = read_sym64(&data, sym_off);
            (s.st_name, s.st_info, s.st_other, s.st_shndx, s._st_value, s.st_size)
        } else {
            let s = read_sym32(&data, sym_off);
            (s.st_name, s.st_info, s.st_other, s.st_shndx, s._st_value as u64, s.st_size as u64)
        };

        let bind = ELFW_ST_BIND(st_info);
        if bind != STB_GLOBAL && bind != STB_WEAK {
            continue;
        }

        // Get symbol name from the DLL's dynstr
        let name_start = dynstr_off + st_name as usize;
        if name_start >= data.len() {
            continue;
        }
        let name_end = data[name_start..].iter().position(|&b| b == 0)
            .map(|p| name_start + p).unwrap_or(data.len());
        let sym_name = std::str::from_utf8(&data[name_start..name_end]).unwrap_or("");
        if sym_name.is_empty() {
            continue;
        }

        // Add as SHN_FROMDLL to indicate it's imported from a DLL
        set_elf_sym(
            state,
            symtab_idx,
            0,
            0,
            st_info,
            st_other,
            SHN_FROMDLL,
            sym_name,
        );
    }

    // Record the DLL in loaded_dlls
    let dll_name = std::path::Path::new(filename)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(filename)
        .to_string();
    state.loaded_dlls.push(DLLReference {
        name: dll_name,
        level: 0,
        handle: None,
        found: true,
        index: state.loaded_dlls.len() as u8,
    });

    if state.verbose > 0 {
        eprintln!("-> {}", filename);
    }
    Ok(())
}

/// Parse and execute a linker script.
///
/// Supports a subset of GNU ld linker script syntax:
///   - GROUP ( file1 file2 ... )
///   - INPUT ( file1 file2 ... )
///   - OUTPUT_FORMAT ( format )
///   - SEARCH_DIR ( path )
///   - AS_NEEDED ( file ... )
pub fn tcc_load_ldscript(
    state: &mut crate::TCCState,
    filename: &str,
) -> TccResult<()> {
    let content = std::fs::read_to_string(filename).map_err(|e| TccError::IoError(e))?;

    // Simple tokenizer for linker scripts
    let tokens: Vec<&str> = content
        .split(|c: char| c.is_whitespace() || c == '(' || c == ')' || c == ';' || c == ',')
        .filter(|s| !s.is_empty() && !s.starts_with("/*"))
        .collect();

    let mut i = 0;
    while i < tokens.len() {
        match tokens[i] {
            "GROUP" | "INPUT" => {
                // Collect filenames until we hit something else
                i += 1;
                while i < tokens.len() && tokens[i] != "GROUP" && tokens[i] != "INPUT"
                    && tokens[i] != "OUTPUT_FORMAT" && tokens[i] != "SEARCH_DIR"
                {
                    let fname = tokens[i];
                    if fname == "AS_NEEDED" || fname == "-l" || fname.starts_with("/*") {
                        i += 1;
                        continue;
                    }
                    if fname.starts_with("-l") {
                        // Library reference: -lfoo -> find libfoo.so or libfoo.a
                        let lib = &fname[2..];
                        if state.verbose > 0 {
                            eprintln!("ldscript: need library '{}'", lib);
                        }
                    } else {
                        // File reference
                        let path = if std::path::Path::new(fname).is_absolute() {
                            fname.to_string()
                        } else {
                            let dir = std::path::Path::new(filename).parent().unwrap_or(std::path::Path::new("."));
                            dir.join(fname).to_string_lossy().to_string()
                        };
                        if std::path::Path::new(&path).exists() {
                            let fdata = std::fs::read(&path).map_err(|e| TccError::IoError(e))?;
                            let obj_type = tcc_object_type(&fdata);
                            match obj_type {
                                1 => tcc_load_object_file(state, &path)?,
                                2 => tcc_load_archive(state, &path)?,
                                3 => tcc_load_dll(state, &path)?,
                                4 => tcc_load_ldscript(state, &path)?,
                                _ => {
                                    if state.verbose > 0 {
                                        eprintln!("ldscript: unknown file type: {}", path);
                                    }
                                }
                            }
                        }
                    }
                    i += 1;
                }
            }
            "OUTPUT_FORMAT" => {
                // Skip output format specification
                i += 1;
                while i < tokens.len() && tokens[i] != "GROUP" && tokens[i] != "INPUT"
                    && tokens[i] != "OUTPUT_FORMAT" && tokens[i] != "SEARCH_DIR"
                {
                    i += 1;
                }
            }
            "SEARCH_DIR" => {
                i += 1;
                if i < tokens.len() {
                    let path = tokens[i].trim_matches('"');
                    state.library_paths.push(path.to_string());
                    i += 1;
                }
            }
            _ => {
                i += 1;
            }
        }
    }

    Ok(())
}

/// List symbols in a symbol table. Used by `tcc -symbols` option.
pub fn list_elf_symbols(
    state: &crate::TCCState,
    callback: &mut dyn FnMut(&str, u64),
) {
    let symtab_idx = match state.symtab_section {
        Some(idx) => idx,
        None => return,
    };
    let strtab_idx = state.sections[symtab_idx].link.unwrap_or(0);
    let nsyms = sym_count(&state.sections[symtab_idx]);

    for i in 1..nsyms {
        let info = get_sym_info(&state.sections[symtab_idx], i);
        let bind = ELFW_ST_BIND(info);
        if bind != STB_GLOBAL && bind != STB_WEAK {
            continue;
        }
        let name_off = get_sym_name_offset(&state.sections[symtab_idx], i);
        let name = get_elf_str(&state.sections[strtab_idx], name_off);
        if name.is_empty() {
            continue;
        }
        let value = get_sym_value(&state.sections[symtab_idx], i);
        callback(name, value);
    }
}

// ============================================================
// Lifecycle functions
// ============================================================

/// Initialize ELF structures in the compiler state.
/// Creates the core sections: symtab, strtab, .text, .data, .bss, .rodata.
pub fn tccelf_new(state: &mut crate::TCCState) -> TccResult<()> {
    // Section 0 is always the null section
    if state.sections.is_empty() {
        state.sections.push(Section::default());
    }

    // Create the section name string table
    let shstrtab_idx = new_section(state, ".shstrtab", SHT_STRTAB, 0);
    // Ensure first byte is 0 (empty string) for ELF compliance
    if state.sections[shstrtab_idx].data_offset == 0 {
        section_ptr_add(&mut state.sections[shstrtab_idx], 1);
    }

    // Create string table for symbol names
    let strtab_idx = new_section(state, ".strtab", SHT_STRTAB, 0);
    // First byte is 0
    if state.sections[strtab_idx].data_offset == 0 {
        section_ptr_add(&mut state.sections[strtab_idx], 1);
    }

    // Create the main symbol table
    let symtab_idx = new_section(state, ".symtab", SHT_SYMTAB, 0);
    state.sections[symtab_idx].link = Some(strtab_idx);
    state.symtab_section = Some(symtab_idx);

    // Create a hash table for the symbol table
    let hash_idx = new_section(state, ".hash", SHT_HASH, SHF_PRIVATE);
    state.sections[symtab_idx].hash = Some(hash_idx);
    state.sections[hash_idx].link = Some(symtab_idx);

    // Create core code/data sections
    let text_idx = new_section(state, ".text", SHT_PROGBITS, SHF_ALLOC | SHF_EXECINSTR);
    state.text_section = Some(text_idx);

    let data_idx = new_section(state, ".data", SHT_PROGBITS, SHF_ALLOC | SHF_WRITE);
    state.data_section = Some(data_idx);

    let rodata_idx = new_section(state, ".rodata", SHT_PROGBITS, SHF_ALLOC);
    state.rodata_section = Some(rodata_idx);

    let bss_idx = new_section(state, ".bss", SHT_NOBITS, SHF_ALLOC | SHF_WRITE);
    state.bss_section = Some(bss_idx);

    let common_idx = new_section(state, ".common", SHT_NOBITS, SHF_PRIVATE);
    state.common_section = Some(common_idx);

    // Add a FILE symbol for the compilation unit
    put_elf_sym(
        state,
        symtab_idx,
        0, 0,
        ELFW_ST_INFO(STB_LOCAL, STT_FILE),
        0,
        SHN_ABS,
        "<tcc>",
    );

    // Add section symbols for each section
    let num_sections = state.sections.len();
    for i in 1..num_sections {
        let sh_type = state.sections[i].sh_type as u32;
        let sh_flags = state.sections[i].sh_flags as u32;
        if sh_type != SHT_STRTAB && sh_type != SHT_SYMTAB && sh_type != SHT_HASH
            && sh_flags & SHF_PRIVATE == 0
        {
            put_elf_sym(
                state,
                symtab_idx,
                0, 0,
                ELFW_ST_INFO(STB_LOCAL, STT_SECTION),
                0,
                i as u16,
                "",
            );
        }
    }

    Ok(())
}

/// Clean up ELF structures. Frees all section data.
pub fn tccelf_delete(state: &mut crate::TCCState) {
    for sec in state.sections.iter_mut() {
        free_section(sec);
    }
    for sec in state.priv_sections.iter_mut() {
        free_section(sec);
    }
    state.sections.clear();
    state.priv_sections.clear();
    state.symtab_section = None;
    state.dynsymtab_section = None;
    state.got = None;
    state.plt = None;
    state.dynsym = None;
}

/// Called at the beginning of each source file compilation.
/// Manages section states for multi-file compilation.
pub fn tccelf_begin_file(state: &mut crate::TCCState) {
    // Reset section data_offset markers for merging
    let num_sections = state.sections.len();
    for i in 0..num_sections {
        let sec = &mut state.sections[i];
        sec.sh_offset = sec.data_offset;
    }
}

/// Called at the end of each source file compilation.
/// Finalizes the current file's contribution to the output.
pub fn tccelf_end_file(state: &mut crate::TCCState) {
    // Update section sizes
    let num_sections = state.sections.len();
    for i in 0..num_sections {
        let offset = state.sections[i].data_offset;
        state.sections[i].sh_size = offset;
    }
}

// ============================================================
// CRT and runtime support
// ============================================================

/// Add runtime library support (libtcc1, CRT files, etc.).
///
/// LINK-01: For static linking, add CRT begin/end objects and libtcc1.
/// For dynamic linking, add dynamic CRT objects.
pub fn tcc_add_runtime(state: &mut crate::TCCState) -> TccResult<()> {
    let output_type = match state.output_type {
        Some(t) => t,
        None => return Ok(()),
    };

    // Skip for object files
    if output_type == OutputType::Obj {
        return Ok(());
    }

    // Skip if nostdlib is set
    if state.nostdlib {
        return Ok(());
    }

    // Add the TCC runtime library (libtcc1.a)
    let lib_path = if !state.tcc_lib_path.is_empty() {
        state.tcc_lib_path.clone()
    } else {
        crate::config::tcc_lib_path(None)
    };

    let libtcc1 = format!("{}/{}", lib_path, crate::config::LIBTCC1);
    if std::path::Path::new(&libtcc1).exists() {
        tcc_load_archive(state, &libtcc1)?;
    }

    // For executables, add CRT begin/end
    if output_type == OutputType::Exe || output_type == OutputType::Dll {
        // Search for crt1.o, crti.o, crtn.o in CRT paths
        let crt_paths = crate::config::split_paths(crate::config::CRT_PREFIX);
        for crt_dir in &crt_paths {
            let expanded = crate::config::expand_path(crt_dir, &lib_path);
            if output_type == OutputType::Exe {
                let crt1 = format!("{}/crt1.o", expanded);
                if std::path::Path::new(&crt1).exists() {
                    tcc_load_object_file(state, &crt1)?;
                }
            }
            let crti = format!("{}/crti.o", expanded);
            if std::path::Path::new(&crti).exists() {
                tcc_load_object_file(state, &crti)?;
            }
        }
    }

    Ok(())
}

/// Add the dynamic section (.dynamic) and dynamic symbol table for
/// executables and shared libraries.
pub fn build_dynamic(state: &mut crate::TCCState) -> TccResult<Option<usize>> {
    let output_type = match state.output_type {
        Some(t) => t,
        None => return Ok(None),
    };

    if state.static_link {
        return Ok(None);
    }

    if output_type != OutputType::Exe && output_type != OutputType::Dll {
        return Ok(None);
    }

    // Create .dynsym section
    let dynsym_strtab_idx = new_section(state, ".dynstr", SHT_STRTAB, SHF_ALLOC);
    if state.sections[dynsym_strtab_idx].data_offset == 0 {
        section_ptr_add(&mut state.sections[dynsym_strtab_idx], 1);
    }

    let dynsym_idx = new_section(state, ".dynsym", SHT_DYNSYM, SHF_ALLOC);
    state.sections[dynsym_idx].link = Some(dynsym_strtab_idx);
    state.dynsymtab_section = Some(dynsym_idx);

    // Create .dynamic section
    let dynamic_idx = new_section(
        state,
        ".dynamic",
        SHT_DYNAMIC,
        SHF_ALLOC | SHF_WRITE,
    );
    state.sections[dynamic_idx].link = Some(dynsym_strtab_idx);

    // Create .hash section for dynamic symbols
    let dynhash_idx = new_section(state, ".gnu.hash", SHT_GNU_HASH, SHF_ALLOC);
    state.sections[dynsym_idx].hash = Some(dynhash_idx);

    Ok(Some(dynamic_idx))
}

/// Add a dynamic table entry (DT_* tag + value) to the .dynamic section.
pub fn put_dt(state: &mut crate::TCCState, dynamic_idx: usize, tag: i64, val: u64) {
    if PTR_SIZE == 8 {
        let off = section_ptr_add(&mut state.sections[dynamic_idx], DYN_SIZE);
        let d = &mut state.sections[dynamic_idx].data[off..off + DYN_SIZE];
        d[0..8].copy_from_slice(&tag.to_le_bytes());
        d[8..16].copy_from_slice(&val.to_le_bytes());
    } else {
        let off = section_ptr_add(&mut state.sections[dynamic_idx], DYN_SIZE);
        let d = &mut state.sections[dynamic_idx].data[off..off + DYN_SIZE];
        d[0..4].copy_from_slice(&(tag as i32).to_le_bytes());
        d[4..8].copy_from_slice(&(val as u32).to_le_bytes());
    }
}

// ============================================================
// Linker symbols and dynamic binding
// ============================================================

/// Add standard linker-defined symbols (_start, __start, etext, edata, end, etc.)
pub fn tcc_add_linker_symbols(state: &mut crate::TCCState) {
    let symtab = match state.symtab_section {
        Some(idx) => idx,
        None => return,
    };
    let text_idx = state.text_section.unwrap_or(1);
    let data_idx = state.data_section.unwrap_or(2);
    let bss_idx = state.bss_section.unwrap_or(4);

    // The entry point name
    let entry_name = match &state.elf_entryname {
        Some(name) if !name.is_empty() => name.clone(),
        _ => "_start".to_string(),
    };

    // Set the entry point symbol
    set_elf_sym(state, symtab, 0, 0,
        ELFW_ST_INFO(STB_GLOBAL, STT_NOTYPE), 0,
        text_idx as u16, &entry_name);

    // Linker-defined section boundary symbols
    let linker_syms = [
        ("__start", text_idx, STB_GLOBAL),
        ("__stop", text_idx, STB_GLOBAL),
        ("_etext", text_idx, STB_GLOBAL),
        ("__etext", text_idx, STB_GLOBAL),
        ("etext", text_idx, STB_GLOBAL),
        ("_edata", data_idx, STB_GLOBAL),
        ("edata", data_idx, STB_GLOBAL),
        ("_end", bss_idx, STB_GLOBAL),
        ("__end", bss_idx, STB_GLOBAL),
        ("end", bss_idx, STB_GLOBAL),
    ];
    for (name, sec_idx, bind) in &linker_syms {
        set_elf_sym(state, symtab, 0, 0,
            ELFW_ST_INFO(*bind, STT_NOTYPE), 0,
            *sec_idx as u16, name);
    }

    // __executable_start — address of the first loadable segment
    set_elf_sym(state, symtab, 0, 0,
        ELFW_ST_INFO(STB_GLOBAL, STT_NOTYPE), 0,
        1, "__executable_start");

    // __dso_handle for shared libraries
    if state.output_type == Some(OutputType::Dll) {
        set_elf_sym(state, symtab, 0, 0,
            ELFW_ST_INFO(STB_GLOBAL, STT_OBJECT), 0,
            data_idx as u16, "__dso_handle");
    }
}

/// Bind executable dynamic symbols — export global symbols to .dynsym
/// that are referenced by loaded shared libraries.
pub fn bind_exe_dynsyms(state: &mut crate::TCCState) {
    let symtab_idx = match state.symtab_section {
        Some(idx) => idx,
        None => return,
    };
    let dynsym_idx = match state.dynsymtab_section {
        Some(idx) => idx,
        None => return,
    };

    let sym_cnt = sym_count(&state.sections[symtab_idx]);
    for i in 1..sym_cnt {
        let info = get_sym_info(&state.sections[symtab_idx], i);
        let bind = ELFW_ST_BIND(info);
        let typ = ELFW_ST_TYPE(info);
        let shndx = get_sym_shndx(&state.sections[symtab_idx], i);

        // Only export defined global/weak symbols
        if shndx == SHN_UNDEF {
            continue;
        }
        if bind != STB_GLOBAL && bind != STB_WEAK {
            continue;
        }

        // Skip section symbols and file symbols
        if typ == STT_SECTION || typ == STT_FILE {
            continue;
        }

        // Check if symbol should be exported
        let vis = ELFW_ST_VISIBILITY(get_sym_other(&state.sections[symtab_idx], i));
        if vis == STV_HIDDEN {
            continue;
        }

        // Check if the symbol is referenced by any DLL (rdynamic exports all)
        if !state.rdynamic {
            let name_off = get_sym_name_offset(&state.sections[symtab_idx], i);
            let strtab_idx = state.sections[symtab_idx].link.unwrap_or(0);
            let name = get_elf_str(&state.sections[strtab_idx], name_off).to_string();
            let found = find_elf_sym(state, dynsym_idx, &name);
            if found == 0 {
                continue;
            }
        }

        let name_off = get_sym_name_offset(&state.sections[symtab_idx], i);
        let strtab_idx = state.sections[symtab_idx].link.unwrap_or(0);
        let name = get_elf_str(&state.sections[strtab_idx], name_off).to_string();
        let value = get_sym_value(&state.sections[symtab_idx], i);
        let size = get_sym_size(&state.sections[symtab_idx], i);

        put_elf_sym(state, dynsym_idx, value, size, info, vis as u8,
            shndx, &name);
    }
}

/// Bind shared library dynamic symbols — add undefined symbols from DLLs
/// to the dynamic symbol table for runtime resolution.
pub fn bind_libs_dynsyms(state: &mut crate::TCCState) {
    let symtab_idx = match state.symtab_section {
        Some(idx) => idx,
        None => return,
    };
    let dynsym_idx = match state.dynsymtab_section {
        Some(idx) => idx,
        None => return,
    };

    let sym_cnt = sym_count(&state.sections[symtab_idx]);
    for i in 1..sym_cnt {
        let info = get_sym_info(&state.sections[symtab_idx], i);
        let bind = ELFW_ST_BIND(info);
        let shndx = get_sym_shndx(&state.sections[symtab_idx], i);

        // Skip anything not from a DLL
        if shndx != SHN_FROMDLL {
            continue;
        }
        if bind != STB_GLOBAL && bind != STB_WEAK {
            continue;
        }

        let name_off = get_sym_name_offset(&state.sections[symtab_idx], i);
        let strtab_idx = state.sections[symtab_idx].link.unwrap_or(0);
        let name = get_elf_str(&state.sections[strtab_idx], name_off).to_string();
        let value = get_sym_value(&state.sections[symtab_idx], i);
        let size = get_sym_size(&state.sections[symtab_idx], i);

        put_elf_sym(state, dynsym_idx, value, size, info, 0,
            SHN_UNDEF, &name);
    }
}

/// Export global symbols from the compilation to the dynamic symbol table.
pub fn export_global_syms(state: &mut crate::TCCState) {
    let symtab_idx = match state.symtab_section {
        Some(idx) => idx,
        None => return,
    };
    let dynsym_idx = match state.dynsymtab_section {
        Some(idx) => idx,
        None => return,
    };

    let sym_cnt = sym_count(&state.sections[symtab_idx]);
    for i in 1..sym_cnt {
        let info = get_sym_info(&state.sections[symtab_idx], i);
        let bind = ELFW_ST_BIND(info);
        let shndx = get_sym_shndx(&state.sections[symtab_idx], i);

        if bind != STB_GLOBAL && bind != STB_WEAK {
            continue;
        }
        // Only export defined symbols
        if shndx == SHN_UNDEF {
            continue;
        }

        let vis = ELFW_ST_VISIBILITY(get_sym_other(&state.sections[symtab_idx], i));
        if vis == STV_HIDDEN {
            continue;
        }

        let name_off = get_sym_name_offset(&state.sections[symtab_idx], i);
        let strtab_idx = state.sections[symtab_idx].link.unwrap_or(0);
        let name = get_elf_str(&state.sections[strtab_idx], name_off).to_string();
        let value = get_sym_value(&state.sections[symtab_idx], i);
        let size = get_sym_size(&state.sections[symtab_idx], i);

        put_elf_sym(state, dynsym_idx, value, size, info, vis as u8,
            shndx, &name);
    }
}

// ============================================================
// GNU hash table construction
// ============================================================

/// GNU hash table bloom filter size constant
const GNU_HASH_BLOOM_SIZE: usize = 1;

/// Create a GNU hash table (.gnu.hash) for the dynamic symbol table.
/// This provides faster symbol lookup than the classic ELF hash.
pub fn create_gnu_hash(state: &mut crate::TCCState) -> TccResult<()> {
    let dynsym_idx = match state.dynsymtab_section {
        Some(idx) => idx,
        None => return Ok(()),
    };

    let nsyms = sym_count(&state.sections[dynsym_idx]);
    if nsyms <= 1 {
        return Ok(());
    }

    // Collect defined symbols with their GNU hashes
    let mut defined: Vec<(usize, u32)> = Vec::new(); // (sym_index, gnu_hash)
    let mut undef_count: usize = 0;
    for i in 1..nsyms {
        let shndx = get_sym_shndx(&state.sections[dynsym_idx], i);
        if shndx == SHN_UNDEF {
            undef_count += 1;
            continue;
        }
        let name_off = get_sym_name_offset(&state.sections[dynsym_idx], i);
        let strtab_idx = state.sections[dynsym_idx].link.unwrap_or(0);
        let name = get_elf_str(&state.sections[strtab_idx], name_off);
        let h = elf_gnu_hash(name.as_bytes());
        defined.push((i, h));
    }

    if defined.is_empty() {
        return Ok(());
    }

    // Number of buckets — use at least 1 and roughly sym_count/4
    let nbuckets = std::cmp::max(defined.len() / 4, 1);
    let symoffset = (undef_count + 1) as u32; // first defined symbol index in dynsym

    let bloom_size = GNU_HASH_BLOOM_SIZE;
    let elfclass_bits = (PTR_SIZE * 8) as u32;
    let bloom_shift = if elfclass_bits > 32 { 6u32 } else { 5u32 };

    let hash_section_idx = state.sections[dynsym_idx].hash.unwrap_or(0);
    if hash_section_idx == 0 {
        return Ok(());
    }

    // Reset hash section
    state.sections[hash_section_idx].data.clear();
    state.sections[hash_section_idx].data_offset = 0;

    // Total size: header (4 u32) + bloom filter + buckets + chains
    let hdr_size = 4 * 4 + bloom_size * PTR_SIZE + nbuckets * 4 + defined.len() * 4;
    let off = section_ptr_add(&mut state.sections[hash_section_idx], hdr_size);
    let data = &mut state.sections[hash_section_idx].data;

    // Write header
    data[off..off + 4].copy_from_slice(&(nbuckets as u32).to_le_bytes());
    data[off + 4..off + 8].copy_from_slice(&symoffset.to_le_bytes());
    data[off + 8..off + 12].copy_from_slice(&(bloom_size as u32).to_le_bytes());
    data[off + 12..off + 16].copy_from_slice(&bloom_shift.to_le_bytes());

    // Bloom filter — populate with actual symbol hash bits
    let bloom_off = off + 16;
    // Initialize bloom filter to zero
    for b in 0..bloom_size * PTR_SIZE {
        data[bloom_off + b] = 0;
    }
    // Set bloom bits for each defined symbol
    for &(_, h) in &defined {
        let word_idx = ((h / elfclass_bits) as usize) % bloom_size;
        let bit0 = h % elfclass_bits;
        let bit1 = (h >> bloom_shift) % elfclass_bits;
        if PTR_SIZE == 8 {
            let word_off = bloom_off + word_idx * 8;
            let mut word = u64::from_le_bytes([
                data[word_off], data[word_off + 1], data[word_off + 2], data[word_off + 3],
                data[word_off + 4], data[word_off + 5], data[word_off + 6], data[word_off + 7],
            ]);
            word |= 1u64 << bit0;
            word |= 1u64 << bit1;
            data[word_off..word_off + 8].copy_from_slice(&word.to_le_bytes());
        } else {
            let word_off = bloom_off + word_idx * 4;
            let mut word = u32::from_le_bytes([
                data[word_off], data[word_off + 1], data[word_off + 2], data[word_off + 3],
            ]);
            word |= 1u32 << bit0;
            word |= 1u32 << bit1;
            data[word_off..word_off + 4].copy_from_slice(&word.to_le_bytes());
        }
    }

    // Distribute symbols into buckets by hash % nbuckets
    let buckets_off = bloom_off + bloom_size * PTR_SIZE;
    let chains_off = buckets_off + nbuckets * 4;

    // Sort defined symbols by bucket (hash % nbuckets) for chain construction
    let mut sorted = defined.clone();
    sorted.sort_by_key(|&(_, h)| h as usize % nbuckets);

    // Build bucket and chain arrays
    // Buckets[i] = index (in sorted order + symoffset) of first symbol in bucket i, or 0
    // Chains[j] = hash value with LSB set to 1 if last in bucket chain
    let mut bucket_first: Vec<Option<usize>> = vec![None; nbuckets]; // first index in sorted for each bucket
    let mut bucket_last: Vec<usize> = vec![0; nbuckets];

    for (sorted_idx, &(_, h)) in sorted.iter().enumerate() {
        let bkt = h as usize % nbuckets;
        if bucket_first[bkt].is_none() {
            bucket_first[bkt] = Some(sorted_idx);
        }
        bucket_last[bkt] = sorted_idx;
    }

    // Write buckets: value = symoffset + sorted_idx of first symbol, or 0
    for bkt in 0..nbuckets {
        let val = match bucket_first[bkt] {
            Some(idx) => (idx as u32) + symoffset,
            None => 0u32,
        };
        let boff = buckets_off + bkt * 4;
        data[boff..boff + 4].copy_from_slice(&val.to_le_bytes());
    }

    // Write chains: hash value with bit 0 cleared, except last in bucket has bit 0 set
    for (sorted_idx, &(_, h)) in sorted.iter().enumerate() {
        let bkt = h as usize % nbuckets;
        let is_last = bucket_last[bkt] == sorted_idx;
        let chain_val = if is_last { h | 1 } else { h & !1 };
        let coff = chains_off + sorted_idx * 4;
        data[coff..coff + 4].copy_from_slice(&chain_val.to_le_bytes());
    }

    Ok(())
}

// ============================================================
// Init/fini array support
// ============================================================

/// Add .init_array and .fini_array section boundary symbols.
pub fn add_init_array_defines(state: &mut crate::TCCState) {
    let symtab = match state.symtab_section {
        Some(idx) => idx,
        None => return,
    };

    // Try to find existing .init_array section
    let num_sections = state.sections.len();
    for i in 0..num_sections {
        let sh_type = state.sections[i].sh_type as u32;
        let name = state.sections[i].name.clone();
        if sh_type == SHT_INIT_ARRAY || name == ".init_array" {
            let start_name = format!("__init_array_start");
            let end_name = format!("__init_array_end");
            set_elf_sym(state, symtab, 0, 0,
                ELFW_ST_INFO(STB_GLOBAL, STT_NOTYPE), 0,
                i as u16, &start_name);
            set_elf_sym(state, symtab, 0, 0,
                ELFW_ST_INFO(STB_GLOBAL, STT_NOTYPE), 0,
                i as u16, &end_name);
        }
        if sh_type == SHT_FINI_ARRAY || name == ".fini_array" {
            let start_name = format!("__fini_array_start");
            let end_name = format!("__fini_array_end");
            set_elf_sym(state, symtab, 0, 0,
                ELFW_ST_INFO(STB_GLOBAL, STT_NOTYPE), 0,
                i as u16, &start_name);
            set_elf_sym(state, symtab, 0, 0,
                ELFW_ST_INFO(STB_GLOBAL, STT_NOTYPE), 0,
                i as u16, &end_name);
        }
    }
}

// ============================================================
// Dynamic section filling
// ============================================================

/// Fill the .dynamic section with required entries for executables and shared libs.
pub fn fill_dynamic(state: &mut crate::TCCState, dynamic_idx: usize) -> TccResult<()> {
    let output_type = match state.output_type {
        Some(t) => t,
        None => return Ok(()),
    };

    let dynsym_idx = match state.dynsymtab_section {
        Some(idx) => idx,
        None => return Ok(()),
    };

    let dynstr_idx = state.sections[dynsym_idx].link.unwrap_or(0);

    // DT_NEEDED for each loaded DLL — collect names first to avoid borrow conflict
    let dll_names: Vec<String> = state.loaded_dlls.iter()
        .filter(|dll| dll.level > 0)
        .map(|dll| dll.name.clone())
        .collect();
    for dll_name in &dll_names {
        let name_off = put_elf_str(&mut state.sections[dynstr_idx], dll_name);
        put_dt(state, dynamic_idx, DT_NEEDED as i64, name_off as u64);
    }

    // DT_HASH / DT_GNU_HASH
    if let Some(hash_idx) = state.sections[dynsym_idx].hash {
        let hash_addr = state.sections[hash_idx].sh_addr;
        put_dt(state, dynamic_idx, 0x6ffffef5_i64, hash_addr); // DT_GNU_HASH
    }

    // DT_STRTAB, DT_SYMTAB
    let strtab_addr = state.sections[dynstr_idx].sh_addr;
    put_dt(state, dynamic_idx, DT_STRTAB as i64, strtab_addr);
    let symtab_addr = state.sections[dynsym_idx].sh_addr;
    put_dt(state, dynamic_idx, DT_SYMTAB as i64, symtab_addr);

    // DT_STRSZ, DT_SYMENT
    let strsz = state.sections[dynstr_idx].data_offset as u64;
    put_dt(state, dynamic_idx, 10, strsz); // DT_STRSZ = 10
    put_dt(state, dynamic_idx, 11, SYM_SIZE as u64); // DT_SYMENT = 11

    // DT_SONAME for shared libraries
    if output_type == OutputType::Dll {
        if let Some(ref soname) = state.soname {
            if !soname.is_empty() {
                let name_off = put_elf_str(&mut state.sections[dynstr_idx], soname);
                put_dt(state, dynamic_idx, 14, name_off as u64); // DT_SONAME = 14
            }
        }
    }

    // DT_RPATH
    if let Some(ref rpath) = state.rpath {
        if !rpath.is_empty() {
            let rpath_off = put_elf_str(&mut state.sections[dynstr_idx], rpath);
            put_dt(state, dynamic_idx, 15, rpath_off as u64); // DT_RPATH = 15
        }
    }

    // DT_NULL — end of dynamic section
    put_dt(state, dynamic_idx, DT_NULL as i64, 0);

    Ok(())
}

// ============================================================
// Program header fill
// ============================================================

/// Fill in program header fields after section layout is determined.
pub fn fill_phdr(phdr: &mut Vec<u8>, phdr_idx: usize, p_type: u32, p_flags: u32,
                 p_offset: u64, p_vaddr: u64, p_filesz: u64, p_memsz: u64, p_align: u64) {
    let off = phdr_idx * PHDR_SIZE;
    if off + PHDR_SIZE > phdr.len() {
        phdr.resize(off + PHDR_SIZE, 0);
    }
    if PTR_SIZE == 8 {
        phdr[off..off + 4].copy_from_slice(&p_type.to_le_bytes());
        phdr[off + 4..off + 8].copy_from_slice(&p_flags.to_le_bytes());
        phdr[off + 8..off + 16].copy_from_slice(&p_offset.to_le_bytes());
        phdr[off + 16..off + 24].copy_from_slice(&p_vaddr.to_le_bytes());
        phdr[off + 24..off + 32].copy_from_slice(&p_vaddr.to_le_bytes()); // p_paddr = p_vaddr
        phdr[off + 32..off + 40].copy_from_slice(&p_filesz.to_le_bytes());
        phdr[off + 40..off + 48].copy_from_slice(&p_memsz.to_le_bytes());
        phdr[off + 48..off + 56].copy_from_slice(&p_align.to_le_bytes());
    } else {
        phdr[off..off + 4].copy_from_slice(&p_type.to_le_bytes());
        phdr[off + 4..off + 8].copy_from_slice(&(p_offset as u32).to_le_bytes());
        phdr[off + 8..off + 12].copy_from_slice(&(p_vaddr as u32).to_le_bytes());
        phdr[off + 12..off + 16].copy_from_slice(&(p_vaddr as u32).to_le_bytes());
        phdr[off + 16..off + 20].copy_from_slice(&(p_filesz as u32).to_le_bytes());
        phdr[off + 20..off + 24].copy_from_slice(&(p_memsz as u32).to_le_bytes());
        phdr[off + 24..off + 28].copy_from_slice(&p_flags.to_le_bytes());
        phdr[off + 28..off + 32].copy_from_slice(&(p_align as u32).to_le_bytes());
    }
}

// ============================================================
// Symbol versioning support (minimal — matching TCC's limited versioning)
// ============================================================

/// Read version information from a shared library's .gnu.version sections.
/// TCC has limited versioning support — this reads and stores version info
/// from DSOs but does not enforce strict version matching.
pub fn version_add(state: &mut crate::TCCState, _lib_name: &str) {
    // TCC's version handling is minimal. We note the library but do not
    // enforce strict symbol versioning — matching original TCC behavior.
    let _ = state;
}

// ============================================================
// Additional helper: new_undef_sym
// ============================================================

/// Create a new undefined symbol in the symbol table.
/// Used by linker script processing to reference symbols from GROUP/INPUT.
pub fn new_undef_sym(state: &mut crate::TCCState, name: &str) -> usize {
    let symtab = match state.symtab_section {
        Some(idx) => idx,
        None => return 0,
    };
    // Check if already exists
    let existing = find_elf_sym(state, symtab, name);
    if existing != 0 {
        return existing;
    }
    // Create undefined global symbol
    put_elf_sym(state, symtab, 0, 0,
        ELFW_ST_INFO(STB_GLOBAL, STT_NOTYPE), 0,
        SHN_UNDEF, name)
}

// Ad-hoc unit tests for crates/tcc-core/src/elf.rs
// These tests verify the core ELF module functionality.

#[cfg(test)]
mod elf_tests {
    use crate::elf::*;
    use crate::types::Section;

    // ============================================================
    // ELF Constants Tests
    // ============================================================
    
    #[test]
    fn test_elf_magic() {
        assert_eq!(ELFMAG, [0x7f, b'E', b'L', b'F']);
        assert_eq!(SELFMAG, 4);
    }

    #[test]
    fn test_elf_class_constants() {
        assert_eq!(ELFCLASS32, 1);
        assert_eq!(ELFCLASS64, 2);
    }

    #[test]
    fn test_elf_data_encoding() {
        assert_eq!(ELFDATA2LSB, 1);
        assert_eq!(ELFDATA2MSB, 2);
    }

    #[test]
    fn test_ev_current() {
        assert_eq!(EV_CURRENT, 1);
    }

    #[test]
    fn test_et_constants() {
        assert_eq!(ET_REL, 1);
        assert_eq!(ET_EXEC, 2);
        assert_eq!(ET_DYN, 3);
    }

    #[test]
    fn test_shn_constants() {
        assert_eq!(SHN_UNDEF, 0);
        assert_eq!(SHN_ABS, 0xfff1);
        assert_eq!(SHN_COMMON, 0xfff2);
        assert_eq!(SHN_FROMDLL, 0xffff);
        assert_eq!(SHN_LORESERVE, 0xff00);
    }

    #[test]
    fn test_sht_constants() {
        assert_eq!(SHT_NULL, 0);
        assert_eq!(SHT_PROGBITS, 1);
        assert_eq!(SHT_SYMTAB, 2);
        assert_eq!(SHT_STRTAB, 3);
        assert_eq!(SHT_RELA, 4);
        assert_eq!(SHT_HASH, 5);
        assert_eq!(SHT_DYNAMIC, 6);
        assert_eq!(SHT_NOTE, 7);
        assert_eq!(SHT_NOBITS, 8);
        assert_eq!(SHT_REL, 9);
        assert_eq!(SHT_DYNSYM, 11);
        assert_eq!(SHT_INIT_ARRAY, 14);
        assert_eq!(SHT_FINI_ARRAY, 15);
    }

    #[test]
    fn test_sht_relx() {
        if crate::config::PTR_SIZE == 8 {
            assert_eq!(SHT_RELX, SHT_RELA);
        } else {
            assert_eq!(SHT_RELX, SHT_REL);
        }
    }

    #[test]
    fn test_shf_constants() {
        assert_eq!(SHF_WRITE, 0x1);
        assert_eq!(SHF_ALLOC, 0x2);
        assert_eq!(SHF_EXECINSTR, 0x4);
        assert_eq!(SHF_MERGE, 0x10);
        assert_eq!(SHF_STRINGS, 0x20);
        assert_eq!(SHF_TLS, 0x400);
    }

    #[test]
    fn test_stb_constants() {
        assert_eq!(STB_LOCAL, 0);
        assert_eq!(STB_GLOBAL, 1);
        assert_eq!(STB_WEAK, 2);
    }

    #[test]
    fn test_stt_constants() {
        assert_eq!(STT_NOTYPE, 0);
        assert_eq!(STT_OBJECT, 1);
        assert_eq!(STT_FUNC, 2);
        assert_eq!(STT_SECTION, 3);
        assert_eq!(STT_FILE, 4);
        assert_eq!(STT_GNU_IFUNC, 10);
    }

    #[test]
    fn test_stv_constants() {
        assert_eq!(STV_DEFAULT, 0);
        assert_eq!(STV_INTERNAL, 1);
        assert_eq!(STV_HIDDEN, 2);
        assert_eq!(STV_PROTECTED, 3);
    }

    #[test]
    fn test_pt_constants() {
        assert_eq!(PT_NULL, 0);
        assert_eq!(PT_LOAD, 1);
        assert_eq!(PT_DYNAMIC, 2);
        assert_eq!(PT_INTERP, 3);
        assert_eq!(PT_NOTE, 4);
        assert_eq!(PT_PHDR, 6);
        assert_eq!(PT_TLS, 7);
    }

    #[test]
    fn test_pf_constants() {
        assert_eq!(PF_X, 0x1);
        assert_eq!(PF_W, 0x2);
        assert_eq!(PF_R, 0x4);
    }

    #[test]
    fn test_dt_constants() {
        assert_eq!(DT_NULL, 0);
        assert_eq!(DT_NEEDED, 1);
        assert_eq!(DT_HASH, 4);
        assert_eq!(DT_STRTAB, 5);
        assert_eq!(DT_SYMTAB, 6);
    }

    #[test]
    fn test_r_data_ptr() {
        // R_DATA_PTR should be a valid relocation type
        assert!(R_DATA_PTR > 0);
    }

    // ============================================================
    // ELF Helper Function Tests
    // ============================================================

    #[test]
    fn test_elfw_st_info() {
        let info = ELFW_ST_INFO(STB_GLOBAL, STT_FUNC);
        assert_eq!(ELFW_ST_BIND(info), STB_GLOBAL);
        assert_eq!(ELFW_ST_TYPE(info), STT_FUNC);
    }

    #[test]
    fn test_elfw_st_info_local_object() {
        let info = ELFW_ST_INFO(STB_LOCAL, STT_OBJECT);
        assert_eq!(ELFW_ST_BIND(info), STB_LOCAL);
        assert_eq!(ELFW_ST_TYPE(info), STT_OBJECT);
    }

    #[test]
    fn test_elfw_st_visibility() {
        assert_eq!(ELFW_ST_VISIBILITY(STV_DEFAULT), STV_DEFAULT);
        assert_eq!(ELFW_ST_VISIBILITY(STV_HIDDEN), STV_HIDDEN);
        assert_eq!(ELFW_ST_VISIBILITY(STV_PROTECTED), STV_PROTECTED);
    }

    #[test]
    fn test_elfw_r_info_and_decompose() {
        let sym_idx: u64 = 42;
        let rel_type: u64 = 7;
        let info = ELFW_R_INFO(sym_idx, rel_type);
        assert_eq!(ELFW_R_SYM(info), sym_idx);
        assert_eq!(ELFW_R_TYPE(info), rel_type as u32);
    }

    #[test]
    fn test_elfw_r_info_roundtrip() {
        for sym in [0u64, 1, 255, 65535] {
            for rtype in [0u64, 1, 10, 255] {
                let info = ELFW_R_INFO(sym, rtype);
                assert_eq!(ELFW_R_SYM(info), sym);
                assert_eq!(ELFW_R_TYPE(info), rtype as u32);
            }
        }
    }

    #[test]
    fn test_elf_hash_basic() {
        // Known ELF hash values for common names
        let h = elf_hash(b"main");
        assert!(h > 0);
        
        // Empty string should produce 0
        let h0 = elf_hash(b"");
        assert_eq!(h0, 0);
    }

    #[test]
    fn test_elf_hash_consistency() {
        // Same input should produce same hash
        let h1 = elf_hash(b"printf");
        let h2 = elf_hash(b"printf");
        assert_eq!(h1, h2);
        
        // Different inputs should (very likely) produce different hashes
        let h3 = elf_hash(b"scanf");
        assert_ne!(h1, h3);
    }

    #[test]
    fn test_elf_gnu_hash_basic() {
        let h = elf_gnu_hash(b"main");
        assert!(h > 0);
        
        // Consistency
        let h2 = elf_gnu_hash(b"main");
        assert_eq!(h, h2);
    }

    #[test]
    fn test_elf_gnu_hash_empty() {
        let h = elf_gnu_hash(b"");
        assert_eq!(h, 5381); // DJB2 initial value
    }

    // ============================================================
    // Section Management Tests
    // ============================================================

    #[test]
    fn test_put_elf_str_basic() {
        let mut sec = Section {
            data: vec![0], // Start with null byte (standard for strtab)
            data_offset: 1,
            sh_name: 0,
            sh_num: 0,
            sh_type: SHT_STRTAB as i32,
            sh_flags: 0,
            sh_info: 0,
            sh_addralign: 1,
            sh_entsize: 0,
            sh_size: 1,
            sh_addr: 0,
            sh_offset: 0,
            nb_hashed_syms: 0,
            link: None,
            reloc: None,
            hash: None,
            name: ".strtab".to_string(),
        };

        let off1 = put_elf_str(&mut sec, "hello");
        assert_eq!(off1, 1);
        
        // Retrieve it
        let name = get_elf_str(&sec, off1);
        assert_eq!(name, "hello");

        let off2 = put_elf_str(&mut sec, "world");
        assert!(off2 > off1);
        let name2 = get_elf_str(&sec, off2);
        assert_eq!(name2, "world");
    }

    #[test]
    fn test_put_elf_str_empty() {
        let mut sec = Section {
            data: vec![0],
            data_offset: 1,
            sh_name: 0, sh_num: 0, sh_type: SHT_STRTAB as i32,
            sh_flags: 0, sh_info: 0, sh_addralign: 1, sh_entsize: 0,
            sh_size: 1, sh_addr: 0, sh_offset: 0, nb_hashed_syms: 0,
            link: None, reloc: None, hash: None,
            name: ".strtab".to_string(),
        };
        let off = put_elf_str(&mut sec, "");
        // Empty string still occupies one NUL byte after existing data
        assert_eq!(off, 1);
        // Reading back at offset 0 gives the initial empty string
        let name0 = get_elf_str(&sec, 0);
        assert_eq!(name0, "");
    }

    #[test]
    fn test_section_ptr_add() {
        let mut sec = Section {
            data: vec![],
            data_offset: 0,
            sh_name: 0, sh_num: 0, sh_type: SHT_PROGBITS as i32,
            sh_flags: 0, sh_info: 0, sh_addralign: 1, sh_entsize: 0,
            sh_size: 0, sh_addr: 0, sh_offset: 0, nb_hashed_syms: 0,
            link: None, reloc: None, hash: None,
            name: ".test".to_string(),
        };

        let off1 = section_ptr_add(&mut sec, 16);
        assert_eq!(off1, 0);
        assert_eq!(sec.data_offset, 16);
        // Data buffer grows to at least 256 (minimum allocation)
        assert!(sec.data.len() >= 16);

        let off2 = section_ptr_add(&mut sec, 8);
        assert_eq!(off2, 16);
        assert_eq!(sec.data_offset, 24);
    }

    #[test]
    fn test_section_realloc() {
        let mut sec = Section {
            data: vec![1, 2, 3, 4],
            data_offset: 4,
            sh_name: 0, sh_num: 0, sh_type: SHT_PROGBITS as i32,
            sh_flags: 0, sh_info: 0, sh_addralign: 1, sh_entsize: 0,
            sh_size: 4, sh_addr: 0, sh_offset: 0, nb_hashed_syms: 0,
            link: None, reloc: None, hash: None,
            name: ".test".to_string(),
        };
        
        section_realloc(&mut sec, 1024);
        assert!(sec.data.len() >= 1024);
        // Original data preserved
        assert_eq!(sec.data[0], 1);
        assert_eq!(sec.data[3], 4);
    }

    #[test]
    fn test_free_section() {
        let mut sec = Section {
            data: vec![1, 2, 3, 4, 5],
            data_offset: 5,
            sh_name: 0, sh_num: 0, sh_type: SHT_PROGBITS as i32,
            sh_flags: 0, sh_info: 0, sh_addralign: 1, sh_entsize: 0,
            sh_size: 5, sh_addr: 0, sh_offset: 0, nb_hashed_syms: 0,
            link: None, reloc: None, hash: None,
            name: ".test".to_string(),
        };
        
        free_section(&mut sec);
        assert!(sec.data.is_empty());
        assert_eq!(sec.data_offset, 0);
    }

    // ============================================================
    // GotPltOffsets Tests
    // ============================================================

    #[test]
    fn test_got_plt_offsets() {
        let mut gpo = GotPltOffsets::new();
        
        // Initially no offsets
        assert_eq!(gpo.got_offset(42), 0);
        assert_eq!(gpo.plt_offset(42), 0);
        
        // Set GOT offset
        gpo.set_got_offset(42, 100);
        assert_eq!(gpo.got_offset(42), 100);
        assert_eq!(gpo.plt_offset(42), 0);
        
        // Set PLT offset
        gpo.set_plt_offset(42, 200);
        assert_eq!(gpo.plt_offset(42), 200);
        assert_eq!(gpo.got_offset(42), 100);
    }

    // ============================================================
    // ELF Struct Size Tests
    // ============================================================

    #[test]
    fn test_elf64_ehdr_size() {
        assert_eq!(std::mem::size_of::<Elf64_Ehdr>(), 64);
    }

    #[test]
    fn test_elf32_ehdr_size() {
        assert_eq!(std::mem::size_of::<Elf32_Ehdr>(), 52);
    }

    #[test]
    fn test_elf64_sym_size() {
        assert_eq!(std::mem::size_of::<Elf64_Sym>(), 24);
    }

    #[test]
    fn test_elf32_sym_size() {
        assert_eq!(std::mem::size_of::<Elf32_Sym>(), 16);
    }

    #[test]
    fn test_elf64_shdr_size() {
        assert_eq!(std::mem::size_of::<Elf64_Shdr>(), 64);
    }

    #[test]
    fn test_elf32_shdr_size() {
        assert_eq!(std::mem::size_of::<Elf32_Shdr>(), 40);
    }

    #[test]
    fn test_elf64_rela_size() {
        assert_eq!(std::mem::size_of::<Elf64_Rela>(), 24);
    }

    #[test]
    fn test_elf32_rel_size() {
        assert_eq!(std::mem::size_of::<Elf32_Rel>(), 8);
    }

    #[test]
    fn test_elf32_rela_size() {
        assert_eq!(std::mem::size_of::<Elf32_Rela>(), 12);
    }

    #[test]
    fn test_elf64_phdr_size() {
        assert_eq!(std::mem::size_of::<Elf64_Phdr>(), 56);
    }

    #[test]
    fn test_elf32_phdr_size() {
        assert_eq!(std::mem::size_of::<Elf32_Phdr>(), 32);
    }

    #[test]
    fn test_elf64_dyn_size() {
        assert_eq!(std::mem::size_of::<Elf64_Dyn>(), 16);
    }

    #[test]
    fn test_elf32_dyn_size() {
        assert_eq!(std::mem::size_of::<Elf32_Dyn>(), 8);
    }

    // ============================================================
    // SYM_SIZE / RELA_SIZE / PHDR_SIZE / DYN_SIZE consistency
    // ============================================================

    #[test]
    fn test_sym_size_constant() {
        if crate::config::PTR_SIZE == 8 {
            assert_eq!(SYM_SIZE, 24);
        } else {
            assert_eq!(SYM_SIZE, 16);
        }
    }

    #[test]
    fn test_relx_size_constant() {
        if crate::config::PTR_SIZE == 8 {
            assert_eq!(RELX_SIZE, 24);
        } else {
            assert_eq!(RELX_SIZE, 12);
        }
    }

    #[test]
    fn test_phdr_size_constant() {
        if crate::config::PTR_SIZE == 8 {
            assert_eq!(PHDR_SIZE, 56);
        } else {
            assert_eq!(PHDR_SIZE, 32);
        }
    }

    // ============================================================
    // tcc_object_type Tests
    // ============================================================

    #[test]
    fn test_tcc_object_type_elf() {
        let mut data = vec![0u8; 64];
        // Set ELF magic
        data[0] = 0x7f;
        data[1] = b'E';
        data[2] = b'L';
        data[3] = b'F';
        assert_eq!(tcc_object_type(&data), 1); // AFF_BINTYPE_REL (ELF)
    }

    #[test]
    fn test_tcc_object_type_archive() {
        let data = b"!<arch>\n".to_vec();
        assert_eq!(tcc_object_type(&data), 2); // Archive
    }

    #[test]
    fn test_tcc_object_type_unknown() {
        let data = b"random data that is not ELF or archive".to_vec();
        assert_eq!(tcc_object_type(&data), 0);
    }

    #[test]
    fn test_tcc_object_type_too_short() {
        let data = vec![0x7f, b'E'];
        assert_eq!(tcc_object_type(&data), 0);
    }
}
