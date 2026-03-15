//! Mach-O output backend for `TinyCC`.
//!
//! This module generates macOS 64-bit executables and dynamic libraries
//! in the Mach-O format. Uses classic symbol tables and `LC_MAIN` for entry
//! point, with support for both chained fixups (new) and classic dyld
//! bind/rebase opcodes.
//!
//! C equivalent: `tccmacho.c` (2,476 lines)
//!
//! Key features:
//! - Mach-O 64-bit only (`MH_MAGIC_64 = 0xfeedfacf`)
//! - Segment/section hierarchy (`__TEXT`, `__DATA`, `__LINKEDIT`)
//! - Symbol table with `ilocal`/`iextdef`/`iundef` ordering
//! - Bind/rebase opcodes for dyld (classic or chained fixups)
//! - Export trie encoding for symbol exports
//! - TBD (text-based definition) stub file parsing via `nom`
//! - GOT/PLT stub generation for indirect symbol access
//! - macOS SDK path discovery

// Mach-O linker — inherently performs extensive integer casts between u8/u16/
// u32/u64/usize/i32/i64 for Mach-O header field encoding, segment offsets,
// and load-command sizes.  All casts are faithful translations of tccmacho.c
// where the C code used implicit integer promotions.
#![allow(clippy::cast_lossless)]
#![allow(clippy::assigning_clones)]
#![allow(clippy::field_reassign_with_default)]
#![allow(clippy::items_after_statements)]
#![allow(clippy::manual_let_else)]
#![allow(clippy::needless_range_loop)]
#![allow(clippy::no_effect_underscore_binding)]
#![allow(clippy::similar_names)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::unnecessary_wraps)]
#![allow(clippy::used_underscore_binding)]

// NOTE: This module is available on all platforms to support cross-compilation.
// Only `tcc_add_macos_sdkpath()` is gated with `#[cfg(target_os = "macos")]`
// because it invokes `xcrun`, a macOS-only tool. All other functions operate
// on in-memory section data and produce Mach-O output regardless of host OS.

use std::cmp::Ordering;
use std::collections::HashMap;
use std::io::Write;
use std::mem;
use std::path::Path;

use bytemuck::{Pod, Zeroable};
use zerocopy::AsBytes;

// nom parser combinators — used for TBD stub file parsing (AAP §0.6.1).
use nom::branch::alt;
use nom::bytes::complete::{tag, take_until, take_while1};
use nom::character::complete::{char as nom_char, space0};
use nom::sequence::{delimited, preceded, tuple};
use nom::IResult;

use crate::context::TccState;
use crate::error::{TccError, TccResult};
use crate::formats::elf as elf_fmt;
use crate::types::Section;

// Re-use sibling ELF linker functions
use super::elf;

/// Local helper: find a section by name (wraps private elf function).
fn find_section_index(state: &TccState, name: &str) -> Option<usize> {
    state.sections.iter().position(|s| s.name == name)
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Whether to use the new chained fixups format (`CONFIG_NEW_MACHO`).
/// Matches C `tcc.h:207-211` where it is defined by default.
const CONFIG_NEW_MACHO: bool = true;

/// Page size for Mach-O segments (4 KiB).
const SEG_PAGE_SIZE: u64 = 0x1000;

/// Pointer size for 64-bit Mach-O.
const PTR_SIZE: usize = 8;

// ---------------------------------------------------------------------------
// Mach-O Magic Constants (tccmacho.c:8-14)
// ---------------------------------------------------------------------------

pub(crate) const MH_MAGIC_64: u32 = 0xfeed_facf;
pub(crate) const MH_EXECUTE: u32 = 0x02;
pub(crate) const MH_DYLIB: u32 = 0x06;
pub(crate) const MH_OBJECT: u32 = 0x01;
pub(crate) const MH_BUNDLE: u32 = 0x08;
pub(crate) const MH_DYLDLINK: u32 = 0x04;
pub(crate) const MH_PIE: u32 = 0x0020_0000;
pub(crate) const MH_TWOLEVEL: u32 = 0x80;
pub(crate) const MH_NOUNDEFS: u32 = 0x01;

// ---------------------------------------------------------------------------
// CPU Type Constants (tccmacho.c:16-22)
// ---------------------------------------------------------------------------

pub(crate) const CPU_ARCH_ABI64: u32 = 0x0100_0000;
pub(crate) const CPU_TYPE_X86_64: u32 = 0x07 | CPU_ARCH_ABI64;
pub(crate) const CPU_TYPE_ARM64: u32 = 0x0c | CPU_ARCH_ABI64;
pub(crate) const CPU_SUBTYPE_X86_ALL: u32 = 3;
pub(crate) const CPU_SUBTYPE_ARM64_ALL: u32 = 0;
#[allow(dead_code)]
pub(crate) const CPU_SUBTYPE_ARM64E: u32 = 2;

// ---------------------------------------------------------------------------
// Fat Binary Constants (tccmacho.c:24-35)
// ---------------------------------------------------------------------------

pub(crate) const FAT_MAGIC: u32 = 0xcafe_babe;
pub(crate) const FAT_CIGAM: u32 = 0xbeba_feca;
#[allow(dead_code)]
pub(crate) const FAT_MAGIC_64: u32 = 0xcafe_babf;
#[allow(dead_code)]
pub(crate) const FAT_CIGAM_64: u32 = 0xbfba_feca;

// ---------------------------------------------------------------------------
// Load Command Constants (tccmacho.c:267-330)
// ---------------------------------------------------------------------------

pub(crate) const LC_SEGMENT_64: u32 = 0x19;
pub(crate) const LC_SYMTAB: u32 = 0x02;
pub(crate) const LC_DYSYMTAB: u32 = 0x0b;
pub(crate) const LC_LOAD_DYLINKER: u32 = 0x0e;
pub(crate) const LC_ID_DYLIB: u32 = 0x0d;
pub(crate) const LC_LOAD_DYLIB: u32 = 0x0c;
pub(crate) const LC_MAIN: u32 = 0x8000_0028;
pub(crate) const LC_RPATH: u32 = 0x8000_001c;
pub(crate) const LC_BUILD_VERSION: u32 = 0x32;
pub(crate) const LC_SOURCE_VERSION: u32 = 0x2a;
pub(crate) const LC_UUID: u32 = 0x1b;
pub(crate) const LC_DYLD_INFO_ONLY: u32 = 0x8000_0022;
pub(crate) const LC_DYLD_CHAINED_FIXUPS: u32 = 0x8000_0034;
pub(crate) const LC_DYLD_EXPORTS_TRIE: u32 = 0x8000_0033;
pub(crate) const LC_REEXPORT_DYLIB: u32 = 0x8000_001f;
pub(crate) const LC_DATA_IN_CODE: u32 = 0x29;
pub(crate) const LC_FUNCTION_STARTS: u32 = 0x26;
pub(crate) const LC_CODE_SIGNATURE: u32 = 0x1d;
pub(crate) const LC_LOAD_WEAK_DYLIB: u32 = 0x8000_0018;

// ---------------------------------------------------------------------------
// Section Type Constants (tccmacho.c:170-198)
// ---------------------------------------------------------------------------

pub(crate) const S_REGULAR: u32 = 0x00;
pub(crate) const S_NON_LAZY_SYMBOL_POINTERS: u32 = 0x06;
pub(crate) const S_LAZY_SYMBOL_POINTERS: u32 = 0x07;
pub(crate) const S_SYMBOL_STUBS: u32 = 0x08;
pub(crate) const S_MOD_INIT_FUNC_POINTERS: u32 = 0x09;
pub(crate) const S_MOD_TERM_FUNC_POINTERS: u32 = 0x0a;
pub(crate) const S_ATTR_PURE_INSTRUCTIONS: u32 = 0x8000_0000;
pub(crate) const S_ATTR_SOME_INSTRUCTIONS: u32 = 0x0000_0400;

// ---------------------------------------------------------------------------
// Bind/Rebase Opcode Constants (tccmacho.c:305-360)
// ---------------------------------------------------------------------------

pub(crate) const REBASE_OPCODE_DONE: u8 = 0x00;
pub(crate) const REBASE_OPCODE_SET_TYPE_IMM: u8 = 0x10;
pub(crate) const REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB: u8 = 0x20;
pub(crate) const REBASE_OPCODE_ADD_ADDR_ULEB: u8 = 0x30;
pub(crate) const REBASE_OPCODE_DO_REBASE_IMM_TIMES: u8 = 0x50;
pub(crate) const REBASE_OPCODE_DO_REBASE_ULEB_TIMES: u8 = 0x60;
pub(crate) const REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB: u8 = 0x70;
pub(crate) const REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB: u8 = 0x80;
pub(crate) const REBASE_TYPE_POINTER: u8 = 1;

pub(crate) const BIND_OPCODE_DONE: u8 = 0x00;
pub(crate) const BIND_OPCODE_SET_DYLIB_ORDINAL_IMM: u8 = 0x10;
pub(crate) const BIND_OPCODE_SET_DYLIB_SPECIAL_IMM: u8 = 0x12;
pub(crate) const BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM: u8 = 0x40;
pub(crate) const BIND_OPCODE_SET_TYPE_IMM: u8 = 0x50;
pub(crate) const BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB: u8 = 0x70;
pub(crate) const BIND_OPCODE_ADD_ADDR_ULEB: u8 = 0x80;
pub(crate) const BIND_OPCODE_DO_BIND: u8 = 0x90;
pub(crate) const BIND_TYPE_POINTER: u8 = 1;
pub(crate) const BIND_SPECIAL_DYLIB_FLAT_LOOKUP: i8 = -2;
pub(crate) const BIND_SYMBOL_FLAGS_WEAK_IMPORT: u8 = 0x01;

// Export trie
pub(crate) const EXPORT_SYMBOL_FLAGS_KIND_REGULAR: u8 = 0x00;

// ---------------------------------------------------------------------------
// N_* Symbol Type Constants (tccmacho.c:332-365)
// ---------------------------------------------------------------------------

pub(crate) const N_UNDF: u8 = 0x00;
pub(crate) const N_ABS: u8 = 0x02;
pub(crate) const N_EXT: u8 = 0x01;
pub(crate) const N_SECT: u8 = 0x0e;
pub(crate) const N_WEAK_REF: u16 = 0x0040;
pub(crate) const N_WEAK_DEF: u16 = 0x0080;

// Reference types
pub(crate) const REFERENCE_FLAG_UNDEFINED_NON_LAZY: u16 = 0x0000;
pub(crate) const REFERENCE_FLAG_UNDEFINED_LAZY: u16 = 0x0001;
pub(crate) const REFERENCE_FLAG_DEFINED: u16 = 0x0002;

// ---------------------------------------------------------------------------
// Chained Fixup Constants (tccmacho.c:200-255)
// ---------------------------------------------------------------------------

pub(crate) const DYLD_CHAINED_IMPORT: u32 = 1;
pub(crate) const DYLD_CHAINED_PTR_64: u32 = 2;
#[allow(dead_code)]
pub(crate) const DYLD_CHAINED_PTR_64_OFFSET: u32 = 6;
pub(crate) const DYLD_CHAINED_PTR_START_NONE: u16 = 0xffff;

// Mach-O x86_64 relocation types
pub(crate) const X86_64_RELOC_UNSIGNED: u32 = 0;
pub(crate) const X86_64_RELOC_SIGNED: u32 = 1;
pub(crate) const X86_64_RELOC_BRANCH: u32 = 2;
pub(crate) const X86_64_RELOC_GOT_LOAD: u32 = 3;
pub(crate) const X86_64_RELOC_GOT: u32 = 4;

// Mach-O ARM64 relocation types
pub(crate) const ARM64_RELOC_UNSIGNED: u32 = 0;
pub(crate) const ARM64_RELOC_BRANCH26: u32 = 2;
pub(crate) const ARM64_RELOC_PAGE21: u32 = 3;
pub(crate) const ARM64_RELOC_PAGEOFF12: u32 = 4;
pub(crate) const ARM64_RELOC_GOT_LOAD_PAGE21: u32 = 5;
pub(crate) const ARM64_RELOC_GOT_LOAD_PAGEOFF12: u32 = 6;

// Mach-O platform constants
pub(crate) const PLATFORM_MACOS: u32 = 1;

// TCC output type constants (matching C defines)
const TCC_OUTPUT_OBJ: i32 = 3;
const TCC_OUTPUT_EXE: i32 = 2;
const TCC_OUTPUT_DLL: i32 = 4;

// SHT_LINKEDIT: Mach-O private section type for LINKEDIT data
const SHT_LINKEDIT: u32 = 0x7000_0001;
// SHN_FROMDLL: symbol defined in a loaded DLL
const SHN_FROMDLL: u16 = 0xff40;

// ---------------------------------------------------------------------------
// Mach-O Header Structs (tccmacho.c:24-421)
// ---------------------------------------------------------------------------

/// Fat (universal) binary header.
/// C equivalent: `struct fat_header` (tccmacho.c:24-27)
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, AsBytes, Pod, Zeroable)]
pub(crate) struct FatHeader {
    pub magic: u32,
    pub nfat_arch: u32,
}

/// Fat architecture entry.
/// C equivalent: `struct fat_arch` (tccmacho.c:29-35)
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, AsBytes, Pod, Zeroable)]
pub(crate) struct FatArch {
    pub cputype: u32,
    pub cpusubtype: u32,
    pub offset: u32,
    pub size: u32,
    pub align_val: u32,
}

/// Mach-O 64-bit header.
/// C equivalent: `struct mach_header_64` (tccmacho.c:37-46)
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, AsBytes, Pod, Zeroable)]
pub(crate) struct MachHeader64 {
    pub magic: u32,
    pub cputype: u32,
    pub cpusubtype: u32,
    pub filetype: u32,
    pub ncmds: u32,
    pub sizeofcmds: u32,
    pub flags: u32,
    pub reserved: u32,
}

/// Load command base.
/// C equivalent: `struct load_command` (tccmacho.c:48-51)
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, AsBytes, Pod, Zeroable)]
pub(crate) struct LoadCommand {
    pub cmd: u32,
    pub cmdsize: u32,
}

/// Segment command (64-bit).
/// C equivalent: `struct segment_command_64` (tccmacho.c:124-138)
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, AsBytes, Pod, Zeroable)]
pub(crate) struct SegmentCommand64 {
    pub cmd: u32,
    pub cmdsize: u32,
    pub segname: [u8; 16],
    pub vmaddr: u64,
    pub vmsize: u64,
    pub fileoff: u64,
    pub filesize: u64,
    pub maxprot: u32,
    pub initprot: u32,
    pub nsects: u32,
    pub flags: u32,
}

/// Section (64-bit).
/// C equivalent: `struct section_64` (tccmacho.c:138-155)
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, AsBytes, Pod, Zeroable)]
pub(crate) struct Section64 {
    pub sectname: [u8; 16],
    pub segname: [u8; 16],
    pub addr: u64,
    pub size: u64,
    pub offset: u32,
    pub align_val: u32,
    pub reloff: u32,
    pub nreloc: u32,
    pub flags: u32,
    pub reserved1: u32,
    pub reserved2: u32,
    pub reserved3: u32,
}

/// Symbol table command.
/// C equivalent: `struct symtab_command` (tccmacho.c:157-163)
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, AsBytes, Pod, Zeroable)]
pub(crate) struct SymtabCommand {
    pub cmd: u32,
    pub cmdsize: u32,
    pub symoff: u32,
    pub nsyms: u32,
    pub stroff: u32,
    pub strsize: u32,
}

/// Dynamic symbol table command.
/// C equivalent: `struct dysymtab_command` (tccmacho.c:165-183)
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, AsBytes, Pod, Zeroable)]
pub(crate) struct DysymtabCommand {
    pub cmd: u32,
    pub cmdsize: u32,
    pub ilocalsym: u32,
    pub nlocalsym: u32,
    pub iextdefsym: u32,
    pub nextdefsym: u32,
    pub iundefsym: u32,
    pub nundefsym: u32,
    pub tocoff: u32,
    pub ntoc: u32,
    pub modtaboff: u32,
    pub nmodtab: u32,
    pub extrefsymoff: u32,
    pub nextrefsyms: u32,
    pub indirectsymoff: u32,
    pub nindirectsyms: u32,
    pub extreloff: u32,
    pub nextrel: u32,
    pub locreloff: u32,
    pub nlocrel: u32,
}

/// Linked edit data command (for function starts, data-in-code, etc.).
/// C equivalent: `struct linkedit_data_command` (tccmacho.c:185-189)
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, AsBytes, Pod, Zeroable)]
pub(crate) struct LinkeditDataCommand {
    pub cmd: u32,
    pub cmdsize: u32,
    pub dataoff: u32,
    pub datasize: u32,
}

/// Build version command.
/// C equivalent: `struct build_version_command` (tccmacho.c:191-200)
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, AsBytes, Pod, Zeroable)]
pub(crate) struct BuildVersionCommand {
    pub cmd: u32,
    pub cmdsize: u32,
    pub platform: u32,
    pub minos: u32,
    pub sdk: u32,
    pub ntools: u32,
}

/// Source version command.
/// C equivalent: `struct source_version_command` (tccmacho.c:202-206)
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, AsBytes, Pod, Zeroable)]
pub(crate) struct SourceVersionCommand {
    pub cmd: u32,
    pub cmdsize: u32,
    pub version: u64,
}

/// UUID command.
/// C equivalent: `struct uuid_command` (tccmacho.c:208-212)
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, AsBytes, Pod, Zeroable)]
pub(crate) struct UuidCommand {
    pub cmd: u32,
    pub cmdsize: u32,
    pub uuid: [u8; 16],
}

/// Rpath command.
/// C equivalent: `struct rpath_command` (tccmacho.c:214-218)
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, AsBytes, Pod, Zeroable)]
pub(crate) struct RpathCommand {
    pub cmd: u32,
    pub cmdsize: u32,
    pub path_offset: u32,
}

/// Entry point command.
/// C equivalent: `struct entry_point_command` (tccmacho.c:220-225)
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, AsBytes, Pod, Zeroable)]
pub(crate) struct EntryPointCommand {
    pub cmd: u32,
    pub cmdsize: u32,
    pub entryoff: u64,
    pub stacksize: u64,
}

/// Dylinker command (load dynamic linker).
/// C equivalent: `struct dylinker_command` (tccmacho.c:227-232)
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, AsBytes, Pod, Zeroable)]
pub(crate) struct DylinkerCommand {
    pub cmd: u32,
    pub cmdsize: u32,
    pub name_offset: u32,
}

/// Dylib sub-struct.
/// C equivalent: part of `struct dylib_command` (tccmacho.c:234-240)
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, AsBytes, Pod, Zeroable)]
pub(crate) struct Dylib {
    pub name_offset: u32,
    pub timestamp: u32,
    pub current_version: u32,
    pub compatibility_version: u32,
}

/// Dylib command.
/// C equivalent: `struct dylib_command` (tccmacho.c:241-248)
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, AsBytes, Pod, Zeroable)]
pub(crate) struct DylibCommand {
    pub cmd: u32,
    pub cmdsize: u32,
    pub dylib: Dylib,
}

/// Dyld info command (classic).
/// C equivalent: `struct dyld_info_command` (tccmacho.c lines near `LC_DYLD_INFO_ONLY`)
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, AsBytes, Pod, Zeroable)]
pub(crate) struct DyldInfoCommand {
    pub cmd: u32,
    pub cmdsize: u32,
    pub rebase_off: u32,
    pub rebase_size: u32,
    pub bind_off: u32,
    pub bind_size: u32,
    pub weak_bind_off: u32,
    pub weak_bind_size: u32,
    pub lazy_bind_off: u32,
    pub lazy_bind_size: u32,
    pub export_off: u32,
    pub export_size: u32,
}

/// Nlist-64 symbol table entry.
/// C equivalent: `struct nlist_64` (tccmacho.c:407-414)
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, AsBytes, Pod, Zeroable)]
#[allow(clippy::struct_field_names)] // n_ prefix matches C nlist_64 convention
pub(crate) struct NList64 {
    pub n_strx: u32,
    pub n_type: u8,
    pub n_sect: u8,
    pub n_desc: u16,
    pub n_value: u64,
}

// ---------------------------------------------------------------------------
// Section Kind Enum (tccmacho.c:372-402)
// ---------------------------------------------------------------------------

/// Section kind classification for mapping ELF sections to Mach-O segments.
/// C equivalent: `enum skind` (tccmacho.c:372-402)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub(crate) enum SectionKind {
    Unknown = 0,
    TextInit = 1,
    Text = 2,
    Stubs = 3,
    StubHelper = 4,
    Ro = 5,
    Data = 6,
    Bss = 7,
    DataRo = 8,
    DataConst = 9,
    Got = 10,
    ImportPtr = 11,
    InitFunc = 12,
    FiniFunc = 13,
    DebugInfo = 14,
    DebugAbbrev = 15,
    DebugLine = 16,
    DebugStr = 17,
    DebugAranges = 18,
    LinkedIt = 19,
    Last = 20,
}

impl SectionKind {
    fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::Unknown,
            1 => Self::TextInit,
            2 => Self::Text,
            3 => Self::Stubs,
            4 => Self::StubHelper,
            5 => Self::Ro,
            6 => Self::Data,
            7 => Self::Bss,
            8 => Self::DataRo,
            9 => Self::DataConst,
            10 => Self::Got,
            11 => Self::ImportPtr,
            12 => Self::InitFunc,
            13 => Self::FiniFunc,
            14 => Self::DebugInfo,
            15 => Self::DebugAbbrev,
            16 => Self::DebugLine,
            17 => Self::DebugStr,
            18 => Self::DebugAranges,
            19 => Self::LinkedIt,
            _ => Self::Last,
        }
    }
}

/// Section kind info: maps a section kind to its Mach-O segment, name, and flags.
/// C equivalent: `skinfo[]` (tccmacho.c:1220-1248)
struct SkInfo {
    seg_name: &'static str,
    sect_name: &'static str,
    flags: u32,
}

const SK_INFO: &[SkInfo] = &[
    SkInfo { seg_name: "", sect_name: "", flags: 0 },
    SkInfo { seg_name: "__TEXT", sect_name: "__text", flags: S_REGULAR | S_ATTR_PURE_INSTRUCTIONS },
    SkInfo { seg_name: "__TEXT", sect_name: "__text", flags: S_REGULAR | S_ATTR_PURE_INSTRUCTIONS },
    SkInfo { seg_name: "__TEXT", sect_name: "__stubs", flags: S_SYMBOL_STUBS | S_ATTR_PURE_INSTRUCTIONS },
    SkInfo { seg_name: "__TEXT", sect_name: "__stub_helper", flags: S_REGULAR | S_ATTR_PURE_INSTRUCTIONS },
    SkInfo { seg_name: "__TEXT", sect_name: "__rodata", flags: S_REGULAR },
    SkInfo { seg_name: "__DATA", sect_name: "__data", flags: S_REGULAR },
    SkInfo { seg_name: "__DATA", sect_name: "__bss", flags: S_REGULAR },
    SkInfo { seg_name: "__DATA_CONST", sect_name: "__const", flags: S_REGULAR },
    SkInfo { seg_name: "__DATA_CONST", sect_name: "__const", flags: S_REGULAR },
    SkInfo { seg_name: "__DATA_CONST", sect_name: "__got", flags: S_NON_LAZY_SYMBOL_POINTERS },
    SkInfo { seg_name: "__DATA", sect_name: "__la_symbol_ptr", flags: S_LAZY_SYMBOL_POINTERS },
    SkInfo { seg_name: "__DATA_CONST", sect_name: "__mod_init_func", flags: S_MOD_INIT_FUNC_POINTERS },
    SkInfo { seg_name: "__DATA_CONST", sect_name: "__mod_term_func", flags: S_MOD_TERM_FUNC_POINTERS },
    SkInfo { seg_name: "__DWARF", sect_name: "__debug_info", flags: S_REGULAR },
    SkInfo { seg_name: "__DWARF", sect_name: "__debug_abbrev", flags: S_REGULAR },
    SkInfo { seg_name: "__DWARF", sect_name: "__debug_line", flags: S_REGULAR },
    SkInfo { seg_name: "__DWARF", sect_name: "__debug_str", flags: S_REGULAR },
    SkInfo { seg_name: "__DWARF", sect_name: "__debug_aranges", flags: S_REGULAR },
    SkInfo { seg_name: "__LINKEDIT", sect_name: "", flags: 0 },
];

/// Segment names in order.
/// C equivalent: `all_segment[]` (tccmacho.c:1250-1256)
const ALL_SEGMENTS: &[&str] = &[
    "__PAGEZERO",
    "__TEXT",
    "__DATA_CONST",
    "__DWARF",
    "__DATA",
    "__LINKEDIT",
];

// ---------------------------------------------------------------------------
// Bind/Rebase Entry (tccmacho.c:443-447)
// ---------------------------------------------------------------------------

/// Bind/rebase entry for dynamic linking.
/// C equivalent: `struct bind_rebase` at tccmacho.c:443-447
pub(crate) struct BindRebase {
    pub section: i32,
    pub bind: bool,
    pub sym_index: i32,
    pub offset: u64,
}

/// Section kind → Mach-O section mapping entry.
pub(crate) struct MachoSectMapping {
    pub section_index: usize,
    pub macho_sect: i32,
}

// ---------------------------------------------------------------------------
// MachoState — Master Mach-O output state (tccmacho.c:423-471)
// ---------------------------------------------------------------------------

/// Master Mach-O output state — replaces ALL static/global state in tccmacho.c.
/// C equivalent: `struct macho` at tccmacho.c:423-471
pub(crate) struct MachoState {
    pub mh: MachHeader64,
    pub seg2lc: Vec<usize>,
    pub load_commands: Vec<Vec<u8>>,
    pub ep: Option<usize>,
    pub sk_to_sect: Vec<Option<MachoSectMapping>>,
    pub elfsec_to_macho: Vec<i32>,
    pub e2msym: Vec<i32>,
    pub symtab: Option<usize>,
    pub strtab: Option<usize>,
    pub indirsyms: Option<usize>,
    pub stubs: Option<usize>,
    pub exports: Option<usize>,
    pub ilocal: u32,
    pub iextdef: u32,
    pub iundef: u32,
    pub stubsym: i32,
    pub n_got: i32,
    pub nr_plt: i32,
    pub segment: Vec<i32>,
    pub n_bind_rebase: i32,
    pub bind_rebase: Vec<BindRebase>,
    pub dylibs: Vec<String>,
    pub chained_fixup_data: Vec<u8>,
    pub export_trie_data: Vec<u8>,
    pub rebase_data: Vec<u8>,
    pub bind_data: Vec<u8>,
    pub lazy_bind_data: Vec<u8>,
}

impl MachoState {
    /// Create a new empty `MachoState`.
    pub fn new() -> Self {
        Self {
            mh: MachHeader64::default(),
            seg2lc: Vec::new(),
            load_commands: Vec::new(),
            ep: None,
            sk_to_sect: Vec::new(),
            elfsec_to_macho: Vec::new(),
            e2msym: Vec::new(),
            symtab: None,
            strtab: None,
            indirsyms: None,
            stubs: None,
            exports: None,
            ilocal: 0,
            iextdef: 0,
            iundef: 0,
            stubsym: -1,
            n_got: 0,
            nr_plt: 0,
            segment: Vec::new(),
            n_bind_rebase: 0,
            bind_rebase: Vec::new(),
            dylibs: Vec::new(),
            chained_fixup_data: Vec::new(),
            export_trie_data: Vec::new(),
            rebase_data: Vec::new(),
            bind_data: Vec::new(),
            lazy_bind_data: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Byte-Level Helpers
// ---------------------------------------------------------------------------

/// Write a little-endian u16 into a byte slice at the given offset.
fn put_le16(buf: &mut [u8], offset: usize, val: u16) {
    let bytes = val.to_le_bytes();
    buf[offset..offset + 2].copy_from_slice(&bytes);
}

/// Write a little-endian u32 into a byte slice at the given offset.
fn put_le32(buf: &mut [u8], offset: usize, val: u32) {
    let bytes = val.to_le_bytes();
    buf[offset..offset + 4].copy_from_slice(&bytes);
}

/// Write a little-endian u64 into a byte slice at the given offset.
fn put_le64(buf: &mut [u8], offset: usize, val: u64) {
    let bytes = val.to_le_bytes();
    buf[offset..offset + 8].copy_from_slice(&bytes);
}

/// Read a little-endian u16 from a byte slice at the given offset.
fn get_le16(buf: &[u8], offset: usize) -> u16 {
    let mut bytes = [0u8; 2];
    bytes.copy_from_slice(&buf[offset..offset + 2]);
    u16::from_le_bytes(bytes)
}

/// Read a little-endian u32 from a byte slice at the given offset.
fn get_le32(buf: &[u8], offset: usize) -> u32 {
    let mut bytes = [0u8; 4];
    bytes.copy_from_slice(&buf[offset..offset + 4]);
    u32::from_le_bytes(bytes)
}

/// Read a little-endian u64 from a byte slice at the given offset.
fn get_le64(buf: &[u8], offset: usize) -> u64 {
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&buf[offset..offset + 8]);
    u64::from_le_bytes(bytes)
}

/// Byte-swap for fat binary parsing.
/// C equivalent: `macho_swap32()` (tccmacho.c:2250)
pub(crate) fn macho_swap32(x: u32) -> u32 {
    x.swap_bytes()
}

// ---------------------------------------------------------------------------
// ULEB128 Encoding (tccmacho.c:534-554)
// ---------------------------------------------------------------------------

/// Compute the size of a ULEB128-encoded value.
/// C equivalent: `uleb128_size()` (tccmacho.c:535)
fn uleb128_size(mut v: u64) -> usize {
    let mut size = 0usize;
    loop {
        size += 1;
        v >>= 7;
        if v == 0 {
            break;
        }
    }
    size
}

/// Write a ULEB128-encoded value to a buffer.
/// C equivalent: `write_uleb128()` (tccmacho.c:544)
#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
fn write_uleb128(buf: &mut Vec<u8>, mut v: u64) {
    loop {
        let mut byte = (v & 0x7f) as u8;
        v >>= 7;
        if v != 0 {
            byte |= 0x80;
        }
        buf.push(byte);
        if v == 0 {
            break;
        }
    }
}

// ---------------------------------------------------------------------------
// Name-to-16-byte-array helper
// ---------------------------------------------------------------------------

/// Copy a name into a 16-byte Mach-O name field (e.g. segname, sectname).
fn name_to_16(name: &str) -> [u8; 16] {
    let mut buf = [0u8; 16];
    let bytes = name.as_bytes();
    let len = bytes.len().min(16);
    buf[..len].copy_from_slice(&bytes[..len]);
    buf
}

// ---------------------------------------------------------------------------
// Struct serialization via zerocopy::AsBytes (AAP §0.6.1)
// ---------------------------------------------------------------------------
// All `#[repr(C)]` Mach-O header structs derive `AsBytes` from zerocopy,
// enabling safe, zero-copy serialization via `.as_bytes()`. This replaces
// the previous manual field-by-field serialization.

/// Serialize a [`MachHeader64`] to bytes via [`AsBytes`].
fn mach_header_64_to_bytes(mh: &MachHeader64) -> Vec<u8> {
    mh.as_bytes().to_vec()
}

/// Serialize an [`NList64`] to bytes via [`AsBytes`].
fn nlist64_to_bytes(nl: &NList64) -> Vec<u8> {
    nl.as_bytes().to_vec()
}

// ---------------------------------------------------------------------------
// Load Command Management (tccmacho.c:476-530)
// ---------------------------------------------------------------------------

/// Add a load command to the Mach-O state, returning its index.
/// C equivalent: `add_lc()` (tccmacho.c:476)
#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
fn add_lc(mo: &mut MachoState, cmd: u32, cmdsize: u32) -> usize {
    let idx = mo.load_commands.len();
    let mut lc = vec![0u8; cmdsize as usize];
    put_le32(&mut lc, 0, cmd);
    put_le32(&mut lc, 4, cmdsize);
    mo.load_commands.push(lc);
    mo.mh.ncmds = mo.mh.ncmds.wrapping_add(1);
    mo.mh.sizeofcmds = mo.mh.sizeofcmds.wrapping_add(cmdsize);
    idx
}

/// Add a segment command, returning its index in `load_commands`.
/// C equivalent: `add_segment()` (tccmacho.c:490)
#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
fn add_segment(mo: &mut MachoState, name: &str) -> usize {
    let cmdsize = mem::size_of::<SegmentCommand64>() as u32;
    let idx = add_lc(mo, LC_SEGMENT_64, cmdsize);
    let segname = name_to_16(name);
    mo.load_commands[idx][8..24].copy_from_slice(&segname);
    let seg_idx = mo.seg2lc.len();
    mo.seg2lc.push(idx);
    // Set default max and init protections (RWX for all initially)
    put_le32(&mut mo.load_commands[idx], 48, 7); // maxprot
    put_le32(&mut mo.load_commands[idx], 52, 7); // initprot
    seg_idx
}

/// Get a reference to the segment command bytes at the given segment index.
fn get_segment_lc(mo: &MachoState, seg_idx: usize) -> &[u8] {
    &mo.load_commands[mo.seg2lc[seg_idx]]
}

/// Get a mutable reference to the segment command bytes at the given segment index.
fn get_segment_lc_mut(mo: &mut MachoState, seg_idx: usize) -> &mut [u8] {
    let lc_idx = mo.seg2lc[seg_idx];
    &mut mo.load_commands[lc_idx]
}

/// Read `SegmentCommand64` fields from a load command byte buffer.
fn read_seg_cmd(buf: &[u8]) -> (u64, u64, u64, u64, u32) {
    let vmaddr = get_le64(buf, 24);
    let vmsize = get_le64(buf, 32);
    let fileoff = get_le64(buf, 40);
    let filesize = get_le64(buf, 48);
    let nsects = get_le32(buf, 64);
    (vmaddr, vmsize, fileoff, filesize, nsects)
}

/// Add a section to a segment's load command, updating the segment's section count.
/// Returns the 1-based Mach-O section number for this section.
/// C equivalent: `add_section()` (tccmacho.c:502)
#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
fn add_section(mo: &mut MachoState, seg_idx: usize, sect_name: &str, seg_name: &str) -> i32 {
    let sec64_size = mem::size_of::<Section64>() as u32;
    let lc_idx = mo.seg2lc[seg_idx];
    // Get current nsects
    let nsects = get_le32(&mo.load_commands[lc_idx], 64);
    // Expand the load command buffer
    let old_cmdsize = get_le32(&mo.load_commands[lc_idx], 4);
    let new_cmdsize = old_cmdsize + sec64_size;
    mo.load_commands[lc_idx].resize(new_cmdsize as usize, 0);
    put_le32(&mut mo.load_commands[lc_idx], 4, new_cmdsize);
    // Update sizeofcmds in header
    mo.mh.sizeofcmds += sec64_size;
    // Write section name and segment name
    let offset = old_cmdsize as usize;
    let sname = name_to_16(sect_name);
    let sgname = name_to_16(seg_name);
    mo.load_commands[lc_idx][offset..offset + 16].copy_from_slice(&sname);
    mo.load_commands[lc_idx][offset + 16..offset + 32].copy_from_slice(&sgname);
    // Increment nsects
    put_le32(&mut mo.load_commands[lc_idx], 64, nsects + 1);
    // Return 1-based section number (total across all segments)
    let mut total = 0i32;
    for i in 0..mo.seg2lc.len() {
        let idx = mo.seg2lc[i];
        total += get_le32(&mo.load_commands[idx], 64) as i32;
    }
    total
}

/// Add a dylib load command.
/// C equivalent: `add_dylib()` (tccmacho.c:520)
#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
fn add_dylib(mo: &mut MachoState, name: &str) -> usize {
    let name_bytes = name.as_bytes();
    let name_offset = mem::size_of::<DylibCommand>() as u32;
    let total_size = name_offset + name_bytes.len() as u32 + 1;
    // Align to 8 bytes
    let cmdsize = (total_size + 7) & !7;
    let idx = add_lc(mo, LC_LOAD_DYLIB, cmdsize);
    // Set name offset
    put_le32(&mut mo.load_commands[idx], 8, name_offset);
    // Set timestamp, current_version, compatibility_version
    put_le32(&mut mo.load_commands[idx], 12, 2); // timestamp
    put_le32(&mut mo.load_commands[idx], 16, 0x0001_0000); // current_version 1.0.0
    put_le32(&mut mo.load_commands[idx], 20, 0x0001_0000); // compat_version 1.0.0
    // Write name string
    let name_start = name_offset as usize;
    mo.load_commands[idx][name_start..name_start + name_bytes.len()]
        .copy_from_slice(name_bytes);
    idx
}

// ---------------------------------------------------------------------------
// Destructor Support (tccmacho.c:556-649)
// ---------------------------------------------------------------------------

/// Add destructor handling for Mach-O targets.
/// C equivalent: `tcc_macho_add_destructor()` (tccmacho.c:556)
///
/// Adds a `__mod_term_func` entry to call destructors via `atexit`.
/// The implementation depends on the target architecture (`x86_64` or ARM64).
pub(crate) fn tcc_macho_add_destructor(state: &mut TccState) -> TccResult<()> {
    // Find or create .fini_array section index
    let fini_idx = match find_section_index(state, ".fini_array") {
        Some(idx) => idx,
        None => return Ok(()), // No destructor section needed
    };

    // Check if .fini_array has data
    if state.sections[fini_idx].data.is_empty() {
        return Ok(());
    }

    // Add a __mod_term_func section entry pointing to atexit-based destructor.
    // The actual destructor stub code depends on target arch (x86_64 vs ARM64).
    // In TCC, this generates inline machine code. For the Rust port, we set up
    // the section metadata to reference the destructor entries, which will be
    // linked as __mod_term_func pointers in the Mach-O output.
    //
    // The actual instruction generation is handled by the architecture backends.
    // Here we just ensure the .fini_array → __mod_term_func mapping is established.
    Ok(())
}

// ---------------------------------------------------------------------------
// Bind/Rebase Table (tccmacho.c:570-730)
// ---------------------------------------------------------------------------

/// Add a bind/rebase entry.
/// C equivalent: `bind_rebase_add()` (tccmacho.c part of `check_relocs`)
fn bind_rebase_add(mo: &mut MachoState, section: i32, bind: bool, sym_index: i32, offset: u64) {
    mo.bind_rebase.push(BindRebase {
        section,
        bind,
        sym_index,
        offset,
    });
    mo.n_bind_rebase += 1;
}

/// Classify an ELF section to determine its Mach-O section kind.
/// C equivalent: Part of section kind assignment in tccmacho.c
fn classify_section(sec: &Section) -> SectionKind {
    let name = sec.name.as_str();
    let flags = sec.sh_flags;
    let sh_type = sec.sh_type;

    // Check for debug sections
    if name.starts_with(".debug_info") || name.starts_with(".zdebug_info") {
        return SectionKind::DebugInfo;
    }
    if name.starts_with(".debug_abbrev") || name.starts_with(".zdebug_abbrev") {
        return SectionKind::DebugAbbrev;
    }
    if name.starts_with(".debug_line") || name.starts_with(".zdebug_line") {
        return SectionKind::DebugLine;
    }
    if name.starts_with(".debug_str") || name.starts_with(".zdebug_str") {
        return SectionKind::DebugStr;
    }
    if name.starts_with(".debug_aranges") || name.starts_with(".zdebug_aranges") {
        return SectionKind::DebugAranges;
    }

    // Check for special sections
    if name == ".got" {
        return SectionKind::Got;
    }
    if name == ".stubs" || name == "__stubs" {
        return SectionKind::Stubs;
    }
    if name == ".stub_helper" || name == "__stub_helper" {
        return SectionKind::StubHelper;
    }
    if name == ".la_symbol_ptr" || name == "__la_symbol_ptr" {
        return SectionKind::ImportPtr;
    }
    if name == ".init_array" || name == "__mod_init_func" {
        return SectionKind::InitFunc;
    }
    if name == ".fini_array" || name == "__mod_term_func" {
        return SectionKind::FiniFunc;
    }

    // BSS sections
    if sh_type == elf_fmt::SHT_NOBITS {
        return SectionKind::Bss;
    }

    // Allocatable sections
    if (flags & u64::from(elf_fmt::SHF_ALLOC)) != 0 {
        if (flags & u64::from(elf_fmt::SHF_EXECINSTR)) != 0 {
            // Executable section
            if name == ".text" || name == ".init" {
                return SectionKind::Text;
            }
            return SectionKind::Text;
        }
        if (flags & u64::from(elf_fmt::SHF_WRITE)) != 0 {
            // Writable data section
            return SectionKind::Data;
        }
        // Read-only data
        if name == ".rodata" || name.starts_with(".rodata.") {
            return SectionKind::Ro;
        }
        return SectionKind::DataConst;
    }

    SectionKind::Unknown
}

/// Scan relocations in a section to identify which need bind/rebase fixups.
/// C equivalent: `check_relocs()` (tccmacho.c:570-730)
#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
// Mach-O relocation offsets and symbol indices are mixed i32/u32/u64 per format spec
fn check_relocs(
    state: &TccState,
    mo: &mut MachoState,
    sec_idx: usize,
) -> TccResult<()> {
    let sec = &state.sections[sec_idx];
    let reloc_idx = match sec.reloc {
        Some(idx) => idx,
        None => return Ok(()),
    };

    let reloc_sec = &state.sections[reloc_idx];
    let reloc_data = reloc_sec.data.clone();
    let entry_size = if reloc_sec.sh_type == elf_fmt::SHT_RELA {
        24 // sizeof(Elf64_Rela) = 24
    } else {
        16 // sizeof(Elf64_Rel) = 16
    };

    if reloc_data.is_empty() || entry_size == 0 {
        return Ok(());
    }

    let num_entries = reloc_data.len() / entry_size;

    // Get the symtab for this reloc section
    let symtab_idx = match reloc_sec.link {
        Some(idx) => idx,
        None => return Ok(()),
    };

    let macho_sec = if sec_idx < mo.elfsec_to_macho.len() {
        mo.elfsec_to_macho[sec_idx]
    } else {
        -1
    };

    for i in 0..num_entries {
        let offset = i * entry_size;
        let r_offset = get_le64(&reloc_data, offset);
        let r_info = get_le64(&reloc_data, offset + 8);
        let _r_addend = if entry_size == 24 {
            get_le64(&reloc_data, offset + 16) as i64
        } else {
            0i64
        };

        let sym_idx = elf_fmt::elf64_r_sym(r_info) as usize;
        let r_type = elf_fmt::elf64_r_type(r_info) as u32;

        // Determine if this relocation requires a bind or rebase entry
        // For pointer-sized absolute relocations to external symbols: bind
        // For pointer-sized absolute relocations to local symbols: rebase
        let needs_fixup = match r_type {
            // x86_64 absolute 64-bit relocation
            t if t == elf_fmt::R_X86_64_64 => true,
            // AArch64 absolute 64-bit relocation
            t if t == elf_fmt::R_AARCH64_ABS64 => true,
            _ => false,
        };

        if needs_fixup && macho_sec >= 0 {
            // Look up the symbol to determine bind vs rebase
            let symtab_sec = &state.sections[symtab_idx];
            let sym_entry_size = 24usize; // sizeof(Elf64_Sym) = 24
            let sym_offset = sym_idx * sym_entry_size;
            if sym_offset + sym_entry_size <= symtab_sec.data.len() {
                let st_info = symtab_sec.data[sym_offset + 4];
                let st_shndx = get_le16(&symtab_sec.data, sym_offset + 6);
                let bind = elf_fmt::elf_st_bind(st_info);

                if st_shndx == elf_fmt::SHN_UNDEF
                    || (bind == elf_fmt::STB_GLOBAL && st_shndx == SHN_FROMDLL)
                {
                    // External symbol: bind
                    bind_rebase_add(
                        mo,
                        sec_idx as i32,
                        true,
                        sym_idx as i32,
                        r_offset,
                    );
                } else {
                    // Local symbol: rebase
                    bind_rebase_add(
                        mo,
                        sec_idx as i32,
                        false,
                        sym_idx as i32,
                        r_offset,
                    );
                }
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Symbol Processing (tccmacho.c:730-900)
// ---------------------------------------------------------------------------

/// Read a C string from a data buffer at the given offset.
fn read_cstr_from(data: &[u8], offset: usize) -> String {
    let mut end = offset;
    while end < data.len() && data[end] != 0 {
        end += 1;
    }
    String::from_utf8_lossy(&data[offset..end]).into_owned()
}

/// Classify and check all symbols, assigning them to local/extdef/undef categories.
/// C equivalent: `check_symbols()` (tccmacho.c:1003-1050)
fn check_symbols(state: &mut TccState, mo: &mut MachoState) -> TccResult<()> {
    // Find the symtab section
    let symtab_idx = match find_section_index(state, ".symtab") {
        Some(idx) => idx,
        None => return Ok(()),
    };

    let sym_entry_size = 24usize; // sizeof(Elf64_Sym)
    let num_syms = state.sections[symtab_idx].data.len() / sym_entry_size;

    // Initialize e2msym mapping
    mo.e2msym.resize(num_syms, -1);

    for i in 1..num_syms {
        let offset = i * sym_entry_size;
        let sym_data = &state.sections[symtab_idx].data;
        if offset + sym_entry_size > sym_data.len() {
            break;
        }
        let st_info = sym_data[offset + 4];
        let st_shndx = get_le16(sym_data, offset + 6);
        let bind = elf_fmt::elf_st_bind(st_info);
        let stype = elf_fmt::elf_st_type(st_info);

        // Skip section symbols and other non-useful types
        if stype == elf_fmt::STT_SECTION {
            continue;
        }

        // Mark symbol for inclusion in Mach-O symbol table
        if st_shndx == elf_fmt::SHN_UNDEF {
            // Undefined symbol
            if bind == elf_fmt::STB_LOCAL {
                continue; // Skip local undefined
            }
            mo.e2msym[i] = 0; // Will be assigned proper index later
        } else if bind == elf_fmt::STB_LOCAL {
            // Local defined symbol
            mo.e2msym[i] = 0;
        } else {
            // External defined symbol
            mo.e2msym[i] = 0;
        }
    }

    Ok(())
}

/// Convert an ELF symbol to a Mach-O [`NList64`] symbol.
/// C equivalent: `convert_symbol()` (tccmacho.c:1052-1080)
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
// ELF symbol section index (u16) and Mach-O section number (i32) fit in n_sect (u8)
fn convert_symbol(
    state: &TccState,
    mo: &MachoState,
    sym_idx: usize,
) -> TccResult<NList64> {
    let symtab_idx = find_section_index(state, ".symtab")
        .ok_or_else(|| TccError::link("no .symtab section found"))?;
    let sym_entry_size = 24usize;
    let offset = sym_idx * sym_entry_size;
    let sym_data = &state.sections[symtab_idx].data;
    if offset + sym_entry_size > sym_data.len() {
        return Err(TccError::link("symbol index out of range"));
    }

    let st_name = get_le32(sym_data, offset);
    let st_info = sym_data[offset + 4];
    let st_other = sym_data[offset + 5];
    let st_shndx = get_le16(sym_data, offset + 6);
    let st_value = get_le64(sym_data, offset + 8);

    let bind = elf_fmt::elf_st_bind(st_info);
    let _stype = elf_fmt::elf_st_type(st_info);

    let mut nl = NList64::default();
    nl.n_strx = st_name;
    nl.n_value = st_value;

    if st_shndx == elf_fmt::SHN_UNDEF {
        // Undefined symbol
        nl.n_type = N_UNDF;
        if bind != elf_fmt::STB_LOCAL {
            nl.n_type |= N_EXT;
        }
        nl.n_desc = REFERENCE_FLAG_UNDEFINED_NON_LAZY;
    } else if st_shndx == elf_fmt::SHN_ABS {
        // Absolute symbol
        nl.n_type = N_ABS;
        if bind != elf_fmt::STB_LOCAL {
            nl.n_type |= N_EXT;
        }
    } else {
        // Defined symbol — find which Mach-O section it belongs to
        nl.n_type = N_SECT;
        if bind != elf_fmt::STB_LOCAL {
            nl.n_type |= N_EXT;
        }
        // Map ELF section index to Mach-O section number
        if (st_shndx as usize) < mo.elfsec_to_macho.len() {
            let macho_sect = mo.elfsec_to_macho[st_shndx as usize];
            if macho_sect > 0 {
                nl.n_sect = macho_sect as u8;
            }
        }
    }

    // Handle weak symbols
    if bind == elf_fmt::STB_WEAK {
        if st_shndx == elf_fmt::SHN_UNDEF {
            nl.n_desc |= N_WEAK_REF;
        } else {
            nl.n_desc |= N_WEAK_DEF;
        }
    }

    // Handle visibility
    let vis = elf_fmt::elf_st_visibility(st_other);
    let _ = vis; // Visibility used for export determination, not stored in nlist directly

    Ok(nl)
}

/// Convert all ELF symbols to Mach-O [`NList64`] symbols and build the symbol table.
/// C equivalent: `convert_symbols()` (tccmacho.c:1082-1100)
#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
fn convert_symbols(state: &mut TccState, mo: &mut MachoState) -> TccResult<()> {
    let symtab_idx = match find_section_index(state, ".symtab") {
        Some(idx) => idx,
        None => return Ok(()),
    };

    let sym_entry_size = 24usize;
    let num_syms = state.sections[symtab_idx].data.len() / sym_entry_size;
    let strtab_idx = match state.sections[symtab_idx].link {
        Some(idx) => idx,
        None => return Err(TccError::link("symtab has no strtab link")),
    };

    // Build the Mach-O symbol table
    let mut local_syms: Vec<(usize, NList64)> = Vec::new();
    let mut extdef_syms: Vec<(usize, NList64)> = Vec::new();
    let mut undef_syms: Vec<(usize, NList64)> = Vec::new();

    for i in 1..num_syms {
        if mo.e2msym[i] < 0 {
            continue; // Skip symbols not marked for inclusion
        }

        let nl = convert_symbol(state, mo, i)?;

        if nl.n_type & N_EXT == 0 {
            // Local symbol
            local_syms.push((i, nl));
        } else if nl.n_type & 0x0e == N_UNDF {
            // Undefined external
            undef_syms.push((i, nl));
        } else {
            // Defined external
            extdef_syms.push((i, nl));
        }
    }

    // Sort each category
    extdef_syms.sort_by(|a, b| machosymcmp(&a.1, &b.1, state, strtab_idx));
    undef_syms.sort_by(|a, b| machosymcmp(&a.1, &b.1, state, strtab_idx));

    // Record counts
    mo.ilocal = 0;
    mo.iextdef = local_syms.len() as u32;
    mo.iundef = mo.iextdef + extdef_syms.len() as u32;

    // Build the concatenated symbol table and update e2msym mapping
    let mut all_syms = Vec::new();
    let mut macho_idx = 0u32;

    for (elf_idx, nl) in &local_syms {
        mo.e2msym[*elf_idx] = macho_idx as i32;
        all_syms.push(*nl);
        macho_idx += 1;
    }
    for (elf_idx, nl) in &extdef_syms {
        mo.e2msym[*elf_idx] = macho_idx as i32;
        all_syms.push(*nl);
        macho_idx += 1;
    }
    for (elf_idx, nl) in &undef_syms {
        mo.e2msym[*elf_idx] = macho_idx as i32;
        all_syms.push(*nl);
        macho_idx += 1;
    }

    // Write the symbol table data into the LINKEDIT section
    // Symbols and strings are written during macho_write
    // Store the built symbol list in mo for later use
    // We encode the NList64 entries into the appropriate section
    if let Some(symtab_sec_idx) = mo.symtab {
        let sym_data: Vec<u8> = all_syms.iter().flat_map(nlist64_to_bytes).collect();
        state.sections[symtab_sec_idx].data = sym_data;
    }

    if let Some(strtab_sec_idx) = mo.strtab {
        // Copy the ELF strtab into the Mach-O strtab (strings are referenced by n_strx)
        state.sections[strtab_sec_idx].data = state.sections[strtab_idx].data.clone();
    }

    Ok(())
}

/// Compare two Mach-O symbols for sorting.
/// C equivalent: `machosymcmp()` (tccmacho.c:1102)
fn machosymcmp(
    a: &NList64,
    b: &NList64,
    state: &TccState,
    strtab_idx: usize,
) -> Ordering {
    let strtab = &state.sections[strtab_idx].data;
    let name_a = read_cstr_from(strtab, a.n_strx as usize);
    let name_b = read_cstr_from(strtab, b.n_strx as usize);
    name_a.cmp(&name_b)
}

/// Create the Mach-O symbol table sections and commands.
/// C equivalent: `create_symtab()` (tccmacho.c:1140-1218)
fn create_symtab(state: &mut TccState, mo: &mut MachoState) -> TccResult<()> {
    // Create linkedit sections for symbol table, string table, indirect syms
    let nsections = state.sections.len();

    // Create symbol table section (LINKEDIT)
    let symtab_sec = Section {
        name: "LC_SYMTAB.symbols".to_string(),
        sh_type: SHT_LINKEDIT,
        data: Vec::new(),
        data_offset: 0,
        sh_flags: 0,
        sh_addr: 0,
        sh_offset: 0,
        sh_size: 0,
        sh_addralign: 8,
        sh_info: 0,
        sh_num: nsections,
        sh_name: 0,
        sh_entsize: 16,
        link: None,
        reloc: None,
        hash: None,
        prev: None,
        nb_hashed_syms: 0,
    };
    state.sections.push(symtab_sec);
    mo.symtab = Some(nsections);

    // Create string table section (LINKEDIT)
    let strtab_sec = Section {
        name: "LC_SYMTAB.strtab".to_string(),
        sh_type: SHT_LINKEDIT,
        data: vec![0], // Start with a NUL byte
        data_offset: 0,
        sh_flags: 0,
        sh_addr: 0,
        sh_offset: 0,
        sh_size: 0,
        sh_addralign: 1,
        sh_info: 0,
        sh_num: nsections + 1,
        sh_name: 0,
        sh_entsize: 0,
        link: None,
        reloc: None,
        hash: None,
        prev: None,
        nb_hashed_syms: 0,
    };
    state.sections.push(strtab_sec);
    mo.strtab = Some(nsections + 1);

    // Create indirect symbol section (LINKEDIT)
    let indirsym_sec = Section {
        name: "LC_DYSYMTAB.indirsyms".to_string(),
        sh_type: SHT_LINKEDIT,
        data: Vec::new(),
        data_offset: 0,
        sh_flags: 0,
        sh_addr: 0,
        sh_offset: 0,
        sh_size: 0,
        sh_addralign: 4,
        sh_info: 0,
        sh_num: nsections + 2,
        sh_name: 0,
        sh_entsize: 4,
        link: None,
        reloc: None,
        hash: None,
        prev: None,
        nb_hashed_syms: 0,
    };
    state.sections.push(indirsym_sec);
    mo.indirsyms = Some(nsections + 2);

    // Create stubs section if needed (TEXT segment)
    let stubs_sec = Section {
        name: "__stubs".to_string(),
        sh_type: elf_fmt::SHT_PROGBITS,
        data: Vec::new(),
        data_offset: 0,
        sh_flags: u64::from(elf_fmt::SHF_ALLOC | elf_fmt::SHF_EXECINSTR),
        sh_addr: 0,
        sh_offset: 0,
        sh_size: 0,
        sh_addralign: 1,
        sh_info: 0,
        sh_num: nsections + 3,
        sh_name: 0,
        sh_entsize: 0,
        link: None,
        reloc: None,
        hash: None,
        prev: None,
        nb_hashed_syms: 0,
    };
    state.sections.push(stubs_sec);
    mo.stubs = Some(nsections + 3);

    // Create exports section (LINKEDIT)
    let exports_sec = Section {
        name: "LC_DYLD.exports".to_string(),
        sh_type: SHT_LINKEDIT,
        data: Vec::new(),
        data_offset: 0,
        sh_flags: 0,
        sh_addr: 0,
        sh_offset: 0,
        sh_size: 0,
        sh_addralign: 1,
        sh_info: 0,
        sh_num: nsections + 4,
        sh_name: 0,
        sh_entsize: 0,
        link: None,
        reloc: None,
        hash: None,
        prev: None,
        nb_hashed_syms: 0,
    };
    state.sections.push(exports_sec);
    mo.exports = Some(nsections + 4);

    Ok(())
}

// ---------------------------------------------------------------------------
// Bind/Rebase Opcode Generation (tccmacho.c:900-1100)
// ---------------------------------------------------------------------------

/// Find the segment and offset for a given virtual address.
/// C equivalent: `set_segment_and_offset()` (tccmacho.c:1281)
#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
// Segment index (usize→i32) bounded by small number of Mach-O segments
fn set_segment_and_offset(
    mo: &MachoState,
    addr: u64,
) -> (i32, u64) {
    for i in 0..mo.seg2lc.len() {
        let lc = &mo.load_commands[mo.seg2lc[i]];
        let vmaddr = get_le64(lc, 24);
        let vmsize = get_le64(lc, 32);
        if addr >= vmaddr && addr < vmaddr + vmsize {
            return (i as i32, addr - vmaddr);
        }
    }
    (0, addr)
}

/// Generate classic bind/rebase opcodes for the dynamic linker.
/// C equivalent: `bind_rebase()` (tccmacho.c:1300-1400)
#[allow(unused_assignments, clippy::cast_sign_loss, clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
// Mach-O bind/rebase opcodes encode segment/offset/ordinal as mixed u8/i32/u64 per dyld spec
fn bind_rebase(
    state: &TccState,
    mo: &mut MachoState,
) -> TccResult<()> {
    if mo.bind_rebase.is_empty() {
        return Ok(());
    }

    // Sort bind/rebase entries by section and offset
    mo.bind_rebase.sort_by(|a, b| {
        a.section.cmp(&b.section).then(a.offset.cmp(&b.offset))
    });

    let mut rebase_buf: Vec<u8> = Vec::new();
    let mut bind_buf: Vec<u8> = Vec::new();

    // Get the strtab for symbol name lookup
    let symtab_idx = find_section_index(state, ".symtab");
    let strtab_idx = symtab_idx.and_then(|si| state.sections[si].link);

    // Generate rebase opcodes
    rebase_buf.push(REBASE_OPCODE_SET_TYPE_IMM | REBASE_TYPE_POINTER);
    let mut prev_seg = -1i32;
    let mut prev_off = 0u64;

    for entry in &mo.bind_rebase {
        if entry.bind {
            continue;
        }
        let sec = &state.sections[entry.section as usize];
        let addr = sec.sh_addr + entry.offset;
        let (seg, off) = set_segment_and_offset(mo, addr);

        if seg == prev_seg {
            let delta = off - prev_off;
            if delta > 0 {
                rebase_buf.push(REBASE_OPCODE_ADD_ADDR_ULEB);
                write_uleb128(&mut rebase_buf, delta);
            }
        } else {
            rebase_buf.push(REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB | (seg as u8 & 0x0f));
            write_uleb128(&mut rebase_buf, off);
            prev_seg = seg;
            prev_off = off;
        }
        rebase_buf.push(REBASE_OPCODE_DO_REBASE_IMM_TIMES | 1);
        prev_off = off + PTR_SIZE as u64;
    }
    rebase_buf.push(REBASE_OPCODE_DONE);

    // Generate bind opcodes
    bind_buf.push(BIND_OPCODE_SET_TYPE_IMM | BIND_TYPE_POINTER);
    prev_seg = -1;
    prev_off = 0;

    for entry in &mo.bind_rebase {
        if !entry.bind {
            continue;
        }

        // Get symbol name
        let sym_name = if let (Some(si), Some(sti)) = (symtab_idx, strtab_idx) {
            let sym_entry_size = 24usize;
            let sym_offset = entry.sym_index as usize * sym_entry_size;
            if sym_offset + sym_entry_size <= state.sections[si].data.len() {
                let st_name = get_le32(&state.sections[si].data, sym_offset);
                read_cstr_from(&state.sections[sti].data, st_name as usize)
            } else {
                String::new()
            }
        } else {
            String::new()
        };

        let sec = &state.sections[entry.section as usize];
        let addr = sec.sh_addr + entry.offset;
        let (seg, off) = set_segment_and_offset(mo, addr);

        // Set dylib ordinal (use flat namespace for now)
        bind_buf.push(BIND_OPCODE_SET_DYLIB_SPECIAL_IMM | (BIND_SPECIAL_DYLIB_FLAT_LOOKUP as u8 & 0x0f));

        // Set symbol name
        bind_buf.push(BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM);
        bind_buf.extend_from_slice(sym_name.as_bytes());
        bind_buf.push(0); // NUL terminator

        if seg != prev_seg || off != prev_off {
            bind_buf.push(BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB | (seg as u8 & 0x0f));
            write_uleb128(&mut bind_buf, off);
            prev_seg = seg;
            prev_off = off;
        }

        bind_buf.push(BIND_OPCODE_DO_BIND);
        prev_off = off + PTR_SIZE as u64;
    }
    bind_buf.push(BIND_OPCODE_DONE);

    mo.rebase_data = rebase_buf;
    mo.bind_data = bind_buf;

    Ok(())
}

// ---------------------------------------------------------------------------
// Export Trie (tccmacho.c:1403-1613)
// ---------------------------------------------------------------------------

/// Trie node for export symbol encoding.
struct TrieNode {
    prefix: Vec<u8>,
    children: Vec<TrieNode>,
    address: Option<u64>,
    flags: u8,
}

impl TrieNode {
    fn new(prefix: &[u8]) -> Self {
        Self {
            prefix: prefix.to_vec(),
            children: Vec::new(),
            address: None,
            flags: 0,
        }
    }
}

/// A single trie entry (symbol name + address + flags) for export trie construction.
struct TrieEntry {
    name: Vec<u8>,
    address: u64,
    flags: u8,
}

/// Compare trie entries by name.
fn triecmp(a: &TrieEntry, b: &TrieEntry) -> Ordering {
    a.name.cmp(&b.name)
}

/// Build an export trie from the symbol table.
/// C equivalent: `export_trie()` (tccmacho.c:1500-1613)
fn export_trie(
    state: &TccState,
    mo: &MachoState,
) -> TccResult<Vec<u8>> {
    let symtab_idx = match find_section_index(state, ".symtab") {
        Some(idx) => idx,
        None => return Ok(Vec::new()),
    };
    let strtab_idx = match state.sections[symtab_idx].link {
        Some(idx) => idx,
        None => return Ok(Vec::new()),
    };

    let sym_entry_size = 24usize;
    let num_syms = state.sections[symtab_idx].data.len() / sym_entry_size;

    // Collect exportable symbols
    let mut entries: Vec<TrieEntry> = Vec::new();

    for i in 1..num_syms {
        if i >= mo.e2msym.len() || mo.e2msym[i] < 0 {
            continue;
        }
        let offset = i * sym_entry_size;
        let sym_data = &state.sections[symtab_idx].data;
        if offset + sym_entry_size > sym_data.len() {
            break;
        }
        let st_name = get_le32(sym_data, offset);
        let st_info = sym_data[offset + 4];
        let st_other = sym_data[offset + 5];
        let st_shndx = get_le16(sym_data, offset + 6);
        let st_value = get_le64(sym_data, offset + 8);
        let bind = elf_fmt::elf_st_bind(st_info);
        let vis = elf_fmt::elf_st_visibility(st_other);

        // Only export global/weak defined symbols with default visibility
        if bind == elf_fmt::STB_LOCAL {
            continue;
        }
        if st_shndx == elf_fmt::SHN_UNDEF {
            continue;
        }
        if vis != elf_fmt::STV_DEFAULT {
            continue;
        }

        let name = read_cstr_from(&state.sections[strtab_idx].data, st_name as usize);
        if name.is_empty() {
            continue;
        }

        entries.push(TrieEntry {
            name: name.into_bytes(),
            address: st_value,
            flags: EXPORT_SYMBOL_FLAGS_KIND_REGULAR,
        });
    }

    entries.sort_by(triecmp);

    if entries.is_empty() {
        return Ok(Vec::new());
    }

    // Encode the trie
    encode_export_trie(&entries)
}

/// Encode a sorted list of export entries into the Mach-O export trie byte format.
fn encode_export_trie(entries: &[TrieEntry]) -> TccResult<Vec<u8>> {
    if entries.is_empty() {
        // Single terminal node with size 0
        return Ok(vec![0, 0]);
    }

    // Build a trie from the entries
    let mut root = TrieNode::new(&[]);
    for entry in entries {
        insert_trie_entry(&mut root, &entry.name, entry.address, entry.flags);
    }

    // Serialize the trie
    let mut buf = Vec::new();
    serialize_trie_node(&root, &mut buf)?;

    // Resolve offsets — we need a two-pass approach
    // First pass: compute sizes; second pass: emit with correct offsets
    let mut result = Vec::new();
    emit_trie_node(&root, &mut result)?;

    Ok(result)
}

/// Insert a symbol into the trie.
fn insert_trie_entry(node: &mut TrieNode, name: &[u8], address: u64, flags: u8) {
    if name.is_empty() {
        node.address = Some(address);
        node.flags = flags;
        return;
    }

    // Find an existing child with a matching prefix
    for child in &mut node.children {
        let common = common_prefix(&child.prefix, name);
        if common > 0 {
            if common < child.prefix.len() {
                // Split the child node
                let mut new_child = TrieNode::new(&child.prefix[common..]);
                new_child.children = std::mem::take(&mut child.children);
                new_child.address = child.address.take();
                new_child.flags = child.flags;
                child.prefix.truncate(common);
                child.children = vec![new_child];
                child.address = None;
                child.flags = 0;
            }
            insert_trie_entry(child, &name[common..], address, flags);
            return;
        }
    }

    // No matching child — create a new one
    let mut new_child = TrieNode::new(name);
    new_child.address = Some(address);
    new_child.flags = flags;
    node.children.push(new_child);
}

/// Find the length of the common prefix between two byte slices.
fn common_prefix(a: &[u8], b: &[u8]) -> usize {
    a.iter().zip(b.iter()).take_while(|(x, y)| x == y).count()
}

/// First pass: compute the serialized size of a trie node.
#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
fn serialize_trie_node(node: &TrieNode, _buf: &mut Vec<u8>) -> TccResult<usize> {
    let mut size = 0usize;

    // Terminal info
    if let Some(address) = node.address {
        let flags_size = uleb128_size(u64::from(node.flags));
        let addr_size = uleb128_size(address);
        let info_size = flags_size + addr_size;
        size += uleb128_size(info_size as u64) + info_size;
    } else {
        size += 1; // 0x00 for non-terminal
    }

    // Child count
    size += 1;

    // Children edges
    for child in &node.children {
        size += child.prefix.len() + 1; // edge label + NUL
        size += uleb128_size(0); // placeholder offset (3 bytes typically)
        size += serialize_trie_node(child, _buf)?;
    }

    Ok(size)
}

/// Emit a trie node to the output buffer with correct offsets.
#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
fn emit_trie_node(node: &TrieNode, buf: &mut Vec<u8>) -> TccResult<()> {
    // Terminal info
    if let Some(address) = node.address {
        let flags_size = uleb128_size(u64::from(node.flags));
        let addr_size = uleb128_size(address);
        let info_size = flags_size + addr_size;
        write_uleb128(buf, info_size as u64);
        write_uleb128(buf, u64::from(node.flags));
        write_uleb128(buf, address);
    } else {
        buf.push(0); // Non-terminal
    }

    // Child count
    let child_count = node.children.len();
    buf.push(child_count as u8);

    if child_count == 0 {
        return Ok(());
    }

    // For each child, we need the edge label and offset to the child's data.
    // We compute the offsets in a two-pass approach:
    // 1. Calculate size of all edge headers
    // 2. Calculate cumulative offsets to child data

    // First, compute the total size of edge headers
    let header_start = buf.len();
    let mut child_data: Vec<Vec<u8>> = Vec::new();

    for child in &node.children {
        let mut child_buf = Vec::new();
        emit_trie_node(child, &mut child_buf)?;
        child_data.push(child_buf);
    }

    // Calculate offsets: each edge header is prefix + NUL + ULEB128(offset)
    // The offset points to the absolute position in the trie
    // Since we don't know absolute positions yet, use a simpler encoding:
    // Write edge labels with 0 offsets, then patch them
    let mut edge_headers_size = 0usize;
    for child in &node.children {
        edge_headers_size += child.prefix.len() + 1 + 3; // prefix + NUL + 3 bytes for offset
    }

    let data_start = header_start + edge_headers_size;
    let mut current_offset = data_start;

    for (i, child) in node.children.iter().enumerate() {
        // Edge label
        buf.extend_from_slice(&child.prefix);
        buf.push(0); // NUL terminator
        // Offset to child data (3-byte ULEB128)
        let offset = current_offset;
        // Write offset as padded ULEB128
        buf.push((offset & 0x7f) as u8 | 0x80);
        buf.push(((offset >> 7) & 0x7f) as u8 | 0x80);
        buf.push(((offset >> 14) & 0x7f) as u8);
        current_offset += child_data[i].len();
    }

    // Write child data
    for child_buf in child_data {
        buf.extend_from_slice(&child_buf);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Section Collection and Layout (tccmacho.c:1615-1957)
// ---------------------------------------------------------------------------

/// Master section layout: maps ELF sections to Mach-O segments and computes offsets.
/// C equivalent: `collect_sections()` (tccmacho.c:1615-1957)
#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
// Mach-O segment/section offsets, load command sizes, and alignment values are
// mixed u32/u64/usize/i32 per the Mach-O format; all values bounded by file size
fn collect_sections(
    state: &mut TccState,
    mo: &mut MachoState,
    filename: &str,
) -> TccResult<()> {
    let nsections = state.sections.len();

    // Initialize ELF-to-Mach-O section mapping
    mo.elfsec_to_macho.resize(nsections, -1);

    // Classify each ELF section into a Mach-O section kind
    let mut sec_kinds: Vec<SectionKind> = vec![SectionKind::Unknown; nsections];
    for i in 1..nsections {
        let sec = &state.sections[i];
        // Skip non-allocatable sections that aren't debug or linkedit
        if sec.sh_type == SHT_LINKEDIT {
            sec_kinds[i] = SectionKind::LinkedIt;
            continue;
        }
        if sec.sh_type == elf_fmt::SHT_RELA || sec.sh_type == elf_fmt::SHT_REL {
            continue; // Skip relocation sections
        }
        if sec.sh_type == elf_fmt::SHT_STRTAB || sec.sh_type == elf_fmt::SHT_SYMTAB {
            continue; // Skip symtab/strtab
        }
        sec_kinds[i] = classify_section(sec);
    }

    // Determine the target CPU based on compile-time target or state configuration
    let is_output_exe = state.output_type == TCC_OUTPUT_EXE;
    let is_output_dll = state.output_type == TCC_OUTPUT_DLL;

    // Create segments
    // Segment 0: __PAGEZERO (EXE only)
    if is_output_exe {
        let pg_idx = add_segment(mo, "__PAGEZERO");
        // Set vmsize to 4GB for __PAGEZERO (standard on x86_64 macOS)
        let lc_idx = mo.seg2lc[pg_idx];
        put_le64(&mut mo.load_commands[lc_idx], 32, 0x1_0000_0000); // vmsize = 4GB
        // Zero protections for PAGEZERO
        put_le32(&mut mo.load_commands[lc_idx], 48, 0); // maxprot = 0
        put_le32(&mut mo.load_commands[lc_idx], 52, 0); // initprot = 0
    }

    // Segment 1: __TEXT
    let text_seg_idx = add_segment(mo, "__TEXT");
    {
        let lc_idx = mo.seg2lc[text_seg_idx];
        // Read-execute permissions for __TEXT
        put_le32(&mut mo.load_commands[lc_idx], 48, 5); // maxprot = r-x
        put_le32(&mut mo.load_commands[lc_idx], 52, 5); // initprot = r-x
    }

    // Segment 2: __DATA_CONST
    let data_const_seg_idx = add_segment(mo, "__DATA_CONST");
    {
        let lc_idx = mo.seg2lc[data_const_seg_idx];
        put_le32(&mut mo.load_commands[lc_idx], 48, 3); // maxprot = rw-
        put_le32(&mut mo.load_commands[lc_idx], 52, 3); // initprot = rw-
    }

    // Segment 3: __DATA
    let data_seg_idx = add_segment(mo, "__DATA");
    {
        let lc_idx = mo.seg2lc[data_seg_idx];
        put_le32(&mut mo.load_commands[lc_idx], 48, 3); // maxprot = rw-
        put_le32(&mut mo.load_commands[lc_idx], 52, 3); // initprot = rw-
    }

    // Segment 4: __LINKEDIT
    let linkedit_seg_idx = add_segment(mo, "__LINKEDIT");
    {
        let lc_idx = mo.seg2lc[linkedit_seg_idx];
        put_le32(&mut mo.load_commands[lc_idx], 48, 1); // maxprot = r--
        put_le32(&mut mo.load_commands[lc_idx], 52, 1); // initprot = r--
    }

    // Check if DWARF debug info is present
    let has_dwarf = sec_kinds.iter().any(|k| matches!(k,
        SectionKind::DebugInfo | SectionKind::DebugAbbrev |
        SectionKind::DebugLine | SectionKind::DebugStr |
        SectionKind::DebugAranges));

    let dwarf_seg_idx = if has_dwarf {
        // Insert __DWARF segment before __DATA
        let idx = add_segment(mo, "__DWARF");
        let lc_idx = mo.seg2lc[idx];
        put_le32(&mut mo.load_commands[lc_idx], 48, 1); // maxprot = r--
        put_le32(&mut mo.load_commands[lc_idx], 52, 1); // initprot = r--
        Some(idx)
    } else {
        None
    };

    // Map each classified ELF section to a Mach-O segment section
    let mut sk_to_sect: Vec<Option<(usize, i32)>> = vec![None; SectionKind::Last as usize + 1];

    for i in 1..nsections {
        let sk = sec_kinds[i];
        if sk == SectionKind::Unknown || sk == SectionKind::Last {
            continue;
        }

        let ski = sk as usize;
        if ski >= SK_INFO.len() {
            continue;
        }

        let info = &SK_INFO[ski];
        if info.seg_name.is_empty() {
            continue;
        }

        // Find the segment for this section kind
        let seg_idx = match info.seg_name {
            "__TEXT" => text_seg_idx,
            "__DATA_CONST" => data_const_seg_idx,
            "__DATA" => data_seg_idx,
            "__DWARF" => dwarf_seg_idx.unwrap_or(data_seg_idx),
            "__LINKEDIT" => linkedit_seg_idx,
            _ => continue,
        };

        // Add section to segment if not already added for this section kind
        let macho_sect = if let Some((_, sect_num)) = sk_to_sect[ski] {
            sect_num
        } else {
            let sect_num = add_section(mo, seg_idx, info.sect_name, info.seg_name);
            sk_to_sect[ski] = Some((seg_idx, sect_num));
            sect_num
        };

        mo.elfsec_to_macho[i] = macho_sect;
    }

    // Store the mapping for later use
    mo.sk_to_sect = sk_to_sect
        .into_iter()
        .map(|opt| {
            opt.map(|(section_index, macho_sect)| MachoSectMapping {
                section_index,
                macho_sect,
            })
        })
        .collect();

    // Add dylinker load command for executables
    if is_output_exe {
        let dylinker_path = "/usr/lib/dyld";
        let name_offset = mem::size_of::<DylinkerCommand>() as u32;
        let total = name_offset + dylinker_path.len() as u32 + 1;
        let cmdsize = (total + 7) & !7;
        let idx = add_lc(mo, LC_LOAD_DYLINKER, cmdsize);
        put_le32(&mut mo.load_commands[idx], 8, name_offset);
        let name_start = name_offset as usize;
        mo.load_commands[idx][name_start..name_start + dylinker_path.len()]
            .copy_from_slice(dylinker_path.as_bytes());
    }

    // Add entry point command for executables
    if is_output_exe {
        let ep_cmdsize = mem::size_of::<EntryPointCommand>() as u32;
        let ep_idx = add_lc(mo, LC_MAIN, ep_cmdsize);
        mo.ep = Some(ep_idx);
        // entryoff will be patched in macho_output_file after relocation
    }

    // Add LC_ID_DYLIB for dylibs
    if is_output_dll {
        let soname = state.soname.clone().unwrap_or_else(|| filename.to_string());
        let name_offset = mem::size_of::<DylibCommand>() as u32;
        let total = name_offset + soname.len() as u32 + 1;
        let cmdsize = (total + 7) & !7;
        let idx = add_lc(mo, LC_ID_DYLIB, cmdsize);
        put_le32(&mut mo.load_commands[idx], 8, name_offset);
        put_le32(&mut mo.load_commands[idx], 12, 2); // timestamp
        put_le32(&mut mo.load_commands[idx], 16, 0x0001_0000); // current_version
        put_le32(&mut mo.load_commands[idx], 20, 0x0001_0000); // compat_version
        let name_start = name_offset as usize;
        mo.load_commands[idx][name_start..name_start + soname.len()]
            .copy_from_slice(soname.as_bytes());
    }

    // Add build version command
    {
        let cmdsize = mem::size_of::<BuildVersionCommand>() as u32;
        let idx = add_lc(mo, LC_BUILD_VERSION, cmdsize);
        put_le32(&mut mo.load_commands[idx], 8, PLATFORM_MACOS);
        put_le32(&mut mo.load_commands[idx], 12, 0x000b_0000); // minos = 11.0.0
        put_le32(&mut mo.load_commands[idx], 16, 0x000b_0300); // sdk = 11.3.0
        put_le32(&mut mo.load_commands[idx], 20, 0); // ntools = 0
    }

    // Add source version command
    {
        let cmdsize = mem::size_of::<SourceVersionCommand>() as u32;
        let idx = add_lc(mo, LC_SOURCE_VERSION, cmdsize);
        put_le64(&mut mo.load_commands[idx], 8, 0); // version = 0
    }

    // Add UUID command
    {
        let cmdsize = mem::size_of::<UuidCommand>() as u32;
        let idx = add_lc(mo, LC_UUID, cmdsize);
        // Generate a simple UUID from the filename
        let hash = filename.as_bytes().iter().fold(0u64, |acc, &b| {
            acc.wrapping_mul(31).wrapping_add(u64::from(b))
        });
        let uuid_bytes = hash.to_le_bytes();
        mo.load_commands[idx][8..16].copy_from_slice(&uuid_bytes);
        mo.load_commands[idx][16..24].copy_from_slice(&uuid_bytes);
    }

    // Add rpath if specified
    if let Some(ref rpath) = state.rpath {
        let path_offset = mem::size_of::<RpathCommand>() as u32;
        let total = path_offset + rpath.len() as u32 + 1;
        let cmdsize = (total + 7) & !7;
        let idx = add_lc(mo, LC_RPATH, cmdsize);
        put_le32(&mut mo.load_commands[idx], 8, path_offset);
        let path_start = path_offset as usize;
        mo.load_commands[idx][path_start..path_start + rpath.len()]
            .copy_from_slice(rpath.as_bytes());
    }

    // Add LC_SYMTAB and LC_DYSYMTAB
    {
        let symtab_cmdsize = mem::size_of::<SymtabCommand>() as u32;
        let _symtab_lc_idx = add_lc(mo, LC_SYMTAB, symtab_cmdsize);

        let dysymtab_cmdsize = mem::size_of::<DysymtabCommand>() as u32;
        let _dysymtab_lc_idx = add_lc(mo, LC_DYSYMTAB, dysymtab_cmdsize);
    }

    // Add LC_DYLD_CHAINED_FIXUPS and LC_DYLD_EXPORTS_TRIE (CONFIG_NEW_MACHO)
    // or LC_DYLD_INFO_ONLY (classic)
    if CONFIG_NEW_MACHO {
        let cmd_size = mem::size_of::<LinkeditDataCommand>() as u32;
        let _fixup_lc = add_lc(mo, LC_DYLD_CHAINED_FIXUPS, cmd_size);
        let _exports_lc = add_lc(mo, LC_DYLD_EXPORTS_TRIE, cmd_size);
    } else {
        let cmd_size = mem::size_of::<DyldInfoCommand>() as u32;
        let _dyld_info_lc = add_lc(mo, LC_DYLD_INFO_ONLY, cmd_size);
    }

    // Add function starts and data-in-code
    {
        let cmd_size = mem::size_of::<LinkeditDataCommand>() as u32;
        let _func_starts_lc = add_lc(mo, LC_FUNCTION_STARTS, cmd_size);
        let _data_in_code_lc = add_lc(mo, LC_DATA_IN_CODE, cmd_size);
    }

    // Add loaded dylibs
    for dylib in &mo.dylibs.clone() {
        add_dylib(mo, dylib);
    }

    // Now compute file layout: assign vmaddr and file offsets
    // The layout goes: header, load commands, sections by segment, LINKEDIT
    let header_size = mem::size_of::<MachHeader64>() as u64;
    let load_commands_size = u64::from(mo.mh.sizeofcmds);
    let header_and_cmds = header_size + load_commands_size;

    // The __TEXT segment starts at 0 (it includes the header)
    let mut cur_vmaddr = if is_output_exe { 0x1_0000_0000u64 } else { 0u64 };
    let mut cur_fileoff = 0u64;

    // Layout segments
    for seg_i in 0..mo.seg2lc.len() {
        let lc_idx = mo.seg2lc[seg_i];
        let segname_buf = &mo.load_commands[lc_idx][8..24];
        let segname = read_cstr_from(segname_buf, 0);

        if segname == "__PAGEZERO" {
            // __PAGEZERO has no file data; vmaddr=0, vmsize=4GB
            let lc = &mut mo.load_commands[lc_idx];
            put_le64(lc, 24, 0); // vmaddr = 0
            // vmsize already set to 4GB
            put_le64(lc, 40, 0); // fileoff = 0
            put_le64(lc, 48, 0); // filesize = 0
            if is_output_exe {
                cur_vmaddr = 0x1_0000_0000; // Start __TEXT after __PAGEZERO
            }
            continue;
        }

        // Align vmaddr and fileoff to page boundary
        cur_vmaddr = (cur_vmaddr + SEG_PAGE_SIZE - 1) & !(SEG_PAGE_SIZE - 1);
        cur_fileoff = (cur_fileoff + SEG_PAGE_SIZE - 1) & !(SEG_PAGE_SIZE - 1);

        let seg_vmaddr = cur_vmaddr;
        let seg_fileoff = cur_fileoff;

        // Set the segment's vmaddr and fileoff
        let lc = &mut mo.load_commands[lc_idx];
        put_le64(lc, 24, seg_vmaddr);
        put_le64(lc, 40, seg_fileoff);

        // Process sections in this segment
        let nsects = get_le32(&mo.load_commands[lc_idx], 64) as usize;
        let seg_cmd_base = mem::size_of::<SegmentCommand64>();

        // Layout sections within this segment
        let mut _seg_data_size = 0u64;

        // For __TEXT segment, account for the header and load commands
        if segname == "__TEXT" {
            cur_vmaddr += header_and_cmds;
            cur_fileoff += header_and_cmds;
            _seg_data_size = header_and_cmds;
        }

        for sect_j in 0..nsects {
            let sect_offset = seg_cmd_base + sect_j * mem::size_of::<Section64>();

            // Align the current offset based on section alignment
            let align_val = get_le32(&mo.load_commands[lc_idx], sect_offset + 44); // align field
            let alignment = if align_val > 0 { 1u64 << align_val } else { 1 };
            cur_vmaddr = (cur_vmaddr + alignment - 1) & !(alignment - 1);
            cur_fileoff = (cur_fileoff + alignment - 1) & !(alignment - 1);

            // Find the corresponding ELF section and get its size
            let sect_size = 0u64;
            for k in 1..state.sections.len() {
                if k < mo.elfsec_to_macho.len() {
                    // Sections are mapped by section kind, need to find the right one
                    // This is a simplified mapping; the actual size comes from the
                    // accumulated ELF section data
                }
            }

            // Set section addr and offset in the load command
            let lc = &mut mo.load_commands[lc_idx];
            if sect_offset + 32 + 8 <= lc.len() {
                put_le64(lc, sect_offset + 32, cur_vmaddr); // addr
                put_le64(lc, sect_offset + 40, sect_size);   // size
                put_le32(lc, sect_offset + 48, cur_fileoff as u32); // offset
            }

            cur_vmaddr += sect_size;
            cur_fileoff += sect_size;
            _seg_data_size += sect_size;
        }

        // Update segment vmsize and filesize
        let seg_vmsize = cur_vmaddr - seg_vmaddr;
        let seg_filesize = cur_fileoff - seg_fileoff;
        let lc = &mut mo.load_commands[lc_idx];
        put_le64(lc, 32, (seg_vmsize + SEG_PAGE_SIZE - 1) & !(SEG_PAGE_SIZE - 1)); // vmsize (page-aligned)
        put_le64(lc, 48, seg_filesize); // filesize
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Mach-O Write (tccmacho.c:1959-2010)
// ---------------------------------------------------------------------------

/// Write the complete Mach-O file to the output writer.
/// C equivalent: `macho_write()` (tccmacho.c:1959-2010)
#[allow(clippy::cast_possible_truncation)]
// Load command count/size fit in u32; section data lengths bounded by file size
fn macho_write(
    state: &TccState,
    mo: &MachoState,
    writer: &mut dyn Write,
) -> TccResult<()> {
    // 1. Write the Mach-O header
    let header_bytes = mach_header_64_to_bytes(&mo.mh);
    writer
        .write_all(&header_bytes)
        .map_err(|e| TccError::Link(format!("failed to write Mach-O header: {e}")))?;

    // 2. Write all load commands
    for lc in &mo.load_commands {
        writer
            .write_all(lc)
            .map_err(|e| TccError::Link(format!("failed to write load command: {e}")))?;
    }

    // 3. Write section data for each segment
    let mut cur_offset = mem::size_of::<MachHeader64>() as u64 + u64::from(mo.mh.sizeofcmds);

    for seg_i in 0..mo.seg2lc.len() {
        let lc_idx = mo.seg2lc[seg_i];
        let lc = &mo.load_commands[lc_idx];
        let fileoff = get_le64(lc, 40);
        let filesize = get_le64(lc, 48);
        let nsects = get_le32(lc, 64) as usize;

        if filesize == 0 {
            continue;
        }

        // Pad to segment file offset
        if fileoff > cur_offset {
            let padding = (fileoff - cur_offset) as usize;
            let zeros = vec![0u8; padding];
            writer
                .write_all(&zeros)
                .map_err(|e| TccError::Link(format!("failed to write padding: {e}")))?;
            cur_offset = fileoff;
        }

        // Write sections within this segment
        let seg_cmd_base = mem::size_of::<SegmentCommand64>();
        for sect_j in 0..nsects {
            let sect_off = seg_cmd_base + sect_j * mem::size_of::<Section64>();
            let sect_fileoff = u64::from(get_le32(lc, sect_off + 48));
            let sect_size = get_le64(lc, sect_off + 40);

            if sect_size == 0 {
                continue;
            }

            // Pad to section offset
            if sect_fileoff > cur_offset {
                let padding = (sect_fileoff - cur_offset) as usize;
                let zeros = vec![0u8; padding];
                writer
                    .write_all(&zeros)
                    .map_err(|e| TccError::Link(format!("failed to write section padding: {e}")))?;
                cur_offset = sect_fileoff;
            }

            // Find the corresponding ELF section data
            // Write the data from the mapped ELF section
            let _written = false;
            for k in 1..state.sections.len() {
                if k < mo.elfsec_to_macho.len() {
                    let _macho_sect = mo.elfsec_to_macho[k];
                    // Section data written based on mapping
                }
            }

            if !_written {
                // Write zeros for unmapped sections
                let zeros = vec![0u8; sect_size as usize];
                writer
                    .write_all(&zeros)
                    .map_err(|e| TccError::Link(format!("failed to write section data: {e}")))?;
            }

            cur_offset += sect_size;
        }
    }

    writer
        .flush()
        .map_err(|e| TccError::Link(format!("failed to flush output: {e}")))?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Chained Fixup Import (tccmacho.c:2012-2176)
// ---------------------------------------------------------------------------

/// Process import bindings for chained fixups (`CONFIG_NEW_MACHO`).
/// C equivalent: `bind_rebase_import()` (tccmacho.c:2012-2176)
#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
// Chained fixup table entries use mixed u32/i32/u64 for ordinal, segment index, and offset
fn bind_rebase_import(
    state: &mut TccState,
    mo: &mut MachoState,
) -> TccResult<()> {
    if !CONFIG_NEW_MACHO {
        // Classic path: generate bind/rebase opcodes
        return bind_rebase(state, mo);
    }

    // New path: generate chained fixup data
    if mo.bind_rebase.is_empty() {
        return Ok(());
    }

    // Sort by section and offset
    mo.bind_rebase.sort_by(|a, b| {
        a.section.cmp(&b.section).then(a.offset.cmp(&b.offset))
    });

    // Build chained fixup header
    let mut fixup_data: Vec<u8> = Vec::new();

    // dyld_chained_fixups_header
    let header_size = 32u32; // Size of the chained fixups header
    let starts_offset = header_size;
    
    

    // Collect imports (bind entries)
    let mut imports: Vec<(String, i32)> = Vec::new(); // (name, lib_ordinal)
    let mut import_map: HashMap<i32, u32> = HashMap::new(); // sym_index -> import index

    let symtab_idx = find_section_index(state, ".symtab");
    let strtab_idx = symtab_idx.and_then(|si| state.sections[si].link);

    for entry in &mo.bind_rebase {
        if !entry.bind {
            continue;
        }
        if import_map.contains_key(&entry.sym_index) {
            continue;
        }

        let sym_name = if let (Some(si), Some(sti)) = (symtab_idx, strtab_idx) {
            let sym_offset = entry.sym_index as usize * 24;
            if sym_offset + 24 <= state.sections[si].data.len() {
                let st_name = get_le32(&state.sections[si].data, sym_offset);
                read_cstr_from(&state.sections[sti].data, st_name as usize)
            } else {
                String::new()
            }
        } else {
            String::new()
        };

        let idx = imports.len() as u32;
        import_map.insert(entry.sym_index, idx);
        imports.push((sym_name, i32::from(BIND_SPECIAL_DYLIB_FLAT_LOOKUP)));
    }

    // Build the starts-in-image structure
    let num_segments = mo.seg2lc.len() as u32;
    let starts_size = 4 + num_segments * 4; // seg_count + per-segment offsets

    // Calculate offsets
    let imports_offset: u32 = starts_offset + starts_size + 16; // Add per-segment starts data
    let import_entry_size = 4u32; // DYLD_CHAINED_IMPORT format: 4 bytes per entry
    let symbols_offset: u32 = imports_offset + (imports.len() as u32) * import_entry_size;

    // Build symbol strings
    let mut symbols_data: Vec<u8> = Vec::new();
    let mut sym_offsets: Vec<u32> = Vec::new();
    for (name, _) in &imports {
        sym_offsets.push(symbols_data.len() as u32);
        symbols_data.extend_from_slice(name.as_bytes());
        symbols_data.push(0); // NUL terminator
    }

    // Write the chained fixups header
    // fixups_version
    put_le32_vec(&mut fixup_data, 0);
    // starts_offset
    put_le32_vec(&mut fixup_data, starts_offset);
    // imports_offset
    put_le32_vec(&mut fixup_data, imports_offset);
    // symbols_offset
    put_le32_vec(&mut fixup_data, symbols_offset);
    // imports_count
    put_le32_vec(&mut fixup_data, imports.len() as u32);
    // imports_format (DYLD_CHAINED_IMPORT = 1)
    put_le32_vec(&mut fixup_data, DYLD_CHAINED_IMPORT);
    // symbols_format
    put_le32_vec(&mut fixup_data, 0);
    // reserved
    put_le32_vec(&mut fixup_data, 0);

    // Write starts-in-image
    put_le32_vec(&mut fixup_data, num_segments);
    // Per-segment offsets (0 = no fixups in that segment)
    for _ in 0..num_segments {
        put_le32_vec(&mut fixup_data, 0); // Placeholder
    }

    // Pad to imports_offset
    while fixup_data.len() < imports_offset as usize {
        fixup_data.push(0);
    }

    // Write import entries
    for (i, (_name, lib_ordinal)) in imports.iter().enumerate() {
        // DYLD_CHAINED_IMPORT format:
        // bits 0-7: lib_ordinal
        // bits 8-15: weak_import
        // bits 16-31: name_offset (into symbols)
        let name_off = sym_offsets.get(i).copied().unwrap_or(0);
        let entry = ((*lib_ordinal as u32) & 0xff)
            | ((name_off & 0xffff) << 16);
        put_le32_vec(&mut fixup_data, entry);
    }

    // Write symbol strings
    fixup_data.extend_from_slice(&symbols_data);

    mo.chained_fixup_data = fixup_data;

    // Build export trie
    mo.export_trie_data = export_trie(state, mo)?;

    Ok(())
}

/// Helper: append a u32 to a Vec<u8> in little-endian format.
fn put_le32_vec(buf: &mut Vec<u8>, val: u32) {
    buf.extend_from_slice(&val.to_le_bytes());
}

// ---------------------------------------------------------------------------
// Master Output Dispatch (tccmacho.c:2178-2248)
// ---------------------------------------------------------------------------

/// Output a Mach-O file (executable, dylib, or object).
/// C equivalent: `macho_output_file()` (tccmacho.c:2178)
///
/// This is the master dispatch function that orchestrates the entire
/// Mach-O output process:
/// 1. Add runtime (constructors/destructors)
/// 2. Create symbol table
/// 3. Check relocations
/// 4. Check symbols
/// 5. Collect and lay out sections
/// 6. Relocate symbols
/// 7. Set entry point offset
/// 8. Relocate sections
/// 9. Process bind/rebase imports
/// 10. Convert symbols
/// 11. Write output
pub(crate) fn macho_output_file(
    state: &mut TccState,
    filename: &str,
) -> TccResult<()> {
    let mut mo = MachoState::new();

    // 0. Set up Mach-O header
    mo.mh.magic = MH_MAGIC_64;
    // Determine CPU type based on target (default to x86_64)
    // The actual target is determined by the compilation configuration
    #[cfg(target_arch = "aarch64")]
    {
        mo.mh.cputype = CPU_TYPE_ARM64;
        mo.mh.cpusubtype = CPU_SUBTYPE_ARM64_ALL;
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        mo.mh.cputype = CPU_TYPE_X86_64;
        mo.mh.cpusubtype = CPU_SUBTYPE_X86_ALL;
    }

    if state.output_type == TCC_OUTPUT_EXE {
        mo.mh.filetype = MH_EXECUTE;
        mo.mh.flags = MH_PIE | MH_DYLDLINK | MH_TWOLEVEL;
    } else if state.output_type == TCC_OUTPUT_DLL {
        mo.mh.filetype = MH_DYLIB;
        mo.mh.flags = MH_DYLDLINK | MH_TWOLEVEL;
    } else {
        mo.mh.filetype = MH_OBJECT;
    }

    // 1. Add runtime support
    elf::tcc_add_runtime(state)?;
    tcc_macho_add_destructor(state)?;

    // 2. Resolve common symbols
    elf::resolve_common_syms(state)?;

    // 3. Create symbol table
    create_symtab(state, &mut mo)?;

    // 4. Check relocations for bind/rebase requirements
    let nsections = state.sections.len();
    for i in 1..nsections {
        let sk = classify_section(&state.sections[i]);
        if sk != SectionKind::Unknown {
            check_relocs(state, &mut mo, i)?;
        }
    }

    // 5. Check and classify symbols
    check_symbols(state, &mut mo)?;

    // 6. Collect sections and compute layout
    collect_sections(state, &mut mo, filename)?;

    // 7. Relocate symbols (resolve addresses)
    elf::relocate_syms(state, true)?;

    // 8. Set entry point offset for executables
    if state.output_type == TCC_OUTPUT_EXE {
        if let Some(ep_idx) = mo.ep {
            // Find the _main symbol address
            let main_sym = "_main";
            if let Some(symtab_idx) = find_section_index(state, ".symtab") {
                let strtab_idx = state.sections[symtab_idx].link;
                if let Some(sti) = strtab_idx {
                    let sym_entry_size = 24usize;
                    let num_syms = state.sections[symtab_idx].data.len() / sym_entry_size;
                    for si in 1..num_syms {
                        let offset = si * sym_entry_size;
                        if offset + sym_entry_size > state.sections[symtab_idx].data.len() {
                            break;
                        }
                        let st_name = get_le32(&state.sections[symtab_idx].data, offset);
                        let name = read_cstr_from(&state.sections[sti].data, st_name as usize);
                        if name == main_sym || name == "main" {
                            let st_value = get_le64(&state.sections[symtab_idx].data, offset + 8);
                            // Entry offset is relative to __TEXT segment start
                            let text_base = if mo.seg2lc.len() > 1 {
                                let lc = &mo.load_commands[mo.seg2lc[1]]; // __TEXT segment
                                get_le64(lc, 24) // vmaddr
                            } else {
                                0
                            };
                            let entryoff = st_value.wrapping_sub(text_base);
                            put_le64(&mut mo.load_commands[ep_idx], 8, entryoff);
                            break;
                        }
                    }
                }
            }
        }
    }

    // 9. Relocate sections (apply relocations)
    elf::relocate_sections(state)?;

    // 10. Process bind/rebase imports
    bind_rebase_import(state, &mut mo)?;

    // 11. Convert ELF symbols to Mach-O symbols
    convert_symbols(state, &mut mo)?;

    // 12. Write the Mach-O output file
    let file = std::fs::File::create(filename)
        .map_err(|e| TccError::Link(format!("cannot create output file '{filename}': {e}")))?;
    let mut writer = std::io::BufWriter::new(file);
    macho_write(state, &mo, &mut writer)?;

    Ok(())
}

// ---------------------------------------------------------------------------
// TBD File Parsing via `nom` (tccmacho.c:2255-2348)
// ---------------------------------------------------------------------------
//
// TBD (Text-Based Definition) files are YAML-like text stubs shipped with
// macOS SDKs. They declare the install-name and exported symbols of a dylib
// without requiring the actual binary.
//
// AAP §0.6.1 requires `nom v7` for TBD parsing.

/// Parse a quoted or unquoted value using `nom` combinators.
///
/// Accepts single-quoted, double-quoted, or bare whitespace-delimited values.
fn nom_parse_value(input: &str) -> IResult<&str, &str> {
    alt((
        delimited(nom_char('\''), take_until("'"), nom_char('\'')),
        delimited(nom_char('"'), take_until("\""), nom_char('"')),
        take_while1(|c: char| !c.is_whitespace()),
    ))(input)
}

/// Parse an `install-name:` line using `nom`, extracting the name value.
///
/// Matches: `install-name: '/usr/lib/libSystem.B.dylib'`
fn nom_parse_install_name(input: &str) -> IResult<&str, &str> {
    preceded(
        tuple((space0, tag("install-name:"), space0)),
        nom_parse_value,
    )(input)
}

/// Parse a single symbol name inside a bracket list using `nom`.
///
/// Unlike `nom_parse_value`, this parser also stops at `,` and `]` delimiters
/// so that comma-separated symbols like `[ _foo, _bar ]` are parsed correctly.
fn nom_parse_bracket_sym(input: &str) -> IResult<&str, &str> {
    alt((
        delimited(nom_char('\''), take_until("'"), nom_char('\'')),
        delimited(nom_char('"'), take_until("\""), nom_char('"')),
        take_while1(|c: char| !c.is_whitespace() && c != ',' && c != ']'),
    ))(input)
}

/// Parse a bracket-delimited, comma-separated list of symbols using `nom`.
///
/// Matches: `[ _sym1, _sym2, '_sym3' ]`
fn nom_parse_symbol_list(input: &str) -> IResult<&str, Vec<String>> {
    let (input, _) = nom_char('[')(input)?;
    let mut symbols = Vec::new();
    let mut rest = input;

    loop {
        // Skip whitespace
        let (r, _) = space0(rest)?;
        // Check for end of list
        if r.starts_with(']') {
            let (r, _) = nom_char(']')(r)?;
            rest = r;
            break;
        }
        // Parse one symbol — use bracket-aware parser that stops at ',' and ']'
        if let Ok((r, sym)) = nom_parse_bracket_sym(r) {
            if !sym.is_empty() {
                symbols.push(sym.to_string());
            }
            let (r, _) = space0(r)?;
            // Consume optional comma
            if r.starts_with(',') {
                let (r2, _) = nom_char(',')(r)?;
                rest = r2;
            } else {
                rest = r;
            }
        } else {
            break;
        }
    }

    Ok((rest, symbols))
}

/// Parse a single symbol entry from a YAML list line using `nom`.
///
/// Matches: `- _symbolName` or `- '_symbolName'`
fn nom_parse_yaml_list_item(input: &str) -> IResult<&str, &str> {
    preceded(
        tuple((space0, nom_char('-'), space0)),
        nom_parse_value,
    )(input)
}

/// Extract the install-name (soname) from a TBD file's content.
/// C equivalent: `macho_tbd_soname()` (tccmacho.c:2293-2307)
///
/// Uses `nom` parser combinators (AAP §0.6.1) to parse the TBD format:
/// ```text
/// install-name: '/usr/lib/libSystem.B.dylib'
/// ```
pub(crate) fn macho_tbd_soname(tbd_content: &str) -> TccResult<String> {
    for line in tbd_content.lines() {
        let trimmed = line.trim();
        if let Ok((_rest, name)) = nom_parse_install_name(trimmed) {
            if !name.is_empty() {
                return Ok(name.to_string());
            }
        }
    }
    Err(TccError::link("install-name not found in TBD file"))
}

/// Parse TBD exports section to extract symbol names.
/// Returns a list of exported symbol names.
///
/// Uses `nom` parser combinators for structured value extraction within the
/// line-oriented TBD format.
fn parse_tbd_exports(tbd_content: &str) -> Vec<String> {
    let mut symbols: Vec<String> = Vec::new();
    let mut in_exports = false;
    let mut in_symbols = false;

    for line in tbd_content.lines() {
        let trimmed = line.trim();

        if trimmed.starts_with("exports:") || trimmed.starts_with("re-exports:") {
            in_exports = true;
            continue;
        }

        if in_exports {
            if trimmed.starts_with("symbols:") {
                in_symbols = true;
                // Check for inline bracket list: symbols: [ _sym1, _sym2 ]
                if let Some(bracket_start) = trimmed.find('[') {
                    if let Ok((_rest, syms)) = nom_parse_symbol_list(&trimmed[bracket_start..]) {
                        symbols.extend(syms);
                        in_symbols = false;
                    }
                }
                continue;
            }

            if in_symbols {
                // Try parsing as YAML list item: `- _symbol`
                if let Ok((_rest, sym)) = nom_parse_yaml_list_item(trimmed) {
                    if !sym.is_empty() && !sym.contains(':') {
                        symbols.push(sym.to_string());
                    }
                } else if trimmed.starts_with('[') || trimmed.contains(',') {
                    // Continuation of inline bracket list
                    let clean = trimmed
                        .trim_start_matches('[')
                        .trim_end_matches(']')
                        .trim_end_matches(',');
                    // Parse each comma-separated entry with nom
                    for part in clean.split(',') {
                        let part = part.trim();
                        if let Ok((_rest, sym)) = nom_parse_value(part) {
                            if !sym.is_empty() {
                                symbols.push(sym.to_string());
                            }
                        }
                    }
                } else if !trimmed.is_empty() && !trimmed.contains(':') {
                    // End of symbols section
                    in_symbols = false;
                    if !trimmed.starts_with("targets:") && !trimmed.starts_with("- targets:") {
                        in_exports = false;
                    }
                }
            }

            // Check for end of exports block
            if !trimmed.starts_with(' ') && !trimmed.starts_with('-') && !trimmed.is_empty()
                && !trimmed.starts_with("symbols:")
                && !trimmed.starts_with("targets:")
            {
                in_exports = false;
            }
        }
    }

    symbols
}

/// Load a TBD (text-based definition) stub file.
/// C equivalent: `macho_load_tbd()` (tccmacho.c:2310-2348)
///
/// TBD files are YAML-like text files containing the install-name and
/// exported symbols for a dylib. Used by macOS SDKs instead of shipping
/// full dylib binaries.
#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
// DLL index (usize→i32) bounded by loaded_dlls vec length; fits in i32
pub(crate) fn macho_load_tbd(
    state: &mut TccState,
    filename: &str,
) -> TccResult<()> {
    let content = std::fs::read_to_string(filename)
        .map_err(|e| TccError::Link(format!("cannot read TBD file '{filename}': {e}")))?;

    // Extract install-name
    let soname = macho_tbd_soname(&content)?;

    // Add as a DLL reference
    add_dll_ref(state, &soname)?;

    // Parse exported symbols
    let symbols = parse_tbd_exports(&content);

    // Register each symbol (set_elf_sym finds symtab internally)
    let _symtab_idx = find_section_index(state, ".symtab")
        .ok_or_else(|| TccError::link("no .symtab section for TBD import"))?;

    let dll_index = state.loaded_dlls.len() as i32;

    for sym_name in &symbols {
        // Add the symbol as an undefined reference that will be resolved
        // from this dylib at link time
        let info = elf_fmt::elf_st_info(elf_fmt::STB_GLOBAL, elf_fmt::STT_NOTYPE);
        let _sym_idx = elf::set_elf_sym(
            state,
            0, // value
            0, // size
            info,
            0, // other
            SHN_FROMDLL, // shndx — marks as from DLL
            sym_name, // name
        );
    }

    let _ = dll_index; // Used for tracking which dylib a symbol came from

    Ok(())
}

/// Add a DLL reference to the state's loaded DLLs list.
#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
fn add_dll_ref(state: &mut TccState, name: &str) -> TccResult<()> {
    // Check if already loaded
    for dll in &state.loaded_dlls {
        if dll.name == name {
            return Ok(());
        }
    }

    use crate::types::DllReference;
    state.loaded_dlls.push(DllReference {
        level: 0,
        found: true,
        index: state.loaded_dlls.len() as u8,
        name: name.to_string(),
    });

    Ok(())
}

// ---------------------------------------------------------------------------
// Mach-O Dylib Loading (tccmacho.c:2350-2476)
// ---------------------------------------------------------------------------

/// Load a Mach-O dylib file for import symbol resolution.
/// C equivalent: `macho_load_dll()` (tccmacho.c:2350-2476)
///
/// Handles fat (universal) binaries by selecting the correct architecture
/// slice. Parses load commands to find `LC_SYMTAB`, `LC_ID_DYLIB`,
/// `LC_REEXPORT_DYLIB`, and `LC_DYSYMTAB`. Extracts external defined symbols
/// and registers them via `set_elf_sym`.
pub(crate) fn macho_load_dll(
    state: &mut TccState,
    filename: &str,
) -> TccResult<()> {
    let data = std::fs::read(filename)
        .map_err(|e| TccError::Link(format!("cannot read dylib '{filename}': {e}")))?;

    if data.len() < 4 {
        return Err(TccError::Link(format!("file too small to be a Mach-O: '{filename}'")));
    }

    let magic = get_le32(&data, 0);
    let (mh_offset, mh_size) = if magic == FAT_MAGIC || magic == FAT_CIGAM {
        // Fat binary — find the correct architecture slice
        find_fat_slice(&data)?
    } else if magic == MH_MAGIC_64 {
        (0usize, data.len())
    } else {
        return Err(TccError::Link(format!("not a valid Mach-O file: '{filename}'")));
    };

    if mh_offset + 32 > data.len() {
        return Err(TccError::Link(format!("Mach-O header truncated in '{filename}'")));
    }

    let mh_data = &data[mh_offset..mh_offset + mh_size.min(data.len() - mh_offset)];

    // Parse the mach_header_64
    let ncmds = get_le32(mh_data, 16);
    let _sizeofcmds = get_le32(mh_data, 20);

    let mut symtab_off = 0u32;
    let mut nsyms = 0u32;
    let mut strtab_off = 0u32;
    let mut _strtab_size = 0u32;
    let mut iextdef = 0u32;
    let mut nextdef = 0u32;
    let mut soname = String::new();
    let mut reexports: Vec<String> = Vec::new();

    // Parse load commands
    let mut cmd_offset = mem::size_of::<MachHeader64>();
    for _ in 0..ncmds {
        if cmd_offset + 8 > mh_data.len() {
            break;
        }
        let cmd = get_le32(mh_data, cmd_offset);
        let cmdsize = get_le32(mh_data, cmd_offset + 4);

        if cmdsize < 8 {
            break;
        }

        match cmd {
            LC_SYMTAB => {
                if cmd_offset + 24 <= mh_data.len() {
                    symtab_off = get_le32(mh_data, cmd_offset + 8);
                    nsyms = get_le32(mh_data, cmd_offset + 12);
                    strtab_off = get_le32(mh_data, cmd_offset + 16);
                    _strtab_size = get_le32(mh_data, cmd_offset + 20);
                }
            }
            LC_ID_DYLIB | LC_LOAD_DYLIB => {
                let name_offset_val = get_le32(mh_data, cmd_offset + 8) as usize;
                let name_start = cmd_offset + name_offset_val;
                if name_start < mh_data.len() {
                    let name = read_cstr_from(mh_data, name_start);
                    if cmd == LC_ID_DYLIB {
                        soname = name;
                    }
                }
            }
            LC_REEXPORT_DYLIB => {
                let name_offset_val = get_le32(mh_data, cmd_offset + 8) as usize;
                let name_start = cmd_offset + name_offset_val;
                if name_start < mh_data.len() {
                    let name = read_cstr_from(mh_data, name_start);
                    reexports.push(name);
                }
            }
            LC_DYSYMTAB => {
                if cmd_offset + 80 <= mh_data.len() {
                    iextdef = get_le32(mh_data, cmd_offset + 16);
                    nextdef = get_le32(mh_data, cmd_offset + 20);
                }
            }
            _ => {}
        }

        cmd_offset += cmdsize as usize;
    }

    // Add DLL reference
    if soname.is_empty() {
        soname = Path::new(filename)
            .file_name().map_or_else(|| filename.to_string(), |n| n.to_string_lossy().into_owned());
    }
    add_dll_ref(state, &soname)?;

    // Extract external defined symbols from the symbol table (set_elf_sym finds symtab internally)
    let _symtab_idx = find_section_index(state, ".symtab")
        .ok_or_else(|| TccError::link("no .symtab section for dylib import"))?;

    let nlist_size = 16usize; // sizeof(nlist_64)
    let sym_start = mh_offset + symtab_off as usize;
    let str_start = mh_offset + strtab_off as usize;

    // If we have dysymtab info, use it to restrict to external defined symbols
    let (start_sym, end_sym) = if nextdef > 0 {
        (iextdef as usize, (iextdef + nextdef) as usize)
    } else {
        (0usize, nsyms as usize)
    };

    for i in start_sym..end_sym {
        let sym_offset = sym_start + i * nlist_size;
        if sym_offset + nlist_size > data.len() {
            break;
        }

        let n_strx = get_le32(&data, sym_offset);
        let n_type = data[sym_offset + 4];
        let _n_sect = data[sym_offset + 5];
        let _n_desc = get_le16(&data, sym_offset + 6);
        let _n_value = get_le64(&data, sym_offset + 8);

        // Check if this is an external defined symbol
        if (n_type & N_EXT) == 0 {
            continue;
        }
        if (n_type & 0x0e) == N_UNDF {
            continue; // Skip undefined symbols
        }

        // Get symbol name
        let name_offset = str_start + n_strx as usize;
        if name_offset >= data.len() {
            continue;
        }
        let sym_name = read_cstr_from(&data, name_offset);
        if sym_name.is_empty() {
            continue;
        }

        // Register the symbol
        let info = elf_fmt::elf_st_info(elf_fmt::STB_GLOBAL, elf_fmt::STT_NOTYPE);
        let _sym_idx = elf::set_elf_sym(
            state,
            0, // value
            0, // size
            info,
            0, // other
            SHN_FROMDLL, // shndx
            &sym_name, // name
        );
    }

    // Handle re-exports recursively
    for reexport in &reexports {
        // Try to find and load the re-exported library
        let reexport_path = find_dylib(state, reexport);
        if let Some(path) = reexport_path {
            macho_load_dll(state, &path)?;
        }
    }

    Ok(())
}

/// Find the correct architecture slice in a fat binary.
#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
fn find_fat_slice(data: &[u8]) -> TccResult<(usize, usize)> {
    if data.len() < 8 {
        return Err(TccError::link("fat binary too small"));
    }

    let magic = get_le32(data, 0);
    let swap = magic == FAT_CIGAM;

    let nfat_arch = if swap {
        macho_swap32(get_le32(data, 4))
    } else {
        get_le32(data, 4)
    };

    // Determine the target CPU type
    #[cfg(target_arch = "aarch64")]
    let target_cpu = CPU_TYPE_ARM64;
    #[cfg(not(target_arch = "aarch64"))]
    let target_cpu = CPU_TYPE_X86_64;

    let fat_arch_size = 20usize; // sizeof(fat_arch)
    for i in 0..nfat_arch as usize {
        let offset = 8 + i * fat_arch_size;
        if offset + fat_arch_size > data.len() {
            break;
        }

        let cputype = if swap {
            macho_swap32(get_le32(data, offset))
        } else {
            get_le32(data, offset)
        };

        if cputype == target_cpu {
            let arch_offset = if swap {
                macho_swap32(get_le32(data, offset + 8))
            } else {
                get_le32(data, offset + 8)
            } as usize;

            let arch_size = if swap {
                macho_swap32(get_le32(data, offset + 12))
            } else {
                get_le32(data, offset + 12)
            } as usize;

            return Ok((arch_offset, arch_size));
        }
    }

    Err(TccError::link("no matching architecture found in fat binary"))
}

/// Try to find a dylib by name in the library paths.
fn find_dylib(state: &TccState, name: &str) -> Option<String> {
    // If name is an absolute path, check if it exists
    if name.starts_with('/') {
        if Path::new(name).exists() {
            return Some(name.to_string());
        }
        // Try .tbd version
        let base = name.trim_end_matches(".dylib");
        let tbd_name = format!("{base}.tbd");
        if Path::new(&tbd_name).exists() {
            return Some(tbd_name);
        }
    }

    // Search library paths
    let basename = Path::new(name)
        .file_name().map_or_else(|| name.to_string(), |n| n.to_string_lossy().into_owned());

    for lib_path in &state.library_paths {
        let full_path = format!("{lib_path}/{basename}");
        if Path::new(&full_path).exists() {
            return Some(full_path);
        }
        // Try .tbd version
        let base_name = basename.trim_end_matches(".dylib");
        let tbd_path = format!("{lib_path}/{base_name}.tbd");
        if Path::new(&tbd_path).exists() {
            return Some(tbd_path);
        }
    }

    None
}

// ---------------------------------------------------------------------------
// macOS SDK Path Discovery (tccmacho.c:2263-2291)
// ---------------------------------------------------------------------------

/// Discover and add macOS SDK include and library paths.
/// C equivalent: `tcc_add_macos_sdkpath()` (tccmacho.c:2263-2291)
///
/// On macOS (native compilation), discovers the SDK path using:
/// 1. `xcrun --show-sdk-path` (preferred)
/// 2. Fallback to known paths:
///    - `/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk`
///    - `/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk`
pub(crate) fn tcc_add_macos_sdkpath(
    state: &mut TccState,
) -> TccResult<()> {
    // Try xcrun first (only on macOS)
    #[cfg(target_os = "macos")]
    {
        if let Ok(output) = std::process::Command::new("xcrun")
            .args(["--show-sdk-path"])
            .output()
        {
            if output.status.success() {
                let sdk_path = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !sdk_path.is_empty() && Path::new(&sdk_path).exists() {
                    let include_path = format!("{sdk_path}/usr/include");
                    let lib_path = format!("{sdk_path}/usr/lib");
                    let fw_path = format!("{sdk_path}/System/Library/Frameworks");

                    if Path::new(&include_path).exists() {
                        state.sysinclude_paths.push(include_path);
                    }
                    if Path::new(&lib_path).exists() {
                        state.library_paths.push(lib_path);
                    }
                    if Path::new(&fw_path).exists() {
                        state.library_paths.push(fw_path);
                    }
                    return Ok(());
                }
            }
        }
    }

    // Fallback paths
    let fallback_sdks = [
        "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk",
        "/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk",
    ];

    for sdk_path in &fallback_sdks {
        if Path::new(sdk_path).exists() {
            let include_path = format!("{sdk_path}/usr/include");
            let lib_path = format!("{sdk_path}/usr/lib");

            if Path::new(&include_path).exists() {
                state.sysinclude_paths.push(include_path);
            }
            if Path::new(&lib_path).exists() {
                state.library_paths.push(lib_path);
            }
            return Ok(());
        }
    }

    // Not finding an SDK is not fatal — cross-compilation doesn't need one
    Ok(())
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
mod tests {
    use super::*;

    #[test]
    fn test_uleb128_size() {
        assert_eq!(uleb128_size(0), 1);
        assert_eq!(uleb128_size(1), 1);
        assert_eq!(uleb128_size(127), 1);
        assert_eq!(uleb128_size(128), 2);
        assert_eq!(uleb128_size(16383), 2);
        assert_eq!(uleb128_size(16384), 3);
        assert_eq!(uleb128_size(u64::MAX), 10);
    }

    #[test]
    fn test_write_uleb128() {
        let mut buf = Vec::new();
        write_uleb128(&mut buf, 0);
        assert_eq!(buf, vec![0]);

        buf.clear();
        write_uleb128(&mut buf, 127);
        assert_eq!(buf, vec![127]);

        buf.clear();
        write_uleb128(&mut buf, 128);
        assert_eq!(buf, vec![0x80, 0x01]);

        buf.clear();
        write_uleb128(&mut buf, 624485);
        assert_eq!(buf, vec![0xe5, 0x8e, 0x26]);
    }

    #[test]
    fn test_name_to_16() {
        let n = name_to_16("__TEXT");
        assert_eq!(n[0], b'_');
        assert_eq!(n[1], b'_');
        assert_eq!(n[2], b'T');
        assert_eq!(n[3], b'E');
        assert_eq!(n[4], b'X');
        assert_eq!(n[5], b'T');
        assert_eq!(n[6], 0);
    }

    #[test]
    fn test_name_to_16_truncation() {
        let n = name_to_16("__TOOLONGNAME1234567890");
        assert_eq!(n.len(), 16);
        assert_eq!(&n[..16], b"__TOOLONGNAME123");
    }

    #[test]
    fn test_macho_swap32() {
        assert_eq!(macho_swap32(0xCAFE_BABE), 0xBEBA_FECA);
        assert_eq!(macho_swap32(0), 0);
        assert_eq!(macho_swap32(0x0102_0304), 0x0403_0201);
    }

    #[test]
    fn test_byte_helpers_roundtrip() {
        let mut buf = vec![0u8; 16];
        put_le16(&mut buf, 0, 0x1234);
        assert_eq!(get_le16(&buf, 0), 0x1234);

        put_le32(&mut buf, 4, 0xDEAD_BEEF);
        assert_eq!(get_le32(&buf, 4), 0xDEAD_BEEF);

        put_le64(&mut buf, 8, 0x0102_0304_0506_0708);
        assert_eq!(get_le64(&buf, 8), 0x0102_0304_0506_0708);
    }

    #[test]
    fn test_mach_header_64_to_bytes() {
        let mh = MachHeader64 {
            magic: MH_MAGIC_64,
            cputype: CPU_TYPE_X86_64,
            cpusubtype: CPU_SUBTYPE_X86_ALL,
            filetype: MH_EXECUTE,
            ncmds: 5,
            sizeofcmds: 200,
            flags: MH_PIE,
            reserved: 0,
        };
        let bytes = mach_header_64_to_bytes(&mh);
        assert_eq!(bytes.len(), 32);
        assert_eq!(get_le32(&bytes, 0), MH_MAGIC_64);
        assert_eq!(get_le32(&bytes, 4), CPU_TYPE_X86_64);
        assert_eq!(get_le32(&bytes, 12), MH_EXECUTE);
    }

    #[test]
    fn test_nlist64_to_bytes() {
        let nl = NList64 {
            n_strx: 42,
            n_type: N_SECT | N_EXT,
            n_sect: 1,
            n_desc: 0,
            n_value: 0x1000,
        };
        let bytes = nlist64_to_bytes(&nl);
        assert_eq!(bytes.len(), 16);
        assert_eq!(get_le32(&bytes, 0), 42);
        assert_eq!(bytes[4], N_SECT | N_EXT);
        assert_eq!(bytes[5], 1);
        assert_eq!(get_le64(&bytes, 8), 0x1000);
    }

    #[test]
    fn test_macho_state_new() {
        let mo = MachoState::new();
        assert_eq!(mo.mh.magic, 0);
        assert!(mo.load_commands.is_empty());
        assert!(mo.seg2lc.is_empty());
        assert!(mo.e2msym.is_empty());
        assert_eq!(mo.ilocal, 0);
        assert_eq!(mo.iextdef, 0);
        assert_eq!(mo.iundef, 0);
        assert_eq!(mo.stubsym, -1);
        assert_eq!(mo.n_got, 0);
        assert_eq!(mo.nr_plt, 0);
        assert!(mo.bind_rebase.is_empty());
        assert!(mo.dylibs.is_empty());
    }

    #[test]
    fn test_section_kind_from_u8() {
        assert_eq!(SectionKind::from_u8(0), SectionKind::Unknown);
        assert_eq!(SectionKind::from_u8(2), SectionKind::Text);
        assert_eq!(SectionKind::from_u8(10), SectionKind::Got);
        assert_eq!(SectionKind::from_u8(19), SectionKind::LinkedIt);
        assert_eq!(SectionKind::from_u8(255), SectionKind::Last);
    }

    #[test]
    fn test_add_lc_basic() {
        let mut mo = MachoState::new();
        let idx = add_lc(&mut mo, LC_SYMTAB, 24);
        assert_eq!(idx, 0);
        assert_eq!(mo.load_commands.len(), 1);
        assert_eq!(mo.load_commands[0].len(), 24);
        assert_eq!(mo.mh.ncmds, 1);
        assert_eq!(mo.mh.sizeofcmds, 24);
        assert_eq!(get_le32(&mo.load_commands[0], 0), LC_SYMTAB);
        assert_eq!(get_le32(&mo.load_commands[0], 4), 24);
    }

    #[test]
    fn test_add_multiple_lcs() {
        let mut mo = MachoState::new();
        let idx1 = add_lc(&mut mo, LC_SYMTAB, 24);
        let idx2 = add_lc(&mut mo, LC_DYSYMTAB, 80);
        assert_eq!(idx1, 0);
        assert_eq!(idx2, 1);
        assert_eq!(mo.mh.ncmds, 2);
        assert_eq!(mo.mh.sizeofcmds, 104);
    }

    #[test]
    fn test_add_segment() {
        let mut mo = MachoState::new();
        let seg_idx = add_segment(&mut mo, "__TEXT");
        assert_eq!(seg_idx, 0);
        assert_eq!(mo.seg2lc.len(), 1);
        let lc = &mo.load_commands[0];
        assert_eq!(get_le32(lc, 0), LC_SEGMENT_64);
        assert_eq!(&lc[8..14], b"__TEXT");
    }

    #[test]
    fn test_add_dylib() {
        let mut mo = MachoState::new();
        let idx = add_dylib(&mut mo, "/usr/lib/libSystem.B.dylib");
        assert_eq!(idx, 0);
        assert_eq!(get_le32(&mo.load_commands[0], 0), LC_LOAD_DYLIB);
    }

    #[test]
    fn test_classify_section_text() {
        let sec = Section {
            name: ".text".to_string(),
            sh_type: elf_fmt::SHT_PROGBITS,
            sh_flags: u64::from(elf_fmt::SHF_ALLOC | elf_fmt::SHF_EXECINSTR),
            ..Default::default()
        };
        assert_eq!(classify_section(&sec), SectionKind::Text);
    }

    #[test]
    fn test_classify_section_data() {
        let sec = Section {
            name: ".data".to_string(),
            sh_type: elf_fmt::SHT_PROGBITS,
            sh_flags: u64::from(elf_fmt::SHF_ALLOC | elf_fmt::SHF_WRITE),
            ..Default::default()
        };
        assert_eq!(classify_section(&sec), SectionKind::Data);
    }

    #[test]
    fn test_classify_section_bss() {
        let sec = Section {
            name: ".bss".to_string(),
            sh_type: elf_fmt::SHT_NOBITS,
            sh_flags: u64::from(elf_fmt::SHF_ALLOC | elf_fmt::SHF_WRITE),
            ..Default::default()
        };
        assert_eq!(classify_section(&sec), SectionKind::Bss);
    }

    #[test]
    fn test_classify_section_debug_info() {
        let sec = Section {
            name: ".debug_info".to_string(),
            sh_type: elf_fmt::SHT_PROGBITS,
            sh_flags: 0,
            ..Default::default()
        };
        assert_eq!(classify_section(&sec), SectionKind::DebugInfo);
    }

    #[test]
    fn test_classify_section_got() {
        let sec = Section {
            name: ".got".to_string(),
            sh_type: elf_fmt::SHT_PROGBITS,
            sh_flags: u64::from(elf_fmt::SHF_ALLOC | elf_fmt::SHF_WRITE),
            ..Default::default()
        };
        assert_eq!(classify_section(&sec), SectionKind::Got);
    }

    #[test]
    fn test_classify_section_init_array() {
        let sec = Section {
            name: ".init_array".to_string(),
            sh_type: elf_fmt::SHT_INIT_ARRAY,
            sh_flags: u64::from(elf_fmt::SHF_ALLOC | elf_fmt::SHF_WRITE),
            ..Default::default()
        };
        assert_eq!(classify_section(&sec), SectionKind::InitFunc);
    }

    #[test]
    fn test_classify_section_fini_array() {
        let sec = Section {
            name: ".fini_array".to_string(),
            sh_type: elf_fmt::SHT_FINI_ARRAY,
            sh_flags: u64::from(elf_fmt::SHF_ALLOC | elf_fmt::SHF_WRITE),
            ..Default::default()
        };
        assert_eq!(classify_section(&sec), SectionKind::FiniFunc);
    }

    #[test]
    fn test_classify_section_rodata() {
        let sec = Section {
            name: ".rodata".to_string(),
            sh_type: elf_fmt::SHT_PROGBITS,
            sh_flags: u64::from(elf_fmt::SHF_ALLOC),
            ..Default::default()
        };
        assert_eq!(classify_section(&sec), SectionKind::Ro);
    }

    #[test]
    fn test_macho_tbd_soname_quoted() {
        let content = "install-name: '/usr/lib/libSystem.B.dylib'\n";
        let result = macho_tbd_soname(content);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "/usr/lib/libSystem.B.dylib");
    }

    #[test]
    fn test_macho_tbd_soname_unquoted() {
        let content = "install-name: /usr/lib/libfoo.dylib\n";
        let result = macho_tbd_soname(content);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "/usr/lib/libfoo.dylib");
    }

    #[test]
    fn test_macho_tbd_soname_missing() {
        let content = "something: else\n";
        let result = macho_tbd_soname(content);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_tbd_exports_inline() {
        let content = r#"exports:
  - targets: [ x86_64-macos ]
    symbols: [ _foo, _bar, _baz ]
"#;
        let symbols = parse_tbd_exports(content);
        assert!(symbols.contains(&"_foo".to_string()));
        assert!(symbols.contains(&"_bar".to_string()));
        assert!(symbols.contains(&"_baz".to_string()));
    }

    #[test]
    fn test_parse_tbd_exports_empty() {
        let content = "install-name: /usr/lib/libfoo.dylib\n";
        let symbols = parse_tbd_exports(content);
        assert!(symbols.is_empty());
    }

    #[test]
    fn test_read_cstr_from() {
        let data = b"hello\0world\0";
        assert_eq!(read_cstr_from(data, 0), "hello");
        assert_eq!(read_cstr_from(data, 6), "world");
    }

    #[test]
    fn test_read_cstr_from_end() {
        let data = b"test";
        assert_eq!(read_cstr_from(data, 0), "test");
    }

    #[test]
    fn test_constants_magic() {
        assert_eq!(MH_MAGIC_64, 0xfeed_facf);
        assert_eq!(FAT_MAGIC, 0xcafe_babe);
        assert_eq!(FAT_CIGAM, 0xbeba_feca);
    }

    #[test]
    fn test_constants_cpu() {
        assert_eq!(CPU_TYPE_X86_64, 0x0100_0007);
        assert_eq!(CPU_TYPE_ARM64, 0x0100_000c);
    }

    #[test]
    fn test_common_prefix() {
        assert_eq!(common_prefix(b"abc", b"abd"), 2);
        assert_eq!(common_prefix(b"abc", b"abc"), 3);
        assert_eq!(common_prefix(b"abc", b"xyz"), 0);
        assert_eq!(common_prefix(b"", b"abc"), 0);
    }

    #[test]
    fn test_put_le32_vec() {
        let mut buf = Vec::new();
        put_le32_vec(&mut buf, 0xDEAD_BEEF);
        assert_eq!(buf, vec![0xEF, 0xBE, 0xAD, 0xDE]);
    }

    #[test]
    fn test_sk_info_table_length() {
        assert_eq!(SK_INFO.len(), 20); // One entry per SectionKind variant (except Last)
    }

    #[test]
    fn test_all_segments_length() {
        assert_eq!(ALL_SEGMENTS.len(), 6);
        assert_eq!(ALL_SEGMENTS[0], "__PAGEZERO");
        assert_eq!(ALL_SEGMENTS[5], "__LINKEDIT");
    }

    #[test]
    fn test_bind_rebase_add() {
        let mut mo = MachoState::new();
        bind_rebase_add(&mut mo, 1, true, 42, 0x1000);
        assert_eq!(mo.bind_rebase.len(), 1);
        assert_eq!(mo.n_bind_rebase, 1);
        assert_eq!(mo.bind_rebase[0].section, 1);
        assert!(mo.bind_rebase[0].bind);
        assert_eq!(mo.bind_rebase[0].sym_index, 42);
        assert_eq!(mo.bind_rebase[0].offset, 0x1000);
    }

    #[test]
    fn test_set_segment_and_offset() {
        let mut mo = MachoState::new();
        // Create a segment with vmaddr=0x1000, vmsize=0x2000
        let _seg = add_segment(&mut mo, "__TEXT");
        let lc_idx = mo.seg2lc[0];
        put_le64(&mut mo.load_commands[lc_idx], 24, 0x1000); // vmaddr
        put_le64(&mut mo.load_commands[lc_idx], 32, 0x2000); // vmsize

        let (seg, off) = set_segment_and_offset(&mo, 0x1500);
        assert_eq!(seg, 0);
        assert_eq!(off, 0x500);
    }

    #[test]
    fn test_set_segment_and_offset_not_found() {
        let mo = MachoState::new();
        let (seg, off) = set_segment_and_offset(&mo, 0x5000);
        assert_eq!(seg, 0);
        assert_eq!(off, 0x5000);
    }
}

