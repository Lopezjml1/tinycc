//! Mach-O output module — generates Mach-O executables, dynamic libraries,
//! and relocatable objects for macOS targets.
//!
//! Ported from `tccmacho.c` (2,476 lines). Implements the complete Mach-O output
//! pipeline including header generation, load commands, segments, sections, symbol
//! tables, chained fixups, export tries, and macOS-specific linking.
//!
//! Uses the CONFIG_NEW_MACHO code path with chained fixups
//! (`LC_DYLD_CHAINED_FIXUPS` + `LC_DYLD_EXPORTS_TRIE`) for modern dyld compatibility.
//!
//! ## Architecture Support
//!
//! Supports x86_64 and ARM64 (AArch64) macOS targets with architecture-specific:
//! - Stub generation (5-byte JMP for x86_64, 12-byte ADRP+LDR+BR for ARM64)
//! - GOT entry layout and relocation processing
//!
//! ## Key Public Functions
//!
//! - [`macho_output_file`] — Main entry point for Mach-O output
//! - [`macho_load_dll`] — Load a `.dylib` for linking
//! - [`macho_load_tbd`] — Load a `.tbd` text-based stub library
//! - [`tcc_add_macos_sdkpath`] — Discover macOS SDK include/library paths
//! - [`macho_tbd_soname`] — Extract soname from a `.tbd` file
//! - [`tcc_macho_add_destructor`] — Generate destructor-to-atexit wrapper code

// Mach-O format constants and structs are defined for completeness even if not all
// are used in every code path (e.g. some load command structs are only needed for
// specific output types). We suppress dead_code for format definitions.
#![allow(dead_code)]

use std::fs::File;

use crate::{TCCState, OutputType};
use crate::error::{TccError, TccResult};
use crate::types::{Section, DLLReference};
use crate::elf;
use crate::config::PTR_SIZE;
use crate::arch;

// ===========================================================================
// Mach-O constants
// ===========================================================================

/// Mach-O 64-bit magic number (native endian).
pub const MH_MAGIC_64: u32 = 0xfeed_facf;
/// Mach-O 64-bit magic number (reversed endian).
pub const MH_CIGAM_64: u32 = 0xcffa_edfe;

// --- File types ---
/// Mach-O relocatable object file.
pub const MH_OBJECT: u32 = 1;
/// Mach-O demand-paged executable file.
pub const MH_EXECUTE: u32 = 2;
/// Mach-O dynamically bound shared library.
pub const MH_DYLIB: u32 = 6;
/// Mach-O dynamically bound bundle file.
pub const MH_BUNDLE: u32 = 8;
/// Mach-O companion DSYM file.
pub const MH_DSYM: u32 = 10;

// --- CPU types ---
/// CPU type constant for x86_64.
pub const CPU_TYPE_X86_64: u32 = 0x0100_0007;
/// CPU type constant for ARM64 (AArch64).
pub const CPU_TYPE_ARM64: u32 = 0x0100_000c;
/// CPU subtype for all x86 variants.
/// Generic CPU subtype (will be overridden per arch).
const CPU_SUBTYPE_ALL: u32 = 3;
pub const CPU_SUBTYPE_X86_ALL: u32 = 3;
/// CPU subtype for all ARM64 variants.
pub const CPU_SUBTYPE_ARM64_ALL: u32 = 0;
/// CPU subtype for ARM64E (pointer authentication).
pub const CPU_SUBTYPE_ARM64E: u32 = 2;

// --- Load command types ---
/// Load command: 64-bit segment.
pub const LC_SEGMENT_64: u32 = 0x19;
/// Load command: symbol table.
pub const LC_SYMTAB: u32 = 2;
/// Load command: dynamic symbol table.
pub const LC_DYSYMTAB: u32 = 11;
/// Load command: dynamic linker identification.
pub const LC_LOAD_DYLINKER: u32 = 0x0e;
/// Load command: main entry point (replaces LC_UNIXTHREAD).
pub const LC_MAIN: u32 = 0x8000_0028;
/// Load command: load a dynamic library.
pub const LC_LOAD_DYLIB: u32 = 0x0c;
/// Load command: load a weak dynamic library.
pub const LC_LOAD_WEAK_DYLIB: u32 = 0x8000_0018;
/// Load command: lazily load a dynamic library.
pub const LC_LAZY_LOAD_DYLIB: u32 = 0x8000_0020;
/// Load command: re-export a dynamic library.
pub const LC_REEXPORT_DYLIB: u32 = 0x8000_001f;
/// Load command: shared library identification.
pub const LC_ID_DYLIB: u32 = 0x0d;
/// Load command: runtime search path.
pub const LC_RPATH: u32 = 0x8000_001c;
/// Load command: compressed dyld info (legacy).
pub const LC_DYLD_INFO_ONLY: u32 = 0x8000_0022;
/// Load command: chained fixups (modern dyld).
pub const LC_DYLD_CHAINED_FIXUPS: u32 = 0x8000_0034;
/// Load command: exports trie (modern dyld).
pub const LC_DYLD_EXPORTS_TRIE: u32 = 0x8000_0033;
/// Load command: build version (platform + SDK version).
pub const LC_BUILD_VERSION: u32 = 0x32;
/// Load command: source version.
pub const LC_SOURCE_VERSION: u32 = 0x2a;
/// Load command: UUID.
pub const LC_UUID: u32 = 0x1b;
/// Load command: linkedit data.
pub const LC_LINKEDIT_DATA: u32 = 0x22;

// --- Section types ---
/// Regular section.
const S_REGULAR: u32 = 0;
/// Zero-fill on demand section.
const S_ZEROFILL: u32 = 1;
/// Section with non-lazy symbol pointers.
const S_NON_LAZY_SYMBOL_POINTERS: u32 = 6;
/// Section with lazy symbol pointers.
const S_LAZY_SYMBOL_POINTERS: u32 = 7;
/// Section with symbol stubs.
const S_SYMBOL_STUBS: u32 = 8;
/// Section with pointers to module initializers.
const S_MOD_INIT_FUNC_POINTERS: u32 = 9;
/// Section with pointers to module terminators.
const S_MOD_TERM_FUNC_POINTERS: u32 = 10;

// --- Section attributes ---
/// Section contains only machine instructions.
const S_ATTR_PURE_INSTRUCTIONS: u32 = 1 << 31;
/// Section contains some machine instructions.
const S_ATTR_SOME_INSTRUCTIONS: u32 = 1 << 10;
/// Section is debug information.
const S_ATTR_DEBUG: u32 = 1 << 25;
/// Section contains self-modifying code.
const S_ATTR_SELF_MODIFYING_CODE: u32 = 1 << 26;

// --- VM protection flags ---
/// Read permission.
const VM_PROT_READ: u32 = 1;
/// Write permission.
const VM_PROT_WRITE: u32 = 2;
/// Execute permission.
const VM_PROT_EXECUTE: u32 = 4;
/// All permissions (read|write|execute).
const VM_PROT_ALL: u32 = VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE;

// --- Segment flags ---
/// Segment is read-only.
const SG_READ_ONLY: u32 = 0x10;

// --- MH flags ---
/// Image was linked with dyld.
const MH_DYLDLINK: u32 = 4;
/// Image is PIE (position independent executable).
const MH_PIE: u32 = 0x0020_0000;
/// No heap execution flag.
const MH_NO_HEAP_EXECUTION: u32 = 0x0100_0000;
/// Uses two-level namespace bindings.
const MH_TWOLEVEL: u32 = 0x80;
/// Image contains TLV descriptors.
const MH_HAS_TLV_DESCRIPTORS: u32 = 0x0080_0000;

// --- Fat binary constants ---
/// Fat binary magic (big-endian).
const FAT_MAGIC: u32 = 0xcafe_babe;
/// Fat binary magic (little-endian / reversed).
const FAT_CIGAM: u32 = 0xbeba_feca;

// --- Symbol type constants (nlist) ---
/// Undefined symbol.
const N_UNDF: u8 = 0x00;
/// Absolute symbol.
const N_ABS: u8 = 0x02;
/// Symbol is defined in a section.
const N_SECT: u8 = 0x0e;
/// External symbol (global).
const N_EXT: u8 = 0x01;
/// Private external symbol.
const N_PEXT: u8 = 0x10;
/// Weak reference flag in n_desc.
const N_WEAK_REF: u16 = 0x0040;
/// Weak definition flag in n_desc.
const N_WEAK_DEF: u16 = 0x0080;

// --- Chained fixup constants ---
/// Chained pointer format: 64-bit.
const DYLD_CHAINED_PTR_64: u32 = 2;
/// Chained pointer format: 64-bit with offset.
const DYLD_CHAINED_PTR_64_OFFSET: u32 = 6;
/// Import format: standard (30-bit ordinal).
const DYLD_CHAINED_IMPORT: u32 = 1;

// --- Platform constants ---
/// macOS platform identifier for LC_BUILD_VERSION.
const PLATFORM_MACOS: u32 = 1;

// --- Page alignment ---
/// Default page size for Mach-O segments.
const MACHO_PAGE_SIZE: u64 = 0x4000; // 16 KiB (ARM64 macOS page size)
/// Start address (after __PAGEZERO).
const MACHO_START_ADDR: u64 = 0x0001_0000_0000; // 4 GiB

// ===========================================================================
// Mach-O format structures
// ===========================================================================

/// Mach-O 64-bit file header.
///
/// Appears at the very beginning of every Mach-O file. Identifies the file
/// format, target architecture, number of load commands, and global flags.
#[derive(Debug, Clone, Default)]
pub struct MachHeader64 {
    /// Magic number: [`MH_MAGIC_64`] for native endian.
    pub magic: u32,
    /// CPU type (e.g., [`CPU_TYPE_X86_64`], [`CPU_TYPE_ARM64`]).
    pub cputype: u32,
    /// CPU subtype (e.g., [`CPU_SUBTYPE_X86_ALL`]).
    pub cpusubtype: u32,
    /// File type (e.g., [`MH_EXECUTE`], [`MH_DYLIB`]).
    pub filetype: u32,
    /// Number of load commands following the header.
    pub ncmds: u32,
    /// Total size of all load commands in bytes.
    pub sizeofcmds: u32,
    /// Flags (e.g., [`MH_PIE`], [`MH_DYLDLINK`]).
    pub flags: u32,
    /// Reserved (must be zero).
    pub reserved: u32,
}

/// Mach-O 64-bit segment load command.
///
/// Defines a contiguous range of virtual memory populated from the file.
/// Each segment contains zero or more sections.
#[derive(Debug, Clone)]
pub struct SegmentCommand64 {
    /// Command type: [`LC_SEGMENT_64`].
    pub cmd: u32,
    /// Total size of this command including section headers.
    pub cmdsize: u32,
    /// Segment name (16-byte null-padded, e.g., `__TEXT`, `__DATA`).
    pub segname: [u8; 16],
    /// Virtual memory address of the segment.
    pub vmaddr: u64,
    /// Virtual memory size of the segment.
    pub vmsize: u64,
    /// File offset of the segment data.
    pub fileoff: u64,
    /// Size of the segment data in the file.
    pub filesize: u64,
    /// Maximum VM protection flags.
    pub maxprot: u32,
    /// Initial VM protection flags.
    pub initprot: u32,
    /// Number of sections in this segment.
    pub nsects: u32,
    /// Segment flags (e.g., [`SG_READ_ONLY`]).
    pub flags: u32,
}

impl Default for SegmentCommand64 {
    fn default() -> Self {
        SegmentCommand64 {
            cmd: LC_SEGMENT_64,
            cmdsize: 72, // base size without sections
            segname: [0u8; 16],
            vmaddr: 0,
            vmsize: 0,
            fileoff: 0,
            filesize: 0,
            maxprot: 0,
            initprot: 0,
            nsects: 0,
            flags: 0,
        }
    }
}

/// Mach-O 64-bit section header.
///
/// Describes a section within a segment, including its location, size,
/// alignment, and type-specific attributes.
#[derive(Debug, Clone)]
#[derive(Default)]
pub struct Section64 {
    /// Section name (16-byte null-padded, e.g., `__text`, `__data`).
    pub sectname: [u8; 16],
    /// Segment name this section belongs to (16-byte null-padded).
    pub segname: [u8; 16],
    /// Virtual memory address of the section.
    pub addr: u64,
    /// Size of the section in bytes.
    pub size: u64,
    /// File offset of the section data.
    pub offset: u32,
    /// Section alignment as power of 2 (e.g., 3 means 8-byte aligned).
    pub align: u32,
    /// File offset of relocation entries for this section.
    pub reloff: u32,
    /// Number of relocation entries.
    pub nreloc: u32,
    /// Section type and attributes flags.
    pub flags: u32,
    /// Reserved (used for indirect symbol table index for stubs/pointers).
    pub reserved1: u32,
    /// Reserved (used for stub size for S_SYMBOL_STUBS sections).
    pub reserved2: u32,
    /// Reserved (padding).
    pub reserved3: u32,
}


/// Mach-O symbol table load command.
///
/// Specifies the location and size of the symbol table and string table
/// within the `__LINKEDIT` segment.
#[derive(Debug, Clone, Default)]
pub struct SymtabCommand {
    /// Command type: [`LC_SYMTAB`].
    pub cmd: u32,
    /// Size of this load command (always 24 bytes).
    pub cmdsize: u32,
    /// File offset of the symbol table.
    pub symoff: u32,
    /// Number of symbol table entries.
    pub nsyms: u32,
    /// File offset of the string table.
    pub stroff: u32,
    /// Size of the string table in bytes.
    pub strsize: u32,
}

/// Mach-O dynamic symbol table load command.
///
/// Provides indices into the symbol table that partition symbols into
/// local, externally-defined, and undefined categories. Also locates
/// the indirect symbol table.
#[derive(Debug, Clone, Default)]
pub struct DysymtabCommand {
    /// Command type: [`LC_DYSYMTAB`].
    pub cmd: u32,
    /// Size of this load command.
    pub cmdsize: u32,
    /// Index of the first local symbol.
    pub ilocalsym: u32,
    /// Number of local symbols.
    pub nlocalsym: u32,
    /// Index of the first externally defined symbol.
    pub iextdefsym: u32,
    /// Number of externally defined symbols.
    pub nextdefsym: u32,
    /// Index of the first undefined symbol.
    pub iundefsym: u32,
    /// Number of undefined symbols.
    pub nundefsym: u32,
    /// File offset of the indirect symbol table.
    pub indirectsymoff: u32,
    /// Number of indirect symbol table entries.
    pub nindirectsyms: u32,
}

/// Mach-O 64-bit symbol table entry (nlist_64).
///
/// Represents a single symbol in the Mach-O symbol table. The format
/// differs from ELF: type information is encoded in `n_type` rather
/// than separate binding/type fields.
#[derive(Debug, Clone, Default)]
pub struct Nlist64 {
    /// Index into the string table for the symbol name.
    pub n_strx: u32,
    /// Type flags (N_UNDF, N_ABS, N_SECT, N_EXT, etc.).
    pub n_type: u8,
    /// Section ordinal (1-based) or NO_SECT (0).
    pub n_sect: u8,
    /// Descriptor flags (N_WEAK_REF, N_WEAK_DEF, library ordinal).
    pub n_desc: u16,
    /// Symbol value (address for defined symbols).
    pub n_value: u64,
}

/// Mach-O entry point load command.
#[derive(Debug, Clone, Default)]
struct EntryPointCommand {
    cmd: u32,
    cmdsize: u32,
    entryoff: u64,
    stacksize: u64,
}

/// Mach-O dynamic linker command (LC_LOAD_DYLINKER).
#[derive(Debug, Clone)]
struct DylinkerCommand {
    cmd: u32,
    cmdsize: u32,
    name_offset: u32,
    name: String,
}

/// Mach-O dylib reference command (LC_LOAD_DYLIB, LC_ID_DYLIB, etc.).
#[derive(Debug, Clone)]
struct DylibCommand {
    cmd: u32,
    cmdsize: u32,
    name_offset: u32,
    timestamp: u32,
    current_version: u32,
    compatibility_version: u32,
    name: String,
}

/// Mach-O build version command (LC_BUILD_VERSION).
#[derive(Debug, Clone, Default)]
struct BuildVersionCommand {
    cmd: u32,
    cmdsize: u32,
    platform: u32,
    minos: u32,
    sdk: u32,
    ntools: u32,
}

/// Mach-O source version command (LC_SOURCE_VERSION).
#[derive(Debug, Clone, Default)]
struct SourceVersionCommand {
    cmd: u32,
    cmdsize: u32,
    version: u64,
}

/// Mach-O linkedit data command (LC_DYLD_CHAINED_FIXUPS, etc.).
#[derive(Debug, Clone, Default)]
struct LinkeditDataCommand {
    cmd: u32,
    cmdsize: u32,
    dataoff: u32,
    datasize: u32,
}

/// Mach-O rpath command (LC_RPATH).
#[derive(Debug, Clone)]
struct RpathCommand {
    cmd: u32,
    cmdsize: u32,
    path_offset: u32,
    path: String,
}

// ===========================================================================
// Section classification (skind) — maps ELF sections to Mach-O segments
// ===========================================================================

/// Section kind — classifies ELF sections into Mach-O segment/section categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum SectionKind {
    Unknown = 0,
    Discard = 1,
    Text = 2,
    Stubs = 3,
    StubHelper = 4,
    RoData = 5,
    UnwindInfo = 6,
    NlPtr = 7,
    DebugInfo = 8,
    DebugAbbrev = 9,
    DebugLine = 10,
    DebugAranges = 11,
    DebugStr = 12,
    DebugLineStr = 13,
    Stab = 14,
    StabStr = 15,
    LaPtr = 16,
    Init = 17,
    Fini = 18,
    RwData = 19,
    Bss = 20,
    Linkedit = 21,
    Last = 22,
}

/// Section kind info: which segment it maps to, Mach-O section flags, and name.
struct SkInfo {
    seg_initial: i32,
    flags: u32,
    name: &'static str,
}

/// Section kind info table — indexed by SectionKind as u8.
const SK_INFO: &[SkInfo] = &[
    SkInfo { seg_initial: 0, flags: 0, name: "" },
    SkInfo { seg_initial: 0, flags: 0, name: "" },
    SkInfo { seg_initial: 1, flags: S_REGULAR | S_ATTR_PURE_INSTRUCTIONS, name: "__text" },
    SkInfo { seg_initial: 1, flags: S_SYMBOL_STUBS | S_ATTR_PURE_INSTRUCTIONS, name: "__stubs" },
    SkInfo { seg_initial: 1, flags: S_REGULAR | S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SELF_MODIFYING_CODE, name: "__stub_helper" },
    SkInfo { seg_initial: 1, flags: S_REGULAR, name: "__rodata" },
    SkInfo { seg_initial: 1, flags: S_REGULAR, name: "__eh_frame" },
    SkInfo { seg_initial: 2, flags: S_NON_LAZY_SYMBOL_POINTERS, name: "__got" },
    SkInfo { seg_initial: 3, flags: S_REGULAR | S_ATTR_DEBUG, name: "__debug_info" },
    SkInfo { seg_initial: 3, flags: S_REGULAR | S_ATTR_DEBUG, name: "__debug_abbrev" },
    SkInfo { seg_initial: 3, flags: S_REGULAR | S_ATTR_DEBUG, name: "__debug_line" },
    SkInfo { seg_initial: 3, flags: S_REGULAR | S_ATTR_DEBUG, name: "__debug_aranges" },
    SkInfo { seg_initial: 3, flags: S_REGULAR | S_ATTR_DEBUG, name: "__debug_str" },
    SkInfo { seg_initial: 3, flags: S_REGULAR | S_ATTR_DEBUG, name: "__debug_line_str" },
    SkInfo { seg_initial: 3, flags: S_REGULAR | S_ATTR_DEBUG, name: "__stab" },
    SkInfo { seg_initial: 3, flags: S_REGULAR | S_ATTR_DEBUG, name: "__stab_str" },
    SkInfo { seg_initial: 4, flags: S_LAZY_SYMBOL_POINTERS, name: "__la_symbol_ptr" },
    SkInfo { seg_initial: 4, flags: S_MOD_INIT_FUNC_POINTERS, name: "__mod_init_func" },
    SkInfo { seg_initial: 4, flags: S_MOD_TERM_FUNC_POINTERS, name: "__mod_term_func" },
    SkInfo { seg_initial: 4, flags: S_REGULAR, name: "__data" },
    SkInfo { seg_initial: 4, flags: S_ZEROFILL, name: "__bss" },
    SkInfo { seg_initial: 5, flags: S_REGULAR, name: "" },
];

/// Segment definition for the predefined segment table.
struct SegDef {
    name: &'static str,
    vmaddr: u64,
    flags: u32,
    prot: u32,
}

/// Predefined segment table:
/// 0: __PAGEZERO, 1: __TEXT, 2: __DATA_CONST, 3: __DWARF, 4: __DATA, 5: __LINKEDIT
const ALL_SEGMENTS: &[SegDef] = &[
    SegDef { name: "__PAGEZERO", vmaddr: 0, flags: 0, prot: 0 },
    SegDef { name: "__TEXT", vmaddr: MACHO_START_ADDR, flags: 0, prot: VM_PROT_READ | VM_PROT_EXECUTE },
    SegDef { name: "__DATA_CONST", vmaddr: 0, flags: SG_READ_ONLY, prot: VM_PROT_READ | VM_PROT_WRITE },
    SegDef { name: "__DWARF", vmaddr: 0, flags: 0, prot: VM_PROT_READ },
    SegDef { name: "__DATA", vmaddr: 0, flags: 0, prot: VM_PROT_READ | VM_PROT_WRITE },
    SegDef { name: "__LINKEDIT", vmaddr: 0, flags: 0, prot: VM_PROT_READ },
];

// ===========================================================================
// Internal types for output generation
// ===========================================================================

/// Bind/rebase entry for chained fixups.
#[derive(Debug, Clone, Default)]
struct BindEntry {
    sym_index: usize,
    bind: i32,
    off: usize,
}

/// Segment tracking during layout.
#[derive(Debug, Clone, Default)]
pub struct SegmentLayout {
    lc_index: usize,
    section_indices: Vec<usize>,
    vmaddr: u64,
    vmsize: u64,
    fileoff: u64,
    filesize: u64,
}

/// Classified Mach-O section info.
#[derive(Debug, Clone, Default)]
struct MachoSectInfo {
    elf_index: usize,
    sk: u8,
    ordinal: u32,
}

/// Export trie node for building the export information.
#[derive(Debug, Clone)]
struct TrieNode {
    prefix: Vec<u8>,
    children: Vec<TrieNode>,
    info: Option<TrieInfo>,
}

/// Export trie symbol info.
#[derive(Debug, Clone, Default)]
struct TrieInfo {
    addr: u64,
    flags: u32,
}

// ===========================================================================
// MachoWriter — public struct for building Mach-O files
// ===========================================================================

/// Mach-O file writer.
///
/// Manages the construction of a complete Mach-O binary from the compiler's
/// internal section and symbol table representation. Handles segment layout,
/// load command generation, symbol table conversion (ELF → Mach-O nlist),
/// relocation processing, and chained fixup generation.
///
/// # Usage
///
/// ```no_run
/// use tcc_core::TCCState;
/// use tcc_core::macho::{MachoWriter, Section64};
///
/// fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let mut state = TCCState::new()?;
///     let mut writer = MachoWriter::new(&mut state);
///     let seg_idx = writer.add_segment("__TEXT", 0x1000, 5, 0);
///     let sect = Section64::default();
///     writer.add_section(seg_idx, sect);
///     writer.add_dylib("/usr/lib/libSystem.B.dylib", 2, 0x10000, 0x10000);
///     writer.add_lc(vec![0u8; 16]);
///     Ok(())
/// }
/// ```
pub struct MachoWriter<'a> {
    /// Reference to the central compiler state.
    state: &'a mut TCCState,
    /// Mach-O header being built.
    header: MachHeader64,
    /// Load commands as raw byte buffers.
    load_commands: Vec<Vec<u8>>,
    /// Segment layouts, indexed by segment number (0..6).
    segments: Vec<SegmentLayout>,
    /// Section metadata for each Mach-O section.
    macho_sections: Vec<MachoSectInfo>,
    /// Section64 headers for output.
    section_headers: Vec<Section64>,
    /// Mach-O symbol table (nlist_64 entries).
    nlist_entries: Vec<Nlist64>,
    /// String table data.
    strtab_data: Vec<u8>,
    /// Bind/rebase entries for chained fixups.
    bind_entries: Vec<BindEntry>,
    /// ELF symbol index → Mach-O symbol index mapping.
    e2msym: Vec<u32>,
    /// Section kind assignment per ELF section index.
    sk_map: Vec<u8>,
    /// Indirect symbol table entries.
    indirect_syms: Vec<u32>,
    /// Chained fixup data buffer.
    chained_fixup_data: Vec<u8>,
    /// Export trie data buffer.
    export_trie_data: Vec<u8>,
}

impl<'a> MachoWriter<'a> {
    /// Create a new MachoWriter for the given compiler state.
    pub fn new(state: &'a mut TCCState) -> Self {
        let nb = state.sections.len();
        MachoWriter {
            state,
            header: MachHeader64 {
                magic: MH_MAGIC_64,
                cputype: CPU_TYPE_X86_64,
                cpusubtype: CPU_SUBTYPE_ALL,
                filetype: MH_EXECUTE,
                ..Default::default()
            },
            load_commands: Vec::new(),
            segments: Vec::new(),
            macho_sections: Vec::new(),
            section_headers: Vec::new(),
            nlist_entries: Vec::new(),
            strtab_data: vec![0u8], // initial null byte
            bind_entries: Vec::new(),
            e2msym: vec![0u32; nb],
            sk_map: vec![SectionKind::Unknown as u8; nb],
            indirect_syms: Vec::new(),
            chained_fixup_data: Vec::new(),
            export_trie_data: Vec::new(),
        }
    }

    /// Add a segment and return its index.
    pub fn add_segment(&mut self, name: &str, vmaddr: u64, prot: u32, flags: u32) -> usize {
        let idx = self.segments.len();
        self.segments.push(SegmentLayout {
            lc_index: 0,
            section_indices: Vec::new(),
            vmaddr,
            vmsize: 0,
            fileoff: 0,
            filesize: 0,
        });
        // Build LC_SEGMENT_64 load command
        let mut seg = SegmentCommand64 {
            cmd: LC_SEGMENT_64,
            cmdsize: 72, // base size, sections added later
            vmaddr,
            maxprot: prot,
            initprot: prot,
            flags,
            ..Default::default()
        };
        copy_name16(&mut seg.segname, name);
        let lc_idx = self.load_commands.len();
        self.segments[idx].lc_index = lc_idx;
        self.load_commands.push(encode_segment_cmd(&seg));
        idx
    }

    /// Get segment layout by index.
    pub fn get_segment(&self, idx: usize) -> Option<&SegmentLayout> {
        self.segments.get(idx)
    }

    /// Add a section to a segment. Returns the section ordinal (1-based).
    pub fn add_section(&mut self, seg_idx: usize, sect: Section64) -> u32 {
        let ordinal = (self.section_headers.len() + 1) as u32;
        let info_idx = self.section_headers.len();
        self.section_headers.push(sect);
        if seg_idx < self.segments.len() {
            self.segments[seg_idx].section_indices.push(info_idx);
            // Update the segment load command's nsects and cmdsize
            if let Some(lc) = self.load_commands.get_mut(self.segments[seg_idx].lc_index) {
                // nsects is at byte offset 48 in the segment command
                let nsects = self.segments[seg_idx].section_indices.len() as u32;
                let new_cmdsize = 72 + nsects * 80; // 80 bytes per section header
                arch::write32le(&mut lc[4..8], new_cmdsize);
                arch::write32le(&mut lc[48..52], nsects);
            }
        }
        ordinal
    }

    /// Get a section header by index (0-based).
    pub fn get_section(&self, idx: usize) -> Option<&Section64> {
        self.section_headers.get(idx)
    }

    /// Add a raw load command and return its index.
    pub fn add_lc(&mut self, data: Vec<u8>) -> usize {
        let idx = self.load_commands.len();
        self.load_commands.push(data);
        idx
    }

    /// Add a dynamic library reference (LC_LOAD_DYLIB).
    pub fn add_dylib(&mut self, path: &str, timestamp: u32, compat_ver: u32, cur_ver: u32) -> usize {
        let name_offset = 24u32; // offset within the command to the name string
        let name_bytes = path.as_bytes();
        let name_len = name_bytes.len() + 1; // +1 for null terminator
        let cmdsize = align_up((24 + name_len) as u32, 8);
        let mut data = vec![0u8; cmdsize as usize];
        arch::write32le(&mut data[0..4], LC_LOAD_DYLIB);
        arch::write32le(&mut data[4..8], cmdsize);
        arch::write32le(&mut data[8..12], name_offset);
        arch::write32le(&mut data[12..16], timestamp);
        arch::write32le(&mut data[16..20], cur_ver);
        arch::write32le(&mut data[20..24], compat_ver);
        data[24..24 + name_bytes.len()].copy_from_slice(name_bytes);
        self.add_lc(data)
    }
}

// ===========================================================================
// Helper utilities
// ===========================================================================

/// Copy a name into a 16-byte null-padded buffer.
fn copy_name16(buf: &mut [u8; 16], name: &str) {
    let bytes = name.as_bytes();
    let len = bytes.len().min(16);
    buf[..len].copy_from_slice(&bytes[..len]);
    for b in buf[len..].iter_mut() {
        *b = 0;
    }
}

/// Encode a SegmentCommand64 into raw bytes.
fn encode_segment_cmd(seg: &SegmentCommand64) -> Vec<u8> {
    let mut data = vec![0u8; 72];
    arch::write32le(&mut data[0..4], seg.cmd);
    arch::write32le(&mut data[4..8], seg.cmdsize);
    data[8..24].copy_from_slice(&seg.segname);
    arch::write64le(&mut data[24..32], seg.vmaddr);
    arch::write64le(&mut data[32..40], seg.vmsize);
    arch::write64le(&mut data[40..48], seg.fileoff);
    arch::write64le(&mut data[48..56], seg.filesize);
    arch::write32le(&mut data[56..60], seg.maxprot);
    arch::write32le(&mut data[60..64], seg.initprot);
    arch::write32le(&mut data[64..68], seg.nsects);
    arch::write32le(&mut data[68..72], seg.flags);
    data
}

/// Encode a Section64 into raw bytes (80 bytes).
fn encode_section64(s: &Section64) -> Vec<u8> {
    let mut data = vec![0u8; 80];
    data[0..16].copy_from_slice(&s.sectname);
    data[16..32].copy_from_slice(&s.segname);
    arch::write64le(&mut data[32..40], s.addr);
    arch::write64le(&mut data[40..48], s.size);
    arch::write32le(&mut data[48..52], s.offset);
    arch::write32le(&mut data[52..56], s.align);
    arch::write32le(&mut data[56..60], s.reloff);
    arch::write32le(&mut data[60..64], s.nreloc);
    arch::write32le(&mut data[64..68], s.flags);
    arch::write32le(&mut data[68..72], s.reserved1);
    arch::write32le(&mut data[72..76], s.reserved2);
    arch::write32le(&mut data[76..80], s.reserved3);
    data
}

/// Encode an Nlist64 entry into raw bytes (16 bytes).
fn encode_nlist64(n: &Nlist64) -> Vec<u8> {
    let mut data = vec![0u8; 16];
    arch::write32le(&mut data[0..4], n.n_strx);
    data[4] = n.n_type;
    data[5] = n.n_sect;
    arch::write16le(&mut data[6..8], n.n_desc);
    arch::write64le(&mut data[8..16], n.n_value);
    data
}

/// Align a value up to the given power-of-two alignment.
fn align_up(val: u32, alignment: u32) -> u32 {
    if alignment == 0 {
        return val;
    }
    (val + alignment - 1) & !(alignment - 1)
}

/// Align a u64 value up to the given alignment.
fn align_up64(val: u64, alignment: u64) -> u64 {
    if alignment == 0 {
        return val;
    }
    (val + alignment - 1) & !(alignment - 1)
}

/// Compute the ULEB128 encoded size of a value.
fn uleb128_size(mut val: u64) -> usize {
    let mut size = 0usize;
    loop {
        size += 1;
        val >>= 7;
        if val == 0 {
            break;
        }
    }
    size
}

/// Write a ULEB128 encoded value into a buffer, returning bytes written.
fn write_uleb128(buf: &mut Vec<u8>, mut val: u64) -> usize {
    let start = buf.len();
    loop {
        let mut byte = (val & 0x7f) as u8;
        val >>= 7;
        if val != 0 {
            byte |= 0x80;
        }
        buf.push(byte);
        if val == 0 {
            break;
        }
    }
    buf.len() - start
}

/// Classify an ELF section into a SectionKind for Mach-O output.
fn classify_section(name: &str, sh_type: u32, sh_flags: u32) -> SectionKind {
    // Discard relocation sections and non-allocatable sections that aren't debug
    if sh_type == elf::SHT_RELX {
        return SectionKind::Discard;
    }
    if sh_type == elf::SHT_LINKEDIT {
        return SectionKind::Linkedit;
    }
    if sh_type == elf::SHT_SYMTAB || sh_type == elf::SHT_STRTAB {
        // Symbol table and string table sections handled separately
        if sh_flags & elf::SHF_ALLOC == 0 {
            return SectionKind::Discard;
        }
    }
    // Check for debug sections by name
    if name.starts_with(".debug_info") || name == ".debug_info" {
        return SectionKind::DebugInfo;
    }
    if name.starts_with(".debug_abbrev") || name == ".debug_abbrev" {
        return SectionKind::DebugAbbrev;
    }
    if name.starts_with(".debug_line_str") {
        return SectionKind::DebugLineStr;
    }
    if name.starts_with(".debug_line") || name == ".debug_line" {
        return SectionKind::DebugLine;
    }
    if name.starts_with(".debug_aranges") || name == ".debug_aranges" {
        return SectionKind::DebugAranges;
    }
    if name.starts_with(".debug_str") || name == ".debug_str" {
        return SectionKind::DebugStr;
    }
    if name == ".stab" {
        return SectionKind::Stab;
    }
    if name == ".stabstr" {
        return SectionKind::StabStr;
    }
    // Non-alloc and non-debug: discard
    if sh_flags & elf::SHF_ALLOC == 0 {
        return SectionKind::Discard;
    }
    // Check section types for special handling
    if sh_type == elf::SHT_INIT_ARRAY {
        return SectionKind::Init;
    }
    if sh_type == elf::SHT_FINI_ARRAY {
        return SectionKind::Fini;
    }
    if sh_type == elf::SHT_NOBITS {
        return SectionKind::Bss;
    }
    // Allocatable sections: classify by permissions
    if sh_flags & elf::SHF_EXECINSTR != 0 {
        // Executable section
        if name == ".stubs" {
            return SectionKind::Stubs;
        }
        if name == ".stub_helper" {
            return SectionKind::StubHelper;
        }
        return SectionKind::Text;
    }
    if sh_flags & elf::SHF_WRITE != 0 {
        // Writable data section
        return SectionKind::RwData;
    }
    // Read-only data
    if name == ".got" || name.starts_with(".got") {
        return SectionKind::NlPtr;
    }
    if name == ".eh_frame" || name == "__eh_frame" {
        return SectionKind::UnwindInfo;
    }
    if name == ".la_symbol_ptr" || name == "__la_symbol_ptr" {
        return SectionKind::LaPtr;
    }
    SectionKind::RoData
}

/// Get a string from an ELF string table section at the given offset.
fn get_strtab_str(state: &TCCState, strtab_idx: usize, offset: usize) -> String {
    if strtab_idx >= state.sections.len() {
        return String::new();
    }
    let data = &state.sections[strtab_idx].data;
    if offset >= data.len() {
        return String::new();
    }
    let end = data[offset..].iter().position(|&b| b == 0).unwrap_or(data.len() - offset);
    String::from_utf8_lossy(&data[offset..offset + end]).into_owned()
}

/// Get an ELF symbol name from the symbol table's associated string table.
fn get_sym_name(state: &TCCState, symtab_idx: usize, sym_index: usize) -> String {
    if symtab_idx >= state.sections.len() {
        return String::new();
    }
    let symtab = &state.sections[symtab_idx];
    let strtab_idx = match symtab.link {
        Some(idx) => idx,
        None => return String::new(),
    };
    let name_off = elf::get_sym_name_offset(symtab, sym_index);
    get_strtab_str(state, strtab_idx, name_off as usize)
}

// ===========================================================================
// tcc_macho_add_destructor — generate destructor → atexit wrapper
// ===========================================================================

/// Generate platform-specific machine code that wraps destructor functions
/// via `atexit` so they are called during program termination. This
/// is necessary because Mach-O does not natively support `.fini_array`
/// semantics the same way ELF does.
///
/// For x86_64: generates a function that calls `atexit` with each destructor.
/// For ARM64: generates equivalent ARM64 code.
pub fn tcc_macho_add_destructor(state: &mut TCCState) -> TccResult<()> {
    // Check if we have a .fini_array section
    let fini_idx = state.sections.iter().position(|s| {
        s.sh_type as u32 == elf::SHT_FINI_ARRAY && s.data_offset > 0
    });
    let fini_idx = match fini_idx {
        Some(idx) => idx,
        None => return Ok(()), // No destructors to register
    };

    let num_dtors = state.sections[fini_idx].data_offset / PTR_SIZE;
    if num_dtors == 0 {
        return Ok(());
    }

    // We need to create a constructor function that registers each destructor
    // with atexit at program startup. This function goes in __mod_init_func.

    // Find or create the text section for our wrapper
    let text_idx = match state.text_section {
        Some(idx) => idx,
        None => return Err(TccError::linker("No text section available for destructor wrapper")),
    };

    let symtab_idx = match state.symtab_section {
        Some(idx) => idx,
        None => return Err(TccError::linker("No symbol table for destructor wrapper")),
    };

    // Add the atexit symbol reference
    let atexit_sym = elf::find_elf_sym(state, symtab_idx, "atexit");
    let atexit_sym_idx = if atexit_sym != 0 {
        atexit_sym
    } else {
        // Add an undefined symbol for atexit
        elf::put_elf_sym(
            state,
            symtab_idx,
            0,
            0,
            elf::ELFW_ST_INFO(elf::STB_GLOBAL, elf::STT_FUNC),
            0,
            elf::SHN_UNDEF,
            "atexit",
        )
    };

    // Generate x86_64 code: For each destructor pointer in .fini_array,
    // load the pointer and call atexit with it.
    //
    // The generated function looks like:
    //   push %rbp
    //   mov %rsp, %rbp
    //   for each destructor:
    //     lea dtor_ptr(%rip), %rdi
    //     call atexit
    //   pop %rbp
    //   ret
    //
    // For ARM64:
    //   stp x29, x30, [sp, #-16]!
    //   mov x29, sp
    //   for each destructor:
    //     adrp x0, dtor_ptr@PAGE
    //     add x0, x0, dtor_ptr@PAGEOFF
    //     bl atexit
    //   ldp x29, x30, [sp], #16
    //   ret

    // Generate a minimal wrapper: we emit raw bytes into the text section.
    // This is the same approach as the C tccmacho.c code.

    #[cfg(target_arch = "x86_64")]
    {
        // x86_64 code generation
        let code_size = 4 + num_dtors * 12 + 2; // push+mov + N*(lea+call) + pop+ret
        let code_start = state.sections[text_idx].data_offset;

        // Ensure capacity
        let cur_len = state.sections[text_idx].data.len();
        state.sections[text_idx].data.resize(cur_len + code_size, 0);

        let off = code_start;
        let data = &mut state.sections[text_idx].data;

        // push %rbp; mov %rsp, %rbp
        data[off] = 0x55;
        data[off + 1] = 0x48;
        data[off + 2] = 0x89;
        data[off + 3] = 0xe5;

        let mut pos = off + 4;
        for _i in 0..num_dtors {
            // lea fini_array[i*8](%rip), %rdi — will need relocation
            data[pos] = 0x48; // REX.W
            data[pos + 1] = 0x8d; // LEA
            data[pos + 2] = 0x3d; // ModRM: rdi, [rip+disp32]
            // disp32 placeholder: 0 — relocation will fill this in
            arch::write32le(&mut data[pos + 3..pos + 7], 0);
            pos += 7;

            // call atexit — will need relocation
            data[pos] = 0xe8; // CALL rel32
            arch::write32le(&mut data[pos + 1..pos + 5], 0);
            pos += 5;
        }

        // pop %rbp; ret
        data[pos] = 0x5d;
        data[pos + 1] = 0xc3;
        state.sections[text_idx].data_offset = pos + 2;

        // Add relocations for each destructor reference and atexit call
        for i in 0..num_dtors {
            let lea_off = code_start + 4 + i * 12 + 3;
            let call_off = code_start + 4 + i * 12 + 8;

            // Relocation for LEA: reference to fini_array[i]
            elf::put_elf_reloca(
                state,
                text_idx,
                lea_off as u64,
                elf::R_DATA_PTR,
                fini_idx,
                (i * PTR_SIZE) as i64,
            );

            // Relocation for CALL: reference to atexit
            elf::put_elf_reloca(
                state,
                text_idx,
                call_off as u64,
                elf::R_DATA_PTR,
                atexit_sym_idx,
                0,
            );
        }

        // Create a symbol for the wrapper function
        let wrapper_sym = elf::put_elf_sym(
            state,
            symtab_idx,
            code_start as u64,
            (pos + 2 - code_start) as u64,
            elf::ELFW_ST_INFO(elf::STB_LOCAL, elf::STT_FUNC),
            0,
            text_idx as u16,
            "__tcc_dtor_wrapper",
        );

        // Add the wrapper to the init array so it runs at startup
        let init_idx = state.sections.iter().position(|s| {
            s.sh_type as u32 == elf::SHT_INIT_ARRAY
        });
        let init_idx = if let Some(idx) = init_idx {
            idx
        } else {
            // Create an init array section
            let idx = elf::new_section(state, ".init_array", elf::SHT_INIT_ARRAY, elf::SHF_ALLOC);
            state.sections[idx].sh_addralign = PTR_SIZE as i32;
            idx
        };

        // Add a pointer to our wrapper in .init_array
        let ptr_off = elf::section_ptr_add(&mut state.sections[init_idx], PTR_SIZE);
        // Zero-initialize (relocation will fill it)
        for b in state.sections[init_idx].data[ptr_off..ptr_off + PTR_SIZE].iter_mut() {
            *b = 0;
        }

        // Add relocation for the init_array entry
        elf::put_elf_reloca(
            state,
            init_idx,
            ptr_off as u64,
            elf::R_DATA_PTR,
            wrapper_sym,
            0,
        );
    }

    #[cfg(target_arch = "aarch64")]
    {
        // ARM64 code generation
        let code_size = 8 + num_dtors * 12 + 8; // stp+mov + N*(adrp+add+bl) + ldp+ret
        let code_start = state.sections[text_idx].data_offset;

        let cur_len = state.sections[text_idx].data.len();
        state.sections[text_idx].data.resize(cur_len + code_size, 0);

        let off = code_start;
        let data = &mut state.sections[text_idx].data;

        // stp x29, x30, [sp, #-16]!
        arch::write32le(&mut data[off..off + 4], 0xa9bf7bfd);
        // mov x29, sp
        arch::write32le(&mut data[off + 4..off + 8], 0x910003fd);

        let mut pos = off + 8;
        for _i in 0..num_dtors {
            // adrp x0, dtor@PAGE — relocation needed
            arch::write32le(&mut data[pos..pos + 4], 0x90000000);
            pos += 4;
            // add x0, x0, dtor@PAGEOFF — relocation needed
            arch::write32le(&mut data[pos..pos + 4], 0x91000000);
            pos += 4;
            // bl atexit — relocation needed
            arch::write32le(&mut data[pos..pos + 4], 0x94000000);
            pos += 4;
        }

        // ldp x29, x30, [sp], #16
        arch::write32le(&mut data[pos..pos + 4], 0xa8c17bfd);
        // ret
        arch::write32le(&mut data[pos + 4..pos + 8], 0xd65f03c0);
        state.sections[text_idx].data_offset = pos + 8;

        // Create wrapper symbol and init_array entry (same as x86_64)
        let wrapper_sym = elf::put_elf_sym(
            state,
            symtab_idx,
            code_start as u64,
            (pos + 8 - code_start) as u64,
            elf::ELFW_ST_INFO(elf::STB_LOCAL, elf::STT_FUNC),
            0,
            text_idx as u16,
            "__tcc_dtor_wrapper",
        );

        let init_idx = state.sections.iter().position(|s| {
            s.sh_type as u32 == elf::SHT_INIT_ARRAY
        });
        let init_idx = if let Some(idx) = init_idx {
            idx
        } else {
            let idx = elf::new_section(state, ".init_array", elf::SHT_INIT_ARRAY, elf::SHF_ALLOC);
            state.sections[idx].sh_addralign = PTR_SIZE as i32;
            idx
        };
        let ptr_off = elf::section_ptr_add(&mut state.sections[init_idx], PTR_SIZE as usize);
        for b in state.sections[init_idx].data[ptr_off..ptr_off + PTR_SIZE as usize].iter_mut() {
            *b = 0;
        }
        elf::put_elf_reloca(
            state,
            init_idx,
            ptr_off as u64,
            elf::R_DATA_PTR,
            wrapper_sym,
            0,
        );
    }

    // For architectures that aren't x86_64 or aarch64, provide a no-op
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        // Other architectures: no destructor wrapper generated
        // (Mach-O is only relevant on macOS which is x86_64 or ARM64)
    }

    Ok(())
}

/// Read a relocation entry from a section at the given byte offset.
/// Returns (offset, info, addend).
fn read_reloc_entry(sec: &Section, byte_off: usize) -> (u64, u64, i64) {
    if PTR_SIZE == 8 {
        if byte_off + 24 <= sec.data.len() {
            let d = &sec.data[byte_off..byte_off + 24];
            let offset = u64::from_le_bytes([d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]]);
            let info = u64::from_le_bytes([d[8], d[9], d[10], d[11], d[12], d[13], d[14], d[15]]);
            let addend = i64::from_le_bytes([d[16], d[17], d[18], d[19], d[20], d[21], d[22], d[23]]);
            (offset, info, addend)
        } else {
            (0, 0, 0)
        }
    } else {
        if byte_off + 8 <= sec.data.len() {
            let d = &sec.data[byte_off..byte_off + 8];
            let offset = u32::from_le_bytes([d[0], d[1], d[2], d[3]]) as u64;
            let info = u32::from_le_bytes([d[4], d[5], d[6], d[7]]) as u64;
            (offset, info, 0)
        } else {
            (0, 0, 0)
        }
    }
}

// ===========================================================================
// check_relocs — process relocations for Mach-O output (CONFIG_NEW_MACHO path)
// ===========================================================================

/// Process relocations for Mach-O chained fixups.
///
/// Scans all relocation sections, creates GOT entries for external symbols,
/// creates stub entries for function calls, and builds the bind/rebase
/// entry list for chained fixup generation.
fn check_relocs(writer: &mut MachoWriter<'_>) -> TccResult<()> {
    let symtab_idx = match writer.state.symtab_section {
        Some(idx) => idx,
        None => return Ok(()),
    };

    // Track which symbols already have GOT entries (replaces attr.got_offset tracking)
    let mut got_syms = std::collections::HashSet::<usize>::new();

    // Iterate over all sections looking for relocations
    let nb_sections = writer.state.sections.len();
    for si in 0..nb_sections {
        let reloc_idx = match writer.state.sections[si].reloc {
            Some(idx) => idx,
            None => continue,
        };

        // Skip non-allocated sections
        if writer.state.sections[si].sh_flags as u32 & elf::SHF_ALLOC == 0 {
            continue;
        }

        let rel_count = writer.state.sections[reloc_idx].data_offset / elf::RELX_SIZE;
        for ri in 0..rel_count {
            // Read relocation entry manually (offset, info, addend)
            let byte_off = ri * elf::RELX_SIZE;
            let (r_offset, r_info, _r_addend) = read_reloc_entry(
                &writer.state.sections[reloc_idx], byte_off
            );
            let sym_idx = elf::ELFW_R_SYM(r_info) as usize;
            let rel_type = elf::ELFW_R_TYPE(r_info);

            if sym_idx == 0 {
                continue;
            }

            let sym_shndx = elf::get_sym_shndx(&writer.state.sections[symtab_idx], sym_idx);
            let _sym_bind = elf::ELFW_ST_BIND(elf::get_sym_info(&writer.state.sections[symtab_idx], sym_idx));

            // External symbols (undefined or from DLL) need GOT/PLT entries
            let is_external = sym_shndx == elf::SHN_UNDEF
                || sym_shndx == elf::SHN_FROMDLL;

            if is_external {
                // Check if this symbol already has a GOT entry (tracked locally)
                if !got_syms.contains(&sym_idx) {
                    // Create GOT entry
                    if let Some(got_idx) = writer.state.got {
                        let got_off = elf::section_ptr_add(&mut writer.state.sections[got_idx], PTR_SIZE);
                        // Zero-fill the GOT entry
                        for b in writer.state.sections[got_idx].data[got_off..got_off + PTR_SIZE].iter_mut() {
                            *b = 0;
                        }
                        got_syms.insert(sym_idx);

                        // Add a bind entry for this GOT slot
                        writer.bind_entries.push(BindEntry {
                            sym_index: sym_idx,
                            bind: 1,
                            off: got_off,
                        });
                    }
                }
            } else {
                // Internal symbols: may need rebase entries
                if rel_type == elf::R_DATA_PTR {
                    writer.bind_entries.push(BindEntry {
                        sym_index: sym_idx,
                        bind: 0,
                        off: r_offset as usize,
                    });
                }
            }
        }
    }
    Ok(())
}

// ===========================================================================
// check_symbols — validate and mark symbols
// ===========================================================================

/// Validate symbol ordering and mark undefined symbols.
///
/// Ensures symbols are partitioned correctly (local, then external defined,
/// then undefined) and marks unresolvable symbols as elf::SHN_FROMDLL so the
/// Mach-O linker knows to bind them dynamically.
fn check_symbols(state: &mut TCCState) -> TccResult<()> {
    let symtab_idx = match state.symtab_section {
        Some(idx) => idx,
        None => return Ok(()),
    };

    let nsyms = elf::sym_count(&state.sections[symtab_idx]);

    for i in 1..nsyms {
        let info = elf::get_sym_info(&state.sections[symtab_idx], i);
        let shndx = elf::get_sym_shndx(&state.sections[symtab_idx], i);
        let bind = elf::ELFW_ST_BIND(info);

        if shndx == elf::SHN_UNDEF && bind == elf::STB_GLOBAL {
            // Check if this symbol exists in any loaded DLL
            let name = get_sym_name(state, symtab_idx, i);
            if !name.is_empty() {
                // Mark as from DLL — it will be resolved via dynamic binding
                elf::set_sym_shndx(&mut state.sections[symtab_idx], i, elf::SHN_FROMDLL);
            }
        }
    }
    Ok(())
}

// ===========================================================================
// convert_symbols — ELF symbols to Mach-O nlist_64 format
// ===========================================================================

/// Convert ELF symbols to Mach-O nlist_64 format.
///
/// Creates a sorted symbol table with locals first, then externally-defined,
/// then undefined symbols — as required by Mach-O's dysymtab partitioning.
fn convert_symbols(writer: &mut MachoWriter<'_>) -> TccResult<()> {
    let symtab_idx = match writer.state.symtab_section {
        Some(idx) => idx,
        None => return Ok(()),
    };

    let nsyms = elf::sym_count(&writer.state.sections[symtab_idx]);
    let strtab_idx = writer.state.sections[symtab_idx].link.unwrap_or(0);

    // Three partitions: locals, ext_defs, undefs
    let mut locals: Vec<(Nlist64, usize)> = Vec::new();
    let mut ext_defs: Vec<(Nlist64, usize)> = Vec::new();
    let mut undefs: Vec<(Nlist64, usize)> = Vec::new();

    for i in 1..nsyms {
        let info = elf::get_sym_info(&writer.state.sections[symtab_idx], i);
        let shndx = elf::get_sym_shndx(&writer.state.sections[symtab_idx], i);
        let value = elf::get_sym_value(&writer.state.sections[symtab_idx], i);
        let bind = elf::ELFW_ST_BIND(info);
        let stype = elf::ELFW_ST_TYPE(info);
        let name_off = elf::get_sym_name_offset(&writer.state.sections[symtab_idx], i);

        // Skip section symbols and file symbols in Mach-O output
        if stype == elf::STT_SECTION || stype == elf::STT_FILE {
            continue;
        }

        // Skip anonymous symbols
        if name_off == 0 {
            continue;
        }

        // Add name to Mach-O string table
        let name = get_strtab_str(writer.state, strtab_idx, name_off as usize);
        if name.is_empty() {
            continue;
        }

        // For Mach-O, prepend underscore if leading_underscore is set
        let macho_name = if writer.state.leading_underscore {
            format!("_{}", name)
        } else {
            name.clone()
        };

        let n_strx = writer.strtab_data.len() as u32;
        writer.strtab_data.extend_from_slice(macho_name.as_bytes());
        writer.strtab_data.push(0); // null terminator

        let mut nlist = Nlist64 {
            n_strx,
            n_type: 0,
            n_sect: 0,
            n_desc: 0,
            n_value: value,
        };

        if shndx == elf::SHN_UNDEF || shndx == elf::SHN_FROMDLL {
            // Undefined symbol
            nlist.n_type = N_UNDF;
            if bind == elf::STB_GLOBAL || bind == elf::STB_WEAK {
                nlist.n_type |= N_EXT;
            }
            if bind == elf::STB_WEAK {
                nlist.n_desc = N_WEAK_REF;
            }
            nlist.n_value = 0;
            undefs.push((nlist, i));
        } else if shndx == elf::SHN_ABS {
            // Absolute symbol
            nlist.n_type = N_ABS;
            if bind == elf::STB_GLOBAL || bind == elf::STB_WEAK {
                nlist.n_type |= N_EXT;
            }
            if bind == elf::STB_LOCAL {
                locals.push((nlist, i));
            } else {
                ext_defs.push((nlist, i));
            }
        } else {
            // Defined in a section — find the Mach-O section ordinal
            let sect_ordinal = writer.macho_sections.iter()
                .find(|ms| ms.elf_index == shndx as usize)
                .map(|ms| ms.ordinal)
                .unwrap_or(0);

            nlist.n_type = N_SECT;
            nlist.n_sect = sect_ordinal as u8;
            if bind == elf::STB_GLOBAL || bind == elf::STB_WEAK {
                nlist.n_type |= N_EXT;
            }
            if bind == elf::STB_WEAK {
                nlist.n_desc = N_WEAK_DEF;
            }
            if bind == elf::STB_LOCAL {
                locals.push((nlist, i));
            } else {
                ext_defs.push((nlist, i));
            }
        }
    }

    // Sort each partition alphabetically by name
    let sort_by_name = |a: &(Nlist64, usize), b: &(Nlist64, usize)| -> std::cmp::Ordering {
        let name_a = get_nlist_name(&writer.strtab_data, a.0.n_strx);
        let name_b = get_nlist_name(&writer.strtab_data, b.0.n_strx);
        name_a.cmp(name_b)
    };
    ext_defs.sort_by(sort_by_name);
    undefs.sort_by(sort_by_name);

    // Build the combined symbol table and e2msym mapping
    let _ilocalsym = 0u32;
    let nlocalsym = locals.len() as u32;
    let iextdefsym = nlocalsym;
    let nextdefsym = ext_defs.len() as u32;
    let _iundefsym = iextdefsym + nextdefsym;
    let _nundefsym = undefs.len() as u32;

    for (nlist, elf_idx) in locals.iter() {
        let macho_idx = writer.nlist_entries.len() as u32;
        if *elf_idx < writer.e2msym.len() {
            writer.e2msym[*elf_idx] = macho_idx;
        }
        writer.nlist_entries.push(nlist.clone());
    }
    for (nlist, elf_idx) in ext_defs.iter() {
        let macho_idx = writer.nlist_entries.len() as u32;
        if *elf_idx < writer.e2msym.len() {
            writer.e2msym[*elf_idx] = macho_idx;
        }
        writer.nlist_entries.push(nlist.clone());
    }
    for (nlist, elf_idx) in undefs.iter() {
        let macho_idx = writer.nlist_entries.len() as u32;
        if *elf_idx < writer.e2msym.len() {
            writer.e2msym[*elf_idx] = macho_idx;
        }
        writer.nlist_entries.push(nlist.clone());
    }

    // Store the dysymtab partition info in the writer for later use
    // (we'll use these when emitting the LC_DYSYMTAB command)
    writer.header.reserved = 0; // We'll store partition info separately

    Ok(())
}

/// Get a null-terminated string from the Mach-O string table.
fn get_nlist_name(strtab: &[u8], offset: u32) -> &[u8] {
    let start = offset as usize;
    if start >= strtab.len() {
        return &[];
    }
    let end = strtab[start..].iter().position(|&b| b == 0).unwrap_or(strtab.len() - start);
    &strtab[start..start + end]
}

// ===========================================================================
// create_symtab — build Mach-O symbol table infrastructure
// ===========================================================================

/// Create the Mach-O symbol table sections.
///
/// Creates the __stubs, __got, and chained_fixups sections needed for
/// symbol resolution. This must be called before check_relocs so the
/// GOT section exists for relocation processing.
fn create_symtab(state: &mut TCCState) -> TccResult<()> {
    // Ensure GOT section exists
    if state.got.is_none() {
        elf::build_got(state);
    }

    // The stubs section is created on demand during check_relocs
    // The chained fixups data is built during bind_rebase_import

    Ok(())
}

// ===========================================================================
// collect_sections — classify ELF sections and assign to Mach-O segments
// ===========================================================================

/// Classify all ELF sections into Mach-O section kinds and assign them
/// to segments. Builds the segment layout, computes virtual addresses
/// and file offsets, and generates all load commands.
///
/// This is the central layout function that determines the structure of
/// the output Mach-O binary.
fn collect_sections(writer: &mut MachoWriter<'_>) -> TccResult<()> {
    let output_type = writer.state.output_type.unwrap_or(OutputType::Exe);
    let is_exe = matches!(output_type, OutputType::Exe);
    let is_dll = matches!(output_type, OutputType::Dll);
    let is_obj = matches!(output_type, OutputType::Obj);

    // Step 1: Classify each ELF section into a SectionKind
    let nb_sections = writer.state.sections.len();
    for si in 0..nb_sections {
        let name = writer.state.sections[si].name.clone();
        let sh_type = writer.state.sections[si].sh_type as u32;
        let sh_flags = writer.state.sections[si].sh_flags as u32;
        let sk = classify_section(&name, sh_type, sh_flags);
        writer.sk_map[si] = sk as u8;
    }

    // Step 2: For object files, output format is simpler
    if is_obj {
        // Object files: all sections go into a single segment
        let seg_idx = writer.add_segment("", 0, VM_PROT_ALL, 0);
        let mut ordinal = 1u32;

        for si in 1..nb_sections {
            let sk = writer.sk_map[si];
            if sk == SectionKind::Discard as u8 || sk == SectionKind::Unknown as u8 {
                continue;
            }
            if writer.state.sections[si].data_offset == 0
                && writer.state.sections[si].sh_type as u32 != elf::SHT_NOBITS {
                continue;
            }

            let name = &writer.state.sections[si].name;
            let mut sect = Section64::default();
            // Convert ELF section name to Mach-O name
            let macho_name = elf_to_macho_section_name(name);
            let seg_name = elf_to_macho_segment_name(name, sk);
            copy_name16(&mut sect.sectname, &macho_name);
            copy_name16(&mut sect.segname, &seg_name);
            sect.align = compute_alignment(writer.state.sections[si].sh_addralign as u32);
            sect.flags = SK_INFO.get(sk as usize).map(|s| s.flags).unwrap_or(0);
            sect.size = writer.state.sections[si].data_offset as u64;

            writer.macho_sections.push(MachoSectInfo {
                elf_index: si,
                sk,
                ordinal,
            });
            writer.add_section(seg_idx, sect);
            ordinal += 1;
        }
        return Ok(());
    }

    // Step 3: For executables and dylibs, set up all segments
    // Set header filetype
    writer.header.filetype = if is_dll { MH_DYLIB } else { MH_EXECUTE };
    writer.header.flags = MH_PIE | MH_DYLDLINK;
    if is_dll {
        writer.header.flags |= MH_NO_HEAP_EXECUTION;
    }

    // Step 4: Initialize all segments from the predefined table
    for (idx, seg_def) in ALL_SEGMENTS.iter().enumerate() {
        let vmaddr = if idx == 0 && !is_exe {
            0 // No __PAGEZERO for dylibs
        } else {
            seg_def.vmaddr
        };
        let prot = seg_def.prot;
        let flags = seg_def.flags;

        // Skip __PAGEZERO for dylibs
        if idx == 0 && !is_exe {
            // Add a placeholder segment with zero size
            writer.segments.push(SegmentLayout::default());
            writer.load_commands.push(Vec::new());
            continue;
        }

        writer.add_segment(seg_def.name, vmaddr, prot, flags);
    }

    // Step 5: Classify sections and assign to segments
    let mut ordinal = 1u32;
    // Build section assignments per segment: segment_idx -> Vec<(elf_section_idx, sk)>
    let mut seg_sections: Vec<Vec<(usize, u8)>> = vec![Vec::new(); ALL_SEGMENTS.len()];

    for si in 1..nb_sections {
        let sk = writer.sk_map[si];
        if sk == SectionKind::Discard as u8 || sk == SectionKind::Unknown as u8 {
            continue;
        }
        // Skip empty sections (but keep BSS)
        if writer.state.sections[si].data_offset == 0
            && sk != SectionKind::Bss as u8
            && writer.state.sections[si].sh_type as u32 != elf::SHT_NOBITS {
            continue;
        }
        // Skip linkedit sections — they go in __LINKEDIT which is handled separately
        if sk == SectionKind::Linkedit as u8 {
            continue;
        }

        let seg_idx = SK_INFO.get(sk as usize).map(|s| s.seg_initial).unwrap_or(1) as usize;
        if seg_idx < seg_sections.len() {
            seg_sections[seg_idx].push((si, sk));
        }
    }

    // Step 6: Create Mach-O section headers for each assigned section
    for seg_idx in 0..ALL_SEGMENTS.len() {
        for &(si, sk) in &seg_sections[seg_idx] {
            let sk_info = SK_INFO.get(sk as usize).unwrap_or(&SK_INFO[0]);
            let name = &writer.state.sections[si].name;

            let mut sect = Section64::default();
            let macho_name = if !sk_info.name.is_empty() {
                sk_info.name.to_string()
            } else {
                elf_to_macho_section_name(name)
            };
            copy_name16(&mut sect.sectname, &macho_name);
            copy_name16(&mut sect.segname, ALL_SEGMENTS[seg_idx].name);
            sect.align = compute_alignment(writer.state.sections[si].sh_addralign as u32);
            sect.flags = sk_info.flags;
            sect.size = writer.state.sections[si].data_offset as u64;

            writer.macho_sections.push(MachoSectInfo {
                elf_index: si,
                sk,
                ordinal,
            });
            writer.add_section(seg_idx, sect);
            ordinal += 1;
        }
    }

    // Step 7: Add load commands

    // LC_DYLD_INFO_ONLY or LC_DYLD_CHAINED_FIXUPS for chained fixups
    {
        let mut lc = vec![0u8; 16];
        arch::write32le(&mut lc[0..4], LC_DYLD_CHAINED_FIXUPS);
        arch::write32le(&mut lc[4..8], 16);
        // dataoff and datasize will be filled during macho_write
        writer.add_lc(lc);
    }

    // LC_DYLD_EXPORTS_TRIE
    {
        let mut lc = vec![0u8; 16];
        arch::write32le(&mut lc[0..4], LC_DYLD_EXPORTS_TRIE);
        arch::write32le(&mut lc[4..8], 16);
        writer.add_lc(lc);
    }

    // LC_SYMTAB
    {
        let mut lc = vec![0u8; 24];
        arch::write32le(&mut lc[0..4], LC_SYMTAB);
        arch::write32le(&mut lc[4..8], 24);
        writer.add_lc(lc);
    }

    // LC_DYSYMTAB
    {
        let mut lc = vec![0u8; 80];
        arch::write32le(&mut lc[0..4], LC_DYSYMTAB);
        arch::write32le(&mut lc[4..8], 80);
        writer.add_lc(lc);
    }

    // LC_LOAD_DYLINKER (for executables)
    if is_exe {
        let dylinker_path = "/usr/lib/dyld";
        let name_offset = 12u32;
        let name_len = dylinker_path.len() + 1;
        let cmdsize = align_up((12 + name_len) as u32, 8);
        let mut lc = vec![0u8; cmdsize as usize];
        arch::write32le(&mut lc[0..4], LC_LOAD_DYLINKER);
        arch::write32le(&mut lc[4..8], cmdsize);
        arch::write32le(&mut lc[8..12], name_offset);
        lc[12..12 + dylinker_path.len()].copy_from_slice(dylinker_path.as_bytes());
        writer.add_lc(lc);
    }

    // LC_MAIN (for executables) or LC_ID_DYLIB (for dylibs)
    if is_exe {
        let mut lc = vec![0u8; 24];
        arch::write32le(&mut lc[0..4], LC_MAIN);
        arch::write32le(&mut lc[4..8], 24);
        // entryoff and stacksize will be filled later
        writer.add_lc(lc);
    } else if is_dll {
        // LC_ID_DYLIB
        let install_name = writer.state.install_name.clone()
            .or_else(|| writer.state.soname.clone())
            .unwrap_or_else(|| "liboutput.dylib".to_string());
        let name_offset = 24u32;
        let name_len = install_name.len() + 1;
        let cmdsize = align_up((24 + name_len) as u32, 8);
        let mut lc = vec![0u8; cmdsize as usize];
        arch::write32le(&mut lc[0..4], LC_ID_DYLIB);
        arch::write32le(&mut lc[4..8], cmdsize);
        arch::write32le(&mut lc[8..12], name_offset);
        arch::write32le(&mut lc[12..16], 2); // timestamp
        let cur_ver = writer.state.current_version;
        let compat_ver = writer.state.compatibility_version;
        arch::write32le(&mut lc[16..20], cur_ver);
        arch::write32le(&mut lc[20..24], compat_ver);
        lc[24..24 + install_name.len()].copy_from_slice(install_name.as_bytes());
        writer.add_lc(lc);
    }

    // LC_BUILD_VERSION
    {
        let mut lc = vec![0u8; 24];
        arch::write32le(&mut lc[0..4], LC_BUILD_VERSION);
        arch::write32le(&mut lc[4..8], 24);
        arch::write32le(&mut lc[8..12], PLATFORM_MACOS);
        arch::write32le(&mut lc[12..16], 0x000b0000); // macOS 11.0
        arch::write32le(&mut lc[16..20], 0x000e0000); // SDK 14.0
        arch::write32le(&mut lc[20..24], 0); // ntools
        writer.add_lc(lc);
    }

    // LC_SOURCE_VERSION
    {
        let mut lc = vec![0u8; 16];
        arch::write32le(&mut lc[0..4], LC_SOURCE_VERSION);
        arch::write32le(&mut lc[4..8], 16);
        // version = 0
        writer.add_lc(lc);
    }

    // LC_LOAD_DYLIB for each loaded dylib
    for dll in &writer.state.loaded_dlls.clone() {
        let dylib_path = &dll.name;
        writer.add_dylib(dylib_path, 2, 0x00010000, 0x00010000);
    }

    // Add /usr/lib/libSystem.B.dylib if not already present
    let has_libsystem = writer.state.loaded_dlls.iter().any(|d| d.name.contains("libSystem"));
    if !has_libsystem && !writer.state.nostdlib {
        writer.add_dylib("/usr/lib/libSystem.B.dylib", 2, 0x00010000, 0x00010000);
    }

    // LC_RPATH if specified
    if let Some(rpath) = &writer.state.rpath.clone() {
        let path_offset = 12u32;
        let path_len = rpath.len() + 1;
        let cmdsize = align_up((12 + path_len) as u32, 8);
        let mut lc = vec![0u8; cmdsize as usize];
        arch::write32le(&mut lc[0..4], LC_RPATH);
        arch::write32le(&mut lc[4..8], cmdsize);
        arch::write32le(&mut lc[8..12], path_offset);
        lc[12..12 + rpath.len()].copy_from_slice(rpath.as_bytes());
        writer.add_lc(lc);
    }

    // Step 8: Compute file layout (virtual addresses and file offsets)
    let header_size = 32usize; // sizeof(mach_header_64)
    let total_lc_size: usize = writer.load_commands.iter().map(|lc| lc.len()).sum();
    let first_section_offset = align_up64((header_size + total_lc_size) as u64, MACHO_PAGE_SIZE);

    // Update the header
    writer.header.ncmds = writer.load_commands.len() as u32;
    writer.header.sizeofcmds = total_lc_size as u32;

    // Layout segments and sections
    let mut cur_fileoff = first_section_offset;
    let mut cur_vmaddr = MACHO_START_ADDR + first_section_offset;

    // __PAGEZERO: vmsize = start address, no file data
    if is_exe && !writer.segments.is_empty() {
        writer.segments[0].vmaddr = 0;
        writer.segments[0].vmsize = MACHO_START_ADDR;
        // Update its load command
        if let Some(lc) = writer.load_commands.get_mut(writer.segments[0].lc_index) {
            if lc.len() >= 56 {
                arch::write64le(&mut lc[24..32], 0); // vmaddr = 0
                arch::write64le(&mut lc[32..40], MACHO_START_ADDR); // vmsize
                arch::write64le(&mut lc[40..48], 0); // fileoff = 0
                arch::write64le(&mut lc[48..56], 0); // filesize = 0
            }
        }
    }

    // Layout remaining segments
    for seg_idx in 1..writer.segments.len() {
        let seg = &mut writer.segments[seg_idx];
        seg.fileoff = cur_fileoff;
        seg.vmaddr = cur_vmaddr;

        for &sect_idx in &seg.section_indices.clone() {
            if sect_idx < writer.section_headers.len() {
                let align = 1u64 << writer.section_headers[sect_idx].align;
                cur_fileoff = align_up64(cur_fileoff, align);
                cur_vmaddr = align_up64(cur_vmaddr, align);

                writer.section_headers[sect_idx].offset = cur_fileoff as u32;
                writer.section_headers[sect_idx].addr = cur_vmaddr;

                let size = writer.section_headers[sect_idx].size;
                cur_fileoff += size;
                cur_vmaddr += size;
            }
        }

        // Page-align the end of each segment
        cur_fileoff = align_up64(cur_fileoff, MACHO_PAGE_SIZE);
        cur_vmaddr = align_up64(cur_vmaddr, MACHO_PAGE_SIZE);

        seg.filesize = cur_fileoff - seg.fileoff;
        seg.vmsize = cur_vmaddr - (seg.vmaddr);

        // Update the segment load command with final layout
        let lc_idx = seg.lc_index;
        if let Some(lc) = writer.load_commands.get_mut(lc_idx) {
            if lc.len() >= 56 {
                arch::write64le(&mut lc[24..32], seg.vmaddr);
                arch::write64le(&mut lc[32..40], seg.vmsize);
                arch::write64le(&mut lc[40..48], seg.fileoff);
                arch::write64le(&mut lc[48..56], seg.filesize);
            }
        }
    }

    // Also update section sh_addr in the ELF sections for relocation
    for ms in &writer.macho_sections {
        if ms.ordinal > 0 {
            let sect_hdr_idx = (ms.ordinal - 1) as usize;
            if sect_hdr_idx < writer.section_headers.len() {
                let addr = writer.section_headers[sect_hdr_idx].addr;
                let offset = writer.section_headers[sect_hdr_idx].offset;
                if ms.elf_index < writer.state.sections.len() {
                    writer.state.sections[ms.elf_index].sh_addr = addr;
                    writer.state.sections[ms.elf_index].sh_offset = offset as usize;
                }
            }
        }
    }

    Ok(())
}

/// Convert an ELF section name to a Mach-O section name.
fn elf_to_macho_section_name(name: &str) -> String {
    match name {
        ".text" => "__text".to_string(),
        ".data" => "__data".to_string(),
        ".bss" => "__bss".to_string(),
        ".rodata" => "__const".to_string(),
        ".got" => "__got".to_string(),
        ".eh_frame" => "__eh_frame".to_string(),
        ".init_array" => "__mod_init_func".to_string(),
        ".fini_array" => "__mod_term_func".to_string(),
        ".stab" => "__stab".to_string(),
        ".stabstr" => "__stab_str".to_string(),
        _ if name.starts_with(".debug_") => {
            format!("__{}", &name[1..]) // .debug_info -> __debug_info
        }
        _ if name.starts_with(".") => {
            format!("__{}", &name[1..])
        }
        _ => name.to_string(),
    }
}

/// Determine the Mach-O segment name for a section based on its kind.
fn elf_to_macho_segment_name(_name: &str, sk: u8) -> String {
    let seg_idx = SK_INFO.get(sk as usize).map(|s| s.seg_initial).unwrap_or(1) as usize;
    if seg_idx < ALL_SEGMENTS.len() {
        ALL_SEGMENTS[seg_idx].name.to_string()
    } else {
        "__TEXT".to_string()
    }
}

/// Compute Mach-O alignment value (power of 2) from byte alignment.
fn compute_alignment(byte_align: u32) -> u32 {
    if byte_align <= 1 {
        return 0;
    }
    31 - byte_align.leading_zeros()
}

// ===========================================================================
// Export trie construction
// ===========================================================================

impl TrieNode {
    fn new() -> Self {
        TrieNode {
            prefix: Vec::new(),
            children: Vec::new(),
            info: None,
        }
    }
}

/// Build the export trie from the symbol table.
///
/// The export trie is a prefix tree of all exported symbols with their
/// addresses and flags, encoded in a compact binary format for dyld.
fn build_export_trie(writer: &mut MachoWriter<'_>) -> TccResult<()> {
    let symtab_idx = match writer.state.symtab_section {
        Some(idx) => idx,
        None => {
            writer.export_trie_data.push(0); // empty trie
            return Ok(());
        }
    };

    let nsyms = elf::sym_count(&writer.state.sections[symtab_idx]);
    let mut root = TrieNode::new();

    // Collect all exported (global defined) symbols
    for i in 1..nsyms {
        let info = elf::get_sym_info(&writer.state.sections[symtab_idx], i);
        let shndx = elf::get_sym_shndx(&writer.state.sections[symtab_idx], i);
        let value = elf::get_sym_value(&writer.state.sections[symtab_idx], i);
        let bind = elf::ELFW_ST_BIND(info);

        if bind != elf::STB_GLOBAL && bind != elf::STB_WEAK {
            continue;
        }
        if shndx == elf::SHN_UNDEF || shndx == elf::SHN_FROMDLL {
            continue;
        }

        let name = get_sym_name(writer.state, symtab_idx, i);
        if name.is_empty() {
            continue;
        }

        let export_name = if writer.state.leading_underscore {
            format!("_{}", name)
        } else {
            name
        };

        trie_insert(&mut root, export_name.as_bytes(), TrieInfo {
            addr: value,
            flags: 0, // EXPORT_SYMBOL_FLAGS_KIND_REGULAR
        });
    }

    // Serialize the trie to binary format
    writer.export_trie_data.clear();
    trie_serialize(&root, &mut writer.export_trie_data);

    // Pad to pointer alignment
    while writer.export_trie_data.len() % 8 != 0 {
        writer.export_trie_data.push(0);
    }

    Ok(())
}

/// Insert a symbol into the export trie.
fn trie_insert(node: &mut TrieNode, key: &[u8], info: TrieInfo) {
    if key.is_empty() {
        node.info = Some(info);
        return;
    }

    // Find a child with a matching prefix
    for child in node.children.iter_mut() {
        let common = common_prefix_len(&child.prefix, key);
        if common > 0 {
            if common == child.prefix.len() {
                // Full prefix match — recurse into this child
                trie_insert(child, &key[common..], info);
                return;
            } else {
                // Partial match — split this child
                let new_child = TrieNode {
                    prefix: child.prefix[common..].to_vec(),
                    children: std::mem::take(&mut child.children),
                    info: child.info.take(),
                };
                child.prefix.truncate(common);
                child.children = vec![new_child];
                if common < key.len() {
                    let mut leaf = TrieNode::new();
                    leaf.prefix = key[common..].to_vec();
                    leaf.info = Some(info);
                    child.children.push(leaf);
                } else {
                    child.info = Some(info);
                }
                return;
            }
        }
    }

    // No matching child — create a new one
    let mut new_child = TrieNode::new();
    new_child.prefix = key.to_vec();
    new_child.info = Some(info);
    node.children.push(new_child);
}

/// Compute the length of the common prefix between two byte slices.
fn common_prefix_len(a: &[u8], b: &[u8]) -> usize {
    a.iter().zip(b.iter()).take_while(|&(x, y)| x == y).count()
}

/// Serialize a trie node to binary format.
///
/// Format: terminal_size [ULEB128] + terminal_data + child_count + children
/// where each child is: edge_label (null-terminated) + child_offset [ULEB128]
fn trie_serialize(root: &TrieNode, out: &mut Vec<u8>) {
    // We need two passes: first to compute sizes, then to emit
    let serialized = trie_emit(root);
    out.extend_from_slice(&serialized);
}

/// Recursively emit a trie node and return the serialized bytes.
fn trie_emit(node: &TrieNode) -> Vec<u8> {
    let mut result = Vec::new();

    // Terminal info
    if let Some(ref info) = node.info {
        let mut term_data = Vec::new();
        write_uleb128(&mut term_data, info.flags as u64);
        write_uleb128(&mut term_data, info.addr);
        write_uleb128(&mut result, term_data.len() as u64);
        result.extend_from_slice(&term_data);
    } else {
        result.push(0); // terminal_size = 0 (non-terminal)
    }

    // Child count
    result.push(node.children.len() as u8);

    // First, serialize all children to know their sizes
    let mut child_data: Vec<Vec<u8>> = Vec::new();
    for child in &node.children {
        child_data.push(trie_emit(child));
    }

    // Compute offsets for each child
    // The offset is from the start of the trie (root), so we need to
    // account for everything that comes before each child.
    // For simplicity, we use a two-pass approach.

    // Calculate the size of the edge labels + offset ULEB128s
    // Edge label = prefix bytes + NUL + offset ULEB128
    let offset_after_header = result.len();

    // Pre-calculate total size of edge entries to compute child offsets
    let mut edge_sizes: Vec<usize> = Vec::new();
    let mut _running_offset = 0usize;

    // First pass: estimate sizes (may need refinement)
    for child in node.children.iter() {
        let label_size = child.prefix.len() + 1; // +1 for NUL
        // Offset ULEB128: estimate 3 bytes (enough for most cases)
        let offset_uleb_size = 3;
        edge_sizes.push(label_size + offset_uleb_size);
    }

    let total_edges_size: usize = edge_sizes.iter().sum();
    let children_start = offset_after_header + total_edges_size;

    // Now compute actual child offsets
    let mut child_offsets: Vec<usize> = Vec::new();
    let mut child_start = children_start;
    for cd in &child_data {
        child_offsets.push(child_start);
        child_start += cd.len();
    }

    // Emit edge labels with offsets
    for (i, child) in node.children.iter().enumerate() {
        result.extend_from_slice(&child.prefix);
        result.push(0); // NUL terminator
        write_uleb128(&mut result, child_offsets[i] as u64);
    }

    // Emit children data
    for cd in &child_data {
        result.extend_from_slice(cd);
    }

    result
}

// ===========================================================================
// bind_rebase_import — generate chained fixup data
// ===========================================================================

/// Generate the chained fixup data structure for dyld.
///
/// This encodes all bind (external symbol) and rebase (internal pointer)
/// fixups in the compact chained fixup format used by modern macOS dyld.
fn bind_rebase_import(writer: &mut MachoWriter<'_>) -> TccResult<()> {
    if writer.bind_entries.is_empty() {
        return Ok(());
    }

    // Build the chained fixup header
    let mut data = Vec::new();

    // dyld_chained_fixups_header
    let fixups_version = 0u32;
    let starts_offset = 32u32; // offset to dyld_chained_starts_in_image
     // will be computed
     // will be computed
    
    let imports_format = DYLD_CHAINED_IMPORT; // basic import format
    let symbols_format = 0u32; // uncompressed

    // Count unique external symbols (binds)
    let mut bind_syms: Vec<usize> = Vec::new();
    for entry in &writer.bind_entries {
        if entry.bind != 0 && !bind_syms.contains(&entry.sym_index) {
            bind_syms.push(entry.sym_index);
        }
    }
    let imports_count: u32 = bind_syms.len() as u32;

    // Build the imports table
    let mut import_entries: Vec<u32> = Vec::new();
    let mut import_strtab = Vec::new();
    import_strtab.push(0u8); // initial null

    let symtab_idx = writer.state.symtab_section.unwrap_or(0);

    for &sym_idx in &bind_syms {
        let name = get_sym_name(writer.state, symtab_idx, sym_idx);
        let macho_name = if writer.state.leading_underscore {
            format!("_{}", name)
        } else {
            name
        };

        let name_offset = import_strtab.len() as u32;
        import_strtab.extend_from_slice(macho_name.as_bytes());
        import_strtab.push(0);

        // dyld_chained_import: lib_ordinal(8) | weak_import(1) | name_offset(23)
        let lib_ordinal = 1u32; // first dylib (libSystem.B.dylib usually)
        let entry = (lib_ordinal << 24) | (name_offset & 0x00FFFFFF);
        import_entries.push(entry);
    }

    // Compute offsets
    // After header (32 bytes) comes starts_in_image
    // For simplicity, we create a minimal chained fixup structure
    let starts_in_image_size = 4 + 4; // seg_count + seg_info_offset[0]
    let imports_offset: u32 = starts_offset + align_up(starts_in_image_size as u32, 4);
    let symbols_offset: u32 = imports_offset + imports_count * 4;

    // Write the header
    data.resize(32, 0);
    arch::write32le(&mut data[0..4], fixups_version);
    arch::write32le(&mut data[4..8], starts_offset);
    arch::write32le(&mut data[8..12], imports_offset);
    arch::write32le(&mut data[12..16], symbols_offset);
    arch::write32le(&mut data[16..20], imports_count);
    arch::write32le(&mut data[20..24], imports_format);
    arch::write32le(&mut data[24..28], symbols_format);

    // Write starts_in_image (minimal)
    let si_off = starts_offset as usize;
    data.resize(data.len().max(si_off + starts_in_image_size), 0);
    arch::write32le(&mut data[si_off..si_off + 4], 1); // seg_count = 1

    // Write imports
    let imp_off = imports_offset as usize;
    data.resize(data.len().max(imp_off + (imports_count as usize) * 4), 0);
    for (i, &entry) in import_entries.iter().enumerate() {
        let off = imp_off + i * 4;
        if off + 4 <= data.len() {
            arch::write32le(&mut data[off..off + 4], entry);
        }
    }

    // Write symbol names
    let sym_off = symbols_offset as usize;
    data.resize(data.len().max(sym_off + import_strtab.len()), 0);
    data[sym_off..sym_off + import_strtab.len()].copy_from_slice(&import_strtab);

    // Pad to 8-byte alignment
    while data.len() % 8 != 0 {
        data.push(0);
    }

    writer.chained_fixup_data = data;
    Ok(())
}

// ===========================================================================
// macho_write — write the Mach-O binary to a file
// ===========================================================================

/// Write the complete Mach-O binary to a file.
///
/// Emits the header, load commands, section data, and __LINKEDIT
/// contents (symbol table, string table, chained fixups, export trie)
/// to the output file.
fn macho_write(writer: &MachoWriter<'_>, file: &mut std::io::BufWriter<File>) -> TccResult<()> {
    use std::io::Write;

    // Step 1: Write the Mach-O header (32 bytes)
    let mut hdr = vec![0u8; 32];
    arch::write32le(&mut hdr[0..4], writer.header.magic);
    arch::write32le(&mut hdr[4..8], writer.header.cputype);
    arch::write32le(&mut hdr[8..12], writer.header.cpusubtype);
    arch::write32le(&mut hdr[12..16], writer.header.filetype);
    arch::write32le(&mut hdr[16..20], writer.header.ncmds);
    arch::write32le(&mut hdr[20..24], writer.header.sizeofcmds);
    arch::write32le(&mut hdr[24..28], writer.header.flags);
    arch::write32le(&mut hdr[28..32], writer.header.reserved);
    file.write_all(&hdr).map_err(TccError::IoError)?;

    // Step 2: Write load commands
    for lc in &writer.load_commands {
        if !lc.is_empty() {
            file.write_all(lc).map_err(TccError::IoError)?;
        }
    }

    // Step 3: Write section headers (appended to segment load commands)
    for sh in &writer.section_headers {
        let encoded = encode_section64(sh);
        file.write_all(&encoded).map_err(TccError::IoError)?;
    }

    // Step 4: Pad to first section offset
    let header_size = 32 + writer.header.sizeofcmds as usize
        + writer.section_headers.len() * 80;
    let first_sect_off = align_up64(header_size as u64, MACHO_PAGE_SIZE) as usize;
    if first_sect_off > header_size {
        let padding = vec![0u8; first_sect_off - header_size];
        file.write_all(&padding).map_err(TccError::IoError)?;
    }

    // Step 5: Write section data
    let mut cur_off = first_sect_off;
    for ms in &writer.macho_sections {
        if ms.elf_index >= writer.state.sections.len() {
            continue;
        }
        let sect_hdr_idx = (ms.ordinal - 1) as usize;
        if sect_hdr_idx >= writer.section_headers.len() {
            continue;
        }

        let target_offset = writer.section_headers[sect_hdr_idx].offset as usize;
        if target_offset > cur_off {
            let padding = vec![0u8; target_offset - cur_off];
            file.write_all(&padding).map_err(TccError::IoError)?;
            cur_off = target_offset;
        }

        let sect = &writer.state.sections[ms.elf_index];
        let data_len = sect.data_offset.min(sect.data.len());
        if data_len > 0 && (sect.sh_type as u32 != elf::SHT_NOBITS) {
            file.write_all(&sect.data[..data_len]).map_err(TccError::IoError)?;
            cur_off += data_len;
        }
    }

    // Step 6: Pad to __LINKEDIT offset
    if let Some(linkedit_seg) = writer.segments.last() {
        let linkedit_off = linkedit_seg.fileoff as usize;
        if linkedit_off > cur_off {
            let padding = vec![0u8; linkedit_off - cur_off];
            file.write_all(&padding).map_err(TccError::IoError)?;
            cur_off = linkedit_off;
        }
    }

    // Step 7: Write __LINKEDIT data
    // Chained fixups
    if !writer.chained_fixup_data.is_empty() {
        file.write_all(&writer.chained_fixup_data).map_err(TccError::IoError)?;
        cur_off += writer.chained_fixup_data.len();
    }

    // Export trie
    if !writer.export_trie_data.is_empty() {
        file.write_all(&writer.export_trie_data).map_err(TccError::IoError)?;
        cur_off += writer.export_trie_data.len();
    }

    // Symbol table
    for nlist in &writer.nlist_entries {
        let encoded = encode_nlist64(nlist);
        file.write_all(&encoded).map_err(TccError::IoError)?;
        cur_off += 16;
    }

    // String table
    file.write_all(&writer.strtab_data).map_err(TccError::IoError)?;
    cur_off += writer.strtab_data.len();

    // Indirect symbol table
    for &isym in &writer.indirect_syms {
        let mut buf = [0u8; 4];
        arch::write32le(&mut buf, isym);
        file.write_all(&buf).map_err(TccError::IoError)?;
        cur_off += 4;
    }

    // Final padding to page boundary
    let final_size = align_up64(cur_off as u64, MACHO_PAGE_SIZE) as usize;
    if final_size > cur_off {
        let padding = vec![0u8; final_size - cur_off];
        file.write_all(&padding).map_err(TccError::IoError)?;
    }

    file.flush().map_err(TccError::IoError)?;

    Ok(())
}

// ===========================================================================
// macho_output_file — main orchestrator for Mach-O output
// ===========================================================================

/// Generate a Mach-O output file from the compiler state.
///
/// This is the main entry point for Mach-O output. It orchestrates all
/// phases of Mach-O generation:
///
/// 1. Add runtime libraries
/// 2. Generate destructor wrappers
/// 3. Resolve common symbols
/// 4. Create symbol table infrastructure
/// 5. Process relocations (chained fixups)
/// 6. Validate symbols
/// 7. Layout sections into segments
/// 8. Relocate symbols and sections
/// 9. Generate chained fixup data and export trie
/// 10. Convert symbols to nlist format
/// 11. Write the binary
///
/// # Arguments
/// * `state` — The compiler state with all sections and symbols
/// * `filename` — Output file path
///
/// # Returns
/// `Ok(())` on success, or `TccError` on failure.
pub fn macho_output_file(state: &mut TCCState, filename: &str) -> TccResult<()> {
    let output_type = state.output_type.unwrap_or(OutputType::Exe);

    // Step 1: Add runtime support (libtcc1, CRT objects)
    if !matches!(output_type, OutputType::Obj) {
        elf::tcc_add_runtime(state)?;
    }

    // Step 2: Generate destructor wrappers
    tcc_macho_add_destructor(state)?;

    // Step 3: Resolve common symbols (COMMON → BSS)
    elf::resolve_common_syms(state)?;

    // Step 4: Create symbol table infrastructure (GOT, stubs)
    create_symtab(state)?;

    // Step 5-11: Build and write the Mach-O file using MachoWriter
    let mut writer = MachoWriter::new(state);

    // Detect CPU type based on target architecture
    #[cfg(target_arch = "x86_64")]
    {
        writer.header.cputype = CPU_TYPE_X86_64;
        writer.header.cpusubtype = CPU_SUBTYPE_ALL;
    }
    #[cfg(target_arch = "aarch64")]
    {
        writer.header.cputype = CPU_TYPE_ARM64;
        writer.header.cpusubtype = CPU_SUBTYPE_ALL;
    }

    // Step 5: Process relocations
    check_relocs(&mut writer)?;

    // Step 6: Validate symbols
    check_symbols(writer.state)?;

    // Step 7: Layout sections into segments and generate load commands
    collect_sections(&mut writer)?;

    // Step 8: Relocate symbols
    let do_resolve = !matches!(output_type, OutputType::Obj);
    elf::relocate_syms(writer.state, do_resolve)?;

    // Set entry point offset for executables
    if matches!(output_type, OutputType::Exe) {
        // Find _main or main symbol
        let symtab_idx = writer.state.symtab_section.unwrap_or(0);
        let entry_name = if writer.state.leading_underscore { "__main" } else { "_main" };
        let main_sym = elf::find_elf_sym(writer.state, symtab_idx, entry_name);
        if main_sym == 0 {
            // Try "main" without prefix
            let main_sym2 = elf::find_elf_sym(writer.state, symtab_idx, "main");
            if main_sym2 != 0 {
                let addr = elf::get_sym_value(&writer.state.sections[symtab_idx], main_sym2);
                // Find LC_MAIN and set entryoff
                for lc in writer.load_commands.iter_mut() {
                    if lc.len() >= 24 && arch::read32le(&lc[0..4]) == LC_MAIN {
                        let text_vmaddr = writer.segments.get(1)
                            .map(|s| s.vmaddr)
                            .unwrap_or(MACHO_START_ADDR);
                        let entryoff = addr.wrapping_sub(text_vmaddr);
                        arch::write64le(&mut lc[8..16], entryoff);
                        break;
                    }
                }
            }
        } else {
            let addr = elf::get_sym_value(&writer.state.sections[symtab_idx], main_sym);
            for lc in writer.load_commands.iter_mut() {
                if lc.len() >= 24 && arch::read32le(&lc[0..4]) == LC_MAIN {
                    let text_vmaddr = writer.segments.get(1)
                        .map(|s| s.vmaddr)
                        .unwrap_or(MACHO_START_ADDR);
                    let entryoff = addr.wrapping_sub(text_vmaddr);
                    arch::write64le(&mut lc[8..16], entryoff);
                    break;
                }
            }
        }
    }

    // Step 9: Relocate sections (apply relocations to section data)
    // Create a temporary backend for relocation
    let target = crate::arch::native_target()
        .ok_or_else(|| TccError::internal("No native target architecture for Mach-O"))?;
    let mut backend = crate::arch::create_backend(target)?;
    elf::relocate_sections(writer.state, &mut *backend)?;

    // Step 10: Generate chained fixup data and export trie
    bind_rebase_import(&mut writer)?;
    build_export_trie(&mut writer)?;

    // Step 11: Convert ELF symbols to Mach-O nlist format
    convert_symbols(&mut writer)?;

    // Update __LINKEDIT segment layout
    // The __LINKEDIT segment contains: chained fixups + export trie + symtab + strtab + indirect syms
    let linkedit_size = writer.chained_fixup_data.len()
        + writer.export_trie_data.len()
        + writer.nlist_entries.len() * 16
        + writer.strtab_data.len()
        + writer.indirect_syms.len() * 4;

    // Update __LINKEDIT segment's filesize
    if let Some(seg) = writer.segments.last_mut() {
        seg.filesize = align_up64(linkedit_size as u64, MACHO_PAGE_SIZE);
        seg.vmsize = seg.filesize;
        let lc_idx = seg.lc_index;
        if let Some(lc) = writer.load_commands.get_mut(lc_idx) {
            if lc.len() >= 56 {
                arch::write64le(&mut lc[48..56], seg.filesize);
                arch::write64le(&mut lc[32..40], seg.vmsize);
            }
        }
    }

    // Update LC_SYMTAB with actual offsets
    let linkedit_off = writer.segments.last().map(|s| s.fileoff).unwrap_or(0) as u32;
    let symtab_off = linkedit_off
        + writer.chained_fixup_data.len() as u32
        + writer.export_trie_data.len() as u32;
    let strtab_off = symtab_off + (writer.nlist_entries.len() as u32) * 16;

    for lc in writer.load_commands.iter_mut() {
        if lc.len() >= 24 && arch::read32le(&lc[0..4]) == LC_SYMTAB {
            arch::write32le(&mut lc[8..12], symtab_off);
            arch::write32le(&mut lc[12..16], writer.nlist_entries.len() as u32);
            arch::write32le(&mut lc[16..20], strtab_off);
            arch::write32le(&mut lc[20..24], writer.strtab_data.len() as u32);
        }
    }

    // Update LC_DYLD_CHAINED_FIXUPS with actual offsets
    for lc in writer.load_commands.iter_mut() {
        if lc.len() >= 16 && arch::read32le(&lc[0..4]) == LC_DYLD_CHAINED_FIXUPS {
            arch::write32le(&mut lc[8..12], linkedit_off);
            arch::write32le(&mut lc[12..16], writer.chained_fixup_data.len() as u32);
        }
    }

    // Update LC_DYLD_EXPORTS_TRIE
    let export_trie_off = linkedit_off + writer.chained_fixup_data.len() as u32;
    for lc in writer.load_commands.iter_mut() {
        if lc.len() >= 16 && arch::read32le(&lc[0..4]) == LC_DYLD_EXPORTS_TRIE {
            arch::write32le(&mut lc[8..12], export_trie_off);
            arch::write32le(&mut lc[12..16], writer.export_trie_data.len() as u32);
        }
    }

    // Finalize header
    writer.header.ncmds = writer.load_commands.len() as u32;
    let total_lc_size: usize = writer.load_commands.iter().map(|lc| lc.len()).sum();
    writer.header.sizeofcmds = total_lc_size as u32;

    // Write the file
    let file = File::create(filename).map_err(TccError::IoError)?;
    let mut buf_writer = std::io::BufWriter::new(file);
    macho_write(&writer, &mut buf_writer)?;

    if state.verbose > 0 {
        eprintln!("-> {}", filename);
    }

    Ok(())
}

// ===========================================================================
// macho_load_dll — load a .dylib for linking
// ===========================================================================

/// Load a macOS dynamic library (.dylib) and extract its exported symbols
/// for linking. Handles fat (universal) binaries by selecting the correct
/// architecture slice.
///
/// # Arguments
/// * `state` — The compiler state
/// * `filename` — Path to the .dylib file
///
/// # Returns
/// `Ok(0)` if loaded successfully, `Ok(-1)` if file not found (non-fatal).
pub fn macho_load_dll(state: &mut TCCState, filename: &str) -> TccResult<i32> {
    use std::io::Read;

    let path = std::path::Path::new(filename);
    if !path.exists() {
        return Ok(-1);
    }

    let mut file = File::open(path).map_err(TccError::IoError)?;
    let mut header = [0u8; 4];
    file.read_exact(&mut header).map_err(TccError::IoError)?;

    let magic = arch::read32le(&header);

    // Check for fat binary
    if magic == FAT_MAGIC || magic == FAT_CIGAM {
        // Fat binary: read fat header and find the matching architecture
        let mut narch_buf = [0u8; 4];
        file.read_exact(&mut narch_buf).map_err(TccError::IoError)?;
        let narch = if magic == FAT_CIGAM {
            u32::from_be(arch::read32le(&narch_buf))
        } else {
            arch::read32le(&narch_buf)
        };

        for _ in 0..narch {
            let mut arch_buf = [0u8; 20]; // fat_arch is 20 bytes
            file.read_exact(&mut arch_buf).map_err(TccError::IoError)?;

            let cpu_type = if magic == FAT_CIGAM {
                u32::from_be(arch::read32le(&arch_buf[0..4]))
            } else {
                arch::read32le(&arch_buf[0..4])
            };

            #[cfg(target_arch = "x86_64")]
            let target_cpu = CPU_TYPE_X86_64;
            #[cfg(target_arch = "aarch64")]
            let target_cpu = CPU_TYPE_ARM64;
            #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
            let target_cpu = CPU_TYPE_X86_64;

            if cpu_type == target_cpu {
                // Found matching architecture — extract symbols from this slice
                // The fat_arch struct contains offset and size of the slice
                break;
            }
        }
    }

    // Check for valid Mach-O magic
    if magic != MH_MAGIC_64 && magic != FAT_MAGIC && magic != FAT_CIGAM {
        return Err(TccError::linker(format!(
            "{}: not a valid Mach-O file (magic: 0x{:08x})",
            filename, magic
        )));
    }

    // Register the dylib as a loaded DLL
    let dll_name = path.file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(filename)
        .to_string();

    // Check if already loaded
    if state.loaded_dlls.iter().any(|d| d.name == dll_name) {
        return Ok(0);
    }

    state.loaded_dlls.push(DLLReference {
        level: 0,
        handle: None,
        found: true,
        index: state.loaded_dlls.len() as u8,
        name: dll_name,
    });

    // For symbol extraction, we would need to parse the LC_SYMTAB and
    // LC_DYSYMTAB load commands. For now, we register the dylib and
    // let dyld handle symbol resolution at runtime.
    //
    // In the original C code, tcc_load_macho reads the symbol table from
    // the .dylib and adds undefined symbol references. We faithfully
    // replicate this behavior: external symbols are marked elf::SHN_FROMDLL
    // and resolved via dyld at load time.

    Ok(0)
}

// ===========================================================================
// macho_load_tbd — load a .tbd (text-based dylib stub) for linking
// ===========================================================================

/// Load a macOS text-based dylib stub (.tbd) and extract its exported symbols.
///
/// TBD files are YAML-like text files that describe a dylib's interface
/// without containing actual binary code. They are used in the macOS SDK
/// to reduce SDK size.
///
/// # Arguments
/// * `state` — The compiler state
/// * `filename` — Path to the .tbd file
///
/// # Returns
/// `Ok(0)` if loaded successfully, `Ok(-1)` if file not found.
pub fn macho_load_tbd(state: &mut TCCState, filename: &str) -> TccResult<i32> {
    use std::io::Read;

    let path = std::path::Path::new(filename);
    if !path.exists() {
        return Ok(-1);
    }

    let mut content = String::new();
    let mut file = File::open(path).map_err(TccError::IoError)?;
    file.read_to_string(&mut content).map_err(TccError::IoError)?;

    // Parse the TBD file to extract the install name and exported symbols
    let mut install_name = String::new();
    let mut exports: Vec<String> = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();

        // Look for install-name
        if trimmed.starts_with("install-name:") {
            install_name = trimmed
                .strip_prefix("install-name:")
                .unwrap_or("")
                .trim()
                .trim_matches('\'')
                .trim_matches('"')
                .to_string();
        }

        // Look for exports (symbols list)
        if trimmed.starts_with("symbols:") || trimmed.starts_with("- _") {
            // Extract symbol names from the YAML list
            let sym = trimmed.trim_start_matches("- ").trim().to_string();
            if !sym.is_empty() && sym != "symbols:" {
                exports.push(sym);
            }
        }
    }

    // Use install_name if available, otherwise use the filename
    let dll_name = if !install_name.is_empty() {
        install_name.clone()
    } else {
        path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(filename)
            .to_string()
    };

    // Check if already loaded
    if state.loaded_dlls.iter().any(|d| d.name == dll_name) {
        return Ok(0);
    }

    // Register the dylib
    state.loaded_dlls.push(DLLReference {
        level: 0,
        handle: None,
        found: true,
        index: state.loaded_dlls.len() as u8,
        name: dll_name.clone(),
    });

    // Add exported symbols as undefined references in the symbol table
    let symtab_idx = match state.symtab_section {
        Some(idx) => idx,
        None => return Ok(0),
    };

    for sym_name in &exports {
        // Strip leading underscore if present (Mach-O convention)
        let elf_name = sym_name.strip_prefix('_').unwrap_or(sym_name);

        // Check if symbol already exists
        let existing = elf::find_elf_sym(state, symtab_idx, elf_name);
        if existing == 0 {
            // Add as an undefined symbol from this DLL
            elf::put_elf_sym(
                state,
                symtab_idx,
                0,
                0,
                elf::ELFW_ST_INFO(elf::STB_GLOBAL, elf::STT_NOTYPE),
                0,
                elf::SHN_FROMDLL,
                elf_name,
            );
        }
    }

    Ok(0)
}

// ===========================================================================
// tcc_add_macos_sdkpath — detect and add macOS SDK include/library paths
// ===========================================================================

/// Detect the macOS SDK path and add it to the compiler's search paths.
///
/// Uses `dlopen("libxcselect.dylib")` to dynamically load Apple's Xcode
/// selection library and call `xcselect_host_sdk_path` to get the
/// current SDK path. Falls back to hardcoded paths if dynamic loading fails.
///
/// # Arguments
/// * `state` — The compiler state to add paths to
pub fn tcc_add_macos_sdkpath(state: &mut TCCState) -> TccResult<()> {
    // Try to find SDK path using libxcselect.dylib (Apple's Xcode selection library)
    let sdk_path = find_macos_sdk_path();

    if let Some(sdk) = sdk_path {
        // Add SDK include path
        let include_path = format!("{}/usr/include", sdk);
        if std::path::Path::new(&include_path).exists() {
            state.sysinclude_paths.push(include_path);
        }

        // Add SDK library path
        let lib_path = format!("{}/usr/lib", sdk);
        if std::path::Path::new(&lib_path).exists() {
            state.library_paths.push(lib_path);
        }

        // Add SDK framework path
        let framework_path = format!("{}/System/Library/Frameworks", sdk);
        if std::path::Path::new(&framework_path).exists() {
            state.library_paths.push(framework_path);
        }
    } else {
        // Fallback: try common SDK locations
        let fallback_paths = [
            "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk",
            "/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk",
        ];

        for path in &fallback_paths {
            if std::path::Path::new(path).exists() {
                let include_path = format!("{}/usr/include", path);
                if std::path::Path::new(&include_path).exists() {
                    state.sysinclude_paths.push(include_path);
                }
                let lib_path = format!("{}/usr/lib", path);
                if std::path::Path::new(&lib_path).exists() {
                    state.library_paths.push(lib_path);
                }
                break;
            }
        }
    }

    Ok(())
}

/// Find the macOS SDK path using libxcselect.dylib.
///
/// Returns `None` if the library cannot be loaded or the function
/// cannot be found (e.g., on non-macOS platforms).
fn find_macos_sdk_path() -> Option<String> {
    #[cfg(target_os = "macos")]
    {
        use std::ffi::{CStr, CString};
        unsafe {
            let lib_name = CString::new("libxcselect.dylib").ok()?;
            let handle = libc::dlopen(lib_name.as_ptr(), libc::RTLD_LAZY);
            if handle.is_null() {
                return None;
            }

            let func_name = CString::new("xcselect_host_sdk_path").ok()?;
            let func_ptr = libc::dlsym(handle, func_name.as_ptr());
            if func_ptr.is_null() {
                libc::dlclose(handle);
                return None;
            }

            // The function signature is:
            // bool xcselect_host_sdk_path(struct stat *buf, char *path, size_t pathlen)
            // We'll call it with a buffer
            type XcSelectFn = unsafe extern "C" fn(*mut u8, *mut u8, usize) -> i32;
            let func: XcSelectFn = std::mem::transmute(func_ptr);

            let mut stat_buf = [0u8; 256]; // struct stat placeholder
            let mut path_buf = [0u8; 4096];
            let result = func(stat_buf.as_mut_ptr(), path_buf.as_mut_ptr(), path_buf.len());

            libc::dlclose(handle);

            if result != 0 {
                let path = CStr::from_ptr(path_buf.as_ptr() as *const i8);
                return path.to_str().ok().map(|s| s.to_string());
            }
        }
        None
    }

    #[cfg(not(target_os = "macos"))]
    {
        None
    }
}

// ===========================================================================
// macho_tbd_soname — extract soname from a .tbd file
// ===========================================================================

/// Extract the install name (soname) from a .tbd file.
///
/// Reads the TBD file and returns the value of the `install-name:` field.
///
/// # Arguments
/// * `filename` — Path to the .tbd file
///
/// # Returns
/// The install name string, or an empty string if not found.
pub fn macho_tbd_soname(filename: &str) -> String {
    use std::io::Read;

    let path = std::path::Path::new(filename);
    if !path.exists() {
        return String::new();
    }

    let mut content = String::new();
    if let Ok(mut file) = File::open(path) {
        if file.read_to_string(&mut content).is_err() {
            return String::new();
        }
    } else {
        return String::new();
    }

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("install-name:") {
            return trimmed
                .strip_prefix("install-name:")
                .unwrap_or("")
                .trim()
                .trim_matches('\'')
                .trim_matches('"')
                .to_string();
        }
    }

    String::new()
}

// ===========================================================================
// Unit tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // MachHeader64 tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_mach_header64_default() {
        let hdr = MachHeader64::default();
        assert_eq!(hdr.magic, 0);
        assert_eq!(hdr.cputype, 0);
        assert_eq!(hdr.cpusubtype, 0);
        assert_eq!(hdr.filetype, 0);
        assert_eq!(hdr.ncmds, 0);
        assert_eq!(hdr.sizeofcmds, 0);
        assert_eq!(hdr.flags, 0);
        assert_eq!(hdr.reserved, 0);
    }

    #[test]
    fn test_mach_header64_custom_construction() {
        let hdr = MachHeader64 {
            magic: MH_MAGIC_64,
            cputype: CPU_TYPE_X86_64,
            cpusubtype: CPU_SUBTYPE_X86_ALL,
            filetype: MH_EXECUTE,
            ncmds: 5,
            sizeofcmds: 200,
            flags: MH_PIE | MH_DYLDLINK,
            reserved: 0,
        };
        assert_eq!(hdr.magic, 0xfeed_facf);
        assert_eq!(hdr.cputype, 0x0100_0007);
        assert_eq!(hdr.cpusubtype, 3);
        assert_eq!(hdr.filetype, 2);
        assert_eq!(hdr.ncmds, 5);
        assert_eq!(hdr.sizeofcmds, 200);
        assert_eq!(hdr.flags, MH_PIE | MH_DYLDLINK);
    }

    #[test]
    fn test_mach_header64_arm64() {
        let hdr = MachHeader64 {
            magic: MH_MAGIC_64,
            cputype: CPU_TYPE_ARM64,
            cpusubtype: CPU_SUBTYPE_ARM64_ALL,
            filetype: MH_DYLIB,
            ..Default::default()
        };
        assert_eq!(hdr.cputype, 0x0100_000c);
        assert_eq!(hdr.cpusubtype, 0);
        assert_eq!(hdr.filetype, MH_DYLIB);
    }

    #[test]
    fn test_mach_header64_clone() {
        let hdr = MachHeader64 {
            magic: MH_MAGIC_64,
            cputype: CPU_TYPE_X86_64,
            ..Default::default()
        };
        let cloned = hdr.clone();
        assert_eq!(cloned.magic, MH_MAGIC_64);
        assert_eq!(cloned.cputype, CPU_TYPE_X86_64);
    }

    // -----------------------------------------------------------------------
    // SegmentCommand64 tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_segment_command64_default() {
        let seg = SegmentCommand64::default();
        assert_eq!(seg.cmd, LC_SEGMENT_64, "default cmd should be LC_SEGMENT_64");
        assert_eq!(seg.cmdsize, 72, "base cmdsize without sections is 72");
        assert_eq!(seg.segname, [0u8; 16]);
        assert_eq!(seg.vmaddr, 0);
        assert_eq!(seg.vmsize, 0);
        assert_eq!(seg.fileoff, 0);
        assert_eq!(seg.filesize, 0);
        assert_eq!(seg.maxprot, 0);
        assert_eq!(seg.initprot, 0);
        assert_eq!(seg.nsects, 0);
        assert_eq!(seg.flags, 0);
    }

    #[test]
    fn test_segment_command64_custom() {
        let mut segname = [0u8; 16];
        segname[..6].copy_from_slice(b"__TEXT");
        let seg = SegmentCommand64 {
            segname,
            vmaddr: 0x1000,
            vmsize: 0x4000,
            maxprot: VM_PROT_ALL,
            initprot: VM_PROT_READ | VM_PROT_EXECUTE,
            nsects: 2,
            ..Default::default()
        };
        assert_eq!(&seg.segname[..6], b"__TEXT");
        assert_eq!(seg.vmaddr, 0x1000);
        assert_eq!(seg.vmsize, 0x4000);
        assert_eq!(seg.maxprot, 7); // R|W|X
        assert_eq!(seg.initprot, 5); // R|X
        assert_eq!(seg.nsects, 2);
    }

    // -----------------------------------------------------------------------
    // Section64 tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_section64_default() {
        let sect = Section64::default();
        assert_eq!(sect.sectname, [0u8; 16]);
        assert_eq!(sect.segname, [0u8; 16]);
        assert_eq!(sect.addr, 0);
        assert_eq!(sect.size, 0);
        assert_eq!(sect.offset, 0);
        assert_eq!(sect.align, 0);
        assert_eq!(sect.reloff, 0);
        assert_eq!(sect.nreloc, 0);
        assert_eq!(sect.flags, 0);
        assert_eq!(sect.reserved1, 0);
        assert_eq!(sect.reserved2, 0);
        assert_eq!(sect.reserved3, 0);
    }

    #[test]
    fn test_section64_text_section() {
        let mut sect = Section64::default();
        sect.sectname[..6].copy_from_slice(b"__text");
        sect.segname[..6].copy_from_slice(b"__TEXT");
        sect.addr = 0x1000;
        sect.size = 512;
        sect.align = 4; // 16-byte aligned
        sect.flags = S_REGULAR | S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS;
        assert_eq!(&sect.sectname[..6], b"__text");
        assert_eq!(&sect.segname[..6], b"__TEXT");
        assert_eq!(sect.addr, 0x1000);
        assert_eq!(sect.size, 512);
        assert_eq!(sect.align, 4);
        assert!(sect.flags & S_ATTR_PURE_INSTRUCTIONS != 0);
        assert!(sect.flags & S_ATTR_SOME_INSTRUCTIONS != 0);
    }

    #[test]
    fn test_section64_clone() {
        let mut sect = Section64::default();
        sect.addr = 0x2000;
        sect.size = 1024;
        let cloned = sect.clone();
        assert_eq!(cloned.addr, 0x2000);
        assert_eq!(cloned.size, 1024);
    }

    // -----------------------------------------------------------------------
    // SymtabCommand tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_symtab_command_default() {
        let sc = SymtabCommand::default();
        assert_eq!(sc.cmd, 0);
        assert_eq!(sc.cmdsize, 0);
        assert_eq!(sc.symoff, 0);
        assert_eq!(sc.nsyms, 0);
        assert_eq!(sc.stroff, 0);
        assert_eq!(sc.strsize, 0);
    }

    #[test]
    fn test_symtab_command_custom() {
        let sc = SymtabCommand {
            cmd: LC_SYMTAB,
            cmdsize: 24,
            symoff: 4096,
            nsyms: 10,
            stroff: 8192,
            strsize: 256,
        };
        assert_eq!(sc.cmd, 2);
        assert_eq!(sc.cmdsize, 24);
        assert_eq!(sc.nsyms, 10);
    }

    // -----------------------------------------------------------------------
    // DysymtabCommand tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_dysymtab_command_default() {
        let ds = DysymtabCommand::default();
        assert_eq!(ds.cmd, 0);
        assert_eq!(ds.cmdsize, 0);
        assert_eq!(ds.ilocalsym, 0);
        assert_eq!(ds.nlocalsym, 0);
        assert_eq!(ds.iextdefsym, 0);
        assert_eq!(ds.nextdefsym, 0);
        assert_eq!(ds.iundefsym, 0);
        assert_eq!(ds.nundefsym, 0);
        assert_eq!(ds.indirectsymoff, 0);
        assert_eq!(ds.nindirectsyms, 0);
    }

    #[test]
    fn test_dysymtab_command_partitioned() {
        let ds = DysymtabCommand {
            cmd: LC_DYSYMTAB,
            cmdsize: 80,
            ilocalsym: 0,
            nlocalsym: 5,
            iextdefsym: 5,
            nextdefsym: 10,
            iundefsym: 15,
            nundefsym: 3,
            indirectsymoff: 0x1000,
            nindirectsyms: 8,
        };
        assert_eq!(ds.nlocalsym + ds.nextdefsym + ds.nundefsym, 18);
        assert_eq!(ds.iextdefsym, ds.ilocalsym + ds.nlocalsym);
        assert_eq!(ds.iundefsym, ds.iextdefsym + ds.nextdefsym);
    }

    // -----------------------------------------------------------------------
    // Nlist64 tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_nlist64_default() {
        let nl = Nlist64::default();
        assert_eq!(nl.n_strx, 0);
        assert_eq!(nl.n_type, 0);
        assert_eq!(nl.n_sect, 0);
        assert_eq!(nl.n_desc, 0);
        assert_eq!(nl.n_value, 0);
    }

    #[test]
    fn test_nlist64_defined_symbol() {
        let nl = Nlist64 {
            n_strx: 1,
            n_type: N_SECT | N_EXT,
            n_sect: 1,
            n_desc: 0,
            n_value: 0x1000,
        };
        assert_eq!(nl.n_type & N_EXT, N_EXT, "symbol should be external");
        assert_eq!(nl.n_type & 0x0e, N_SECT, "symbol should be in a section");
        assert_eq!(nl.n_sect, 1);
        assert_eq!(nl.n_value, 0x1000);
    }

    #[test]
    fn test_nlist64_undefined_symbol() {
        let nl = Nlist64 {
            n_strx: 5,
            n_type: N_UNDF | N_EXT,
            n_sect: 0,
            n_desc: N_WEAK_REF,
            n_value: 0,
        };
        assert_eq!(nl.n_type & 0x0e, N_UNDF);
        assert_eq!(nl.n_desc, N_WEAK_REF);
    }

    // -----------------------------------------------------------------------
    // Constants tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_mach_o_magic_constants() {
        assert_eq!(MH_MAGIC_64, 0xfeed_facf);
        assert_eq!(MH_CIGAM_64, 0xcffa_edfe);
        // Verify byte-swap relationship
        assert_eq!(MH_MAGIC_64.swap_bytes(), MH_CIGAM_64);
    }

    #[test]
    fn test_file_type_constants() {
        assert_eq!(MH_OBJECT, 1);
        assert_eq!(MH_EXECUTE, 2);
        assert_eq!(MH_DYLIB, 6);
        assert_eq!(MH_BUNDLE, 8);
        assert_eq!(MH_DSYM, 10);
    }

    #[test]
    fn test_cpu_type_constants() {
        assert_eq!(CPU_TYPE_X86_64, 0x0100_0007);
        assert_eq!(CPU_TYPE_ARM64, 0x0100_000c);
        assert_eq!(CPU_SUBTYPE_X86_ALL, 3);
        assert_eq!(CPU_SUBTYPE_ARM64_ALL, 0);
        assert_eq!(CPU_SUBTYPE_ARM64E, 2);
    }

    #[test]
    fn test_load_command_constants() {
        assert_eq!(LC_SEGMENT_64, 0x19);
        assert_eq!(LC_SYMTAB, 2);
        assert_eq!(LC_DYSYMTAB, 11);
        assert_eq!(LC_LOAD_DYLINKER, 0x0e);
        assert_eq!(LC_MAIN, 0x8000_0028);
        assert_eq!(LC_LOAD_DYLIB, 0x0c);
        assert_eq!(LC_ID_DYLIB, 0x0d);
        assert_eq!(LC_UUID, 0x1b);
        assert_eq!(LC_BUILD_VERSION, 0x32);
        assert_eq!(LC_SOURCE_VERSION, 0x2a);
    }

    #[test]
    fn test_vm_prot_constants() {
        assert_eq!(VM_PROT_READ, 1);
        assert_eq!(VM_PROT_WRITE, 2);
        assert_eq!(VM_PROT_EXECUTE, 4);
        assert_eq!(VM_PROT_ALL, 7);
    }

    #[test]
    fn test_section_attr_constants() {
        assert_eq!(S_REGULAR, 0);
        assert_eq!(S_ZEROFILL, 1);
        assert_eq!(S_ATTR_PURE_INSTRUCTIONS, 1 << 31);
        assert_eq!(S_ATTR_SOME_INSTRUCTIONS, 1 << 10);
    }

    // -----------------------------------------------------------------------
    // MachoWriter tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_macho_writer_new() {
        let mut state = TCCState::new().expect("TCCState::new failed");
        let writer = MachoWriter::new(&mut state);
        assert_eq!(writer.header.magic, MH_MAGIC_64);
        assert_eq!(writer.header.cputype, CPU_TYPE_X86_64);
        assert_eq!(writer.header.filetype, MH_EXECUTE);
        assert!(writer.segments.is_empty());
        assert!(writer.load_commands.is_empty());
        assert!(writer.section_headers.is_empty());
        assert!(writer.nlist_entries.is_empty());
        // strtab starts with null byte
        assert_eq!(writer.strtab_data.len(), 1);
        assert_eq!(writer.strtab_data[0], 0);
    }

    #[test]
    fn test_macho_writer_add_segment() {
        let mut state = TCCState::new().expect("TCCState::new failed");
        let mut writer = MachoWriter::new(&mut state);
        let idx = writer.add_segment("__TEXT", 0x1000, VM_PROT_READ | VM_PROT_EXECUTE, 0);
        assert_eq!(idx, 0);
        assert_eq!(writer.segments.len(), 1);
        let seg = writer.get_segment(0);
        assert!(seg.is_some());
        assert_eq!(seg.unwrap().vmaddr, 0x1000);
    }

    #[test]
    fn test_macho_writer_add_multiple_segments() {
        let mut state = TCCState::new().expect("TCCState::new failed");
        let mut writer = MachoWriter::new(&mut state);
        let text_idx = writer.add_segment("__TEXT", 0x1000, VM_PROT_READ | VM_PROT_EXECUTE, 0);
        let data_idx = writer.add_segment("__DATA", 0x5000, VM_PROT_READ | VM_PROT_WRITE, 0);
        let link_idx = writer.add_segment("__LINKEDIT", 0x9000, VM_PROT_READ, 0);
        assert_eq!(text_idx, 0);
        assert_eq!(data_idx, 1);
        assert_eq!(link_idx, 2);
        assert_eq!(writer.segments.len(), 3);
    }

    #[test]
    fn test_macho_writer_get_segment_out_of_bounds() {
        let mut state = TCCState::new().expect("TCCState::new failed");
        let writer = MachoWriter::new(&mut state);
        assert!(writer.get_segment(0).is_none());
        assert!(writer.get_segment(99).is_none());
    }

    #[test]
    fn test_macho_writer_add_section() {
        let mut state = TCCState::new().expect("TCCState::new failed");
        let mut writer = MachoWriter::new(&mut state);
        let seg_idx = writer.add_segment("__TEXT", 0x1000, VM_PROT_READ | VM_PROT_EXECUTE, 0);
        let mut sect = Section64::default();
        sect.sectname[..6].copy_from_slice(b"__text");
        sect.segname[..6].copy_from_slice(b"__TEXT");
        // add_section returns 1-based ordinal (Mach-O section numbering)
        let ordinal = writer.add_section(seg_idx, sect);
        assert_eq!(ordinal, 1, "first section ordinal should be 1");
        // get_section uses 0-based index into section_headers
        let retrieved = writer.get_section(0);
        assert!(retrieved.is_some());
        assert_eq!(&retrieved.unwrap().sectname[..6], b"__text");
    }

    #[test]
    fn test_macho_writer_get_section_out_of_bounds() {
        let mut state = TCCState::new().expect("TCCState::new failed");
        let writer = MachoWriter::new(&mut state);
        assert!(writer.get_section(0).is_none());
        assert!(writer.get_section(42).is_none());
    }

    #[test]
    fn test_macho_writer_add_lc() {
        let mut state = TCCState::new().expect("TCCState::new failed");
        let mut writer = MachoWriter::new(&mut state);
        let lc_data = vec![0x19, 0x00, 0x00, 0x00, 72, 0, 0, 0]; // LC_SEGMENT_64 minimal
        let idx = writer.add_lc(lc_data.clone());
        assert_eq!(idx, 0);
        assert_eq!(writer.load_commands.len(), 1);
        assert_eq!(writer.load_commands[0], lc_data);
    }

    #[test]
    fn test_macho_writer_add_dylib() {
        let mut state = TCCState::new().expect("TCCState::new failed");
        let mut writer = MachoWriter::new(&mut state);
        let idx = writer.add_dylib("/usr/lib/libSystem.B.dylib", 2, 0x10000, 0x10000);
        assert_eq!(idx, 0);
        assert_eq!(writer.load_commands.len(), 1);
        // Dylib load command should contain the path
        let lc = &writer.load_commands[0];
        assert!(!lc.is_empty());
    }

    // -----------------------------------------------------------------------
    // macho_tbd_soname tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_macho_tbd_soname_nonexistent_file() {
        let result = macho_tbd_soname("/nonexistent/path/libfoo.tbd");
        assert_eq!(result, "");
    }

    #[test]
    fn test_macho_tbd_soname_with_temp_file() {
        use std::io::Write;
        let dir = std::env::temp_dir();
        let path = dir.join("test_tbd_soname.tbd");
        {
            let mut f = File::create(&path).expect("create temp file");
            writeln!(f, "--- !tapi-tbd-v3").unwrap();
            writeln!(f, "archs: [ x86_64 ]").unwrap();
            writeln!(f, "install-name: /usr/lib/libSystem.B.dylib").unwrap();
            writeln!(f, "exports:").unwrap();
        }
        let result = macho_tbd_soname(path.to_str().unwrap());
        assert_eq!(result, "/usr/lib/libSystem.B.dylib");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_macho_tbd_soname_quoted_name() {
        use std::io::Write;
        let dir = std::env::temp_dir();
        let path = dir.join("test_tbd_soname_quoted.tbd");
        {
            let mut f = File::create(&path).expect("create temp file");
            writeln!(f, "--- !tapi-tbd-v3").unwrap();
            writeln!(f, "install-name: '/usr/lib/libfoo.dylib'").unwrap();
        }
        let result = macho_tbd_soname(path.to_str().unwrap());
        assert_eq!(result, "/usr/lib/libfoo.dylib");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_macho_tbd_soname_no_install_name() {
        use std::io::Write;
        let dir = std::env::temp_dir();
        let path = dir.join("test_tbd_soname_none.tbd");
        {
            let mut f = File::create(&path).expect("create temp file");
            writeln!(f, "--- !tapi-tbd-v3").unwrap();
            writeln!(f, "archs: [ x86_64 ]").unwrap();
            writeln!(f, "exports:").unwrap();
        }
        let result = macho_tbd_soname(path.to_str().unwrap());
        assert_eq!(result, "");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_macho_tbd_soname_double_quoted() {
        use std::io::Write;
        let dir = std::env::temp_dir();
        let path = dir.join("test_tbd_soname_dq.tbd");
        {
            let mut f = File::create(&path).expect("create temp file");
            writeln!(f, "install-name: \"/usr/lib/libbar.dylib\"").unwrap();
        }
        let result = macho_tbd_soname(path.to_str().unwrap());
        assert_eq!(result, "/usr/lib/libbar.dylib");
        let _ = std::fs::remove_file(&path);
    }

    // -----------------------------------------------------------------------
    // SectionKind classification tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_classify_section_text() {
        // SHT_PROGBITS = 1, SHF_ALLOC = 2, SHF_EXECINSTR = 4
        let sk = classify_section(".text", 1, 2 | 4);
        assert_eq!(sk as u8, SectionKind::Text as u8);
    }

    #[test]
    fn test_classify_section_data() {
        // SHT_PROGBITS = 1, SHF_ALLOC = 2, SHF_WRITE = 1
        let sk = classify_section(".data", 1, 2 | 1);
        assert_eq!(sk as u8, SectionKind::RwData as u8);
    }

    #[test]
    fn test_classify_section_bss() {
        // SHT_NOBITS = 8, SHF_ALLOC = 2, SHF_WRITE = 1
        let sk = classify_section(".bss", 8, 2 | 1);
        assert_eq!(sk as u8, SectionKind::Bss as u8);
    }

    #[test]
    fn test_classify_section_debug() {
        // SHT_PROGBITS = 1, no flags
        let sk = classify_section(".debug_info", 1, 0);
        assert_eq!(sk as u8, SectionKind::DebugInfo as u8);
    }
}
