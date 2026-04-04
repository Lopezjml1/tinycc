//! PE/COFF Output Module — Port of `tccpe.c` (2,114 lines)
//!
//! This module implements PE (Portable Executable) and COFF output for
//! Windows targets. It handles:
//! - PE executable and DLL generation
//! - Import/export table construction
//! - Base relocation tables
//! - Resource section processing
//! - .def file loading for DLL imports
//! - DLL loading and export extraction
//! - x86_64 unwind data (.pdata) generation
//!
//! The module preserves behavioral equivalence with the original C
//! implementation while leveraging Rust's type safety and error handling.

// PE/COFF format uses Windows-style naming conventions (PascalCase struct fields,
// SCREAMING_CASE constants with full IMAGE_ prefixes). We preserve these for
// direct correspondence with the PE specification and original C code.
#![allow(non_snake_case, non_camel_case_types, dead_code, unused_variables)]

use std::fs;
use std::io::{self, BufWriter, Read, Seek, Write};
use std::mem;
use std::path::Path;

use crate::arch::{read16le, read32le, write16le, write32le, TargetArch};
use crate::config::LIBTCC1;
use crate::error::{TccError, TccResult};
use crate::elf::{
    find_elf_sym, find_section, get_sym_addr, get_sym_attr, get_sym_info, get_sym_name_offset,
    get_sym_other, get_sym_shndx, get_sym_value, new_section, put_elf_reloc,
    resolve_common_syms, relocate_syms, section_ptr_add,
    set_elf_sym, sym_count,
    ELFW_R_TYPE, ELFW_ST_BIND, ELFW_ST_INFO, ELFW_ST_TYPE,
    SHF_ALLOC, SHF_EXECINSTR, SHF_WRITE,
    SHN_FROMDLL, SHN_UNDEF,
    SHT_INIT_ARRAY, SHT_FINI_ARRAY, SHT_NOBITS, SHT_PROGBITS, SHT_RELX,
    SHT_STRTAB, SHT_SYMTAB,
    STB_GLOBAL, STB_LOCAL,
    STT_FUNC,
};
use crate::types::{DLLReference, OutputType, Section};
use crate::TCCState;

// ============================================================
// PE Constants
// ============================================================

/// Symbol type flag: PE export attribute.
pub const ST_PE_EXPORT: u8 = 0x10;
/// Symbol type flag: PE import attribute.
pub const ST_PE_IMPORT: u8 = 0x20;
/// Symbol type flag: stdcall convention with @N decoration.
pub const ST_PE_STDCALL: u8 = 0x40;

/// Machine type for i386 PE files.
pub const IMAGE_FILE_MACHINE_I386: u16 = 0x014c;
/// Machine type for x86_64 PE files.
pub const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
/// Machine type for ARM PE files.
pub const IMAGE_FILE_MACHINE_ARMNT: u16 = 0x01c4;

// PE subsystem values
const IMAGE_SUBSYSTEM_UNKNOWN: u16 = 0;
const IMAGE_SUBSYSTEM_NATIVE: u16 = 1;
const IMAGE_SUBSYSTEM_WINDOWS_GUI: u16 = 2;
const IMAGE_SUBSYSTEM_WINDOWS_CUI: u16 = 3;
const IMAGE_SUBSYSTEM_EFI_APPLICATION: u16 = 10;

// Section characteristic flags
const IMAGE_SCN_CNT_CODE: u32 = 0x0000_0020;
const IMAGE_SCN_CNT_INITIALIZED_DATA: u32 = 0x0000_0040;
const IMAGE_SCN_CNT_UNINITIALIZED_DATA: u32 = 0x0000_0080;
const IMAGE_SCN_LNK_OTHER: u32 = 0x0000_0100;
const IMAGE_SCN_LNK_REMOVE: u32 = 0x0000_0800;
const IMAGE_SCN_MEM_DISCARDABLE: u32 = 0x0200_0000;
const IMAGE_SCN_MEM_NOT_CACHED: u32 = 0x0400_0000;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;

// Image file characteristics
const IMAGE_FILE_RELOCS_STRIPPED: u16 = 0x0001;
const IMAGE_FILE_EXECUTABLE_IMAGE: u16 = 0x0002;
const IMAGE_FILE_LINE_NUMS_STRIPPED: u16 = 0x0004;
const IMAGE_FILE_LOCAL_SYMS_STRIPPED: u16 = 0x0008;
const IMAGE_FILE_LARGE_ADDRESS_AWARE: u16 = 0x0020;
const IMAGE_FILE_32BIT_MACHINE: u16 = 0x0100;
const IMAGE_FILE_DLL: u16 = 0x2000;

// DLL characteristics
const IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE: u16 = 0x0040;
const IMAGE_DLL_CHARACTERISTICS_NX_COMPAT: u16 = 0x0100;
const IMAGE_DLL_CHARACTERISTICS_HIGH_ENTROPY_VA: u16 = 0x0020;

// Optional header magic
const PE32_MAGIC: u16 = 0x010b;
const PE32PLUS_MAGIC: u16 = 0x020b;

// Data directory indices
const IMAGE_DIRECTORY_ENTRY_EXPORT: usize = 0;
const IMAGE_DIRECTORY_ENTRY_IMPORT: usize = 1;
const IMAGE_DIRECTORY_ENTRY_RESOURCE: usize = 2;
const IMAGE_DIRECTORY_ENTRY_BASERELOC: usize = 5;
const IMAGE_DIRECTORY_ENTRY_DEBUG: usize = 6;
const IMAGE_DIRECTORY_ENTRY_IAT: usize = 12;
const IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT: usize = 13;
const IMAGE_NUMBER_OF_DIRECTORY_ENTRIES: usize = 16;

// Base relocation types
const IMAGE_REL_BASED_ABSOLUTE: u16 = 0;
const IMAGE_REL_BASED_HIGH: u16 = 1;
const IMAGE_REL_BASED_LOW: u16 = 2;
const IMAGE_REL_BASED_HIGHLOW: u16 = 3;
const IMAGE_REL_BASED_DIR64: u16 = 10;

/// DOS stub magic bytes ("MZ").
const MZ_MAGIC: u16 = 0x5A4D;
/// PE signature ("PE\0\0").
const PE_SIGNATURE: u32 = 0x0000_4550;

// Section alignment and file alignment defaults
const PE_SECTION_ALIGN: u32 = 0x1000;
const PE_FILE_ALIGN_DEFAULT: u32 = 0x200;

// Default image bases
const PE_IMAGEBASE_32: u64 = 0x0040_0000;
const PE_IMAGEBASE_64: u64 = 0x0000_0001_4000_0000;
const PE_DLL_IMAGEBASE_32: u64 = 0x1000_0000;
const PE_DLL_IMAGEBASE_64: u64 = 0x0000_0001_8000_0000;

// Stack size defaults
const PE_STACK_SIZE_DEFAULT: u64 = 0x0010_0000;
const PE_HEAP_SIZE_DEFAULT: u64 = 0x0010_0000;

// PE section indices used in the writer
const PE_SEC_TEXT: usize = 0;
const PE_SEC_DATA: usize = 1;
const PE_SEC_BSS: usize = 2;
const PE_SEC_IDATA: usize = 3;
const PE_SEC_PDATA: usize = 4;
const PE_SEC_RSRC: usize = 5;
const PE_SEC_RELOC: usize = 6;
const PE_SEC_DEBUG: usize = 7;
const PE_SEC_RDATA: usize = 8;
const PE_SEC_STAB: usize = 9;
const PE_SEC_NUMBER: usize = 10;

// ============================================================
// PE Format Structures
// ============================================================

/// IMAGE_DOS_HEADER — The initial header of any PE file.
/// Only e_magic and e_lfanew are significant for modern PE files;
/// all other fields are for legacy DOS compatibility.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct ImageDosHeader {
    /// Magic number ("MZ" = 0x5A4D).
    pub e_magic: u16,
    /// Bytes on last page of file.
    pub e_cblp: u16,
    /// Pages in file.
    pub e_cp: u16,
    /// Relocations.
    pub e_crlc: u16,
    /// Size of header in paragraphs.
    pub e_cparhdr: u16,
    /// Minimum extra paragraphs needed.
    pub e_minalloc: u16,
    /// Maximum extra paragraphs needed.
    pub e_maxalloc: u16,
    /// Initial SS value.
    pub e_ss: u16,
    /// Initial SP value.
    pub e_sp: u16,
    /// Checksum.
    pub e_csum: u16,
    /// Initial IP value.
    pub e_ip: u16,
    /// Initial CS value.
    pub e_cs: u16,
    /// File offset of relocation table.
    pub e_lfarlc: u16,
    /// Overlay number.
    pub e_ovno: u16,
    /// Reserved words.
    pub e_res: [u16; 4],
    /// OEM identifier.
    pub e_oemid: u16,
    /// OEM information.
    pub e_oeminfo: u16,
    /// Reserved words.
    pub e_res2: [u16; 10],
    /// File offset to the PE signature and IMAGE_NT_HEADERS.
    pub e_lfanew: i32,
}

/// IMAGE_FILE_HEADER — COFF file header.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct ImageFileHeader {
    /// Target machine architecture.
    pub Machine: u16,
    /// Number of sections.
    pub NumberOfSections: u16,
    /// Creation timestamp.
    pub TimeDateStamp: u32,
    /// File pointer to COFF symbol table.
    pub PointerToSymbolTable: u32,
    /// Number of entries in the symbol table.
    pub NumberOfSymbols: u32,
    /// Size of the optional header.
    pub SizeOfOptionalHeader: u16,
    /// File attribute flags.
    pub Characteristics: u16,
}

/// IMAGE_DATA_DIRECTORY — Describes a data directory entry in the optional header.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct ImageDataDirectory {
    /// Relative virtual address.
    pub VirtualAddress: u32,
    /// Size in bytes.
    pub Size: u32,
}

/// IMAGE_OPTIONAL_HEADER (32-bit) — Contains OS/linker configuration.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ImageOptionalHeader32 {
    pub Magic: u16,
    pub MajorLinkerVersion: u8,
    pub MinorLinkerVersion: u8,
    pub SizeOfCode: u32,
    pub SizeOfInitializedData: u32,
    pub SizeOfUninitializedData: u32,
    pub AddressOfEntryPoint: u32,
    pub BaseOfCode: u32,
    pub BaseOfData: u32,
    pub ImageBase: u32,
    pub SectionAlignment: u32,
    pub FileAlignment: u32,
    pub MajorOperatingSystemVersion: u16,
    pub MinorOperatingSystemVersion: u16,
    pub MajorImageVersion: u16,
    pub MinorImageVersion: u16,
    pub MajorSubsystemVersion: u16,
    pub MinorSubsystemVersion: u16,
    pub Win32VersionValue: u32,
    pub SizeOfImage: u32,
    pub SizeOfHeaders: u32,
    pub CheckSum: u32,
    pub Subsystem: u16,
    pub DllCharacteristics: u16,
    pub SizeOfStackReserve: u32,
    pub SizeOfStackCommit: u32,
    pub SizeOfHeapReserve: u32,
    pub SizeOfHeapCommit: u32,
    pub LoaderFlags: u32,
    pub NumberOfRvaAndSizes: u32,
    pub DataDirectory: [ImageDataDirectory; IMAGE_NUMBER_OF_DIRECTORY_ENTRIES],
}

impl Default for ImageOptionalHeader32 {
    fn default() -> Self {
        // Safety: All fields are integer types, zeroed is valid
        unsafe { mem::zeroed() }
    }
}

/// IMAGE_OPTIONAL_HEADER (64-bit / PE32+) — Contains OS/linker configuration.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ImageOptionalHeader64 {
    pub Magic: u16,
    pub MajorLinkerVersion: u8,
    pub MinorLinkerVersion: u8,
    pub SizeOfCode: u32,
    pub SizeOfInitializedData: u32,
    pub SizeOfUninitializedData: u32,
    pub AddressOfEntryPoint: u32,
    pub BaseOfCode: u32,
    pub ImageBase: u64,
    pub SectionAlignment: u32,
    pub FileAlignment: u32,
    pub MajorOperatingSystemVersion: u16,
    pub MinorOperatingSystemVersion: u16,
    pub MajorImageVersion: u16,
    pub MinorImageVersion: u16,
    pub MajorSubsystemVersion: u16,
    pub MinorSubsystemVersion: u16,
    pub Win32VersionValue: u32,
    pub SizeOfImage: u32,
    pub SizeOfHeaders: u32,
    pub CheckSum: u32,
    pub Subsystem: u16,
    pub DllCharacteristics: u16,
    pub SizeOfStackReserve: u64,
    pub SizeOfStackCommit: u64,
    pub SizeOfHeapReserve: u64,
    pub SizeOfHeapCommit: u64,
    pub LoaderFlags: u32,
    pub NumberOfRvaAndSizes: u32,
    pub DataDirectory: [ImageDataDirectory; IMAGE_NUMBER_OF_DIRECTORY_ENTRIES],
}

impl Default for ImageOptionalHeader64 {
    fn default() -> Self {
        unsafe { mem::zeroed() }
    }
}

/// IMAGE_SECTION_HEADER — Describes one section in the PE file.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ImageSectionHeader {
    /// Section name (up to 8 bytes, NUL-padded).
    pub Name: [u8; 8],
    /// Virtual size of the section (when loaded).
    pub VirtualSize: u32,
    /// RVA of the section start when loaded.
    pub VirtualAddress: u32,
    /// Size of raw data on disk (file-aligned).
    pub SizeOfRawData: u32,
    /// File pointer to the raw data.
    pub PointerToRawData: u32,
    /// File pointer to relocations (always 0 in executables).
    pub PointerToRelocations: u32,
    /// File pointer to line numbers (deprecated).
    pub PointerToLinenumbers: u32,
    /// Number of relocation entries.
    pub NumberOfRelocations: u16,
    /// Number of line-number entries.
    pub NumberOfLinenumbers: u16,
    /// Section attribute flags.
    pub Characteristics: u32,
}

impl Default for ImageSectionHeader {
    fn default() -> Self {
        unsafe { mem::zeroed() }
    }
}

/// IMAGE_IMPORT_DESCRIPTOR — Entry in the import directory table.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct ImageImportDescriptor {
    /// RVA of the Import Lookup Table (INT) / Characteristics.
    pub OriginalFirstThunk: u32,
    /// Timestamp (0 if not bound).
    pub TimeDateStamp: u32,
    /// Forwarder chain index (-1 if no forwarders).
    pub ForwarderChain: u32,
    /// RVA of the DLL name string.
    pub Name: u32,
    /// RVA of the Import Address Table (IAT).
    pub FirstThunk: u32,
}

/// IMAGE_EXPORT_DIRECTORY — Export directory table.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct ImageExportDirectory {
    /// Reserved, must be 0.
    pub Characteristics: u32,
    /// Creation timestamp.
    pub TimeDateStamp: u32,
    /// Major version.
    pub MajorVersion: u16,
    /// Minor version.
    pub MinorVersion: u16,
    /// RVA of the DLL name.
    pub Name: u32,
    /// Starting ordinal number.
    pub Base: u32,
    /// Number of entries in the Export Address Table.
    pub NumberOfFunctions: u32,
    /// Number of entries in the Name Pointer Table.
    pub NumberOfNames: u32,
    /// RVA of the Export Address Table.
    pub AddressOfFunctions: u32,
    /// RVA of the Export Name Pointer Table.
    pub AddressOfNames: u32,
    /// RVA of the Ordinal Table.
    pub AddressOfNameOrdinals: u32,
}

/// IMAGE_BASE_RELOCATION — Block header for base relocations.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct ImageBaseRelocation {
    /// Page RVA (base of the relocation block).
    pub VirtualAddress: u32,
    /// Total size of this block including this header and the entries.
    pub SizeOfBlock: u32,
}

/// IMAGE_RESOURCE_DIRECTORY — Resource directory entry (used in .rsrc).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct ImageResourceDirectory {
    pub Characteristics: u32,
    pub TimeDateStamp: u32,
    pub MajorVersion: u16,
    pub MinorVersion: u16,
    pub NumberOfNamedEntries: u16,
    pub NumberOfIdEntries: u16,
}

// ============================================================
// PE Type Enum and PE Writer State
// ============================================================

/// PE output type — determines the kind of PE file being generated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeType {
    /// Standard console executable (subsystem = CUI).
    Exe = 3,
    /// GUI executable (subsystem = GUI).
    Gui = 2,
    /// Dynamic-link library.
    Dll = 1,
    /// In-memory execution mode (no file output).
    Run = 4,
}

impl PeType {
    /// Create PeType from output type and subsystem.
    pub fn from_state(output_type: Option<OutputType>, subsystem: u16) -> Self {
        match output_type {
            Some(OutputType::Dll) => PeType::Dll,
            Some(OutputType::Memory) => PeType::Run,
            Some(OutputType::Exe) => {
                if subsystem == IMAGE_SUBSYSTEM_WINDOWS_GUI {
                    PeType::Gui
                } else {
                    PeType::Exe
                }
            }
            _ => PeType::Exe,
        }
    }
}

/// Internal section classification for PE output.
/// Each ELF section is classified into one of these PE section categories.
struct PeSectionClass {
    /// Name of the PE output section.
    name: &'static str,
    /// PE section characteristics flags.
    flags: u32,
}

/// PE section class definitions — maps PE_SEC_* index to section properties.
const PE_SEC_CLASSES: [PeSectionClass; PE_SEC_NUMBER] = [
    PeSectionClass { name: ".text", flags: IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ },
    PeSectionClass { name: ".data", flags: IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE },
    PeSectionClass { name: ".bss", flags: IMAGE_SCN_CNT_UNINITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE },
    PeSectionClass { name: ".idata", flags: IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE },
    PeSectionClass { name: ".pdata", flags: IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ },
    PeSectionClass { name: ".rsrc", flags: IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ },
    PeSectionClass { name: ".reloc", flags: IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_DISCARDABLE | IMAGE_SCN_MEM_READ },
    PeSectionClass { name: ".debug", flags: IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_DISCARDABLE | IMAGE_SCN_MEM_READ },
    PeSectionClass { name: ".rdata", flags: IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ },
    PeSectionClass { name: ".stab", flags: IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_DISCARDABLE | IMAGE_SCN_MEM_READ },
];

/// Entry tracking an ELF section assigned to a PE section category.
struct PeSectionEntry {
    /// Index into the TCCState sections array.
    section_idx: usize,
}

/// Describes one PE output section (may contain multiple ELF sections).
struct PeOutputSection {
    /// PE section class index (PE_SEC_TEXT, PE_SEC_DATA, etc.).
    cls: usize,
    /// ELF section indices belonging to this PE section.
    entries: Vec<usize>,
    /// Virtual address of this PE section.
    virtual_addr: u32,
    /// Virtual size (unaligned).
    virtual_size: u32,
    /// Raw data size (file-aligned).
    raw_size: u32,
    /// File offset of raw data.
    raw_offset: u32,
}

/// Import entry — tracks one import from a DLL.
struct PeImportEntry {
    /// DLL index in loaded_dlls.
    dll_index: usize,
    /// Symbol index in the symbol table.
    sym_index: usize,
}

/// Export entry — tracks one exported symbol.
struct PeExportEntry {
    /// Symbol name.
    name: String,
    /// Symbol index in the symbol table.
    sym_index: usize,
    /// Ordinal number (-1 for auto-assigned).
    ordinal: i32,
}

/// The PE writer state, analogous to `struct pe_info` in tccpe.c.
/// Orchestrates the entire PE/DLL output process.
pub struct PeWriter<'a> {
    /// Reference to the compiler state.
    state: &'a mut TCCState,
    /// PE subsystem value (CUI, GUI, etc.).
    pub pe_subsystem: u16,
    /// PE file header characteristics flags.
    pub pe_characteristics: u32,
    /// File alignment (typically 0x200).
    pub pe_file_align: u32,
    /// Stack reserve size.
    pub pe_stack_size: u64,
    /// Image base address.
    pub pe_imagebase: u64,
    /// Output file name.
    pub filename: String,
    /// PE output type (Exe, Dll, Gui, Run).
    pub pe_type: PeType,
    /// Target architecture.
    target_arch: TargetArch,
    /// Classified PE output sections.
    pe_sections: Vec<PeOutputSection>,
    /// Import entries to build the import table.
    imports: Vec<PeImportEntry>,
    /// Export entries to build the export table.
    exports: Vec<PeExportEntry>,
    /// Relocation entries (page_rva, type+offset pairs).
    relocations: Vec<(u32, Vec<u16>)>,
    /// DLL name for export table.
    dll_name: String,
    /// Section alignment (always PE_SECTION_ALIGN).
    section_align: u32,
    /// Image size (updated during address assignment).
    image_size: u32,
    /// Number of PE sections in the output.
    num_sections: u16,
    /// Address of entry point.
    entry_addr: u32,
    /// Data directories for the optional header.
    data_dirs: [ImageDataDirectory; IMAGE_NUMBER_OF_DIRECTORY_ENTRIES],
    /// IAT (Import Address Table) section index.
    iat_section: Option<usize>,
    /// Whether we have any imports.
    has_imports: bool,
    /// Whether we have any exports.
    has_exports: bool,
    /// Whether we have base relocations.
    has_relocs: bool,
}

impl<'a> PeWriter<'a> {
    /// Create a new PE writer from compiler state.
    pub fn new(
        state: &'a mut TCCState,
        filename: &str,
        pe_type: PeType,
        arch: TargetArch,
    ) -> Self {
        let pe_subsystem = state.pe_subsystem;
        let pe_characteristics = state.pe_characteristics;
        let pe_file_align = if state.pe_file_align > 0 {
            state.pe_file_align
        } else {
            PE_FILE_ALIGN_DEFAULT
        };
        let pe_stack_size = if state.pe_stack_size > 0 {
            state.pe_stack_size
        } else {
            PE_STACK_SIZE_DEFAULT
        };
        let pe_imagebase = if state.pe_imagebase > 0 {
            state.pe_imagebase
        } else {
            match pe_type {
                PeType::Dll => {
                    if matches!(arch, TargetArch::X86_64) {
                        PE_DLL_IMAGEBASE_64
                    } else {
                        PE_DLL_IMAGEBASE_32
                    }
                }
                _ => {
                    if matches!(arch, TargetArch::X86_64) {
                        PE_IMAGEBASE_64
                    } else {
                        PE_IMAGEBASE_32
                    }
                }
            }
        };

        PeWriter {
            state,
            pe_subsystem,
            pe_characteristics,
            pe_file_align,
            pe_stack_size,
            pe_imagebase,
            filename: filename.to_string(),
            pe_type,
            target_arch: arch,
            pe_sections: Vec::new(),
            imports: Vec::new(),
            exports: Vec::new(),
            relocations: Vec::new(),
            dll_name: String::new(),
            section_align: PE_SECTION_ALIGN,
            image_size: 0,
            num_sections: 0,
            entry_addr: 0,
            data_dirs: [ImageDataDirectory::default(); IMAGE_NUMBER_OF_DIRECTORY_ENTRIES],
            iat_section: None,
            has_imports: false,
            has_exports: false,
            has_relocs: false,
        }
    }

    /// Get the machine type for the target architecture.
    fn machine_type(&self) -> u16 {
        match self.target_arch {
            TargetArch::I386 => IMAGE_FILE_MACHINE_I386,
            TargetArch::X86_64 => IMAGE_FILE_MACHINE_AMD64,
            TargetArch::Arm => IMAGE_FILE_MACHINE_ARMNT,
            _ => IMAGE_FILE_MACHINE_I386,
        }
    }

    /// Get the pointer size for the target architecture (4 or 8 bytes).
    fn ptr_size(&self) -> usize {
        match self.target_arch {
            TargetArch::X86_64 | TargetArch::Arm64 | TargetArch::Riscv64 => 8,
            _ => 4,
        }
    }

    /// Is this a 64-bit PE (PE32+)?
    fn is_pe64(&self) -> bool {
        self.ptr_size() == 8
    }

    /// Align a value up to the given alignment boundary.
    fn align_up(value: u32, align: u32) -> u32 {
        if align == 0 {
            return value;
        }
        (value + align - 1) & !(align - 1)
    }

    /// Classify an ELF section into a PE section category.
    /// Returns the PE_SEC_* index for the given ELF section, or None if it
    /// should be skipped (e.g., symbol tables, string tables, relocation sections).
    fn classify_section(sec: &Section) -> Option<usize> {
        let name = sec.name.as_str();
        let sh_flags = sec.sh_flags as u32;
        let sh_type = sec.sh_type as u32;

        // Skip non-allocated sections, relocation sections, symbol/string tables
        if sh_flags & SHF_ALLOC == 0 && !name.starts_with(".stab") && !name.starts_with(".debug") {
            return None;
        }
        if sh_type == SHT_RELX || sh_type == SHT_SYMTAB || sh_type == SHT_STRTAB {
            return None;
        }

        // Classify by name first, then by flags
        if name == ".pdata" || name.starts_with(".pdata") {
            return Some(PE_SEC_PDATA);
        }
        if name == ".rsrc" || name.starts_with(".rsrc") {
            return Some(PE_SEC_RSRC);
        }
        if name.starts_with(".stab") {
            return Some(PE_SEC_STAB);
        }
        if name.starts_with(".debug") {
            return Some(PE_SEC_DEBUG);
        }
        if name == ".reloc" {
            return Some(PE_SEC_RELOC);
        }
        if name == ".idata" || name.starts_with(".idata") {
            return Some(PE_SEC_IDATA);
        }

        // Classify by ELF section type/flags
        if sh_type == SHT_NOBITS {
            return Some(PE_SEC_BSS);
        }
        if sh_flags & SHF_EXECINSTR != 0 {
            return Some(PE_SEC_TEXT);
        }
        if sh_flags & SHF_WRITE != 0 {
            return Some(PE_SEC_DATA);
        }
        if sh_type == SHT_INIT_ARRAY || sh_type == SHT_FINI_ARRAY {
            return Some(PE_SEC_DATA);
        }

        // Default: read-only data
        Some(PE_SEC_RDATA)
    }

    /// Classify all ELF sections into PE output sections.
    fn classify_sections(&mut self) {
        // Initialize PE section groups
        let mut section_groups: Vec<Vec<usize>> = vec![Vec::new(); PE_SEC_NUMBER];

        let num_sections = self.state.sections.len();
        for i in 0..num_sections {
            let cls = {
                let sec = &self.state.sections[i];
                // Skip empty sections and the null section
                if sec.data_offset == 0 && sec.sh_type as u32 != SHT_NOBITS {
                    continue;
                }
                if i == 0 {
                    continue;
                }
                Self::classify_section(sec)
            };
            if let Some(c) = cls {
                section_groups[c].push(i);
            }
        }

        // Build PE output sections from non-empty groups
        self.pe_sections.clear();
        for (cls_idx, entries) in section_groups.into_iter().enumerate() {
            if entries.is_empty() {
                continue;
            }
            self.pe_sections.push(PeOutputSection {
                cls: cls_idx,
                entries,
                virtual_addr: 0,
                virtual_size: 0,
                raw_size: 0,
                raw_offset: 0,
            });
        }
    }

    /// Check symbols and build import/export lists.
    /// Resolves dllimport/dllexport attributes and creates IAT helper symbols.
    fn check_symbols(&mut self) -> TccResult<()> {
        let symtab_idx = match self.state.symtab_section {
            Some(idx) => idx,
            None => return Ok(()),
        };
        let dynsym_idx = match self.state.dynsymtab_section {
            Some(idx) => idx,
            None => return Ok(()),
        };

        let nsyms = sym_count(&self.state.sections[symtab_idx]);
        let mut undefined_syms: Vec<String> = Vec::new();

        for i in 1..nsyms {
            let info = get_sym_info(&self.state.sections[symtab_idx], i);
            let shndx = get_sym_shndx(&self.state.sections[symtab_idx], i);
            let bind = ELFW_ST_BIND(info);
            let _stype = ELFW_ST_TYPE(info);

            // Skip local symbols
            if bind == STB_LOCAL {
                continue;
            }

            // Get the symbol name
            let name_off = get_sym_name_offset(&self.state.sections[symtab_idx], i);
            let strtab_idx = self.state.sections[symtab_idx].link.unwrap_or(0);
            let name = crate::elf::get_elf_str(&self.state.sections[strtab_idx], name_off).to_string();

            if name.is_empty() {
                continue;
            }

            // Check for dllexport attribute
            let is_dllexport = if i < self.state.sym_attrs.len() {
                self.state.sym_attrs[i].dllexport
            } else {
                false
            };

            // Check for dllimport attribute
            let is_dllimport = if i < self.state.sym_attrs.len() {
                self.state.sym_attrs[i].dllimport
            } else {
                false
            };

            // Handle dllexport: add to exports list
            if is_dllexport && shndx != SHN_UNDEF {
                self.exports.push(PeExportEntry {
                    name: name.clone(),
                    sym_index: i,
                    ordinal: -1,
                });
                self.has_exports = true;
            }

            // Handle undefined symbols: try to resolve from DLL imports
            if shndx == SHN_UNDEF {
                // Search in dynsymtab (DLL imports)
                let dyn_idx = find_elf_sym(self.state, dynsym_idx, &name);
                if dyn_idx != 0 {
                    let dyn_shndx = get_sym_shndx(&self.state.sections[dynsym_idx], dyn_idx);
                    if dyn_shndx == SHN_FROMDLL {
                        let dyn_other = get_sym_other(&self.state.sections[dynsym_idx], dyn_idx);
                        let dll_idx = dyn_other as usize;
                        self.imports.push(PeImportEntry {
                            dll_index: dll_idx,
                            sym_index: i,
                        });
                        self.has_imports = true;
                        continue;
                    }
                }
                // Check if it is dllimport
                if is_dllimport {
                    // Mark as import - will be resolved at load time
                    continue;
                }
                // Truly undefined — report error
                if bind == STB_GLOBAL {
                    undefined_syms.push(name);
                }
            }
        }

        if !undefined_syms.is_empty() && self.state.nb_errors == 0 {
            for sym_name in &undefined_syms {
                self.state.nb_errors += 1;
                eprintln!("tcc: error: undefined symbol '{}'", sym_name);
            }
            return Err(TccError::linker(format!(
                "{} undefined symbol(s)",
                undefined_syms.len()
            )));
        }

        Ok(())
    }

    /// Assign virtual addresses to all PE sections.
    fn assign_addresses(&mut self) {
        // Calculate header size
        let dos_header_size = mem::size_of::<ImageDosHeader>() as u32;
        let pe_sig_size = 4u32; // "PE\0\0"
        let file_header_size = mem::size_of::<ImageFileHeader>() as u32;
        let opt_header_size = if self.is_pe64() {
            mem::size_of::<ImageOptionalHeader64>() as u32
        } else {
            mem::size_of::<ImageOptionalHeader32>() as u32
        };
        let section_header_size = mem::size_of::<ImageSectionHeader>() as u32;
        let num_pe_sections = self.pe_sections.len() as u32;

        let headers_size = dos_header_size
            + pe_sig_size
            + file_header_size
            + opt_header_size
            + section_header_size * num_pe_sections;
        let headers_size_aligned = Self::align_up(headers_size, self.pe_file_align);

        // Start virtual address after headers
        let mut vaddr = Self::align_up(headers_size, self.section_align);
        let mut file_offset = headers_size_aligned;

        for pe_sec in &mut self.pe_sections {
            pe_sec.virtual_addr = vaddr;

            // Calculate total virtual size from ELF sections
            let mut total_vsize: u32 = 0;
            let mut total_raw: u32 = 0;

            for &sec_idx in &pe_sec.entries {
                // Align within the PE section based on ELF alignment
                let align = self.state.sections[sec_idx].sh_addralign.max(1) as u32;
                total_vsize = Self::align_up(total_vsize, align);

                // Set the section's virtual address
                self.state.sections[sec_idx].sh_addr =
                    self.pe_imagebase + (vaddr + total_vsize) as u64;

                let sec_size = self.state.sections[sec_idx].data_offset as u32;
                total_vsize += sec_size;

                let sh_type = self.state.sections[sec_idx].sh_type as u32;
                if sh_type != SHT_NOBITS {
                    total_raw += sec_size;
                }
            }

            pe_sec.virtual_size = total_vsize;
            pe_sec.raw_size = Self::align_up(total_raw, self.pe_file_align);
            pe_sec.raw_offset = if total_raw > 0 { file_offset } else { 0 };

            if total_raw > 0 {
                file_offset += pe_sec.raw_size;
            }

            vaddr += Self::align_up(total_vsize, self.section_align);
        }

        self.image_size = vaddr;
        self.num_sections = self.pe_sections.len() as u16;
    }

    /// Build the import directory table and IAT.
    /// Creates import descriptors for each DLL referenced by imported symbols.
    fn build_imports(&mut self) -> TccResult<()> {
        if !self.has_imports || self.imports.is_empty() {
            return Ok(());
        }

        // Group imports by DLL
        let mut dll_imports: Vec<(usize, Vec<usize>)> = Vec::new(); // (dll_idx, [sym_indices])
        for imp in &self.imports {
            let found = dll_imports.iter_mut().find(|(d, _)| *d == imp.dll_index);
            if let Some((_, syms)) = found {
                syms.push(imp.sym_index);
            } else {
                dll_imports.push((imp.dll_index, vec![imp.sym_index]));
            }
        }

        // Create the .idata section if not present
        let idata_idx = match find_section(self.state, ".idata") {
            Some(idx) => idx,
            None => new_section(self.state, ".idata", SHT_PROGBITS, SHF_ALLOC | SHF_WRITE),
        };

        let symtab_idx = self.state.symtab_section.unwrap_or(0);
        let strtab_idx = self.state.sections[symtab_idx].link.unwrap_or(0);

        // Calculate sizes:
        // Import directory: (num_dlls + 1) * sizeof(IMAGE_IMPORT_DESCRIPTOR)
        // For each DLL: INT entries, IAT entries, hint/name entries, DLL name string
        let desc_size = mem::size_of::<ImageImportDescriptor>();
        let num_dlls = dll_imports.len();
        let dir_size = (num_dlls + 1) * desc_size; // +1 for null terminator

        // Reserve space for import directory
        let dir_offset = section_ptr_add(&mut self.state.sections[idata_idx], dir_size);

        // For each DLL, build INT, IAT, and hint/name tables
        let ptr_size = self.ptr_size();
        for (dll_idx_raw, sym_indices) in &dll_imports {
            let dll_name = if *dll_idx_raw < self.state.loaded_dlls.len() {
                self.state.loaded_dlls[*dll_idx_raw].name.clone()
            } else {
                format!("unknown_{}.dll", dll_idx_raw)
            };

            // Write DLL name string
            let name_offset = section_ptr_add(&mut self.state.sections[idata_idx], dll_name.len() + 1);
            self.state.sections[idata_idx].data[name_offset..name_offset + dll_name.len()]
                .copy_from_slice(dll_name.as_bytes());
            self.state.sections[idata_idx].data[name_offset + dll_name.len()] = 0;

            // Build INT (Import Name Table)
            let int_offset = section_ptr_add(
                &mut self.state.sections[idata_idx],
                (sym_indices.len() + 1) * ptr_size,
            );

            // Build IAT (Import Address Table) — same content initially
            let iat_offset = section_ptr_add(
                &mut self.state.sections[idata_idx],
                (sym_indices.len() + 1) * ptr_size,
            );

            // Write hint/name entries and INT/IAT pointers
            for (entry_idx, &sym_idx) in sym_indices.iter().enumerate() {
                let sym_name_off = get_sym_name_offset(&self.state.sections[symtab_idx], sym_idx);
                let sym_name = crate::elf::get_elf_str(&self.state.sections[strtab_idx], sym_name_off).to_string();

                // Strip leading underscore if present and leading_underscore is set
                let import_name = if self.state.leading_underscore && sym_name.starts_with('_') {
                    &sym_name[1..]
                } else {
                    &sym_name
                };

                // Write hint/name entry: u16 hint (0) + name string + padding
                let hint_offset = section_ptr_add(
                    &mut self.state.sections[idata_idx],
                    2 + import_name.len() + 1 + ((import_name.len() + 1) % 2),
                );
                // Hint = 0 (we don't know the ordinal)
                write16le(&mut self.state.sections[idata_idx].data[hint_offset..], 0);
                let name_start = hint_offset + 2;
                self.state.sections[idata_idx].data[name_start..name_start + import_name.len()]
                    .copy_from_slice(import_name.as_bytes());
                self.state.sections[idata_idx].data[name_start + import_name.len()] = 0;

                // Write INT entry (RVA to hint/name)
                let int_entry_off = int_offset + entry_idx * ptr_size;
                let hint_rva = hint_offset as u32; // Will be fixed up during relocation
                if self.is_pe64() {
                    let d = &mut self.state.sections[idata_idx].data;
                    d[int_entry_off..int_entry_off + 4].copy_from_slice(&hint_rva.to_le_bytes());
                    d[int_entry_off + 4..int_entry_off + 8].copy_from_slice(&0u32.to_le_bytes());
                } else {
                    let d = &mut self.state.sections[idata_idx].data;
                    d[int_entry_off..int_entry_off + 4].copy_from_slice(&hint_rva.to_le_bytes());
                }

                // Write IAT entry (same as INT initially)
                let iat_entry_off = iat_offset + entry_idx * ptr_size;
                if self.is_pe64() {
                    let d = &mut self.state.sections[idata_idx].data;
                    d[iat_entry_off..iat_entry_off + 4].copy_from_slice(&hint_rva.to_le_bytes());
                    d[iat_entry_off + 4..iat_entry_off + 8].copy_from_slice(&0u32.to_le_bytes());
                } else {
                    let d = &mut self.state.sections[idata_idx].data;
                    d[iat_entry_off..iat_entry_off + 4].copy_from_slice(&hint_rva.to_le_bytes());
                }
            }

            // Write import descriptor for this DLL
            // Find the descriptor slot index for this DLL
            let desc_idx = dll_imports.iter().position(|(d, _)| *d == *dll_idx_raw).unwrap_or(0);
            let desc_off = dir_offset + desc_idx * desc_size;
            let d = &mut self.state.sections[idata_idx].data;
            // OriginalFirstThunk = RVA of INT
            d[desc_off..desc_off + 4].copy_from_slice(&(int_offset as u32).to_le_bytes());
            // TimeDateStamp = 0
            d[desc_off + 4..desc_off + 8].copy_from_slice(&0u32.to_le_bytes());
            // ForwarderChain = -1
            d[desc_off + 8..desc_off + 12].copy_from_slice(&(-1i32 as u32).to_le_bytes());
            // Name = RVA of DLL name
            d[desc_off + 12..desc_off + 16].copy_from_slice(&(name_offset as u32).to_le_bytes());
            // FirstThunk = RVA of IAT
            d[desc_off + 16..desc_off + 20].copy_from_slice(&(iat_offset as u32).to_le_bytes());
        }

        // Write null terminator descriptor
        let null_desc_off = dir_offset + num_dlls * desc_size;
        let d = &mut self.state.sections[idata_idx].data;
        for byte in &mut d[null_desc_off..null_desc_off + desc_size] {
            *byte = 0;
        }

        self.iat_section = Some(idata_idx);
        Ok(())
    }

    /// Build the export directory table for DLL output.
    fn build_exports(&mut self) -> TccResult<()> {
        if !self.has_exports || self.exports.is_empty() {
            return Ok(());
        }

        // Sort exports by name for binary search at runtime
        self.exports.sort_by(|a, b| a.name.cmp(&b.name));

        // Create or find the .edata section
        let edata_idx = new_section(
            self.state,
            ".edata",
            SHT_PROGBITS,
            SHF_ALLOC,
        );

        let num_exports = self.exports.len();
        let dir_size = mem::size_of::<ImageExportDirectory>();

        // Calculate total size:
        // Export directory + address table + name ptr table + ordinal table + name strings + dll name
        let addr_table_size = num_exports * 4; // u32 RVAs
        let name_ptr_size = num_exports * 4; // u32 RVAs
        let ordinal_table_size = num_exports * 2; // u16 ordinals

        // Calculate name strings total length
        let names_total: usize = self.exports.iter().map(|e| e.name.len() + 1).sum();
        let dll_name_len = self.dll_name.len() + 1;

        let total_size = dir_size + addr_table_size + name_ptr_size + ordinal_table_size + names_total + dll_name_len;
        let base_offset = section_ptr_add(&mut self.state.sections[edata_idx], total_size);

        let addr_table_off = base_offset + dir_size;
        let name_ptr_off = addr_table_off + addr_table_size;
        let ordinal_off = name_ptr_off + name_ptr_size;
        let names_off = ordinal_off + ordinal_table_size;
        let dll_name_off = names_off + names_total;

        // Write DLL name
        let d = &mut self.state.sections[edata_idx].data;
        d[dll_name_off..dll_name_off + self.dll_name.len()]
            .copy_from_slice(self.dll_name.as_bytes());
        d[dll_name_off + self.dll_name.len()] = 0;

        // Write export entries
        let symtab_idx = self.state.symtab_section.unwrap_or(0);
        let mut current_name_off = names_off;
        for (idx, export) in self.exports.iter().enumerate() {
            // Address table entry: RVA of the exported symbol
            let sym_value = get_sym_value(&self.state.sections[symtab_idx], export.sym_index);
            let sym_shndx = get_sym_shndx(&self.state.sections[symtab_idx], export.sym_index);
            let rva = if sym_shndx != SHN_UNDEF
                && (sym_shndx as usize) < self.state.sections.len()
            {
                let sec_addr = self.state.sections[sym_shndx as usize].sh_addr;
                (sec_addr + sym_value - self.pe_imagebase) as u32
            } else {
                0
            };

            let d = &mut self.state.sections[edata_idx].data;
            let addr_entry = addr_table_off + idx * 4;
            d[addr_entry..addr_entry + 4].copy_from_slice(&rva.to_le_bytes());

            // Name pointer entry
            let name_entry = name_ptr_off + idx * 4;
            d[name_entry..name_entry + 4].copy_from_slice(&(current_name_off as u32).to_le_bytes());

            // Ordinal entry
            let ord_entry = ordinal_off + idx * 2;
            d[ord_entry..ord_entry + 2].copy_from_slice(&(idx as u16).to_le_bytes());

            // Write name string
            d[current_name_off..current_name_off + export.name.len()]
                .copy_from_slice(export.name.as_bytes());
            d[current_name_off + export.name.len()] = 0;
            current_name_off += export.name.len() + 1;
        }

        // Write export directory header
        let d = &mut self.state.sections[edata_idx].data;
        // Characteristics = 0
        d[base_offset..base_offset + 4].copy_from_slice(&0u32.to_le_bytes());
        // TimeDateStamp = 0
        d[base_offset + 4..base_offset + 8].copy_from_slice(&0u32.to_le_bytes());
        // MajorVersion / MinorVersion = 0
        d[base_offset + 8..base_offset + 12].copy_from_slice(&0u32.to_le_bytes());
        // Name = RVA of DLL name (will be fixed during address assignment)
        d[base_offset + 12..base_offset + 16].copy_from_slice(&(dll_name_off as u32).to_le_bytes());
        // Base = 1 (ordinal base)
        d[base_offset + 16..base_offset + 20].copy_from_slice(&1u32.to_le_bytes());
        // NumberOfFunctions
        d[base_offset + 20..base_offset + 24].copy_from_slice(&(num_exports as u32).to_le_bytes());
        // NumberOfNames
        d[base_offset + 24..base_offset + 28].copy_from_slice(&(num_exports as u32).to_le_bytes());
        // AddressOfFunctions
        d[base_offset + 28..base_offset + 32].copy_from_slice(&(addr_table_off as u32).to_le_bytes());
        // AddressOfNames
        d[base_offset + 32..base_offset + 36].copy_from_slice(&(name_ptr_off as u32).to_le_bytes());
        // AddressOfNameOrdinals
        d[base_offset + 36..base_offset + 40].copy_from_slice(&(ordinal_off as u32).to_le_bytes());

        Ok(())
    }

    /// Build the base relocation table for the PE file.
    /// Base relocations allow the OS loader to fix up absolute addresses
    /// when the image is loaded at a different base address than preferred.
    fn build_reloc(&mut self) -> TccResult<()> {
        let _symtab_idx = match self.state.symtab_section {
            Some(idx) => idx,
            None => return Ok(()),
        };

        let reloc_type_abs = if self.is_pe64() {
            IMAGE_REL_BASED_DIR64
        } else {
            IMAGE_REL_BASED_HIGHLOW
        };

        // Collect all relocations that need base relocation entries
        let mut reloc_entries: Vec<u32> = Vec::new();

        let num_sections = self.state.sections.len();
        for i in 0..num_sections {
            let sh_type = self.state.sections[i].sh_type as u32;
            if sh_type != SHT_RELX {
                continue;
            }
            let target_sec_idx = self.state.sections[i].sh_info as usize;
            if target_sec_idx >= self.state.sections.len() {
                continue;
            }

            // Only process relocations for allocated sections
            let target_flags = self.state.sections[target_sec_idx].sh_flags as u32;
            if target_flags & SHF_ALLOC == 0 {
                continue;
            }

            let entry_size = if self.is_pe64() {
                mem::size_of::<crate::elf::Elf64_Rela>()
            } else {
                mem::size_of::<crate::elf::Elf32_Rel>()
            };

            if entry_size == 0 {
                continue;
            }

            let reloc_count = self.state.sections[i].data_offset / entry_size;
            for r in 0..reloc_count {
                let rel_offset = r * entry_size;
                let rel_data = &self.state.sections[i].data[rel_offset..rel_offset + entry_size];

                // Read relocation offset and info
                let r_offset = u64::from_le_bytes([
                    rel_data[0], rel_data[1], rel_data[2], rel_data[3],
                    if self.is_pe64() { rel_data[4] } else { 0 },
                    if self.is_pe64() { rel_data[5] } else { 0 },
                    if self.is_pe64() { rel_data[6] } else { 0 },
                    if self.is_pe64() { rel_data[7] } else { 0 },
                ]);

                let r_info = if self.is_pe64() {
                    u64::from_le_bytes([
                        rel_data[8], rel_data[9], rel_data[10], rel_data[11],
                        rel_data[12], rel_data[13], rel_data[14], rel_data[15],
                    ])
                } else {
                    u32::from_le_bytes([
                        rel_data[4], rel_data[5], rel_data[6], rel_data[7],
                    ]) as u64
                };

                let rtype = ELFW_R_TYPE(r_info);

                // Check if this relocation type requires a base relocation
                // For x86_64: R_X86_64_64 (absolute 64-bit) needs base reloc
                // For i386: R_386_32 (absolute 32-bit) needs base reloc
                let needs_base_reloc = match self.target_arch {
                    TargetArch::X86_64 => rtype == 1, // R_X86_64_64
                    TargetArch::I386 => rtype == 1,    // R_386_32
                    TargetArch::Arm => rtype == 2,     // R_ARM_ABS32
                    _ => false,
                };

                if needs_base_reloc {
                    let sec_addr = self.state.sections[target_sec_idx].sh_addr;
                    let addr = (sec_addr - self.pe_imagebase + r_offset) as u32;
                    reloc_entries.push(addr);
                }
            }
        }

        if reloc_entries.is_empty() {
            return Ok(());
        }

        // Sort relocation entries by address
        reloc_entries.sort();

        // Group into 4K pages and create base relocation blocks
        let mut blocks: Vec<(u32, Vec<u16>)> = Vec::new();
        let page_mask: u32 = 0xFFFF_F000;

        for addr in &reloc_entries {
            let page_rva = addr & page_mask;
            let offset = (addr & 0xFFF) as u16;
            let entry = (reloc_type_abs << 12) | offset;

            let found = blocks.iter_mut().find(|(p, _)| *p == page_rva);
            if let Some((_, entries)) = found {
                entries.push(entry);
            } else {
                blocks.push((page_rva, vec![entry]));
            }
        }

        self.relocations = blocks;
        self.has_relocs = !self.relocations.is_empty();

        // Create .reloc section
        if self.has_relocs {
            let reloc_sec_idx = new_section(
                self.state,
                ".reloc",
                SHT_PROGBITS,
                SHF_ALLOC,
            );

            // Write relocation blocks
            for (page_rva, entries) in &self.relocations {
                // Each block: header (8 bytes) + entries (2 bytes each)
                // Must be aligned to 4 bytes; pad with IMAGE_REL_BASED_ABSOLUTE if needed
                let mut block_entries = entries.clone();
                if block_entries.len() % 2 != 0 {
                    block_entries.push(IMAGE_REL_BASED_ABSOLUTE); // padding
                }
                let block_size = 8 + block_entries.len() * 2;
                let block_off = section_ptr_add(&mut self.state.sections[reloc_sec_idx], block_size);
                let d = &mut self.state.sections[reloc_sec_idx].data;

                // Write block header
                d[block_off..block_off + 4].copy_from_slice(&page_rva.to_le_bytes());
                d[block_off + 4..block_off + 8].copy_from_slice(&(block_size as u32).to_le_bytes());

                // Write entries
                for (i, entry) in block_entries.iter().enumerate() {
                    let off = block_off + 8 + i * 2;
                    d[off..off + 2].copy_from_slice(&entry.to_le_bytes());
                }
            }
        }

        Ok(())
    }

    /// Write the PE file to disk.
    /// This is the main output routine that writes headers and section data.
    fn write_pe_file(&mut self) -> TccResult<()> {
        let file = fs::File::create(&self.filename).map_err(|e| {
            TccError::IoError(io::Error::other(format!("cannot create '{}': {}", self.filename, e)))
        })?;
        let mut writer = BufWriter::new(file);

        // --- DOS Header ---
        let dos_header = ImageDosHeader {
            e_magic: MZ_MAGIC,
            e_lfanew: mem::size_of::<ImageDosHeader>() as i32,
            ..Default::default()
        };
        write_dos_header(&mut writer, &dos_header)?;

        // --- PE Signature ---
        writer.write_all(&PE_SIGNATURE.to_le_bytes())?;

        // --- COFF File Header ---
        let mut characteristics = IMAGE_FILE_EXECUTABLE_IMAGE
            | IMAGE_FILE_LINE_NUMS_STRIPPED
            | IMAGE_FILE_LOCAL_SYMS_STRIPPED;
        if !self.is_pe64() {
            characteristics |= IMAGE_FILE_32BIT_MACHINE;
        }
        if self.pe_type == PeType::Dll {
            characteristics |= IMAGE_FILE_DLL;
        }
        if !self.has_relocs {
            characteristics |= IMAGE_FILE_RELOCS_STRIPPED;
        }
        if self.is_pe64() {
            characteristics |= IMAGE_FILE_LARGE_ADDRESS_AWARE;
        }
        let file_header = ImageFileHeader {
            Machine: self.machine_type(),
            NumberOfSections: self.num_sections,
            TimeDateStamp: 0, // Reproducible builds
            SizeOfOptionalHeader: if self.is_pe64() {
                mem::size_of::<ImageOptionalHeader64>() as u16
            } else {
                mem::size_of::<ImageOptionalHeader32>() as u16
            },
            Characteristics: characteristics | self.pe_characteristics as u16,
            ..Default::default()
        };
        write_file_header(&mut writer, &file_header)?;

        // --- Optional Header ---
        let subsystem = if self.pe_subsystem == 0 {
            if self.pe_type == PeType::Gui {
                IMAGE_SUBSYSTEM_WINDOWS_GUI
            } else {
                IMAGE_SUBSYSTEM_WINDOWS_CUI
            }
        } else {
            self.pe_subsystem
        };

        let dll_characteristics = IMAGE_DLL_CHARACTERISTICS_NX_COMPAT
            | if self.has_relocs { IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE } else { 0 }
            | if self.is_pe64() { IMAGE_DLL_CHARACTERISTICS_HIGH_ENTROPY_VA } else { 0 };

        // Calculate size of headers
        let headers_raw_size = Self::align_up(
            mem::size_of::<ImageDosHeader>() as u32
                + 4
                + mem::size_of::<ImageFileHeader>() as u32
                + file_header.SizeOfOptionalHeader as u32
                + self.num_sections as u32 * mem::size_of::<ImageSectionHeader>() as u32,
            self.pe_file_align,
        );

        if self.is_pe64() {
            let opt = ImageOptionalHeader64 {
                Magic: PE32PLUS_MAGIC,
                MajorLinkerVersion: 6,
                AddressOfEntryPoint: self.entry_addr,
                ImageBase: self.pe_imagebase,
                SectionAlignment: self.section_align,
                FileAlignment: self.pe_file_align,
                MajorOperatingSystemVersion: 4,
                MajorSubsystemVersion: 4,
                SizeOfImage: self.image_size,
                SizeOfHeaders: headers_raw_size,
                Subsystem: subsystem,
                DllCharacteristics: dll_characteristics,
                SizeOfStackReserve: self.pe_stack_size,
                SizeOfStackCommit: 0x1000,
                SizeOfHeapReserve: PE_HEAP_SIZE_DEFAULT,
                SizeOfHeapCommit: 0x1000,
                NumberOfRvaAndSizes: IMAGE_NUMBER_OF_DIRECTORY_ENTRIES as u32,
                DataDirectory: self.data_dirs,
                ..Default::default()
            };
            write_opt_header_64(&mut writer, &opt)?;
        } else {
            let opt = ImageOptionalHeader32 {
                Magic: PE32_MAGIC,
                MajorLinkerVersion: 6,
                AddressOfEntryPoint: self.entry_addr,
                ImageBase: self.pe_imagebase as u32,
                SectionAlignment: self.section_align,
                FileAlignment: self.pe_file_align,
                MajorOperatingSystemVersion: 4,
                MajorSubsystemVersion: 4,
                SizeOfImage: self.image_size,
                SizeOfHeaders: headers_raw_size,
                Subsystem: subsystem,
                DllCharacteristics: dll_characteristics,
                SizeOfStackReserve: self.pe_stack_size as u32,
                SizeOfStackCommit: 0x1000,
                SizeOfHeapReserve: PE_HEAP_SIZE_DEFAULT as u32,
                SizeOfHeapCommit: 0x1000,
                NumberOfRvaAndSizes: IMAGE_NUMBER_OF_DIRECTORY_ENTRIES as u32,
                DataDirectory: self.data_dirs,
                ..Default::default()
            };
            write_opt_header_32(&mut writer, &opt)?;
        }

        // --- Section Headers ---
        for pe_sec in &self.pe_sections {
            let cls = &PE_SEC_CLASSES[pe_sec.cls];
            let mut sec_header = ImageSectionHeader::default();

            // Copy section name (max 8 bytes)
            let name_bytes = cls.name.as_bytes();
            let copy_len = name_bytes.len().min(8);
            sec_header.Name[..copy_len].copy_from_slice(&name_bytes[..copy_len]);

            sec_header.VirtualSize = pe_sec.virtual_size;
            sec_header.VirtualAddress = pe_sec.virtual_addr;
            sec_header.SizeOfRawData = pe_sec.raw_size;
            sec_header.PointerToRawData = pe_sec.raw_offset;
            sec_header.Characteristics = cls.flags;

            write_section_header(&mut writer, &sec_header)?;
        }

        // --- Section Data ---
        // Pad to first section's file offset
        let current_pos = writer.stream_position().map_err(|e| {
            TccError::IoError(io::Error::other(format!("seek error: {}", e)))
        })? as u32;
        if !self.pe_sections.is_empty() && self.pe_sections[0].raw_offset > current_pos {
            let pad = self.pe_sections[0].raw_offset - current_pos;
            write_padding(&mut writer, pad as usize)?;
        }

        for pe_sec in &self.pe_sections {
            if pe_sec.raw_size == 0 {
                continue;
            }

            let mut written: u32 = 0;
            for &sec_idx in &pe_sec.entries {
                let sh_type = self.state.sections[sec_idx].sh_type as u32;
                if sh_type == SHT_NOBITS {
                    continue;
                }

                // Align within the PE section
                let align = self.state.sections[sec_idx].sh_addralign.max(1) as u32;
                let aligned = Self::align_up(written, align);
                if aligned > written {
                    write_padding(&mut writer, (aligned - written) as usize)?;
                    written = aligned;
                }

                let data_len = self.state.sections[sec_idx].data_offset;
                if data_len > 0 {
                    writer.write_all(&self.state.sections[sec_idx].data[..data_len]).map_err(|e| {
                        TccError::IoError(io::Error::other(format!("write error: {}", e)))
                    })?;
                    written += data_len as u32;
                }
            }

            // Pad to file alignment
            if written < pe_sec.raw_size {
                write_padding(&mut writer, (pe_sec.raw_size - written) as usize)?;
            }
        }

        writer.flush().map_err(|e| {
            TccError::IoError(io::Error::other(format!("flush error: {}", e)))
        })?;

        Ok(())
    }

    /// Resolve the entry point symbol name based on PE type and subsystem.
    fn resolve_entry_symbol(&self) -> &str {
        if let Some(ref entry) = self.state.elf_entryname {
            return entry;
        }

        match self.pe_type {
            PeType::Dll => "_DllMainCRTStartup",
            PeType::Gui => {
                if self.state.leading_underscore {
                    "_WinMain@16"
                } else {
                    "WinMain"
                }
            }
            _ => {
                if self.state.leading_underscore {
                    "_mainCRTStartup"
                } else {
                    "mainCRTStartup"
                }
            }
        }
    }

    /// Find the entry point address.
    fn find_entry_addr(&mut self) -> TccResult<u32> {
        let entry_name = self.resolve_entry_symbol().to_string();
        match get_sym_addr(self.state, &entry_name, false) {
            Ok(addr) if addr != 0 => {
                Ok((addr - self.pe_imagebase) as u32)
            }
            _ => {
                // Try alternative names
                let alt_names = match self.pe_type {
                    PeType::Gui => vec!["WinMain", "wWinMain", "wWinMainCRTStartup"],
                    PeType::Dll => vec!["DllMainCRTStartup", "DllMain"],
                    _ => vec!["main", "_main", "mainCRTStartup", "_mainCRTStartup", "__start"],
                };
                for alt_name in alt_names {
                    if let Ok(addr) = get_sym_addr(self.state, alt_name, false) {
                        if addr != 0 {
                            return Ok((addr - self.pe_imagebase) as u32);
                        }
                    }
                }
                // For DLLs without an entry point, address = 0 is valid
                if self.pe_type == PeType::Dll {
                    Ok(0)
                } else {
                    Err(TccError::linker(format!(
                        "undefined entry point '{}'",
                        entry_name
                    )))
                }
            }
        }
    }

    /// Set PE-specific options from the compiler state flags.
    fn set_options(&mut self) {
        // Propagate options from state
        if self.state.pe_subsystem != 0 {
            self.pe_subsystem = self.state.pe_subsystem;
        }
        if self.state.pe_characteristics != 0 {
            self.pe_characteristics = self.state.pe_characteristics;
        }
        if self.state.pe_file_align != 0 {
            self.pe_file_align = self.state.pe_file_align;
        }
        if self.state.pe_stack_size != 0 {
            self.pe_stack_size = self.state.pe_stack_size;
        }
        if self.state.pe_imagebase != 0 {
            self.pe_imagebase = self.state.pe_imagebase;
        }
    }

    /// Main PE output orchestration — coordinates all the build steps.
    fn output(&mut self) -> TccResult<()> {
        // 1. Apply PE-specific options
        self.set_options();

        // 2. Determine DLL name for exports (basename of output file)
        self.dll_name = Path::new(&self.filename)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("output.dll")
            .to_string();

        // 3. Resolve common symbols
        resolve_common_syms(self.state)?;

        // 4. Check symbols and build import/export lists
        self.check_symbols()?;

        // 5. Build import table
        self.build_imports()?;

        // 6. Build export table
        if self.pe_type == PeType::Dll {
            self.build_exports()?;
        }

        // 7. Classify ELF sections into PE sections
        self.classify_sections();

        // 8. Assign virtual addresses
        self.assign_addresses();

        // 9. Relocate symbols
        relocate_syms(self.state, self.pe_type == PeType::Run)?;

        // 10. Build base relocations (must be after symbol relocation)
        self.build_reloc()?;

        // If we added reloc section, reclassify and reassign
        if self.has_relocs {
            self.classify_sections();
            self.assign_addresses();
        }

        // 11. Find entry point
        if self.pe_type != PeType::Run {
            self.entry_addr = self.find_entry_addr()?;
        }

        // 12. Set data directories for import/export/reloc sections
        self.set_data_directories();

        // 13. Write the PE file
        if self.pe_type != PeType::Run {
            self.write_pe_file()?;
        }

        Ok(())
    }

    /// Populate the data directory entries based on the PE sections present.
    fn set_data_directories(&mut self) {
        for pe_sec in &self.pe_sections {
            match pe_sec.cls {
                PE_SEC_IDATA => {
                    // Import directory
                    if pe_sec.virtual_size > 0 {
                        self.data_dirs[IMAGE_DIRECTORY_ENTRY_IMPORT] = ImageDataDirectory {
                            VirtualAddress: pe_sec.virtual_addr,
                            Size: pe_sec.virtual_size,
                        };
                        // IAT is a subset of idata
                        self.data_dirs[IMAGE_DIRECTORY_ENTRY_IAT] = ImageDataDirectory {
                            VirtualAddress: pe_sec.virtual_addr,
                            Size: pe_sec.virtual_size,
                        };
                    }
                }
                PE_SEC_RELOC => {
                    if pe_sec.virtual_size > 0 {
                        self.data_dirs[IMAGE_DIRECTORY_ENTRY_BASERELOC] = ImageDataDirectory {
                            VirtualAddress: pe_sec.virtual_addr,
                            Size: pe_sec.virtual_size,
                        };
                    }
                }
                PE_SEC_RSRC => {
                    if pe_sec.virtual_size > 0 {
                        self.data_dirs[IMAGE_DIRECTORY_ENTRY_RESOURCE] = ImageDataDirectory {
                            VirtualAddress: pe_sec.virtual_addr,
                            Size: pe_sec.virtual_size,
                        };
                    }
                }
                PE_SEC_PDATA => {
                    // Exception directory (x86_64 unwind data)
                    if pe_sec.virtual_size > 0 {
                        self.data_dirs[3] = ImageDataDirectory { // IMAGE_DIRECTORY_ENTRY_EXCEPTION
                            VirtualAddress: pe_sec.virtual_addr,
                            Size: pe_sec.virtual_size,
                        };
                    }
                }
                PE_SEC_DEBUG => {
                    if pe_sec.virtual_size > 0 {
                        self.data_dirs[IMAGE_DIRECTORY_ENTRY_DEBUG] = ImageDataDirectory {
                            VirtualAddress: pe_sec.virtual_addr,
                            Size: pe_sec.virtual_size,
                        };
                    }
                }
                _ => {}
            }
        }

        // Export directory — find the .edata section
        for pe_sec in &self.pe_sections {
            for &sec_idx in &pe_sec.entries {
                if self.state.sections[sec_idx].name == ".edata" {
                    let sec_addr = self.state.sections[sec_idx].sh_addr;
                    let rva = (sec_addr - self.pe_imagebase) as u32;
                    let size = self.state.sections[sec_idx].data_offset as u32;
                    if size > 0 {
                        self.data_dirs[IMAGE_DIRECTORY_ENTRY_EXPORT] = ImageDataDirectory {
                            VirtualAddress: rva,
                            Size: size,
                        };
                    }
                }
            }
        }
    }
}

// ============================================================
// Binary Writing Helpers
// ============================================================

/// Write padding bytes (zeros) to the output file.
fn write_padding(writer: &mut impl Write, count: usize) -> TccResult<()> {
    let zeros = vec![0u8; count];
    writer.write_all(&zeros).map_err(|e| {
        TccError::IoError(io::Error::other(format!("write padding error: {}", e)))
    })
}

/// Write the DOS header to the output stream.
fn write_dos_header(writer: &mut impl Write, hdr: &ImageDosHeader) -> TccResult<()> {
    writer.write_all(&hdr.e_magic.to_le_bytes()).map_err(io_err)?;
    writer.write_all(&hdr.e_cblp.to_le_bytes()).map_err(io_err)?;
    writer.write_all(&hdr.e_cp.to_le_bytes()).map_err(io_err)?;
    writer.write_all(&hdr.e_crlc.to_le_bytes()).map_err(io_err)?;
    writer.write_all(&hdr.e_cparhdr.to_le_bytes()).map_err(io_err)?;
    writer.write_all(&hdr.e_minalloc.to_le_bytes()).map_err(io_err)?;
    writer.write_all(&hdr.e_maxalloc.to_le_bytes()).map_err(io_err)?;
    writer.write_all(&hdr.e_ss.to_le_bytes()).map_err(io_err)?;
    writer.write_all(&hdr.e_sp.to_le_bytes()).map_err(io_err)?;
    writer.write_all(&hdr.e_csum.to_le_bytes()).map_err(io_err)?;
    writer.write_all(&hdr.e_ip.to_le_bytes()).map_err(io_err)?;
    writer.write_all(&hdr.e_cs.to_le_bytes()).map_err(io_err)?;
    writer.write_all(&hdr.e_lfarlc.to_le_bytes()).map_err(io_err)?;
    writer.write_all(&hdr.e_ovno.to_le_bytes()).map_err(io_err)?;
    for v in &hdr.e_res {
        writer.write_all(&v.to_le_bytes()).map_err(io_err)?;
    }
    writer.write_all(&hdr.e_oemid.to_le_bytes()).map_err(io_err)?;
    writer.write_all(&hdr.e_oeminfo.to_le_bytes()).map_err(io_err)?;
    for v in &hdr.e_res2 {
        writer.write_all(&v.to_le_bytes()).map_err(io_err)?;
    }
    writer.write_all(&hdr.e_lfanew.to_le_bytes()).map_err(io_err)?;
    Ok(())
}

/// Write the COFF file header to the output stream.
fn write_file_header(writer: &mut impl Write, hdr: &ImageFileHeader) -> TccResult<()> {
    writer.write_all(&hdr.Machine.to_le_bytes()).map_err(io_err)?;
    writer.write_all(&hdr.NumberOfSections.to_le_bytes()).map_err(io_err)?;
    writer.write_all(&hdr.TimeDateStamp.to_le_bytes()).map_err(io_err)?;
    writer.write_all(&hdr.PointerToSymbolTable.to_le_bytes()).map_err(io_err)?;
    writer.write_all(&hdr.NumberOfSymbols.to_le_bytes()).map_err(io_err)?;
    writer.write_all(&hdr.SizeOfOptionalHeader.to_le_bytes()).map_err(io_err)?;
    writer.write_all(&hdr.Characteristics.to_le_bytes()).map_err(io_err)?;
    Ok(())
}

/// Write the PE32+ (64-bit) optional header.
fn write_opt_header_64(writer: &mut impl Write, opt: &ImageOptionalHeader64) -> TccResult<()> {
    writer.write_all(&opt.Magic.to_le_bytes()).map_err(io_err)?;
    writer.write_all(&[opt.MajorLinkerVersion, opt.MinorLinkerVersion]).map_err(io_err)?;
    writer.write_all(&opt.SizeOfCode.to_le_bytes()).map_err(io_err)?;
    writer.write_all(&opt.SizeOfInitializedData.to_le_bytes()).map_err(io_err)?;
    writer.write_all(&opt.SizeOfUninitializedData.to_le_bytes()).map_err(io_err)?;
    writer.write_all(&opt.AddressOfEntryPoint.to_le_bytes()).map_err(io_err)?;
    writer.write_all(&opt.BaseOfCode.to_le_bytes()).map_err(io_err)?;
    writer.write_all(&opt.ImageBase.to_le_bytes()).map_err(io_err)?;
    writer.write_all(&opt.SectionAlignment.to_le_bytes()).map_err(io_err)?;
    writer.write_all(&opt.FileAlignment.to_le_bytes()).map_err(io_err)?;
    writer.write_all(&opt.MajorOperatingSystemVersion.to_le_bytes()).map_err(io_err)?;
    writer.write_all(&opt.MinorOperatingSystemVersion.to_le_bytes()).map_err(io_err)?;
    writer.write_all(&opt.MajorImageVersion.to_le_bytes()).map_err(io_err)?;
    writer.write_all(&opt.MinorImageVersion.to_le_bytes()).map_err(io_err)?;
    writer.write_all(&opt.MajorSubsystemVersion.to_le_bytes()).map_err(io_err)?;
    writer.write_all(&opt.MinorSubsystemVersion.to_le_bytes()).map_err(io_err)?;
    writer.write_all(&opt.Win32VersionValue.to_le_bytes()).map_err(io_err)?;
    writer.write_all(&opt.SizeOfImage.to_le_bytes()).map_err(io_err)?;
    writer.write_all(&opt.SizeOfHeaders.to_le_bytes()).map_err(io_err)?;
    writer.write_all(&opt.CheckSum.to_le_bytes()).map_err(io_err)?;
    writer.write_all(&opt.Subsystem.to_le_bytes()).map_err(io_err)?;
    writer.write_all(&opt.DllCharacteristics.to_le_bytes()).map_err(io_err)?;
    writer.write_all(&opt.SizeOfStackReserve.to_le_bytes()).map_err(io_err)?;
    writer.write_all(&opt.SizeOfStackCommit.to_le_bytes()).map_err(io_err)?;
    writer.write_all(&opt.SizeOfHeapReserve.to_le_bytes()).map_err(io_err)?;
    writer.write_all(&opt.SizeOfHeapCommit.to_le_bytes()).map_err(io_err)?;
    writer.write_all(&opt.LoaderFlags.to_le_bytes()).map_err(io_err)?;
    writer.write_all(&opt.NumberOfRvaAndSizes.to_le_bytes()).map_err(io_err)?;
    for dir in &opt.DataDirectory {
        writer.write_all(&dir.VirtualAddress.to_le_bytes()).map_err(io_err)?;
        writer.write_all(&dir.Size.to_le_bytes()).map_err(io_err)?;
    }
    Ok(())
}

/// Write the PE32 (32-bit) optional header.
fn write_opt_header_32(writer: &mut impl Write, opt: &ImageOptionalHeader32) -> TccResult<()> {
    writer.write_all(&opt.Magic.to_le_bytes()).map_err(io_err)?;
    writer.write_all(&[opt.MajorLinkerVersion, opt.MinorLinkerVersion]).map_err(io_err)?;
    writer.write_all(&opt.SizeOfCode.to_le_bytes()).map_err(io_err)?;
    writer.write_all(&opt.SizeOfInitializedData.to_le_bytes()).map_err(io_err)?;
    writer.write_all(&opt.SizeOfUninitializedData.to_le_bytes()).map_err(io_err)?;
    writer.write_all(&opt.AddressOfEntryPoint.to_le_bytes()).map_err(io_err)?;
    writer.write_all(&opt.BaseOfCode.to_le_bytes()).map_err(io_err)?;
    writer.write_all(&opt.BaseOfData.to_le_bytes()).map_err(io_err)?;
    writer.write_all(&opt.ImageBase.to_le_bytes()).map_err(io_err)?;
    writer.write_all(&opt.SectionAlignment.to_le_bytes()).map_err(io_err)?;
    writer.write_all(&opt.FileAlignment.to_le_bytes()).map_err(io_err)?;
    writer.write_all(&opt.MajorOperatingSystemVersion.to_le_bytes()).map_err(io_err)?;
    writer.write_all(&opt.MinorOperatingSystemVersion.to_le_bytes()).map_err(io_err)?;
    writer.write_all(&opt.MajorImageVersion.to_le_bytes()).map_err(io_err)?;
    writer.write_all(&opt.MinorImageVersion.to_le_bytes()).map_err(io_err)?;
    writer.write_all(&opt.MajorSubsystemVersion.to_le_bytes()).map_err(io_err)?;
    writer.write_all(&opt.MinorSubsystemVersion.to_le_bytes()).map_err(io_err)?;
    writer.write_all(&opt.Win32VersionValue.to_le_bytes()).map_err(io_err)?;
    writer.write_all(&opt.SizeOfImage.to_le_bytes()).map_err(io_err)?;
    writer.write_all(&opt.SizeOfHeaders.to_le_bytes()).map_err(io_err)?;
    writer.write_all(&opt.CheckSum.to_le_bytes()).map_err(io_err)?;
    writer.write_all(&opt.Subsystem.to_le_bytes()).map_err(io_err)?;
    writer.write_all(&opt.DllCharacteristics.to_le_bytes()).map_err(io_err)?;
    writer.write_all(&opt.SizeOfStackReserve.to_le_bytes()).map_err(io_err)?;
    writer.write_all(&opt.SizeOfStackCommit.to_le_bytes()).map_err(io_err)?;
    writer.write_all(&opt.SizeOfHeapReserve.to_le_bytes()).map_err(io_err)?;
    writer.write_all(&opt.SizeOfHeapCommit.to_le_bytes()).map_err(io_err)?;
    writer.write_all(&opt.LoaderFlags.to_le_bytes()).map_err(io_err)?;
    writer.write_all(&opt.NumberOfRvaAndSizes.to_le_bytes()).map_err(io_err)?;
    for dir in &opt.DataDirectory {
        writer.write_all(&dir.VirtualAddress.to_le_bytes()).map_err(io_err)?;
        writer.write_all(&dir.Size.to_le_bytes()).map_err(io_err)?;
    }
    Ok(())
}

/// Write a section header to the output stream.
fn write_section_header(writer: &mut impl Write, hdr: &ImageSectionHeader) -> TccResult<()> {
    writer.write_all(&hdr.Name).map_err(io_err)?;
    writer.write_all(&hdr.VirtualSize.to_le_bytes()).map_err(io_err)?;
    writer.write_all(&hdr.VirtualAddress.to_le_bytes()).map_err(io_err)?;
    writer.write_all(&hdr.SizeOfRawData.to_le_bytes()).map_err(io_err)?;
    writer.write_all(&hdr.PointerToRawData.to_le_bytes()).map_err(io_err)?;
    writer.write_all(&hdr.PointerToRelocations.to_le_bytes()).map_err(io_err)?;
    writer.write_all(&hdr.PointerToLinenumbers.to_le_bytes()).map_err(io_err)?;
    writer.write_all(&hdr.NumberOfRelocations.to_le_bytes()).map_err(io_err)?;
    writer.write_all(&hdr.NumberOfLinenumbers.to_le_bytes()).map_err(io_err)?;
    writer.write_all(&hdr.Characteristics.to_le_bytes()).map_err(io_err)?;
    Ok(())
}

/// Convert an IO error into a TccError.
fn io_err(e: io::Error) -> TccError {
    TccError::IoError(io::Error::other(format!("PE output I/O error: {}", e)))
}

// ============================================================
// Public API Functions
// ============================================================

/// Main PE output function — orchestrates the entire PE/DLL generation.
///
/// This is the top-level entry point called from the linker when the
/// output format is PE/COFF. It sets up the PeWriter, processes all
/// sections and symbols, and writes the final PE file.
///
/// # Arguments
/// * `state` — The compiler state with all compiled sections and symbols.
/// * `filename` — Output file path.
///
/// # Errors
/// Returns `TccError::LinkerError` for undefined symbols or PE structure errors.
/// Returns `TccError::IoError` for file writing failures.
pub fn pe_output_file(state: &mut TCCState, filename: &str) -> TccResult<()> {
    let arch = crate::arch::native_target().unwrap_or(TargetArch::I386);
    let pe_type = PeType::from_state(state.output_type, state.pe_subsystem);

    if state.verbose > 0 {
        eprintln!("-> pe_output_file({}, type={:?})", filename, pe_type);
    }

    let mut pe = PeWriter::new(state, filename, pe_type, arch);
    pe.output()?;

    Ok(())
}

/// Load a PE file — dispatches to pe_load_def or pe_load_dll based on
/// the file extension.
///
/// - `.def` files are parsed as import definition files.
/// - All other files are treated as DLL import libraries.
///
/// # Arguments
/// * `state` — The compiler state.
/// * `filename` — Path to the file to load.
///
/// # Errors
/// Returns appropriate errors for I/O, parsing, or linking failures.
pub fn pe_load_file(state: &mut TCCState, filename: &str) -> TccResult<()> {
    let path = Path::new(filename);
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");

    if ext.eq_ignore_ascii_case("def") {
        pe_load_def(state, filename)
    } else {
        pe_load_dll(state, filename)
    }
}

/// Load a .def file for DLL import definitions.
///
/// Parses a Windows .def file to extract exported symbol names and
/// add them to the dynamic symbol table for linking against the DLL.
///
/// # .def file format:
/// ```text
/// LIBRARY dllname.dll
/// EXPORTS
///   symbol1
///   symbol2 @ordinal
///   symbol3 = alias
/// ```
fn pe_load_def(state: &mut TCCState, filename: &str) -> TccResult<()> {
    let content = fs::read_to_string(filename).map_err(|e| {
        TccError::IoError(io::Error::other(format!("cannot open def file '{}': {}", filename, e)))
    })?;

    let mut dll_name = String::new();
    let mut in_exports = false;

    // Ensure dynsymtab exists
    let dynsym_idx = match state.dynsymtab_section {
        Some(idx) => idx,
        None => {
            let idx = new_section(state, ".dynsym", SHT_SYMTAB, SHF_ALLOC);
            let strtab = new_section(state, ".dynstr", SHT_STRTAB, SHF_ALLOC);
            state.sections[idx].link = Some(strtab);
            // Create hash table
            let hash = new_section(state, ".hash", crate::elf::SHT_HASH, SHF_ALLOC);
            state.sections[idx].hash = Some(hash);
            state.dynsymtab_section = Some(idx);
            idx
        }
    };

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with(';') {
            continue;
        }

        // Check for LIBRARY directive
        if line.starts_with("LIBRARY") || line.starts_with("library") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                dll_name = parts[1].trim_matches('"').to_string();
            }
            continue;
        }

        // Check for EXPORTS section start
        if line.eq_ignore_ascii_case("EXPORTS") {
            in_exports = true;
            continue;
        }

        // Process export entries
        if in_exports {
            // Parse: name [@ordinal] [NONAME] [DATA] [= alias]
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.is_empty() {
                continue;
            }

            let sym_name = parts[0].trim();
            if sym_name.is_empty() {
                continue;
            }

            // Register this DLL if we haven't already
            if !dll_name.is_empty() {
                let dll_idx = ensure_dll_reference(state, &dll_name);

                // Add symbol to dynsymtab with SHN_FROMDLL
                let info = ELFW_ST_INFO(STB_GLOBAL, STT_FUNC);
                set_elf_sym(
                    state,
                    dynsym_idx,
                    0,
                    0,
                    info,
                    dll_idx as u8,
                    SHN_FROMDLL,
                    sym_name,
                );
            }
        }
    }

    Ok(())
}

/// Load a DLL file and extract its export table.
///
/// Reads the PE headers of a DLL file to find exported symbols and
/// adds them to the dynamic symbol table for linking.
fn pe_load_dll(state: &mut TCCState, filename: &str) -> TccResult<()> {
    let mut file = fs::File::open(filename).map_err(|e| {
        TccError::IoError(io::Error::other(format!("cannot open DLL '{}': {}", filename, e)))
    })?;

    let mut data = Vec::new();
    file.read_to_end(&mut data).map_err(|e| {
        TccError::IoError(io::Error::other(format!("cannot read DLL '{}': {}", filename, e)))
    })?;

    // Extract DLL name from filename
    let dll_name = Path::new(filename)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(filename)
        .to_string();

    // Parse DLL exports and add to dynsymtab
    let exports = parse_pe_exports(&data, &dll_name)?;

    if exports.is_empty() {
        return Ok(());
    }

    // Register the DLL reference
    let dll_idx = ensure_dll_reference(state, &dll_name);

    // Ensure dynsymtab exists
    let dynsym_idx = match state.dynsymtab_section {
        Some(idx) => idx,
        None => {
            let idx = new_section(state, ".dynsym", SHT_SYMTAB, SHF_ALLOC);
            let strtab = new_section(state, ".dynstr", SHT_STRTAB, SHF_ALLOC);
            state.sections[idx].link = Some(strtab);
            let hash = new_section(state, ".hash", crate::elf::SHT_HASH, SHF_ALLOC);
            state.sections[idx].hash = Some(hash);
            state.dynsymtab_section = Some(idx);
            idx
        }
    };

    // Add each exported symbol to the dynamic symbol table
    for export_name in &exports {
        let info = ELFW_ST_INFO(STB_GLOBAL, STT_FUNC);
        set_elf_sym(
            state,
            dynsym_idx,
            0,
            0,
            info,
            dll_idx as u8,
            SHN_FROMDLL,
            export_name,
        );
    }

    Ok(())
}

/// Parse the PE export directory of a DLL from raw file data.
/// Returns a list of exported symbol names.
fn parse_pe_exports(data: &[u8], _dll_name: &str) -> TccResult<Vec<String>> {
    let mut exports = Vec::new();

    // Validate MZ header
    if data.len() < mem::size_of::<ImageDosHeader>() {
        return Ok(exports);
    }
    let e_magic = read16le(&data[0..2]);
    if e_magic != MZ_MAGIC {
        return Ok(exports);
    }
    let e_lfanew = u32::from_le_bytes([data[60], data[61], data[62], data[63]]) as usize;

    // Validate PE signature
    if e_lfanew + 4 > data.len() {
        return Ok(exports);
    }
    let pe_sig = u32::from_le_bytes([
        data[e_lfanew], data[e_lfanew + 1], data[e_lfanew + 2], data[e_lfanew + 3],
    ]);
    if pe_sig != PE_SIGNATURE {
        return Ok(exports);
    }

    // Read COFF file header
    let coff_offset = e_lfanew + 4;
    if coff_offset + mem::size_of::<ImageFileHeader>() > data.len() {
        return Ok(exports);
    }
    let opt_header_size = read16le(&data[coff_offset + 16..coff_offset + 18]) as usize;

    // Read optional header to find data directories
    let opt_offset = coff_offset + mem::size_of::<ImageFileHeader>();
    if opt_offset + opt_header_size > data.len() {
        return Ok(exports);
    }

    let magic = read16le(&data[opt_offset..opt_offset + 2]);
    let is_pe64 = magic == PE32PLUS_MAGIC;

    // Find the export data directory entry
    let export_dir_offset = if is_pe64 {
        opt_offset + 112 // offset of DataDirectory[0] in PE32+ optional header
    } else {
        opt_offset + 96 // offset of DataDirectory[0] in PE32 optional header
    };

    if export_dir_offset + 8 > data.len() {
        return Ok(exports);
    }

    let export_rva = read32le(&data[export_dir_offset..export_dir_offset + 4]);
    let export_size = read32le(&data[export_dir_offset + 4..export_dir_offset + 8]);

    if export_rva == 0 || export_size == 0 {
        return Ok(exports);
    }

    // Convert RVA to file offset using section headers
    let num_sections = read16le(&data[coff_offset + 2..coff_offset + 4]) as usize;
    let sections_offset = opt_offset + opt_header_size;

    let export_file_offset = match rva_to_file_offset(data, sections_offset, num_sections, export_rva) {
        Some(off) => off,
        None => return Ok(exports),
    };

    // Parse the export directory
    if export_file_offset + mem::size_of::<ImageExportDirectory>() > data.len() {
        return Ok(exports);
    }

    let num_names = read32le(&data[export_file_offset + 24..export_file_offset + 28]) as usize;
    let names_rva = read32le(&data[export_file_offset + 32..export_file_offset + 36]);

    let names_file_off = match rva_to_file_offset(data, sections_offset, num_sections, names_rva) {
        Some(off) => off,
        None => return Ok(exports),
    };

    // Read each name
    for i in 0..num_names {
        let name_ptr_off = names_file_off + i * 4;
        if name_ptr_off + 4 > data.len() {
            break;
        }
        let name_rva = read32le(&data[name_ptr_off..name_ptr_off + 4]);
        let name_off = match rva_to_file_offset(data, sections_offset, num_sections, name_rva) {
            Some(off) => off,
            None => continue,
        };

        // Read NUL-terminated name
        let mut end = name_off;
        while end < data.len() && data[end] != 0 {
            end += 1;
        }
        if let Ok(name) = std::str::from_utf8(&data[name_off..end]) {
            if !name.is_empty() {
                exports.push(name.to_string());
            }
        }
    }

    Ok(exports)
}

/// Convert an RVA (Relative Virtual Address) to a file offset
/// using the PE section headers.
fn rva_to_file_offset(
    data: &[u8],
    sections_offset: usize,
    num_sections: usize,
    rva: u32,
) -> Option<usize> {
    let sec_hdr_size = mem::size_of::<ImageSectionHeader>();
    for i in 0..num_sections {
        let sec_off = sections_offset + i * sec_hdr_size;
        if sec_off + sec_hdr_size > data.len() {
            break;
        }
        let vaddr = read32le(&data[sec_off + 12..sec_off + 16]);
        let vsize = read32le(&data[sec_off + 8..sec_off + 12]);
        let raw_off = read32le(&data[sec_off + 20..sec_off + 24]);

        if rva >= vaddr && rva < vaddr + vsize {
            return Some((raw_off + (rva - vaddr)) as usize);
        }
    }
    None
}

/// Ensure a DLL reference exists in the state's loaded_dlls list.
/// Returns the index of the DLL reference.
fn ensure_dll_reference(state: &mut TCCState, dll_name: &str) -> usize {
    // Check if already registered
    for (i, dll) in state.loaded_dlls.iter().enumerate() {
        if dll.name.eq_ignore_ascii_case(dll_name) {
            return i;
        }
    }
    // Add new reference
    let idx = state.loaded_dlls.len();
    state.loaded_dlls.push(DLLReference {
        level: 0,
        handle: None,
        found: true,
        index: idx as u8,
        name: dll_name.to_string(),
    });
    idx
}

/// Add an import symbol to the compiler state.
///
/// Called during compilation when a `__declspec(dllimport)` symbol is
/// encountered. Creates the necessary symbol table entries for the
/// import to be resolved during PE output.
///
/// # Arguments
/// * `state` — The compiler state.
/// * `sym_index` — Symbol index in the main symbol table.
/// * `dll_name` — Name of the DLL providing the symbol.
/// * `func_name` — Name of the imported function/data.
pub fn pe_putimport(
    state: &mut TCCState,
    sym_index: usize,
    dll_name: &str,
    func_name: &str,
) -> TccResult<()> {
    // Register the DLL
    let dll_idx = ensure_dll_reference(state, dll_name);

    // Ensure dynsymtab exists
    let dynsym_idx = match state.dynsymtab_section {
        Some(idx) => idx,
        None => {
            let idx = new_section(state, ".dynsym", SHT_SYMTAB, SHF_ALLOC);
            let strtab = new_section(state, ".dynstr", SHT_STRTAB, SHF_ALLOC);
            state.sections[idx].link = Some(strtab);
            let hash = new_section(state, ".hash", crate::elf::SHT_HASH, SHF_ALLOC);
            state.sections[idx].hash = Some(hash);
            state.dynsymtab_section = Some(idx);
            idx
        }
    };

    // Add symbol to dynsymtab
    let info = ELFW_ST_INFO(STB_GLOBAL, STT_FUNC);
    set_elf_sym(
        state,
        dynsym_idx,
        0,
        0,
        info,
        dll_idx as u8,
        SHN_FROMDLL,
        func_name,
    );

    // Mark as dllimport in sym_attrs
    if let Some(attr) = get_sym_attr(state, sym_index, true) {
        attr.dllimport = true;
    }

    Ok(())
}

/// Set the PE subsystem type from a string value.
///
/// Recognized values: "console", "gui", "native", "posix", "efi_application",
/// or numeric values.
///
/// # Arguments
/// * `state` — The compiler state.
/// * `subsystem_str` — Subsystem identifier string.
pub fn pe_setsubsy(state: &mut TCCState, subsystem_str: &str) -> TccResult<()> {
    let subsys = match subsystem_str.to_lowercase().as_str() {
        "console" | "windows_cui" => IMAGE_SUBSYSTEM_WINDOWS_CUI,
        "gui" | "windows" | "windows_gui" => IMAGE_SUBSYSTEM_WINDOWS_GUI,
        "native" => IMAGE_SUBSYSTEM_NATIVE,
        "efi_application" | "efi" => IMAGE_SUBSYSTEM_EFI_APPLICATION,
        other => {
            // Try parsing as numeric value
            other.parse::<u16>().map_err(|_| {
                TccError::linker(format!("unknown PE subsystem: '{}'", other))
            })?
        }
    };

    state.pe_subsystem = subsys;
    Ok(())
}

/// Add unwind data for x86_64 PE executables.
///
/// Creates .pdata entries containing RUNTIME_FUNCTION records for
/// structured exception handling (SEH) on Windows x86_64.
/// Each record contains the function start RVA, end RVA, and
/// a pointer to unwind info.
///
/// # Arguments
/// * `state` — The compiler state.
/// * `sym_index` — Symbol index for the function.
/// * `func_size` — Size of the function in bytes.
pub fn pe_add_unwind_data(
    state: &mut TCCState,
    sym_index: usize,
    func_size: u32,
) -> TccResult<()> {
    // Unwind data is only relevant for x86_64
    let arch = crate::arch::native_target().unwrap_or(TargetArch::I386);
    if !matches!(arch, TargetArch::X86_64) {
        return Ok(());
    }

    // Create .pdata section if it doesn't exist
    let pdata_idx = match state.uw_pdata {
        Some(idx) => idx,
        None => {
            let idx = new_section(state, ".pdata", SHT_PROGBITS, SHF_ALLOC);
            state.sections[idx].sh_addralign = 4;
            state.uw_pdata = Some(idx);
            idx
        }
    };

    // Each RUNTIME_FUNCTION entry is 12 bytes:
    // - BeginAddress (4 bytes): RVA of function start
    // - EndAddress (4 bytes): RVA of function end
    // - UnwindInfoAddress (4 bytes): RVA of UNWIND_INFO
    let entry_size = 12;
    let entry_offset = section_ptr_add(&mut state.sections[pdata_idx], entry_size);

    // Get the function's section and offset
    let symtab_idx = match state.symtab_section {
        Some(idx) => idx,
        None => return Ok(()),
    };

    let sym_value = get_sym_value(&state.sections[symtab_idx], sym_index);
    let sym_shndx = get_sym_shndx(&state.sections[symtab_idx], sym_index);

    if sym_shndx == SHN_UNDEF {
        return Ok(());
    }

    // Write RUNTIME_FUNCTION entry
    // The addresses are written as relocations that will be resolved
    // during the PE output phase.
    let d = &mut state.sections[pdata_idx].data;

    // BeginAddress — function start RVA (placeholder, resolved via relocation)
    write32le(&mut d[entry_offset..], sym_value as u32);
    // EndAddress — function end RVA
    write32le(&mut d[entry_offset + 4..], (sym_value + func_size as u64) as u32);
    // UnwindInfoAddress — will point to unwind info (0 for now)
    write32le(&mut d[entry_offset + 8..], 0);

    // Add relocations for the function addresses
    // These will be resolved when addresses are finalized
    put_elf_reloc(
        state,
        pdata_idx,
        entry_offset as u64,
        1, // R_X86_64_64 equivalent for PE
        sym_index,
    );

    // Track the latest unwind offset
    state.uw_offs = (entry_offset + entry_size) as u32;
    state.uw_sym = Some(sym_index);

    Ok(())
}

/// Get the list of exported symbols from a DLL file.
///
/// Reads the PE export directory from the specified DLL and returns
/// a vector of exported symbol names. This is used by the linker
/// to resolve imports against DLL files.
///
/// # Arguments
/// * `filename` — Path to the DLL file.
///
/// # Returns
/// A vector of exported function/data names.
pub fn tcc_get_dllexports(filename: &str) -> TccResult<Vec<String>> {
    let mut file = fs::File::open(filename).map_err(|e| {
        TccError::IoError(io::Error::other(format!("cannot open DLL '{}': {}", filename, e)))
    })?;

    let mut data = Vec::new();
    file.read_to_end(&mut data).map_err(|e| {
        TccError::IoError(io::Error::other(format!("cannot read DLL '{}': {}", filename, e)))
    })?;

    let dll_name = Path::new(filename)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(filename);

    parse_pe_exports(&data, dll_name)
}

/// Add PE runtime support — CRT startup files and runtime library.
///
/// When nostdlib is not set, this function adds the appropriate CRT
/// startup object files and the TCC runtime library (libtcc1.a) to
/// the link. The startup file is chosen based on PE type:
/// - DLLs: dllcrt1.o or dllmain.o
/// - GUI executables: wincrt1.o
/// - Console executables: crt1.o
fn pe_add_runtime(state: &mut TCCState) -> TccResult<()> {
    if state.nostdlib {
        return Ok(());
    }

    // Add the appropriate CRT startup file based on PE type
    let pe_type = PeType::from_state(state.output_type, state.pe_subsystem);
    let crt_name = match pe_type {
        PeType::Dll => "dllcrt1",
        PeType::Gui => "wincrt1",
        _ => "crt1",
    };

    // Try to add the CRT startup library
    if state.add_library(crt_name).is_err() && state.verbose > 0 {
        eprintln!("warning: CRT startup '{}' not found", crt_name);
    }

    // Add libtcc1 runtime library
    if state.add_library("tcc1").is_err() && state.verbose > 0 {
        eprintln!("warning: runtime library '{}' not found", LIBTCC1);
    }

    // Add bounds checking support if enabled
    if state.do_bounds_check && state.add_library("bcheck").is_err() && state.verbose > 0 {
        eprintln!("warning: bounds checking library not found");
    }

    // Add backtrace support if enabled
    if state.do_backtrace && state.add_library("bt-exe").is_err() && state.verbose > 0 {
        eprintln!("warning: backtrace library not found");
    }

    Ok(())
}

/// Load a PE resource COFF object file.
/// Resources (.res compiled to COFF by windres) are loaded as
/// regular object files and merged into the .rsrc section.
fn pe_load_res(state: &mut TCCState, filename: &str) -> TccResult<()> {
    let mut file = fs::File::open(filename).map_err(|e| {
        TccError::IoError(io::Error::other(format!("cannot open resource file '{}': {}", filename, e)))
    })?;

    let mut data = Vec::new();
    file.read_to_end(&mut data).map_err(|e| {
        TccError::IoError(io::Error::other(format!("cannot read resource file '{}': {}", filename, e)))
    })?;

    if data.len() < 4 {
        return Err(TccError::linker(format!(
            "invalid resource file '{}': too small",
            filename
        )));
    }

    // Check for COFF format (not PE, not MZ)
    let magic = read16le(&data[0..2]);
    if magic == MZ_MAGIC {
        return Err(TccError::linker(format!(
            "'{}' is a PE executable, not a resource file",
            filename
        )));
    }

    // Create or find the .rsrc section
    let rsrc_idx = match find_section(state, ".rsrc") {
        Some(idx) => idx,
        None => new_section(state, ".rsrc", SHT_PROGBITS, SHF_ALLOC),
    };

    // Copy resource data into the .rsrc section
    let offset = section_ptr_add(&mut state.sections[rsrc_idx], data.len());
    state.sections[rsrc_idx].data[offset..offset + data.len()].copy_from_slice(&data);

    Ok(())
}

/// Auto-generate a .def file alongside a DLL output.
/// Lists all exported symbols in the standard .def format.
fn pe_generate_def_file(_state: &TCCState, dll_filename: &str, exports: &[PeExportEntry]) -> TccResult<()> {
    let def_path = Path::new(dll_filename).with_extension("def");
    let def_filename = def_path.to_str().unwrap_or("output.def");

    let mut file = fs::File::create(def_filename).map_err(|e| {
        TccError::IoError(io::Error::other(format!("cannot create def file '{}': {}", def_filename, e)))
    })?;

    let dll_name = Path::new(dll_filename)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("output.dll");

    writeln!(file, "LIBRARY {}", dll_name).map_err(|e| {
        TccError::IoError(io::Error::other(format!("write error: {}", e)))
    })?;
    writeln!(file, "EXPORTS").map_err(|e| {
        TccError::IoError(io::Error::other(format!("write error: {}", e)))
    })?;

    for export in exports {
        writeln!(file, "    {}", export.name).map_err(|e| {
            TccError::IoError(io::Error::other(format!("write error: {}", e)))
        })?;
    }

    Ok(())
}

// ============================================================
// Unit Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pe_type_enum() {
        assert_eq!(PeType::Exe as u32, 3);
        assert_eq!(PeType::Gui as u32, 2);
        assert_eq!(PeType::Dll as u32, 1);
        assert_eq!(PeType::Run as u32, 4);
    }

    #[test]
    fn test_pe_type_from_state() {
        assert_eq!(PeType::from_state(Some(OutputType::Dll), 3), PeType::Dll);
        assert_eq!(PeType::from_state(Some(OutputType::Memory), 3), PeType::Run);
        assert_eq!(PeType::from_state(Some(OutputType::Exe), IMAGE_SUBSYSTEM_WINDOWS_GUI), PeType::Gui);
        assert_eq!(PeType::from_state(Some(OutputType::Exe), IMAGE_SUBSYSTEM_WINDOWS_CUI), PeType::Exe);
        assert_eq!(PeType::from_state(None, 0), PeType::Exe);
    }

    #[test]
    fn test_image_dos_header_size() {
        assert_eq!(mem::size_of::<ImageDosHeader>(), 64);
    }

    #[test]
    fn test_image_file_header_size() {
        assert_eq!(mem::size_of::<ImageFileHeader>(), 20);
    }

    #[test]
    fn test_image_section_header_size() {
        assert_eq!(mem::size_of::<ImageSectionHeader>(), 40);
    }

    #[test]
    fn test_image_import_descriptor_size() {
        assert_eq!(mem::size_of::<ImageImportDescriptor>(), 20);
    }

    #[test]
    fn test_image_export_directory_size() {
        assert_eq!(mem::size_of::<ImageExportDirectory>(), 40);
    }

    #[test]
    fn test_align_up() {
        assert_eq!(PeWriter::align_up(0, 0x200), 0);
        assert_eq!(PeWriter::align_up(1, 0x200), 0x200);
        assert_eq!(PeWriter::align_up(0x200, 0x200), 0x200);
        assert_eq!(PeWriter::align_up(0x201, 0x200), 0x400);
        assert_eq!(PeWriter::align_up(0x1000, 0x1000), 0x1000);
        assert_eq!(PeWriter::align_up(0x1001, 0x1000), 0x2000);
    }

    #[test]
    fn test_machine_constants() {
        assert_eq!(IMAGE_FILE_MACHINE_I386, 0x014c);
        assert_eq!(IMAGE_FILE_MACHINE_AMD64, 0x8664);
    }

    #[test]
    fn test_pe_constants() {
        assert_eq!(MZ_MAGIC, 0x5A4D);
        assert_eq!(PE_SIGNATURE, 0x0000_4550);
        assert_eq!(PE32_MAGIC, 0x010b);
        assert_eq!(PE32PLUS_MAGIC, 0x020b);
    }

    #[test]
    fn test_st_pe_constants() {
        assert_eq!(ST_PE_EXPORT, 0x10);
        assert_eq!(ST_PE_IMPORT, 0x20);
        assert_eq!(ST_PE_STDCALL, 0x40);
    }

    #[test]
    fn test_section_characteristics() {
        // Code section flags: code + execute + read
        let code_flags = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
        assert_ne!(code_flags & IMAGE_SCN_CNT_CODE, 0);
        assert_ne!(code_flags & IMAGE_SCN_MEM_EXECUTE, 0);
        assert_ne!(code_flags & IMAGE_SCN_MEM_READ, 0);
        assert_eq!(code_flags & IMAGE_SCN_MEM_WRITE, 0);
    }

    #[test]
    fn test_rva_to_file_offset_empty() {
        let data = [0u8; 64];
        assert_eq!(rva_to_file_offset(&data, 0, 0, 0x1000), None);
    }

    #[test]
    fn test_parse_pe_exports_invalid() {
        // Invalid data (not a PE file)
        let data = [0u8; 100];
        let result = parse_pe_exports(&data, "test.dll").unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_classify_section_text() {
        let mut sec = Section::default();
        sec.sh_flags = SHF_ALLOC as i32 | SHF_EXECINSTR as i32;
        sec.sh_type = SHT_PROGBITS as i32;
        sec.name = ".text".to_string();
        assert_eq!(PeWriter::classify_section(&sec), Some(PE_SEC_TEXT));
    }

    #[test]
    fn test_classify_section_data() {
        let mut sec = Section::default();
        sec.sh_flags = SHF_ALLOC as i32 | SHF_WRITE as i32;
        sec.sh_type = SHT_PROGBITS as i32;
        sec.name = ".data".to_string();
        assert_eq!(PeWriter::classify_section(&sec), Some(PE_SEC_DATA));
    }

    #[test]
    fn test_classify_section_bss() {
        let mut sec = Section::default();
        sec.sh_flags = SHF_ALLOC as i32 | SHF_WRITE as i32;
        sec.sh_type = SHT_NOBITS as i32;
        sec.name = ".bss".to_string();
        assert_eq!(PeWriter::classify_section(&sec), Some(PE_SEC_BSS));
    }

    #[test]
    fn test_classify_section_rdata() {
        let mut sec = Section::default();
        sec.sh_flags = SHF_ALLOC as i32;
        sec.sh_type = SHT_PROGBITS as i32;
        sec.name = ".rdata".to_string();
        assert_eq!(PeWriter::classify_section(&sec), Some(PE_SEC_RDATA));
    }

    #[test]
    fn test_classify_section_pdata() {
        let mut sec = Section::default();
        sec.sh_flags = SHF_ALLOC as i32;
        sec.sh_type = SHT_PROGBITS as i32;
        sec.name = ".pdata".to_string();
        assert_eq!(PeWriter::classify_section(&sec), Some(PE_SEC_PDATA));
    }

    #[test]
    fn test_classify_section_skip_reloc() {
        let mut sec = Section::default();
        sec.sh_type = SHT_RELX as i32;
        sec.sh_flags = SHF_ALLOC as i32;
        sec.name = ".rela.text".to_string();
        assert_eq!(PeWriter::classify_section(&sec), None);
    }

    #[test]
    fn test_default_structs() {
        let dos = ImageDosHeader::default();
        assert_eq!(dos.e_magic, 0);
        assert_eq!(dos.e_lfanew, 0);

        let file_hdr = ImageFileHeader::default();
        assert_eq!(file_hdr.Machine, 0);
        assert_eq!(file_hdr.NumberOfSections, 0);

        let sec_hdr = ImageSectionHeader::default();
        assert_eq!(sec_hdr.VirtualSize, 0);
        assert_eq!(sec_hdr.VirtualAddress, 0);
        assert_eq!(sec_hdr.Name, [0u8; 8]);

        let data_dir = ImageDataDirectory::default();
        assert_eq!(data_dir.VirtualAddress, 0);
        assert_eq!(data_dir.Size, 0);

        let import_desc = ImageImportDescriptor::default();
        assert_eq!(import_desc.OriginalFirstThunk, 0);

        let export_dir = ImageExportDirectory::default();
        assert_eq!(export_dir.NumberOfFunctions, 0);

        let base_reloc = ImageBaseRelocation::default();
        assert_eq!(base_reloc.VirtualAddress, 0);

        let res_dir = ImageResourceDirectory::default();
        assert_eq!(res_dir.NumberOfNamedEntries, 0);
    }
}
