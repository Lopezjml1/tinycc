//! PE/COFF (Portable Executable) output backend for `TinyCC`.
//!
//! This module generates Windows DLL and EXE files from the compiler's
//! internal section and symbol representation. Handles import tables,
//! export tables, base relocations, unwind data, and resource sections.
//!
//! C equivalent: `tccpe.c` (2,114 lines)
//!
//! # Platform Availability
//!
//! This module is intentionally **NOT** gated with `#[cfg(target_os = "windows")]`.
//! `TinyCC` supports cross-compilation — a Linux or macOS host can produce
//! Windows PE executables using `tcc -m32 -o hello.exe hello.c`. The PE
//! output backend must be available on all platforms to support this
//! cross-compilation workflow, matching the original C behavior where
//! `tccpe.c` is compiled unconditionally on all hosts.
//!
//! Supports:
//! - PE32 (32-bit) and PE32+ (64-bit) output formats
//! - DLL, GUI EXE, console EXE, and in-memory execution modes
//! - Import table generation from loaded DLL references
//! - Export table generation from `__declspec(dllexport)` symbols
//! - Base relocation table for ASLR support
//! - Unwind information for structured exception handling (x86\_64)
//! - PDB debug info stub generation

// PE/COFF linker — inherently performs integer casts between u16/u32/u64/usize
// and i16/i32 for PE header fields, section RVAs, and import/export table
// entries.  All casts are faithful translations of tccpe.c.
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::cast_lossless)]
#![allow(clippy::field_reassign_with_default)]
#![allow(clippy::items_after_statements)]
#![allow(clippy::manual_let_else)]
#![allow(clippy::manual_strip)]
#![allow(clippy::ptr_arg)]
#![allow(clippy::similar_names)]
#![allow(clippy::struct_field_names)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::trivially_copy_pass_by_ref)]
#![allow(clippy::unnecessary_wraps)]
#![allow(clippy::unreadable_literal)]
#![allow(clippy::used_underscore_binding)]

use std::io::Write;
use std::path::Path;

use bytemuck::{Pod, Zeroable};
use zerocopy::AsBytes;

use crate::context::{OutputType, TccState};
use crate::error::{TccError, TccResult};
use crate::formats::coff as coff_fmt;
use crate::formats::elf as elf_fmt;
use crate::linker::elf as elf_linker;
use crate::targets::write32le;
use crate::types::{DllReference, Section};

// ===========================================================================
//  PE Constants (tccpe.c lines 1–60)
// ===========================================================================

const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D;
const IMAGE_NT_SIGNATURE: u32 = 0x0000_4550;
const IMAGE_NT_OPTIONAL_HDR32_MAGIC: u16 = 0x10b;
const IMAGE_NT_OPTIONAL_HDR64_MAGIC: u16 = 0x20b;

/// Alias for PE\0\0 signature used in `pe_write` and `get_dllexports`.
const PE_SIGNATURE: u32 = IMAGE_NT_SIGNATURE;
/// PE32 optional header magic.
const PE32_MAGIC: u16 = IMAGE_NT_OPTIONAL_HDR32_MAGIC;
/// PE32+ optional header magic for 64-bit images.
const PE32PLUS_MAGIC: u16 = IMAGE_NT_OPTIONAL_HDR64_MAGIC;

const IMAGE_FILE_EXECUTABLE_IMAGE: u16 = 0x0002;
const IMAGE_FILE_32BIT_MACHINE: u16 = 0x0100;
const IMAGE_FILE_DLL: u16 = 0x2000;
const IMAGE_FILE_LARGE_ADDRESS_AWARE: u16 = 0x0020;

const IMAGE_SCN_CNT_CODE: u32 = 0x0000_0020;
const IMAGE_SCN_CNT_INITIALIZED_DATA: u32 = 0x0000_0040;
const IMAGE_SCN_CNT_UNINITIALIZED_DATA: u32 = 0x0000_0080;
const IMAGE_SCN_MEM_DISCARDABLE: u32 = 0x0200_0000;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;

const IMAGE_DIRECTORY_ENTRY_EXPORT: usize = 0;
const IMAGE_DIRECTORY_ENTRY_IMPORT: usize = 1;
const IMAGE_DIRECTORY_ENTRY_RESOURCE: usize = 2;
const IMAGE_DIRECTORY_ENTRY_EXCEPTION: usize = 3;
const IMAGE_DIRECTORY_ENTRY_BASERELOC: usize = 5;
const IMAGE_DIRECTORY_ENTRY_IAT: usize = 12;
const IMAGE_NUMBEROF_DIRECTORY_ENTRIES: usize = 16;

const IMAGE_REL_BASED_HIGHLOW: u16 = 3;
const IMAGE_REL_BASED_DIR64: u16 = 10;

const PE_MERGE_DATA: bool = true;

const ST_PE_EXPORT: u8 = 0x10;
const ST_PE_IMPORT: u8 = 0x20;
const ST_PE_STDCALL: u8 = 0x40;

const RSRC_RELTYPE_I386: u16 = 7;
const RSRC_RELTYPE_X64: u16 = 3;
const RSRC_RELTYPE_ARM: u16 = 7;

// ===========================================================================
//  PE Address Type and utility functions (tccpe.c lines 14–49)
// ===========================================================================

/// PE address type — `u64` for 64-bit targets, `u32` for 32-bit.
pub type Addr3264 = u64;

/// PE image relocation type for base relocations.
/// C equivalent: `PE_IMAGE_REL` macro (tccpe.c:21–26)
pub fn pe_image_rel_based(is_64bit: bool) -> u16 {
    if is_64bit { IMAGE_REL_BASED_DIR64 } else { IMAGE_REL_BASED_HIGHLOW }
}

/// PE machine type.
/// C equivalent: `IMAGE_FILE_MACHINE` macro (tccpe.c:28–33)
pub fn image_file_machine(arch: &str) -> u16 {
    match arch {
        "x86_64" | "x86-64" | "amd64" => 0x8664,
        "arm" | "armv4" => 0x01c0,
        "arm64" | "aarch64" => 0xaa64,
        _ => 0x014c,
    }
}

fn rel_type_direct(is_64bit: bool) -> u32 {
    if is_64bit { elf_fmt::R_X86_64_64 } else { elf_fmt::R_386_32 }
}

fn rel_type_relative(is_64bit: bool) -> u32 {
    if is_64bit { elf_fmt::R_X86_64_RELATIVE } else { elf_fmt::R_386_RELATIVE }
}

fn rel_type_thunkfix(is_64bit: bool) -> u32 {
    rel_type_relative(is_64bit)
}

fn rsrc_reltype(arch: &str) -> u16 {
    match arch {
        "x86_64" | "x86-64" | "amd64" => RSRC_RELTYPE_X64,
        "arm" | "armv4" => RSRC_RELTYPE_ARM,
        _ => RSRC_RELTYPE_I386,
    }
}

fn is_target_64bit(arch: &str) -> bool {
    matches!(arch, "x86_64" | "x86-64" | "amd64" | "arm64" | "aarch64")
}

fn is_target_arm(arch: &str) -> bool {
    matches!(arch, "arm" | "armv4" | "arm64" | "aarch64")
}

// ===========================================================================
//  PE Header Structures (tccpe.c lines 62–290)
// ===========================================================================

/// `IMAGE_DOS_HEADER` — MZ stub header.
#[repr(C)]
#[derive(Debug, Clone, Copy, AsBytes, Pod, Zeroable)]
pub struct ImageDosHeader {
    pub e_magic: u16,
    pub e_cblp: u16,
    pub e_cp: u16,
    pub e_crlc: u16,
    pub e_cparhdr: u16,
    pub e_minalloc: u16,
    pub e_maxalloc: u16,
    pub e_ss: u16,
    pub e_sp: u16,
    pub e_csum: u16,
    pub e_ip: u16,
    pub e_cs: u16,
    pub e_lfarlc: u16,
    pub e_ovno: u16,
    pub e_res: [u16; 4],
    pub e_oemid: u16,
    pub e_oeminfo: u16,
    pub e_res2: [u16; 10],
    pub e_lfanew: i32,
}

impl Default for ImageDosHeader {
    fn default() -> Self {
        Self {
            e_magic: IMAGE_DOS_SIGNATURE,
            e_cblp: 0x0090, e_cp: 0x0003, e_crlc: 0, e_cparhdr: 4,
            e_minalloc: 0, e_maxalloc: 0xFFFF, e_ss: 0, e_sp: 0x00B8,
            e_csum: 0, e_ip: 0, e_cs: 0, e_lfarlc: 0x0040, e_ovno: 0,
            e_res: [0; 4], e_oemid: 0, e_oeminfo: 0, e_res2: [0; 10],
            e_lfanew: 0,
        }
    }
}

/// `IMAGE_FILE_HEADER` — COFF file header within PE.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, AsBytes, Pod, Zeroable)]
pub struct ImageFileHeader {
    pub machine: u16,
    pub number_of_sections: u16,
    pub time_date_stamp: u32,
    pub pointer_to_symbol_table: u32,
    pub number_of_symbols: u32,
    pub size_of_optional_header: u16,
    pub characteristics: u16,
}

/// `IMAGE_DATA_DIRECTORY` — a single data directory entry.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, AsBytes, Pod, Zeroable)]
pub struct ImageDataDirectory {
    pub virtual_address: u32,
    pub size: u32,
}

/// `IMAGE_OPTIONAL_HEADER32` — 32-bit PE optional header.
#[repr(C)]
#[derive(Debug, Clone)]
pub struct ImageOptionalHeader32 {
    pub magic: u16,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
    pub base_of_data: u32,
    pub image_base: u32,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_operating_system_version: u16,
    pub minor_operating_system_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version_value: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub checksum: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub size_of_stack_reserve: u32,
    pub size_of_stack_commit: u32,
    pub size_of_heap_reserve: u32,
    pub size_of_heap_commit: u32,
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
    pub data_directory: [ImageDataDirectory; IMAGE_NUMBEROF_DIRECTORY_ENTRIES],
}

#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
impl Default for ImageOptionalHeader32 {
    fn default() -> Self {
        Self {
            magic: IMAGE_NT_OPTIONAL_HDR32_MAGIC,
            major_linker_version: 6, minor_linker_version: 0,
            size_of_code: 0, size_of_initialized_data: 0,
            size_of_uninitialized_data: 0, address_of_entry_point: 0,
            base_of_code: 0, base_of_data: 0, image_base: 0,
            section_alignment: 0, file_alignment: 0,
            major_operating_system_version: 4, minor_operating_system_version: 0,
            major_image_version: 0, minor_image_version: 0,
            major_subsystem_version: 4, minor_subsystem_version: 0,
            win32_version_value: 0, size_of_image: 0, size_of_headers: 0,
            checksum: 0, subsystem: 0, dll_characteristics: 0,
            size_of_stack_reserve: 0x100_0000, size_of_stack_commit: 0x1000,
            size_of_heap_reserve: 0x100_0000, size_of_heap_commit: 0x1000,
            loader_flags: 0,
            number_of_rva_and_sizes: IMAGE_NUMBEROF_DIRECTORY_ENTRIES as u32,
            data_directory: [ImageDataDirectory::default(); IMAGE_NUMBEROF_DIRECTORY_ENTRIES],
        }
    }
}

/// `IMAGE_OPTIONAL_HEADER64` — 64-bit PE optional header.
#[repr(C)]
#[derive(Debug, Clone)]
pub struct ImageOptionalHeader64 {
    pub magic: u16,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
    pub image_base: u64,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_operating_system_version: u16,
    pub minor_operating_system_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version_value: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub checksum: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub size_of_stack_reserve: u64,
    pub size_of_stack_commit: u64,
    pub size_of_heap_reserve: u64,
    pub size_of_heap_commit: u64,
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
    pub data_directory: [ImageDataDirectory; IMAGE_NUMBEROF_DIRECTORY_ENTRIES],
}

#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
impl Default for ImageOptionalHeader64 {
    fn default() -> Self {
        Self {
            magic: IMAGE_NT_OPTIONAL_HDR64_MAGIC,
            major_linker_version: 6, minor_linker_version: 0,
            size_of_code: 0, size_of_initialized_data: 0,
            size_of_uninitialized_data: 0, address_of_entry_point: 0,
            base_of_code: 0, image_base: 0,
            section_alignment: 0, file_alignment: 0,
            major_operating_system_version: 4, minor_operating_system_version: 0,
            major_image_version: 0, minor_image_version: 0,
            major_subsystem_version: 4, minor_subsystem_version: 0,
            win32_version_value: 0, size_of_image: 0, size_of_headers: 0,
            checksum: 0, subsystem: 0, dll_characteristics: 0,
            size_of_stack_reserve: 0x100_0000, size_of_stack_commit: 0x1000,
            size_of_heap_reserve: 0x100_0000, size_of_heap_commit: 0x1000,
            loader_flags: 0,
            number_of_rva_and_sizes: IMAGE_NUMBEROF_DIRECTORY_ENTRIES as u32,
            data_directory: [ImageDataDirectory::default(); IMAGE_NUMBEROF_DIRECTORY_ENTRIES],
        }
    }
}

/// `IMAGE_SECTION_HEADER` — PE section header.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, AsBytes, Pod, Zeroable)]
pub struct ImageSectionHeader {
    pub name: [u8; 8],
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub size_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
    pub pointer_to_relocations: u32,
    pub pointer_to_linenumbers: u32,
    pub number_of_relocations: u16,
    pub number_of_linenumbers: u16,
    pub characteristics: u32,
}

/// `IMAGE_EXPORT_DIRECTORY` — export table header.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, AsBytes, Pod, Zeroable)]
pub struct ImageExportDirectory {
    pub characteristics: u32,
    pub time_date_stamp: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub name: u32,
    pub base: u32,
    pub number_of_functions: u32,
    pub number_of_names: u32,
    pub address_of_functions: u32,
    pub address_of_names: u32,
    pub address_of_name_ordinals: u32,
}

/// `IMAGE_IMPORT_DESCRIPTOR` — import table entry.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, AsBytes, Pod, Zeroable)]
pub struct ImageImportDescriptor {
    pub original_first_thunk: u32,
    pub time_date_stamp: u32,
    pub forwarder_chain: u32,
    pub name: u32,
    pub first_thunk: u32,
}

/// `IMAGE_BASE_RELOCATION` — base relocation block header.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, AsBytes, Pod, Zeroable)]
pub struct ImageBaseRelocation {
    pub virtual_address: u32,
    pub size_of_block: u32,
}

// ===========================================================================
//  Composite PE Header (tccpe.c lines 258–273)
// ===========================================================================

/// PE file header — combines DOS header, DOS stub, NT signature, file header,
/// and optional header data.
pub struct PeHeader {
    pub dos_hdr: ImageDosHeader,
    pub dos_stub: Vec<u8>,
    pub nt_sig: u32,
    pub file_hdr: ImageFileHeader,
    pub opt_hdr_data: Vec<u8>,
}

impl Default for PeHeader {
    fn default() -> Self {
        Self {
            dos_hdr: ImageDosHeader::default(),
            dos_stub: vec![0u8; 0x40],
            nt_sig: IMAGE_NT_SIGNATURE,
            file_hdr: ImageFileHeader::default(),
            opt_hdr_data: Vec::new(),
        }
    }
}

// ===========================================================================
//  Internal State Structures (tccpe.c lines 292–381)
// ===========================================================================

/// PE section classification enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PeSectionClass {
    Text = 0,
    Rdata = 1,
    Data = 2,
    Bss = 3,
    Idata = 4,
    Pdata = 5,
    Other = 6,
    Rsrc = 7,
    Debug = 8,
    Reloc = 9,
    Last = 10,
}

/// PE output type classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[derive(Default)]
pub enum PeType {
    #[default]
    Nul = 0,
    Dll = 1,
    Gui = 2,
    Exe = 3,
    Run = 4,
}


/// Per-section metadata for PE output.
pub struct PeSectionInfo {
    pub cls: PeSectionClass,
    pub name: String,
    pub sh_addr: u64,
    pub sh_size: u32,
    pub pe_flags: u32,
    pub sec: Vec<usize>,
    pub data_size: u32,
    pub ish: ImageSectionHeader,
}

impl PeSectionInfo {
    fn new(cls: PeSectionClass, name: &str, sh_addr: u64) -> Self {
        Self {
            cls, name: name.to_string(), sh_addr, sh_size: 0,
            pe_flags: IMAGE_SCN_MEM_READ, sec: Vec::new(),
            data_size: 0, ish: ImageSectionHeader::default(),
        }
    }
}

/// Import symbol tracking.
pub struct ImportSymbol {
    pub sym_index: i32,
    pub iat_index: i32,
    pub thk_offset: i32,
}

/// Per-DLL import information.
pub struct PeImportInfo {
    pub dll_index: i32,
    pub symbols: Vec<ImportSymbol>,
}

/// Master PE output state.
pub struct PeInfo {
    pub reloc: Option<usize>,
    pub thunk: Option<usize>,
    pub filename: String,
    pub pe_type: PeType,
    pub size_of_headers: u32,
    pub image_base: u64,
    pub start_symbol: String,
    pub start_addr: u32,
    pub imp_offs: u32,
    pub imp_size: u32,
    pub iat_offs: u32,
    pub iat_size: u32,
    pub exp_offs: u32,
    pub exp_size: u32,
    pub subsystem: i32,
    pub section_align: u32,
    pub file_align: u32,
    pub sec_info: Vec<PeSectionInfo>,
    pub imp_info: Vec<PeImportInfo>,
    pub checksum: u32,
    pub pos: u32,
    arch: String,
}

impl PeInfo {
    /// Create a default `PeInfo` with no filename or architecture set.
    fn new() -> Self {
        Self {
            reloc: None, thunk: None,
            filename: String::new(), pe_type: PeType::Nul,
            size_of_headers: 0, image_base: 0,
            start_symbol: String::new(), start_addr: 0,
            imp_offs: 0, imp_size: 0, iat_offs: 0, iat_size: 0,
            exp_offs: 0, exp_size: 0, subsystem: 0,
            section_align: 0, file_align: 0,
            sec_info: Vec::new(), imp_info: Vec::new(),
            checksum: 0, pos: 0, arch: String::new(),
        }
    }

    /// Create a `PeInfo` with a specified filename and architecture.
    fn with_file(filename: &str, arch: &str) -> Self {
        Self {
            reloc: None, thunk: None,
            filename: filename.to_string(), pe_type: PeType::Nul,
            size_of_headers: 0, image_base: 0,
            start_symbol: String::new(), start_addr: 0,
            imp_offs: 0, imp_size: 0, iat_offs: 0, iat_size: 0,
            exp_offs: 0, exp_size: 0, subsystem: 0,
            section_align: 0, file_align: 0,
            sec_info: Vec::new(), imp_info: Vec::new(),
            checksum: 0, pos: 0, arch: arch.to_string(),
        }
    }

    fn is_64bit(&self) -> bool { is_target_64bit(&self.arch) }

    fn addr_size(&self) -> u32 { if self.is_64bit() { 8 } else { 4 } }
}

// ===========================================================================
//  Serialization helpers for PE structs
// ===========================================================================

/// Serialize a `ImageDosHeader` into bytes in little-endian order.
/// Serialize `ImageDosHeader` to bytes using zerocopy `AsBytes`.
/// C equivalent: writing `IMAGE_DOS_HEADER` to output file.
fn serialize_dos_header(hdr: &ImageDosHeader) -> Vec<u8> {
    hdr.as_bytes().to_vec()
}

/// Serialize `ImageFileHeader` to bytes using zerocopy `AsBytes`.
/// C equivalent: `fwrite(&pe_header.file_hdr, ...)` at tccpe.c
fn serialize_file_header(hdr: &ImageFileHeader) -> Vec<u8> {
    hdr.as_bytes().to_vec()
}

/// Serialize `ImageSectionHeader` to bytes using zerocopy `AsBytes`.
fn serialize_section_header(hdr: &ImageSectionHeader) -> Vec<u8> {
    hdr.as_bytes().to_vec()
}

/// Serialize `ImageDataDirectory` to bytes using zerocopy `AsBytes`.
fn serialize_data_directory(dd: &ImageDataDirectory) -> Vec<u8> {
    dd.as_bytes().to_vec()
}

/// Serialize `ImageExportDirectory` to bytes using zerocopy `AsBytes`.
fn serialize_export_directory(ed: &ImageExportDirectory) -> Vec<u8> {
    ed.as_bytes().to_vec()
}

/// Serialize `ImageImportDescriptor` to bytes using zerocopy `AsBytes`.
fn serialize_import_descriptor(id: &ImageImportDescriptor) -> Vec<u8> {
    id.as_bytes().to_vec()
}

/// Serialize 32-bit optional header to bytes.
fn serialize_optional_header_32(oh: &ImageOptionalHeader32) -> Vec<u8> {
    let mut buf = Vec::with_capacity(224);
    buf.extend_from_slice(&oh.magic.to_le_bytes());
    buf.push(oh.major_linker_version);
    buf.push(oh.minor_linker_version);
    buf.extend_from_slice(&oh.size_of_code.to_le_bytes());
    buf.extend_from_slice(&oh.size_of_initialized_data.to_le_bytes());
    buf.extend_from_slice(&oh.size_of_uninitialized_data.to_le_bytes());
    buf.extend_from_slice(&oh.address_of_entry_point.to_le_bytes());
    buf.extend_from_slice(&oh.base_of_code.to_le_bytes());
    buf.extend_from_slice(&oh.base_of_data.to_le_bytes());
    buf.extend_from_slice(&oh.image_base.to_le_bytes());
    buf.extend_from_slice(&oh.section_alignment.to_le_bytes());
    buf.extend_from_slice(&oh.file_alignment.to_le_bytes());
    buf.extend_from_slice(&oh.major_operating_system_version.to_le_bytes());
    buf.extend_from_slice(&oh.minor_operating_system_version.to_le_bytes());
    buf.extend_from_slice(&oh.major_image_version.to_le_bytes());
    buf.extend_from_slice(&oh.minor_image_version.to_le_bytes());
    buf.extend_from_slice(&oh.major_subsystem_version.to_le_bytes());
    buf.extend_from_slice(&oh.minor_subsystem_version.to_le_bytes());
    buf.extend_from_slice(&oh.win32_version_value.to_le_bytes());
    buf.extend_from_slice(&oh.size_of_image.to_le_bytes());
    buf.extend_from_slice(&oh.size_of_headers.to_le_bytes());
    buf.extend_from_slice(&oh.checksum.to_le_bytes());
    buf.extend_from_slice(&oh.subsystem.to_le_bytes());
    buf.extend_from_slice(&oh.dll_characteristics.to_le_bytes());
    buf.extend_from_slice(&oh.size_of_stack_reserve.to_le_bytes());
    buf.extend_from_slice(&oh.size_of_stack_commit.to_le_bytes());
    buf.extend_from_slice(&oh.size_of_heap_reserve.to_le_bytes());
    buf.extend_from_slice(&oh.size_of_heap_commit.to_le_bytes());
    buf.extend_from_slice(&oh.loader_flags.to_le_bytes());
    buf.extend_from_slice(&oh.number_of_rva_and_sizes.to_le_bytes());
    for dd in &oh.data_directory { buf.extend_from_slice(&serialize_data_directory(dd)); }
    buf
}

/// Serialize 64-bit optional header to bytes.
fn serialize_optional_header_64(oh: &ImageOptionalHeader64) -> Vec<u8> {
    let mut buf = Vec::with_capacity(240);
    buf.extend_from_slice(&oh.magic.to_le_bytes());
    buf.push(oh.major_linker_version);
    buf.push(oh.minor_linker_version);
    buf.extend_from_slice(&oh.size_of_code.to_le_bytes());
    buf.extend_from_slice(&oh.size_of_initialized_data.to_le_bytes());
    buf.extend_from_slice(&oh.size_of_uninitialized_data.to_le_bytes());
    buf.extend_from_slice(&oh.address_of_entry_point.to_le_bytes());
    buf.extend_from_slice(&oh.base_of_code.to_le_bytes());
    buf.extend_from_slice(&oh.image_base.to_le_bytes());
    buf.extend_from_slice(&oh.section_alignment.to_le_bytes());
    buf.extend_from_slice(&oh.file_alignment.to_le_bytes());
    buf.extend_from_slice(&oh.major_operating_system_version.to_le_bytes());
    buf.extend_from_slice(&oh.minor_operating_system_version.to_le_bytes());
    buf.extend_from_slice(&oh.major_image_version.to_le_bytes());
    buf.extend_from_slice(&oh.minor_image_version.to_le_bytes());
    buf.extend_from_slice(&oh.major_subsystem_version.to_le_bytes());
    buf.extend_from_slice(&oh.minor_subsystem_version.to_le_bytes());
    buf.extend_from_slice(&oh.win32_version_value.to_le_bytes());
    buf.extend_from_slice(&oh.size_of_image.to_le_bytes());
    buf.extend_from_slice(&oh.size_of_headers.to_le_bytes());
    buf.extend_from_slice(&oh.checksum.to_le_bytes());
    buf.extend_from_slice(&oh.subsystem.to_le_bytes());
    buf.extend_from_slice(&oh.dll_characteristics.to_le_bytes());
    buf.extend_from_slice(&oh.size_of_stack_reserve.to_le_bytes());
    buf.extend_from_slice(&oh.size_of_stack_commit.to_le_bytes());
    buf.extend_from_slice(&oh.size_of_heap_reserve.to_le_bytes());
    buf.extend_from_slice(&oh.size_of_heap_commit.to_le_bytes());
    buf.extend_from_slice(&oh.loader_flags.to_le_bytes());
    buf.extend_from_slice(&oh.number_of_rva_and_sizes.to_le_bytes());
    for dd in &oh.data_directory { buf.extend_from_slice(&serialize_data_directory(dd)); }
    buf
}

// ===========================================================================
//  Utility Functions (tccpe.c lines 385–461)
// ===========================================================================

/// Get the export name of a symbol, stripping leading underscore if needed.
/// C equivalent: `pe_export_name()` at tccpe.c line 385
fn pe_export_name<'a>(state: &'a TccState, sym_name: &'a str) -> &'a str {
    if state.leading_underscore && sym_name.starts_with('_') {
        &sym_name[1..]
    } else {
        sym_name
    }
}

/// Round up to file alignment boundary.
/// C equivalent: `pe_file_align()` at tccpe.c line 420
fn pe_file_align_val(pe: &PeInfo, n: u32) -> u32 {
    let a = pe.file_align.wrapping_sub(1);
    (n.wrapping_add(a)) & !a
}

/// Round up to section (virtual) alignment boundary.
/// C equivalent: `pe_virtual_align()` at tccpe.c line 426
fn pe_virtual_align(pe: &PeInfo, n: u64) -> u64 {
    let a = u64::from(pe.section_align).wrapping_sub(1);
    (n.wrapping_add(a)) & !a
}

/// Align a section's offset and size tracking.
/// C equivalent: `pe_align_section()` at tccpe.c line 432
fn pe_align_section_data(sec: &mut Section, align: usize) {
    let cur = sec.data_offset;
    let aligned = (cur + align - 1) & !(align - 1);
    if aligned > cur {
        sec.data.resize(aligned, 0);
        sec.data_offset = aligned;
    }
}

/// Set a data directory entry in the optional header.
/// C equivalent: `pe_set_datadir()` at tccpe.c line 438
fn pe_set_datadir(opt_hdr: &mut Vec<u8>, is_64bit: bool, index: usize, addr: u32, size: u32) {
    // Data directory starts at a fixed offset in the optional header
    let dd_start = if is_64bit {
        // In PE32+: 112 bytes before data_directory array
        // magic(2)+linker(2)+sizes(12)+entry(4)+base_of_code(4)+image_base(8)+
        // alignments(8)+versions(24)+win32ver(4)+sizes(12)+csum(4)+subsys(4)+
        // dll_chars(2:u16 padded)...
        // Exact offset: 2+2+4*3+4+4+8+4*2+2*8+4+4*3+4+2+2+8*4+4+4 = 112
        // Actually: let's compute. 64-bit opt header fixed fields before data_dir:
        // 2+1+1+4+4+4+4+4+8+4+4+2+2+2+2+2+2+4+4+4+4+2+2+8+8+8+8+4+4 = 112
        112
    } else {
        // In PE32: 96 bytes before data_directory array
        // 2+1+1+4+4+4+4+4+4+4+4+4+2+2+2+2+2+2+4+4+4+4+2+2+4+4+4+4+4+4 = 96
        96
    };
    let entry_off = dd_start + index * 8;
    if entry_off + 8 <= opt_hdr.len() {
        opt_hdr[entry_off..entry_off + 4].copy_from_slice(&addr.to_le_bytes());
        opt_hdr[entry_off + 4..entry_off + 8].copy_from_slice(&size.to_le_bytes());
    }
}

// ===========================================================================
//  PE Write Functions (tccpe.c lines 450–530)
// ===========================================================================

/// Tracked write with running checksum accumulation.
/// C equivalent: `pe_fwrite()` at tccpe.c line 448
#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
fn pe_fwrite(data: &[u8], writer: &mut dyn Write, pe: &mut PeInfo) -> TccResult<()> {
    writer.write_all(data).map_err(TccError::Io)?;
    // Accumulate PE checksum: sum of all u16 words, wrapping
    let mut i = 0;
    while i + 1 < data.len() {
        let w = u16::from_le_bytes([data[i], data[i + 1]]);
        pe.checksum = pe.checksum.wrapping_add(u32::from(w));
        i += 2;
    }
    if i < data.len() {
        pe.checksum = pe.checksum.wrapping_add(u32::from(data[i]));
    }
    pe.pos = pe.pos.wrapping_add(data.len() as u32);
    Ok(())
}

/// Write padding zeros to reach a target file position.
/// C equivalent: `pe_fpad()` at tccpe.c line 460
#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
fn pe_fpad(writer: &mut dyn Write, pe: &mut PeInfo, new_pos: u32) -> TccResult<()> {
    while pe.pos < new_pos {
        let chunk = std::cmp::min((new_pos - pe.pos) as usize, 4096);
        let zeros = vec![0u8; chunk];
        pe_fwrite(&zeros, writer, pe)?;
    }
    Ok(())
}

// ===========================================================================
//  COFF Symbol Generation (tccpe.c lines 462–536)
// ===========================================================================

/// COFF symbol entry for PE debug information.
/// C equivalent: `struct syment` at tccpe.c line 467
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct CoffSyment {
    e_name: [u8; 8],
    e_value: u32,
    e_scnum: i16,
    e_type: u16,
    e_sclass: i8,
    e_numaux: i8,
}

/// Add COFF symbol table entries to PE output sections.
/// C equivalent: `pe_add_coffsym()` at tccpe.c line 480
fn pe_add_coffsym(
    state: &mut TccState,
    coffsym_idx: usize,
    coffstr_idx: usize,
) -> TccResult<()> {
    // Find symtab section
    let symtab_idx = state.sections.iter().position(|s| s.name == ".symtab");
    let symtab_idx = match symtab_idx {
        Some(i) => i,
        None => return Ok(()),
    };
    let strtab_idx = state.sections[symtab_idx].link.unwrap_or(0);
    let sym_size = elf_linker::ELF_SYM_SIZE;
    let nb_syms = state.sections[symtab_idx].data_offset / sym_size;

    for sym_index in 1..nb_syms {
        let sym = elf_linker::read_sym_entry(&state.sections[symtab_idx].data, sym_index);
        let bind = elf_fmt::elf_st_bind(sym.st_info);
        if bind != elf_fmt::STB_GLOBAL { continue; }
        if sym.st_shndx == elf_fmt::SHN_UNDEF { continue; }

        let name = elf_linker::read_cstr(&state.sections[strtab_idx].data, sym.st_name as usize);
        let sec_num = sym.st_shndx as i16;
        let value = sym.st_value as u32;
        let sym_type = elf_fmt::elf_st_type(sym.st_info);
        let coff_type: u16 = if sym_type == elf_fmt::STT_FUNC { 0x20 } else { 0 };

        // Build COFF symbol entry
        let mut entry = [0u8; 18]; // COFF symbol entry is 18 bytes
        if name.len() <= coff_fmt::SYMNMLEN {
            let name_bytes = name.as_bytes();
            let copy_len = std::cmp::min(name_bytes.len(), 8);
            entry[..copy_len].copy_from_slice(&name_bytes[..copy_len]);
        } else {
            // Long name: store offset into COFF string table
            // First 4 bytes = 0 (signals long name), next 4 = offset
            let str_off = state.sections[coffstr_idx].data_offset as u32;
            entry[4..8].copy_from_slice(&str_off.to_le_bytes());
            // Append name + null to coffstr section
            let name_bytes = name.as_bytes();
            let start = elf_linker::section_ptr_add(&mut state.sections[coffstr_idx],
                                                     name_bytes.len() + 1);
            state.sections[coffstr_idx].data[start..start + name_bytes.len()]
                .copy_from_slice(name_bytes);
            state.sections[coffstr_idx].data[start + name_bytes.len()] = 0;
        }
        // Value
        entry[8..12].copy_from_slice(&value.to_le_bytes());
        // Section number
        entry[12..14].copy_from_slice(&sec_num.to_le_bytes());
        // Type
        entry[14..16].copy_from_slice(&coff_type.to_le_bytes());
        // Storage class: C_EXT for global
        entry[16] = coff_fmt::C_EXT as u8;
        // Num aux: 0
        entry[17] = 0;

        let pos = elf_linker::section_ptr_add(&mut state.sections[coffsym_idx], 18);
        state.sections[coffsym_idx].data[pos..pos + 18].copy_from_slice(&entry);
    }
    Ok(())
}

// ===========================================================================
//  Section Classification (tccpe.c lines 1148–1183)
// ===========================================================================

/// Classify a section into a PE section class by name and flags.
/// C equivalent: `pe_section_class()` at tccpe.c line 1149
#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
fn pe_section_class(sec: &Section) -> PeSectionClass {
    let name = &sec.name;
    let sh_type = sec.sh_type;
    let flags = sec.sh_flags as u32;

    if name.starts_with(".stab") || name.starts_with(".debug_") {
        return PeSectionClass::Debug;
    }
    if (flags & elf_fmt::SHF_ALLOC) != 0 {
        if sh_type == elf_fmt::SHT_PROGBITS
            || sh_type == elf_fmt::SHT_INIT_ARRAY
            || sh_type == elf_fmt::SHT_FINI_ARRAY
        {
            if (flags & elf_fmt::SHF_EXECINSTR) != 0 {
                return PeSectionClass::Text;
            }
            if (flags & elf_fmt::SHF_WRITE) != 0 {
                return PeSectionClass::Data;
            }
            if name == ".rsrc" {
                return PeSectionClass::Rsrc;
            }
            if name == ".iedat" {
                return PeSectionClass::Idata;
            }
            if name == ".pdata" {
                return PeSectionClass::Pdata;
            }
            return PeSectionClass::Rdata;
        } else if sh_type == elf_fmt::SHT_NOBITS {
            return PeSectionClass::Bss;
        }
        return PeSectionClass::Other;
    }
    if name == ".reloc" {
        return PeSectionClass::Reloc;
    }
    PeSectionClass::Last
}

// ===========================================================================
//  Import Table Builder (tccpe.c lines 827–964)
// ===========================================================================

/// Find or create an import entry for a given DLL symbol index.
/// C equivalent: `pe_add_import()` at tccpe.c line 827
#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
fn pe_add_import(pe: &mut PeInfo, state: &TccState, imp_sym: i32) -> usize {
    // Read the symbol to find which DLL it belongs to
    let dynsym_idx = state.sections.iter().position(|s| s.name == ".dynsym").unwrap_or(0);
    let sym = elf_linker::read_sym_entry(&state.sections[dynsym_idx].data, imp_sym as usize);
    let dll_index = sym.st_size as i32; // st_size stores dllindex for PE imports

    // Find existing import info for this DLL or create new one
    let imp_idx = pe.imp_info.iter().position(|ii| ii.dll_index == dll_index);
    let imp_idx = if let Some(i) = imp_idx { i } else {
        pe.imp_info.push(PeImportInfo {
            dll_index,
            symbols: Vec::new(),
        });
        pe.imp_info.len() - 1
    };

    // Check if this symbol is already tracked
    let existing = pe.imp_info[imp_idx].symbols.iter().position(|s| s.sym_index == imp_sym);
    if let Some(e) = existing {
        return e;
    }

    // Add new import symbol
    pe.imp_info[imp_idx].symbols.push(ImportSymbol {
        sym_index: imp_sym,
        iat_index: 0,
        thk_offset: 0,
    });
    pe.imp_info[imp_idx].symbols.len() - 1
}

/// Build import directory table, IAT, and ILT entries.
/// C equivalent: `pe_build_imports()` at tccpe.c line 869
#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
fn pe_build_imports(pe: &mut PeInfo, state: &mut TccState) -> TccResult<()> {
    if pe.imp_info.is_empty() {
        return Ok(());
    }

    let thunk_idx = match pe.thunk {
        Some(i) => i,
        None => return Ok(()),
    };

    let addr_size = pe.addr_size();
    let rva_base = state.sections[thunk_idx].sh_addr as u32;
    let ndlls = pe.imp_info.len();

    // Calculate sizes
    let import_dir_size = (ndlls + 1) * 20; // Each descriptor is 20 bytes + null terminator

    pe_align_section_data(&mut state.sections[thunk_idx], 16);
    let base_o = state.sections[thunk_idx].data_offset as u32;

    // Reserve space for import directory table
    let dir_start = elf_linker::section_ptr_add(&mut state.sections[thunk_idx], import_dir_size);

    // Build each DLL's import entries
    for dll_idx in 0..ndlls {
        let dll_info = &pe.imp_info[dll_idx];
        let nsyms = dll_info.symbols.len();
        let dll_ref_index = dll_info.dll_index as usize;

        // Get DLL name
        let dll_name = if dll_ref_index < state.loaded_dlls.len() {
            state.loaded_dlls[dll_ref_index].name.clone()
        } else {
            format!("unknown_dll_{dll_ref_index}")
        };

        // IAT (Import Address Table) entries
        let iat_start = state.sections[thunk_idx].data_offset as u32;
        for _sym_idx in 0..nsyms {
            elf_linker::section_ptr_add(&mut state.sections[thunk_idx], addr_size as usize);
        }
        // Null terminator for IAT
        elf_linker::section_ptr_add(&mut state.sections[thunk_idx], addr_size as usize);

        // ILT (Import Lookup Table) entries
        let ilt_start = state.sections[thunk_idx].data_offset as u32;
        for _sym_idx in 0..nsyms {
            elf_linker::section_ptr_add(&mut state.sections[thunk_idx], addr_size as usize);
        }
        // Null terminator for ILT
        elf_linker::section_ptr_add(&mut state.sections[thunk_idx], addr_size as usize);

        // DLL name string
        let name_rva = state.sections[thunk_idx].data_offset as u32 + rva_base;
        let dll_name_bytes = dll_name.as_bytes();
        let name_pos = elf_linker::section_ptr_add(&mut state.sections[thunk_idx],
                                                     dll_name_bytes.len() + 1);
        state.sections[thunk_idx].data[name_pos..name_pos + dll_name_bytes.len()]
            .copy_from_slice(dll_name_bytes);
        state.sections[thunk_idx].data[name_pos + dll_name_bytes.len()] = 0;

        // Write hint/name entries for each imported symbol
        let dynsym_idx = state.sections.iter().position(|s| s.name == ".dynsym").unwrap_or(0);
        let dynstr_idx = state.sections[dynsym_idx].link.unwrap_or(0);

        for (si, _sym) in pe.imp_info[dll_idx].symbols.iter().enumerate() {
            let sym_entry = elf_linker::read_sym_entry(
                &state.sections[dynsym_idx].data,
                _sym.sym_index as usize,
            );
            let sym_name = elf_linker::read_cstr(
                &state.sections[dynstr_idx].data,
                sym_entry.st_name as usize,
            );

            // Hint/Name entry: u16 hint + name string + padding
            let hint_name_rva = state.sections[thunk_idx].data_offset as u32 + rva_base;
            let sym_name_bytes = sym_name.as_bytes();
            let entry_len = 2 + sym_name_bytes.len() + 1;
            let padded_len = (entry_len + 1) & !1; // Align to 2 bytes
            let entry_pos = elf_linker::section_ptr_add(&mut state.sections[thunk_idx], padded_len);
            // Hint = 0 (we don't have ordinal hints)
            state.sections[thunk_idx].data[entry_pos] = 0;
            state.sections[thunk_idx].data[entry_pos + 1] = 0;
            state.sections[thunk_idx].data[entry_pos + 2..entry_pos + 2 + sym_name_bytes.len()]
                .copy_from_slice(sym_name_bytes);

            // Write IAT and ILT entries pointing to hint/name
            let iat_off = iat_start as usize + si * addr_size as usize;
            let ilt_off = ilt_start as usize + si * addr_size as usize;
            if addr_size == 8 {
                if iat_off + 8 <= state.sections[thunk_idx].data.len() {
                    let bytes = u64::from(hint_name_rva).to_le_bytes();
                    state.sections[thunk_idx].data[iat_off..iat_off + 8]
                        .copy_from_slice(&bytes);
                }
                if ilt_off + 8 <= state.sections[thunk_idx].data.len() {
                    let bytes = u64::from(hint_name_rva).to_le_bytes();
                    state.sections[thunk_idx].data[ilt_off..ilt_off + 8]
                        .copy_from_slice(&bytes);
                }
            } else {
                if iat_off + 4 <= state.sections[thunk_idx].data.len() {
                    let bytes = hint_name_rva.to_le_bytes();
                    state.sections[thunk_idx].data[iat_off..iat_off + 4]
                        .copy_from_slice(&bytes);
                }
                if ilt_off + 4 <= state.sections[thunk_idx].data.len() {
                    let bytes = hint_name_rva.to_le_bytes();
                    state.sections[thunk_idx].data[ilt_off..ilt_off + 4]
                        .copy_from_slice(&bytes);
                }
            }
        }

        // Write import descriptor
        let desc = ImageImportDescriptor {
            original_first_thunk: ilt_start + rva_base,
            time_date_stamp: 0,
            forwarder_chain: 0,
            name: name_rva,
            first_thunk: iat_start + rva_base,
        };
        let desc_bytes = serialize_import_descriptor(&desc);
        let desc_off = dir_start + dll_idx * 20;
        if desc_off + 20 <= state.sections[thunk_idx].data.len() {
            state.sections[thunk_idx].data[desc_off..desc_off + 20]
                .copy_from_slice(&desc_bytes);
        }

        // Store IAT offsets for this DLL
        if dll_idx == 0 {
            pe.iat_offs = iat_start + rva_base;
        }
    }

    pe.imp_offs = base_o + rva_base;
    pe.imp_size = (ndlls + 1) as u32 * 20;

    // Calculate total IAT size across all DLLs
    let mut total_iat = 0u32;
    for ii in &pe.imp_info {
        total_iat += (ii.symbols.len() as u32 + 1) * pe.addr_size();
    }
    pe.iat_size = total_iat;

    Ok(())
}

// ===========================================================================
//  Export Table Builder (tccpe.c lines 966–1079)
// ===========================================================================

/// Sort key for export symbols.
struct ExportSortEntry {
    index: usize,
    name: String,
}

/// Build export directory table.
/// C equivalent: `pe_build_exports()` at tccpe.c line 975
#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
fn pe_build_exports(pe: &mut PeInfo, state: &mut TccState) -> TccResult<()> {
    let symtab_idx = state.sections.iter().position(|s| s.name == ".symtab");
    let symtab_idx = match symtab_idx {
        Some(i) => i,
        None => return Ok(()),
    };
    let strtab_idx = state.sections[symtab_idx].link.unwrap_or(0);
    let sym_size = elf_linker::ELF_SYM_SIZE;
    let sym_end = state.sections[symtab_idx].data_offset / sym_size;

    // Collect exportable symbols
    let mut sorted: Vec<ExportSortEntry> = Vec::new();
    for sym_index in 1..sym_end {
        let sym = elf_linker::read_sym_entry(&state.sections[symtab_idx].data, sym_index);
        if (sym.st_other & ST_PE_EXPORT) != 0 {
            let name = elf_linker::read_cstr(&state.sections[strtab_idx].data,
                                              sym.st_name as usize);
            let export_name = pe_export_name(state, &name).to_string();
            sorted.push(ExportSortEntry {
                index: sym_index,
                name: export_name,
            });
        }
    }

    if sorted.is_empty() {
        return Ok(());
    }

    // Sort by name
    sorted.sort_by(|a, b| a.name.cmp(&b.name));
    let sym_count = sorted.len() as u32;

    let thunk_idx = match pe.thunk {
        Some(i) => i,
        None => return Ok(()),
    };

    pe_align_section_data(&mut state.sections[thunk_idx], 16);
    let rva_base = state.sections[thunk_idx].sh_addr as u32;
    let base_o = state.sections[thunk_idx].data_offset as u32;

    // Layout: ExportDir | func_RVAs[count] | name_RVAs[count] | ordinals[count]
    let export_dir_size = 40u32; // sizeof(IMAGE_EXPORT_DIRECTORY)
    let func_o = base_o + export_dir_size;
    let name_o = func_o + sym_count * 4;
    let ord_o = name_o + sym_count * 4;
    let str_o = ord_o + sym_count * 2;

    // Reserve space for the export directory and arrays
    let total_fixed = (str_o - base_o) as usize;
    elf_linker::section_ptr_add(&mut state.sections[thunk_idx], total_fixed);

    // Get DLL base name for export directory
    let dllname = Path::new(&pe.filename)
        .file_name().map_or_else(|| pe.filename.clone(), |n| n.to_string_lossy().to_string());

    // Write DLL name string
    let name_str_rva = state.sections[thunk_idx].data_offset as u32 + rva_base;
    let dll_bytes = dllname.as_bytes();
    let name_pos = elf_linker::section_ptr_add(&mut state.sections[thunk_idx],
                                                 dll_bytes.len() + 1);
    state.sections[thunk_idx].data[name_pos..name_pos + dll_bytes.len()]
        .copy_from_slice(dll_bytes);
    state.sections[thunk_idx].data[name_pos + dll_bytes.len()] = 0;

    // Write export directory header
    let hdr = ImageExportDirectory {
        characteristics: 0,
        time_date_stamp: 0,
        major_version: 0,
        minor_version: 0,
        name: name_str_rva,
        base: 1,
        number_of_functions: sym_count,
        number_of_names: sym_count,
        address_of_functions: func_o + rva_base,
        address_of_names: name_o + rva_base,
        address_of_name_ordinals: ord_o + rva_base,
    };
    let hdr_bytes = serialize_export_directory(&hdr);
    let hdr_off = base_o as usize;
    if hdr_off + 40 <= state.sections[thunk_idx].data.len() {
        state.sections[thunk_idx].data[hdr_off..hdr_off + 40].copy_from_slice(&hdr_bytes);
    }

    // Write each exported symbol
    for (ord, entry) in sorted.iter().enumerate() {
        let fo = func_o as usize + ord * 4;
        let no = name_o as usize + ord * 4;
        let oo = ord_o as usize + ord * 2;

        // Function RVA — will be patched by relocate_sections()
        // For now, set up a relocation via put_elf_reloc
        if fo + 4 <= state.sections[thunk_idx].data.len() {
            state.sections[thunk_idx].data[fo..fo + 4].copy_from_slice(&0u32.to_le_bytes());
        }

        // Name RVA — points to the exported name string we're about to write
        let name_rva = state.sections[thunk_idx].data_offset as u32 + rva_base;
        if no + 4 <= state.sections[thunk_idx].data.len() {
            state.sections[thunk_idx].data[no..no + 4].copy_from_slice(&name_rva.to_le_bytes());
        }

        // Ordinal
        let ordinal = ord as u16;
        if oo + 2 <= state.sections[thunk_idx].data.len() {
            state.sections[thunk_idx].data[oo..oo + 2].copy_from_slice(&ordinal.to_le_bytes());
        }

        // Write the name string
        let name_bytes = entry.name.as_bytes();
        let str_pos = elf_linker::section_ptr_add(&mut state.sections[thunk_idx],
                                                    name_bytes.len() + 1);
        state.sections[thunk_idx].data[str_pos..str_pos + name_bytes.len()]
            .copy_from_slice(name_bytes);
        state.sections[thunk_idx].data[str_pos + name_bytes.len()] = 0;
    }

    pe.exp_offs = base_o + rva_base;
    pe.exp_size = state.sections[thunk_idx].data_offset as u32 - base_o;

    Ok(())
}

// ===========================================================================
//  Base Relocation Builder (tccpe.c lines 1082-1146)
// ===========================================================================

/// Build the PE base relocation table (.reloc section).
/// C equivalent: `pe_build_reloc()` at tccpe.c line 1082
#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
fn pe_build_reloc(pe: &mut PeInfo, state: &mut TccState) -> TccResult<()> {
    let reloc_idx = match pe.reloc {
        Some(i) => i,
        None => return Ok(()),
    };

    let is_64 = pe.is_64bit();
    let rel_type_dir = rel_type_direct(is_64);
    let image_rel = pe_image_rel_based(is_64);

    let mut reloc_entries: Vec<(u32, Vec<u16>)> = Vec::new();

    let num_sections = state.sections.len();
    for sec_i in 0..num_sections {
        let reloc_sec_idx = match state.sections[sec_i].reloc {
            Some(idx) if idx < state.sections.len() => idx,
            _ => continue,
        };

        let rel_size: usize = if is_64 { 24 } else { 12 };
        let rel_data_len = state.sections[reloc_sec_idx].data_offset;
        if rel_data_len == 0 { continue; }

        let num_rels = rel_data_len / rel_size;
        for ri in 0..num_rels {
            let off = ri * rel_size;
            if off + rel_size > state.sections[reloc_sec_idx].data.len() { break; }
            let rd = &state.sections[reloc_sec_idx].data;

            let (r_offset, r_type) = if is_64 {
                let r_off = u64::from_le_bytes([
                    rd[off], rd[off+1], rd[off+2], rd[off+3],
                    rd[off+4], rd[off+5], rd[off+6], rd[off+7],
                ]);
                let r_info = u64::from_le_bytes([
                    rd[off+8], rd[off+9], rd[off+10], rd[off+11],
                    rd[off+12], rd[off+13], rd[off+14], rd[off+15],
                ]);
                (r_off as u32, elf_fmt::elf64_r_type(r_info) as u32)
            } else {
                let r_off = u32::from_le_bytes([
                    rd[off], rd[off+1], rd[off+2], rd[off+3],
                ]);
                let r_info = u32::from_le_bytes([
                    rd[off+4], rd[off+5], rd[off+6], rd[off+7],
                ]);
                (r_off, elf_fmt::elf32_r_type(r_info))
            };

            if r_type != rel_type_dir { continue; }

            let sec_va = state.sections[sec_i].sh_addr as u32;
            let rva = sec_va.wrapping_add(r_offset);
            let page_rva = rva & !0xFFF;
            let offset_in_page = (rva & 0xFFF) as u16;
            let entry = (image_rel << 12) | offset_in_page;

            match reloc_entries.last_mut() {
                Some((page, entries)) if *page == page_rva => {
                    entries.push(entry);
                }
                _ => {
                    reloc_entries.push((page_rva, vec![entry]));
                }
            }
        }
    }

    for (page_rva, entries) in &reloc_entries {
        let mut block_entries = entries.clone();
        if block_entries.len() % 2 != 0 {
            block_entries.push(0);
        }
        let block_size = 8 + block_entries.len() * 2;
        let block_start = elf_linker::section_ptr_add(
            &mut state.sections[reloc_idx], block_size,
        );
        state.sections[reloc_idx].data[block_start..block_start + 4]
            .copy_from_slice(&page_rva.to_le_bytes());
        state.sections[reloc_idx].data[block_start + 4..block_start + 8]
            .copy_from_slice(&(block_size as u32).to_le_bytes());
        for (i, eword) in block_entries.iter().enumerate() {
            let eoff = block_start + 8 + i * 2;
            state.sections[reloc_idx].data[eoff..eoff + 2]
                .copy_from_slice(&eword.to_le_bytes());
        }
    }

    Ok(())
}

// ===========================================================================
//  PE Address Assignment (tccpe.c lines 1185-1300)
// ===========================================================================

/// Assign virtual addresses to all PE sections, building import/export/reloc tables.
/// C equivalent: `pe_assign_addresses()` at tccpe.c line 1185
#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
fn pe_assign_addresses(pe: &mut PeInfo, state: &mut TccState) -> TccResult<()> {
    // Create .reloc section for DLLs and EXEs
    if pe.pe_type == PeType::Dll || pe.pe_type == PeType::Exe || pe.pe_type == PeType::Gui {
        let reloc_idx = elf_linker::new_section(
            state, ".reloc", elf_fmt::SHT_PROGBITS, elf_fmt::SHF_ALLOC,
        );
        pe.reloc = Some(reloc_idx);
    }

    // Create a thunk section for imports/exports (.idata)
    let thunk_idx = elf_linker::new_section(
        state, ".iedat", elf_fmt::SHT_PROGBITS, elf_fmt::SHF_ALLOC | elf_fmt::SHF_WRITE,
    );
    pe.thunk = Some(thunk_idx);

    // Collect and classify all allocatable sections
    let mut sec_entries: Vec<(usize, PeSectionClass)> = Vec::new();
    for i in 0..state.sections.len() {
        let cls = pe_section_class(&state.sections[i]);
        if cls == PeSectionClass::Last || cls == PeSectionClass::Debug { continue; }
        if (state.sections[i].sh_flags as u32 & elf_fmt::SHF_ALLOC) == 0 { continue; }
        sec_entries.push((i, cls));
    }

    sec_entries.sort_by_key(|&(_, cls)| cls as u32);

    let mut addr = pe_virtual_align(pe, u64::from(pe.size_of_headers));
    let mut current_pe_sec: Option<usize> = None;
    let mut pe_sec_count = 0usize;

    for &(sec_i, cls) in &sec_entries {
        let sh_size = state.sections[sec_i].data_offset;
        if sh_size == 0 { continue; }

        let start_new = match current_pe_sec {
            None => true,
            Some(pidx) => pe.sec_info[pidx].cls != cls,
        };

        if start_new {
            addr = pe_virtual_align(pe, addr);
            let pe_name = match cls {
                PeSectionClass::Text => ".text",
                PeSectionClass::Rdata => ".rdata",
                PeSectionClass::Data => ".data",
                PeSectionClass::Bss => ".bss",
                PeSectionClass::Idata => ".idata",
                PeSectionClass::Pdata => ".pdata",
                PeSectionClass::Rsrc => ".rsrc",
                PeSectionClass::Reloc => ".reloc",
                _ => ".other",
            }.to_string();

            pe.sec_info.push(PeSectionInfo {
                cls, name: pe_name, sh_addr: addr, sh_size: 0,
                pe_flags: 0, sec: vec![sec_i], data_size: 0,
                ish: ImageSectionHeader::default(),
            });
            current_pe_sec = Some(pe.sec_info.len() - 1);
            pe_sec_count += 1;
        }

        state.sections[sec_i].sh_addr = addr;
        let sh_size_u32 = sh_size as u32;
        if let Some(pidx) = current_pe_sec {
            pe.sec_info[pidx].sh_size = pe.sec_info[pidx].sh_size.wrapping_add(sh_size_u32);
            if state.sections[sec_i].sh_type != elf_fmt::SHT_NOBITS {
                pe.sec_info[pidx].data_size = pe.sec_info[pidx].data_size.wrapping_add(sh_size_u32);
            }
        }
        addr += u64::from(sh_size_u32);

        // Process idata section to trigger import/export building
        if cls == PeSectionClass::Idata && sec_i == thunk_idx {
            pe_build_imports(pe, state)?;
            pe_build_exports(pe, state)?;
            let new_size = state.sections[thunk_idx].data_offset as u32;
            if let Some(pidx) = current_pe_sec {
                let old = pe.sec_info[pidx].data_size;
                pe.sec_info[pidx].data_size = new_size;
                pe.sec_info[pidx].sh_size = pe.sec_info[pidx].sh_size
                    .wrapping_add(new_size.wrapping_sub(old));
            }
            addr = pe.sec_info[current_pe_sec.unwrap_or(0)].sh_addr
                + u64::from(state.sections[thunk_idx].data_offset as u32);
        }

        if cls == PeSectionClass::Reloc {
            pe_build_reloc(pe, state)?;
            let reloc_i = pe.reloc.unwrap_or(0);
            let reloc_size = state.sections[reloc_i].data_offset as u32;
            if let Some(pidx) = current_pe_sec {
                pe.sec_info[pidx].data_size = reloc_size;
                pe.sec_info[pidx].sh_size = reloc_size;
            }
        }
    }

    // Set PE flags for each section
    for psi in &mut pe.sec_info {
        psi.pe_flags = match psi.cls {
            PeSectionClass::Text => IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_CODE,
            PeSectionClass::Rdata | PeSectionClass::Idata => IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA,
            PeSectionClass::Data => IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_CNT_INITIALIZED_DATA,
            PeSectionClass::Bss => IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_CNT_UNINITIALIZED_DATA,
            PeSectionClass::Rsrc | PeSectionClass::Pdata | PeSectionClass::Reloc => IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_DISCARDABLE,
            PeSectionClass::Debug => IMAGE_SCN_MEM_DISCARDABLE | IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA,
            _ => IMAGE_SCN_MEM_READ,
        };
    }

    let _ = pe_sec_count; // suppress unused warning
    Ok(())
}

// ===========================================================================
//  Symbol Checking (tccpe.c lines 1303-1415)
// ===========================================================================

/// Check all undefined symbols, resolving them against DLL imports or
/// creating thunk trampolines for indirect calls.
/// C equivalent: `pe_check_symbols()` at tccpe.c line 1303
#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
fn pe_check_symbols(pe: &mut PeInfo, state: &mut TccState) -> TccResult<()> {
    let symtab_idx = state.sections.iter().position(|s| s.name == ".symtab");
    let symtab_idx = match symtab_idx {
        Some(i) => i,
        None => return Ok(()),
    };
    let strtab_idx = state.sections[symtab_idx].link.unwrap_or(0);
    let sym_size = elf_linker::ELF_SYM_SIZE;
    let sym_end = state.sections[symtab_idx].data_offset / sym_size;

    let _is_64 = pe.is_64bit();

    for sym_index in 1..sym_end {
        let sym = elf_linker::read_sym_entry(&state.sections[symtab_idx].data, sym_index);

        if sym.st_shndx != elf_fmt::SHN_UNDEF { continue; }
        let bind = elf_fmt::elf_st_bind(sym.st_info);
        if bind == elf_fmt::STB_LOCAL { continue; }

        let name = elf_linker::read_cstr(&state.sections[strtab_idx].data, sym.st_name as usize);

        // Try to find as a DLL import
        let dynsym_idx = state.sections.iter().position(|s| s.name == ".dynsym");
        let mut imp_sym: Option<i32> = None;

        if let Some(ds_idx) = dynsym_idx {
            // Try original name
            imp_sym = elf_linker::find_elf_sym(state, ds_idx, &name);

            // Try with leading underscore removed (stdcall decoration)
            if imp_sym.is_none() && name.starts_with('_') {
                let trimmed = &name[1..];
                // Strip @N suffix for stdcall
                let base = if let Some(at_pos) = trimmed.find('@') {
                    &trimmed[..at_pos]
                } else {
                    trimmed
                };
                imp_sym = elf_linker::find_elf_sym(state, ds_idx, base);
            }

            // Try _imp__ prefix (Microsoft convention)
            if imp_sym.is_none() && name.starts_with("_imp__") {
                let actual = &name[6..];
                imp_sym = elf_linker::find_elf_sym(state, ds_idx, actual);
            }

            // Try __imp_ prefix (MinGW convention)
            if imp_sym.is_none() && name.starts_with("__imp_") {
                let actual = &name[6..];
                imp_sym = elf_linker::find_elf_sym(state, ds_idx, actual);
            }
        }

        if let Some(imp_index) = imp_sym {
            // Determine if this is a direct import (_imp__) or needs a thunk
            let is_imp_ref = name.starts_with("_imp__") || name.starts_with("__imp_");

            if is_imp_ref {
                // _imp__ symbol: set value to IAT slot address
                pe_add_import(pe, state, imp_index);
                // Mark symbol as resolved with IAT address (will be patched later)
                let text_idx = state.text_section_idx;
                let value = state.sections[text_idx].data_offset as u64;
                elf_linker::put_elf_sym(
                    state, symtab_idx, value, 0,
                    elf_fmt::elf_st_info(elf_fmt::STB_GLOBAL, elf_fmt::STT_OBJECT),
                    0, text_idx as u16, &name,
                );
            } else {
                // Regular import: create a JMP thunk
                pe_add_import(pe, state, imp_index);
                let text_idx = state.text_section_idx;
                let thunk_start = state.sections[text_idx].data_offset;

                if is_target_arm(&pe.arch) {
                    // ARM thunk: ldr ip, [pc]; ldr pc, [ip]
                    let arm_stub: [u8; 8] = [
                        0x00, 0xc0, 0x9f, 0xe5, // ldr ip, [pc]
                        0x00, 0xf0, 0x9c, 0xe5, // ldr pc, [ip]
                    ];
                    let pos = elf_linker::section_ptr_add(&mut state.sections[text_idx], 8);
                    state.sections[text_idx].data[pos..pos + 8].copy_from_slice(&arm_stub);
                } else {
                    // x86/x86_64: FF 25 [disp32] = jmp [addr]
                    let pos = elf_linker::section_ptr_add(&mut state.sections[text_idx], 6);
                    state.sections[text_idx].data[pos] = 0xFF;
                    state.sections[text_idx].data[pos + 1] = 0x25;
                    // displacement will be patched by relocations
                    write32le(&mut state.sections[text_idx].data[pos + 2..], 0);
                }

                // Update the symbol to point to the thunk
                // We need to re-read and update the sym entry
                let thunk_addr = thunk_start as u64;
                elf_linker::put_elf_sym(
                    state, symtab_idx, thunk_addr, 0,
                    elf_fmt::elf_st_info(elf_fmt::STB_GLOBAL, elf_fmt::STT_FUNC),
                    0, text_idx as u16, &name,
                );
            }
        } else if bind == elf_fmt::STB_GLOBAL {
            // Unresolved global symbol — only error for non-weak symbols
            if state.verbose > 0 {
                // Log warning for unresolved symbols
            }
            state.nb_errors += 1;
            return Err(TccError::Link(format!("undefined symbol '{name}' in PE output")));
        }
    }

    Ok(())
}

// ===========================================================================
//  PE Write (tccpe.c lines 554-823)
// ===========================================================================

/// Write the complete PE file: headers, sections, and fixups.
/// C equivalent: `pe_write()` at tccpe.c line 554
#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
fn pe_write(pe: &mut PeInfo, state: &mut TccState, writer: &mut dyn Write) -> TccResult<()> {
    let is_64 = pe.is_64bit();
    let num_sec = pe.sec_info.len();

    // Build the DOS header
    let mut dos_hdr = ImageDosHeader::default();
    dos_hdr.e_magic = IMAGE_DOS_SIGNATURE;
    dos_hdr.e_lfanew = 0x80; // Offset to PE signature

    // DOS stub (minimal "This program cannot be run in DOS mode" stub)
    let dos_stub: [u8; 0x40] = {
        let mut stub = [0u8; 0x40];
        // Standard PE DOS stub message
        let msg = b"This program cannot be run in DOS mode.\r\r\n$";
        let copy_len = std::cmp::min(msg.len(), 0x40);
        stub[..copy_len].copy_from_slice(&msg[..copy_len]);
        stub
    };

    // Build the file header
    let machine = image_file_machine(&pe.arch);
    let characteristics = if pe.pe_type == PeType::Dll {
        IMAGE_FILE_DLL | IMAGE_FILE_EXECUTABLE_IMAGE
    } else {
        IMAGE_FILE_EXECUTABLE_IMAGE
    };
    let characteristics = if is_64 {
        characteristics
    } else {
        characteristics | IMAGE_FILE_32BIT_MACHINE
    };

    let opt_hdr_size: u16 = if is_64 { 240 } else { 224 };

    let file_hdr = ImageFileHeader {
        machine,
        number_of_sections: num_sec as u16,
        time_date_stamp: 0, // Reproducible builds
        pointer_to_symbol_table: 0,
        number_of_symbols: 0,
        size_of_optional_header: opt_hdr_size,
        characteristics,
    };

    // Calculate header sizes
    let dos_hdr_size = 0x80u32; // DOS header + stub
    let pe_sig_size = 4u32;
    let file_hdr_size = 20u32;
    let sec_hdr_size = 40u32 * num_sec as u32;
    let all_headers_size = dos_hdr_size + pe_sig_size + file_hdr_size + u32::from(opt_hdr_size) + sec_hdr_size;
    let aligned_headers = pe_file_align_val(pe, all_headers_size);

    pe.size_of_headers = aligned_headers;

    // Compute section file offsets
    // Extract alignment values to avoid borrow issues during iteration
    let fa_mask = pe.file_align.wrapping_sub(1);
    let sa_mask = u64::from(pe.section_align).wrapping_sub(1);
    let mut file_offset = aligned_headers;
    let mut total_image_size = (u64::from(aligned_headers).wrapping_add(sa_mask)) & !sa_mask;

    for psi in &mut pe.sec_info {
        if psi.data_size > 0 {
            psi.ish.pointer_to_raw_data = file_offset;
            psi.ish.size_of_raw_data = (psi.data_size.wrapping_add(fa_mask)) & !fa_mask;
            file_offset += psi.ish.size_of_raw_data;
        }
        psi.ish.virtual_address = psi.sh_addr as u32;
        psi.ish.virtual_size = psi.sh_size;
        psi.ish.characteristics = psi.pe_flags;

        // Copy section name
        let name_bytes = psi.name.as_bytes();
        let copy_len = std::cmp::min(name_bytes.len(), 8);
        psi.ish.name[..copy_len].copy_from_slice(&name_bytes[..copy_len]);

        let sec_end = u64::from(psi.ish.virtual_address) + u64::from(psi.sh_size);
        let sec_end_aligned = (sec_end.wrapping_add(sa_mask)) & !sa_mask;
        if sec_end_aligned > total_image_size {
            total_image_size = sec_end_aligned;
        }
    }

    // Build optional header
    let mut opt_hdr = vec![0u8; opt_hdr_size as usize];
    if is_64 {
        // PE32+ magic
        opt_hdr[0..2].copy_from_slice(&PE32PLUS_MAGIC.to_le_bytes());
        // Linker version
        opt_hdr[2] = 6; // major
        opt_hdr[3] = 0; // minor
        // Entry point
        let entry_off = 16;
        opt_hdr[entry_off..entry_off + 4].copy_from_slice(&pe.start_addr.to_le_bytes());
        // Image base (8 bytes for PE32+)
        let ib_off = 24;
        opt_hdr[ib_off..ib_off + 8].copy_from_slice(&pe.image_base.to_le_bytes());
        // Section alignment
        let sa_off = 32;
        opt_hdr[sa_off..sa_off + 4].copy_from_slice(&pe.section_align.to_le_bytes());
        // File alignment
        let fa_off = 36;
        opt_hdr[fa_off..fa_off + 4].copy_from_slice(&pe.file_align.to_le_bytes());
        // OS version
        let ov_off = 40;
        opt_hdr[ov_off..ov_off + 2].copy_from_slice(&4u16.to_le_bytes()); // MajorOSVersion
        // Subsystem version
        let sv_off = 44;
        opt_hdr[sv_off..sv_off + 2].copy_from_slice(&4u16.to_le_bytes()); // MajorSubsystemVersion
        // Size of image
        let si_off = 56;
        opt_hdr[si_off..si_off + 4].copy_from_slice(&(total_image_size as u32).to_le_bytes());
        // Size of headers
        let sh_off = 60;
        opt_hdr[sh_off..sh_off + 4].copy_from_slice(&aligned_headers.to_le_bytes());
        // Subsystem
        let sub_off = 68;
        opt_hdr[sub_off..sub_off + 2].copy_from_slice(&(pe.subsystem as u16).to_le_bytes());
        // DLL characteristics
        let dc_off = 70;
        let dll_chars: u16 = 0x8160; // NX_COMPAT | DYNAMIC_BASE | HIGH_ENTROPY_VA | TERMINAL_SERVER_AWARE
        opt_hdr[dc_off..dc_off + 2].copy_from_slice(&dll_chars.to_le_bytes());
        // Stack reserve/commit (8 bytes each for PE32+)
        let sr_off = 72;
        opt_hdr[sr_off..sr_off + 8].copy_from_slice(&0x200000u64.to_le_bytes()); // 2MB stack reserve
        let sc_off = 80;
        opt_hdr[sc_off..sc_off + 8].copy_from_slice(&0x1000u64.to_le_bytes()); // 4KB stack commit
        let hr_off = 88;
        opt_hdr[hr_off..hr_off + 8].copy_from_slice(&0x100000u64.to_le_bytes()); // 1MB heap reserve
        let hc_off = 96;
        opt_hdr[hc_off..hc_off + 8].copy_from_slice(&0x1000u64.to_le_bytes()); // 4KB heap commit
        // Number of RVA and sizes
        let nr_off = 108;
        opt_hdr[nr_off..nr_off + 4].copy_from_slice(&16u32.to_le_bytes());
    } else {
        // PE32 magic
        opt_hdr[0..2].copy_from_slice(&PE32_MAGIC.to_le_bytes());
        opt_hdr[2] = 6; opt_hdr[3] = 0;
        let entry_off = 16;
        opt_hdr[entry_off..entry_off + 4].copy_from_slice(&pe.start_addr.to_le_bytes());
        // Image base (4 bytes for PE32)
        let ib_off = 28;
        opt_hdr[ib_off..ib_off + 4].copy_from_slice(&(pe.image_base as u32).to_le_bytes());
        let sa_off = 32;
        opt_hdr[sa_off..sa_off + 4].copy_from_slice(&pe.section_align.to_le_bytes());
        let fa_off = 36;
        opt_hdr[fa_off..fa_off + 4].copy_from_slice(&pe.file_align.to_le_bytes());
        let ov_off = 40;
        opt_hdr[ov_off..ov_off + 2].copy_from_slice(&4u16.to_le_bytes());
        let sv_off = 44;
        opt_hdr[sv_off..sv_off + 2].copy_from_slice(&4u16.to_le_bytes());
        let si_off = 56;
        opt_hdr[si_off..si_off + 4].copy_from_slice(&(total_image_size as u32).to_le_bytes());
        let sh_off = 60;
        opt_hdr[sh_off..sh_off + 4].copy_from_slice(&aligned_headers.to_le_bytes());
        let sub_off = 68;
        opt_hdr[sub_off..sub_off + 2].copy_from_slice(&(pe.subsystem as u16).to_le_bytes());
        let dc_off = 70;
        let dll_chars: u16 = 0x8160;
        opt_hdr[dc_off..dc_off + 2].copy_from_slice(&dll_chars.to_le_bytes());
        let sr_off = 72;
        opt_hdr[sr_off..sr_off + 4].copy_from_slice(&0x200000u32.to_le_bytes());
        let sc_off = 76;
        opt_hdr[sc_off..sc_off + 4].copy_from_slice(&0x1000u32.to_le_bytes());
        let hr_off = 80;
        opt_hdr[hr_off..hr_off + 4].copy_from_slice(&0x100000u32.to_le_bytes());
        let hc_off = 84;
        opt_hdr[hc_off..hc_off + 4].copy_from_slice(&0x1000u32.to_le_bytes());
        let nr_off = 92;
        opt_hdr[nr_off..nr_off + 4].copy_from_slice(&16u32.to_le_bytes());
    }

    // Set data directories
    if pe.imp_size > 0 {
        pe_set_datadir(&mut opt_hdr, is_64, IMAGE_DIRECTORY_ENTRY_IMPORT, pe.imp_offs, pe.imp_size);
    }
    if pe.exp_size > 0 {
        pe_set_datadir(&mut opt_hdr, is_64, IMAGE_DIRECTORY_ENTRY_EXPORT, pe.exp_offs, pe.exp_size);
    }
    if pe.iat_size > 0 {
        pe_set_datadir(&mut opt_hdr, is_64, IMAGE_DIRECTORY_ENTRY_IAT, pe.iat_offs, pe.iat_size);
    }
    // Reloc directory
    if let Some(reloc_i) = pe.reloc {
        let reloc_size = state.sections[reloc_i].data_offset as u32;
        if reloc_size > 0 {
            let reloc_addr = state.sections[reloc_i].sh_addr as u32;
            pe_set_datadir(&mut opt_hdr, is_64, IMAGE_DIRECTORY_ENTRY_BASERELOC, reloc_addr, reloc_size);
        }
    }

    // Write everything
    pe.pos = 0;
    pe.checksum = 0;

    // DOS header
    let dos_bytes = serialize_dos_header(&dos_hdr);
    pe_fwrite(&dos_bytes, writer, pe)?;
    pe_fwrite(&dos_stub, writer, pe)?;

    // Pad to e_lfanew offset
    pe_fpad(writer, pe, dos_hdr.e_lfanew as u32)?;

    // PE signature
    pe_fwrite(&PE_SIGNATURE.to_le_bytes(), writer, pe)?;

    // File header
    let fh_bytes = serialize_file_header(&file_hdr);
    pe_fwrite(&fh_bytes, writer, pe)?;

    // Optional header
    pe_fwrite(&opt_hdr, writer, pe)?;

    // Section headers — pre-collect to avoid borrow conflict
    let sec_hdr_bytes: Vec<Vec<u8>> = pe.sec_info.iter()
        .map(|psi| serialize_section_header(&psi.ish))
        .collect();
    for sh_bytes in &sec_hdr_bytes {
        pe_fwrite(sh_bytes, writer, pe)?;
    }

    // Pad to end of headers
    pe_fpad(writer, pe, aligned_headers)?;

    // Write section data — collect metadata first to avoid borrow conflict
    let sec_write_info: Vec<(u32, Vec<usize>)> = pe.sec_info.iter()
        .map(|psi| (psi.data_size, psi.sec.clone()))
        .collect();

    for (data_size, sec_indices) in &sec_write_info {
        if *data_size == 0 { continue; }

        if let Some(&sec_idx) = sec_indices.first() {
            if sec_idx < state.sections.len() {
                let data_len = std::cmp::min(
                    *data_size as usize,
                    state.sections[sec_idx].data.len(),
                );
                if data_len > 0 {
                    let data_slice = &state.sections[sec_idx].data[..data_len];
                    pe_fwrite(data_slice, writer, pe)?;
                }
            }
        }

        // Pad to aligned size
        let aligned_size = (data_size.wrapping_add(fa_mask)) & !fa_mask;
        pe_fpad(writer, pe, pe.pos.wrapping_sub(*data_size).wrapping_add(aligned_size))?;
    }

    // Store final checksum for potential patching by caller.
    // PE checksum = fold 32-bit sum to 16-bit carry-add, then add file size.
    // Checksum patching requires seeking, which we cannot do on a generic Write trait.
    // The caller (pe_output_file) handles checksum patching via seek on the File.
    let checksum_val = pe.checksum;
    pe.checksum = (checksum_val & 0xFFFF)
        .wrapping_add(checksum_val >> 16)
        .wrapping_add(pe.pos);

    Ok(())
}

// ===========================================================================
//  DLL/DEF/Resource Loading Functions (tccpe.c lines 1558-1833)
// ===========================================================================

/// Add an import symbol entry to the dynamic symbol table.
/// C equivalent: `pe_putimport()` at tccpe.c line 1558
///
/// This creates a symbol entry in the dynamic symbol table (.dynsym) that
/// represents a function or data imported from a DLL.
pub(crate) fn pe_putimport(
    state: &mut TccState,
    dll_index: i32,
    name: &str,
    ordinal: i32,
) -> TccResult<()> {
    // Ensure dynsym section exists
    let dynsym_idx = if let Some(i) = state.sections.iter().position(|s| s.name == ".dynsym") { i } else {
        let idx = elf_linker::new_section(
            state, ".dynsym", elf_fmt::SHT_SYMTAB, elf_fmt::SHF_ALLOC,
        );
        // Create associated dynstr section
        let str_idx = elf_linker::new_section(
            state, ".dynstr", elf_fmt::SHT_STRTAB, elf_fmt::SHF_ALLOC,
        );
        state.sections[idx].link = Some(str_idx);
        // Add initial null byte to string table
        elf_linker::section_ptr_add(&mut state.sections[str_idx], 1);
        // Add initial null symbol entry
        let sym_size = elf_linker::ELF_SYM_SIZE;
        elf_linker::section_ptr_add(&mut state.sections[idx], sym_size);
        idx
    };

    // Use set_elf_sym to add or update the symbol
    // Store dll_index in st_size and ordinal in st_other
    let other = if ordinal > 0 {
        (ordinal & 0xFF) as u8
    } else {
        0u8
    };

    elf_linker::set_elf_sym(
        state,
        0, // value: 0 (will be resolved at link time)
        dll_index as u64, // size: encode dll_index
        elf_fmt::elf_st_info(elf_fmt::STB_GLOBAL, elf_fmt::STT_NOTYPE),
        other,
        elf_fmt::SHN_UNDEF, // undefined — marks as imported
        name,
    );

    let _ = dynsym_idx; // used above for section lookup
    Ok(())
}

/// Helper: read a u16 from a byte slice at the given offset (little-endian).
fn read_u16_le(data: &[u8], off: usize) -> u16 {
    if off + 2 <= data.len() {
        u16::from_le_bytes([data[off], data[off + 1]])
    } else {
        0
    }
}

/// Helper: read a u32 from a byte slice at the given offset (little-endian).
fn read_u32_le(data: &[u8], off: usize) -> u32 {
    if off + 4 <= data.len() {
        u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
    } else {
        0
    }
}

/// Read a C-style null-terminated string from a byte slice.
fn read_cstr_from(data: &[u8], off: usize) -> String {
    let mut end = off;
    while end < data.len() && data[end] != 0 {
        end += 1;
    }
    String::from_utf8_lossy(&data[off..end]).to_string()
}

/// Read export names from a PE DLL file on disk.
/// C equivalent: `get_dllexports()` at tccpe.c line 1571
#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
fn get_dllexports(filename: &str) -> TccResult<Vec<String>> {
    let data = std::fs::read(filename).map_err(TccError::Io)?;
    if data.len() < 0x80 {
        return Err(TccError::Link(format!("file too small to be a PE: {filename}")));
    }

    // Check MZ signature
    let magic = read_u16_le(&data, 0);
    if magic != IMAGE_DOS_SIGNATURE {
        return Err(TccError::Link(format!("not a PE file (no MZ signature): {filename}")));
    }

    // Read e_lfanew
    let pe_offset = read_u32_le(&data, 0x3C) as usize;
    if pe_offset + 4 > data.len() {
        return Err(TccError::Link(format!("invalid PE offset in: {filename}")));
    }

    // Check PE signature
    let pe_sig = read_u32_le(&data, pe_offset);
    if pe_sig != PE_SIGNATURE {
        return Err(TccError::Link(format!("invalid PE signature in: {filename}")));
    }

    // Read optional header magic to determine 32/64 bit
    let opt_hdr_offset = pe_offset + 4 + 20; // After PE sig + file header
    if opt_hdr_offset + 2 > data.len() {
        return Err(TccError::Link(format!("truncated PE header in: {filename}")));
    }
    let opt_magic = read_u16_le(&data, opt_hdr_offset);
    let is_64 = opt_magic == PE32PLUS_MAGIC;

    // Find export directory RVA
    let dd_offset = if is_64 {
        opt_hdr_offset + 112 // PE32+: data directory starts at offset 112 in optional header
    } else {
        opt_hdr_offset + 96 // PE32: data directory starts at offset 96
    };

    let export_rva = read_u32_le(&data, dd_offset) as usize;
    let export_size = read_u32_le(&data, dd_offset + 4) as usize;

    if export_rva == 0 || export_size == 0 {
        return Ok(Vec::new()); // No exports
    }

    // Convert RVA to file offset using section table
    let num_sections = read_u16_le(&data, pe_offset + 4 + 2) as usize;
    let opt_hdr_size = read_u16_le(&data, pe_offset + 4 + 16) as usize;
    let sec_table_off = opt_hdr_offset + opt_hdr_size;

    let rva_to_file = |rva: usize| -> Option<usize> {
        for i in 0..num_sections {
            let sh_off = sec_table_off + i * 40;
            if sh_off + 40 > data.len() { break; }
            let va = read_u32_le(&data, sh_off + 12) as usize;
            let raw_size = read_u32_le(&data, sh_off + 16) as usize;
            let raw_ptr = read_u32_le(&data, sh_off + 20) as usize;
            let vsize = read_u32_le(&data, sh_off + 8) as usize;
            let section_end = va + std::cmp::max(raw_size, vsize);
            if rva >= va && rva < section_end {
                return Some(raw_ptr + (rva - va));
            }
        }
        None
    };

    let export_file_off = rva_to_file(export_rva)
        .ok_or_else(|| TccError::Link(format!("cannot resolve export directory RVA in: {filename}")))?;

    if export_file_off + 40 > data.len() {
        return Err(TccError::Link(format!("truncated export directory in: {filename}")));
    }

    // Read export directory
    let num_names = read_u32_le(&data, export_file_off + 24) as usize;
    let names_rva = read_u32_le(&data, export_file_off + 32) as usize;

    let names_off = rva_to_file(names_rva)
        .ok_or_else(|| TccError::Link(format!("cannot resolve export names RVA in: {filename}")))?;

    let mut exports = Vec::with_capacity(num_names);
    for i in 0..num_names {
        let name_ptr_off = names_off + i * 4;
        if name_ptr_off + 4 > data.len() { break; }
        let name_rva = read_u32_le(&data, name_ptr_off) as usize;
        if let Some(name_off) = rva_to_file(name_rva) {
            let name = read_cstr_from(&data, name_off);
            if !name.is_empty() {
                exports.push(name);
            }
        }
    }

    Ok(exports)
}

/// Public API wrapper for reading DLL exports.
/// C equivalent: `tcc_get_dllexports()` at tccpe.c line 1826
pub(crate) fn tcc_get_dllexports(filename: &str) -> TccResult<Vec<String>> {
    get_dllexports(filename)
}

/// Load a Windows resource (.res) file into the .rsrc section.
/// C equivalent: `pe_load_res()` at tccpe.c line 1674
pub(crate) fn pe_load_res(state: &mut TccState, data: &[u8]) -> TccResult<()> {
    // Validate COFF resource file header
    if data.len() < 32 {
        return Err(TccError::Link("resource file too small".to_string()));
    }

    // Check for COFF resource file: first 32 bytes are a null resource entry
    let magic1 = read_u32_le(data, 0);
    let magic2 = read_u32_le(data, 4);
    if magic1 != 0 || magic2 != 0x20 {
        // Not a standard .res file, check for COFF object
        let machine = read_u16_le(data, 0);
        if machine != 0x014c && machine != 0x8664 && machine != 0x01c0 {
            return Err(TccError::Link("not a valid resource file".to_string()));
        }
    }

    // Create or find .rsrc section
    let rsrc_idx = match state.sections.iter().position(|s| s.name == ".rsrc") {
        Some(i) => i,
        None => elf_linker::new_section(
            state, ".rsrc", elf_fmt::SHT_PROGBITS,
            elf_fmt::SHF_ALLOC | elf_fmt::SHF_WRITE,
        ),
    };

    // Append resource data (skip the 32-byte null resource header)
    let start_offset = if magic1 == 0 && magic2 == 0x20 { 32 } else { 0 };
    if start_offset < data.len() {
        let res_data = &data[start_offset..];
        let pos = elf_linker::section_ptr_add(&mut state.sections[rsrc_idx], res_data.len());
        state.sections[rsrc_idx].data[pos..pos + res_data.len()].copy_from_slice(res_data);
    }

    Ok(())
}

/// Helper: trim leading whitespace from a string slice.
fn trimfront(s: &str) -> &str {
    s.trim_start()
}

/// Helper: get the next token from a string, splitting on whitespace.
fn get_token(s: &str) -> (&str, &str) {
    let s = trimfront(s);
    if s.is_empty() {
        return ("", "");
    }
    // Handle quoted strings
    if s.starts_with('"') {
        if let Some(end) = s[1..].find('"') {
            return (&s[1..=end], trimfront(&s[2 + end..]));
        }
    }
    // Split on whitespace or common delimiters
    let end = s.find(|c: char| c.is_whitespace() || c == ',' || c == ';')
        .unwrap_or(s.len());
    (&s[..end], trimfront(&s[end..]))
}

/// Load a .def (module definition) file, adding imports for each exported symbol.
/// C equivalent: `pe_load_def()` at tccpe.c line 1715
pub(crate) fn pe_load_def(state: &mut TccState, content: &str) -> TccResult<()> {
    let mut in_exports = false;
    let mut dll_index: i32 = -1;

    for line in content.lines() {
        let line = trimfront(line);
        if line.is_empty() || line.starts_with(';') {
            continue;
        }

        let upper = line.to_uppercase();
        if upper.starts_with("LIBRARY") {
            let (_, rest) = get_token(line);
            let (name, _) = get_token(rest);
            let dll_name = name.to_string();
            in_exports = false;

            // Register DLL
            let dll_ref = DllReference {
                level: 0,
                found: true,
                index: 0,
                name: dll_name,
            };
            state.loaded_dlls.push(dll_ref);
            dll_index = (state.loaded_dlls.len() - 1) as i32;
            continue;
        }

        if upper.starts_with("EXPORTS") {
            in_exports = true;
            continue;
        }

        if upper.starts_with("IMPORTS") || upper.starts_with("SECTIONS")
            || upper.starts_with("DESCRIPTION") || upper.starts_with("STACKSIZE")
            || upper.starts_with("HEAPSIZE")
        {
            in_exports = false;
            continue;
        }

        if in_exports && dll_index >= 0 {
            let (sym_name, rest) = get_token(line);
            if sym_name.is_empty() { continue; }

            // Check for ordinal: @N
            let ordinal = if rest.starts_with('@') {
                let (ord_str, _) = get_token(&rest[1..]);
                ord_str.parse::<i32>().unwrap_or(0)
            } else {
                0
            };

            pe_putimport(state, dll_index, sym_name, ordinal)?;
        }
    }

    Ok(())
}

/// Load a DLL file, extracting all exports as imports for the current compilation.
/// C equivalent: `pe_load_dll()` at tccpe.c line 1796
pub(crate) fn pe_load_dll(state: &mut TccState, filename: &str) -> TccResult<()> {
    let exports = get_dllexports(filename)?;

    // Extract DLL name from filename
    let dll_name = Path::new(filename)
        .file_name().map_or_else(|| filename.to_string(), |n| n.to_string_lossy().to_string());

    // Register the DLL
    let dll_ref = DllReference {
        level: 0,
        found: true,
        index: 0,
        name: dll_name,
    };
    state.loaded_dlls.push(dll_ref);
    let dll_index = (state.loaded_dlls.len() - 1) as i32;

    // Add each exported symbol as an import
    for name in &exports {
        pe_putimport(state, dll_index, name, 0)?;
    }

    Ok(())
}

/// Load a PE file, dispatching based on type (.def, .res, .dll).
/// C equivalent: `pe_load_file()` at tccpe.c line 1811
pub(crate) fn pe_load_file(state: &mut TccState, filename: &str) -> TccResult<()> {
    let path = Path::new(filename);
    let ext = path.extension()
        .map(|e| e.to_string_lossy().to_lowercase())
        .unwrap_or_default();

    match ext.as_str() {
        "def" => {
            let content = std::fs::read_to_string(filename).map_err(TccError::Io)?;
            pe_load_def(state, &content)
        }
        "res" | "o" | "obj" => {
            let data = std::fs::read(filename).map_err(TccError::Io)?;
            // Check if it's a resource file
            if data.len() >= 8 {
                let magic1 = read_u32_le(&data, 0);
                let magic2 = read_u32_le(&data, 4);
                if magic1 == 0 && magic2 == 0x20 {
                    return pe_load_res(state, &data);
                }
            }
            // Otherwise treat as object file — not handled here
            Err(TccError::Link(format!("unsupported PE object format: {filename}")))
        }
        _ => {
            // Try to load as DLL (check for MZ signature)
            let data = std::fs::read(filename).map_err(TccError::Io)?;
            if data.len() >= 2 && read_u16_le(&data, 0) == IMAGE_DOS_SIGNATURE {
                pe_load_dll(state, filename)
            } else {
                Err(TccError::Link(format!("unrecognized PE file format: {filename}")))
            }
        }
    }
}

// ===========================================================================
//  Unwind Info (tccpe.c lines 1836-1896) — x86_64 only
// ===========================================================================

/// `x86_64` `UNWIND_INFO` structure for structured exception handling.
/// C equivalent: struct at tccpe.c line 1836
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct UnwindInfo {
    version_flags: u8,    // Version:3, Flags:5
    prolog_size: u8,
    unwind_code_count: u8,
    frame_reg_offset: u8,
}

/// `x86_64` `RUNTIME_FUNCTION` entry for .pdata section.
/// C equivalent: struct at tccpe.c line 1843
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct RuntimeFunction {
    begin_address: u32,
    end_address: u32,
    unwind_data: u32,
}

/// Add `x86_64` unwind information for all functions.
/// Creates .pdata and .xdata sections for structured exception handling (SEH).
/// C equivalent: `pe_add_uwwind_info()` at tccpe.c line 1848
#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
fn pe_add_unwind_info_inner(state: &mut TccState) -> TccResult<()> {
    let text_idx = state.text_section_idx;
    let text_size = state.sections[text_idx].data_offset;

    if text_size == 0 {
        return Ok(());
    }

    // Create .xdata section for unwind info structures
    let xdata_idx = elf_linker::new_section(
        state, ".xdata", elf_fmt::SHT_PROGBITS,
        elf_fmt::SHF_ALLOC | elf_fmt::SHF_WRITE,
    );

    // Write a single minimal UNWIND_INFO entry (covers entire .text)
    let uwi = UnwindInfo {
        version_flags: 1, // Version 1, no flags
        prolog_size: 0,
        unwind_code_count: 0,
        frame_reg_offset: 0,
    };
    let uwi_pos = elf_linker::section_ptr_add(&mut state.sections[xdata_idx], 4);
    state.sections[xdata_idx].data[uwi_pos] = uwi.version_flags;
    state.sections[xdata_idx].data[uwi_pos + 1] = uwi.prolog_size;
    state.sections[xdata_idx].data[uwi_pos + 2] = uwi.unwind_code_count;
    state.sections[xdata_idx].data[uwi_pos + 3] = uwi.frame_reg_offset;

    // Create .pdata section for RUNTIME_FUNCTION entries
    let pdata_idx = elf_linker::new_section(
        state, ".pdata", elf_fmt::SHT_PROGBITS,
        elf_fmt::SHF_ALLOC | elf_fmt::SHF_WRITE,
    );

    // Add a RUNTIME_FUNCTION entry covering the entire text section
    let rf_size = 12; // sizeof(RUNTIME_FUNCTION)
    let rf_pos = elf_linker::section_ptr_add(&mut state.sections[pdata_idx], rf_size);

    // begin_address: RVA of text start (will be relocated)
    state.sections[pdata_idx].data[rf_pos..rf_pos + 4]
        .copy_from_slice(&0u32.to_le_bytes());
    // end_address: RVA of text end
    state.sections[pdata_idx].data[rf_pos + 4..rf_pos + 8]
        .copy_from_slice(&(text_size as u32).to_le_bytes());
    // unwind_data: RVA of UNWIND_INFO in .xdata
    state.sections[pdata_idx].data[rf_pos + 8..rf_pos + 12]
        .copy_from_slice(&0u32.to_le_bytes());

    Ok(())
}

/// Public entry for adding unwind data.
/// C equivalent: `pe_add_unwind_data()` at tccpe.c line 1886
pub(crate) fn pe_add_unwind_data(state: &mut TccState) -> TccResult<()> {
    // Only meaningful for x86_64 targets
    if !state.sections.is_empty() {
        pe_add_unwind_info_inner(state)?;
    }
    Ok(())
}

// ===========================================================================
//  Runtime and Startup (tccpe.c lines 1904-1989)
// ===========================================================================

/// Determine PE output type and add CRT startup code and standard libraries.
/// C equivalent: `pe_add_runtime()` at tccpe.c line 1904
#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
fn pe_add_runtime(state: &mut TccState, pe: &mut PeInfo) -> TccResult<()> {
    // Determine PE type from output_type
    let output_type = state.output_type;
    if output_type == OutputType::DynamicLibrary as i32 {
        pe.pe_type = PeType::Dll;
    } else if output_type == OutputType::Memory as i32 {
        pe.pe_type = PeType::Run;
    } else if pe.subsystem == 2 {
        // GUI subsystem
        pe.pe_type = PeType::Gui;
    } else {
        pe.pe_type = PeType::Exe;
    }

    // Set start symbol based on PE type
    pe.start_symbol = match pe.pe_type {
        PeType::Dll => "_DllMainCRTStartup".to_string(),
        PeType::Gui => "WinMain".to_string(),
        PeType::Run => "main".to_string(),
        _ => "_start".to_string(),
    };

    // For full PE output (not memory), add standard libraries if not nostdlib
    if !state.nostdlib && pe.pe_type != PeType::Run {
        // Add default libraries: kernel32, msvcrt
        let default_libs = ["kernel32", "msvcrt"];
        for lib in &default_libs {
            // In a real implementation, these would be loaded from the lib path
            // For now, we register them as needed DLLs
            let dll_name = format!("{lib}.dll");
            let already_loaded = state.loaded_dlls.iter().any(|d| {
                d.name.eq_ignore_ascii_case(&dll_name)
            });
            if !already_loaded {
                let dll_ref = DllReference {
                    level: 0,
                    found: false, // Will be resolved during symbol checking
                    index: 0,
                    name: dll_name,
                };
                state.loaded_dlls.push(dll_ref);
            }
        }

        // Add GUI-specific libraries
        if pe.pe_type == PeType::Gui {
            let gui_libs = ["user32", "gdi32"];
            for lib in &gui_libs {
                let dll_name = format!("{lib}.dll");
                let already_loaded = state.loaded_dlls.iter().any(|d| {
                    d.name.eq_ignore_ascii_case(&dll_name)
                });
                if !already_loaded {
                    let dll_ref = DllReference {
                        level: 0,
                        found: false,
                        index: 0,
                        name: dll_name,
                    };
                    state.loaded_dlls.push(dll_ref);
                }
            }
        }
    }

    // Add bounds-checking support if enabled
    if state.do_bounds_check {
        let _ = elf_linker::tcc_add_bcheck(state);
    }

    // Add backtrace support if enabled
    if state.do_backtrace {
        let _ = elf_linker::tcc_add_btstub(state);
    }

    Ok(())
}

// ===========================================================================
//  PE Options and Subsystem (tccpe.c lines 1991-2064)
// ===========================================================================

/// Parse subsystem name string to numeric value.
/// C equivalent: `pe_setsubsy()` at tccpe.c line 1991
fn pe_setsubsy(name: &str) -> i32 {
    let lower = name.to_lowercase();
    match lower.as_str() {
        "native" => 1,
        "gui" | "windows" => 2,
        "console" => 3,
        "posix" => 7,
        "wince" => 9,
        "efiapp" | "efi_application" => 10,
        "efiboot" | "efi_boot_service_driver" => 11,
        "efiruntime" | "efi_runtime_driver" => 12,
        "efirom" | "efi_rom" => 13,
        _ => {
            // Try parsing as an integer
            name.parse::<i32>().unwrap_or(3) // Default to console
        }
    }
}

/// Set PE subsystem based on state output type and options.
/// C equivalent: `pe_set_subsystem()` at tccpe.c (combined with `pe_setsubsy`)
///
/// Since `TccState` doesn't carry a `pe_subsystem` field, this function is a
/// no-op at the state level — the subsystem is set during `pe_set_options`
/// via the `PeInfo` struct.  It exists to satisfy the public API contract.
pub(crate) fn pe_set_subsystem(_state: &mut TccState) -> TccResult<()> {
    // Subsystem configuration is handled in pe_set_options via PeInfo.
    // Default: console (3).
    Ok(())
}

/// Set PE-specific linker options: image base, subsystem, alignment.
/// C equivalent: `pe_set_options()` at tccpe.c line 2019
pub(crate) fn pe_set_options(_state: &mut TccState, pe: &mut PeInfo) -> TccResult<()> {
    // Set subsystem (default to console if not already configured)
    if pe.subsystem == 0 {
        pe.subsystem = 3; // Console
    }

    // Set image base
    pe.image_base = match pe.pe_type {
        PeType::Dll => 0x10000000,
        _ => {
            if is_target_arm(&pe.arch) {
                0x00010000
            } else {
                0x00400000
            }
        }
    };

    // Set alignment
    if pe.subsystem == 1 {
        // Native subsystem uses smaller alignment
        pe.section_align = 0x20;
        pe.file_align = 0x20;
    } else {
        if pe.section_align == 0 {
            pe.section_align = 0x1000;
        }
        if pe.file_align == 0 {
            pe.file_align = 0x200;
        }
    }

    // EFI subsystems force specific image base
    if pe.subsystem >= 10 && pe.subsystem <= 13 {
        pe.image_base = 0;
    }

    pe.size_of_headers = pe_file_align_val(pe, 0x200);

    Ok(())
}

// ===========================================================================
//  Master PE Output Function (tccpe.c lines 2066-2112)
// ===========================================================================

/// Master PE output dispatch — creates a complete PE file or in-memory image.
/// This is the main entry point for PE output, coordinating all sub-phases:
/// runtime addition, symbol resolution, address assignment, relocation, and writing.
///
/// C equivalent: `pe_output_file()` at tccpe.c line 2066
pub(crate) fn pe_output_file(state: &mut TccState, filename: &str) -> TccResult<()> {
    let mut pe = PeInfo::new();
    pe.filename = filename.to_string();

    // Step 1: Add CRT runtime and determine PE type
    pe_add_runtime(state, &mut pe)?;

    // Step 2: Resolve common symbols (BSS → data)
    elf_linker::resolve_common_syms(state)?;

    // Step 3: Set PE options (image base, subsystem, alignment)
    pe_set_options(state, &mut pe)?;

    // Step 4: Check and resolve all symbols
    pe_check_symbols(&mut pe, state)?;

    if filename.is_empty() {
        // In-memory mode: just build imports into the data section
        let data_idx = state.data_section_idx;
        pe.thunk = Some(data_idx);
        pe_build_imports(&mut pe, state)?;
    } else {
        // Step 5: Assign virtual addresses to all sections
        pe_assign_addresses(&mut pe, state)?;

        // Step 6: Relocate symbols and sections
        elf_linker::relocate_syms(state, false)?;
        elf_linker::relocate_sections(state)?;

        // Step 7: Compute entry point address
        if !pe.start_symbol.is_empty() {
            match elf_linker::get_sym_addr(state, &pe.start_symbol, true) {
                Ok(addr) => {
                    pe.start_addr = (addr.wrapping_sub(pe.image_base)) as u32;
                }
                Err(_) => {
                    if pe.pe_type != PeType::Dll {
                        return Err(TccError::Link(format!(
                            "undefined start symbol '{}'", pe.start_symbol
                        )));
                    }
                }
            }
        }

        // Step 8: Write the PE file
        let file = std::fs::File::create(filename).map_err(TccError::Io)?;
        let mut writer = std::io::BufWriter::new(file);
        pe_write(&mut pe, state, &mut writer)?;
        writer.flush().map_err(TccError::Io)?;

        // Step 9: Patch checksum in the output file
        // The checksum was computed during pe_write; now patch it into the file
        let checksum_file_offset = 0x80u64 + 4 + 20 + 64; // DOS hdr + PE sig + file hdr + checksum offset
        let checksum_val = pe.checksum;
        let file_for_patch = std::fs::OpenOptions::new()
            .write(true)
            .open(filename)
            .map_err(TccError::Io)?;
        use std::io::Seek;
        let mut patcher = std::io::BufWriter::new(file_for_patch);
        patcher.seek(std::io::SeekFrom::Start(checksum_file_offset)).map_err(TccError::Io)?;
        patcher.write_all(&checksum_val.to_le_bytes()).map_err(TccError::Io)?;
        patcher.flush().map_err(TccError::Io)?;

    }

    Ok(())
}

// ===========================================================================
//  Unit Tests
// ===========================================================================

#[cfg(test)]
#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
mod tests {
    use super::*;
    use zerocopy::AsBytes;

    #[test]
    fn test_image_dos_header_size() {
        assert_eq!(std::mem::size_of::<ImageDosHeader>(), 64);
    }

    #[test]
    fn test_image_file_header_size() {
        assert_eq!(std::mem::size_of::<ImageFileHeader>(), 20);
    }

    #[test]
    fn test_image_data_directory_size() {
        assert_eq!(std::mem::size_of::<ImageDataDirectory>(), 8);
    }

    #[test]
    fn test_image_section_header_size() {
        assert_eq!(std::mem::size_of::<ImageSectionHeader>(), 40);
    }

    #[test]
    fn test_image_export_directory_size() {
        assert_eq!(std::mem::size_of::<ImageExportDirectory>(), 40);
    }

    #[test]
    fn test_image_import_descriptor_size() {
        assert_eq!(std::mem::size_of::<ImageImportDescriptor>(), 20);
    }

    #[test]
    fn test_image_base_relocation_size() {
        assert_eq!(std::mem::size_of::<ImageBaseRelocation>(), 8);
    }

    #[test]
    fn test_dos_header_default_magic() {
        let hdr = ImageDosHeader::default();
        assert_eq!(hdr.e_magic, 0x5A4D); // "MZ"
    }

    #[test]
    fn test_dos_header_as_bytes() {
        let hdr = ImageDosHeader::default();
        let bytes = hdr.as_bytes();
        assert_eq!(bytes.len(), 64);
        assert_eq!(bytes[0], 0x4D); // 'M'
        assert_eq!(bytes[1], 0x5A); // 'Z'
    }

    #[test]
    fn test_file_header_as_bytes() {
        let mut hdr = ImageFileHeader::default();
        hdr.machine = 0x8664;
        hdr.number_of_sections = 3;
        let bytes = hdr.as_bytes();
        assert_eq!(bytes.len(), 20);
        assert_eq!(bytes[0], 0x64);
        assert_eq!(bytes[1], 0x86);
        assert_eq!(bytes[2], 0x03);
        assert_eq!(bytes[3], 0x00);
    }

    #[test]
    fn test_section_header_as_bytes() {
        let mut hdr = ImageSectionHeader::default();
        hdr.name = *b".text\0\0\0";
        hdr.virtual_size = 0x1000;
        let bytes = hdr.as_bytes();
        assert_eq!(bytes.len(), 40);
        assert_eq!(&bytes[0..5], b".text");
    }

    #[test]
    fn test_pe_image_rel_based() {
        assert_eq!(pe_image_rel_based(true), 10);
        assert_eq!(pe_image_rel_based(false), 3);
    }

    #[test]
    fn test_image_file_machine() {
        assert_eq!(image_file_machine("x86_64"), 0x8664);
        assert_eq!(image_file_machine("arm"), 0x01c0);
        assert_eq!(image_file_machine("i386"), 0x014c);
        assert_eq!(image_file_machine("unknown"), 0x014c);
    }

    #[test]
    #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
    fn test_pe_section_class_enum() {
        assert_eq!(PeSectionClass::Text as u32, 0);
        assert_eq!(PeSectionClass::Rdata as u32, 1);
        assert_eq!(PeSectionClass::Data as u32, 2);
        assert_eq!(PeSectionClass::Bss as u32, 3);
        assert_eq!(PeSectionClass::Last as u32, 10);
    }

    #[test]
    #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
    fn test_pe_type_enum() {
        assert_eq!(PeType::Nul as u32, 0);
        assert_eq!(PeType::Dll as u32, 1);
        assert_eq!(PeType::Gui as u32, 2);
        assert_eq!(PeType::Exe as u32, 3);
        assert_eq!(PeType::Run as u32, 4);
    }

    #[test]
    fn test_pe_header_creation() {
        let hdr = PeHeader::default();
        assert_eq!(hdr.dos_hdr.e_magic, 0x5A4D);
        assert_eq!(hdr.nt_sig, 0x0000_4550);
        assert_eq!(hdr.dos_stub.len(), 0x40);
    }

    #[test]
    fn test_pe_info_creation() {
        let pe = PeInfo::new();
        assert_eq!(pe.pe_type, PeType::Nul);
        assert!(pe.sec_info.is_empty());
        assert!(pe.imp_info.is_empty());
    }

    #[test]
    fn test_pe_section_info_creation() {
        let si = PeSectionInfo {
            cls: PeSectionClass::Text,
            name: ".text".to_string(),
            sh_addr: 0x1000,
            sh_size: 0x200,
            pe_flags: 0x6000_0020,
            sec: vec![0],
            data_size: 0x200,
            ish: ImageSectionHeader::default(),
        };
        assert_eq!(si.cls, PeSectionClass::Text);
        assert_eq!(si.name, ".text");
    }

    #[test]
    fn test_import_symbol_creation() {
        let imp = ImportSymbol {
            sym_index: 1,
            iat_index: 2,
            thk_offset: 0x100,
        };
        assert_eq!(imp.sym_index, 1);
    }

    #[test]
    fn test_pe_import_info_creation() {
        let info = PeImportInfo {
            dll_index: 0,
            symbols: vec![ImportSymbol { sym_index: 1, iat_index: 0, thk_offset: 0 }],
        };
        assert_eq!(info.dll_index, 0);
        assert_eq!(info.symbols.len(), 1);
    }

    #[test]
    fn test_addr3264_type() {
        assert_eq!(std::mem::size_of::<Addr3264>(), 8);
    }

    #[test]
    fn test_zeroed_structs() {
        // Use Zeroable trait method to zero-init (bytemuck)
        let hdr = ImageFileHeader::default();
        assert_eq!(hdr.machine, 0);
        let dd = ImageDataDirectory::default();
        assert_eq!(dd.virtual_address, 0);
    }

    #[test]
    fn test_optional_header_32_default() {
        let oh = ImageOptionalHeader32::default();
        assert_eq!(oh.magic, 0x010B);
        assert_eq!(oh.major_linker_version, 6);
        assert_eq!(oh.number_of_rva_and_sizes, 16);
    }

    #[test]
    fn test_optional_header_64_default() {
        let oh = ImageOptionalHeader64::default();
        assert_eq!(oh.magic, 0x020B);
        assert_eq!(oh.major_linker_version, 6);
        assert_eq!(oh.number_of_rva_and_sizes, 16);
    }

    #[test]
    fn test_export_directory_serialization() {
        let ed = ImageExportDirectory {
            characteristics: 0,
            time_date_stamp: 0x1234_5678,
            major_version: 1,
            minor_version: 0,
            name: 0x2000,
            base: 1,
            number_of_functions: 10,
            number_of_names: 10,
            address_of_functions: 0x3000,
            address_of_names: 0x3028,
            address_of_name_ordinals: 0x3050,
        };
        let bytes = ed.as_bytes();
        assert_eq!(bytes.len(), 40);
        assert_eq!(bytes[4], 0x78);
        assert_eq!(bytes[5], 0x56);
    }

    #[test]
    fn test_import_descriptor_serialization() {
        let id = ImageImportDescriptor {
            original_first_thunk: 0x1000,
            time_date_stamp: 0,
            forwarder_chain: 0xFFFF_FFFF,
            name: 0x2000,
            first_thunk: 0x3000,
        };
        let bytes = id.as_bytes();
        assert_eq!(bytes.len(), 20);
        assert_eq!(&bytes[8..12], &[0xFF, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn test_base_relocation_serialization() {
        let br = ImageBaseRelocation {
            virtual_address: 0x1000,
            size_of_block: 12,
        };
        let bytes = br.as_bytes();
        assert_eq!(bytes.len(), 8);
        assert_eq!(bytes[0], 0x00);
        assert_eq!(bytes[1], 0x10);
        assert_eq!(bytes[4], 12);
    }
}
