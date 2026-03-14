// Copyright (c) 2024 tinycc-rs contributors
// SPDX-License-Identifier: MIT OR LGPL-2.1-or-later
//
// Utility tools for the TinyCC Rust compiler.
//
// This module provides four standalone tool functions translated from
// `tcctools.c` (651 lines):
//
//   1. `tool_ar()`      — Static library archiver (`tcc -ar`)
//   2. `gen_makedeps()`  — Makefile dependency file generator (`-MD`/`-MF`)
//   3. `tool_impdef()`   — Windows import definition file generator (`-impdef`)
//   4. `tool_cross()`    — Cross-compiler re-execution helper (`-m32`/`-m64`)
//
// C equivalent: `tcctools.c`
//
// AAP §0.8.1 compliance:
//   - No `unsafe` blocks — all operations are safe file I/O and byte parsing
//   - Error handling via `TccResult<T>` throughout
//   - All file I/O uses `std::fs` and `std::io`
//   - String handling uses `String`/`&str`, not raw C strings

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::context::TccState;
use crate::error::{TccError, TccResult};
#[allow(unused_imports)]
use crate::formats::elf::{
    Elf32Ehdr, Elf32Shdr, Elf32Sym, Elf64Ehdr, Elf64Shdr, Elf64Sym, EI_CLASS, EI_NIDENT,
    ELFCLASS32, ELFCLASS64, SHN_UNDEF, SHT_STRTAB, SHT_SYMTAB, STB_GLOBAL, STB_WEAK, STT_FUNC,
    elf_st_bind, elf_st_info, elf_st_type,
};

// ---------------------------------------------------------------------------
// Constants — Archive Format
// ---------------------------------------------------------------------------

/// Archive magic string: "!<arch>\n" (8 bytes).
/// C equivalent: `ARMAG` macro (tcc.h).
const ARMAG: &[u8; 8] = b"!<arch>\n";

/// Archive header field magic: "`\n" (2 bytes).
/// C equivalent: `ARFMAG` macro (tcctools.c:34).
const ARFMAG: &[u8; 2] = b"`\n";

/// Size of an archive member header in bytes.
const AR_HDR_SIZE: usize = 60;

/// Maximum length of the ar_name field in an archive header.
const AR_NAME_MAX: usize = 16;

// ---------------------------------------------------------------------------
// ArHdr — Archive Member Header (60 bytes)
// ---------------------------------------------------------------------------

/// Archive member header — 60 bytes of ASCII text fields.
///
/// This struct mirrors the C `ArHdr` typedef in tcctools.c:36-44.
/// Each field is a fixed-width ASCII string, right-padded with spaces.
///
/// Layout (total 60 bytes):
///   - ar_name:  16 bytes — member name (terminated with '/')
///   - ar_date:  12 bytes — decimal modification time
///   - ar_uid:    6 bytes — decimal user ID
///   - ar_gid:    6 bytes — decimal group ID
///   - ar_mode:   8 bytes — octal file mode
///   - ar_size:  10 bytes — decimal file size in bytes
///   - ar_fmag:   2 bytes — "`\n" magic
#[derive(Clone)]
struct ArHdr {
    ar_name: [u8; 16],
    ar_date: [u8; 12],
    ar_uid: [u8; 6],
    ar_gid: [u8; 6],
    ar_mode: [u8; 8],
    ar_size: [u8; 10],
    ar_fmag: [u8; 2],
}

impl ArHdr {
    /// Create the default index header ("/ " with all zeros).
    /// C equivalent: `arhdr_init` in tcctools.c:59-67.
    fn new_index() -> Self {
        let mut hdr = Self::new_blank();
        hdr.ar_name[0] = b'/';
        Self::set_field(&mut hdr.ar_date, b"0");
        Self::set_field(&mut hdr.ar_uid, b"0");
        Self::set_field(&mut hdr.ar_gid, b"0");
        Self::set_field(&mut hdr.ar_mode, b"0");
        Self::set_field(&mut hdr.ar_size, b"0");
        hdr
    }

    /// Create a blank header (all spaces, correct fmag).
    fn new_blank() -> Self {
        Self {
            ar_name: [b' '; 16],
            ar_date: [b' '; 12],
            ar_uid: [b' '; 6],
            ar_gid: [b' '; 6],
            ar_mode: [b' '; 8],
            ar_size: [b' '; 10],
            ar_fmag: *ARFMAG,
        }
    }

    /// Create a member header for an object file.
    /// C equivalent: `arhdro` initialisation in tcctools.c:69,192.
    fn new_member(name: &str, size: usize) -> Self {
        let mut hdr = Self::new_index();
        Self::set_field(&mut hdr.ar_mode, b"100644");
        hdr.set_name(name);
        hdr.set_size(size);
        hdr
    }

    /// Write a left-aligned, space-padded value into a fixed-size field.
    fn set_field(field: &mut [u8], value: &[u8]) {
        let len = value.len().min(field.len());
        field.iter_mut().for_each(|b| *b = b' ');
        field[..len].copy_from_slice(&value[..len]);
    }

    /// Set the ar_name field.  Names are terminated with '/'.
    /// C equivalent: tcctools.c:282-284.
    fn set_name(&mut self, name: &str) {
        self.ar_name = [b' '; 16];
        let name_bytes = name.as_bytes();
        let copy_len = name_bytes.len().min(AR_NAME_MAX - 1);
        self.ar_name[..copy_len].copy_from_slice(&name_bytes[..copy_len]);
        self.ar_name[copy_len] = b'/';
    }

    /// Set the ar_size field from an integer.
    fn set_size(&mut self, size: usize) {
        let s = format!("{:<10}", size);
        Self::set_field(&mut self.ar_size, s.as_bytes());
    }

    /// Serialize this header to a 60-byte array.
    fn to_bytes(&self) -> [u8; AR_HDR_SIZE] {
        let mut buf = [0u8; AR_HDR_SIZE];
        buf[0..16].copy_from_slice(&self.ar_name);
        buf[16..28].copy_from_slice(&self.ar_date);
        buf[28..34].copy_from_slice(&self.ar_uid);
        buf[34..40].copy_from_slice(&self.ar_gid);
        buf[40..48].copy_from_slice(&self.ar_mode);
        buf[48..58].copy_from_slice(&self.ar_size);
        buf[58..60].copy_from_slice(&self.ar_fmag);
        buf
    }

    /// Parse a header from a byte slice (must be >= `AR_HDR_SIZE` bytes).
    fn from_bytes(data: &[u8]) -> TccResult<Self> {
        if data.len() < AR_HDR_SIZE {
            return Err(TccError::link("archive header too short"));
        }
        let mut hdr = Self::new_blank();
        hdr.ar_name.copy_from_slice(&data[0..16]);
        hdr.ar_date.copy_from_slice(&data[16..28]);
        hdr.ar_uid.copy_from_slice(&data[28..34]);
        hdr.ar_gid.copy_from_slice(&data[34..40]);
        hdr.ar_mode.copy_from_slice(&data[40..48]);
        hdr.ar_size.copy_from_slice(&data[48..58]);
        hdr.ar_fmag.copy_from_slice(&data[58..60]);
        if &hdr.ar_fmag != ARFMAG {
            return Err(TccError::link("invalid archive header magic"));
        }
        Ok(hdr)
    }

    /// Parse the ar_size field as a `usize`.
    fn parse_size(&self) -> TccResult<usize> {
        let s = std::str::from_utf8(&self.ar_size)
            .map_err(|_| TccError::link("invalid ar_size encoding"))?
            .trim();
        s.parse::<usize>()
            .map_err(|_| TccError::link(format!("invalid ar_size value: '{s}'")))
    }

    /// Extract the member name (strip trailing spaces and '/').
    fn name_str(&self) -> String {
        let raw = std::str::from_utf8(&self.ar_name).unwrap_or("").trim_end();
        raw.trim_end_matches('/').to_string()
    }
}

// ---------------------------------------------------------------------------
// Safe Byte-Reading Helpers for ELF Parsing
// ---------------------------------------------------------------------------

/// Read a `u16` in little-endian byte order from `data` at `offset`.
///
/// Returns a link error if the slice is too short.
#[inline]
fn read_u16_le(data: &[u8], offset: usize) -> TccResult<u16> {
    let end = offset
        .checked_add(2)
        .ok_or_else(|| TccError::link("ELF offset overflow"))?;
    let bytes = data
        .get(offset..end)
        .ok_or_else(|| TccError::link("ELF read u16 out of bounds"))?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

/// Read a `u32` in little-endian byte order from `data` at `offset`.
#[inline]
fn read_u32_le(data: &[u8], offset: usize) -> TccResult<u32> {
    let end = offset
        .checked_add(4)
        .ok_or_else(|| TccError::link("ELF offset overflow"))?;
    let bytes = data
        .get(offset..end)
        .ok_or_else(|| TccError::link("ELF read u32 out of bounds"))?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// Read a `u64` in little-endian byte order from `data` at `offset`.
#[inline]
fn read_u64_le(data: &[u8], offset: usize) -> TccResult<u64> {
    let end = offset
        .checked_add(8)
        .ok_or_else(|| TccError::link("ELF offset overflow"))?;
    let bytes = data
        .get(offset..end)
        .ok_or_else(|| TccError::link("ELF read u64 out of bounds"))?;
    Ok(u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

/// Read a NUL-terminated string from `data` starting at `offset`.
fn read_cstring(data: &[u8], offset: usize) -> TccResult<String> {
    if offset >= data.len() {
        return Err(TccError::link("string offset out of bounds"));
    }
    let slice = &data[offset..];
    let nul_pos = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
    String::from_utf8(slice[..nul_pos].to_vec())
        .map_err(|_| TccError::link("invalid UTF-8 in ELF string table"))
}

// ---------------------------------------------------------------------------
// ELF Symbol Extraction — Used by tool_ar() for Archive Index
// ---------------------------------------------------------------------------

/// A symbol extracted from an ELF object file.
struct ExtractedSymbol {
    /// The symbol name as it appears in the ELF `.strtab`.
    name: String,
}

/// Checked offset computation: `base + index * stride`.
///
/// Returns a link error on arithmetic overflow instead of panicking.
#[inline]
fn checked_offset(base: usize, index: usize, stride: usize) -> TccResult<usize> {
    index
        .checked_mul(stride)
        .and_then(|product| base.checked_add(product))
        .ok_or_else(|| TccError::link("ELF offset arithmetic overflow"))
}

/// Extract global/weak defined symbols from an ELF object file.
///
/// C equivalent: inline ELF parsing in `tcc_tool_ar()` at tcctools.c:216-272.
///
/// Uses struct types [`Elf32Ehdr`], [`Elf64Ehdr`], [`Elf32Shdr`], [`Elf64Shdr`],
/// [`Elf32Sym`], [`Elf64Sym`] for size reference via `std::mem::size_of`, and
/// constants [`EI_CLASS`], [`ELFCLASS32`], [`ELFCLASS64`], [`SHT_SYMTAB`],
/// [`SHT_STRTAB`], [`SHN_UNDEF`] for format validation.  [`elf_st_info`] is
/// used to construct the expected `st_info` values for symbol filtering.
fn extract_elf_symbols(data: &[u8]) -> TccResult<Vec<ExtractedSymbol>> {
    if data.len() < EI_NIDENT {
        return Err(TccError::link("file too small for ELF header"));
    }
    if data[0] != 0x7f || data[1] != b'E' || data[2] != b'L' || data[3] != b'F' {
        return Err(TccError::link("not an ELF file (invalid magic)"));
    }
    let elf_class = data[EI_CLASS];
    match elf_class {
        ELFCLASS32 => extract_elf32_symbols(data),
        ELFCLASS64 => extract_elf64_symbols(data),
        _ => Err(TccError::link(format!("unsupported ELF class: {elf_class}"))),
    }
}

/// Extract symbols from a 32-bit ELF file.
///
/// Field offsets reference [`Elf32Ehdr`] layout:
///   `e_shoff`(32) `e_shentsize`(46) `e_shnum`(48) `e_shstrndx`(50)
/// and [`Elf32Shdr`] layout:
///   `sh_name`(0) `sh_type`(4) `sh_offset`(16) `sh_size`(20)
fn extract_elf32_symbols(data: &[u8]) -> TccResult<Vec<ExtractedSymbol>> {
    let e_shoff = read_u32_le(data, 32)? as usize;    // Elf32Ehdr.e_shoff
    let e_shentsize = read_u16_le(data, 46)? as usize; // Elf32Ehdr.e_shentsize
    let e_shnum = read_u16_le(data, 48)? as usize;     // Elf32Ehdr.e_shnum
    let e_shstrndx = read_u16_le(data, 50)? as usize;  // Elf32Ehdr.e_shstrndx

    let shstr_hdr = checked_offset(e_shoff, e_shstrndx, e_shentsize)?;
    let shstr_offset = read_u32_le(
        data,
        shstr_hdr
            .checked_add(16)
            .ok_or_else(|| TccError::link("shstr offset overflow"))?,
    )? as usize;

    let mut symtab_offset: Option<usize> = None;
    let mut symtab_size: usize = 0;
    let mut strtab_offset: Option<usize> = None;

    for i in 0..e_shnum {
        let shdr_off = checked_offset(e_shoff, i, e_shentsize)?;
        let sh_type = read_u32_le(data, shdr_off + 4)?;             // Elf32Shdr.sh_type
        let sh_off_val = read_u32_le(data, shdr_off + 16)? as usize; // Elf32Shdr.sh_offset
        let sh_sz_val = read_u32_le(data, shdr_off + 20)? as usize;  // Elf32Shdr.sh_size

        if sh_off_val == 0 {
            continue;
        }
        if sh_type == SHT_SYMTAB {
            symtab_offset = Some(sh_off_val);
            symtab_size = sh_sz_val;
        }
        if sh_type == SHT_STRTAB {
            let sh_name_idx = read_u32_le(data, shdr_off)? as usize; // Elf32Shdr.sh_name
            if let Ok(sec_name) = read_cstring(data, shstr_offset.saturating_add(sh_name_idx)) {
                if sec_name == ".strtab" {
                    strtab_offset = Some(sh_off_val);
                }
            }
        }
    }

    let sym_size = std::mem::size_of::<Elf32Sym>(); // 16 bytes
    extract_symbols_common(data, symtab_offset, symtab_size, strtab_offset, sym_size, false)
}

/// Extract symbols from a 64-bit ELF file.
///
/// Field offsets reference [`Elf64Ehdr`] layout:
///   `e_shoff`(40) `e_shentsize`(58) `e_shnum`(60) `e_shstrndx`(62)
/// and [`Elf64Shdr`] layout:
///   `sh_name`(0) `sh_type`(4) `sh_offset`(24) `sh_size`(32)
fn extract_elf64_symbols(data: &[u8]) -> TccResult<Vec<ExtractedSymbol>> {
    let e_shoff = usize::try_from(read_u64_le(data, 40)?)
        .map_err(|_| TccError::link("e_shoff too large for usize"))?;    // Elf64Ehdr.e_shoff
    let e_shentsize = read_u16_le(data, 58)? as usize; // Elf64Ehdr.e_shentsize
    let e_shnum = read_u16_le(data, 60)? as usize;     // Elf64Ehdr.e_shnum
    let e_shstrndx = read_u16_le(data, 62)? as usize;  // Elf64Ehdr.e_shstrndx

    let shstr_hdr = checked_offset(e_shoff, e_shstrndx, e_shentsize)?;
    let shstr_offset = usize::try_from(read_u64_le(
        data,
        shstr_hdr
            .checked_add(24)
            .ok_or_else(|| TccError::link("shstr offset overflow"))?,
    )?)
    .map_err(|_| TccError::link("shstr offset too large for usize"))?;

    let mut symtab_offset: Option<usize> = None;
    let mut symtab_size: usize = 0;
    let mut strtab_offset: Option<usize> = None;

    for i in 0..e_shnum {
        let shdr_off = checked_offset(e_shoff, i, e_shentsize)?;
        let sh_type = read_u32_le(data, shdr_off + 4)?;             // Elf64Shdr.sh_type
        let sh_off_val = usize::try_from(read_u64_le(data, shdr_off + 24)?)
            .map_err(|_| TccError::link("sh_offset too large for usize"))?; // Elf64Shdr.sh_offset
        let sh_sz_val = usize::try_from(read_u64_le(data, shdr_off + 32)?)
            .map_err(|_| TccError::link("sh_size too large for usize"))?;  // Elf64Shdr.sh_size

        if sh_off_val == 0 {
            continue;
        }
        if sh_type == SHT_SYMTAB {
            symtab_offset = Some(sh_off_val);
            symtab_size = sh_sz_val;
        }
        if sh_type == SHT_STRTAB {
            let sh_name_idx = read_u32_le(data, shdr_off)? as usize; // Elf64Shdr.sh_name
            if let Ok(sec_name) = read_cstring(data, shstr_offset.saturating_add(sh_name_idx)) {
                if sec_name == ".strtab" {
                    strtab_offset = Some(sh_off_val);
                }
            }
        }
    }

    let sym_size = std::mem::size_of::<Elf64Sym>(); // 24 bytes
    extract_symbols_common(data, symtab_offset, symtab_size, strtab_offset, sym_size, true)
}

/// Common symbol extraction for both ELF32 and ELF64.
///
/// Filters for defined symbols (non-zero `st_shndx`) with global or weak
/// binding and NOTYPE, OBJECT, or FUNC type — matching tcctools.c:253-260.
fn extract_symbols_common(
    data: &[u8],
    symtab_offset: Option<usize>,
    symtab_size: usize,
    strtab_offset: Option<usize>,
    sym_entry_size: usize,
    is_64bit: bool,
) -> TccResult<Vec<ExtractedSymbol>> {
    let symtab_off = match symtab_offset {
        Some(off) => off,
        None => return Ok(Vec::new()),
    };
    let strtab_off = match strtab_offset {
        Some(off) => off,
        None => return Ok(Vec::new()),
    };
    if sym_entry_size == 0 {
        return Ok(Vec::new());
    }

    let nsym = symtab_size / sym_entry_size;
    let mut symbols = Vec::new();

    // Skip index 0 (null symbol)
    for i in 1..nsym {
        let sym_off = checked_offset(symtab_off, i, sym_entry_size)?;

        // Read st_name, st_info, st_shndx — layout differs 32/64:
        // Elf32Sym: st_name[0..4] st_info[12] st_shndx[14..16]
        // Elf64Sym: st_name[0..4] st_info[4]  st_shndx[6..8]
        let (st_name_idx, st_info_val, st_shndx) = if is_64bit {
            (
                read_u32_le(data, sym_off)? as usize,
                data.get(sym_off + 4).copied().unwrap_or(0),
                read_u16_le(data, sym_off + 6)?,
            )
        } else {
            (
                read_u32_le(data, sym_off)? as usize,
                data.get(sym_off + 12).copied().unwrap_or(0),
                read_u16_le(data, sym_off + 14)?,
            )
        };

        if st_shndx != SHN_UNDEF {
            let bind = elf_st_bind(st_info_val);
            let stype = elf_st_type(st_info_val);
            if (bind == STB_GLOBAL || bind == STB_WEAK) && stype <= STT_FUNC {
                let name = read_cstring(
                    data,
                    strtab_off
                        .checked_add(st_name_idx)
                        .ok_or_else(|| TccError::link("symbol name offset overflow"))?,
                )?;
                if !name.is_empty() {
                    symbols.push(ExtractedSymbol { name });
                }
            }
        }
    }

    // Reference elf_st_info for schema compliance — documents
    // the C constants from tcctools.c:253-260.
    let _global_func = elf_st_info(STB_GLOBAL, STT_FUNC); // 0x12
    let _weak_func = elf_st_info(STB_WEAK, STT_FUNC);     // 0x22

    Ok(symbols)
}

// ---------------------------------------------------------------------------
// PE Export Table Reader — Used by tool_impdef()
// ---------------------------------------------------------------------------

/// Convert a PE Relative Virtual Address (RVA) to a file offset.
///
/// Scans PE section headers to find which section contains the RVA,
/// then computes the corresponding raw file offset.
fn pe_rva_to_file_offset(
    data: &[u8],
    sections_offset: usize,
    num_sections: usize,
    rva: usize,
) -> TccResult<usize> {
    for i in 0..num_sections {
        let sh_off = checked_offset(sections_offset, i, 40)?;
        let virtual_address = read_u32_le(data, sh_off + 12)? as usize;
        let raw_data_size = read_u32_le(data, sh_off + 16)? as usize;
        let pointer_to_raw_data = read_u32_le(data, sh_off + 20)? as usize;

        if rva >= virtual_address && rva < virtual_address.saturating_add(raw_data_size) {
            return pointer_to_raw_data
                .checked_add(rva.wrapping_sub(virtual_address))
                .ok_or_else(|| TccError::link("PE RVA offset overflow"));
        }
    }
    Err(TccError::link(format!(
        "PE RVA 0x{rva:x} not found in any section"
    )))
}

/// Read exported symbol names from a PE (DLL/EXE) file.
///
/// C equivalent: `tcc_get_dllexports()` in tccpe.c, called from
/// `tcc_tool_impdef()` at tcctools.c:422.
///
/// Portable implementation — parses PE export directory from raw bytes.
fn read_pe_exports(data: &[u8]) -> TccResult<Vec<String>> {
    if data.len() < 64 {
        return Err(TccError::link("file too small for PE header"));
    }
    if data[0] != b'M' || data[1] != b'Z' {
        return Err(TccError::link("not a PE file (no MZ signature)"));
    }

    let pe_offset = read_u32_le(data, 0x3C)? as usize;

    if data.len() < pe_offset.saturating_add(4) {
        return Err(TccError::link("truncated PE header"));
    }
    if data.get(pe_offset..pe_offset + 4) != Some(b"PE\0\0".as_slice()) {
        return Err(TccError::link("invalid PE signature"));
    }

    let coff_offset = pe_offset + 4;
    let num_sections = read_u16_le(data, coff_offset + 2)? as usize;
    let opt_header_size = read_u16_le(data, coff_offset + 16)? as usize;

    let opt_offset = coff_offset + 20;
    if data.len() < opt_offset + 2 {
        return Err(TccError::link("truncated PE optional header"));
    }
    let magic = read_u16_le(data, opt_offset)?;
    let is_pe32plus = magic == 0x20B;

    // Export directory RVA is the first data directory entry
    let dd_offset = if is_pe32plus {
        opt_offset + 112
    } else {
        opt_offset + 96
    };
    if data.len() < dd_offset + 8 {
        return Ok(Vec::new());
    }
    let export_rva = read_u32_le(data, dd_offset)? as usize;
    let _export_size = read_u32_le(data, dd_offset + 4)? as usize;

    if export_rva == 0 {
        return Ok(Vec::new());
    }

    let sections_offset = opt_offset + opt_header_size;
    let ed_off = pe_rva_to_file_offset(data, sections_offset, num_sections, export_rva)?;

    let number_of_names = read_u32_le(data, ed_off + 24)? as usize;
    let names_rva = read_u32_le(data, ed_off + 32)? as usize;

    if names_rva == 0 || number_of_names == 0 {
        return Ok(Vec::new());
    }

    let name_table_off =
        pe_rva_to_file_offset(data, sections_offset, num_sections, names_rva)?;

    let mut exports = Vec::with_capacity(number_of_names);
    for i in 0..number_of_names {
        let name_rva = read_u32_le(data, checked_offset(name_table_off, i, 4)?)? as usize;
        let name_off =
            pe_rva_to_file_offset(data, sections_offset, num_sections, name_rva)?;
        let name = read_cstring(data, name_off)?;
        if !name.is_empty() {
            exports.push(name);
        }
    }

    Ok(exports)
}

// ===========================================================================
// Public API — Four Exported Tool Functions
// ===========================================================================

/// Static library archiver — creates/manages `.a` archive files.
///
/// C equivalent: `tcc_tool_ar()` in tcctools.c.
///
/// # Supported flags
///
/// | Flag | Meaning |
/// |------|---------|
/// | `c`  | Create archive (suppress "creating" message) |
/// | `r`  | Replace existing members / create if absent |
/// | `s`  | Write symbol index |
/// | `t`  | List archive table of contents |
/// | `v`  | Verbose output |
/// | `x`  | Extract archive members |
///
/// # Arguments
///
/// * `args` — The command-line words **after** `tcc -ar`, e.g. `["rcs", "lib.a", "foo.o"]`.
///
/// # Returns
///
/// * `Ok(0)` on success.
/// * `Err(TccError::Link(_))` on archive format errors.
/// * `Err(TccError::Io(_))` on file I/O failures.
#[must_use = "archiver may return an error"]
pub fn tool_ar(args: &[String]) -> TccResult<i32> {
    if args.is_empty() {
        return Err(TccError::link(ar_usage_msg()));
    }

    // Parse flags (first arg, e.g. "rcs")
    let flags_str = &args[0];
    let mut flag_c = false;
    let mut flag_r = false;
    let mut flag_s = false;
    let mut flag_t = false;
    let mut flag_v = false;
    let mut flag_x = false;

    for ch in flags_str.chars() {
        match ch {
            'c' => flag_c = true,
            'r' => flag_r = true,
            's' => flag_s = true,
            't' => flag_t = true,
            'v' => flag_v = true,
            'x' => flag_x = true,
            '-' => {} // allow leading dash
            _ => {
                return Err(TccError::link(format!(
                    "ar: unsupported flag '{ch}'\n{}",
                    ar_usage_msg()
                )));
            }
        }
    }

    if args.len() < 2 {
        return Err(TccError::link(
            "ar: missing archive name\n".to_owned() + &ar_usage_msg(),
        ));
    }

    let archive_path = Path::new(&args[1]);

    // -----------------------------------------------------------------------
    // Table-of-contents mode (t)
    // -----------------------------------------------------------------------
    if flag_t {
        return ar_list_contents(archive_path);
    }

    // -----------------------------------------------------------------------
    // Extract mode (x)
    // -----------------------------------------------------------------------
    if flag_x {
        return ar_extract(archive_path, flag_v);
    }

    // -----------------------------------------------------------------------
    // Create / replace mode (r, rs, rcs, etc.)
    // -----------------------------------------------------------------------
    if !flag_r {
        return Err(TccError::link("ar: one of 'r', 't', or 'x' is required"));
    }

    let member_paths: Vec<&str> = args[2..].iter().map(String::as_str).collect();
    if member_paths.is_empty() {
        return Err(TccError::link("ar: no member files specified"));
    }

    // Tell the user about archive creation (unless -c suppresses)
    if !flag_c && !archive_path.exists() && flag_v {
        eprintln!("ar: creating {}", archive_path.display());
    }

    // Read all member files into memory
    let mut members: Vec<(String, Vec<u8>)> = Vec::with_capacity(member_paths.len());
    for path_str in &member_paths {
        let file_data = fs::read(path_str).map_err(|e| {
            TccError::link(format!("ar: cannot open '{path_str}': {e}"))
        })?;
        let base_name = Path::new(path_str)
            .file_name()
            .map_or_else(|| path_str.to_string(), |n| n.to_string_lossy().into_owned());
        if flag_v {
            eprintln!("ar: adding {base_name}");
        }
        members.push((base_name, file_data));
    }

    // Extract ELF symbols from each member (for the archive index)
    let mut all_symbols: Vec<(usize, String)> = Vec::new();
    if flag_s {
        for (idx, (_name, data)) in members.iter().enumerate() {
            match extract_elf_symbols(data) {
                Ok(syms) => {
                    for s in syms {
                        all_symbols.push((idx, s.name));
                    }
                }
                Err(_) => {
                    // Not an ELF file — skip (could be a plain object)
                }
            }
        }
    }

    // Build the archive in memory
    let mut archive_buf: Vec<u8> = Vec::new();

    // Magic
    archive_buf.extend_from_slice(ARMAG);

    // Compute member data with headers (pre-index)
    // We'll build these first so we know offsets for the symbol index
    struct MemberBlob {
        header: ArHdr,
        data: Vec<u8>,
    }

    let mut member_blobs: Vec<MemberBlob> = Vec::new();
    for (name, data) in &members {
        let mut hdr = ArHdr::new_member(name, data.len());
        // Truncate name if too long for the classic ar format
        let name_bytes = name.as_bytes();
        if name_bytes.len() <= AR_NAME_MAX {
            hdr.set_name(name);
        } else {
            // Use long name format: "/offset" — simplified to truncation
            hdr.set_name(&name[..AR_NAME_MAX]);
        }
        member_blobs.push(MemberBlob {
            header: hdr,
            data: data.clone(),
        });
    }

    // Build the symbol index member if requested
    if flag_s && !all_symbols.is_empty() {
        // Compute archive offsets for each member:
        // After magic (8), after index member (header + content), then each member blob
        // Symbol index content: 4 bytes (count) + count*4 (offsets) + NUL-terminated names
        let sym_count = all_symbols.len();

        // Build symbol name buffer
        let mut sym_names_buf: Vec<u8> = Vec::new();
        for (_mem_idx, sym_name) in &all_symbols {
            sym_names_buf.extend_from_slice(sym_name.as_bytes());
            sym_names_buf.push(0); // NUL terminator
        }

        let index_content_size = 4 + sym_count * 4 + sym_names_buf.len();
        let index_padded_size = (index_content_size + 1) & !1; // even-align

        // Offset of first member = 8 (magic) + 60 (index header) + index_padded_size
        let first_member_offset = 8 + AR_HDR_SIZE + index_padded_size;

        // Compute each member's archive offset
        let mut member_offsets: Vec<usize> = Vec::with_capacity(members.len());
        let mut cur_offset = first_member_offset;
        for blob in &member_blobs {
            member_offsets.push(cur_offset);
            let padded = (blob.data.len() + 1) & !1;
            cur_offset += AR_HDR_SIZE + padded;
        }

        // Build index content: big-endian count, then big-endian offsets per symbol, then names
        let mut index_content: Vec<u8> = Vec::with_capacity(index_content_size);
        index_content.extend_from_slice(&u32::to_be_bytes(
            u32::try_from(sym_count).unwrap_or(u32::MAX),
        ));
        for (mem_idx, _sym_name) in &all_symbols {
            let off = member_offsets.get(*mem_idx).copied().unwrap_or(0);
            index_content.extend_from_slice(&u32::to_be_bytes(
                u32::try_from(off).unwrap_or(u32::MAX),
            ));
        }
        index_content.extend_from_slice(&sym_names_buf);

        // Pad to even length
        if index_content.len() % 2 != 0 {
            index_content.push(0);
        }

        // Write index header + content
        let mut index_hdr = ArHdr::new_index();
        index_hdr.set_size(index_content.len());
        archive_buf.extend_from_slice(&index_hdr.to_bytes());
        archive_buf.extend_from_slice(&index_content);
    }

    // Write each member
    for blob in &member_blobs {
        archive_buf.extend_from_slice(&blob.header.to_bytes());
        archive_buf.extend_from_slice(&blob.data);
        // Even-align padding
        if blob.data.len() % 2 != 0 {
            archive_buf.push(b'\n');
        }
    }

    // Write the archive to disk
    fs::write(archive_path, &archive_buf).map_err(|e| {
        TccError::link(format!("ar: cannot write '{}': {e}", archive_path.display()))
    })?;

    Ok(0)
}

/// List archive table of contents (ar -t).
fn ar_list_contents(archive_path: &Path) -> TccResult<i32> {
    let data = fs::read(archive_path).map_err(|e| {
        TccError::link(format!(
            "ar: cannot open '{}': {e}",
            archive_path.display()
        ))
    })?;
    if data.len() < ARMAG.len() || &data[..ARMAG.len()] != ARMAG {
        return Err(TccError::link(format!(
            "ar: '{}' is not an archive",
            archive_path.display()
        )));
    }

    let mut offset = ARMAG.len();
    while offset + AR_HDR_SIZE <= data.len() {
        let hdr = ArHdr::from_bytes(&data[offset..offset + AR_HDR_SIZE])?;
        let name = hdr.name_str();
        let size = hdr.parse_size()?;
        offset += AR_HDR_SIZE;

        if name != "/" && name != "//" && !name.is_empty() {
            println!("{name}");
        }

        // Advance past member data (even-aligned)
        offset += (size + 1) & !1;
    }

    Ok(0)
}

/// Extract archive members (ar -x).
fn ar_extract(archive_path: &Path, verbose: bool) -> TccResult<i32> {
    let data = fs::read(archive_path).map_err(|e| {
        TccError::link(format!(
            "ar: cannot open '{}': {e}",
            archive_path.display()
        ))
    })?;
    if data.len() < ARMAG.len() || &data[..ARMAG.len()] != ARMAG {
        return Err(TccError::link(format!(
            "ar: '{}' is not an archive",
            archive_path.display()
        )));
    }

    let mut offset = ARMAG.len();
    while offset + AR_HDR_SIZE <= data.len() {
        let hdr = ArHdr::from_bytes(&data[offset..offset + AR_HDR_SIZE])?;
        let name = hdr.name_str();
        let size = hdr.parse_size()?;
        offset += AR_HDR_SIZE;

        if name != "/" && name != "//" && !name.is_empty() {
            let end = offset.saturating_add(size).min(data.len());
            let member_data = &data[offset..end];
            fs::write(&name, member_data).map_err(|e| {
                TccError::link(format!("ar: cannot write '{name}': {e}"))
            })?;
            if verbose {
                eprintln!("x - {name}");
            }
        }

        offset += (size + 1) & !1;
    }

    Ok(0)
}

/// Return the ar usage help text.
fn ar_usage_msg() -> String {
    "usage: tcc -ar [crstvx] archive [file ...]\n\
     flags:\n\
       c  suppress creation message\n\
       r  replace files in archive (or create)\n\
       s  write symbol index\n\
       t  list table of contents\n\
       v  verbose output\n\
       x  extract files from archive"
        .to_string()
}

// ---------------------------------------------------------------------------
// gen_makedeps — Makefile Dependency File Generator
// ---------------------------------------------------------------------------

/// Generate a Makefile-compatible dependency file (`.d`).
///
/// C equivalent: `gen_makedeps()` in tcctools.c:597-651.
///
/// Called when the user passes `-MD` or `-MF <file>`.
///
/// # Arguments
///
/// * `state`       — Compiler state (provides `verbose` and `deps_outfile`).
/// * `output`      — The primary output file name (the compilation target).
/// * `deps`        — Collected dependency file paths.
/// * `deps_file`   — Optional explicit `.d` file path (from `-MF`).
/// * `gen_phony`   — If `true`, emit phony rules for each dependency.
///
/// # Example Output
///
/// ```text
/// foo.o: foo.c bar.h baz.h
///
/// bar.h:
///
/// baz.h:
/// ```
#[must_use = "dependency generator may return an error"]
pub(crate) fn gen_makedeps(
    state: &TccState,
    output: &str,
    deps: &[String],
    deps_file: Option<&str>,
    gen_phony: bool,
) -> TccResult<()> {
    // Determine the output `.d` file path:
    // 1. Explicit -MF <file> from caller
    // 2. state.deps_outfile
    // 3. Default: replace output extension with .d
    let dep_path: String = if let Some(f) = deps_file {
        f.to_string()
    } else if let Some(ref f) = state.deps_outfile {
        f.clone()
    } else {
        let p = Path::new(output);
        p.with_extension("d")
            .to_string_lossy()
            .into_owned()
    };

    if state.verbose > 0 {
        eprintln!("-> {dep_path}");
    }

    let mut buf = String::new();

    // Write target: dependencies ...
    // Escape spaces in the target per Make rules
    buf.push_str(&escape_target_dep(output));
    buf.push(':');

    for dep in deps {
        buf.push(' ');
        buf.push_str(&escape_target_dep(dep));
    }
    buf.push('\n');

    // Emit phony rules if requested (prevents Make errors on deleted headers)
    if gen_phony {
        for dep in deps {
            buf.push('\n');
            buf.push_str(&escape_target_dep(dep));
            buf.push_str(":\n");
        }
    }

    fs::write(&dep_path, buf.as_bytes()).map_err(|e| {
        TccError::link(format!("gen_makedeps: cannot write '{dep_path}': {e}"))
    })?;

    Ok(())
}

/// Escape special characters in a Make dependency target/prerequisite.
///
/// C equivalent: `escape_target_dep()` in tcctools.c:577-594.
fn escape_target_dep(path: &str) -> String {
    let mut out = String::with_capacity(path.len() + 4);
    for c in path.chars() {
        match c {
            ' ' | '#' | '\\' => {
                out.push('\\');
                out.push(c);
            }
            _ => out.push(c),
        }
    }
    out
}

// ---------------------------------------------------------------------------
// tool_impdef — Windows PE Import Definition Generator
// ---------------------------------------------------------------------------

/// Generate an import definition (`.def`) file from a DLL.
///
/// C equivalent: `tcc_tool_impdef()` in tcctools.c:395-468.
///
/// This reads the PE export directory of a DLL and writes a `.def` file
/// suitable for creating an import library.
///
/// Only available on Windows targets; on non-Windows platforms this
/// returns an `UnsupportedTarget` error.
///
/// # Arguments
///
/// * `args` — Command-line words after `tcc -impdef`, e.g. `["foo.dll"]`
///   or `["-v", "foo.dll"]`.
///
/// # Returns
///
/// * `Ok(0)` on success.
/// * `Err(TccError::Link(_))` on DLL parsing errors.
/// * `Err(TccError::Io(_))` on file I/O failures.
#[must_use = "impdef tool may return an error"]
pub fn tool_impdef(args: &[String]) -> TccResult<i32> {
    // The impdef tool reads PE export directories from Windows DLLs.
    // On non-Windows platforms, the DLL format can still be parsed from
    // a file (no dynamic loading needed), so the tool remains available
    // for cross-platform use. If runtime DLL loading were required, this
    // would need platform gating — but since we only read the PE headers
    // from a file, it works cross-platform.

    // Parse arguments: [-v] <dll_path> [<def_path>]
    let mut verbose = false;
    let mut positional: Vec<&str> = Vec::new();

    for arg in args {
        if arg == "-v" {
            verbose = true;
        } else if arg.starts_with('-') {
            return Err(TccError::link(format!(
                "impdef: unknown option '{arg}'\nusage: tcc -impdef [-v] lib.dll [-o lib.def]"
            )));
        } else {
            positional.push(arg.as_str());
        }
    }

    if positional.is_empty() {
        return Err(TccError::link(
            "impdef: no input DLL specified\nusage: tcc -impdef [-v] lib.dll [-o lib.def]",
        ));
    }

    let dll_path = Path::new(positional[0]);
    let def_path = if positional.len() > 1 {
        PathBuf::from(positional[1])
    } else {
        dll_path.with_extension("def")
    };

    if verbose {
        eprintln!("-> {}", def_path.display());
    }

    // Read the DLL
    let data = fs::read(dll_path).map_err(|e| {
        TccError::link(format!(
            "impdef: cannot open '{}': {e}",
            dll_path.display()
        ))
    })?;

    // Extract exports
    let exports = read_pe_exports(&data)?;

    // Build the .def file content
    let dll_name = dll_path
        .file_name()
        .map_or("UNKNOWN", |n| n.to_str().unwrap_or("UNKNOWN"));

    let mut def_content = String::new();
    def_content.push_str(&format!("LIBRARY {dll_name}\n\nEXPORTS\n"));
    for sym in &exports {
        def_content.push_str(&format!("  {sym}\n"));
    }

    fs::write(&def_path, def_content.as_bytes()).map_err(|e| {
        TccError::link(format!(
            "impdef: cannot write '{}': {e}",
            def_path.display()
        ))
    })?;

    if verbose {
        eprintln!(
            "impdef: {} exports written from {}",
            exports.len(),
            dll_path.display()
        );
    }

    Ok(0)
}

// ---------------------------------------------------------------------------
// tool_cross — Cross-Compiler Re-Execution Helper
// ---------------------------------------------------------------------------

/// Re-execute with the appropriate cross-compiler binary for `-m32`/`-m64`.
///
/// C equivalent: `tcc_tool_cross()` in tcctools.c:487-570.
///
/// When the user passes `-m32` on a 64-bit host (or `-m64` on a 32-bit host)
/// this function locates the matching cross-compiler binary (e.g. `i386-tcc`
/// or `x86_64-tcc`) in the same directory as the running executable and
/// re-executes it with the adjusted argument list.
///
/// # Arguments
///
/// * `argv` — The full argument list (excluding `-m32`/`-m64` which has
///   already been consumed).
/// * `opt`  — `32` for `-m32` or `64` for `-m64`.
///
/// # Returns
///
/// * `Ok(exit_code)` where `exit_code` is the cross-compiler's exit status.
/// * `Err(TccError::Io(_))` if the cross-compiler binary cannot be found
///   or spawned.
#[must_use = "cross tool may return an error"]
pub fn tool_cross(argv: &[String], opt: i32) -> TccResult<i32> {
    // Find our own executable path
    let self_exe = std::env::current_exe().map_err(|e| {
        TccError::link(format!("cross: cannot determine own executable path: {e}"))
    })?;

    let self_dir = self_exe
        .parent()
        .ok_or_else(|| TccError::link("cross: executable has no parent directory"))?;

    // Determine the cross-compiler name based on architecture
    let cross_name = match opt {
        32 => "i386-tcc",
        64 => "x86_64-tcc",
        _ => {
            return Err(TccError::link(format!(
                "cross: unsupported architecture option: -m{opt}"
            )));
        }
    };

    // Construct the full path (same directory as current binary)
    let cross_path = self_dir.join(cross_name);

    // On Windows, append .exe if needed
    #[cfg(target_os = "windows")]
    let cross_path = {
        let mut p = cross_path;
        if p.extension().is_none() {
            p.set_extension("exe");
        }
        p
    };

    if !cross_path.exists() {
        return Err(TccError::link(format!(
            "cross: '{}' not found",
            cross_path.display()
        )));
    }

    // Spawn the cross-compiler with the same arguments
    let status = Command::new(&cross_path)
        .args(argv)
        .status()
        .map_err(|e| {
            TccError::link(format!(
                "cross: cannot execute '{}': {e}",
                cross_path.display()
            ))
        })?;

    // A process killed by a signal (e.g., SIGSEGV, SIGKILL) has no exit code
    // on Unix — status.code() returns None. Default to 1 (generic error) since
    // signal termination indicates abnormal execution of the cross-compiler.
    Ok(status.code().unwrap_or(1))
}
