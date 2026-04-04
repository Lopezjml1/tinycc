// Copyright (c) TinyCC contributors. LGPL licensed.
// Ported from tcctools.c (651 lines) and tcc.h to Rust as part of
// the TCC C-to-Rust migration.
//
//! # Built-in Tools Module
//!
//! Provides self-contained tool emulation originally found in `tcctools.c`:
//!
//! - **`tool_ar`**: Built-in archive/static-library creation (`tcc -ar`).
//!   Creates `.a` archive files in the Unix `ar` format, including a
//!   symbol index table derived by parsing ELF object files. Supports
//!   `rcs` (create), `x` (extract), and `t` (table/listing) operations.
//!
//! - **`gen_makedeps`**: Generates Makefile-format dependency files for
//!   `-MD`/`-MF` options, with `-MP` (phony targets) support.
//!
//! - **`tool_impdef`**: Windows-only import definition file generator.
//!   Creates `.def` files from DLL export tables for import library
//!   creation. On non-Windows hosts, returns a descriptive error.
//!
//! - **`tool_cross`**: Cross-compiler re-execution for `-m32`/`-m64`.
//!   Re-invokes the appropriate `i386-tcc` or `x86_64-tcc` binary.
//!
//! # Design Principles
//!
//! - **Standalone**: The `tool_ar` function works without full compiler
//!   initialization, requiring only file paths as arguments.
//! - **No external `ar` dependency**: Self-contained archive creation is
//!   a key TCC feature — the compiler ships without requiring GNU binutils.
//! - **Error handling**: All public functions return [`TccResult<()>`].

use std::fs::{self, File};
use std::io::{self, BufWriter, Write};
use std::mem;
use std::path::Path;
use std::process::{self, Command};

use crate::elf::{
    Elf32_Ehdr, Elf32_Sym, Elf64_Ehdr, Elf64_Sym, ELFCLASS32, ELFCLASS64, EI_CLASS, SHN_UNDEF,
    SHT_STRTAB, SHT_SYMTAB,
};
use crate::error::{TccError, TccResult};
use crate::TCCState;

// ============================================================================
// Archive (ar) Format Constants
// ============================================================================

/// Archive file magic string: `"!<arch>\n"`.
/// Written at the start of every `.a` archive file.
pub const ARMAG: &[u8; 8] = b"!<arch>\n";

/// Archive member trailer magic: `` "`\n" ``.
/// Written at the end of every archive member header.
pub const ARFMAG: &[u8; 2] = b"`\n";

/// Size of the archive file magic string.
const SARMAG: usize = 8;

/// Size of an `ArHdr` when serialized (fixed 60 bytes per the ar format spec).
const AR_HDR_SIZE: usize = 60;

// ============================================================================
// ArHdr — Archive Member Header
// ============================================================================

/// Archive member header structure (60 bytes, fixed-width ASCII fields).
///
/// Each member in a `.a` archive file is preceded by this fixed-format header.
/// All fields are ASCII text, right-padded with spaces to their fixed width.
///
/// The format matches the POSIX / System V `ar` file format exactly:
///
/// | Field     | Width | Content                     |
/// |-----------|-------|-----------------------------|
/// | ar_name   | 16    | Member name (space-padded)  |
/// | ar_date   | 12    | Modification time (decimal) |
/// | ar_uid    | 6     | User ID (decimal)           |
/// | ar_gid    | 6     | Group ID (decimal)          |
/// | ar_mode   | 8     | File mode (octal)           |
/// | ar_size   | 10    | File size (decimal)         |
/// | ar_fmag   | 2     | Trailer magic (`` "`\n" ``) |
#[derive(Clone)]
pub struct ArHdr {
    /// Member name, 16 bytes, space-padded. For normal members the name is
    /// terminated with a `/` character. The special name `/` denotes the
    /// symbol index, and `//` denotes extended (long) file names.
    pub ar_name: [u8; 16],
    /// Modification time as a decimal ASCII string, 12 bytes, space-padded.
    pub ar_date: [u8; 12],
    /// User ID as a decimal ASCII string, 6 bytes, space-padded.
    pub ar_uid: [u8; 6],
    /// Group ID as a decimal ASCII string, 6 bytes, space-padded.
    pub ar_gid: [u8; 6],
    /// File permission mode as an octal ASCII string, 8 bytes, space-padded.
    pub ar_mode: [u8; 8],
    /// Member data size as a decimal ASCII string, 10 bytes, space-padded.
    pub ar_size: [u8; 10],
    /// Trailer magic bytes (always [`ARFMAG`]: `` "`\n" ``).
    pub ar_fmag: [u8; 2],
}

impl ArHdr {
    /// Creates a new archive header with all fields space-padded and the
    /// standard format magic trailer. This matches the C `arhdr_init` initializer.
    fn new() -> Self {
        let mut hdr = ArHdr {
            ar_name: [b' '; 16],
            ar_date: [b' '; 12],
            ar_uid: [b' '; 6],
            ar_gid: [b' '; 6],
            ar_mode: [b' '; 8],
            ar_size: [b' '; 10],
            ar_fmag: *ARFMAG,
        };
        // Set default index header fields matching C: "/               "
        hdr.ar_name[0] = b'/';
        // Zero-fill date, uid, gid like the C initializer
        hdr.ar_date[0] = b'0';
        hdr.ar_uid[0] = b'0';
        hdr.ar_gid[0] = b'0';
        hdr.ar_mode[0] = b'0';
        hdr.ar_size[0] = b'0';
        hdr
    }

    /// Creates a header for a regular object file member.
    fn for_object(name: &str, size: usize) -> Self {
        let mut hdr = Self::new();
        // Set mode to "100644" like C: memcpy(&arhdro.ar_mode, "100644", 6)
        hdr.ar_mode[..6].copy_from_slice(b"100644");

        // Write member name, truncated to 15 chars + '/' suffix
        let name_bytes = name.as_bytes();
        let copy_len = name_bytes.len().min(15);
        hdr.ar_name = [b' '; 16];
        hdr.ar_name[..copy_len].copy_from_slice(&name_bytes[..copy_len]);
        hdr.ar_name[copy_len] = b'/';

        // Write size as left-justified decimal
        Self::write_decimal(&mut hdr.ar_size, size);
        hdr
    }

    /// Writes a decimal integer left-justified into a fixed-width field,
    /// padding remaining bytes with spaces.
    fn write_decimal(field: &mut [u8], value: usize) {
        let s = format!("{}", value);
        let bytes = s.as_bytes();
        let copy_len = bytes.len().min(field.len());
        field.fill(b' ');
        field[..copy_len].copy_from_slice(&bytes[..copy_len]);
    }

    /// Serializes the header into a 60-byte buffer for writing to an archive file.
    fn as_bytes(&self) -> [u8; AR_HDR_SIZE] {
        let mut buf = [0u8; AR_HDR_SIZE];
        let mut pos = 0;
        buf[pos..pos + 16].copy_from_slice(&self.ar_name);
        pos += 16;
        buf[pos..pos + 12].copy_from_slice(&self.ar_date);
        pos += 12;
        buf[pos..pos + 6].copy_from_slice(&self.ar_uid);
        pos += 6;
        buf[pos..pos + 6].copy_from_slice(&self.ar_gid);
        pos += 6;
        buf[pos..pos + 8].copy_from_slice(&self.ar_mode);
        pos += 8;
        buf[pos..pos + 10].copy_from_slice(&self.ar_size);
        pos += 10;
        buf[pos..pos + 2].copy_from_slice(&self.ar_fmag);
        buf
    }

    /// Parses a 60-byte buffer into an ArHdr.
    fn from_bytes(buf: &[u8; AR_HDR_SIZE]) -> Self {
        let mut hdr = ArHdr {
            ar_name: [0; 16],
            ar_date: [0; 12],
            ar_uid: [0; 6],
            ar_gid: [0; 6],
            ar_mode: [0; 8],
            ar_size: [0; 10],
            ar_fmag: [0; 2],
        };
        let mut pos = 0;
        hdr.ar_name.copy_from_slice(&buf[pos..pos + 16]);
        pos += 16;
        hdr.ar_date.copy_from_slice(&buf[pos..pos + 12]);
        pos += 12;
        hdr.ar_uid.copy_from_slice(&buf[pos..pos + 6]);
        pos += 6;
        hdr.ar_gid.copy_from_slice(&buf[pos..pos + 6]);
        pos += 6;
        hdr.ar_mode.copy_from_slice(&buf[pos..pos + 8]);
        pos += 8;
        hdr.ar_size.copy_from_slice(&buf[pos..pos + 10]);
        pos += 10;
        hdr.ar_fmag.copy_from_slice(&buf[pos..pos + 2]);
        hdr
    }

    /// Extracts the member name as a trimmed string.
    /// Strips trailing spaces and the optional `/` suffix used in the archive format.
    fn name_str(&self) -> String {
        let mut end = self.ar_name.len();
        // Trim trailing spaces
        while end > 0 && self.ar_name[end - 1] == b' ' {
            end -= 1;
        }
        let name = &self.ar_name[..end];
        String::from_utf8_lossy(name).into_owned()
    }

    /// Parses the `ar_size` field as a usize.
    fn size(&self) -> usize {
        let s = String::from_utf8_lossy(&self.ar_size);
        s.trim().parse::<usize>().unwrap_or(0)
    }
}

// ============================================================================
// Helper: Little-Endian to Big-Endian (Network Byte Order)
// ============================================================================

/// Converts a 32-bit value from host byte order (assumed little-endian) to
/// big-endian (network byte order) for the archive symbol index.
///
/// The archive symbol index stores counts and offsets in big-endian format
/// per the System V ar specification.
#[inline]
fn to_big_endian_u32(val: u32) -> u32 {
    val.to_be()
}

// ============================================================================
// Helper: Extract base filename from a path
// ============================================================================

/// Extracts the file name component from a path string, similar to C's
/// `tcc_basename()`. Returns the last path component, or the entire
/// string if no directory separator is found.
fn basename(path: &str) -> &str {
    Path::new(path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(path)
}

// ============================================================================
// ELF Symbol Extraction — 32-bit and 64-bit implementations
// ============================================================================

/// Extracts global/defined symbols from a 32-bit ELF object file.
fn extract_elf32_symbols(data: &[u8]) -> Option<ElfSymbols> {
    if data.len() < mem::size_of::<Elf32_Ehdr>() {
        return None;
    }

    // Parse ELF32 header using safe byte-level reads
    // Elf32_Ehdr layout: e_ident(16), e_type(2), e_machine(2), e_version(4),
    //   e_entry(4), e_phoff(4), e_shoff(4@32), e_flags(4), e_ehsize(2),
    //   e_phentsize(2), e_phnum(2), e_shentsize(2@46), e_shnum(2@48), e_shstrndx(2@50)
    let e_shoff = read_u32_le(data, 32) as usize;
    let e_shentsize = read_u16_le(data, 46) as usize;
    let e_shnum = read_u16_le(data, 48) as usize;
    let e_shstrndx = read_u16_le(data, 50) as usize;

    if e_shoff == 0 || e_shnum == 0 || e_shentsize == 0 {
        return None;
    }

    // Read section name string table offset
    if e_shstrndx >= e_shnum {
        return None;
    }
    let shstr_hdr_off = e_shoff + e_shstrndx * e_shentsize;
    if shstr_hdr_off + e_shentsize > data.len() {
        return None;
    }
    // Elf32_Shdr: sh_name(4), sh_type(4), sh_flags(4), sh_addr(4), sh_offset(4@16), sh_size(4@20)
    let shstr_sh_offset = read_u32_le(data, shstr_hdr_off + 16) as usize;

    // Find .symtab and .strtab sections
    let mut symtab_offset: usize = 0;
    let mut symtab_size: usize = 0;
    let mut strtab_offset: usize = 0;

    for i in 0..e_shnum {
        let sh_base = e_shoff + i * e_shentsize;
        if sh_base + e_shentsize > data.len() {
            break;
        }
        let sh_name = read_u32_le(data, sh_base) as usize;
        let sh_type = read_u32_le(data, sh_base + 4);
        let sh_offset = read_u32_le(data, sh_base + 16) as usize;
        let sh_size = read_u32_le(data, sh_base + 20) as usize;

        if sh_type == SHT_SYMTAB {
            symtab_offset = sh_offset;
            symtab_size = sh_size;
        }
        if sh_type == SHT_STRTAB && shstr_sh_offset > 0 {
            // Verify it's ".strtab" (not ".shstrtab")
            let name = read_c_string(data, shstr_sh_offset + sh_name);
            if name == ".strtab" {
                strtab_offset = sh_offset;
            }
        }
    }

    if symtab_offset == 0 || strtab_offset == 0 {
        return Some(ElfSymbols { names: Vec::new() });
    }

    // Extract global symbols
    // Elf32_Sym: st_name(4), st_value(4), st_size(4), st_info(1@12), st_other(1), st_shndx(2@14)
    let sym_entry_size = mem::size_of::<Elf32_Sym>(); // 16 bytes
    let nsym = symtab_size / sym_entry_size;
    let mut names = Vec::new();

    for i in 1..nsym {
        // skip index 0 (undefined)
        let sym_off = symtab_offset + i * sym_entry_size;
        if sym_off + sym_entry_size > data.len() {
            break;
        }
        let st_name = read_u32_le(data, sym_off) as usize;
        let st_info = data[sym_off + 12];
        let st_shndx = read_u16_le(data, sym_off + 14);

        if is_global_defined_symbol(st_info, st_shndx) {
            if let Some(name) = read_symbol_name(data, strtab_offset, st_name) {
                if !name.is_empty() {
                    names.push(name);
                }
            }
        }
    }

    Some(ElfSymbols { names })
}

/// Extracts global/defined symbols from a 64-bit ELF object file.
fn extract_elf64_symbols(data: &[u8]) -> Option<ElfSymbols> {
    if data.len() < mem::size_of::<Elf64_Ehdr>() {
        return None;
    }

    // Parse ELF64 header
    // Elf64_Ehdr layout: e_ident(16), e_type(2), e_machine(2), e_version(4),
    //   e_entry(8), e_phoff(8), e_shoff(8@40), e_flags(4), e_ehsize(2),
    //   e_phentsize(2), e_phnum(2), e_shentsize(2@58), e_shnum(2@60), e_shstrndx(2@62)
    let e_shoff = read_u64_le(data, 40) as usize;
    let e_shentsize = read_u16_le(data, 58) as usize;
    let e_shnum = read_u16_le(data, 60) as usize;
    let e_shstrndx = read_u16_le(data, 62) as usize;

    if e_shoff == 0 || e_shnum == 0 || e_shentsize == 0 {
        return None;
    }

    // Read section name string table offset
    if e_shstrndx >= e_shnum {
        return None;
    }
    let shstr_hdr_off = e_shoff + e_shstrndx * e_shentsize;
    if shstr_hdr_off + e_shentsize > data.len() {
        return None;
    }
    // Elf64_Shdr: sh_name(4), sh_type(4), sh_flags(8), sh_addr(8), sh_offset(8@24), sh_size(8@32)
    let shstr_sh_offset = read_u64_le(data, shstr_hdr_off + 24) as usize;

    // Find .symtab and .strtab sections
    let mut symtab_offset: usize = 0;
    let mut symtab_size: usize = 0;
    let mut strtab_offset: usize = 0;

    for i in 0..e_shnum {
        let sh_base = e_shoff + i * e_shentsize;
        if sh_base + e_shentsize > data.len() {
            break;
        }
        let sh_name = read_u32_le(data, sh_base) as usize;
        let sh_type = read_u32_le(data, sh_base + 4);
        let sh_offset = read_u64_le(data, sh_base + 24) as usize;
        let sh_size = read_u64_le(data, sh_base + 32) as usize;

        if sh_type == SHT_SYMTAB {
            symtab_offset = sh_offset;
            symtab_size = sh_size;
        }
        if sh_type == SHT_STRTAB && shstr_sh_offset > 0 {
            let name = read_c_string(data, shstr_sh_offset + sh_name);
            if name == ".strtab" {
                strtab_offset = sh_offset;
            }
        }
    }

    if symtab_offset == 0 || strtab_offset == 0 {
        return Some(ElfSymbols { names: Vec::new() });
    }

    // Extract global symbols
    // Elf64_Sym: st_name(4@0), st_info(1@4), st_other(1@5), st_shndx(2@6), st_value(8), st_size(8) = 24 bytes
    let sym_entry_size = mem::size_of::<Elf64_Sym>(); // 24 bytes
    let nsym = symtab_size / sym_entry_size;
    let mut names = Vec::new();

    for i in 1..nsym {
        let sym_off = symtab_offset + i * sym_entry_size;
        if sym_off + sym_entry_size > data.len() {
            break;
        }
        let st_name = read_u32_le(data, sym_off) as usize;
        let st_info = data[sym_off + 4];
        let st_shndx = read_u16_le(data, sym_off + 6);

        if is_global_defined_symbol(st_info, st_shndx) {
            if let Some(name) = read_symbol_name(data, strtab_offset, st_name) {
                if !name.is_empty() {
                    names.push(name);
                }
            }
        }
    }

    Some(ElfSymbols { names })
}

/// Determines if a symbol is a global/weak defined symbol that should
/// appear in the archive symbol index.
///
/// Matches the C code's `st_info` check values: `0x10`, `0x11`, `0x12`,
/// `0x20`, `0x21`, `0x22`. These correspond to:
/// - `0x10` = `STB_GLOBAL | STT_NOTYPE`
/// - `0x11` = `STB_GLOBAL | STT_OBJECT`
/// - `0x12` = `STB_GLOBAL | STT_FUNC`
/// - `0x20` = `STB_WEAK   | STT_NOTYPE`
/// - `0x21` = `STB_WEAK   | STT_OBJECT`
/// - `0x22` = `STB_WEAK   | STT_FUNC`
#[inline]
fn is_global_defined_symbol(st_info: u8, st_shndx: u16) -> bool {
    if st_shndx == SHN_UNDEF {
        return false;
    }
    matches!(st_info, 0x10 | 0x11 | 0x12 | 0x20 | 0x21 | 0x22)
}

// ============================================================================
// Byte-level reading helpers (safe, bounds-checked)
// ============================================================================

/// Reads a little-endian `u16` from the data buffer at the given offset.
/// Returns `0` if the offset is out of bounds.
#[inline]
fn read_u16_le(data: &[u8], offset: usize) -> u16 {
    if offset + 2 > data.len() {
        return 0;
    }
    u16::from_le_bytes([data[offset], data[offset + 1]])
}

/// Reads a little-endian `u32` from the data buffer at the given offset.
/// Returns `0` if the offset is out of bounds.
#[inline]
fn read_u32_le(data: &[u8], offset: usize) -> u32 {
    if offset + 4 > data.len() {
        return 0;
    }
    u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ])
}

/// Reads a little-endian `u64` from the data buffer at the given offset.
/// Returns `0` if the offset is out of bounds.
#[inline]
fn read_u64_le(data: &[u8], offset: usize) -> u64 {
    if offset + 8 > data.len() {
        return 0;
    }
    u64::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
        data[offset + 4],
        data[offset + 5],
        data[offset + 6],
        data[offset + 7],
    ])
}

/// Reads a null-terminated C string from the data buffer starting at the given offset.
/// Returns an empty string if the offset is out of bounds.
fn read_c_string(data: &[u8], offset: usize) -> String {
    if offset >= data.len() {
        return String::new();
    }
    let mut end = offset;
    while end < data.len() && data[end] != 0 {
        end += 1;
    }
    String::from_utf8_lossy(&data[offset..end]).into_owned()
}

/// Reads a symbol name from the ELF string table at the given name offset.
fn read_symbol_name(data: &[u8], strtab_offset: usize, name_offset: usize) -> Option<String> {
    let abs_offset = strtab_offset + name_offset;
    if abs_offset >= data.len() {
        return None;
    }
    Some(read_c_string(data, abs_offset))
}

// ============================================================================
// tool_ar — Built-in archive creation tool
// ============================================================================

/// Built-in archive (`.a`) creation tool, replacing `tcc_tool_ar()` from `tcctools.c`.
///
/// Creates, lists, or extracts static library archives in the standard Unix `ar`
/// format. This is a key TCC feature: the compiler can create static libraries
/// without requiring an external `ar` binary.
///
/// # Arguments
///
/// * `args` — Command-line arguments after the `-ar` flag, e.g. `["rcs", "libfoo.a", "foo.o", "bar.o"]`.
///
/// # Supported Operations
///
/// - `r`/`c`/`s` — Create archive with symbol index (default)
/// - `x` — Extract members from archive
/// - `t` — List archive contents
/// - `v` — Verbose output
///
/// # Errors
///
/// Returns `TccError::IoError` for file I/O failures, `TccError::ConfigError`
/// for invalid arguments, and `TccError::InternalError` for malformed ELF inputs.
pub fn tool_ar(args: &[String]) -> TccResult<()> {
    let ops_conflict = "habdiopN";
    let mut extract = false;
    let mut table = false;
    let mut verbose = false;
    let mut i_lib: Option<usize> = None;
    let mut i_obj: Option<usize> = None;
    let mut invalid = false;

    // Parse arguments: find options, library path, and first object path
    for (i, a) in args.iter().enumerate() {
        let a_str = a.as_str();
        // Detect `-x.y` pattern (always invalid, matching GNU ar behavior)
        if a_str.starts_with('-') && a_str.contains('.') {
            invalid = true;
        }
        // Options: starts with '-' or is the first arg without a '.' (e.g. "rcs")
        if a_str.starts_with('-') || (i == 0 && !a_str.contains('.')) {
            if a_str.bytes().any(|c| ops_conflict.as_bytes().contains(&c)) {
                invalid = true;
            }
            if a_str.contains('x') {
                extract = true;
            }
            if a_str.contains('t') {
                table = true;
            }
            if a_str.contains('v') {
                verbose = true;
            }
        } else {
            // Non-option argument: library or object file
            if i_lib.is_none() {
                i_lib = Some(i);
            } else if i_obj.is_none() {
                i_obj = Some(i);
            }
        }
    }

    // Must have at least a library file
    if i_lib.is_none() {
        invalid = true;
    }

    if invalid {
        eprintln!("usage: tcc -ar [crstvx] lib [files]");
        eprintln!("create library ([abdiopN] not supported).");
        return Err(TccError::config("invalid ar arguments"));
    }

    let lib_idx = i_lib.unwrap();
    let lib_path = &args[lib_idx];
    let obj_start = i_obj.unwrap_or(args.len());

    // -----------------------------------------------------------------------
    // Extract or Table (listing) mode
    // -----------------------------------------------------------------------
    if extract || table {
        return ar_extract_or_list(lib_path, extract, table, verbose);
    }

    // -----------------------------------------------------------------------
    // Create mode (default: rcs)
    // -----------------------------------------------------------------------
    ar_create(lib_path, args, obj_start, verbose)
}

// ============================================================================
// Helper: ELF Symbol Extraction for Archive Index
// ============================================================================

/// Information about global symbols extracted from an ELF object file.
/// Used to build the archive symbol index (the `/` pseudo-member).
struct ElfSymbols {
    /// Global symbol names found in the object file.
    names: Vec<String>,
}

/// Extracts global/defined symbol names from an ELF object file's data buffer.
///
/// Reads the ELF header to determine class (32/64-bit), locates the `.symtab`
/// and `.strtab` sections, and collects names of symbols that are:
/// - Defined (st_shndx != SHN_UNDEF)
/// - Global or weak binding (st_info indicates STB_GLOBAL or STB_WEAK scope
///   with OBJECT, FUNC, or NOTYPE type)
///
/// This matches the C code's symbol filtering logic which checks specific
/// `st_info` values: 0x10, 0x11, 0x12, 0x20, 0x21, 0x22.
fn extract_elf_symbols(data: &[u8]) -> Option<ElfSymbols> {
    if data.len() < mem::size_of::<Elf64_Ehdr>() {
        return None;
    }

    // Check ELF magic
    if data.len() < 4 || data[0] != 0x7f || data[1] != b'E' || data[2] != b'L' || data[3] != b'F'
    {
        return None;
    }

    let elf_class = data[EI_CLASS];
    match elf_class {
        ELFCLASS32 => extract_elf32_symbols(data),
        ELFCLASS64 => extract_elf64_symbols(data),
        _ => None,
    }
}

// ============================================================================
// ar sub-operations: extract/list and create
// ============================================================================

/// Handles `ar x` (extract) and `ar t` (table/list) operations on an existing archive.
fn ar_extract_or_list(
    lib_path: &str,
    extract: bool,
    _table: bool,
    verbose: bool,
) -> TccResult<()> {
    let data = fs::read(lib_path).map_err(|e| {
        eprintln!("tcc: ar: can't open file {}", lib_path);
        TccError::IoError(e)
    })?;

    // Verify archive magic
    if data.len() < SARMAG || &data[..SARMAG] != ARMAG.as_slice() {
        eprintln!("tcc: ar: not an ar archive {}", lib_path);
        return Err(TccError::config(format!(
            "not an ar archive: {}",
            lib_path
        )));
    }

    let mut pos = SARMAG;

    while pos + AR_HDR_SIZE <= data.len() {
        // Read member header
        let mut hdr_bytes = [0u8; AR_HDR_SIZE];
        hdr_bytes.copy_from_slice(&data[pos..pos + AR_HDR_SIZE]);
        let hdr = ArHdr::from_bytes(&hdr_bytes);
        pos += AR_HDR_SIZE;

        // Validate format magic
        if &hdr.ar_fmag != ARFMAG {
            eprintln!("tcc: ar: not an ar archive {}", lib_path);
            return Err(TccError::config(format!(
                "not an ar archive: {}",
                lib_path
            )));
        }

        // Get member name and file size
        let mut name = hdr.name_str();
        let fsize = hdr.size();

        if pos + fsize > data.len() {
            break;
        }
        let member_data = &data[pos..pos + fsize];

        // Skip special members ("/" is symbol index, "//" is long name table)
        if name != "/" && name != "//" && name != "/SYM64/" {
            // Strip trailing '/' from member name (ar format convention)
            if name.ends_with('/') {
                name.pop();
            }

            if verbose || !extract {
                // table mode or verbose extract
                let prefix = if extract { "x - " } else { "" };
                println!("{}{}", prefix, name);
            }

            if extract {
                let mut fo = File::create(&name).map_err(|e| {
                    eprintln!("tcc: ar: can't create file {}", name);
                    TccError::IoError(e)
                })?;
                fo.write_all(member_data)?;
            }
        }

        // Advance past member data, aligning to even boundary
        pos += fsize;
        if pos & 1 != 0 {
            pos += 1;
        }
    }

    Ok(())
}

/// Internal representation of an archive member (object file) being added.
struct ArMember {
    /// Base filename of the object file (used as the archive member name).
    name: String,
    /// Raw file data.
    data: Vec<u8>,
}

/// Creates a new archive file from the given object files with a symbol index.
///
/// Implements the core `ar rcs` workflow:
/// 1. Read each object file and parse ELF headers to collect global symbols
/// 2. Build a symbol index mapping symbol names to member positions
/// 3. Write the archive with ARMAG header, symbol index, and member data
fn ar_create(
    lib_path: &str,
    args: &[String],
    obj_start: usize,
    verbose: bool,
) -> TccResult<()> {
    // Collect object file data and symbols
    let mut members: Vec<ArMember> = Vec::new();
    let mut all_symbols: Vec<String> = Vec::new();
    let mut symbol_member_indices: Vec<usize> = Vec::new();

    for i in obj_start..args.len() {
        let arg = &args[i];
        // Skip options
        if arg.starts_with('-') {
            continue;
        }

        if verbose {
            println!("a - {}", arg);
        }

        let data = fs::read(arg).map_err(|e| {
            eprintln!("tcc: ar: can't open file {}", arg);
            TccError::IoError(e)
        })?;

        // Parse ELF to extract global symbols for the archive index
        if let Some(elf_syms) = extract_elf_symbols(&data) {
            for sym_name in &elf_syms.names {
                all_symbols.push(sym_name.clone());
                symbol_member_indices.push(members.len());
            }
        }

        let name = basename(arg).to_string();
        members.push(ArMember { name, data });
    }

    // Calculate member data positions within the file
    // Each member: ArHdr (60 bytes) + data + optional padding
    let mut member_file_positions: Vec<usize> = Vec::new();
    {
        let mut fpos: usize = 0;
        for m in &members {
            member_file_positions.push(fpos);
            fpos += AR_HDR_SIZE + m.data.len();
            if fpos & 1 != 0 {
                fpos += 1;
            }
        }
    }

    // Build symbol name table (NUL-terminated names concatenated)
    let mut sym_names_buf: Vec<u8> = Vec::new();
    for s in &all_symbols {
        sym_names_buf.extend_from_slice(s.as_bytes());
        sym_names_buf.push(0);
    }
    let strpos = sym_names_buf.len();
    let funccnt = all_symbols.len();

    // Calculate header offset:
    // = 8 (ARMAG) + 60 (index ArHdr) + (funccnt+1)*4 (count+offsets) + strpos (names)
    let mut hofs: usize = SARMAG + AR_HDR_SIZE + (funccnt + 1) * 4 + strpos;
    let mut extra_pad: usize = 0;
    if hofs & 1 != 0 {
        hofs += 1;
        extra_pad = 1;
    }

    // Open output archive
    let fo = File::create(lib_path).map_err(|e| {
        eprintln!("tcc: ar: can't create file {}", lib_path);
        TccError::IoError(e)
    })?;
    let mut writer = BufWriter::new(fo);

    // Write archive magic
    writer.write_all(ARMAG)?;

    // If there are no symbols, just write the members without an index
    if funccnt == 0 && members.is_empty() {
        writer.flush()?;
        return Ok(());
    }

    // Write symbol index header ("/" member)
    if funccnt > 0 {
        let index_size = (funccnt + 1) * 4 + strpos + extra_pad;
        let mut index_hdr = ArHdr::new();
        ArHdr::write_decimal(&mut index_hdr.ar_size, index_size);
        writer.write_all(&index_hdr.as_bytes())?;

        // Symbol count as big-endian u32
        writer.write_all(&to_big_endian_u32(funccnt as u32).to_ne_bytes())?;

        // File position for each symbol (big-endian u32)
        for &sym_member_idx in &symbol_member_indices {
            let offset = member_file_positions[sym_member_idx] + hofs;
            writer.write_all(&to_big_endian_u32(offset as u32).to_ne_bytes())?;
        }

        // Symbol names (NUL-terminated)
        writer.write_all(&sym_names_buf)?;

        // Alignment padding
        if extra_pad > 0 {
            writer.write_all(&[0u8])?;
        }
    }

    // Write member headers and data
    for m in &members {
        let hdr = ArHdr::for_object(&m.name, m.data.len());
        writer.write_all(&hdr.as_bytes())?;
        writer.write_all(&m.data)?;
        // Pad to even boundary
        if m.data.len() & 1 != 0 {
            writer.write_all(&[0u8])?;
        }
    }

    writer.flush()?;
    Ok(())
}

// ============================================================================
// gen_makedeps — Makefile Dependency Generation
// ============================================================================

/// Escapes spaces and tabs in a file path for Makefile dependency format.
///
/// Spaces and tabs in file paths are escaped with a preceding backslash so
/// that `make` interprets the path as a single token.
fn escape_target_dep(s: &str) -> String {
    let mut result = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        if c == ' ' || c == '\t' {
            result.push('\\');
        }
        result.push(c);
    }
    result
}

/// Generates a Makefile-format dependency file for the `-MD`/`-MF` compiler options.
///
/// Ported from `gen_makedeps()` in `tcctools.c`. Writes dependency rules:
///
/// ```text
/// target.o: \
///   source.c \
///   header1.h \
///   header2.h
/// ```
///
/// With `-MP` (phony deps), additionally:
/// ```text
/// header1.h:
/// header2.h:
/// ```
///
/// # Arguments
///
/// * `state` — Compiler state providing `target_deps` (tracked include files),
///   `verbose` flag, and `gen_phony_deps` flag.
/// * `target` — The rule target name (e.g., `"foo.o"`).
/// * `filename` — Output filename. `None` derives from target (e.g., `"foo.d"`).
///   `Some("-")` writes to stdout.
pub fn gen_makedeps(state: &TCCState, target: &str, filename: Option<&str>) -> TccResult<()> {
    // Determine output filename
    let auto_filename: String;
    let out_name = match filename {
        Some(name) => name,
        None => {
            let dot_pos = target.rfind('.').unwrap_or(target.len());
            auto_filename = format!("{}.d", &target[..dot_pos]);
            &auto_filename
        }
    };

    // Open output (stdout if "-", else file)
    let mut depout: Box<dyn Write> = if out_name == "-" {
        Box::new(io::stdout())
    } else {
        let f = File::create(out_name).map_err(|e| {
            TccError::IoError(io::Error::new(
                e.kind(),
                format!("could not open '{}'", out_name),
            ))
        })?;
        Box::new(BufWriter::new(f))
    };

    if state.verbose > 0 {
        println!("<- {}", out_name);
    }

    // Deduplicate dependencies while preserving order
    let mut seen: Vec<&str> = Vec::new();
    let mut escaped_targets: Vec<String> = Vec::new();

    for dep in &state.target_deps {
        let dep_str = dep.as_str();
        if !seen.contains(&dep_str) {
            seen.push(dep_str);
            escaped_targets.push(escape_target_dep(dep_str));
        }
    }

    // Write main dependency rule
    write!(depout, "{}:", target)?;
    for escaped in &escaped_targets {
        write!(depout, " \\\n  {}", escaped)?;
    }
    writeln!(depout)?;

    // Write phony targets for headers (-MP option)
    // Skip first dependency (the .c source file itself)
    if state.gen_phony_deps {
        for escaped in escaped_targets.iter().skip(1) {
            writeln!(depout, "{}:", escaped)?;
        }
    }

    depout.flush()?;
    Ok(())
}

// ============================================================================
// tool_impdef — Windows Import Definition File Generator
// ============================================================================

/// Generates a `.def` (import definition) file from a PE DLL's export table.
///
/// Ported from `tcc_tool_impdef()` in `tcctools.c`. Reads the PE export
/// directory and writes a `.def` file suitable for creating import libraries.
///
/// # Arguments
///
/// * `args` — Command-line arguments: `["library.dll", "-v", "-o", "output.def"]`.
///   - First non-option argument: input DLL path.
///   - `-o <file>` specifies the output `.def` file (default: derived from DLL name).
///   - `-v` enables verbose output.
pub fn tool_impdef(args: &[String]) -> TccResult<()> {
    let mut infile: Option<String> = None;
    let mut outfile: Option<String> = None;
    let mut verbose = false;

    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if a == "-v" {
            verbose = true;
        } else if a == "-o" {
            i += 1;
            if i >= args.len() {
                return Err(impdef_usage());
            }
            outfile = Some(args[i].clone());
        } else if a.starts_with('-') {
            return Err(impdef_usage());
        } else if infile.is_none() {
            infile = Some(a.clone());
        } else {
            return Err(impdef_usage());
        }
        i += 1;
    }

    let infile = match infile {
        Some(f) => f,
        None => return Err(impdef_usage()),
    };

    // Derive output filename if not specified
    let outfile = outfile.unwrap_or_else(|| {
        let base = basename(&infile);
        match base.rfind('.') {
            Some(pos) => format!("{}.def", &base[..pos]),
            None => format!("{}.def", base),
        }
    });

    // Read PE/DLL and extract export names
    let exports = read_pe_exports(&infile)?;

    if exports.is_empty() {
        eprintln!("tcc: impdef: no symbols found in '{}'", infile);
        return Err(TccError::config(format!(
            "no symbols found in '{}'",
            infile
        )));
    }

    if verbose {
        println!("-> {}", infile);
    }

    // Write .def file
    let mut f = File::create(&outfile).map_err(|e| {
        eprintln!("tcc: impdef: could not create output file: {}", outfile);
        TccError::IoError(e)
    })?;

    let lib_basename = basename(&infile);
    writeln!(f, "LIBRARY {}", lib_basename)?;
    writeln!(f)?;
    writeln!(f, "EXPORTS")?;
    for name in &exports {
        writeln!(f, "{}", name)?;
    }

    if verbose {
        let count = exports.len();
        let plural = if count < 2 { "" } else { "s" };
        println!("<- {} ({} symbol{})", outfile, count, plural);
    }

    Ok(())
}

/// Returns a usage error for the impdef tool.
fn impdef_usage() -> TccError {
    eprintln!("usage: tcc -impdef library.dll [-v] [-o outputfile]");
    eprintln!("create export definition file (.def) from dll");
    TccError::config("invalid impdef arguments")
}

/// Reads PE export table from a DLL file and returns exported symbol names.
///
/// Handles both PE32 and PE32+ (64-bit) formats by parsing the DOS header,
/// COFF header, optional header, and export directory.
fn read_pe_exports(dll_path: &str) -> TccResult<Vec<String>> {
    let data = fs::read(dll_path).map_err(|e| {
        eprintln!("tcc: impdef: can't find file '{}'", dll_path);
        TccError::IoError(e)
    })?;

    // Check MZ (DOS) header magic
    if data.len() < 64 || data[0] != b'M' || data[1] != b'Z' {
        return Err(TccError::config(format!(
            "unknown file type: '{}'",
            dll_path
        )));
    }

    // Get PE header offset from DOS header (at offset 0x3C)
    let pe_offset = read_u32_le(&data, 0x3C) as usize;
    if pe_offset + 4 > data.len() {
        return Err(TccError::config(format!(
            "can't read symbols: '{}'",
            dll_path
        )));
    }

    // Check PE signature ("PE\0\0")
    if &data[pe_offset..pe_offset + 4] != b"PE\0\0" {
        return Err(TccError::config(format!(
            "unknown file type: '{}'",
            dll_path
        )));
    }

    // Parse COFF header (starts at pe_offset + 4)
    let coff_offset = pe_offset + 4;
    let num_sections = read_u16_le(&data, coff_offset + 2) as usize;
    let optional_header_size = read_u16_le(&data, coff_offset + 16) as usize;

    // Parse optional header to find export directory RVA
    let opt_offset = coff_offset + 20;
    if opt_offset + 2 > data.len() {
        return Err(TccError::config(format!(
            "can't read symbols: '{}'",
            dll_path
        )));
    }

    let magic = read_u16_le(&data, opt_offset);
    let export_dir_rva_offset = match magic {
        0x10b => opt_offset + 96,  // PE32
        0x20b => opt_offset + 112, // PE32+ (64-bit)
        _ => {
            return Err(TccError::config(format!(
                "unknown PE magic: 0x{:04x} in '{}'",
                magic, dll_path
            )));
        }
    };

    if export_dir_rva_offset + 8 > data.len() {
        return Err(TccError::config(format!(
            "can't read symbols: '{}'",
            dll_path
        )));
    }

    let export_rva = read_u32_le(&data, export_dir_rva_offset) as usize;
    if export_rva == 0 {
        return Ok(Vec::new());
    }

    // Parse section headers to resolve RVA to file offset
    let sections_offset = opt_offset + optional_header_size;
    let file_offset = rva_to_file_offset(&data, sections_offset, num_sections, export_rva);
    let file_offset = match file_offset {
        Some(off) => off,
        None => return Ok(Vec::new()),
    };

    // Parse export directory table (40 bytes)
    if file_offset + 40 > data.len() {
        return Ok(Vec::new());
    }

    let num_names = read_u32_le(&data, file_offset + 24) as usize;
    let names_rva = read_u32_le(&data, file_offset + 32) as usize;

    let names_offset =
        match rva_to_file_offset(&data, sections_offset, num_sections, names_rva) {
            Some(off) => off,
            None => return Ok(Vec::new()),
        };

    let mut exports = Vec::with_capacity(num_names);
    for i in 0..num_names {
        let name_ptr_offset = names_offset + i * 4;
        if name_ptr_offset + 4 > data.len() {
            break;
        }
        let name_rva = read_u32_le(&data, name_ptr_offset) as usize;
        let name_file_offset =
            match rva_to_file_offset(&data, sections_offset, num_sections, name_rva) {
                Some(off) => off,
                None => continue,
            };
        let name = read_c_string(&data, name_file_offset);
        if !name.is_empty() {
            exports.push(name);
        }
    }

    Ok(exports)
}

/// Converts a PE Relative Virtual Address (RVA) to a file offset by
/// searching the section headers. Each section header is 40 bytes.
fn rva_to_file_offset(
    data: &[u8],
    sections_offset: usize,
    num_sections: usize,
    rva: usize,
) -> Option<usize> {
    for i in 0..num_sections {
        let sh_off = sections_offset + i * 40;
        if sh_off + 40 > data.len() {
            break;
        }
        let virtual_size = read_u32_le(data, sh_off + 8) as usize;
        let virtual_addr = read_u32_le(data, sh_off + 12) as usize;
        let raw_data_ptr = read_u32_le(data, sh_off + 20) as usize;

        if rva >= virtual_addr && rva < virtual_addr + virtual_size {
            return Some(rva - virtual_addr + raw_data_ptr);
        }
    }
    None
}

// ============================================================================
// tool_cross — Cross-Compiler Re-execution
// ============================================================================

/// Re-executes the compiler with the appropriate cross-compiler binary for
/// `-m32`/`-m64` option handling.
///
/// Ported from `tcc_tool_cross()` in `tcctools.c`. Constructs the path to
/// the target-specific binary (e.g., `i386-tcc` or `x86_64-tcc`) by replacing
/// the basename in `argv[0]` and re-invokes it via `std::process::Command`.
///
/// # Arguments
///
/// * `argv` — Full command-line arguments. `argv[0]` is the current binary path.
/// * `target` — Target bit width: `32` for i386 or `64` for x86_64.
///
/// # Behavior
///
/// 1. Extracts directory prefix from `argv[0]`.
/// 2. Appends `{arch}-tcc[.exe]` to form the cross-compiler path.
/// 3. Invokes the cross-compiler; exits with its exit code on success.
/// 4. Returns error if cross-compiler cannot be found/executed.
pub fn tool_cross(argv: &[String], target: i32) -> TccResult<()> {
    if argv.is_empty() {
        return Err(TccError::config("tool_cross: empty argv"));
    }

    let a0 = &argv[0];

    // Extract the directory prefix from argv[0]
    let prefix = match a0.rfind('/') {
        Some(pos) => &a0[..=pos],
        None => {
            match a0.rfind('\\') {
                Some(pos) => &a0[..=pos],
                None => "",
            }
        }
    };

    // Construct the cross-compiler binary name
    let arch = if target == 64 { "x86_64" } else { "i386" };
    let mut program = format!("{}{}-tcc", prefix, arch);

    // On Windows, append .exe extension
    if cfg!(target_os = "windows") {
        program.push_str(".exe");
    }

    // Only re-execute if the program name is different from current
    if a0 != &program {
        let new_args: Vec<&str> = argv[1..].iter().map(|s| s.as_str()).collect();

        let status = Command::new(&program)
            .args(&new_args)
            .status()
            .map_err(|_| TccError::config(format!("could not run '{}'", program)))?;

        // Exit with the cross-compiler's exit code
        process::exit(status.code().unwrap_or(1));
    }

    eprintln!("tcc: could not run '{}'", program);
    Err(TccError::config(format!("could not run '{}'", program)))
}

// ============================================================================
// Unit tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_armag_constant() {
        assert_eq!(ARMAG, b"!<arch>\n");
        assert_eq!(ARMAG.len(), 8);
    }

    #[test]
    fn test_arfmag_constant() {
        assert_eq!(ARFMAG, b"`\n");
        assert_eq!(ARFMAG.len(), 2);
    }

    #[test]
    fn test_arhdr_size() {
        assert_eq!(AR_HDR_SIZE, 60);
    }

    #[test]
    fn test_arhdr_new() {
        let hdr = ArHdr::new();
        assert_eq!(hdr.ar_name[0], b'/');
        assert_eq!(hdr.ar_fmag, *ARFMAG);
        assert_eq!(hdr.ar_date[0], b'0');
    }

    #[test]
    fn test_arhdr_for_object() {
        let hdr = ArHdr::for_object("test.o", 1234);
        let name_str = hdr.name_str();
        assert!(name_str.starts_with("test.o"));
        assert_eq!(hdr.size(), 1234);
        assert_eq!(&hdr.ar_mode[..6], b"100644");
        assert_eq!(hdr.ar_fmag, *ARFMAG);
    }

    #[test]
    fn test_arhdr_roundtrip() {
        let orig = ArHdr::for_object("hello.o", 4096);
        let bytes = orig.as_bytes();
        assert_eq!(bytes.len(), AR_HDR_SIZE);
        let parsed = ArHdr::from_bytes(&bytes);
        assert_eq!(parsed.ar_name, orig.ar_name);
        assert_eq!(parsed.ar_size, orig.ar_size);
        assert_eq!(parsed.ar_fmag, orig.ar_fmag);
    }

    #[test]
    fn test_basename_fn() {
        assert_eq!(basename("/usr/lib/libfoo.a"), "libfoo.a");
        assert_eq!(basename("libfoo.a"), "libfoo.a");
        assert_eq!(basename("path/to/file.o"), "file.o");
    }

    #[test]
    fn test_escape_target_dep() {
        assert_eq!(escape_target_dep("foo.h"), "foo.h");
        assert_eq!(escape_target_dep("my file.h"), "my\\ file.h");
        assert_eq!(escape_target_dep("a\tb"), "a\\\tb");
    }

    #[test]
    fn test_to_big_endian() {
        let val = to_big_endian_u32(1);
        let bytes = val.to_ne_bytes();
        assert_eq!(bytes, [0, 0, 0, 1]);
    }

    #[test]
    fn test_to_big_endian_zero() {
        let val = to_big_endian_u32(0);
        let bytes = val.to_ne_bytes();
        assert_eq!(bytes, [0, 0, 0, 0]);
    }

    #[test]
    fn test_read_u16_le() {
        let data = [0x01, 0x02, 0x03, 0x04];
        assert_eq!(read_u16_le(&data, 0), 0x0201);
        assert_eq!(read_u16_le(&data, 2), 0x0403);
        // Out of bounds returns 0
        assert_eq!(read_u16_le(&data, 3), 0);
    }

    #[test]
    fn test_read_u32_le() {
        let data = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        assert_eq!(read_u32_le(&data, 0), 0x04030201);
        assert_eq!(read_u32_le(&data, 4), 0x08070605);
        assert_eq!(read_u32_le(&data, 5), 0);
    }

    #[test]
    fn test_read_u64_le() {
        let data = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        assert_eq!(read_u64_le(&data, 0), 0x0807060504030201);
        assert_eq!(read_u64_le(&data, 1), 0);
    }

    #[test]
    fn test_read_c_string() {
        let data = b"hello\0world\0";
        assert_eq!(read_c_string(data, 0), "hello");
        assert_eq!(read_c_string(data, 6), "world");
        assert_eq!(read_c_string(data, 12), "");
    }

    #[test]
    fn test_read_c_string_no_null() {
        let data = b"hello";
        assert_eq!(read_c_string(data, 0), "hello");
    }

    #[test]
    fn test_is_global_defined_symbol_valid() {
        // STB_GLOBAL | STT_FUNC = 0x12, defined section
        assert!(is_global_defined_symbol(0x12, 1));
        // STB_GLOBAL | STT_NOTYPE = 0x10
        assert!(is_global_defined_symbol(0x10, 1));
        // STB_GLOBAL | STT_OBJECT = 0x11
        assert!(is_global_defined_symbol(0x11, 1));
        // STB_WEAK | STT_NOTYPE = 0x20
        assert!(is_global_defined_symbol(0x20, 1));
        // STB_WEAK | STT_OBJECT = 0x21
        assert!(is_global_defined_symbol(0x21, 1));
        // STB_WEAK | STT_FUNC = 0x22
        assert!(is_global_defined_symbol(0x22, 1));
    }

    #[test]
    fn test_is_global_defined_symbol_invalid() {
        // Undefined (SHN_UNDEF = 0)
        assert!(!is_global_defined_symbol(0x12, 0));
        // STB_LOCAL | STT_FUNC = 0x02
        assert!(!is_global_defined_symbol(0x02, 1));
        // STB_LOCAL | STT_NOTYPE = 0x00
        assert!(!is_global_defined_symbol(0x00, 1));
    }

    #[test]
    fn test_write_decimal() {
        let mut field = [b' '; 10];
        ArHdr::write_decimal(&mut field, 12345);
        assert_eq!(&field[..5], b"12345");
        assert_eq!(field[5], b' ');
    }

    #[test]
    fn test_write_decimal_zero() {
        let mut field = [b' '; 10];
        ArHdr::write_decimal(&mut field, 0);
        assert_eq!(field[0], b'0');
        assert_eq!(field[1], b' ');
    }

    #[test]
    fn test_extract_elf_symbols_non_elf() {
        let data = b"not an elf file at all";
        assert!(extract_elf_symbols(data).is_none());
    }

    #[test]
    fn test_extract_elf_symbols_too_short() {
        let data = [0x7f, b'E', b'L', b'F'];
        assert!(extract_elf_symbols(&data).is_none());
    }

    #[test]
    fn test_tool_ar_no_args() {
        let args: Vec<String> = vec![];
        let result = tool_ar(&args);
        assert!(result.is_err());
    }

    #[test]
    fn test_tool_ar_invalid_ops() {
        let args = vec!["habcd".to_string(), "lib.a".to_string()];
        let result = tool_ar(&args);
        assert!(result.is_err());
    }

    #[test]
    fn test_tool_impdef_no_args() {
        let args: Vec<String> = vec![];
        let result = tool_impdef(&args);
        assert!(result.is_err());
    }

    #[test]
    fn test_tool_cross_empty_argv() {
        let argv: Vec<String> = vec![];
        let result = tool_cross(&argv, 64);
        assert!(result.is_err());
    }

    #[test]
    fn test_rva_to_file_offset_no_match() {
        // Empty section data
        assert!(rva_to_file_offset(&[], 0, 0, 0x1000).is_none());
    }

    #[test]
    fn test_rva_to_file_offset_match() {
        // Craft a minimal section header (40 bytes):
        // Offset 8: virtual_size = 0x2000
        // Offset 12: virtual_addr = 0x1000
        // Offset 20: raw_data_ptr = 0x200
        let mut section = [0u8; 40];
        // virtual_size at +8
        section[8] = 0x00;
        section[9] = 0x20;
        section[10] = 0x00;
        section[11] = 0x00;
        // virtual_addr at +12
        section[12] = 0x00;
        section[13] = 0x10;
        section[14] = 0x00;
        section[15] = 0x00;
        // raw_data_ptr at +20
        section[20] = 0x00;
        section[21] = 0x02;
        section[22] = 0x00;
        section[23] = 0x00;

        let result = rva_to_file_offset(&section, 0, 1, 0x1000);
        // file_offset = rva(0x1000) - virtual_addr(0x1000) + raw_data_ptr(0x200)
        assert_eq!(result, Some(0x200));

        let result2 = rva_to_file_offset(&section, 0, 1, 0x1100);
        assert_eq!(result2, Some(0x300));
    }

    #[test]
    fn test_ar_create_and_list_roundtrip() {
        // Create a temporary archive with some dummy data
        let dir = std::env::temp_dir();
        let archive_path = dir.join("blitzy_test_roundtrip.a");

        // Create a minimal "object file" (not real ELF, but tests the data flow)
        let obj_path = dir.join("blitzy_test_obj.o");
        fs::write(&obj_path, b"dummy object data").unwrap();

        let args = vec![
            "rcs".to_string(),
            archive_path.to_string_lossy().to_string(),
            obj_path.to_string_lossy().to_string(),
        ];

        // Create archive
        let result = tool_ar(&args);
        assert!(result.is_ok(), "ar create failed: {:?}", result);

        // Verify archive exists and starts with magic
        let archive_data = fs::read(&archive_path).unwrap();
        assert!(archive_data.len() >= SARMAG);
        assert_eq!(&archive_data[..SARMAG], ARMAG.as_slice());

        // Clean up
        let _ = fs::remove_file(&archive_path);
        let _ = fs::remove_file(&obj_path);
    }
}
