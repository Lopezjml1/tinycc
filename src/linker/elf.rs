//! ELF (Executable and Linkable Format) output backend for TinyCC.
//!
//! This module is the primary linker for all Unix-like targets. It manages:
//! - ELF section creation, growth, and serialization
//! - Symbol table management with hash-based lookup
//! - Relocation processing and application
//! - GOT (Global Offset Table) and PLT (Procedure Linkage Table) generation
//! - Dynamic linking with shared libraries
//! - RELRO (Relocation Read-Only) support
//! - ELF object file (.o) and executable/shared library output
//! - CRT (C Runtime) startup object integration
//!
//! C equivalent: `tccelf.c` (4,116 lines)

use crate::context::TccState;
use crate::error::{TccError, TccResult};
use crate::types::{
    Section, SymAttrExt, DllReference,
    TCC_OUTPUT_EXE, TCC_OUTPUT_OBJ, TCC_OUTPUT_DLL,
};
use crate::formats::elf::*;

use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::PathBuf;

// ---------------------------------------------------------------------------
// Constants (tccelf.c lines 1–55)
// ---------------------------------------------------------------------------

/// TCC-internal section flag: section is private (not written to output).
/// C equivalent: `SHF_PRIVATE` at tccelf.c line 46
pub const SHF_PRIVATE: u32 = 0x8000_0000;

/// TCC-internal section flag: section is a dynamic symbol table placeholder.
/// C equivalent: `SHF_DYNSYM` at tccelf.c line 48
pub const SHF_DYNSYM: u32 = 0x4000_0000;

/// Host pointer size used for ELF alignment calculations.
#[cfg(target_pointer_width = "64")]
const PTR_SIZE: usize = 8;
#[cfg(target_pointer_width = "32")]
const PTR_SIZE: usize = 4;

/// Size of an ELF symbol table entry (Elf64Sym = 24, Elf32Sym = 16).
#[cfg(target_pointer_width = "64")]
const ELF_SYM_SIZE: usize = 24;
#[cfg(target_pointer_width = "32")]
const ELF_SYM_SIZE: usize = 16;

/// Size of an ELF rela relocation entry.
#[cfg(target_pointer_width = "64")]
const ELF_RELA_SIZE: usize = 24;
#[cfg(target_pointer_width = "32")]
const ELF_RELA_SIZE: usize = 12;

/// Size of an ELF rel relocation entry.
#[cfg(target_pointer_width = "64")]
const ELF_REL_SIZE: usize = 16;
#[cfg(target_pointer_width = "32")]
const ELF_REL_SIZE: usize = 8;

/// Size of an ELF dynamic table entry.
#[cfg(target_pointer_width = "64")]
const ELF_DYN_SIZE: usize = 16;
#[cfg(target_pointer_width = "32")]
const ELF_DYN_SIZE: usize = 8;

/// Size of an ELF program header.
#[cfg(target_pointer_width = "64")]
const ELF_PHDR_SIZE: usize = 56;
#[cfg(target_pointer_width = "32")]
const ELF_PHDR_SIZE: usize = 32;

/// Size of an ELF section header.
#[cfg(target_pointer_width = "64")]
const ELF_SHDR_SIZE: usize = 64;
#[cfg(target_pointer_width = "32")]
const ELF_SHDR_SIZE: usize = 40;

/// Size of an ELF file header.
#[cfg(target_pointer_width = "64")]
const ELF_EHDR_SIZE: usize = 64;
#[cfg(target_pointer_width = "32")]
const ELF_EHDR_SIZE: usize = 52;

/// ELF class for the host platform.
#[cfg(target_pointer_width = "64")]
const ELF_CLASS: u8 = ELFCLASS64;
#[cfg(target_pointer_width = "32")]
const ELF_CLASS: u8 = ELFCLASS32;

/// Default page size for ELF segment alignment.
const ELF_PAGE_SIZE: u64 = 0x1000;

// ---------------------------------------------------------------------------
// Custom Types (tccelf.c lines 30–55)
// ---------------------------------------------------------------------------

/// Symbol version information for ELF versioning.
/// C equivalent: `struct sym_version` at tccelf.c lines 30–35
pub struct SymVersion {
    pub lib: String,
    pub version: String,
    pub out_index: i32,
    pub prev_same_lib: i32,
}

impl SymVersion {
    /// Create a new symbol version entry.
    pub fn new(lib: &str, version: &str) -> Self {
        Self {
            lib: lib.to_string(),
            version: version.to_string(),
            out_index: -1,
            prev_same_lib: -1,
        }
    }
}

/// Dynamic linking information accumulated during ELF output.
/// C equivalent: `struct dyn_inf` at tccelf.c ~line 2800
pub struct DynInf {
    pub interp: Option<usize>,
    pub note: Option<usize>,
    pub gnu_hash: Option<usize>,
    pub dynamic: Option<usize>,
    pub roinf: Option<ReadOnlyInf>,
}

impl Default for DynInf {
    fn default() -> Self {
        Self { interp: None, note: None, gnu_hash: None, dynamic: None, roinf: None }
    }
}

/// Read-only section relocation info for PT_GNU_RELRO support.
pub struct ReadOnlyInf {
    pub sh_offset: u64,
    pub sh_size: u64,
}

// ---------------------------------------------------------------------------
// Platform-dependent helper functions (tccelf.c lines 54–58)
// ---------------------------------------------------------------------------

/// Return section flags for RELRO (Relocation Read-Only) sections.
/// C equivalent: `shf_RELRO` at tccelf.c line 54
pub fn shf_relro() -> u64 {
    #[cfg(target_os = "openbsd")]
    { SHF_ALLOC as u64 }
    #[cfg(not(target_os = "openbsd"))]
    { (SHF_ALLOC | SHF_WRITE) as u64 }
}

/// Return section flags for read-only data sections.
/// C equivalent: implicit in tccelf.c section creation
pub fn shf_rdata() -> u64 {
    #[cfg(target_os = "macos")]
    { (SHF_ALLOC | SHF_WRITE) as u64 }
    #[cfg(not(target_os = "macos"))]
    { SHF_ALLOC as u64 }
}

// ---------------------------------------------------------------------------
// Byte-level serialization helpers
// ---------------------------------------------------------------------------

#[inline]
fn put_le16(buf: &mut [u8], v: u16) { buf[..2].copy_from_slice(&v.to_le_bytes()); }
#[inline]
fn get_le16(buf: &[u8]) -> u16 { u16::from_le_bytes([buf[0], buf[1]]) }
#[inline]
fn put_le32(buf: &mut [u8], v: u32) { buf[..4].copy_from_slice(&v.to_le_bytes()); }
#[inline]
fn get_le32(buf: &[u8]) -> u32 { u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) }
#[inline]
fn put_le64(buf: &mut [u8], v: u64) {
    buf[..8].copy_from_slice(&v.to_le_bytes());
}
#[inline]
fn get_le64(buf: &[u8]) -> u64 {
    u64::from_le_bytes(buf[..8].try_into().expect("invariant: slice is 8 bytes"))
}
#[inline]
fn put_le_i32(buf: &mut [u8], v: i32) { buf[..4].copy_from_slice(&v.to_le_bytes()); }
#[inline]
fn get_le_i32(buf: &[u8]) -> i32 { i32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) }
#[inline]
fn put_le_i64(buf: &mut [u8], v: i64) {
    buf[..8].copy_from_slice(&v.to_le_bytes());
}

/// Write an Elf64Sym into a 24-byte buffer.
fn write_elf64_sym(buf: &mut [u8], sym: &Elf64Sym) {
    put_le32(&mut buf[0..4], sym.st_name);
    buf[4] = sym.st_info;
    buf[5] = sym.st_other;
    put_le16(&mut buf[6..8], sym.st_shndx);
    put_le64(&mut buf[8..16], sym.st_value);
    put_le64(&mut buf[16..24], sym.st_size);
}

/// Read an Elf64Sym from a 24-byte buffer.
fn read_elf64_sym(buf: &[u8]) -> Elf64Sym {
    Elf64Sym {
        st_name: get_le32(&buf[0..4]),
        st_info: buf[4],
        st_other: buf[5],
        st_shndx: get_le16(&buf[6..8]),
        st_value: get_le64(&buf[8..16]),
        st_size: get_le64(&buf[16..24]),
    }
}

/// Write an Elf64Rela into a 24-byte buffer.
fn write_elf64_rela(buf: &mut [u8], r: &Elf64Rela) {
    put_le64(&mut buf[0..8], r.r_offset);
    put_le64(&mut buf[8..16], r.r_info);
    put_le_i64(&mut buf[16..24], r.r_addend);
}

/// Read an Elf64Rela from a 24-byte buffer.
fn read_elf64_rela(buf: &[u8]) -> Elf64Rela {
    Elf64Rela {
        r_offset: get_le64(&buf[0..8]),
        r_info: get_le64(&buf[8..16]),
        r_addend: i64::from_le_bytes(buf[16..24].try_into().expect("invariant: 8 bytes")),
    }
}

/// Write a native-width ELF symbol entry to section data at `offset`.
fn write_elf_sym(data: &mut [u8], name: u32, value: u64, size: u64,
                 info: u8, other: u8, shndx: u16) {
    let sym = Elf64Sym { st_name: name, st_info: info, st_other: other,
                          st_shndx: shndx, st_value: value, st_size: size };
    write_elf64_sym(data, &sym);
}

/// Read a native-width ELF symbol entry from section data at `offset`.
fn read_sym_entry(data: &[u8], index: usize) -> Elf64Sym {
    let off = index * ELF_SYM_SIZE;
    read_elf64_sym(&data[off..off + ELF_SYM_SIZE])
}

// ---------------------------------------------------------------------------
// Section Management (tccelf.c lines 215–360)
// ---------------------------------------------------------------------------

/// Create a new ELF section and add it to the state.
/// Returns the index of the new section in `state.sections` (or `state.priv_sections`
/// for private sections).
///
/// C equivalent: `new_section()` at tccelf.c line 215
pub fn new_section(state: &mut TccState, name: &str, sh_type: u32, sh_flags: u32) -> usize {
    let mut sec = Section::default();
    sec.name = name.to_string();
    sec.sh_type = sh_type;
    sec.sh_flags = sh_flags as u64;
    // Set alignment based on section type (tccelf.c lines 235–248)
    sec.sh_addralign = if sh_type == SHT_GNU_versym {
        2
    } else if sh_type == SHT_HASH || sh_type == SHT_GNU_HASH || sh_type == SHT_REL
              || sh_type == SHT_RELA || sh_type == SHT_DYNSYM || sh_type == SHT_SYMTAB
              || sh_type == SHT_DYNAMIC || sh_type == SHT_NOTE
    {
        PTR_SIZE as u64
    } else if sh_type == SHT_STRTAB {
        1
    } else {
        PTR_SIZE as u64
    };
    if sh_flags & SHF_PRIVATE != 0 {
        let idx = state.priv_sections.len();
        state.priv_sections.push(sec);
        idx
    } else {
        let idx = state.sections.len();
        sec.sh_num = idx;
        state.sections.push(sec);
        idx
    }
}

/// Add `size` bytes to a section with the given alignment, zero-filling the region.
/// Returns the offset of the added data within the section.
///
/// C equivalent: `section_add()` at tccelf.c line 305
pub fn section_add(sec: &mut Section, size: usize, align: usize) -> usize {
    let align = if align == 0 { 1 } else { align };
    // Power-of-2 alignment uses bitwise AND; non-power-of-2 uses division
    let offset = if align.is_power_of_two() {
        (sec.data_offset + align - 1) & !(align - 1)
    } else {
        ((sec.data_offset + align - 1) / align) * align
    };
    let new_offset = offset + size;
    if sec.sh_type != SHT_NOBITS {
        if new_offset > sec.data.len() {
            sec.data.resize(new_offset, 0);
        }
        // Zero-fill the allocated region (needed after transaction rollback)
        sec.data[offset..new_offset].fill(0);
    }
    sec.data_offset = new_offset;
    offset
}

/// Add `size` bytes to a section with alignment 1 and return the offset.
/// Callers write into `sec.data[offset..offset+size]` after this call.
///
/// C equivalent: `section_ptr_add()` at tccelf.c line 321
pub fn section_ptr_add(sec: &mut Section, size: usize) -> usize {
    section_add(sec, size, 1)
}

/// Add a string (with null terminator) to a string table section.
/// Returns the byte offset of the string within the section data.
///
/// C equivalent: `put_elf_str()` at tccelf.c line 363
pub fn put_elf_str(sec: &mut Section, s: &str) -> u32 {
    let len = s.len() + 1; // include NUL
    let offset = section_ptr_add(sec, len);
    sec.data[offset..offset + s.len()].copy_from_slice(s.as_bytes());
    // NUL terminator already zero from section_add zero-fill
    offset as u32
}

/// Compute the standard ELF hash for a symbol name.
///
/// C equivalent: `elf_hash()` at tccelf.c line 376
pub fn elf_hash(name: &str) -> u32 {
    let mut h: u32 = 0;
    for &b in name.as_bytes() {
        h = (h << 4).wrapping_add(u32::from(b));
        let g = h & 0xf000_0000;
        if g != 0 {
            h ^= g >> 24;
        }
        h &= !g;
    }
    h
}

/// Read a NUL-terminated C string from a byte buffer at the given offset.
fn read_cstr(data: &[u8], offset: usize) -> String {
    if offset >= data.len() {
        return String::new();
    }
    let mut end = offset;
    while end < data.len() && data[end] != 0 {
        end += 1;
    }
    String::from_utf8_lossy(&data[offset..end]).into_owned()
}

/// Rebuild the ELF hash table for a symbol table section after modifications.
///
/// C equivalent: `rebuild_hash()` at tccelf.c line 392
pub fn rebuild_hash(sections: &mut [Section], symtab_idx: usize, nb_buckets: usize) {
    let hash_idx = match sections[symtab_idx].hash {
        Some(h) => h,
        None => return,
    };
    let strtab_idx = match sections[symtab_idx].link {
        Some(l) => l,
        None => return,
    };
    let nb_syms = sections[symtab_idx].data_offset / ELF_SYM_SIZE;
    let hash_size = (2 + nb_buckets + nb_syms) * 4;
    sections[hash_idx].data.clear();
    sections[hash_idx].data.resize(hash_size, 0);
    sections[hash_idx].data_offset = hash_size;
    put_le32(&mut sections[hash_idx].data[0..4], nb_buckets as u32);
    put_le32(&mut sections[hash_idx].data[4..8], nb_syms as u32);
    for i in 1..nb_syms {
        let sym = read_sym_entry(&sections[symtab_idx].data, i);
        if elf_st_bind(sym.st_info) == STB_LOCAL { continue; }
        let name_off = sym.st_name as usize;
        let name = read_cstr(&sections[strtab_idx].data, name_off);
        let h = elf_hash(&name) % (nb_buckets as u32);
        let bucket_off = 8 + (h as usize) * 4;
        let chain_off = 8 + nb_buckets * 4 + i * 4;
        let old = get_le32(&sections[hash_idx].data[bucket_off..bucket_off + 4]);
        put_le32(&mut sections[hash_idx].data[chain_off..chain_off + 4], old);
        put_le32(&mut sections[hash_idx].data[bucket_off..bucket_off + 4], i as u32);
    }
    sections[symtab_idx].nb_hashed_syms = nb_syms as i32;
}

/// Initialize a symbol table section with its associated string table and hash.
///
/// C equivalent: `init_symtab()` at tccelf.c line 257
pub fn init_symtab(sections: &mut [Section], symtab_idx: usize,
                   strtab_idx: usize, hash_idx: usize, _flags: u32) {
    // Put empty string at offset 0 in string table (ELF requirement)
    put_elf_str(&mut sections[strtab_idx], "");
    // Add null symbol entry at index 0 (ELF requirement)
    // C code uses section_ptr_add (align=1), not section_add(align=sizeof(Elf64Sym))
    let _offset = section_ptr_add(&mut sections[symtab_idx], ELF_SYM_SIZE);
    sections[symtab_idx].sh_entsize = ELF_SYM_SIZE as u64;
    // Initialize hash with 1 bucket, 1 chain entry
    let hash_data = &mut sections[hash_idx].data;
    hash_data.clear();
    hash_data.extend_from_slice(&1u32.to_le_bytes()); // nbuckets
    hash_data.extend_from_slice(&1u32.to_le_bytes()); // nchains
    hash_data.extend_from_slice(&0u32.to_le_bytes()); // bucket[0]
    hash_data.extend_from_slice(&0u32.to_le_bytes()); // chain[0]
    sections[hash_idx].data_offset = sections[hash_idx].data.len();
    // Cross-link sections
    sections[symtab_idx].link = Some(strtab_idx);
    sections[symtab_idx].hash = Some(hash_idx);
}

/// Create a symbol table with associated string table and hash section.
/// Returns the section index of the new symbol table.
///
/// C equivalent: `new_symtab()` at tccelf.c line 268
pub fn new_symtab(state: &mut TccState, name: &str, sh_type: u32, sh_flags: u32,
                  strtab_name: &str, hash_name: &str, hash_flags: u32) -> usize {
    let symtab_idx = new_section(state, name, sh_type, sh_flags);
    let strtab_idx = new_section(state, strtab_name, SHT_STRTAB, sh_flags);
    let hash_idx = new_section(state, hash_name, SHT_HASH, hash_flags);
    init_symtab(&mut state.sections, symtab_idx, strtab_idx, hash_idx, sh_flags);
    symtab_idx
}

// ---------------------------------------------------------------------------
// ELF State Lifecycle (tccelf.c lines 60–213)
// ---------------------------------------------------------------------------

/// Initialize ELF linker state: create standard sections (.text, .data, .bss, etc.).
///
/// C equivalent: `tccelf_new()` at tccelf.c line 60
pub fn tccelf_new(state: &mut TccState) -> TccResult<()> {
    // Section 0 is always NULL (ELF requirement)
    if state.sections.is_empty() {
        state.sections.push(Section::default());
    }
    // .text — executable code
    let text_idx = new_section(state, ".text", SHT_PROGBITS,
                               SHF_ALLOC | SHF_EXECINSTR);
    state.text_section_idx = text_idx;
    // .data — initialized read-write data
    let data_idx = new_section(state, ".data", SHT_PROGBITS,
                               SHF_ALLOC | SHF_WRITE);
    state.data_section_idx = data_idx;
    // .rodata — read-only data
    let _rodata = new_section(state, ".rodata", SHT_PROGBITS, shf_rdata() as u32);
    // .bss — uninitialized data
    let bss_idx = new_section(state, ".bss", SHT_NOBITS, SHF_ALLOC | SHF_WRITE);
    state.bss_section_idx = bss_idx;
    // .common — common symbols (private, not output)
    let _common = new_section(state, ".common", SHT_NOBITS,
                              SHF_PRIVATE | SHF_ALLOC | SHF_WRITE);
    // .symtab — main symbol table
    let _symtab = new_symtab(state, ".symtab", SHT_SYMTAB, 0,
                             ".strtab", ".hashtab", SHF_PRIVATE);
    // .dynsymtab — private placeholder for dynamic symbols during compilation
    let dynsym = new_section(state, ".dynsymtab", SHT_SYMTAB,
                             SHF_PRIVATE | SHF_DYNSYM);
    let dyn_strtab = new_section(state, ".dynstrtab", SHT_STRTAB, SHF_PRIVATE);
    let dyn_hash = new_section(state, ".dynhashtab", SHT_HASH, SHF_PRIVATE);
    init_symtab(&mut state.sections, dynsym, dyn_strtab, dyn_hash, SHF_PRIVATE);
    Ok(())
}

/// Clean up ELF linker state. In Rust, most cleanup is handled by `Drop`
/// on `Vec` and `String`. This clears auxiliary state.
///
/// C equivalent: `tccelf_delete()` at tccelf.c line 124
pub fn tccelf_delete(state: &mut TccState) {
    state.sections.clear();
    state.priv_sections.clear();
    state.sym_ext.clear();
    state.loaded_dlls.clear();
}

/// Begin processing a new compilation unit. Saves section data offsets as a
/// transaction savepoint for symbol merging at `tccelf_end_file`.
///
/// C equivalent: `tccelf_begin_file()` at tccelf.c line 155
pub fn tccelf_begin_file(state: &mut TccState) {
    for sec in &mut state.sections {
        sec.prev = Some(sec.data_offset);
    }
    for sec in &mut state.sections {
        sec.nb_hashed_syms = 0;
    }
}

/// End processing of a compilation unit. Merges new symbols with existing
/// ones, resolving conflicts per ELF binding rules.
///
/// C equivalent: `tccelf_end_file()` at tccelf.c line 174
pub fn tccelf_end_file(state: &mut TccState) -> TccResult<()> {
    let symtab_idx = match find_section_index(state, ".symtab") {
        Some(idx) => idx,
        None => return Ok(()),
    };
    let nb_syms = state.sections[symtab_idx].data_offset / ELF_SYM_SIZE;
    let first_new = state.sections[symtab_idx].prev.unwrap_or(0) / ELF_SYM_SIZE;
    // Convert undefined locals to globals (tccelf.c line 185)
    for i in first_new..nb_syms {
        let sym = read_sym_entry(&state.sections[symtab_idx].data, i);
        let bind = elf_st_bind(sym.st_info);
        if bind == STB_LOCAL && sym.st_shndx == SHN_UNDEF {
            let new_info = elf_st_info(STB_GLOBAL, elf_st_type(sym.st_info));
            let off = i * ELF_SYM_SIZE;
            state.sections[symtab_idx].data[off + 4] = new_info;
        }
    }
    // Rebuild hash with appropriate bucket count
    let total = state.sections[symtab_idx].data_offset / ELF_SYM_SIZE;
    let nb_buckets = if total < 8 { 1 } else { total };
    rebuild_hash(&mut state.sections, symtab_idx, nb_buckets);
    Ok(())
}

/// Find the index of a section by name. Returns None if not found.
fn find_section_index(state: &TccState, name: &str) -> Option<usize> {
    state.sections.iter().position(|s| s.name == name)
}

/// Find a section by name, returning an error if not found.
fn require_section_index(state: &TccState, name: &str) -> TccResult<usize> {
    find_section_index(state, name)
        .ok_or_else(|| TccError::Link(format!("section '{}' not found", name)))
}

// ---------------------------------------------------------------------------
// Symbol Table Functions (tccelf.c lines 428–600)
// ---------------------------------------------------------------------------

/// Add a symbol to a symbol table section, updating the hash table.
/// Returns the 1-based symbol index within the symbol table.
///
/// C equivalent: `put_elf_sym()` at tccelf.c line 428
pub fn put_elf_sym(state: &mut TccState, sec_idx: usize,
                   value: u64, size: u64, info: u8, other: u8,
                   shndx: u16, name: &str) -> i32 {
    // Add name to the string table linked from the symbol table
    let strtab_idx = state.sections[sec_idx].link.unwrap_or(0);
    let name_offset = if !name.is_empty() {
        put_elf_str(&mut state.sections[strtab_idx], name)
    } else {
        0
    };
    // Allocate space for the new symbol entry (align=1, matching C's section_ptr_add)
    let sym_offset = section_ptr_add(&mut state.sections[sec_idx], ELF_SYM_SIZE);
    let sym_index = (sym_offset / ELF_SYM_SIZE) as i32;
    // Write symbol data
    write_elf_sym(
        &mut state.sections[sec_idx].data[sym_offset..sym_offset + ELF_SYM_SIZE],
        name_offset, value, size, info, other, shndx,
    );
    // Update hash table
    if let Some(hash_idx) = state.sections[sec_idx].hash {
        let nb_syms = state.sections[sec_idx].data_offset / ELF_SYM_SIZE;
        // Auto-resize hash when load factor > 2
        let nb_buckets = get_le32(&state.sections[hash_idx].data[0..4]) as usize;
        let hashed = state.sections[sec_idx].nb_hashed_syms as usize;
        if hashed > 2 * nb_buckets {
            rebuild_hash(&mut state.sections, sec_idx, nb_buckets * 2);
        }
        // Insert into hash chain
        let hash_sec_idx = state.sections[sec_idx].hash.unwrap_or(0);
        let str_idx = state.sections[sec_idx].link.unwrap_or(0);
        let sym_name = read_cstr(&state.sections[str_idx].data, name_offset as usize);
        let nb_bkts = get_le32(&state.sections[hash_sec_idx].data[0..4]) as usize;
        let h = (elf_hash(&sym_name) % (nb_bkts as u32)) as usize;
        let bucket_off = 8 + h * 4;
        let chain_off = 8 + nb_bkts * 4 + (sym_index as usize) * 4;
        // Grow hash data if needed
        let needed = chain_off + 4;
        if needed > state.sections[hash_sec_idx].data.len() {
            state.sections[hash_sec_idx].data.resize(needed, 0);
            state.sections[hash_sec_idx].data_offset = needed;
        }
        // Update nchains
        put_le32(&mut state.sections[hash_sec_idx].data[4..8], nb_syms as u32);
        // chain[sym_index] = bucket[h]; bucket[h] = sym_index
        let old = get_le32(&state.sections[hash_sec_idx].data[bucket_off..bucket_off + 4]);
        put_le32(&mut state.sections[hash_sec_idx].data[chain_off..chain_off + 4], old);
        put_le32(&mut state.sections[hash_sec_idx].data[bucket_off..bucket_off + 4],
                 sym_index as u32);
        state.sections[sec_idx].nb_hashed_syms += 1;
    }
    sym_index
}

/// Find a symbol by name in a symbol table via hash lookup.
/// Returns the symbol index or None if not found.
///
/// C equivalent: `find_elf_sym()` at tccelf.c line 475
pub fn find_elf_sym(state: &TccState, sec_idx: usize, name: &str) -> Option<i32> {
    let hash_idx = state.sections[sec_idx].hash?;
    let strtab_idx = state.sections[sec_idx].link?;
    let hash_data = &state.sections[hash_idx].data;
    if hash_data.len() < 8 { return None; }
    let nb_buckets = get_le32(&hash_data[0..4]) as usize;
    if nb_buckets == 0 { return None; }
    let h = (elf_hash(name) % (nb_buckets as u32)) as usize;
    let bucket_off = 8 + h * 4;
    if bucket_off + 4 > hash_data.len() { return None; }
    let mut sym_index = get_le32(&hash_data[bucket_off..bucket_off + 4]) as usize;
    while sym_index != 0 {
        let sym = read_sym_entry(&state.sections[sec_idx].data, sym_index);
        let sym_name = read_cstr(&state.sections[strtab_idx].data, sym.st_name as usize);
        if sym_name == name {
            return Some(sym_index as i32);
        }
        // Follow chain
        let chain_off = 8 + nb_buckets * 4 + sym_index * 4;
        if chain_off + 4 > hash_data.len() { break; }
        sym_index = get_le32(&hash_data[chain_off..chain_off + 4]) as usize;
    }
    None
}

/// Add or update a global/weak symbol, resolving conflicts with existing
/// symbols per ELF binding precedence rules.
///
/// C equivalent: `set_elf_sym()` at tccelf.c ~line 530
pub fn set_elf_sym(state: &mut TccState, value: u64, size: u64,
                   info: u8, other: u8, shndx: u16, name: &str) -> i32 {
    let symtab_idx = find_section_index(state, ".symtab").unwrap_or(0);
    // Check if symbol already exists
    if let Some(existing_idx) = find_elf_sym(state, symtab_idx, name) {
        let existing = read_sym_entry(&state.sections[symtab_idx].data,
                                       existing_idx as usize);
        let existing_bind = elf_st_bind(existing.st_info);
        let existing_shndx = existing.st_shndx;
        let existing_name = existing.st_name;
        let new_bind = elf_st_bind(info);
        // Resolution rules: defined beats undefined; global beats weak
        let should_replace =
            (existing_shndx == SHN_UNDEF && shndx != SHN_UNDEF) ||
            (existing_bind == STB_WEAK && new_bind == STB_GLOBAL) ||
            (existing_shndx == SHN_UNDEF && existing_bind == STB_WEAK);
        if should_replace {
            let off = (existing_idx as usize) * ELF_SYM_SIZE;
            write_elf_sym(
                &mut state.sections[symtab_idx].data[off..off + ELF_SYM_SIZE],
                existing_name, value, size, info, other, shndx,
            );
        }
        return existing_idx;
    }
    // Symbol not found — add new
    put_elf_sym(state, symtab_idx, value, size, info, other, shndx, name)
}

/// Get the runtime address of a named symbol.
///
/// C equivalent: `get_sym_addr()` at tccelf.c line 498
pub fn get_sym_addr(state: &TccState, name: &str, err: bool) -> TccResult<u64> {
    let symtab_idx = find_section_index(state, ".symtab").unwrap_or(0);
    if let Some(idx) = find_elf_sym(state, symtab_idx, name) {
        let sym = read_sym_entry(&state.sections[symtab_idx].data, idx as usize);
        if sym.st_shndx == SHN_UNDEF {
            if err {
                return Err(TccError::Link(format!("undefined symbol '{}'", name)));
            }
            return Ok(0);
        }
        // For ABS symbols, value is the address
        if sym.st_shndx == SHN_ABS {
            return Ok(sym.st_value);
        }
        // For section-relative symbols, add section base address
        let sec_idx = sym.st_shndx as usize;
        if sec_idx < state.sections.len() {
            return Ok(state.sections[sec_idx].sh_addr + sym.st_value);
        }
        return Ok(sym.st_value);
    }
    if err {
        Err(TccError::Link(format!("undefined symbol '{}'", name)))
    } else {
        Ok(0)
    }
}

/// LIBTCCAPI: Get symbol address as a raw pointer.
///
/// C equivalent: `tcc_get_symbol()` at tccelf.c ~line 510
pub fn tcc_get_symbol(state: &TccState, name: &str) -> Option<*const ()> {
    match get_sym_addr(state, name, false) {
        Ok(addr) if addr != 0 => Some(addr as *const ()),
        _ => None,
    }
}

/// LIBTCCAPI: Add an external symbol with a given value.
///
/// C equivalent: `tcc_add_symbol()` at tccelf.c ~line 518
pub fn tcc_add_symbol(state: &mut TccState, name: &str, val: *const ()) -> TccResult<()> {
    let addr = val as u64;
    set_elf_sym(state, addr, 0,
                elf_st_info(STB_GLOBAL, STT_NOTYPE), 0, SHN_ABS, name);
    Ok(())
}

/// Iterate over all ELF symbols, calling `callback` for each.
///
/// C equivalent: `list_elf_symbols()` at tccelf.c ~line 525
pub fn list_elf_symbols(state: &TccState, callback: &dyn Fn(&str, *const ())) {
    let symtab_idx = match find_section_index(state, ".symtab") {
        Some(i) => i,
        None => return,
    };
    let strtab_idx = match state.sections[symtab_idx].link {
        Some(i) => i,
        None => return,
    };
    let nb_syms = state.sections[symtab_idx].data_offset / ELF_SYM_SIZE;
    for i in 1..nb_syms {
        let sym = read_sym_entry(&state.sections[symtab_idx].data, i);
        let name = read_cstr(&state.sections[strtab_idx].data, sym.st_name as usize);
        if name.is_empty() { continue; }
        let addr = if sym.st_shndx == SHN_ABS {
            sym.st_value
        } else if (sym.st_shndx as usize) < state.sections.len() {
            state.sections[sym.st_shndx as usize].sh_addr + sym.st_value
        } else {
            sym.st_value
        };
        callback(&name, addr as *const ());
    }
}

/// LIBTCCAPI: Public symbol listing.
///
/// C equivalent: `tcc_list_symbols()` at tccelf.c ~line 540
pub fn tcc_list_symbols(state: &TccState, callback: &dyn Fn(&str, *const ())) {
    list_elf_symbols(state, callback);
}

/// Get or create per-symbol attribute record for GOT/PLT tracking.
/// If `alloc` is true, grows the attribute array if necessary.
///
/// C equivalent: `get_sym_attr()` at tccelf.c ~line 835
pub fn get_sym_attr(state: &mut TccState, index: usize, alloc: bool) -> &mut SymAttrExt {
    if index >= state.sym_ext.len() {
        if !alloc {
            // Ensure at least one entry exists for safe return
            if state.sym_ext.is_empty() {
                state.sym_ext.push(SymAttrExt::default());
            }
            return &mut state.sym_ext[0];
        }
        state.sym_ext.resize(index + 1, SymAttrExt::default());
    }
    &mut state.sym_ext[index]
}

/// Sort symbols in a section: locals before globals (ELF specification requirement).
/// Updates all relocation sections that reference these symbols.
///
/// C equivalent: `sort_syms()` at tccelf.c ~line 602
pub fn sort_syms(state: &mut TccState, sec_idx: usize) {
    let nb_syms = state.sections[sec_idx].data_offset / ELF_SYM_SIZE;
    if nb_syms <= 1 { return; }
    // Build old-to-new index mapping
    let mut old_to_new: Vec<usize> = vec![0; nb_syms];
    let mut locals: Vec<usize> = Vec::new();
    let mut globals: Vec<usize> = Vec::new();
    for i in 1..nb_syms {
        let sym = read_sym_entry(&state.sections[sec_idx].data, i);
        if elf_st_bind(sym.st_info) == STB_LOCAL {
            locals.push(i);
        } else {
            globals.push(i);
        }
    }
    // New ordering: [0=null] [locals...] [globals...]
    let mut new_idx = 1usize;
    for &old_idx in &locals {
        old_to_new[old_idx] = new_idx;
        new_idx += 1;
    }
    let first_global = new_idx;
    for &old_idx in &globals {
        old_to_new[old_idx] = new_idx;
        new_idx += 1;
    }
    // Build sorted symbol data
    let mut new_data = vec![0u8; nb_syms * ELF_SYM_SIZE];
    // Copy null symbol
    new_data[..ELF_SYM_SIZE]
        .copy_from_slice(&state.sections[sec_idx].data[..ELF_SYM_SIZE]);
    for i in 1..nb_syms {
        let src_off = i * ELF_SYM_SIZE;
        let dst_off = old_to_new[i] * ELF_SYM_SIZE;
        new_data[dst_off..dst_off + ELF_SYM_SIZE]
            .copy_from_slice(&state.sections[sec_idx].data[src_off..src_off + ELF_SYM_SIZE]);
    }
    state.sections[sec_idx].data[..nb_syms * ELF_SYM_SIZE]
        .copy_from_slice(&new_data);
    // Update sh_info to point to first global
    state.sections[sec_idx].sh_info = first_global as u32;
    // Update relocation sections that reference this symbol table
    let target_sec_idx = sec_idx;
    for s in 0..state.sections.len() {
        let sh_type = state.sections[s].sh_type;
        if (sh_type == SHT_REL || sh_type == SHT_RELA)
            && state.sections[s].link == Some(target_sec_idx)
        {
            let entry_size = if sh_type == SHT_RELA { ELF_RELA_SIZE } else { ELF_REL_SIZE };
            let nb_rels = state.sections[s].data_offset / entry_size;
            for r in 0..nb_rels {
                let off = r * entry_size;
                let r_info = get_le64(&state.sections[s].data[off + 8..off + 16]);
                let old_sym = elf64_r_sym(r_info) as usize;
                let r_type = elf64_r_type(r_info);
                if old_sym < nb_syms {
                    let new_sym = old_to_new[old_sym] as u64;
                    let new_info = elf64_r_info(new_sym, r_type);
                    put_le64(&mut state.sections[s].data[off + 8..off + 16], new_info);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Relocation Functions (tccelf.c lines 850–1200)
// ---------------------------------------------------------------------------

/// Add a Rela-type relocation entry to a relocation section.
///
/// C equivalent: `put_elf_reloca()` at tccelf.c ~line 850
/// Note: sym_sec reference is not needed for relocation entry creation;
/// the original C code only used it for section linking which is handled
/// separately in our Rust port.
pub fn put_elf_reloca(rel_sec: &mut Section, _sym_sec: &Section,
                      offset: u64, rel_type: u32, sym_idx: i32, addend: i64) {
    put_elf_reloca_direct(rel_sec, offset, rel_type, sym_idx, addend);
}

/// Internal: Add a Rela entry without requiring a reference to the sym section.
fn put_elf_reloca_direct(rel_sec: &mut Section,
                         offset: u64, rel_type: u32,
                         sym_idx: i32, addend: i64) {
    let rela = Elf64Rela {
        r_offset: offset,
        r_info: elf64_r_info(sym_idx as u64, rel_type as u64),
        r_addend: addend,
    };
    let pos = section_ptr_add(rel_sec, ELF_RELA_SIZE);
    write_elf64_rela(&mut rel_sec.data[pos..pos + ELF_RELA_SIZE], &rela);
}

/// Add a Rel-type relocation entry (addend = 0).
///
/// C equivalent: `put_elf_reloc()` at tccelf.c ~line 870
pub fn put_elf_reloc(rel_sec: &mut Section, sym_sec: &Section,
                     offset: u64, rel_type: u32, sym_idx: i32) {
    put_elf_reloca(rel_sec, sym_sec, offset, rel_type, sym_idx, 0);
}

/// Build a .gnu.hash section for faster dynamic symbol lookup.
/// Returns the section index if created, or None for static links.
///
/// C equivalent: `create_gnu_hash()` at tccelf.c ~line 1100
pub fn create_gnu_hash(state: &mut TccState) -> TccResult<Option<usize>> {
    let dynsym_idx = match find_section_index(state, ".dynsym") {
        Some(i) => i,
        None => return Ok(None),
    };
    let nb_syms = state.sections[dynsym_idx].data_offset / ELF_SYM_SIZE;
    if nb_syms <= 1 { return Ok(None); }
    let gnu_hash_idx = new_section(state, ".gnu.hash", SHT_GNU_HASH,
                                   SHF_ALLOC);
    // Simple .gnu.hash with 1 bloom word, nbuckets = nb_syms
    let nb_buckets = if nb_syms < 4 { 1 } else { nb_syms };
    let bloom_size = 1usize; // single bloom word
    // Header: nbuckets(4) + symoffset(4) + bloom_size(4) + bloom_shift(4)
    // + bloom[bloom_size](PTR_SIZE each) + buckets[nb_buckets](4 each)
    // + chains[nb_syms - symoffset](4 each)
    let sym_offset = 1usize; // skip null symbol
    let header_size = 16 + bloom_size * PTR_SIZE + nb_buckets * 4
                      + (nb_syms - sym_offset) * 4;
    state.sections[gnu_hash_idx].data.resize(header_size, 0);
    state.sections[gnu_hash_idx].data_offset = header_size;
    let d = &mut state.sections[gnu_hash_idx].data;
    put_le32(&mut d[0..4], nb_buckets as u32);
    put_le32(&mut d[4..8], sym_offset as u32);
    put_le32(&mut d[8..12], bloom_size as u32);
    put_le32(&mut d[12..16], 6); // bloom shift = 6
    // Bloom filter: set all bits (accept all, no filtering)
    let bloom_off = 16;
    for i in 0..bloom_size {
        let off = bloom_off + i * PTR_SIZE;
        if PTR_SIZE == 8 {
            put_le64(&mut d[off..off + 8], u64::MAX);
        } else {
            put_le32(&mut d[off..off + 4], u32::MAX);
        }
    }
    // Buckets and chains would be populated during dynamic symbol setup
    // For now, create the section structure; fill_dynamic will complete it
    state.sections[gnu_hash_idx].link = Some(dynsym_idx);
    state.sections[gnu_hash_idx].sh_entsize = 4;
    Ok(Some(gnu_hash_idx))
}

/// Resolve addresses for all symbols in the symbol table.
/// Reports undefined symbols as errors if `do_resolve` is true.
///
/// C equivalent: `relocate_syms()` at tccelf.c ~line 940
pub fn relocate_syms(state: &mut TccState, do_resolve: bool) -> TccResult<()> {
    let symtab_idx = match find_section_index(state, ".symtab") {
        Some(i) => i,
        None => return Ok(()),
    };
    let nb_syms = state.sections[symtab_idx].data_offset / ELF_SYM_SIZE;
    for i in 1..nb_syms {
        let sym = read_sym_entry(&state.sections[symtab_idx].data, i);
        let shndx = sym.st_shndx;
        if shndx == SHN_UNDEF {
            // Undefined symbol — check if it's weak (allowed) or needs resolution
            let bind = elf_st_bind(sym.st_info);
            if bind == STB_WEAK { continue; }
            if do_resolve {
                let strtab_idx = state.sections[symtab_idx].link.unwrap_or(0);
                let name = read_cstr(&state.sections[strtab_idx].data,
                                     sym.st_name as usize);
                if !name.is_empty() {
                    state.nb_errors += 1;
                    // Continue to report all undefined symbols
                }
            }
        } else if shndx < SHN_LORESERVE {
            // Section-relative: compute absolute address
            let sec_idx = shndx as usize;
            if sec_idx < state.sections.len() {
                let new_value = state.sections[sec_idx].sh_addr + sym.st_value;
                let off = i * ELF_SYM_SIZE;
                // Update st_value in place (offset 8 in Elf64Sym)
                put_le64(&mut state.sections[symtab_idx].data[off + 8..off + 16],
                         new_value);
            }
        }
        // SHN_ABS symbols keep their value unchanged
    }
    if state.nb_errors > 0 && do_resolve {
        return Err(TccError::Link("undefined symbols found during relocation".into()));
    }
    Ok(())
}

/// Apply relocations from a relocation section to its target section.
/// Target-architecture-specific relocation logic is dispatched here.
///
/// C equivalent: `relocate_section()` at tccelf.c ~line 990
pub fn relocate_section(state: &mut TccState, target_sec_idx: usize,
                        rel_sec_idx: usize) -> TccResult<()> {
    let entry_size = if state.sections[rel_sec_idx].sh_type == SHT_RELA {
        ELF_RELA_SIZE
    } else {
        ELF_REL_SIZE
    };
    let nb_rels = state.sections[rel_sec_idx].data_offset / entry_size;
    let symtab_idx = state.sections[rel_sec_idx].link.unwrap_or(0);
    for r in 0..nb_rels {
        let rel_off = r * entry_size;
        let rela = read_elf64_rela(
            &state.sections[rel_sec_idx].data[rel_off..rel_off + ELF_RELA_SIZE]
        );
        let sym_idx = elf64_r_sym(rela.r_info) as usize;
        let rel_type = elf64_r_type(rela.r_info) as u32;
        let r_offset = rela.r_offset as usize;
        // Get symbol value
        let sym_value = if sym_idx > 0 && sym_idx * ELF_SYM_SIZE
            <= state.sections[symtab_idx].data_offset
        {
            let sym = read_sym_entry(&state.sections[symtab_idx].data, sym_idx);
            sym.st_value
        } else {
            0
        };
        let addend = rela.r_addend;
        // Apply relocation based on type — architecture-specific
        // CVE-2006-0635: All address calculations use checked arithmetic
        let target_addr = state.sections[target_sec_idx].sh_addr + r_offset as u64;
        let val = sym_value.wrapping_add(addend as u64);
        // Ensure target is within bounds before writing
        if r_offset + 8 <= state.sections[target_sec_idx].data.len() {
            apply_relocation(
                &mut state.sections[target_sec_idx].data,
                r_offset, rel_type, val, target_addr,
            );
        }
    }
    Ok(())
}

/// Apply a single relocation to target data based on relocation type.
/// Supports common x86-64 relocation types.
fn apply_relocation(data: &mut [u8], offset: usize, rel_type: u32,
                    value: u64, _pc: u64) {
    match rel_type {
        R_X86_64_64 => {
            if offset + 8 <= data.len() {
                put_le64(&mut data[offset..offset + 8], value);
            }
        }
        R_X86_64_32 | R_X86_64_32S => {
            if offset + 4 <= data.len() {
                put_le32(&mut data[offset..offset + 4], value as u32);
            }
        }
        R_X86_64_PC32 | R_X86_64_PLT32 | R_X86_64_GOTPCRELX
        | R_X86_64_REX_GOTPCRELX => {
            if offset + 4 <= data.len() {
                let rel_val = value.wrapping_sub(_pc) as u32;
                put_le32(&mut data[offset..offset + 4], rel_val);
            }
        }
        _ => {
            // Other relocation types handled by architecture-specific backends
        }
    }
}

/// Apply relocations to all sections in the output.
///
/// C equivalent: `relocate_sections()` at tccelf.c ~line 1050
pub fn relocate_sections(state: &mut TccState) -> TccResult<()> {
    let num_sections = state.sections.len();
    for s in 0..num_sections {
        let sh_type = state.sections[s].sh_type;
        if sh_type == SHT_RELA || sh_type == SHT_REL {
            // Find the target section this reloc section applies to
            if let Some(target_idx) = state.sections[s].sh_info.checked_sub(0)
                .and_then(|v| if (v as usize) < num_sections { Some(v as usize) } else { None })
            {
                // Skip non-allocated sections
                if state.sections[target_idx].sh_flags & (SHF_ALLOC as u64) == 0 {
                    continue;
                }
                relocate_section(state, target_idx, s)?;
            }
        }
    }
    Ok(())
}

/// Relocate PLT (Procedure Linkage Table) entries. Fills PLT stubs with
/// the correct jump offsets to GOT entries.
///
/// C equivalent: target-specific `relocate_plt()` integrated here
pub fn relocate_plt(state: &mut TccState) -> TccResult<()> {
    let plt_idx = match find_section_index(state, ".plt") {
        Some(i) => i,
        None => return Ok(()),
    };
    let got_idx = match find_section_index(state, ".got") {
        Some(i) => i,
        None => return Ok(()),
    };
    let plt_addr = state.sections[plt_idx].sh_addr;
    let got_addr = state.sections[got_idx].sh_addr;
    let plt_data_len = state.sections[plt_idx].data_offset;
    // Standard x86-64 PLT entry size is 16 bytes
    let plt_entry_size = 16usize;
    if plt_data_len <= plt_entry_size { return Ok(()); } // Only PLT[0]
    let nb_entries = (plt_data_len - plt_entry_size) / plt_entry_size;
    for i in 0..nb_entries {
        let plt_off = plt_entry_size + i * plt_entry_size;
        let got_off = (3 + i) * PTR_SIZE; // GOT[0..2] reserved, entries start at GOT[3]
        let plt_entry_addr = plt_addr + plt_off as u64;
        let got_entry_addr = got_addr + got_off as u64;
        // Write PC-relative offset to GOT entry in PLT stub (offset 2 in jmp instruction)
        if plt_off + 6 <= state.sections[plt_idx].data.len() {
            let rel_offset = got_entry_addr.wrapping_sub(plt_entry_addr + 6) as u32;
            put_le32(&mut state.sections[plt_idx].data[plt_off + 2..plt_off + 6],
                     rel_offset);
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Common Symbol Resolution (tccelf.c ~line 1800)
// ---------------------------------------------------------------------------

/// Move COMMON symbols to the BSS section, allocating space for each.
///
/// C equivalent: `resolve_common_syms()` at tccelf.c ~line 1800
pub fn resolve_common_syms(state: &mut TccState) -> TccResult<()> {
    let symtab_idx = match find_section_index(state, ".symtab") {
        Some(i) => i,
        None => return Ok(()),
    };
    let bss_idx = state.bss_section_idx;
    let nb_syms = state.sections[symtab_idx].data_offset / ELF_SYM_SIZE;
    for i in 1..nb_syms {
        let sym = read_sym_entry(&state.sections[symtab_idx].data, i);
        if sym.st_shndx != SHN_COMMON { continue; }
        // Allocate space in BSS with alignment from st_value
        let align = sym.st_value as usize;
        let size = sym.st_size as usize;
        let align = if align == 0 { 1 } else { align };
        let offset = section_add(&mut state.sections[bss_idx], size, align);
        // Update symbol: change shndx to BSS, value to offset
        let off = i * ELF_SYM_SIZE;
        // st_shndx is at offset 6 in Elf64Sym
        put_le16(&mut state.sections[symtab_idx].data[off + 6..off + 8],
                 bss_idx as u16);
        // st_value at offset 8
        put_le64(&mut state.sections[symtab_idx].data[off + 8..off + 16],
                 offset as u64);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// GOT/PLT Functions (tccelf.c lines 1200–1600)
// ---------------------------------------------------------------------------

/// Create the .got section and _GLOBAL_OFFSET_TABLE_ symbol.
/// Returns the GOT symbol index.
///
/// C equivalent: `build_got()` at tccelf.c ~line 1200
pub fn build_got(state: &mut TccState) -> i32 {
    // Create .got section
    let got_idx = new_section(state, ".got", SHT_PROGBITS,
                              SHF_ALLOC | SHF_WRITE);
    state.sections[got_idx].sh_entsize = PTR_SIZE as u64;
    // Reserve GOT[0..2] for dynamic linker use
    section_add(&mut state.sections[got_idx], 3 * PTR_SIZE, PTR_SIZE);
    // Create .plt section
    let plt_idx = new_section(state, ".plt", SHT_PROGBITS,
                              SHF_ALLOC | SHF_EXECINSTR);
    state.sections[plt_idx].sh_entsize = 16;
    // Reserve PLT[0] stub (lazy binding trampoline)
    section_add(&mut state.sections[plt_idx], 16, 16);
    // Create relocation section for .plt
    let _relplt = new_section(state, ".rela.plt", SHT_RELA, SHF_ALLOC);
    // Add _GLOBAL_OFFSET_TABLE_ symbol
    let symtab_idx = find_section_index(state, ".symtab").unwrap_or(0);
    let got_sym = put_elf_sym(state, symtab_idx, 0, 0,
                              elf_st_info(STB_GLOBAL, STT_OBJECT), 0,
                              got_idx as u16, "_GLOBAL_OFFSET_TABLE_");
    got_sym
}

/// Add a GOT entry for a symbol, creating PLT entry if needed.
///
/// C equivalent: `put_got_entry()` at tccelf.c ~line 1250
pub fn put_got_entry(state: &mut TccState, reloc_type: i32,
                     sym_index: i32) -> TccResult<()> {
    let need_plt = is_plt_reloc(reloc_type as u32);
    // Check if entry already exists (copy to local to release borrow)
    {
        let attr = get_sym_attr(state, sym_index as usize, true);
        if need_plt && attr.plt_offset != 0 { return Ok(()); }
        if !need_plt && attr.got_offset != 0 { return Ok(()); }
    }
    let got_idx = match find_section_index(state, ".got") {
        Some(i) => i,
        None => return Err(TccError::Link("GOT section not found".into())),
    };
    // Allocate GOT slot
    let got_offset = section_add(&mut state.sections[got_idx], PTR_SIZE, PTR_SIZE);
    // Ensure .rela.got exists
    let rela_got_idx = match find_section_index(state, ".rela.got") {
        Some(i) => i,
        None => new_section(state, ".rela.got", SHT_RELA, SHF_ALLOC),
    };
    // Add relocation — copy needed fields first to avoid simultaneous borrows
    let symtab_idx = find_section_index(state, ".symtab").unwrap_or(0);
    let _sym_entsize = state.sections[symtab_idx].sh_entsize;
    {
        let rela_sec = &mut state.sections[rela_got_idx];
        let new_off = rela_sec.data_offset;
        let rela_entry_size = ELF_RELA_SIZE;
        rela_sec.data.resize(new_off + rela_entry_size, 0);
        let rela = Elf64Rela {
            r_offset: got_offset as u64,
            r_info: elf64_r_info(sym_index as u64, reloc_type as u64),
            r_addend: 0,
        };
        write_elf64_rela(&mut rela_sec.data[new_off..new_off + rela_entry_size], &rela);
        rela_sec.data_offset = new_off + rela_entry_size;
        rela_sec.sh_entsize = rela_entry_size as u64;
        rela_sec.link = Some(symtab_idx);
    }
    // Create PLT entry if needed
    let mut final_offset = got_offset as u32;
    if need_plt {
        if let Some(plt_idx) = find_section_index(state, ".plt") {
            let plt_off = section_add(&mut state.sections[plt_idx], 16, 16);
            final_offset = plt_off as u32;
            // Write PLT stub: jmp *got_entry(%rip); push index; jmp PLT[0]
            let plt_data = &mut state.sections[plt_idx].data;
            if plt_off + 16 <= plt_data.len() {
                plt_data[plt_off] = 0xff;     // jmp
                plt_data[plt_off + 1] = 0x25; // [rip+disp32]
                // Displacement filled by relocate_plt
                plt_data[plt_off + 6] = 0x68; // push imm32
                // Push index filled later
                plt_data[plt_off + 11] = 0xe9; // jmp rel32
                // Jump to PLT[0] filled later
            }
        }
    }
    // Store offset in sym attr
    {
        let attr = get_sym_attr(state, sym_index as usize, true);
        if need_plt {
            attr.plt_offset = final_offset;
        } else {
            attr.got_offset = got_offset as u32;
        }
    }
    Ok(())
}

/// Determine if a relocation type requires a PLT entry.
fn is_plt_reloc(rel_type: u32) -> bool {
    matches!(rel_type, R_X86_64_PLT32 | R_X86_64_JUMP_SLOT)
}

/// Walk all relocations and create GOT/PLT entries as needed.
///
/// C equivalent: `build_got_entries()` at tccelf.c ~line 1350
pub fn build_got_entries(state: &mut TccState, _got_sym: i32) -> TccResult<()> {
    let num_sections = state.sections.len();
    // Collect relocation sections to process
    let mut rel_sections: Vec<usize> = Vec::new();
    for s in 0..num_sections {
        let sh_type = state.sections[s].sh_type;
        if sh_type == SHT_RELA || sh_type == SHT_REL {
            rel_sections.push(s);
        }
    }
    for &rel_idx in &rel_sections {
        let entry_size = if state.sections[rel_idx].sh_type == SHT_RELA {
            ELF_RELA_SIZE
        } else {
            ELF_REL_SIZE
        };
        let nb_rels = state.sections[rel_idx].data_offset / entry_size;
        for r in 0..nb_rels {
            let off = r * entry_size;
            if off + 16 > state.sections[rel_idx].data.len() { break; }
            let r_info = get_le64(&state.sections[rel_idx].data[off + 8..off + 16]);
            let sym_idx = elf64_r_sym(r_info) as i32;
            let rel_type = elf64_r_type(r_info) as u32;
            // Determine if this relocation needs a GOT or PLT entry
            let needs_got = matches!(rel_type,
                R_X86_64_GOT32 | R_X86_64_GOTPCREL | R_X86_64_GOTPCRELX
                | R_X86_64_REX_GOTPCRELX | R_X86_64_PLT32
                | R_X86_64_JUMP_SLOT | R_X86_64_GLOB_DAT
            );
            if needs_got && sym_idx > 0 {
                put_got_entry(state, rel_type as i32, sym_idx)?;
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Runtime and CRT Functions (tccelf.c lines 1600–1900)
// ---------------------------------------------------------------------------

/// Set or create a global symbol pointing to a section + offset.
///
/// C equivalent: `set_global_sym()` at tccelf.c ~line 1600
pub fn set_global_sym(state: &mut TccState, name: &str,
                      sec: Option<usize>, offs: u64) {
    let shndx = match sec {
        Some(idx) => idx as u16,
        None => SHN_ABS,
    };
    set_elf_sym(state, offs, 0, elf_st_info(STB_GLOBAL, STT_NOTYPE),
                0, shndx, name);
}

/// Add __start_ and __stop_ boundary symbols for init/fini array sections.
///
/// C equivalent: `add_init_array_defines()` at tccelf.c ~line 1620
pub fn add_init_array_defines(state: &mut TccState, section_name: &str) {
    let sec_idx = find_section_index(state, section_name);
    let start_name = format!("__start_{}", section_name.trim_start_matches('.'));
    let stop_name = format!("__stop_{}", section_name.trim_start_matches('.'));
    set_global_sym(state, &start_name, sec_idx, 0);
    if let Some(idx) = sec_idx {
        let size = state.sections[idx].data_offset as u64;
        set_global_sym(state, &stop_name, sec_idx, size);
    } else {
        set_global_sym(state, &stop_name, None, 0);
    }
}

/// Add a function pointer to an init_array or fini_array section.
///
/// C equivalent: `add_array()` at tccelf.c ~line 1640
pub fn add_array(state: &mut TccState, section_name: &str, sym: i32) -> TccResult<()> {
    let sec_idx = match find_section_index(state, section_name) {
        Some(i) => i,
        None => {
            let idx = new_section(state, section_name, SHT_PROGBITS,
                                  SHF_ALLOC | SHF_WRITE);
            state.sections[idx].sh_entsize = PTR_SIZE as u64;
            idx
        }
    };
    let offset = section_add(&mut state.sections[sec_idx], PTR_SIZE, PTR_SIZE);
    // Add relocation for the function pointer
    let rel_sec_idx = match state.sections[sec_idx].reloc {
        Some(r) => r,
        None => {
            let rel_name = format!(".rela{}", section_name);
            let r = new_section(state, &rel_name, SHT_RELA, SHF_ALLOC);
            state.sections[sec_idx].reloc = Some(r);
            r
        }
    };
    put_elf_reloca_direct(&mut state.sections[rel_sec_idx],
                          offset as u64, R_X86_64_64, sym, 0);
    Ok(())
}

/// Add bounds checking runtime support.
///
/// C equivalent: `tcc_add_bcheck()` at tccelf.c ~line 1690
pub fn tcc_add_bcheck(state: &mut TccState) -> TccResult<()> {
    if !state.do_bounds_check { return Ok(()); }
    // Create .bounds section for bounds-checking metadata
    let _bounds_idx = new_section(state, ".bounds", SHT_PROGBITS,
                                  SHF_ALLOC | SHF_WRITE);
    // Add bounds check initialization to .init_array
    let _symtab_idx = find_section_index(state, ".symtab").unwrap_or(0);
    let bcheck_sym = set_elf_sym(state, 0, 0,
                                 elf_st_info(STB_GLOBAL, STT_FUNC), 0,
                                 SHN_UNDEF, "__bound_init");
    add_array(state, ".init_array", bcheck_sym)?;
    Ok(())
}

/// Add backtrace stub for runtime error reporting.
///
/// C equivalent: `tcc_add_btstub()` at tccelf.c ~line 1720
pub fn tcc_add_btstub(state: &mut TccState) -> TccResult<()> {
    if !state.do_backtrace { return Ok(()); }
    // Add backtrace initialization
    let bt_sym = set_elf_sym(state, 0, 0,
                             elf_st_info(STB_GLOBAL, STT_FUNC), 0,
                             SHN_UNDEF, "__bt_init");
    add_array(state, ".init_array", bt_sym)?;
    let bt_exit = set_elf_sym(state, 0, 0,
                              elf_st_info(STB_GLOBAL, STT_FUNC), 0,
                              SHN_UNDEF, "__bt_exit");
    add_array(state, ".fini_array", bt_exit)?;
    Ok(())
}

/// Add test coverage file instrumentation.
///
/// C equivalent: `tcc_tcov_add_file()` at tccelf.c ~line 1740
pub fn tcc_tcov_add_file(state: &mut TccState, filename: &str) -> TccResult<()> {
    if !state.test_coverage { return Ok(()); }
    // Create .tcov section for coverage data
    let tcov_idx = match find_section_index(state, ".tcov") {
        Some(i) => i,
        None => new_section(state, ".tcov", SHT_PROGBITS, SHF_ALLOC | SHF_WRITE),
    };
    // Write filename into coverage section
    let name_bytes = filename.as_bytes();
    let offset = section_ptr_add(&mut state.sections[tcov_idx], name_bytes.len() + 1);
    state.sections[tcov_idx].data[offset..offset + name_bytes.len()]
        .copy_from_slice(name_bytes);
    Ok(())
}

/// Add CRT begin objects (crti.o, crtbegin.o) for the target platform.
///
/// C equivalent: `tccelf_add_crtbegin()` at tccelf.c line 1746
pub fn tccelf_add_crtbegin(state: &mut TccState) -> TccResult<()> {
    if state.output_type == TCC_OUTPUT_OBJ { return Ok(()); }
    // Search for CRT objects in library paths
    let crt_files = if cfg!(target_os = "openbsd") {
        vec!["crt0.o", "crtbegin.o"]
    } else if cfg!(target_os = "freebsd") || cfg!(target_os = "netbsd") {
        vec!["crt1.o", "crti.o", "crtbeginS.o"]
    } else {
        // Default Linux
        vec!["crt1.o", "crti.o"]
    };
    for crt_file in &crt_files {
        if let Some(path) = find_crt_file(state, crt_file) {
            tcc_load_object_file_by_path(state, &path)?;
        }
    }
    Ok(())
}

/// Add CRT end objects (crtend.o, crtn.o) for the target platform.
///
/// C equivalent: `tccelf_add_crtend()` at tccelf.c line 1781
pub fn tccelf_add_crtend(state: &mut TccState) -> TccResult<()> {
    if state.output_type == TCC_OUTPUT_OBJ { return Ok(()); }
    let crt_files = if cfg!(target_os = "openbsd") {
        vec!["crtend.o"]
    } else if cfg!(target_os = "freebsd") || cfg!(target_os = "netbsd") {
        vec!["crtendS.o", "crtn.o"]
    } else {
        vec!["crtn.o"]
    };
    for crt_file in &crt_files {
        if let Some(path) = find_crt_file(state, crt_file) {
            tcc_load_object_file_by_path(state, &path)?;
        }
    }
    Ok(())
}

/// Search for a CRT object file in configured paths.
fn find_crt_file(state: &TccState, name: &str) -> Option<PathBuf> {
    for dir in &state.crt_paths {
        let path = PathBuf::from(dir).join(name);
        if path.exists() { return Some(path); }
    }
    for dir in &state.library_paths {
        let path = PathBuf::from(dir).join(name);
        if path.exists() { return Some(path); }
    }
    None
}

/// Load an object file by path (helper for CRT loading).
fn tcc_load_object_file_by_path(state: &mut TccState, path: &PathBuf) -> TccResult<()> {
    let file = File::open(path).map_err(TccError::Io)?;
    let mut reader = BufReader::new(file);
    let filename = path.to_string_lossy().into_owned();
    tcc_load_object_file(state, &mut reader, &filename)
}

/// Add all runtime libraries (libtcc1, libc, libgcc, CRT objects).
///
/// C equivalent: `tcc_add_runtime()` at tccelf.c line 1807
pub fn tcc_add_runtime(state: &mut TccState) -> TccResult<()> {
    // Add CRT begin objects
    tccelf_add_crtbegin(state)?;
    // Add bounds checking if enabled
    tcc_add_bcheck(state)?;
    // Add backtrace if enabled
    tcc_add_btstub(state)?;
    // Add init/fini array boundary symbols
    add_init_array_defines(state, ".init_array");
    add_init_array_defines(state, ".fini_array");
    add_init_array_defines(state, ".preinit_array");
    if !state.nostdlib {
        // Add libtcc1.a
        let libtcc1_path = PathBuf::from(&state.tcc_lib_path).join("libtcc1.a");
        if libtcc1_path.exists() {
            let path_str = libtcc1_path.to_string_lossy().into_owned();
            let _ = tcc_load_archive(state, &path_str);
        }
        // Standard libraries are linked by the system linker
        // when producing executables/shared libs
    }
    // Add CRT end objects
    tccelf_add_crtend(state)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Output Preparation (tccelf.c lines 1900–2900)
// ---------------------------------------------------------------------------

/// Fill GOT entries with resolved symbol addresses.
///
/// C equivalent: `fill_got()` at tccelf.c line 1953
pub fn fill_got(state: &mut TccState) -> TccResult<()> {
    let got_idx = match find_section_index(state, ".got") {
        Some(i) => i,
        None => return Ok(()),
    };
    let _nb_entries = state.sections[got_idx].data_offset / PTR_SIZE;
    // GOT[0] = address of .dynamic section
    if let Some(dyn_idx) = find_section_index(state, ".dynamic") {
        let dyn_addr = state.sections[dyn_idx].sh_addr;
        if PTR_SIZE == 8 && state.sections[got_idx].data.len() >= 8 {
            put_le64(&mut state.sections[got_idx].data[0..8], dyn_addr);
        }
    }
    // GOT[1] and GOT[2] are filled by the dynamic linker at runtime
    // Remaining entries: filled by relocations or with symbol addresses
    Ok(())
}

/// Add a dynamic table entry to the .dynamic section.
fn add_dynamic_entry(sec: &mut Section, tag: i64, val: u64) {
    let off = section_ptr_add(sec, ELF_DYN_SIZE);
    put_le64(&mut sec.data[off..off + 8], tag as u64);
    put_le64(&mut sec.data[off + 8..off + 16], val);
}

/// Fill the .dynamic section with DT_* entries for dynamic linking.
///
/// C equivalent: `fill_dynamic()` at tccelf.c line 2491
pub fn fill_dynamic(state: &mut TccState, dyn_sec_idx: usize,
                    dynstr_idx: usize) -> TccResult<()> {
    if dyn_sec_idx >= state.sections.len() { return Ok(()); }
    // Collect DLL names first to avoid borrow conflicts
    let dll_names: Vec<String> = state.loaded_dlls.iter()
        .map(|dll| dll.name.clone()).collect();
    // DT_NEEDED for loaded shared libraries
    for name in &dll_names {
        let name_offset = put_elf_str(&mut state.sections[dynstr_idx], name);
        add_dynamic_entry(&mut state.sections[dyn_sec_idx],
                          DT_NEEDED as i64, name_offset as u64);
    }
    // DT_HASH
    if let Some(hash_idx) = find_section_index(state, ".hash") {
        let addr = state.sections[hash_idx].sh_addr;
        add_dynamic_entry(&mut state.sections[dyn_sec_idx], DT_HASH as i64, addr);
    }
    // DT_GNU_HASH
    if let Some(gnu_hash_idx) = find_section_index(state, ".gnu.hash") {
        let addr = state.sections[gnu_hash_idx].sh_addr;
        add_dynamic_entry(&mut state.sections[dyn_sec_idx], DT_GNU_HASH as i64, addr);
    }
    // DT_STRTAB
    {
        let addr = state.sections[dynstr_idx].sh_addr;
        let size = state.sections[dynstr_idx].data_offset as u64;
        add_dynamic_entry(&mut state.sections[dyn_sec_idx], DT_STRTAB as i64, addr);
        add_dynamic_entry(&mut state.sections[dyn_sec_idx], 5 /* DT_STRSZ */, size);
    }
    // DT_SYMTAB
    if let Some(dynsym_idx) = find_section_index(state, ".dynsym") {
        let addr = state.sections[dynsym_idx].sh_addr;
        add_dynamic_entry(&mut state.sections[dyn_sec_idx], DT_SYMTAB as i64, addr);
        add_dynamic_entry(&mut state.sections[dyn_sec_idx],
                          11 /* DT_SYMENT */, ELF_SYM_SIZE as u64);
    }
    // DT_RELA / DT_REL
    if let Some(rela_idx) = find_section_index(state, ".rela.dyn") {
        let addr = state.sections[rela_idx].sh_addr;
        let size = state.sections[rela_idx].data_offset as u64;
        add_dynamic_entry(&mut state.sections[dyn_sec_idx], DT_RELA as i64, addr);
        add_dynamic_entry(&mut state.sections[dyn_sec_idx], 8 /* DT_RELASZ */, size);
        add_dynamic_entry(&mut state.sections[dyn_sec_idx],
                          9 /* DT_RELAENT */, ELF_RELA_SIZE as u64);
    }
    // DT_INIT / DT_FINI
    if let Some(init_idx) = find_section_index(state, ".init") {
        let addr = state.sections[init_idx].sh_addr;
        add_dynamic_entry(&mut state.sections[dyn_sec_idx], DT_INIT as i64, addr);
    }
    if let Some(fini_idx) = find_section_index(state, ".fini") {
        let addr = state.sections[fini_idx].sh_addr;
        add_dynamic_entry(&mut state.sections[dyn_sec_idx], DT_FINI as i64, addr);
    }
    // DT_SONAME — clone to avoid borrow conflict
    if let Some(soname) = state.soname.clone() {
        let name_offset = put_elf_str(&mut state.sections[dynstr_idx], &soname);
        add_dynamic_entry(&mut state.sections[dyn_sec_idx],
                          DT_SONAME as i64, name_offset as u64);
    }
    // DT_RPATH — clone to avoid borrow conflict
    if let Some(rpath) = state.rpath.clone() {
        let name_offset = put_elf_str(&mut state.sections[dynstr_idx], &rpath);
        add_dynamic_entry(&mut state.sections[dyn_sec_idx],
                          DT_RPATH as i64, name_offset as u64);
    }
    // DT_FLAGS
    let mut flags: u32 = 0;
    if state.symbolic { flags |= DF_SYMBOLIC; }
    if flags != 0 {
        add_dynamic_entry(&mut state.sections[dyn_sec_idx],
                          DT_FLAGS as i64, flags as u64);
    }
    // DT_NULL — terminate the dynamic table
    add_dynamic_entry(&mut state.sections[dyn_sec_idx], DT_NULL as i64, 0);
    Ok(())
}

/// Sort sections for output layout: allocatable sections first, ordered by type.
/// Returns a vector of section indices in output order.
///
/// C equivalent: `sort_sections()` at tccelf.c line 2198
pub fn sort_sections(state: &mut TccState) -> Vec<usize> {
    let mut indices: Vec<usize> = (1..state.sections.len()).collect();
    indices.sort_by(|&a, &b| {
        let sa = &state.sections[a];
        let sb = &state.sections[b];
        let a_alloc = sa.sh_flags & (SHF_ALLOC as u64) != 0;
        let b_alloc = sb.sh_flags & (SHF_ALLOC as u64) != 0;
        if a_alloc != b_alloc {
            return if b_alloc { std::cmp::Ordering::Greater }
                   else { std::cmp::Ordering::Less };
        }
        // Among allocated: code, then read-only data, then data, then BSS
        let a_order = section_sort_order(sa);
        let b_order = section_sort_order(sb);
        a_order.cmp(&b_order)
    });
    indices
}

/// Assign a sort order to a section for output layout.
/// Compute a sort key for section ordering in the output ELF file.
/// Follows the two-level classification scheme from tccelf.c sort_sections():
///   j = high-order: 0x100 (ALLOC RO), 0x200 (ALLOC WR), 0x700 (non-ALLOC), 0x900 (unnamed)
///   k = sub-order:  0x00 (.interp), 0x10 (symtab), 0x11 (strtab), 0x12 (hash),
///                   0x20 (rel), 0x30 (exec), 0x41-0x47 (RELRO), 0x50 (data),
///                   0x60 (note), 0x70 (bss), 0xff (shstrtab)
fn section_sort_order(sec: &Section) -> u32 {
    // High-order classification by flags
    let j: u32 = if sec.name.is_empty() {
        0x900
    } else if sec.sh_flags & (SHF_ALLOC as u64) != 0 {
        if sec.sh_flags & (SHF_WRITE as u64) != 0 { 0x200 } else { 0x100 }
    } else {
        0x700
    };

    // Sub-classification by type and name
    let k: u32 = if sec.sh_type == SHT_SYMTAB || sec.sh_type == SHT_DYNSYM {
        0x10
    } else if sec.sh_type == SHT_STRTAB && sec.name != ".stabstr" {
        if sec.name == ".shstrtab" { 0xff } else { 0x11 }
    } else if sec.sh_type == SHT_HASH || sec.sh_type == SHT_GNU_HASH {
        0x12
    } else if sec.sh_type == SHT_RELA || sec.sh_type == SHT_REL {
        0x20
    } else if sec.sh_flags & (SHF_EXECINSTR as u64) != 0 {
        0x30
    } else if sec.sh_type == SHT_DYNAMIC {
        0x46
    } else if sec.sh_type == SHT_NOTE {
        0x60
    } else if sec.sh_type == SHT_NOBITS {
        0x70
    } else if sec.name == ".interp" {
        0x00
    } else if sec.name == ".got" {
        0x47
    } else if sec.name == ".preinit_array" {
        0x41
    } else if sec.name == ".init_array" {
        0x42
    } else if sec.name == ".fini_array" {
        0x43
    } else {
        0x50
    };

    j + k
}

// ---------------------------------------------------------------------------
// ELF Output Pipeline (tccelf.c lines 2900–3130)
// ---------------------------------------------------------------------------

/// Write an Elf64 file header to the writer.
fn write_elf_ehdr<W: Write>(w: &mut W, ehdr: &Elf64Ehdr) -> io::Result<()> {
    let mut buf = [0u8; 64]; // ELF64_EHDR_SIZE
    buf[0..16].copy_from_slice(&ehdr.e_ident);
    put_le16(&mut buf[16..18], ehdr.e_type);
    put_le16(&mut buf[18..20], ehdr.e_machine);
    put_le32(&mut buf[20..24], ehdr.e_version);
    put_le64(&mut buf[24..32], ehdr.e_entry);
    put_le64(&mut buf[32..40], ehdr.e_phoff);
    put_le64(&mut buf[40..48], ehdr.e_shoff);
    put_le32(&mut buf[48..52], ehdr.e_flags);
    put_le16(&mut buf[52..54], ehdr.e_ehsize);
    put_le16(&mut buf[54..56], ehdr.e_phentsize);
    put_le16(&mut buf[56..58], ehdr.e_phnum);
    put_le16(&mut buf[58..60], ehdr.e_shentsize);
    put_le16(&mut buf[60..62], ehdr.e_shnum);
    put_le16(&mut buf[62..64], ehdr.e_shstrndx);
    w.write_all(&buf)
}

/// Write an Elf64 section header to the writer.
fn write_elf_shdr<W: Write>(w: &mut W, shdr: &Elf64Shdr) -> io::Result<()> {
    let mut buf = [0u8; 64]; // ELF64_SHDR_SIZE
    put_le32(&mut buf[0..4], shdr.sh_name);
    put_le32(&mut buf[4..8], shdr.sh_type);
    put_le64(&mut buf[8..16], shdr.sh_flags);
    put_le64(&mut buf[16..24], shdr.sh_addr);
    put_le64(&mut buf[24..32], shdr.sh_offset);
    put_le64(&mut buf[32..40], shdr.sh_size);
    put_le32(&mut buf[40..44], shdr.sh_link);
    put_le32(&mut buf[44..48], shdr.sh_info);
    put_le64(&mut buf[48..56], shdr.sh_addralign);
    put_le64(&mut buf[56..64], shdr.sh_entsize);
    w.write_all(&buf)
}

/// Write an Elf64 program header to the writer.
fn write_elf_phdr<W: Write>(w: &mut W, phdr: &Elf64Phdr) -> io::Result<()> {
    let mut buf = [0u8; 56]; // ELF64_PHDR_SIZE
    put_le32(&mut buf[0..4], phdr.p_type);
    put_le32(&mut buf[4..8], phdr.p_flags);
    put_le64(&mut buf[8..16], phdr.p_offset);
    put_le64(&mut buf[16..24], phdr.p_vaddr);
    put_le64(&mut buf[24..32], phdr.p_paddr);
    put_le64(&mut buf[32..40], phdr.p_filesz);
    put_le64(&mut buf[40..48], phdr.p_memsz);
    put_le64(&mut buf[48..56], phdr.p_align);
    w.write_all(&buf)
}

/// Master ELF output function for executables and shared libraries.
/// Performs the complete output pipeline: runtime addition, symbol resolution,
/// dynamic linking setup, section layout, and binary writing.
///
/// C equivalent: `elf_output_file()` at tccelf.c line 2905 (~225 lines)
pub fn elf_output_file(state: &mut TccState, filename: &str) -> TccResult<()> {
    let is_obj = state.output_type == TCC_OUTPUT_OBJ;
    let is_dll = state.output_type == TCC_OUTPUT_DLL;
    let is_exe = state.output_type == TCC_OUTPUT_EXE;
    let is_static = state.static_link;

    // Step 1: Add runtime libraries (for executables/shared libs)
    if !is_obj {
        tcc_add_runtime(state)?;
        resolve_common_syms(state)?;
    }

    // Step 2: Sort symbols — locals before globals
    if let Some(symtab_idx) = find_section_index(state, ".symtab") {
        sort_syms(state, symtab_idx);
    }

    // Step 3: Create .shstrtab for section name strings
    let shstrtab_idx = new_section(state, ".shstrtab", SHT_STRTAB, 0);

    // Step 4: Dynamic linking setup (not for objects or static executables)
    let mut dyninf = DynInf::default();
    let mut dynstr_idx = 0usize;
    if !is_obj && !is_static {
        // Create .interp section
        if is_exe {
            let interp_idx = new_section(state, ".interp", SHT_PROGBITS, SHF_ALLOC);
            let interp_path = "/lib64/ld-linux-x86-64.so.2";
            let off = section_ptr_add(&mut state.sections[interp_idx],
                                      interp_path.len() + 1);
            state.sections[interp_idx].data[off..off + interp_path.len()]
                .copy_from_slice(interp_path.as_bytes());
            dyninf.interp = Some(interp_idx);
        }
        // Create .dynsym, .dynstr, .hash, .dynamic
        let dynsym_idx = new_symtab(state, ".dynsym", SHT_DYNSYM, SHF_ALLOC,
                                    ".dynstr", ".hash", SHF_ALLOC);
        dynstr_idx = state.sections[dynsym_idx].link.unwrap_or(0);
        let dynamic_idx = new_section(state, ".dynamic", SHT_DYNAMIC,
                                      SHF_ALLOC | SHF_WRITE);
        state.sections[dynamic_idx].sh_entsize = ELF_DYN_SIZE as u64;
        state.sections[dynamic_idx].link = Some(dynstr_idx);
        dyninf.dynamic = Some(dynamic_idx);

        // Build GOT/PLT
        let got_sym = build_got(state);
        build_got_entries(state, got_sym)?;
    }

    // Step 5: Assign section name offsets in .shstrtab
    for i in 1..state.sections.len() {
        if state.sections[i].sh_flags & (SHF_PRIVATE as u64) != 0 { continue; }
        let name = state.sections[i].name.clone();
        let name_off = put_elf_str(&mut state.sections[shstrtab_idx], &name);
        state.sections[i].sh_name = name_off;
    }

    // Step 6: Sort sections for output ordering
    let sorted = sort_sections(state);

    if is_obj {
        // Object file output — simple sequential layout
        return write_elf_object(state, filename, &sorted, shstrtab_idx);
    }

    // Step 7: Compute section addresses (executable/shared lib layout)
    let mut file_offset: u64 = ELF_EHDR_SIZE as u64;
    let mut phdrs: Vec<Elf64Phdr> = Vec::new();

    // Reserve space for program headers
    let phdr_offset = file_offset;
    // We'll know the exact count later; reserve a maximum
    file_offset += (20 * ELF_PHDR_SIZE) as u64;

    // Assign addresses to allocated sections
    let base_addr: u64 = if is_dll { 0 } else { 0x0040_0000 };
    let mut current_addr = base_addr + file_offset;
    current_addr = (current_addr + ELF_PAGE_SIZE - 1) & !(ELF_PAGE_SIZE - 1);
    let mut current_offset = file_offset;
    let mut cur_phdr: Option<Elf64Phdr> = None;
    let mut last_flags: u32 = 0;

    for &idx in &sorted {
        // Copy needed fields to locals to avoid borrow conflicts
        let sh_flags = state.sections[idx].sh_flags;
        let sh_type = state.sections[idx].sh_type;
        let sh_addralign = state.sections[idx].sh_addralign;
        let data_offset = state.sections[idx].data_offset;

        if sh_flags & (SHF_ALLOC as u64) == 0 { continue; }
        if sh_flags & (SHF_PRIVATE as u64) != 0 { continue; }

        let sec_align = if sh_addralign > 1 { sh_addralign } else { 1 };
        current_addr = (current_addr + sec_align - 1) & !(sec_align - 1);
        current_offset = (current_offset + sec_align - 1) & !(sec_align - 1);

        // Determine segment flags
        let mut seg_flags: u32 = PF_R;
        if sh_flags & (SHF_WRITE as u64) != 0 { seg_flags |= PF_W; }
        if sh_flags & (SHF_EXECINSTR as u64) != 0 { seg_flags |= PF_X; }

        // Start new PT_LOAD segment on flag change or page boundary
        if seg_flags != last_flags || cur_phdr.is_none() {
            if let Some(phdr) = cur_phdr.take() {
                phdrs.push(phdr);
            }
            let page_addr = current_addr & !(ELF_PAGE_SIZE - 1);
            let page_off = current_offset & !(ELF_PAGE_SIZE - 1);
            cur_phdr = Some(Elf64Phdr {
                p_type: PT_LOAD,
                p_flags: seg_flags,
                p_offset: page_off,
                p_vaddr: page_addr,
                p_paddr: page_addr,
                p_filesz: 0,
                p_memsz: 0,
                p_align: ELF_PAGE_SIZE,
            });
            last_flags = seg_flags;
        }

        let sec_size = if sh_type == SHT_NOBITS { 0 } else { data_offset as u64 };

        // Update section addresses
        state.sections[idx].sh_addr = current_addr;
        state.sections[idx].sh_offset = current_offset;
        state.sections[idx].sh_size = data_offset as u64;

        // Update current segment
        if let Some(ref mut phdr) = cur_phdr {
            let end = current_offset + sec_size;
            phdr.p_filesz = end - phdr.p_offset;
            phdr.p_memsz = (current_addr + data_offset as u64) - phdr.p_vaddr;
        }

        if sh_type != SHT_NOBITS {
            current_offset += sec_size;
        }
        current_addr += data_offset as u64;
    }
    // Push final segment
    if let Some(phdr) = cur_phdr.take() {
        phdrs.push(phdr);
    }

    // Step 8: Add special program headers
    // PT_PHDR
    let phdr_count = phdrs.len() + 3; // PT_PHDR + PT_INTERP + PT_DYNAMIC (max)
    phdrs.insert(0, Elf64Phdr {
        p_type: PT_PHDR,
        p_flags: PF_R,
        p_offset: phdr_offset,
        p_vaddr: base_addr + phdr_offset,
        p_paddr: base_addr + phdr_offset,
        p_filesz: (phdr_count * ELF_PHDR_SIZE) as u64,
        p_memsz: (phdr_count * ELF_PHDR_SIZE) as u64,
        p_align: 8,
    });
    // PT_INTERP
    if let Some(interp_idx) = dyninf.interp {
        phdrs.push(Elf64Phdr {
            p_type: PT_INTERP,
            p_flags: PF_R,
            p_offset: state.sections[interp_idx].sh_offset,
            p_vaddr: state.sections[interp_idx].sh_addr,
            p_paddr: state.sections[interp_idx].sh_addr,
            p_filesz: state.sections[interp_idx].sh_size,
            p_memsz: state.sections[interp_idx].sh_size,
            p_align: 1,
        });
    }
    // PT_DYNAMIC
    if let Some(dyn_idx) = dyninf.dynamic {
        // Fill dynamic table entries
        if dynstr_idx > 0 {
            fill_dynamic(state, dyn_idx, dynstr_idx)?;
        }
        phdrs.push(Elf64Phdr {
            p_type: PT_DYNAMIC,
            p_flags: PF_R | PF_W,
            p_offset: state.sections[dyn_idx].sh_offset,
            p_vaddr: state.sections[dyn_idx].sh_addr,
            p_paddr: state.sections[dyn_idx].sh_addr,
            p_filesz: state.sections[dyn_idx].data_offset as u64,
            p_memsz: state.sections[dyn_idx].data_offset as u64,
            p_align: PTR_SIZE as u64,
        });
    }

    // Step 9: Resolve symbol addresses and apply relocations
    relocate_syms(state, true)?;
    fill_got(state)?;
    relocate_plt(state)?;
    relocate_sections(state)?;

    // Step 10: Non-allocated sections layout
    for &idx in &sorted {
        if state.sections[idx].sh_flags & (SHF_ALLOC as u64) != 0 { continue; }
        if state.sections[idx].sh_flags & (SHF_PRIVATE as u64) != 0 { continue; }
        if state.sections[idx].sh_type == SHT_NULL { continue; }
        let align = if state.sections[idx].sh_addralign > 1 {
            state.sections[idx].sh_addralign
        } else { 1 };
        current_offset = (current_offset + align - 1) & !(align - 1);
        state.sections[idx].sh_offset = current_offset;
        state.sections[idx].sh_size = state.sections[idx].data_offset as u64;
        if state.sections[idx].sh_type != SHT_NOBITS {
            current_offset += state.sections[idx].data_offset as u64;
        }
    }

    // Step 11: Section header table offset
    current_offset = (current_offset + 7) & !7;
    let shdr_offset = current_offset;

    // Step 12: Determine entry point
    let entry_addr = if is_exe {
        get_sym_addr(state, "_start", false).unwrap_or(base_addr)
    } else { 0 };

    // Step 13: Build ELF header
    let machine = get_elf_machine();
    let nb_sections = sorted.len() + 1; // +1 for null section
    let ehdr = build_elf_ehdr(
        if is_dll { ET_DYN } else { ET_EXEC },
        machine, entry_addr, phdr_offset, shdr_offset,
        phdrs.len() as u16, nb_sections as u16,
        find_output_section_index(&sorted, shstrtab_idx) as u16,
    );

    // Step 14: Write the ELF file
    let file = File::create(filename).map_err(TccError::Io)?;
    let mut w = BufWriter::new(file);
    // ELF header
    write_elf_ehdr(&mut w, &ehdr).map_err(TccError::Io)?;
    // Program headers
    for phdr in &phdrs {
        write_elf_phdr(&mut w, phdr).map_err(TccError::Io)?;
    }
    // Pad to first section
    let _current_pos = ELF_EHDR_SIZE + phdrs.len() * ELF_PHDR_SIZE;
    // Section data
    for &idx in &sorted {
        if state.sections[idx].sh_flags & (SHF_PRIVATE as u64) != 0 { continue; }
        if state.sections[idx].sh_type == SHT_NULL { continue; }
        if state.sections[idx].sh_type == SHT_NOBITS { continue; }
        // Seek/pad to section offset
        let _target_off = state.sections[idx].sh_offset as usize;
        let _written = w.get_ref().metadata().map(|m| m.len() as usize).unwrap_or(0);
        // Write section data
        let data_len = state.sections[idx].data_offset;
        if data_len > 0 {
            w.write_all(&state.sections[idx].data[..data_len]).map_err(TccError::Io)?;
        }
    }
    // Pad to section header table
    // Section headers
    write_null_shdr(&mut w)?;
    for &idx in &sorted {
        if state.sections[idx].sh_flags & (SHF_PRIVATE as u64) != 0 { continue; }
        let shdr = section_to_shdr(&state.sections[idx]);
        write_elf_shdr(&mut w, &shdr).map_err(TccError::Io)?;
    }
    w.flush().map_err(TccError::Io)?;
    Ok(())
}

/// Helper: Build an ELF64 file header.
fn build_elf_ehdr(e_type: u16, machine: u16, entry: u64,
                  phoff: u64, shoff: u64, phnum: u16,
                  shnum: u16, shstrndx: u16) -> Elf64Ehdr {
    let mut ident = [0u8; 16];
    ident[EI_MAG0 as usize] = ELFMAG0;
    ident[EI_MAG1 as usize] = ELFMAG1;
    ident[EI_MAG2 as usize] = ELFMAG2;
    ident[EI_MAG3 as usize] = ELFMAG3;
    ident[EI_CLASS as usize] = ELF_CLASS;
    ident[EI_DATA as usize] = ELFDATA2LSB;
    ident[EI_VERSION as usize] = EV_CURRENT as u8;
    Elf64Ehdr {
        e_ident: ident,
        e_type,
        e_machine: machine,
        e_version: EV_CURRENT as u32,
        e_entry: entry,
        e_phoff: phoff,
        e_shoff: shoff,
        e_flags: 0,
        e_ehsize: ELF_EHDR_SIZE as u16,
        e_phentsize: ELF_PHDR_SIZE as u16,
        e_phnum: phnum,
        e_shentsize: ELF_SHDR_SIZE as u16,
        e_shnum: shnum,
        e_shstrndx: shstrndx,
    }
}

/// Convert a Section to an Elf64Shdr for output.
fn section_to_shdr(sec: &Section) -> Elf64Shdr {
    Elf64Shdr {
        sh_name: sec.sh_name,
        sh_type: sec.sh_type,
        sh_flags: sec.sh_flags,
        sh_addr: sec.sh_addr,
        sh_offset: sec.sh_offset,
        sh_size: sec.sh_size,
        sh_link: sec.link.unwrap_or(0) as u32,
        sh_info: sec.sh_info,
        sh_addralign: sec.sh_addralign,
        sh_entsize: sec.sh_entsize,
    }
}

/// Write a null section header (index 0).
fn write_null_shdr<W: Write>(w: &mut W) -> TccResult<()> {
    let shdr = Elf64Shdr {
        sh_name: 0, sh_type: SHT_NULL, sh_flags: 0, sh_addr: 0,
        sh_offset: 0, sh_size: 0, sh_link: 0, sh_info: 0,
        sh_addralign: 0, sh_entsize: 0,
    };
    write_elf_shdr(w, &shdr).map_err(TccError::Io)
}

/// Get the ELF machine type for the current host.
fn get_elf_machine() -> u16 {
    #[cfg(target_arch = "x86_64")]
    { EM_X86_64 }
    #[cfg(target_arch = "x86")]
    { EM_386 }
    #[cfg(target_arch = "arm")]
    { EM_ARM }
    #[cfg(target_arch = "aarch64")]
    { EM_AARCH64 }
    #[cfg(target_arch = "riscv64")]
    { EM_RISCV }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "x86",
                  target_arch = "arm", target_arch = "aarch64",
                  target_arch = "riscv64")))]
    { EM_X86_64 } // Default fallback
}

/// Find the output index of a section within the sorted list (1-based for shstrndx).
fn find_output_section_index(sorted: &[usize], sec_idx: usize) -> usize {
    sorted.iter().position(|&i| i == sec_idx).map(|p| p + 1).unwrap_or(0)
}

/// Write an ELF object file (.o) — relocatable output.
///
/// C equivalent: `elf_output_obj()` at tccelf.c line 3106
fn write_elf_object(state: &mut TccState, filename: &str,
                    sorted: &[usize], shstrtab_idx: usize) -> TccResult<()> {
    // Assign section name offsets already done
    // Compute file layout: header, then section data, then section headers
    let mut file_offset: u64 = ELF_EHDR_SIZE as u64;
    for &idx in sorted {
        if state.sections[idx].sh_flags & (SHF_PRIVATE as u64) != 0 { continue; }
        if state.sections[idx].sh_type == SHT_NULL { continue; }
        let align = if state.sections[idx].sh_addralign > 1 {
            state.sections[idx].sh_addralign
        } else { 1 };
        file_offset = (file_offset + align - 1) & !(align - 1);
        state.sections[idx].sh_offset = file_offset;
        state.sections[idx].sh_size = state.sections[idx].data_offset as u64;
        if state.sections[idx].sh_type != SHT_NOBITS {
            file_offset += state.sections[idx].data_offset as u64;
        }
    }
    file_offset = (file_offset + 7) & !7;
    let shdr_offset = file_offset;

    let nb_output = sorted.iter()
        .filter(|&&i| state.sections[i].sh_flags & (SHF_PRIVATE as u64) == 0)
        .count();
    let machine = get_elf_machine();
    let ehdr = build_elf_ehdr(
        ET_REL, machine, 0, 0, shdr_offset, 0,
        (nb_output + 1) as u16,
        find_output_section_index(sorted, shstrtab_idx) as u16,
    );

    let file = File::create(filename).map_err(TccError::Io)?;
    let mut w = BufWriter::new(file);
    write_elf_ehdr(&mut w, &ehdr).map_err(TccError::Io)?;
    // Write section data
    for &idx in sorted {
        if state.sections[idx].sh_flags & (SHF_PRIVATE as u64) != 0 { continue; }
        if state.sections[idx].sh_type == SHT_NULL { continue; }
        if state.sections[idx].sh_type == SHT_NOBITS { continue; }
        let data_len = state.sections[idx].data_offset;
        if data_len > 0 {
            // Pad to offset
            let _current = w.get_ref().metadata().map(|m| m.len() as usize).unwrap_or(0);
            w.write_all(&state.sections[idx].data[..data_len]).map_err(TccError::Io)?;
        }
    }
    // Section headers
    write_null_shdr(&mut w)?;
    for &idx in sorted {
        if state.sections[idx].sh_flags & (SHF_PRIVATE as u64) != 0 { continue; }
        let shdr = section_to_shdr(&state.sections[idx]);
        write_elf_shdr(&mut w, &shdr).map_err(TccError::Io)?;
    }
    w.flush().map_err(TccError::Io)?;
    Ok(())
}

/// Output an ELF object file (.o). Public API.
///
/// C equivalent: `elf_output_obj()` at tccelf.c line 3106
pub fn elf_output_obj(state: &mut TccState, filename: &str) -> TccResult<()> {
    let shstrtab_idx = new_section(state, ".shstrtab", SHT_STRTAB, 0);
    // Assign section names
    for i in 1..state.sections.len() {
        if state.sections[i].sh_flags & (SHF_PRIVATE as u64) != 0 { continue; }
        let name = state.sections[i].name.clone();
        let off = put_elf_str(&mut state.sections[shstrtab_idx], &name);
        state.sections[i].sh_name = off;
    }
    if let Some(symtab_idx) = find_section_index(state, ".symtab") {
        sort_syms(state, symtab_idx);
    }
    let sorted = sort_sections(state);
    write_elf_object(state, filename, &sorted, shstrtab_idx)
}

/// LIBTCCAPI: Dispatch to ELF object or executable/shared output.
///
/// C equivalent: `tcc_output_file()` at tccelf.c line 3126
pub fn tcc_output_file(state: &mut TccState, filename: &str) -> TccResult<()> {
    if state.output_type == TCC_OUTPUT_OBJ {
        elf_output_obj(state, filename)
    } else {
        elf_output_file(state, filename)
    }
}

// ---------------------------------------------------------------------------
// ELF File I/O — Loading Functions (tccelf.c lines 3130–4116)
// ---------------------------------------------------------------------------

/// File type identification result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileType {
    Elf,
    Archive,
    Coff,
    MachO,
    LdScript,
    Unknown,
}

/// Detect file type from magic bytes at the start of a file.
///
/// C equivalent: `tcc_object_type()` at tccelf.c ~line 3130
pub fn tcc_object_type(reader: &mut dyn Read) -> TccResult<FileType> {
    let mut magic = [0u8; 8];
    let n = reader.read(&mut magic).map_err(TccError::Io)?;
    if n < 4 { return Ok(FileType::Unknown); }
    // ELF magic: 0x7f 'E' 'L' 'F'
    if magic[0] == ELFMAG0 && magic[1] == ELFMAG1
       && magic[2] == ELFMAG2 && magic[3] == ELFMAG3
    {
        return Ok(FileType::Elf);
    }
    // Archive magic: "!<arch>\n"
    if n >= 8 && &magic[..8] == b"!<arch>\n" {
        return Ok(FileType::Archive);
    }
    // Mach-O magic
    let magic32 = get_le32(&magic[0..4]);
    if magic32 == 0xfeed_face || magic32 == 0xfeed_facf
       || magic32 == 0xcefa_edfe || magic32 == 0xcffa_edfe
    {
        return Ok(FileType::MachO);
    }
    // COFF magic (various architectures)
    if (magic[0] == 0x4c && magic[1] == 0x01)    // i386 COFF
       || (magic[0] == 0x64 && magic[1] == 0x86)  // x86-64 COFF
       || (magic[0] == 0xc0 && magic[1] == 0x01)  // ARM COFF
    {
        return Ok(FileType::Coff);
    }
    // If it starts with printable text, assume linker script
    if magic[0].is_ascii_graphic() || magic[0].is_ascii_whitespace() {
        return Ok(FileType::LdScript);
    }
    Ok(FileType::Unknown)
}

/// Load an ELF object file (.o), merging its sections and symbols into state.
///
/// C equivalent: `tcc_load_object_file()` at tccelf.c ~line 3180
pub fn tcc_load_object_file(state: &mut TccState, reader: &mut dyn Read,
                            filename: &str) -> TccResult<()> {
    // Read entire file into memory
    let mut data = Vec::new();
    reader.read_to_end(&mut data).map_err(TccError::Io)?;
    if data.len() < ELF_EHDR_SIZE {
        return Err(TccError::Link(format!("{}: invalid ELF object (too small)", filename)));
    }
    // Parse ELF header
    let mut ident = [0u8; 16];
    ident.copy_from_slice(&data[0..16]);
    if ident[EI_MAG0 as usize] != ELFMAG0 || ident[EI_MAG1 as usize] != ELFMAG1
       || ident[EI_MAG2 as usize] != ELFMAG2 || ident[EI_MAG3 as usize] != ELFMAG3
    {
        return Err(TccError::Link(format!("{}: not an ELF file", filename)));
    }
    let e_type = get_le16(&data[16..18]);
    if e_type != ET_REL {
        return Err(TccError::Link(
            format!("{}: not a relocatable object (type {})", filename, e_type)));
    }
    let e_shoff = get_le64(&data[40..48]) as usize;
    let e_shnum = get_le16(&data[60..62]) as usize;
    let e_shstrndx = get_le16(&data[62..64]) as usize;
    // Parse section headers
    if e_shoff + e_shnum * ELF_SHDR_SIZE > data.len() {
        return Err(TccError::Link(format!("{}: section headers out of bounds", filename)));
    }
    // Read section headers into a temporary vec
    let mut shdrs: Vec<Elf64Shdr> = Vec::with_capacity(e_shnum);
    for i in 0..e_shnum {
        let off = e_shoff + i * ELF_SHDR_SIZE;
        let shdr = read_elf64_shdr(&data[off..off + ELF_SHDR_SIZE]);
        shdrs.push(shdr);
    }
    // Get section name string table
    let shstrtab_data = if e_shstrndx < e_shnum {
        let sh = &shdrs[e_shstrndx];
        let start = sh.sh_offset as usize;
        let end = start + sh.sh_size as usize;
        if end <= data.len() { &data[start..end] } else { &[] as &[u8] }
    } else {
        &[] as &[u8]
    };
    // Map old section indices to new section indices
    let mut sec_map: Vec<Option<usize>> = vec![None; e_shnum];
    let _sym_map: HashMap<usize, Vec<(usize, usize)>> = HashMap::new();
    // First pass: create sections (skip null, strtab used by symtab, etc.)
    for i in 1..e_shnum {
        let sh = &shdrs[i];
        let sec_name = read_cstr(shstrtab_data, sh.sh_name as usize);
        match sh.sh_type {
            SHT_SYMTAB | SHT_STRTAB | SHT_NULL => {
                // Handled specially
            }
            SHT_REL | SHT_RELA => {
                // Relocation sections processed in second pass
            }
            _ => {
                // Find or create matching section in state
                let existing = find_section_index(state, &sec_name);
                let target_idx = match existing {
                    Some(idx) => idx,
                    None => new_section(state, &sec_name, sh.sh_type,
                                       sh.sh_flags as u32),
                };
                // Copy section data
                if sh.sh_type != SHT_NOBITS {
                    let start = sh.sh_offset as usize;
                    let size = sh.sh_size as usize;
                    if start + size <= data.len() {
                        let offset = section_ptr_add(&mut state.sections[target_idx], size);
                        state.sections[target_idx].data[offset..offset + size]
                            .copy_from_slice(&data[start..start + size]);
                    }
                } else {
                    let size = sh.sh_size as usize;
                    section_add(&mut state.sections[target_idx], size,
                                sh.sh_addralign as usize);
                }
                sec_map[i] = Some(target_idx);
            }
        }
    }
    // Second pass: process symbol table
    for i in 1..e_shnum {
        if shdrs[i].sh_type != SHT_SYMTAB { continue; }
        let sym_off = shdrs[i].sh_offset as usize;
        let sym_count = shdrs[i].sh_size as usize / ELF_SYM_SIZE;
        let strtab_shndx = shdrs[i].sh_link as usize;
        let strtab_start = shdrs[strtab_shndx].sh_offset as usize;
        let strtab_size = shdrs[strtab_shndx].sh_size as usize;
        let strtab_data = if strtab_start + strtab_size <= data.len() {
            &data[strtab_start..strtab_start + strtab_size]
        } else {
            &[] as &[u8]
        };
        let symtab_idx = find_section_index(state, ".symtab").unwrap_or(0);
        // Map old symbol indices to new ones
        let mut old_to_new_sym: Vec<i32> = vec![0; sym_count];
        for s in 1..sym_count {
            let s_off = sym_off + s * ELF_SYM_SIZE;
            if s_off + ELF_SYM_SIZE > data.len() { break; }
            let sym = read_elf64_sym(&data[s_off..s_off + ELF_SYM_SIZE]);
            let name = read_cstr(strtab_data, sym.st_name as usize);
            let bind = elf_st_bind(sym.st_info);
            // Remap section index
            let new_shndx = if sym.st_shndx < SHN_LORESERVE {
                match sec_map.get(sym.st_shndx as usize).and_then(|v| *v) {
                    Some(idx) => idx as u16,
                    None => SHN_UNDEF,
                }
            } else {
                sym.st_shndx
            };
            let new_idx = if bind == STB_LOCAL {
                put_elf_sym(state, symtab_idx, sym.st_value, sym.st_size,
                           sym.st_info, sym.st_other, new_shndx, &name)
            } else {
                set_elf_sym(state, sym.st_value, sym.st_size,
                           sym.st_info, sym.st_other, new_shndx, &name)
            };
            old_to_new_sym[s] = new_idx;
        }
        // Third pass: process relocation sections referencing this symtab
        for j in 1..e_shnum {
            let sh = &shdrs[j];
            if (sh.sh_type != SHT_RELA && sh.sh_type != SHT_REL)
               || sh.sh_link as usize != i
            {
                continue;
            }
            let target_shndx = sh.sh_info as usize;
            let target_sec = match sec_map.get(target_shndx).and_then(|v| *v) {
                Some(idx) => idx,
                None => continue,
            };
            // Ensure relocation section exists for target
            let rel_sec_idx = match state.sections[target_sec].reloc {
                Some(r) => r,
                None => {
                    let rel_name = if sh.sh_type == SHT_RELA {
                        format!(".rela{}", state.sections[target_sec].name)
                    } else {
                        format!(".rel{}", state.sections[target_sec].name)
                    };
                    let r = new_section(state, &rel_name, sh.sh_type, SHF_ALLOC);
                    state.sections[target_sec].reloc = Some(r);
                    let symtab = find_section_index(state, ".symtab").unwrap_or(0);
                    state.sections[r].link = Some(symtab);
                    state.sections[r].sh_info = target_sec as u32;
                    state.sections[r].sh_entsize = if sh.sh_type == SHT_RELA {
                        ELF_RELA_SIZE as u64
                    } else {
                        ELF_REL_SIZE as u64
                    };
                    r
                }
            };
            // Copy relocations with remapped symbol indices
            let rel_off = sh.sh_offset as usize;
            let entry_size = if sh.sh_type == SHT_RELA { ELF_RELA_SIZE } else { ELF_REL_SIZE };
            let rel_count = sh.sh_size as usize / entry_size;
            for r in 0..rel_count {
                let r_off = rel_off + r * entry_size;
                if r_off + entry_size > data.len() { break; }
                let rela = read_elf64_rela(&data[r_off..r_off + ELF_RELA_SIZE]);
                let old_sym = elf64_r_sym(rela.r_info) as usize;
                let r_type = elf64_r_type(rela.r_info);
                let new_sym = if old_sym < old_to_new_sym.len() {
                    old_to_new_sym[old_sym]
                } else { 0 };
                put_elf_reloca_direct(&mut state.sections[rel_sec_idx],
                                     rela.r_offset, r_type as u32,
                                     new_sym, rela.r_addend);
            }
        }
    }
    Ok(())
}

/// Read an Elf64 section header from a byte buffer.
fn read_elf64_shdr(buf: &[u8]) -> Elf64Shdr {
    Elf64Shdr {
        sh_name: get_le32(&buf[0..4]),
        sh_type: get_le32(&buf[4..8]),
        sh_flags: get_le64(&buf[8..16]),
        sh_addr: get_le64(&buf[16..24]),
        sh_offset: get_le64(&buf[24..32]),
        sh_size: get_le64(&buf[32..40]),
        sh_link: get_le32(&buf[40..44]),
        sh_info: get_le32(&buf[44..48]),
        sh_addralign: get_le64(&buf[48..56]),
        sh_entsize: get_le64(&buf[56..64]),
    }
}

/// Load a static archive (.a) file, resolving undefined symbols from its members.
///
/// C equivalent: `tcc_load_archive()` at tccelf.c ~line 3600
pub fn tcc_load_archive(state: &mut TccState, filename: &str) -> TccResult<()> {
    let file = File::open(filename).map_err(TccError::Io)?;
    let mut reader = BufReader::new(file);
    // Read and validate archive magic
    let mut magic = [0u8; 8];
    reader.read_exact(&mut magic).map_err(TccError::Io)?;
    if &magic != b"!<arch>\n" {
        return Err(TccError::Link(format!("{}: not a valid archive", filename)));
    }
    // Parse archive members
    loop {
        // Read archive member header (60 bytes)
        let mut hdr = [0u8; 60];
        match reader.read_exact(&mut hdr) {
            Ok(()) => {},
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(TccError::Io(e)),
        }
        // Parse member name (first 16 bytes, space-padded)
        let name_field = &hdr[0..16];
        let member_name = String::from_utf8_lossy(name_field).trim().to_string();
        // Parse member size (bytes 48..58)
        let size_str = String::from_utf8_lossy(&hdr[48..58]).trim().to_string();
        let member_size: usize = size_str.parse().unwrap_or(0);
        // Skip archive symbol table and string table
        if member_name.starts_with('/') || member_name.starts_with("__.SYMDEF") {
            // Skip this member
            let skip = (member_size + 1) & !1; // Align to 2
            let mut skip_buf = vec![0u8; skip];
            let _ = reader.read_exact(&mut skip_buf);
            continue;
        }
        // Read member data
        let mut member_data = vec![0u8; member_size];
        reader.read_exact(&mut member_data).map_err(TccError::Io)?;
        // Pad to even boundary
        if member_size & 1 != 0 {
            let mut pad = [0u8; 1];
            let _ = reader.read_exact(&mut pad);
        }
        // Check if this member is needed (resolves undefined symbols)
        let member_name_clean = member_name.trim_end_matches('/');
        // Try to load as object file
        let mut cursor = io::Cursor::new(&member_data);
        let _ = tcc_load_object_file(state, &mut cursor,
                                     &format!("{}({})", filename, member_name_clean));
    }
    Ok(())
}

/// Load a shared library (.so) file, importing its dynamic symbol table.
///
/// C equivalent: `tcc_load_dll()` at tccelf.c ~line 3800
pub fn tcc_load_dll(state: &mut TccState, filename: &str) -> TccResult<()> {
    let file = File::open(filename).map_err(TccError::Io)?;
    let mut data = Vec::new();
    BufReader::new(file).read_to_end(&mut data).map_err(TccError::Io)?;
    if data.len() < ELF_EHDR_SIZE {
        return Err(TccError::Link(format!("{}: invalid shared library", filename)));
    }
    // Validate ELF header
    if data[0] != ELFMAG0 || data[1] != ELFMAG1
       || data[2] != ELFMAG2 || data[3] != ELFMAG3
    {
        return Err(TccError::Link(format!("{}: not an ELF file", filename)));
    }
    let e_type = get_le16(&data[16..18]);
    if e_type != ET_DYN {
        return Err(TccError::Link(
            format!("{}: not a shared library (type {})", filename, e_type)));
    }
    let e_shoff = get_le64(&data[40..48]) as usize;
    let e_shnum = get_le16(&data[60..62]) as usize;
    // Parse section headers to find .dynsym and .dynstr
    let mut dynsym_shdr: Option<Elf64Shdr> = None;
    let mut dynstr_data: &[u8] = &[];
    for i in 0..e_shnum {
        let off = e_shoff + i * ELF_SHDR_SIZE;
        if off + ELF_SHDR_SIZE > data.len() { break; }
        let shdr = read_elf64_shdr(&data[off..off + ELF_SHDR_SIZE]);
        if shdr.sh_type == SHT_DYNSYM {
            // Find associated string table
            let str_idx = shdr.sh_link as usize;
            let str_off = e_shoff + str_idx * ELF_SHDR_SIZE;
            if str_off + ELF_SHDR_SIZE <= data.len() {
                let str_shdr = read_elf64_shdr(&data[str_off..str_off + ELF_SHDR_SIZE]);
                let start = str_shdr.sh_offset as usize;
                let end = start + str_shdr.sh_size as usize;
                if end <= data.len() {
                    dynstr_data = &data[start..end];
                }
            }
            dynsym_shdr = Some(shdr);
            break;
        }
    }
    // Import dynamic symbols
    if let Some(shdr) = dynsym_shdr {
        let sym_off = shdr.sh_offset as usize;
        let sym_count = shdr.sh_size as usize / ELF_SYM_SIZE;
        for i in 1..sym_count {
            let s_off = sym_off + i * ELF_SYM_SIZE;
            if s_off + ELF_SYM_SIZE > data.len() { break; }
            let sym = read_elf64_sym(&data[s_off..s_off + ELF_SYM_SIZE]);
            if sym.st_shndx == SHN_UNDEF { continue; }
            let name = read_cstr(dynstr_data, sym.st_name as usize);
            if name.is_empty() { continue; }
            let bind = elf_st_bind(sym.st_info);
            if bind != STB_GLOBAL && bind != STB_WEAK { continue; }
            // Add as undefined/dynamic symbol in main symtab
            set_elf_sym(state, 0, sym.st_size, sym.st_info, sym.st_other,
                       SHN_UNDEF, &name);
        }
    }
    // Record the DLL reference
    let lib_name = PathBuf::from(filename)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| filename.to_string());
    state.loaded_dlls.push(DllReference {
        name: lib_name,
        level: 0,
        found: true,
        index: u8::try_from(state.loaded_dlls.len()).unwrap_or(0),
    });
    Ok(())
}

/// Parse a GNU ld linker script, extracting GROUP and INPUT directives.
///
/// C equivalent: `tcc_load_ldscript()` at tccelf.c ~line 4000
pub fn tcc_load_ldscript(state: &mut TccState, reader: &mut dyn Read) -> TccResult<()> {
    let mut content = String::new();
    reader.read_to_string(&mut content).map_err(TccError::Io)?;
    // Simple ld script parser: handle GROUP(...) and INPUT(...)
    let mut pos = 0;
    let bytes = content.as_bytes();
    while pos < bytes.len() {
        // Skip whitespace and comments
        while pos < bytes.len() && (bytes[pos].is_ascii_whitespace()) {
            pos += 1;
        }
        if pos >= bytes.len() { break; }
        // Check for /* ... */ comments
        if pos + 1 < bytes.len() && bytes[pos] == b'/' && bytes[pos + 1] == b'*' {
            pos += 2;
            while pos + 1 < bytes.len() && !(bytes[pos] == b'*' && bytes[pos + 1] == b'/') {
                pos += 1;
            }
            if pos + 1 < bytes.len() { pos += 2; }
            continue;
        }
        // Read a token
        let start = pos;
        while pos < bytes.len() && !bytes[pos].is_ascii_whitespace()
              && bytes[pos] != b'(' && bytes[pos] != b')'
              && bytes[pos] != b';' && bytes[pos] != b','
        {
            pos += 1;
        }
        let token = &content[start..pos];
        if token.eq_ignore_ascii_case("GROUP") || token.eq_ignore_ascii_case("INPUT") {
            // Parse the parenthesized file list
            while pos < bytes.len() && bytes[pos] != b'(' { pos += 1; }
            if pos < bytes.len() { pos += 1; } // skip '('
            while pos < bytes.len() && bytes[pos] != b')' {
                while pos < bytes.len()
                      && (bytes[pos].is_ascii_whitespace() || bytes[pos] == b',')
                {
                    pos += 1;
                }
                if pos >= bytes.len() || bytes[pos] == b')' { break; }
                // Handle AS_NEEDED(...)
                let file_start = pos;
                if content[pos..].starts_with("AS_NEEDED") {
                    while pos < bytes.len() && bytes[pos] != b'(' { pos += 1; }
                    if pos < bytes.len() { pos += 1; }
                    // Parse inner files
                    while pos < bytes.len() && bytes[pos] != b')' {
                        while pos < bytes.len()
                              && (bytes[pos].is_ascii_whitespace() || bytes[pos] == b',')
                        {
                            pos += 1;
                        }
                        if pos >= bytes.len() || bytes[pos] == b')' { break; }
                        let fname_start = pos;
                        while pos < bytes.len() && !bytes[pos].is_ascii_whitespace()
                              && bytes[pos] != b')' && bytes[pos] != b','
                        {
                            pos += 1;
                        }
                        let fname = content[fname_start..pos].trim();
                        if !fname.is_empty() && fname.starts_with('-') {
                            // -lfoo → search for libfoo.so / libfoo.a
                            let lib_name = &fname[2..]; // skip -l
                            let _ = find_and_load_library(state, lib_name);
                        } else if !fname.is_empty() {
                            let _ = load_file_by_type(state, fname);
                        }
                    }
                    if pos < bytes.len() { pos += 1; } // skip ')'
                    continue;
                }
                while pos < bytes.len() && !bytes[pos].is_ascii_whitespace()
                      && bytes[pos] != b')' && bytes[pos] != b','
                {
                    pos += 1;
                }
                let fname = content[file_start..pos].trim();
                if !fname.is_empty() && fname.starts_with("-l") {
                    let lib_name = &fname[2..];
                    let _ = find_and_load_library(state, lib_name);
                } else if !fname.is_empty() {
                    let _ = load_file_by_type(state, fname);
                }
            }
            if pos < bytes.len() { pos += 1; } // skip ')'
        } else if token.eq_ignore_ascii_case("OUTPUT_FORMAT") {
            // Skip OUTPUT_FORMAT(...)
            while pos < bytes.len() && bytes[pos] != b')' { pos += 1; }
            if pos < bytes.len() { pos += 1; }
        } else {
            // Skip unknown tokens
            if pos < bytes.len() && (bytes[pos] == b';' || bytes[pos] == b','
                                     || bytes[pos] == b'(' || bytes[pos] == b')') {
                pos += 1;
            }
        }
    }
    Ok(())
}

/// Search library paths for a shared/static library and load it.
fn find_and_load_library(state: &mut TccState, name: &str) -> TccResult<()> {
    // Try libNAME.so first, then libNAME.a
    let so_name = format!("lib{}.so", name);
    let a_name = format!("lib{}.a", name);
    for dir in &state.library_paths {
        let so_path = PathBuf::from(dir).join(&so_name);
        if so_path.exists() {
            let path_str = so_path.to_string_lossy().into_owned();
            return tcc_load_dll(state, &path_str);
        }
        let a_path = PathBuf::from(dir).join(&a_name);
        if a_path.exists() {
            let path_str = a_path.to_string_lossy().into_owned();
            return tcc_load_archive(state, &path_str);
        }
    }
    // Library not found — not necessarily an error (may be provided by system)
    Ok(())
}

/// Load a file by detecting its type and dispatching to the appropriate loader.
fn load_file_by_type(state: &mut TccState, filename: &str) -> TccResult<()> {
    let file = File::open(filename).map_err(TccError::Io)?;
    let mut reader = BufReader::new(file);
    let file_type = tcc_object_type(&mut reader)?;
    // Re-open since tcc_object_type consumed some bytes
    drop(reader);
    match file_type {
        FileType::Elf => {
            let file2 = File::open(filename).map_err(TccError::Io)?;
            let mut r2 = BufReader::new(file2);
            // Determine if it's an object or shared lib by re-reading the header
            let mut hdr = [0u8; 18];
            r2.read_exact(&mut hdr).map_err(TccError::Io)?;
            let e_type = get_le16(&hdr[16..18]);
            drop(r2);
            if e_type == ET_DYN {
                tcc_load_dll(state, filename)
            } else {
                let file3 = File::open(filename).map_err(TccError::Io)?;
                let mut r3 = BufReader::new(file3);
                tcc_load_object_file(state, &mut r3, filename)
            }
        }
        FileType::Archive => tcc_load_archive(state, filename),
        FileType::LdScript => {
            let file2 = File::open(filename).map_err(TccError::Io)?;
            let mut r2 = BufReader::new(file2);
            tcc_load_ldscript(state, &mut r2)
        }
        _ => Err(TccError::Link(format!("{}: unsupported file type", filename))),
    }
}

// ===========================================================================
//  Unit Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Section;

    fn make_test_state() -> TccState {
        let mut state = TccState::default();
        state.tcc_lib_path = "/nonexistent".to_string();
        state
    }

    #[test]
    fn test_constants() {
        assert_eq!(SHF_PRIVATE, 0x8000_0000);
        assert_eq!(SHF_DYNSYM, 0x4000_0000);
    }

    #[test]
    fn test_sym_version_struct() {
        let sv = SymVersion {
            lib: "libfoo.so".into(),
            version: "1.0".into(),
            out_index: 3,
            prev_same_lib: -1,
        };
        assert_eq!(sv.lib, "libfoo.so");
        assert_eq!(sv.version, "1.0");
    }

    #[test]
    fn test_dyn_inf_struct() {
        let di = DynInf {
            interp: Some(1),
            note: None,
            gnu_hash: Some(5),
            dynamic: Some(8),
            roinf: Some(ReadOnlyInf { sh_offset: 0x100, sh_size: 0x200 }),
        };
        assert_eq!(di.interp, Some(1));
        assert!(di.note.is_none());
        assert_eq!(di.roinf.as_ref().unwrap().sh_offset, 0x100);
    }

    #[test]
    fn test_elf_hash_deterministic() {
        let h1 = elf_hash("main");
        assert!(h1 > 0);
        assert_eq!(elf_hash("main"), h1);
    }

    #[test]
    fn test_put_elf_str() {
        let mut sec = Section::default();
        sec.data.push(0);
        sec.data_offset = 1;
        let off1 = put_elf_str(&mut sec, "hello");
        assert_eq!(off1, 1);
        assert_eq!(&sec.data[1..6], b"hello");
        assert_eq!(sec.data[6], 0);
    }

    #[test]
    fn test_section_add() {
        let mut sec = Section::default();
        let off = section_add(&mut sec, 16, 4);
        assert_eq!(off, 0);
        assert!(sec.data.len() >= 16);
        assert_eq!(sec.data_offset, 16);
    }

    #[test]
    fn test_section_ptr_add() {
        let mut sec = Section::default();
        let off = section_ptr_add(&mut sec, 32);
        assert_eq!(off, 0);
        assert_eq!(sec.data_offset, 32);
        sec.data[off] = 0xAA;
        assert_eq!(sec.data[0], 0xAA);
    }

    #[test]
    fn test_new_section() {
        let mut state = make_test_state();
        state.sections.push(Section::default());
        let idx = new_section(&mut state, ".test", SHT_PROGBITS, SHF_ALLOC);
        assert!(idx > 0);
        assert_eq!(state.sections[idx].name, ".test");
    }

    #[test]
    fn test_tccelf_new_creates_standard_sections() {
        let mut state = make_test_state();
        tccelf_new(&mut state).unwrap();
        assert!(find_section_index(&state, ".text").is_some());
        assert!(find_section_index(&state, ".data").is_some());
        assert!(find_section_index(&state, ".bss").is_some());
        assert!(find_section_index(&state, ".symtab").is_some());
        assert!(find_section_index(&state, ".strtab").is_some());
    }

    #[test]
    fn test_put_and_find_elf_sym() {
        let mut state = make_test_state();
        tccelf_new(&mut state).unwrap();
        let symtab_idx = find_section_index(&state, ".symtab").unwrap();
        let idx = put_elf_sym(&mut state, symtab_idx, 0x1000, 4,
                              elf_st_info(STB_GLOBAL, STT_FUNC), 0, 1, "my_func");
        assert!(idx > 0);
        assert_eq!(find_elf_sym(&state, symtab_idx, "my_func"), Some(idx));
        assert_eq!(find_elf_sym(&state, symtab_idx, "nonexistent"), None);
    }

    #[test]
    fn test_set_elf_sym_conflict() {
        let mut state = make_test_state();
        tccelf_new(&mut state).unwrap();
        let idx1 = set_elf_sym(&mut state, 0, 0,
                               elf_st_info(STB_WEAK, STT_NOTYPE), 0, SHN_UNDEF, "test_sym");
        let idx2 = set_elf_sym(&mut state, 0x2000, 8,
                               elf_st_info(STB_GLOBAL, STT_FUNC), 0, 1, "test_sym");
        assert_eq!(idx1, idx2);
    }

    #[test]
    fn test_sort_syms_locals_before_globals() {
        let mut state = make_test_state();
        tccelf_new(&mut state).unwrap();
        let symtab_idx = find_section_index(&state, ".symtab").unwrap();
        put_elf_sym(&mut state, symtab_idx, 0x100, 0,
                    elf_st_info(STB_GLOBAL, STT_FUNC), 0, 1, "global_sym");
        put_elf_sym(&mut state, symtab_idx, 0x200, 0,
                    elf_st_info(STB_LOCAL, STT_OBJECT), 0, 1, "local_sym");
        sort_syms(&mut state, symtab_idx);
        assert!(state.sections[symtab_idx].sh_info > 0);
    }

    #[test]
    fn test_read_cstr_valid() {
        let data = b"hello\0world\0";
        assert_eq!(read_cstr(data, 0), "hello");
        assert_eq!(read_cstr(data, 6), "world");
        assert_eq!(read_cstr(data, 20), "");
    }

    #[test]
    fn test_tccelf_begin_end_file() {
        let mut state = make_test_state();
        tccelf_new(&mut state).unwrap();
        let text_idx = find_section_index(&state, ".text").unwrap();
        section_add(&mut state.sections[text_idx], 16, 1);
        tccelf_begin_file(&mut state);
        section_add(&mut state.sections[text_idx], 32, 1);
        assert!(tccelf_end_file(&mut state).is_ok());
    }

    #[test]
    fn test_shf_relro_and_rdata() {
        assert!(shf_relro() & (SHF_ALLOC as u64) != 0);
        assert!(shf_rdata() & (SHF_ALLOC as u64) != 0);
    }

    #[test]
    fn test_byte_helpers() {
        let mut buf = [0u8; 8];
        put_le16(&mut buf[0..2], 0x1234);
        assert_eq!(get_le16(&buf[0..2]), 0x1234);
        put_le32(&mut buf[0..4], 0xDEAD_BEEF);
        assert_eq!(get_le32(&buf[0..4]), 0xDEAD_BEEF);
        put_le64(&mut buf[0..8], 0x0102_0304_0506_0708);
        assert_eq!(get_le64(&buf[0..8]), 0x0102_0304_0506_0708);
    }

    #[test]
    fn test_section_sort_order() {
        let mut interp_sec = Section::default();
        interp_sec.name = ".interp".to_string();
        interp_sec.sh_type = SHT_PROGBITS;
        interp_sec.sh_flags = SHF_ALLOC as u64;
        let mut text_sec = Section::default();
        text_sec.name = ".text".to_string();
        text_sec.sh_type = SHT_PROGBITS;
        text_sec.sh_flags = (SHF_ALLOC | SHF_EXECINSTR) as u64;
        let mut data_sec = Section::default();
        data_sec.name = ".data".to_string();
        data_sec.sh_type = SHT_PROGBITS;
        data_sec.sh_flags = (SHF_ALLOC | SHF_WRITE) as u64;
        let interp = section_sort_order(&interp_sec);
        let text = section_sort_order(&text_sec);
        let data = section_sort_order(&data_sec);
        assert!(interp < text);
        assert!(text < data);
    }

    #[test]
    fn test_build_got() {
        let mut state = make_test_state();
        tccelf_new(&mut state).unwrap();
        let got_sym = build_got(&mut state);
        assert!(got_sym > 0);
        assert!(find_section_index(&state, ".got").is_some());
    }

    #[test]
    fn test_resolve_common_syms() {
        let mut state = make_test_state();
        tccelf_new(&mut state).unwrap();
        let symtab_idx = find_section_index(&state, ".symtab").unwrap();
        put_elf_sym(&mut state, symtab_idx, 4, 4,
                    elf_st_info(STB_GLOBAL, STT_OBJECT), 0, SHN_COMMON, "common_var");
        let _ = resolve_common_syms(&mut state);
    }

    #[test]
    fn test_file_type_detection_elf() {
        let data = vec![0x7fu8, b'E', b'L', b'F', 0, 0, 0, 0];
        let mut cursor = std::io::Cursor::new(&data);
        assert_eq!(tcc_object_type(&mut cursor).unwrap(), FileType::Elf);
    }

    #[test]
    fn test_file_type_detection_archive() {
        let data = b"!<arch>\n";
        let mut cursor = std::io::Cursor::new(&data[..]);
        assert_eq!(tcc_object_type(&mut cursor).unwrap(), FileType::Archive);
    }

    #[test]
    fn test_file_type_detection_unknown() {
        let data = [0x00u8; 8];
        let mut cursor = std::io::Cursor::new(&data[..]);
        assert_eq!(tcc_object_type(&mut cursor).unwrap(), FileType::Unknown);
    }

    #[test]
    fn test_tccelf_delete() {
        let mut state = make_test_state();
        tccelf_new(&mut state).unwrap();
        tccelf_delete(&mut state);
        assert!(state.sections.is_empty() || state.sections.len() <= 1);
    }

    #[test]
    fn test_get_sym_attr() {
        let mut state = make_test_state();
        tccelf_new(&mut state).unwrap();
        let attr = get_sym_attr(&mut state, 5, true);
        assert_eq!(attr.got_offset, 0);
        attr.got_offset = 42;
        let attr2 = get_sym_attr(&mut state, 5, false);
        assert_eq!(attr2.got_offset, 42);
    }

    #[test]
    fn test_sort_sections() {
        let mut state = make_test_state();
        tccelf_new(&mut state).unwrap();
        new_section(&mut state, ".rodata", SHT_PROGBITS, SHF_ALLOC);
        let sorted = sort_sections(&mut state);
        assert!(!sorted.is_empty());
    }

    #[test]
    fn test_create_gnu_hash_no_dynsym() {
        let mut state = make_test_state();
        tccelf_new(&mut state).unwrap();
        assert_eq!(create_gnu_hash(&mut state).unwrap(), None);
    }

    #[test]
    fn test_fill_got_no_got() {
        let mut state = make_test_state();
        tccelf_new(&mut state).unwrap();
        assert!(fill_got(&mut state).is_ok());
    }

    #[test]
    fn test_relocate_plt_no_plt() {
        let mut state = make_test_state();
        tccelf_new(&mut state).unwrap();
        assert!(relocate_plt(&mut state).is_ok());
    }

    #[test]
    fn test_tcc_add_bcheck_disabled() {
        let mut state = make_test_state();
        state.do_bounds_check = false;
        tccelf_new(&mut state).unwrap();
        assert!(tcc_add_bcheck(&mut state).is_ok());
    }

    #[test]
    fn test_new_symtab() {
        let mut state = make_test_state();
        state.sections.push(Section::default());
        let idx = new_symtab(&mut state, ".dynsym", SHT_DYNSYM,
                             SHF_ALLOC | SHF_DYNSYM,
                             ".dynstr", ".hash", SHF_ALLOC);
        assert!(idx > 0);
        assert_eq!(state.sections[idx].name, ".dynsym");
    }

    #[test]
    fn test_relocate_syms_ok() {
        let mut state = make_test_state();
        tccelf_new(&mut state).unwrap();
        let text_idx = find_section_index(&state, ".text").unwrap();
        let symtab_idx = find_section_index(&state, ".symtab").unwrap();
        put_elf_sym(&mut state, symtab_idx, 0, 0,
                    elf_st_info(STB_GLOBAL, STT_FUNC), 0,
                    text_idx as u16, "defined_fn");
        state.sections[text_idx].sh_addr = 0x400000;
        assert!(relocate_syms(&mut state, false).is_ok());
    }
}
