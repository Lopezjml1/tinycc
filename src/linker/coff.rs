//! COFF (Common Object File Format) output backend for `TinyCC`.
//!
//! This module generates COFF object files and executables for the
//! `TMS320C67x` DSP target. It also supports loading external COFF files
//! to resolve symbols.
//!
//! C equivalent: `tcccoff.c` (951 lines)
//!
//! The COFF output pipeline:
//! 1. Collect compiler sections (.text, .data, .bss)
//! 2. Build COFF section headers from ELF sections
//! 3. Convert ELF symbol table to COFF symbol table
//! 4. Build COFF relocation entries from ELF relocations
//! 5. Assign line number information for debugging
//! 6. Write file header, optional header, section headers, raw data,
//!    relocations, line numbers, symbol table, and string table

use std::collections::HashMap;
use std::io::{self, Read, Seek, SeekFrom, Write};

use crate::context::TccState;
use crate::error::{TccError, TccResult};
use crate::formats::coff::{
    CoffAoutHeader, CoffFileHeader, CoffLineno, CoffReloc, CoffSectionHeader, CoffSyment,
    COFF_C67_MAGIC, C_EXT, C_FCN, C_FILE, C_LABEL, DT_FCN, FILHSZ, LINESZ, N_DEBUG, RELSZ,
    STYP_ALIGN, STYP_BSS, STYP_COPY, STYP_DATA, STYP_TEXT, SYMESZ, SYMNMLEN, T_CHAR, T_DOUBLE,
    T_FLOAT, T_INT, T_SHORT,
};
use crate::formats::elf::Elf32Sym;
use crate::formats::stab::{N_BINCL, N_EINCL, N_FUN, N_SLINE, N_SO};
use crate::types::{
    Section, StabSym, INCLUDE_STACK_SIZE, VT_BTYPE, VT_BYTE, VT_DOUBLE, VT_FLOAT, VT_INT,
    VT_SHORT,
};

// ============================================================================
// Constants — translated from tcccoff.c:27-52
// ============================================================================

/// Maximum number of COFF sections.
/// C equivalent: `MAXNSCNS` at tcccoff.c:27.
const MAXNSCNS: usize = 255;

/// Maximum string table size in bytes.
/// C equivalent: `MAX_STR_TABLE` at tcccoff.c:28.
const MAX_STR_TABLE: usize = 1_000_000;

/// Maximum number of tracked functions for debug info.
/// C equivalent: `MAX_FUNCS` at tcccoff.c:33.
const MAX_FUNCS: usize = 1000;

/// Maximum function name length.
/// C equivalent: `MAX_FUNC_NAME_LENGTH` at tcccoff.c:34.
const MAX_FUNC_NAME_LENGTH: usize = 128;

/// Size of the AOUT optional header (in bytes).
/// Matches `sizeof(AOUTHDR)` = 28 bytes (7 × i32/i16 fields packed).
const AOUTSZ: usize = 28;

/// Size of a COFF section header on disk.
/// Matches `sizeof(SCNHDR)` as defined in the C code.
const SCNHSZ: usize = 48;

// ============================================================================
// Auxiliary Symbol Structs — tcccoff.c:54-78
// ============================================================================

/// Auxiliary function symbol entry for COFF output.
///
/// C equivalent: `AUXFUNC` struct at tcccoff.c:54-60.
/// Contains per-function metadata written alongside function symbols
/// in the COFF symbol table.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct AuxFunc {
    /// Tag index (0 for standard functions).
    pub tag_index: i32,
    /// Total size of the function in bytes.
    pub total_size: i32,
    /// File pointer to line number entries for this function.
    pub lnno_ptr: i32,
    /// Symbol table index of the next function.
    pub next_function: i32,
    /// Padding to fill 18-byte AUXENT size.
    pub dummy: u16,
}

/// Auxiliary begin-function (.bf) entry.
///
/// C equivalent: `AUXBF` struct at tcccoff.c:62-69.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct AuxBf {
    /// Register mask (currently always 0).
    pub regmask: i32,
    /// Source line number of function start.
    pub lineno: u16,
    /// Number of line-number entries for this function.
    pub nentries: u16,
    /// Local frame size.
    pub localframe: i32,
    /// Symbol table index of the next .bf entry.
    pub nextentry: i32,
    /// Padding.
    pub dummy: u16,
}

/// Auxiliary end-function (.ef) entry.
///
/// C equivalent: `AUXEF` struct at tcccoff.c:71-78.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct AuxEf {
    /// Reserved (always 0).
    pub dummy: i32,
    /// Source line number of function end.
    pub lineno: u16,
    /// Reserved fields.
    pub dummy1: u16,
    /// Reserved.
    pub dummy2: i32,
    /// Reserved.
    pub dummy3: i32,
    /// Reserved.
    pub dummy4: u16,
}

// ============================================================================
// Per-Function Tracking — consolidates parallel C arrays
// ============================================================================

/// Per-function tracking information for COFF debug output.
///
/// Consolidates the parallel C arrays `Func[]`, `AssociatedFile[]`,
/// `LineNoFilePtr[]`, `EndAddress[]`, `LastLineNo[]`, `FuncEntries[]`
/// into a single owned struct per AAP §0.8.1 (no static mut).
#[derive(Default)]
pub struct CoffFuncInfo {
    /// Function name (from STABS `N_FUN` entry).
    pub name: String,
    /// Source file associated with this function.
    pub associated_file: String,
    /// File pointer to the start of line number entries for this function.
    pub line_no_file_ptr: i32,
    /// Number of line number entries for this function.
    pub func_entries: i32,
    /// End address (last PC) of this function.
    pub end_address: u32,
    /// Last source line number in this function.
    pub last_line_no: i32,
}

// ============================================================================
// CoffOutput — replaces ALL global/static state in tcccoff.c
// ============================================================================

/// COFF output state — replaces all global/static variables in tcccoff.c.
///
/// All state is owned, no static mut per AAP §0.8.1.
pub struct CoffOutput {
    /// COFF section headers built from ELF sections.
    pub section_headers: Vec<CoffSectionHeader>,
    /// Per-function debug info tracking.
    pub functions: Vec<CoffFuncInfo>,
    /// String table for long symbol names (> 8 bytes).
    pub string_table: Vec<u8>,
    /// COFF symbol table entries.
    pub symbol_table: Vec<CoffSyment>,
    /// Entry point address for the C67 `_main` symbol.
    pub c67_main_entry_point: u32,
}

impl Default for CoffOutput {
    fn default() -> Self {
        Self {
            section_headers: Vec::with_capacity(MAXNSCNS),
            functions: Vec::with_capacity(MAX_FUNCS),
            string_table: Vec::new(),
            symbol_table: Vec::new(),
            c67_main_entry_point: 0,
        }
    }
}

// ============================================================================
// Helper Functions — translate static helpers from tcccoff.c
// ============================================================================

/// Determine if an ELF section should be output to COFF.
///
/// C equivalent: `OutputTheSection()` at tcccoff.c:820-830.
/// Only `.text` and `.data` sections are output in the original implementation.
fn output_the_section(section: &Section) -> bool {
    let s = section.name.as_str();
    s == ".text" || s == ".data"
}

/// Map a section name to its COFF section flags.
///
/// C equivalent: `GetCoffFlags()` at tcccoff.c:832-846.
fn get_coff_flags(name: &str) -> u32 {
    match name {
        ".text" => STYP_TEXT | STYP_DATA | STYP_ALIGN | 0x400,
        ".data" => STYP_DATA,
        ".bss" => STYP_BSS,
        ".stack" => STYP_BSS | STYP_ALIGN | 0x200,
        ".cinit" => STYP_COPY | STYP_DATA | STYP_ALIGN | 0x200,
        _ => 0,
    }
}

/// Find a section by name in `TccState`.
///
/// C equivalent: `FindSection()` at tcccoff.c:848-862.
/// Uses `iter().find()` instead of C linear scan. Returns `TccResult` on not found.
fn find_section<'a>(state: &'a TccState, sname: &str) -> TccResult<&'a Section> {
    state
        .sections
        .iter()
        .skip(1) // skip index 0 (null section)
        .find(|s| s.name == sname)
        .ok_or_else(|| TccError::Link(format!("could not find section {sname}")))
}

/// Find a section index by name in `TccState`.
///
/// Returns the index into `state.sections` or an error if not found.
fn find_section_index(state: &TccState, sname: &str) -> TccResult<usize> {
    state
        .sections
        .iter()
        .enumerate()
        .skip(1)
        .find(|(_, s)| s.name == sname)
        .map(|(i, _)| i)
        .ok_or_else(|| TccError::Link(format!("could not find section {sname}")))
}

/// Count COFF symbol table entries up to (and including) a named function.
///
/// C equivalent: `FindCoffSymbolIndex()` at tcccoff.c:776-818.
///
/// Each ELF symbol generates a different number of COFF entries:
/// - `st_info` == 4 (file): 1 entry
/// - `st_info` == 0x12 (function): 6 entries (name + aux + .bf + aux + .ef + aux)
/// - other: 2 entries (symbol + aux)
///
/// Returns the COFF symbol index of the named function, or the total count
/// if the name is not found.
fn find_coff_symbol_index(state: &TccState, func_name: &str) -> i32 {
    let symtab = get_symtab_section(state);
    let strtab = get_symtab_strtab(state);
    let sym_size = std::mem::size_of::<Elf32Sym>();
    let nb_syms = symtab.data_offset / sym_size;

    let mut n: i32 = 0;
    for i in 0..nb_syms {
        let sym = read_elf32_sym(&symtab.data, i);
        let name = read_str_from_section(strtab, sym.st_name);

        if sym.st_info == 4 {
            // file symbol: 1 entry
            n = n.saturating_add(1);
        } else if sym.st_info == 0x12 {
            // function symbol: 6 entries
            if name == func_name {
                return n;
            }
            n = n.saturating_add(6);
        } else {
            // other symbol: 2 entries
            n = n.saturating_add(2);
        }
    }

    n // total number of symbols (name not found)
}

/// Build a `HashMap` mapping function names to their COFF symbol table indices.
///
/// This provides O(1) lookup for COFF symbol indices by name, replacing
/// repeated O(n) linear scans via `find_coff_symbol_index`.
fn build_coff_symbol_index_map(state: &TccState) -> HashMap<String, i32> {
    let symtab = get_symtab_section(state);
    let strtab = get_symtab_strtab(state);
    let sym_size = 16_usize;
    let nb_syms = symtab.data_offset / sym_size;

    let mut map = HashMap::new();
    let mut n: i32 = 0;

    for i in 0..nb_syms {
        let sym = read_elf32_sym(&symtab.data, i);
        let name = read_str_from_section(strtab, sym.st_name);

        if sym.st_info == 4 {
            n = n.saturating_add(1);
        } else if sym.st_info == 0x12 {
            map.insert(name, n);
            n = n.saturating_add(6);
        } else {
            n = n.saturating_add(2);
        }
    }

    map
}

/// Find a function info entry by name.
///
/// C equivalent: finding function in `Func[]` array.
fn get_func_index(functions: &[CoffFuncInfo], name: &str) -> Option<usize> {
    functions.iter().position(|f| f.name == name)
}

/// Construct a COFF type field using the MKTYPE macro pattern.
///
/// C equivalent: `MKTYPE(basic, d1, d2, d3, d4, d5, d6)` macro in coff.h:347-349.
fn mktype(basic: u16, d1: u16) -> u16 {
    basic | (d1 << 4)
}

// ============================================================================
// Section data access helpers (safe, bounds-checked)
// ============================================================================

/// Read an `Elf32Sym` from section data at a given index.
///
/// All access is bounds-checked. Returns a zeroed `Elf32Sym` if out of bounds.
fn read_elf32_sym(data: &[u8], index: usize) -> Elf32Sym {
    let sym_size = 16_usize; // sizeof(Elf32_Sym) = 16 bytes
    let offset = index.saturating_mul(sym_size);
    if offset.saturating_add(sym_size) > data.len() {
        return Elf32Sym {
            st_name: 0,
            st_value: 0,
            st_size: 0,
            st_info: 0,
            st_other: 0,
            st_shndx: 0,
        };
    }
    let b = &data[offset..offset + sym_size];
    Elf32Sym {
        st_name: u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
        st_value: u32::from_le_bytes([b[4], b[5], b[6], b[7]]),
        st_size: u32::from_le_bytes([b[8], b[9], b[10], b[11]]),
        st_info: b[12],
        st_other: b[13],
        st_shndx: u16::from_le_bytes([b[14], b[15]]),
    }
}

/// Read a NUL-terminated string from a section's data buffer.
///
/// Returns an empty string if the offset is out of bounds.
fn read_str_from_section(section: &Section, offset: u32) -> String {
    let start = offset as usize;
    if start >= section.data.len() {
        return String::new();
    }
    let end = section.data[start..]
        .iter()
        .position(|&b| b == 0)
        .map_or(section.data.len(), |pos| start + pos);
    String::from_utf8_lossy(&section.data[start..end]).into_owned()
}

/// Get a reference to the symtab section. Falls back to an empty section
/// if the state doesn't have well-known section indices.
fn get_symtab_section(state: &TccState) -> &Section {
    // The symtab section is typically at a well-known index.
    // In the TCC codebase, `symtab_section` is often stored separately.
    // Here we search for the section named ".symtab".
    state
        .sections
        .iter()
        .find(|s| s.name == ".symtab")
        .unwrap_or_else(|| {
            // Fallback: return the first section (empty/null section)
            &state.sections[0]
        })
}

/// Get the string table section linked from the symtab section.
fn get_symtab_strtab(state: &TccState) -> &Section {
    let symtab = get_symtab_section(state);
    if let Some(link_idx) = symtab.link {
        if link_idx < state.sections.len() {
            return &state.sections[link_idx];
        }
    }
    // Fallback: search for ".strtab"
    state
        .sections
        .iter()
        .find(|s| s.name == ".strtab")
        .unwrap_or(&state.sections[0])
}

/// Get the stab section (".stab") from `TccState`.
fn get_stab_section(state: &TccState) -> Option<&Section> {
    state.sections.iter().find(|s| s.name == ".stab")
}

/// Get the stab string section (".stabstr") from `TccState`.
fn get_stabstr_section(state: &TccState) -> Option<&Section> {
    state.sections.iter().find(|s| s.name == ".stabstr")
}

/// Read a `StabSym` from stab section data at a byte offset.
fn read_stab_sym(data: &[u8], offset: usize) -> Option<StabSym> {
    let stab_size = 12_usize; // sizeof(Stab_Sym) = 12 bytes
    if offset.saturating_add(stab_size) > data.len() {
        return None;
    }
    let b = &data[offset..offset + stab_size];
    Some(StabSym {
        n_strx: u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
        n_type: b[4],
        n_other: b[5],
        n_desc: u16::from_le_bytes([b[6], b[7]]),
        n_value: u32::from_le_bytes([b[8], b[9], b[10], b[11]]),
    })
}

/// Read a NUL-terminated string from raw byte data at a given offset.
fn read_str_from_data(data: &[u8], offset: u32) -> String {
    let start = offset as usize;
    if start >= data.len() {
        return String::new();
    }
    let end = data[start..]
        .iter()
        .position(|&b| b == 0)
        .map_or(data.len(), |pos| start + pos);
    String::from_utf8_lossy(&data[start..end]).into_owned()
}

// ============================================================================
// Binary serialization helpers — all use Vec<u8>, no raw pointer writes
// ============================================================================

/// Write a COFF file header to bytes.
///
/// Writes exactly `FILHSZ` (22) bytes in little-endian format.
fn write_file_header(buf: &mut Vec<u8>, hdr: &CoffFileHeader) {
    buf.extend_from_slice(&hdr.f_magic.to_le_bytes());
    buf.extend_from_slice(&hdr.f_nscns.to_le_bytes());
    buf.extend_from_slice(&hdr.f_timdat.to_le_bytes());
    buf.extend_from_slice(&hdr.f_symptr.to_le_bytes());
    buf.extend_from_slice(&hdr.f_nsyms.to_le_bytes());
    buf.extend_from_slice(&hdr.f_opthdr.to_le_bytes());
    buf.extend_from_slice(&hdr.f_flags.to_le_bytes());
    buf.extend_from_slice(&hdr.f_target_id.to_le_bytes());
}

/// Write a COFF AOUT optional header to bytes.
///
/// Writes exactly `AOUTSZ` (28) bytes in little-endian format.
fn write_aout_header(buf: &mut Vec<u8>, hdr: &CoffAoutHeader) {
    buf.extend_from_slice(&hdr.magic.to_le_bytes());
    buf.extend_from_slice(&hdr.vstamp.to_le_bytes());
    buf.extend_from_slice(&hdr.tsize.to_le_bytes());
    buf.extend_from_slice(&hdr.dsize.to_le_bytes());
    buf.extend_from_slice(&hdr.bsize.to_le_bytes());
    buf.extend_from_slice(&hdr.entrypt.to_le_bytes());
    buf.extend_from_slice(&hdr.text_start.to_le_bytes());
    buf.extend_from_slice(&hdr.data_start.to_le_bytes());
}

/// Write a COFF section header to bytes.
fn write_section_header(buf: &mut Vec<u8>, hdr: &CoffSectionHeader) {
    buf.extend_from_slice(&hdr.s_name);
    buf.extend_from_slice(&hdr.s_paddr.to_le_bytes());
    buf.extend_from_slice(&hdr.s_vaddr.to_le_bytes());
    buf.extend_from_slice(&hdr.s_size.to_le_bytes());
    buf.extend_from_slice(&hdr.s_scnptr.to_le_bytes());
    buf.extend_from_slice(&hdr.s_relptr.to_le_bytes());
    buf.extend_from_slice(&hdr.s_lnnoptr.to_le_bytes());
    buf.extend_from_slice(&hdr.s_nreloc.to_le_bytes());
    buf.extend_from_slice(&hdr.s_nlnno.to_le_bytes());
    buf.extend_from_slice(&hdr.s_flags.to_le_bytes());
    buf.extend_from_slice(&hdr.s_reserved.to_le_bytes());
    buf.extend_from_slice(&hdr.s_page.to_le_bytes());
}

/// Write a COFF symbol entry (SYMENT, 18 bytes) to a byte buffer.
fn write_syment(buf: &mut Vec<u8>, sym: &CoffSyment) {
    buf.extend_from_slice(&sym.n_name);
    buf.extend_from_slice(&sym.n_value.to_le_bytes());
    buf.extend_from_slice(&sym.n_scnum.to_le_bytes());
    buf.extend_from_slice(&sym.n_type.to_le_bytes());
    buf.push(sym.n_sclass.to_le_bytes()[0]);
    buf.push(sym.n_numaux.to_le_bytes()[0]);
}

/// Write an `AuxFunc` (18 bytes) to a byte buffer.
fn write_auxfunc(buf: &mut Vec<u8>, aux: &AuxFunc) {
    buf.extend_from_slice(&aux.tag_index.to_le_bytes());
    buf.extend_from_slice(&aux.total_size.to_le_bytes());
    buf.extend_from_slice(&aux.lnno_ptr.to_le_bytes());
    buf.extend_from_slice(&aux.next_function.to_le_bytes());
    buf.extend_from_slice(&aux.dummy.to_le_bytes());
}

/// Write an `AuxBf` (18 bytes) to a byte buffer.
fn write_auxbf(buf: &mut Vec<u8>, aux: &AuxBf) {
    buf.extend_from_slice(&aux.regmask.to_le_bytes());
    buf.extend_from_slice(&aux.lineno.to_le_bytes());
    buf.extend_from_slice(&aux.nentries.to_le_bytes());
    buf.extend_from_slice(&aux.localframe.to_le_bytes());
    buf.extend_from_slice(&aux.nextentry.to_le_bytes());
    buf.extend_from_slice(&aux.dummy.to_le_bytes());
}

/// Write an `AuxEf` (18 bytes) to a byte buffer.
fn write_auxef(buf: &mut Vec<u8>, aux: &AuxEf) {
    buf.extend_from_slice(&aux.dummy.to_le_bytes());
    buf.extend_from_slice(&aux.lineno.to_le_bytes());
    buf.extend_from_slice(&aux.dummy1.to_le_bytes());
    buf.extend_from_slice(&aux.dummy2.to_le_bytes());
    buf.extend_from_slice(&aux.dummy3.to_le_bytes());
    buf.extend_from_slice(&aux.dummy4.to_le_bytes());
}

/// Write a COFF line number entry (6 bytes) to a byte buffer.
fn write_lineno(buf: &mut Vec<u8>, lineno: CoffLineno) {
    buf.extend_from_slice(&lineno.l_addr.to_le_bytes());
    buf.extend_from_slice(&lineno.l_lnno.to_le_bytes());
}

/// Write a COFF relocation entry (RELSZ bytes) to a byte buffer.
fn write_reloc_entry(buf: &mut Vec<u8>, rel: &CoffReloc) {
    buf.extend_from_slice(&rel.r_vaddr.to_le_bytes());
    buf.extend_from_slice(&rel.r_symndx.to_le_bytes());
    buf.extend_from_slice(&rel.r_disp.to_le_bytes());
    buf.extend_from_slice(&rel.r_type.to_le_bytes());
}

// ============================================================================
// Symbol name handling
// ============================================================================

/// Set a COFF symbol name field. If the name fits in 8 bytes, it is
/// placed directly in the `n_name` array. Otherwise, the first 4 bytes
/// are set to zero and the next 4 bytes contain the offset into the
/// string table.
///
/// Returns the updated string table offset (or the same offset if the
/// name was short enough).
fn set_coff_sym_name(
    n_name: &mut [u8; SYMNMLEN],
    name: &str,
    str_table: &mut Vec<u8>,
    str_offset: &mut usize,
) -> TccResult<()> {
    // Zero out the name field first
    *n_name = [0u8; SYMNMLEN];

    if name.len() <= SYMNMLEN {
        let len = name.len().min(SYMNMLEN);
        n_name[..len].copy_from_slice(&name.as_bytes()[..len]);
    } else {
        // Long name: store in string table
        if str_offset
            .checked_add(name.len().saturating_add(1))
            .is_none_or(|end| end > MAX_STR_TABLE)
        {
            return Err(TccError::Link("String table too large".into()));
        }

        // n_zeroes = 0 (first 4 bytes)
        n_name[0..4].copy_from_slice(&0_i32.to_le_bytes());
        // n_offset = current string table offset + 4 (per COFF convention)
        let offset_val =
            i32::try_from(*str_offset + 4).map_err(|_| TccError::Link("string table offset overflow".into()))?;
        n_name[4..8].copy_from_slice(&offset_val.to_le_bytes());

        str_table.extend_from_slice(name.as_bytes());
        str_table.push(0); // null terminator
        *str_offset = str_offset.saturating_add(name.len() + 1);
    }
    Ok(())
}

// ============================================================================
// Sort Symbol Table — tcccoff.c:696-773
// ============================================================================

/// Sort the ELF symbol table for COFF output.
///
/// Groups symbols in order: file symbols first, then function symbols
/// (matched by source file association), then remaining global symbols.
///
/// C equivalent: `SortSymbolTable()` at tcccoff.c:696-773.
///
/// This function operates on a copy of the symbol data and writes the
/// sorted result back to the symtab section data buffer.
fn sort_symbol_table(state: &mut TccState, functions: &[CoffFuncInfo]) -> TccResult<()> {
    let symtab_idx = state
        .sections
        .iter()
        .position(|s| s.name == ".symtab")
        .ok_or_else(|| TccError::Link("symtab section not found".into()))?;

    let strtab_idx = state.sections[symtab_idx].link;
    let sym_size = 16_usize; // sizeof(Elf32_Sym)
    let nb_syms = state.sections[symtab_idx].data_offset / sym_size;

    if nb_syms == 0 {
        return Ok(());
    }

    // Read all symbols
    let mut all_syms: Vec<Elf32Sym> = Vec::with_capacity(nb_syms);
    for i in 0..nb_syms {
        all_syms.push(read_elf32_sym(&state.sections[symtab_idx].data, i));
    }

    // Helper to read symbol name
    let read_name = |sym: &Elf32Sym| -> String {
        if let Some(strtab) = strtab_idx {
            if strtab < state.sections.len() {
                return read_str_from_section(&state.sections[strtab], sym.st_name);
            }
        }
        String::new()
    };

    let mut new_table: Vec<Elf32Sym> = Vec::with_capacity(nb_syms);

    // Phase 1: For each file symbol, copy it and then copy matching function symbols
    for file_sym in &all_syms {
        if file_sym.st_info == 4 {
            // File symbol
            let file_name = read_name(file_sym);
            new_table.push(*file_sym);

            // Find all function symbols associated with this file
            for func_sym in &all_syms {
                if func_sym.st_info == 0x12 {
                    let func_name_str = read_name(func_sym);

                    // Look up association in the functions table
                    if let Some(fi) = functions.iter().find(|f| f.name == func_name_str) {
                        if fi.associated_file == file_name {
                            new_table.push(*func_sym);
                        }
                    }
                }
            }
        }
    }

    // Phase 2: Copy all remaining symbols (not file, not function)
    for sym in &all_syms {
        if sym.st_info != 4 && sym.st_info != 0x12 {
            new_table.push(*sym);
        }
    }

    if new_table.len() != nb_syms {
        return Err(TccError::Link(
            "Internal compiler error: symbol count mismatch after sorting".into(),
        ));
    }

    // Write sorted symbols back to section data
    let data = &mut state.sections[symtab_idx].data;
    for (i, sym) in new_table.iter().enumerate() {
        let offset = i * sym_size;
        if offset + sym_size <= data.len() {
            data[offset..offset + 4].copy_from_slice(&sym.st_name.to_le_bytes());
            data[offset + 4..offset + 8].copy_from_slice(&sym.st_value.to_le_bytes());
            data[offset + 8..offset + 12].copy_from_slice(&sym.st_size.to_le_bytes());
            data[offset + 12] = sym.st_info;
            data[offset + 13] = sym.st_other;
            data[offset + 14..offset + 16].copy_from_slice(&sym.st_shndx.to_le_bytes());
        }
    }

    Ok(())
}

// ============================================================================
// Main Output Function — tcc_output_coff
// ============================================================================

/// Generate a complete COFF output file.
///
/// C equivalent: `tcc_output_coff()` at tcccoff.c:80-689.
///
/// Pipeline:
/// 1. Find .text, .data, .bss sections
/// 2. Count COFF symbols from ELF symtab
/// 3. Fill COFF file header (`magic=COFF_C67_MAGIC`, `target_id=0x99`)
/// 4. Fill AOUT optional header (entry point, text/data/bss sizes)
/// 5. Build section headers for each output section
/// 6. Assign file pointers for raw data, relocations, line numbers
/// 7. Write raw section data
/// 8. Convert ELF relocations to COFF relocations
/// 9. Build COFF line number records from STABS data
/// 10. Build COFF symbol table from ELF symbols
/// 11. Build string table for long symbol names
/// 12. Write everything via `std::io::Write`
///
/// All buffer writes use `Vec<u8>` — NO raw pointer writes (CVE prevention).
/// All section/symbol access uses bounds-checked indexing.
#[allow(clippy::cast_possible_truncation)]
#[allow(clippy::cast_sign_loss)]
#[allow(clippy::cast_possible_wrap)]
#[allow(clippy::too_many_lines)]
pub fn tcc_output_coff(state: &mut TccState, writer: &mut dyn Write) -> TccResult<()> {
    let mut output = CoffOutput::default();

    // Find key sections
    let stext = find_section(state, ".text")?;
    let sdata = find_section(state, ".data")?;
    let sbss = find_section(state, ".bss")?;

    let text_data_offset = stext.data_offset;
    let data_data_offset = sdata.data_offset;
    let bss_data_offset = sbss.data_offset;
    let text_sh_addr = stext.sh_addr;
    let data_sh_addr = sdata.sh_addr;
    let stext_name = stext.name.clone();

    // Count ELF symbols — sym_size used for symbol table calculations below
    let sym_size = 16_usize;
    let coff_nb_syms = find_coff_symbol_index(state, "XXXXXXXXXX1");

    // -------------------------------------------------------------------
    // Fill COFF file header (tcccoff.c:100-104)
    // -------------------------------------------------------------------
    let mut file_hdr = CoffFileHeader {
        f_magic: COFF_C67_MAGIC,
        f_nscns: 0,
        f_timdat: 0,
        f_symptr: 0,
        f_nsyms: 0,
        f_opthdr: AOUTSZ as u16,
        f_flags: 0x1143,
        f_target_id: 0x99,
    };

    // -------------------------------------------------------------------
    // Fill AOUT optional header (tcccoff.c:106-113)
    // -------------------------------------------------------------------
    let o_filehdr = CoffAoutHeader {
        magic: 0x0108,
        vstamp: 0x0190,
        tsize: text_data_offset as i32,
        dsize: data_data_offset as i32,
        bsize: bss_data_offset as i32,
        entrypt: output.c67_main_entry_point as i32,
        text_start: text_sh_addr as i32,
        data_start: data_sh_addr as i32,
    };

    // -------------------------------------------------------------------
    // Create section headers (tcccoff.c:118-147)
    // -------------------------------------------------------------------
    let mut file_pointer: i32 = (FILHSZ + AOUTSZ) as i32;
    let mut coff_text_section_no: i32 = -1;
    let mut n_sections_to_output: u16 = 0;

    // Initialize section_headers with enough capacity for all sections
    let total_sections = state.sections.len();
    output.section_headers = vec![
        CoffSectionHeader {
            s_name: [0u8; 8],
            s_paddr: 0,
            s_vaddr: 0,
            s_size: 0,
            s_scnptr: 0,
            s_relptr: 0,
            s_lnnoptr: 0,
            s_nreloc: 0,
            s_nlnno: 0,
            s_flags: 0,
            s_reserved: 0,
            s_page: 0,
        };
        total_sections
    ];

    for i in 1..total_sections {
        if !output_the_section(&state.sections[i]) {
            continue;
        }
        n_sections_to_output = n_sections_to_output.saturating_add(1);

        if coff_text_section_no == -1 && state.sections[i].name == stext_name {
            coff_text_section_no = i32::from(n_sections_to_output);
        }

        let coff_sec = &mut output.section_headers[i];

        // Set section name
        let name_bytes = state.sections[i].name.as_bytes();
        let name_len = name_bytes.len().min(8);
        coff_sec.s_name[..name_len].copy_from_slice(&name_bytes[..name_len]);

        coff_sec.s_paddr = state.sections[i].sh_addr as i32;
        coff_sec.s_vaddr = state.sections[i].sh_addr as i32;
        coff_sec.s_size = state.sections[i].data_offset as i32;
        coff_sec.s_scnptr = 0;
        coff_sec.s_relptr = 0;
        coff_sec.s_lnnoptr = 0;
        coff_sec.s_nreloc = 0;
        coff_sec.s_flags = get_coff_flags(&state.sections[i].name);
        coff_sec.s_reserved = 0;
        coff_sec.s_page = 0;

        file_pointer = file_pointer.saturating_add(SCNHSZ as i32);
    }

    file_hdr.f_nscns = n_sections_to_output;

    // -------------------------------------------------------------------
    // Assign file pointers for raw data (tcccoff.c:155-164)
    // -------------------------------------------------------------------
    for i in 1..total_sections {
        if !output_the_section(&state.sections[i]) {
            continue;
        }
        output.section_headers[i].s_scnptr = file_pointer;
        file_pointer = file_pointer.saturating_add(output.section_headers[i].s_size);
    }

    // -------------------------------------------------------------------
    // Assign file pointers for relocations (tcccoff.c:169-180)
    // -------------------------------------------------------------------
    for i in 1..total_sections {
        if !output_the_section(&state.sections[i]) {
            continue;
        }
        if output.section_headers[i].s_nreloc > 0 {
            output.section_headers[i].s_relptr = file_pointer;
            file_pointer = file_pointer.saturating_add(
                (output.section_headers[i].s_nreloc as i32).saturating_mul(RELSZ as i32),
            );
        }
    }

    // -------------------------------------------------------------------
    // Assign file pointers for line numbers (tcccoff.c:185-316)
    // -------------------------------------------------------------------
    for i in 1..total_sections {
        output.section_headers[i].s_nlnno = 0;
        output.section_headers[i].s_lnnoptr = 0;

        if state.do_debug && state.sections[i].name == stext_name {
            output.section_headers[i].s_lnnoptr = file_pointer;

            // Parse STABS data to count line numbers and build function info
            if let (Some(stab_sec), Some(stabstr_sec)) =
                (get_stab_section(state), get_stabstr_section(state))
            {
                let stab_size = 12_usize;
                let mut stab_offset = stab_size; // skip first entry
                let stab_end = stab_sec.data_offset;

                let mut func_name = String::new();
                let mut func_addr: u32 = 0;
                let mut incl_files: Vec<String> = Vec::with_capacity(INCLUDE_STACK_SIZE);
                let mut incl_index: usize = 0;
                let mut last_line_num: i32 = 1;

                output.functions.clear();
                let mut n_funcs: usize = 0;

                while stab_offset < stab_end {
                    if let Some(sym) = read_stab_sym(&stab_sec.data, stab_offset) {
                        match sym.n_type {
                            x if x == N_FUN => {
                                if sym.n_strx == 0 {
                                    // End of function
                                    output.section_headers[i].s_nlnno =
                                        output.section_headers[i].s_nlnno.saturating_add(1);
                                    file_pointer = file_pointer.saturating_add(LINESZ as i32);

                                    let pc = sym.n_value.saturating_add(func_addr);

                                    if n_funcs < output.functions.len() {
                                        output.functions[n_funcs].end_address = pc;
                                        output.functions[n_funcs].func_entries =
                                            ((file_pointer
                                                - output.functions[n_funcs].line_no_file_ptr)
                                                / LINESZ as i32)
                                                - 1;
                                        output.functions[n_funcs].last_line_no =
                                            last_line_num + 1;
                                    }
                                    n_funcs = n_funcs.saturating_add(1);
                                    func_name.clear();
                                    func_addr = 0;
                                } else {
                                    // Beginning of function
                                    let str_data =
                                        read_str_from_data(&stabstr_sec.data, sym.n_strx);

                                    let parsed_name = if let Some(colon_pos) =
                                        str_data.find(':')
                                    {
                                        str_data[..colon_pos].to_string()
                                    } else {
                                        str_data.clone()
                                    };

                                    // Truncate to max length
                                    let truncated = if parsed_name.len() > MAX_FUNC_NAME_LENGTH {
                                        parsed_name[..MAX_FUNC_NAME_LENGTH].to_string()
                                    } else {
                                        parsed_name
                                    };

                                    func_name.clone_from(&truncated);

                                    let assoc_file = if incl_index > 0
                                        && incl_index <= incl_files.len()
                                    {
                                        incl_files[incl_index - 1].clone()
                                    } else {
                                        String::new()
                                    };

                                    let func_info = CoffFuncInfo {
                                        name: truncated,
                                        associated_file: assoc_file,
                                        line_no_file_ptr: file_pointer,
                                        func_entries: 0,
                                        end_address: 0,
                                        last_line_no: 0,
                                    };
                                    output.functions.push(func_info);

                                    output.section_headers[i].s_nlnno =
                                        output.section_headers[i].s_nlnno.saturating_add(1);
                                    file_pointer = file_pointer.saturating_add(LINESZ as i32);

                                    func_addr = sym.n_value;
                                }
                            }
                            x if x == N_SLINE => {
                                last_line_num = i32::from(sym.n_desc);
                                output.section_headers[i].s_nlnno =
                                    output.section_headers[i].s_nlnno.saturating_add(1);
                                file_pointer = file_pointer.saturating_add(LINESZ as i32);
                            }
                            x if x == N_BINCL => {
                                let str_data =
                                    read_str_from_data(&stabstr_sec.data, sym.n_strx);
                                if incl_index < INCLUDE_STACK_SIZE {
                                    if incl_index >= incl_files.len() {
                                        incl_files.push(str_data);
                                    } else {
                                        incl_files[incl_index] = str_data;
                                    }
                                    incl_index = incl_index.saturating_add(1);
                                }
                            }
                            x if x == N_EINCL => {
                                if incl_index > 1 {
                                    incl_index = incl_index.saturating_sub(1);
                                }
                            }
                            x if x == N_SO => {
                                if sym.n_strx == 0 {
                                    incl_index = 0;
                                } else {
                                    let str_data =
                                        read_str_from_data(&stabstr_sec.data, sym.n_strx);
                                    if !str_data.is_empty()
                                        && !str_data.ends_with('/')
                                        && incl_index < INCLUDE_STACK_SIZE
                                    {
                                        if incl_index >= incl_files.len() {
                                            incl_files.push(str_data);
                                        } else {
                                            incl_files[incl_index] = str_data;
                                        }
                                        incl_index = incl_index.saturating_add(1);
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                    stab_offset = stab_offset.saturating_add(stab_size);
                }
            }
        }
    }

    // -------------------------------------------------------------------
    // Symbol table pointer (tcccoff.c:318-325)
    // -------------------------------------------------------------------
    file_hdr.f_symptr = file_pointer;

    if state.do_debug {
        file_hdr.f_nsyms = coff_nb_syms;
    } else {
        file_hdr.f_nsyms = 0;
    }

    file_pointer = file_pointer.saturating_add(file_hdr.f_nsyms.saturating_mul(SYMESZ as i32));

    // -------------------------------------------------------------------
    // Build the complete output buffer
    // -------------------------------------------------------------------
    let mut out_buf: Vec<u8> = Vec::with_capacity(file_pointer as usize + 4096);

    // Write file header (tcccoff.c:330)
    write_file_header(&mut out_buf, &file_hdr);

    // Write AOUT optional header (tcccoff.c:331)
    write_aout_header(&mut out_buf, &o_filehdr);

    // Write section headers (tcccoff.c:334-341)
    for i in 1..total_sections {
        if output_the_section(&state.sections[i]) {
            write_section_header(&mut out_buf, &output.section_headers[i]);
        }
    }

    // Write raw data (tcccoff.c:344-351)
    for i in 1..total_sections {
        if output_the_section(&state.sections[i]) {
            let data_len = state.sections[i].data_offset;
            if data_len <= state.sections[i].data.len() {
                out_buf.extend_from_slice(&state.sections[i].data[..data_len]);
            } else {
                out_buf.extend_from_slice(&state.sections[i].data);
            }
        }
    }

    // Write relocation data (tcccoff.c:354-365)
    for i in 1..total_sections {
        if output_the_section(&state.sections[i]) && output.section_headers[i].s_nreloc > 0 {
            // Convert ELF relocations to COFF format
            if let Some(reloc_idx) = state.sections[i].reloc {
                if reloc_idx < state.sections.len() {
                    let reloc_data = &state.sections[reloc_idx].data;
                    out_buf.extend_from_slice(reloc_data);
                }
            }
        }
    }

    // Sort symbol table if debug mode (tcccoff.c:372)
    if state.do_debug {
        sort_symbol_table(state, &output.functions)?;
    }

    // Build symbol index map for O(1) lookups during line number emission
    let sym_index_map = build_coff_symbol_index_map(state);

    // Write line number data (tcccoff.c:376-505)
    for i in 1..total_sections {
        if state.do_debug && state.sections[i].name == stext_name {
            if let (Some(stab_sec), Some(stabstr_sec)) =
                (get_stab_section(state), get_stabstr_section(state))
            {
                let stab_size = 12_usize;
                let mut stab_offset = stab_size;
                let stab_end = stab_sec.data_offset;

                let mut func_name = String::new();
                let mut func_addr: u32 = 0;
                let mut last_pc: u32 = 0;
                let mut last_line_num: i32 = 1;
                let mut incl_files: Vec<String> = Vec::with_capacity(INCLUDE_STACK_SIZE);
                let mut incl_index: usize = 0;

                while stab_offset < stab_end {
                    if let Some(sym) = read_stab_sym(&stab_sec.data, stab_offset) {
                        match sym.n_type {
                            x if x == N_FUN => {
                                if sym.n_strx == 0 {
                                    // End of function — write final line entry
                                    let lineno = CoffLineno {
                                        l_addr: last_pc as i32,
                                        l_lnno: (last_line_num + 1) as u16,
                                    };
                                    write_lineno(&mut out_buf, lineno);

                                    func_name.clear();
                                    func_addr = 0;
                                } else {
                                    // Beginning of function
                                    let str_data =
                                        read_str_from_data(&stabstr_sec.data, sym.n_strx);
                                    func_name = if let Some(colon_pos) = str_data.find(':') {
                                        str_data[..colon_pos].to_string()
                                    } else {
                                        str_data
                                    };

                                    func_addr = sym.n_value;
                                    last_pc = func_addr;
                                    last_line_num = -1;

                                    // Write function-begin line entry (l_lnno = 0)
                                    // Use HashMap for O(1) lookup instead of repeated O(n) scans
                                    let sym_idx = sym_index_map
                                        .get(&func_name)
                                        .copied()
                                        .unwrap_or_else(|| {
                                            find_coff_symbol_index(state, &func_name)
                                        });
                                    let lineno = CoffLineno {
                                        l_addr: sym_idx,
                                        l_lnno: 0,
                                    };
                                    write_lineno(&mut out_buf, lineno);
                                }
                            }
                            x if x == N_SLINE => {
                                let pc = sym.n_value.saturating_add(func_addr);

                                let l_lnno = if last_line_num == -1 {
                                    sym.n_desc
                                } else {
                                    (last_line_num + 1) as u16
                                };

                                let lineno = CoffLineno {
                                    l_addr: last_pc as i32,
                                    l_lnno,
                                };
                                write_lineno(&mut out_buf, lineno);

                                last_pc = pc;
                                last_line_num = i32::from(sym.n_desc);
                            }
                            x if x == N_BINCL => {
                                let str_data =
                                    read_str_from_data(&stabstr_sec.data, sym.n_strx);
                                if incl_index < INCLUDE_STACK_SIZE {
                                    if incl_index >= incl_files.len() {
                                        incl_files.push(str_data);
                                    } else {
                                        incl_files[incl_index] = str_data;
                                    }
                                    incl_index = incl_index.saturating_add(1);
                                }
                            }
                            x if x == N_EINCL => {
                                if incl_index > 1 {
                                    incl_index = incl_index.saturating_sub(1);
                                }
                            }
                            x if x == N_SO => {
                                if sym.n_strx == 0 {
                                    incl_index = 0;
                                } else {
                                    let str_data =
                                        read_str_from_data(&stabstr_sec.data, sym.n_strx);
                                    if !str_data.is_empty()
                                        && !str_data.ends_with('/')
                                        && incl_index < INCLUDE_STACK_SIZE
                                    {
                                        if incl_index >= incl_files.len() {
                                            incl_files.push(str_data);
                                        } else {
                                            incl_files[incl_index] = str_data;
                                        }
                                        incl_index = incl_index.saturating_add(1);
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                    stab_offset = stab_offset.saturating_add(stab_size);
                }
            }
        }
    }

    // -------------------------------------------------------------------
    // Write symbol table (tcccoff.c:508-672)
    // -------------------------------------------------------------------
    if state.do_debug {
        let symtab = get_symtab_section(state);
        let strtab = get_symtab_strtab(state);
        let sym_count = symtab.data_offset / sym_size;

        let mut str_table: Vec<u8> = Vec::new();
        let mut str_offset: usize = 0;
        let mut n: i32 = 0;

        for sym_i in 0..sym_count {
            let p = read_elf32_sym(&symtab.data, sym_i);
            let name = read_str_from_section(strtab, p.st_name);

            let mut csym = CoffSyment {
                n_name: [0u8; SYMNMLEN],
                n_value: 0,
                n_scnum: 0,
                n_type: 0,
                n_sclass: 0,
                n_numaux: 0,
            };

            set_coff_sym_name(&mut csym.n_name, &name, &mut str_table, &mut str_offset)?;

            if p.st_info == 4 {
                // File symbol (tcccoff.c:550-558)
                csym.n_value = 33;
                csym.n_scnum = N_DEBUG;
                csym.n_type = 0;
                csym.n_sclass = C_FILE;
                csym.n_numaux = 0;
                write_syment(&mut out_buf, &csym);
                n = n.saturating_add(1);
            } else if p.st_info == 0x12 {
                // Function symbol (tcccoff.c:560-629)
                let k = get_func_index(&output.functions, &name);

                if k.is_none() {
                    return Err(TccError::Link(format!(
                        "debug info can't find function: {name}"
                    )));
                }
                let k = k.unwrap_or(0);

                // Function name entry
                csym.n_value = p.st_value as i32;
                csym.n_scnum = coff_text_section_no as i16;
                csym.n_type = mktype(T_INT, DT_FCN);
                csym.n_sclass = C_EXT;
                csym.n_numaux = 1;
                write_syment(&mut out_buf, &csym);

                // Auxiliary function entry
                let auxfunc = AuxFunc {
                    tag_index: 0,
                    total_size: (output.functions[k].end_address as i32)
                        .saturating_sub(p.st_value as i32),
                    lnno_ptr: output.functions[k].line_no_file_ptr,
                    next_function: n.saturating_add(6),
                    dummy: 0,
                };
                write_auxfunc(&mut out_buf, &auxfunc);

                // .bf entry
                let mut bf_sym = CoffSyment {
                    n_name: [0u8; SYMNMLEN],
                    n_value: p.st_value as i32,
                    n_scnum: coff_text_section_no as i16,
                    n_type: 0,
                    n_sclass: C_FCN,
                    n_numaux: 1,
                };
                bf_sym.n_name[..3].copy_from_slice(b".bf");
                write_syment(&mut out_buf, &bf_sym);

                // .bf auxiliary entry
                let bf_aux_entry = AuxBf {
                    regmask: 0,
                    lineno: 0,
                    nentries: output.functions[k].func_entries as u16,
                    localframe: 0,
                    nextentry: n.saturating_add(6),
                    dummy: 0,
                };
                write_auxbf(&mut out_buf, &bf_aux_entry);

                // .ef entry
                let mut ef_sym = CoffSyment {
                    n_name: [0u8; SYMNMLEN],
                    n_value: output.functions[k].end_address as i32,
                    n_scnum: coff_text_section_no as i16,
                    n_type: 0,
                    n_sclass: C_FCN,
                    n_numaux: 1,
                };
                ef_sym.n_name[..3].copy_from_slice(b".ef");
                write_syment(&mut out_buf, &ef_sym);

                // .ef auxiliary entry
                let ef_aux_entry = AuxEf {
                    dummy: 0,
                    lineno: output.functions[k].last_line_no as u16,
                    dummy1: 0,
                    dummy2: 0,
                    dummy3: 0,
                    dummy4: 0,
                };
                write_auxef(&mut out_buf, &ef_aux_entry);

                n = n.saturating_add(6);
            } else {
                // Other symbols (tcccoff.c:631-668)
                let vt_btype_val = i32::from(p.st_other) & VT_BTYPE;

                if vt_btype_val == VT_DOUBLE {
                    csym.n_type = T_DOUBLE;
                    csym.n_sclass = C_EXT;
                } else if vt_btype_val == VT_FLOAT {
                    csym.n_type = T_FLOAT;
                    csym.n_sclass = C_EXT;
                } else if vt_btype_val == VT_INT {
                    csym.n_type = T_INT;
                    csym.n_sclass = C_EXT;
                } else if vt_btype_val == VT_SHORT {
                    csym.n_type = T_SHORT;
                    csym.n_sclass = C_EXT;
                } else if vt_btype_val == VT_BYTE {
                    csym.n_type = T_CHAR;
                    csym.n_sclass = C_EXT;
                } else {
                    csym.n_type = T_INT;
                    csym.n_sclass = C_LABEL;
                }

                csym.n_value = p.st_value as i32;
                csym.n_scnum = 2; // data section
                csym.n_numaux = 1;
                write_syment(&mut out_buf, &csym);

                // Auxiliary entry for non-function symbols
                let auxfunc = AuxFunc {
                    tag_index: 0,
                    total_size: 0x20,
                    lnno_ptr: 0,
                    next_function: 0,
                    dummy: 0,
                };
                write_auxfunc(&mut out_buf, &auxfunc);
                n = n.saturating_add(2);
            }
        }

        // -------------------------------------------------------------------
        // Write string table (tcccoff.c:675-686)
        // -------------------------------------------------------------------
        // First write the string table size (4 bytes)
        let str_table_size = str_offset as i32;
        out_buf.extend_from_slice(&str_table_size.to_le_bytes());
        // Then write the string data
        out_buf.extend_from_slice(&str_table);
    }

    // -------------------------------------------------------------------
    // Flush entire buffer to writer
    // -------------------------------------------------------------------
    writer.write_all(&out_buf)?;

    Ok(())
}

// ============================================================================
// Symbol registration helper for COFF loading
// ============================================================================

/// Add a loaded COFF symbol to `TccState`'s internal symbol tracking.
///
/// This is an internal helper used by `tcc_load_coff`. The public API
/// `TccContext::add_symbol()` wraps similar logic but operates on the
/// public wrapper type. This function directly manipulates `TccState`'s
/// internal structures to register a loaded symbol.
///
/// C equivalent: `tcc_add_symbol()` in libtcc.c (called from `tcc_load_coff`).
fn add_coff_symbol_to_state(state: &mut TccState, name: &str, value: u32) -> TccResult<()> {
    // Add the symbol name and value to the symtab section data.
    // Find (or create) the ".symtab" section in the state.
    let symtab_idx = state
        .sections
        .iter()
        .position(|s| s.name == ".symtab");

    let symtab_idx = match symtab_idx {
        Some(idx) => idx,
        None => {
            // Create a new symtab section if none exists
            state.new_section(".symtab", 2, 0) // SHT_SYMTAB = 2
        }
    };

    // Write a minimal Elf32_Sym entry to the symtab section data.
    // This allows the linker to resolve references to this symbol later.
    let sym_size = 16_usize;

    // First, ensure the string table section exists and add the name
    let strtab_idx = state.sections[symtab_idx].link;
    let strtab_idx = match strtab_idx {
        Some(idx) if idx < state.sections.len() => idx,
        _ => {
            let idx = state
                .sections
                .iter()
                .position(|s| s.name == ".strtab")
                .unwrap_or_else(|| state.new_section(".strtab", 3, 0)); // SHT_STRTAB = 3
            state.sections[symtab_idx].link = Some(idx);
            idx
        }
    };

    // Add name to string table
    let name_offset = state.sections[strtab_idx].data_offset;
    state.sections[strtab_idx]
        .data
        .extend_from_slice(name.as_bytes());
    state.sections[strtab_idx].data.push(0); // NUL terminator
    state.sections[strtab_idx].data_offset = state.sections[strtab_idx]
        .data_offset
        .saturating_add(name.len() + 1);

    // Write Elf32_Sym entry: { st_name, st_value, st_size, st_info, st_other, st_shndx }
    let name_off_u32: u32 = u32::try_from(name_offset)
        .map_err(|_| TccError::Link("symbol name offset overflow".into()))?;

    let section_data = &mut state.sections[symtab_idx].data;
    section_data.extend_from_slice(&name_off_u32.to_le_bytes()); // st_name
    section_data.extend_from_slice(&value.to_le_bytes()); // st_value
    section_data.extend_from_slice(&0_u32.to_le_bytes()); // st_size
    section_data.push(0x12); // st_info: STB_GLOBAL (1) << 4 | STT_FUNC (2) = 0x12
    section_data.push(0); // st_other
    section_data.extend_from_slice(&0_u16.to_le_bytes()); // st_shndx: SHN_UNDEF

    state.sections[symtab_idx].data_offset = state.sections[symtab_idx]
        .data_offset
        .saturating_add(sym_size);

    Ok(())
}

// ============================================================================
// COFF Loading Function — tcc_load_coff
// ============================================================================

/// Load symbols from a COFF object file.
///
/// C equivalent: `tcc_load_coff()` at tcccoff.c:864-951.
///
/// Pipeline:
/// 1. Read COFF file header (FILHDR)
/// 2. Read optional AOUT header
/// 3. Seek to string table (after symbol table)
/// 4. Read string table
/// 5. Iterate over symbol table entries
/// 6. For each external symbol (`C_EXT`), add to `TccState` symbol table
/// 7. Strip leading underscores except for `_main`
/// 8. Skip auxiliary symbol entries
///
/// All file I/O uses `std::io::Read` + `BufReader`.
/// Symbol name extraction from union uses safe byte array access.
#[allow(clippy::cast_possible_truncation)]
#[allow(clippy::cast_sign_loss)]
#[allow(clippy::cast_possible_wrap)]
#[allow(clippy::too_many_lines)]
pub fn tcc_load_coff<R: Read + Seek>(state: &mut TccState, reader: &mut R) -> TccResult<()> {
    let mut buf_reader = io::BufReader::new(reader);

    // -------------------------------------------------------------------
    // Read file header (tcccoff.c:881-882)
    // -------------------------------------------------------------------
    let mut hdr_buf = [0u8; FILHSZ];
    buf_reader
        .read_exact(&mut hdr_buf)
        .map_err(|e| TccError::Link(format!("error reading COFF file header: {e}")))?;

    let file_hdr = CoffFileHeader {
        f_magic: u16::from_le_bytes([hdr_buf[0], hdr_buf[1]]),
        f_nscns: u16::from_le_bytes([hdr_buf[2], hdr_buf[3]]),
        f_timdat: i32::from_le_bytes([hdr_buf[4], hdr_buf[5], hdr_buf[6], hdr_buf[7]]),
        f_symptr: i32::from_le_bytes([hdr_buf[8], hdr_buf[9], hdr_buf[10], hdr_buf[11]]),
        f_nsyms: i32::from_le_bytes([hdr_buf[12], hdr_buf[13], hdr_buf[14], hdr_buf[15]]),
        f_opthdr: u16::from_le_bytes([hdr_buf[16], hdr_buf[17]]),
        f_flags: u16::from_le_bytes([hdr_buf[18], hdr_buf[19]]),
        f_target_id: u16::from_le_bytes([hdr_buf[20], hdr_buf[21]]),
    };

    // -------------------------------------------------------------------
    // Read AOUT optional header (tcccoff.c:884-885)
    // -------------------------------------------------------------------
    let mut aout_buf = [0u8; AOUTSZ];
    buf_reader
        .read_exact(&mut aout_buf)
        .map_err(|e| TccError::Link(format!("error reading COFF optional header: {e}")))?;

    // -------------------------------------------------------------------
    // Seek to string table (after symbol table) (tcccoff.c:889-890)
    // -------------------------------------------------------------------
    let sym_end_offset = (file_hdr.f_symptr as u64)
        .saturating_add((file_hdr.f_nsyms as u64).saturating_mul(SYMESZ as u64));
    buf_reader
        .seek(SeekFrom::Start(sym_end_offset))
        .map_err(|e| TccError::Link(format!("error seeking in COFF file: {e}")))?;

    // -------------------------------------------------------------------
    // Read string table size (tcccoff.c:892-893)
    // -------------------------------------------------------------------
    let mut str_size_buf = [0u8; 4];
    buf_reader
        .read_exact(&mut str_size_buf)
        .map_err(|e| TccError::Link(format!("error reading string table size: {e}")))?;
    let str_size = u32::from_le_bytes(str_size_buf) as usize;

    // -------------------------------------------------------------------
    // Read string table data (tcccoff.c:896-899)
    // -------------------------------------------------------------------
    let str_data_size = str_size.saturating_sub(4);
    let mut coff_str_table = vec![0u8; str_data_size];
    if str_data_size > 0 {
        buf_reader
            .read_exact(&mut coff_str_table)
            .map_err(|e| TccError::Link(format!("error reading string table: {e}")))?;
    }

    // -------------------------------------------------------------------
    // Seek back to symbol table (tcccoff.c:905-906)
    // -------------------------------------------------------------------
    buf_reader
        .seek(SeekFrom::Start(file_hdr.f_symptr as u64))
        .map_err(|e| TccError::Link(format!("error seeking to symbol table: {e}")))?;

    // -------------------------------------------------------------------
    // Read and process symbols (tcccoff.c:908-948)
    // -------------------------------------------------------------------
    let mut i: i32 = 0;
    while i < file_hdr.f_nsyms {
        let mut sym_buf = [0u8; SYMESZ];
        buf_reader
            .read_exact(&mut sym_buf)
            .map_err(|e| TccError::Link(format!("error reading COFF symbol: {e}")))?;

        // Parse symbol entry
        let n_name = {
            let mut arr = [0u8; SYMNMLEN];
            arr.copy_from_slice(&sym_buf[0..SYMNMLEN]);
            arr
        };
        let n_value = i32::from_le_bytes([sym_buf[8], sym_buf[9], sym_buf[10], sym_buf[11]]);
        let _n_scnum = i16::from_le_bytes([sym_buf[12], sym_buf[13]]);
        let n_type = u16::from_le_bytes([sym_buf[14], sym_buf[15]]);
        let n_sclass = sym_buf[16] as i8;
        let n_numaux = sym_buf[17] as i8;

        // Determine symbol name (tcccoff.c:912-924)
        let n_zeroes = i32::from_le_bytes([n_name[0], n_name[1], n_name[2], n_name[3]]);

        let name: String = if n_zeroes == 0 {
            // Long name: get from string table
            let n_offset =
                u32::from_le_bytes([n_name[4], n_name[5], n_name[6], n_name[7]]) as usize;
            let table_offset = n_offset.saturating_sub(4);
            if table_offset < coff_str_table.len() {
                let end = coff_str_table[table_offset..]
                    .iter()
                    .position(|&b| b == 0)
                    .map_or(coff_str_table.len(), |pos| table_offset + pos);
                String::from_utf8_lossy(&coff_str_table[table_offset..end]).into_owned()
            } else {
                String::new()
            }
        } else {
            // Short name: directly in n_name field
            // Check if all 8 bytes are used (no null terminator within 8 bytes)
            let end = n_name
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(SYMNMLEN);
            String::from_utf8_lossy(&n_name[..end]).into_owned()
        };

        // Check if this is an external symbol we should add (tcccoff.c:929-940)
        // Factor out common n_sclass == C_EXT check per clippy nonminimal_bool
        let type_match = n_sclass == C_EXT
            && ((n_type & 0x30) == 0x20
                || (n_type & 0x30) == 0x30
                || n_type == 0x4
                || n_type == 0x8
                || n_type == 0x18
                || n_type == 0x7
                || n_type == 0x6);

        if type_match {
            // Strip leading underscore, except for _main (tcccoff.c:936-937)
            let sym_name = if name.starts_with('_') && name != "_main" {
                &name[1..]
            } else {
                &name
            };

            // Add symbol to TccState (tcccoff.c:939)
            // Uses internal helper since add_symbol() is on TccContext public API.
            // This directly adds a COFF-loaded symbol to the compiler state.
            add_coff_symbol_to_state(state, sym_name, n_value as u32)?;
        }

        // Skip auxiliary entries (tcccoff.c:943-947)
        if n_numaux == 1 {
            let mut aux_buf = [0u8; SYMESZ];
            buf_reader
                .read_exact(&mut aux_buf)
                .map_err(|e| TccError::Link(format!("error reading COFF aux entry: {e}")))?;
            i = i.saturating_add(1);
        }

        i = i.saturating_add(1);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_output_the_section() {
        let mut sec = Section {
            name: ".text".into(),
            ..Section::default()
        };
        assert!(output_the_section(&sec));

        sec.name = ".data".into();
        assert!(output_the_section(&sec));

        sec.name = ".bss".into();
        assert!(!output_the_section(&sec));

        sec.name = ".rodata".into();
        assert!(!output_the_section(&sec));
    }

    #[test]
    fn test_get_coff_flags() {
        assert_eq!(
            get_coff_flags(".text"),
            STYP_TEXT | STYP_DATA | STYP_ALIGN | 0x400
        );
        assert_eq!(get_coff_flags(".data"), STYP_DATA);
        assert_eq!(get_coff_flags(".bss"), STYP_BSS);
        assert_eq!(
            get_coff_flags(".stack"),
            STYP_BSS | STYP_ALIGN | 0x200
        );
        assert_eq!(
            get_coff_flags(".cinit"),
            STYP_COPY | STYP_DATA | STYP_ALIGN | 0x200
        );
        assert_eq!(get_coff_flags(".unknown"), 0);
    }

    #[test]
    fn test_mktype() {
        // MKTYPE(T_INT, DT_FCN, 0, 0, 0, 0, 0) should yield T_INT | (DT_FCN << 4)
        let result = mktype(T_INT, DT_FCN);
        assert_eq!(result, T_INT | (DT_FCN << 4));
    }

    #[test]
    fn test_set_coff_sym_name_short() {
        let mut n_name = [0u8; SYMNMLEN];
        let mut str_table = Vec::new();
        let mut str_offset = 0_usize;

        set_coff_sym_name(&mut n_name, "main", &mut str_table, &mut str_offset).unwrap();
        assert_eq!(&n_name[..4], b"main");
        assert_eq!(n_name[4], 0);
        assert!(str_table.is_empty());
        assert_eq!(str_offset, 0);
    }

    #[test]
    fn test_set_coff_sym_name_long() {
        let mut n_name = [0u8; SYMNMLEN];
        let mut str_table = Vec::new();
        let mut str_offset = 0_usize;

        let long_name = "very_long_symbol_name";
        set_coff_sym_name(&mut n_name, long_name, &mut str_table, &mut str_offset).unwrap();

        // First 4 bytes should be zero (long name indicator)
        let zeroes = i32::from_le_bytes([n_name[0], n_name[1], n_name[2], n_name[3]]);
        assert_eq!(zeroes, 0);

        // Offset should be 4 (string table starts at index 0, but COFF convention adds 4)
        let offset = i32::from_le_bytes([n_name[4], n_name[5], n_name[6], n_name[7]]);
        assert_eq!(offset, 4);

        // String table should contain the name + null
        assert_eq!(str_table.len(), long_name.len() + 1);
        assert_eq!(&str_table[..long_name.len()], long_name.as_bytes());
        assert_eq!(str_table[long_name.len()], 0);
    }

    #[test]
    fn test_coff_output_default() {
        let output = CoffOutput::default();
        assert!(output.section_headers.is_empty() || output.section_headers.capacity() >= 1);
        assert!(output.functions.is_empty());
        assert!(output.string_table.is_empty());
        assert!(output.symbol_table.is_empty());
        assert_eq!(output.c67_main_entry_point, 0);
    }

    #[test]
    fn test_write_file_header_size() {
        let hdr = CoffFileHeader {
            f_magic: COFF_C67_MAGIC,
            f_nscns: 2,
            f_timdat: 0,
            f_symptr: 100,
            f_nsyms: 10,
            #[allow(clippy::cast_possible_truncation)]
            f_opthdr: AOUTSZ as u16,
            f_flags: 0x1143,
            f_target_id: 0x99,
        };
        let mut buf = Vec::new();
        write_file_header(&mut buf, &hdr);
        assert_eq!(buf.len(), FILHSZ);
    }

    #[test]
    fn test_write_aout_header_size() {
        let hdr = CoffAoutHeader {
            magic: 0x0108,
            vstamp: 0x0190,
            tsize: 1000,
            dsize: 200,
            bsize: 50,
            entrypt: 0,
            text_start: 0x0040_0000,
            data_start: 0x0050_0000,
        };
        let mut buf = Vec::new();
        write_aout_header(&mut buf, &hdr);
        assert_eq!(buf.len(), AOUTSZ);
    }

    #[test]
    fn test_write_syment_size() {
        let sym = CoffSyment {
            n_name: [0u8; SYMNMLEN],
            n_value: 0,
            n_scnum: 0,
            n_type: 0,
            n_sclass: 0,
            n_numaux: 0,
        };
        let mut buf = Vec::new();
        write_syment(&mut buf, &sym);
        assert_eq!(buf.len(), SYMESZ);
    }

    #[test]
    fn test_write_lineno_size() {
        let ln = CoffLineno {
            l_addr: 0x1000,
            l_lnno: 42,
        };
        let mut buf = Vec::new();
        write_lineno(&mut buf, ln);
        assert_eq!(buf.len(), LINESZ);
    }

    #[test]
    fn test_coff_func_info_default() {
        let info = CoffFuncInfo::default();
        assert!(info.name.is_empty());
        assert!(info.associated_file.is_empty());
        assert_eq!(info.line_no_file_ptr, 0);
        assert_eq!(info.func_entries, 0);
        assert_eq!(info.end_address, 0);
        assert_eq!(info.last_line_no, 0);
    }

    #[test]
    fn test_aux_structs_default() {
        let af = AuxFunc::default();
        assert_eq!(af.tag_index, 0);
        assert_eq!(af.total_size, 0);

        let abf = AuxBf::default();
        assert_eq!(abf.regmask, 0);
        assert_eq!(abf.lineno, 0);

        let aef = AuxEf::default();
        assert_eq!(aef.dummy, 0);
        assert_eq!(aef.lineno, 0);
    }

    #[test]
    fn test_read_elf32_sym_out_of_bounds() {
        let data = vec![0u8; 4]; // too small
        let sym = read_elf32_sym(&data, 0);
        assert_eq!(sym.st_name, 0);
        assert_eq!(sym.st_info, 0);
    }

    #[test]
    fn test_read_str_from_data_empty() {
        let data = vec![0u8; 10];
        let result = read_str_from_data(&data, 0);
        assert!(result.is_empty());
    }

    #[test]
    fn test_read_str_from_data_valid() {
        let mut data = Vec::new();
        data.extend_from_slice(b"hello\0world\0");
        let result = read_str_from_data(&data, 0);
        assert_eq!(result, "hello");
        let result2 = read_str_from_data(&data, 6);
        assert_eq!(result2, "world");
    }

    #[test]
    fn test_get_func_index() {
        let funcs = vec![
            CoffFuncInfo {
                name: "foo".into(),
                ..CoffFuncInfo::default()
            },
            CoffFuncInfo {
                name: "bar".into(),
                ..CoffFuncInfo::default()
            },
        ];
        assert_eq!(get_func_index(&funcs, "foo"), Some(0));
        assert_eq!(get_func_index(&funcs, "bar"), Some(1));
        assert_eq!(get_func_index(&funcs, "baz"), None);
    }
}
