//! COFF (Common Object File Format) binary format definitions.
//!
//! This module provides Rust struct definitions and constants translated from
//! the original `TinyCC` `coff.h` header (446 lines). All structs use `#[repr(C)]`
//! for binary compatibility. These definitions are used primarily by the C67 DSP
//! target's COFF linker backend and PE/COFF output.
//!
//! C equivalent: `coff.h`

// COFF format definitions — struct field prefixes (f_*, s_*, r_*, n_*, ar_*)
// preserve the COFF specification naming convention from coff.h for traceability.
#![allow(clippy::struct_field_names)]

// Allow dead_code: this is a data-definition module whose consumers
// (src/linker/coff.rs, src/linker/pe.rs) are created by other agents.
#![allow(dead_code)]

// -------------------------------------------------------------------------
//  COFF FILE HEADER
//  C equivalent: struct filehdr in coff.h:9-18
// -------------------------------------------------------------------------

/// COFF File Header.
///
/// C equivalent: `struct filehdr` in `coff.h:9-18`.
/// Note: The C `long` type in the COFF header maps to `i32` (TCC uses 32-bit
/// COFF where `long` is 4 bytes). `FILHSZ` = 22 confirms the packed on-disk
/// layout (the in-memory struct may have trailing padding due to alignment).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub(crate) struct CoffFileHeader {
    /// Magic number
    pub f_magic: u16,
    /// Number of sections
    pub f_nscns: u16,
    /// Time and date stamp
    pub f_timdat: i32,
    /// File pointer to symbol table
    pub f_symptr: i32,
    /// Number of symbol table entries
    pub f_nsyms: i32,
    /// Size of optional header (`sizeof(optional hdr)`)
    pub f_opthdr: u16,
    /// Flags (see `F_RELFLG`, `F_EXEC`, etc.)
    pub f_flags: u16,
    /// Target ID (for C6x = 0x0099)
    pub f_target_id: u16,
}

// -------------------------------------------------------------------------
//  File header flags — coff.h:23-38
// -------------------------------------------------------------------------

/// Relocation info stripped from file
pub(crate) const F_RELFLG: u16 = 0x01;
/// File is executable (no unresolved refs)
pub(crate) const F_EXEC: u16 = 0x02;
/// Line numbers stripped from file
pub(crate) const F_LNNO: u16 = 0x04;
/// Local symbols stripped from file
pub(crate) const F_LSYMS: u16 = 0x08;
/// 34010 version
pub(crate) const F_GSP10: u16 = 0x10;
/// 34020 version
pub(crate) const F_GSP20: u16 = 0x20;
/// Bytes swabbed (in names)
pub(crate) const F_SWABD: u16 = 0x40;
/// Byte ordering of an AR16WR (PDP-11)
pub(crate) const F_AR16WR: u16 = 0x80;
/// Byte ordering of an AR32WR (vax) — little endian
pub(crate) const F_LITTLE: u16 = 0x100;
/// Byte ordering of an AR32W (3B, maxi) — big endian
pub(crate) const F_BIG: u16 = 0x200;
/// Contains "patch" list in optional header
pub(crate) const F_PATCH: u16 = 0x400;
/// No-definition flag (same value as `F_PATCH`)
pub(crate) const F_NODF: u16 = 0x400;

/// Combined version flags (`F_GSP10 | F_GSP20`)
pub(crate) const F_VERSION: u16 = F_GSP10 | F_GSP20;
/// Combined byte-order flags (`F_LITTLE | F_BIG`)
pub(crate) const F_BYTE_ORDER: u16 = F_LITTLE | F_BIG;

/// Size of COFF file header on disk (bytes). The in-memory `CoffFileHeader`
/// struct may be larger due to alignment padding; always use this constant
/// for I/O serialization.
pub(crate) const FILHSZ: usize = 22;

/// COFF C67 magic number (`TMS320C6x` DSP)
pub(crate) const COFF_C67_MAGIC: u16 = 0x00c2;

// -------------------------------------------------------------------------
//  OPTIONAL (AOUT) FILE HEADER
//  C equivalent: struct aouthdr / AOUTHDR in coff.h:56-65
// -------------------------------------------------------------------------

/// COFF Optional (AOUT) Header.
///
/// C equivalent: `typedef struct aouthdr` / `AOUTHDR` in `coff.h:56-65`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub(crate) struct CoffAoutHeader {
    /// See magic.h
    pub magic: i16,
    /// Version stamp
    pub vstamp: i16,
    /// Text size in bytes, padded to FW boundary
    pub tsize: i32,
    /// Initialized data size
    pub dsize: i32,
    /// Uninitialized data size
    pub bsize: i32,
    /// Entry point
    pub entrypt: i32,
    /// Base of text used for this file
    pub text_start: i32,
    /// Base of data used for this file
    pub data_start: i32,
}

/// Default: readonly sharable text segment
pub(crate) const AOUT1MAGIC: u16 = 0o410;
/// Writable text segment
pub(crate) const AOUT2MAGIC: u16 = 0o407;
/// Configured for paging
pub(crate) const PAGEMAGIC: u16 = 0o413;

// -------------------------------------------------------------------------
//  COMMON ARCHIVE FILE STRUCTURES
//  C equivalent: coff.h:82-126
// -------------------------------------------------------------------------

/// Archive magic string (`"!<arch>\n"`)
pub(crate) const COFF_ARMAG: &[u8; 8] = b"!<arch>\n";
/// Size of archive magic string
pub(crate) const SARMAG: usize = 8;
/// Archive file member terminator (`` "`\n" ``)
pub(crate) const ARFMAG: &[u8; 2] = b"`\n";

/// Archive file member header — printable ASCII.
///
/// C equivalent: `struct ar_hdr` in `coff.h:117-126`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub(crate) struct CoffArHeader {
    /// File member name — `'/'` terminated
    pub ar_name: [u8; 16],
    /// File member date — decimal
    pub ar_date: [u8; 12],
    /// File member user id — decimal
    pub ar_uid: [u8; 6],
    /// File member group id — decimal
    pub ar_gid: [u8; 6],
    /// File member mode — octal
    pub ar_mode: [u8; 8],
    /// File member size — decimal
    pub ar_size: [u8; 10],
    /// ARFMAG — string to end header
    pub ar_fmag: [u8; 2],
}

// -------------------------------------------------------------------------
//  SECTION HEADER
//  C equivalent: struct scnhdr in coff.h:132-145
// -------------------------------------------------------------------------

/// COFF Section Header.
///
/// C equivalent: `struct scnhdr` in `coff.h:132-145`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub(crate) struct CoffSectionHeader {
    /// Section name
    pub s_name: [u8; 8],
    /// Physical address
    pub s_paddr: i32,
    /// Virtual address
    pub s_vaddr: i32,
    /// Section size
    pub s_size: i32,
    /// File pointer to raw data for section
    pub s_scnptr: i32,
    /// File pointer to relocation
    pub s_relptr: i32,
    /// File pointer to line numbers
    pub s_lnnoptr: i32,
    /// Number of relocation entries
    pub s_nreloc: u32,
    /// Number of line number entries
    pub s_nlnno: u32,
    /// Flags (see `STYP_*` constants)
    pub s_flags: u32,
    /// Reserved byte
    pub s_reserved: u16,
    /// Memory page id
    pub s_page: u16,
}

// -------------------------------------------------------------------------
//  Section name constants — coff.h:153-157
// -------------------------------------------------------------------------

/// Section name: `.data`
pub(crate) const SECT_DATA: &str = ".data";
/// Section name: `.bss`
pub(crate) const SECT_BSS: &str = ".bss";
/// Section name: `.cinit`
pub(crate) const SECT_CINIT: &str = ".cinit";
/// Section name: `.tv`
pub(crate) const SECT_TV: &str = ".tv";

// -------------------------------------------------------------------------
//  Section type flags — coff.h:162-177
// -------------------------------------------------------------------------

/// "regular": allocated, relocated, loaded
pub(crate) const STYP_REG: u32 = 0x00;
/// "dummy": not allocated, relocated, not loaded
pub(crate) const STYP_DSECT: u32 = 0x01;
/// "noload": allocated, relocated, not loaded
pub(crate) const STYP_NOLOAD: u32 = 0x02;
/// "grouped": formed of input sections
pub(crate) const STYP_GROUP: u32 = 0x04;
/// "padding": not allocated, not relocated, loaded
pub(crate) const STYP_PAD: u32 = 0x08;
/// "copy": used for C init tables — not allocated, relocated, loaded;
/// relocation and line number entries processed normally
pub(crate) const STYP_COPY: u32 = 0x10;
/// Section contains text only
pub(crate) const STYP_TEXT: u32 = 0x20;
/// Section contains data only
pub(crate) const STYP_DATA: u32 = 0x40;
/// Section contains BSS only
pub(crate) const STYP_BSS: u32 = 0x80;
/// Align flag passed by old version assemblers
pub(crate) const STYP_ALIGN: u32 = 0x100;
/// Part of `s_flags` used for alignment values
pub(crate) const ALIGN_MASK: u32 = 0x0F00;

// -------------------------------------------------------------------------
//  RELOCATION ENTRIES
//  C equivalent: struct reloc in coff.h:183-189
// -------------------------------------------------------------------------

/// COFF Relocation Entry.
///
/// C equivalent: `struct reloc` in `coff.h:183-189`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub(crate) struct CoffReloc {
    /// (Virtual) address of reference
    pub r_vaddr: i32,
    /// Index into symbol table
    pub r_symndx: i16,
    /// Additional bits for address calculation
    pub r_disp: u16,
    /// Relocation type (see `R_*` constants)
    pub r_type: u16,
}

/// Size of relocation entry on disk (bytes)
pub(crate) const RELSZ: usize = 10;

// -------------------------------------------------------------------------
//  Relocation type constants — coff.h:198-217
//  All values translated from octal C defines.
// -------------------------------------------------------------------------

/// Absolute address — no relocation
pub(crate) const R_ABS: u16 = 0;
/// 16-bit direct
pub(crate) const R_DIR16: u16 = 0o01; // 1
/// 16-bit PC-relative
pub(crate) const R_REL16: u16 = 0o02; // 2
/// 24-bit direct
pub(crate) const R_DIR24: u16 = 0o04; // 4
/// 24-bit PC-relative
pub(crate) const R_REL24: u16 = 0o05; // 5
/// 32-bit direct
pub(crate) const R_DIR32: u16 = 0o06; // 6
/// 32-bit direct unsigned
pub(crate) const R_DIR32_U: u16 = 7;
/// 8 bits, direct
pub(crate) const R_RELBYTE: u16 = 0o017; // 15
/// 16 bits, direct
pub(crate) const R_RELWORD: u16 = 0o020; // 16
/// 32 bits, direct
pub(crate) const R_RELLONG: u16 = 0o021; // 17
/// 8 bits, PC-relative
pub(crate) const R_PCRBYTE: u16 = 0o022; // 18
/// 16 bits, PC-relative
pub(crate) const R_PCRWORD: u16 = 0o023; // 19
/// 32 bits, PC-relative
pub(crate) const R_PCRLONG: u16 = 0o024; // 20
/// GSP: 32 bits, one's complement direct
pub(crate) const R_OCRLONG: u16 = 0o030; // 24
/// GSP: 16 bits, PC-relative (in words)
pub(crate) const R_GSPPCR16: u16 = 0o031; // 25
/// GSP: 32 bits, direct big-endian
pub(crate) const R_GSPOPR32: u16 = 0o032; // 26
/// Brahma: 16-bit offset of 24-bit address
pub(crate) const R_PARTLS16: u16 = 0o040; // 32
/// Brahma: 8-bit page of 24-bit address
pub(crate) const R_PARTMS8: u16 = 0o041; // 33
/// DSP: 7-bit offset of 16-bit address
pub(crate) const R_PARTLS7: u16 = 0o050; // 40
/// DSP: 9-bit page of 16-bit address
pub(crate) const R_PARTMS9: u16 = 0o051; // 41
/// DSP: 13 bits, direct
pub(crate) const R_REL13: u16 = 0o052; // 42

// -------------------------------------------------------------------------
//  LINE NUMBER ENTRIES
//  C equivalent: struct lineno in coff.h:223-232
// -------------------------------------------------------------------------

/// COFF Line Number Entry.
///
/// C equivalent: `struct lineno` in `coff.h:223-232`.
/// The C `union l_addr` contains `l_symndx` (symbol table index when
/// `l_lnno == 0`) or `l_paddr` (physical address). Both are `long` (i32),
/// so a single `i32` field suffices.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub(crate) struct CoffLineno {
    /// Symbol table index of function name (when `l_lnno == 0`) or
    /// physical address of line number.
    pub l_addr: i32,
    /// Line number (0 means this entry identifies a function)
    pub l_lnno: u16,
}

/// Size of line number entry on disk (bytes)
pub(crate) const LINESZ: usize = 6;

// -------------------------------------------------------------------------
//  STORAGE CLASSES — coff.h:241-268
// -------------------------------------------------------------------------

/// Physical end of function
pub(crate) const C_EFCN: i8 = -1;
/// Null storage class
pub(crate) const C_NULL_COFF: i8 = 0;
/// Automatic variable
pub(crate) const C_AUTO: i8 = 1;
/// External symbol
pub(crate) const C_EXT: i8 = 2;
/// Static
pub(crate) const C_STAT: i8 = 3;
/// Register variable
pub(crate) const C_REG: i8 = 4;
/// External definition
pub(crate) const C_EXTDEF: i8 = 5;
/// Label
pub(crate) const C_LABEL: i8 = 6;
/// Undefined label
pub(crate) const C_ULABEL: i8 = 7;
/// Member of structure
pub(crate) const C_MOS: i8 = 8;
/// Function argument
pub(crate) const C_ARG: i8 = 9;
/// Structure tag
pub(crate) const C_STRTAG: i8 = 10;
/// Member of union
pub(crate) const C_MOU: i8 = 11;
/// Union tag
pub(crate) const C_UNTAG: i8 = 12;
/// Type definition
pub(crate) const C_TPDEF: i8 = 13;
/// Undefined static
pub(crate) const C_USTATIC: i8 = 14;
/// Enumeration tag
pub(crate) const C_ENTAG: i8 = 15;
/// Member of enumeration
pub(crate) const C_MOE: i8 = 16;
/// Register parameter
pub(crate) const C_REGPARM: i8 = 17;
/// Bit field
pub(crate) const C_FIELD: i8 = 18;
/// `.bb` or `.eb` (begin/end block)
pub(crate) const C_BLOCK: i8 = 100;
/// `.bf` or `.ef` (begin/end function)
pub(crate) const C_FCN: i8 = 101;
/// End of structure
pub(crate) const C_EOS: i8 = 102;
/// File name
pub(crate) const C_FILE: i8 = 103;
/// Dummy for line number entry
pub(crate) const C_LINE: i8 = 104;
/// Duplicate tag
pub(crate) const C_ALIAS: i8 = 105;
/// Special storage class for external symbols in dmert public libraries
pub(crate) const C_HIDDEN: i8 = 106;

// -------------------------------------------------------------------------
//  SYMBOL TABLE ENTRIES — coff.h:275-297
// -------------------------------------------------------------------------

/// Number of characters in a symbol name
pub(crate) const SYMNMLEN: usize = 8;
/// Number of characters in a file name
pub(crate) const FILNMLEN: usize = 14;
/// Number of array dimensions in auxiliary entry
pub(crate) const DIMNUM: usize = 4;

/// COFF Symbol Table Entry.
///
/// C equivalent: `struct syment` in `coff.h:280-297`.
///
/// The C union for `_n` (symbol name) is modeled as a `[u8; 8]` byte array.
/// When `n_name[0..4]` (interpreted as a `u32`) is zero, the remaining 4 bytes
/// (`n_name[4..8]`) contain an offset into the string table. Otherwise the
/// bytes contain the symbol name directly (padded with NULs).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub(crate) struct CoffSyment {
    /// Symbol name or `(n_zeroes=0, n_offset)` for long names
    pub n_name: [u8; SYMNMLEN],
    /// Value of symbol
    pub n_value: i32,
    /// Section number (see `N_UNDEF`, `N_ABS`, `N_DEBUG`)
    pub n_scnum: i16,
    /// Type and derived type (see `T_*`, `DT_*` constants)
    pub n_type: u16,
    /// Storage class (see `C_*` constants)
    pub n_sclass: i8,
    /// Number of auxiliary entries
    pub n_numaux: i8,
}

/// Size of SYMENT on disk (bytes)
pub(crate) const SYMESZ: usize = 18;

/// Size of AUXENT on disk (bytes)
pub(crate) const AUXESZ: usize = 18;

// -------------------------------------------------------------------------
//  Symbol section number constants — coff.h:309-313
// -------------------------------------------------------------------------

/// Undefined symbol
pub(crate) const N_UNDEF: i16 = 0;
/// Value of symbol is absolute
pub(crate) const N_ABS: i16 = -1;
/// Special debugging symbol
pub(crate) const N_DEBUG: i16 = -2;
/// Needs transfer vector (preload). C equivalent: `(unsigned short)-3`
pub(crate) const N_TV: i16 = -3;
/// Needs transfer vector (postload). C equivalent: `(unsigned short)-4`
pub(crate) const P_TV: i16 = -4;

// -------------------------------------------------------------------------
//  FUNDAMENTAL TYPE CONSTANTS — coff.h:322-337
//  The fundamental type of a symbol packed into the low 4 bits of the word.
// -------------------------------------------------------------------------

/// No type info
pub(crate) const T_NULL: u16 = 0;
/// Function argument (only used by compiler)
pub(crate) const T_ARG: u16 = 1;
/// Character
pub(crate) const T_CHAR: u16 = 2;
/// Short integer
pub(crate) const T_SHORT: u16 = 3;
/// Integer
pub(crate) const T_INT: u16 = 4;
/// Long integer
pub(crate) const T_LONG: u16 = 5;
/// Floating point
pub(crate) const T_FLOAT: u16 = 6;
/// Double word
pub(crate) const T_DOUBLE: u16 = 7;
/// Structure
pub(crate) const T_STRUCT: u16 = 8;
/// Union
pub(crate) const T_UNION: u16 = 9;
/// Enumeration
pub(crate) const T_ENUM: u16 = 10;
/// Member of enumeration
pub(crate) const T_MOE: u16 = 11;
/// Unsigned character
pub(crate) const T_UCHAR: u16 = 12;
/// Unsigned short
pub(crate) const T_USHORT: u16 = 13;
/// Unsigned integer
pub(crate) const T_UINT: u16 = 14;
/// Unsigned long
pub(crate) const T_ULONG: u16 = 15;

// -------------------------------------------------------------------------
//  DERIVED TYPE CONSTANTS — coff.h:342-345
// -------------------------------------------------------------------------

/// No derived type
pub(crate) const DT_NON: u16 = 0;
/// Pointer
pub(crate) const DT_PTR: u16 = 1;
/// Function
pub(crate) const DT_FCN: u16 = 2;
/// Array
pub(crate) const DT_ARY: u16 = 3;

// -------------------------------------------------------------------------
//  Type packing constants and helper functions — coff.h:354-367
// -------------------------------------------------------------------------

/// Base-type mask (low 4 bits)
pub(crate) const N_BTMASK_COFF: u16 = 0o17; // 0x0F
/// Derived-type mask (bits 4-5)
pub(crate) const N_TMASK_COFF: u16 = 0o60; // 0x30
/// Extended type mask 1 (bits 6-7)
pub(crate) const N_TMASK1_COFF: u16 = 0o300; // 0xC0
/// Extended type mask 2 (bits 4-7)
pub(crate) const N_TMASK2_COFF: u16 = 0o360; // 0xF0
/// Shift count for base-type extraction
pub(crate) const N_BTSHFT_COFF: u16 = 4;
/// Shift count for derived-type extraction
pub(crate) const N_TSHIFT_COFF: u16 = 2;

/// Get the base type from a COFF type field.
///
/// C equivalent: `BTYPE_COFF(x)` macro in `coff.h:361`.
#[inline]
pub(crate) const fn btype_coff(x: u16) -> u16 {
    x & N_BTMASK_COFF
}

/// Check if a COFF type field represents a pointer.
///
/// C equivalent: `ISPTR_COFF(x)` macro in `coff.h:365`.
#[inline]
pub(crate) const fn is_ptr_coff(x: u16) -> bool {
    (x & N_TMASK_COFF) == (DT_PTR << N_BTSHFT_COFF)
}

/// Check if a COFF type field represents a function.
///
/// C equivalent: `ISFCN_COFF(x)` macro in `coff.h:366`.
#[inline]
pub(crate) const fn is_fcn_coff(x: u16) -> bool {
    (x & N_TMASK_COFF) == (DT_FCN << N_BTSHFT_COFF)
}

/// Check if a COFF type field represents an array.
///
/// C equivalent: `ISARY_COFF(x)` macro in `coff.h:367`.
#[inline]
pub(crate) const fn is_ary_coff(x: u16) -> bool {
    (x & N_TMASK_COFF) == (DT_ARY << N_BTSHFT_COFF)
}

// -------------------------------------------------------------------------
//  AUXILIARY SYMBOL ENTRY — coff.h:377-415
// -------------------------------------------------------------------------

/// COFF Auxiliary Symbol Entry.
///
/// C equivalent: `union auxent` in `coff.h:377-415`.
///
/// The C original is a complex union with multiple interpretation variants
/// (function info, file info, section info). This is modeled as a raw byte
/// array of `AUXESZ` bytes; callers interpret the bytes according to the
/// associated symbol's storage class and type.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub(crate) struct CoffAuxent {
    /// Raw auxiliary entry data — interpret based on symbol context
    pub data: [u8; AUXESZ],
}

// -------------------------------------------------------------------------
//  NAMES OF "SPECIAL" SYMBOLS — coff.h:426-438
// -------------------------------------------------------------------------

/// Text section name (`.text`)
pub(crate) const STEXT: &str = ".text";
/// End-of-text symbol name (`etext`)
pub(crate) const ETEXT: &str = "etext";
/// Data section name (`.data`)
pub(crate) const SDATA: &str = ".data";
/// End-of-data symbol name (`edata`)
pub(crate) const EDATA: &str = "edata";
/// BSS section name (`.bss`)
pub(crate) const SBSS: &str = ".bss";
/// End symbol name (`end`)
pub(crate) const END: &str = "end";
/// C-init pointer symbol name (`cinit`)
pub(crate) const CINITPTR: &str = "cinit";
/// Program start symbol name (`_start`)
pub(crate) const START: &str = "_start";
/// Main function symbol name (`_main`)
pub(crate) const MAIN: &str = "_main";
