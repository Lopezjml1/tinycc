//! STABS (Symbol Table) debug format definitions.
//!
//! This module provides STABS debug symbol type constants and the `nlist` struct,
//! translated from the original TinyCC `stab.h` (17 lines) and `stab.def` (234 lines).
//! STABS is the legacy debug format used by TCC when DWARF is not selected.
//!
//! The `stab.def` file defines symbol types using the `__define_stab(NAME, CODE, STRING)`
//! macro pattern. Each entry is translated into a Rust constant.
//!
//! C equivalent: `stab.h` + `stab.def`

// =============================================================================
// Standard a.out symbol types (non-stab, 0x00–0x1F range)
//
// These come from the matrix comment at the end of stab.def. The low byte
// encodes segment identity; bit 0 is the EXTernal flag (N_EXT).
// =============================================================================

/// Undefined symbol.
pub(crate) const N_UNDF: u8 = 0x00;

/// Absolute symbol.
///
/// Named `N_ABS_SYM` (not `N_ABS`) to avoid collision with the COFF
/// `N_ABS` constant defined in `src/formats/coff.rs`.
pub(crate) const N_ABS_SYM: u8 = 0x02;

/// Text segment symbol.
pub(crate) const N_TEXT: u8 = 0x04;

/// Data segment symbol.
pub(crate) const N_DATA: u8 = 0x06;

/// BSS segment symbol.
pub(crate) const N_BSS: u8 = 0x08;

/// Indirect reference.
pub(crate) const N_INDR: u8 = 0x0a;

/// Sequence number (filename).
pub(crate) const N_FN_SEQ: u8 = 0x0c;

/// Common symbol.
pub(crate) const N_COMM: u8 = 0x12;

/// Set element (absolute).
pub(crate) const N_SETA: u8 = 0x14;

/// Set element (text).
pub(crate) const N_SETT: u8 = 0x16;

/// Set element (data).
pub(crate) const N_SETD: u8 = 0x18;

/// Set element (bss).
pub(crate) const N_SETB: u8 = 0x1a;

/// Set element (vector).
pub(crate) const N_SETV: u8 = 0x1c;

/// Warning symbol.
pub(crate) const N_WARNING: u8 = 0x1e;

/// File name symbol.
pub(crate) const N_FN: u8 = 0x1f;

// =============================================================================
// Mask and flag constants
// =============================================================================

/// External bit flag (OR'd with symbol type to mark external linkage).
pub(crate) const N_EXT: u8 = 0x01;

/// Type mask — extracts the symbol type without the external bit.
pub(crate) const N_TYPE: u8 = 0xfe;

/// Stab type mask — bits 0xe0 identify stab debug entries
/// (any symbol whose `n_type & N_STAB != 0` is a stab entry).
pub(crate) const N_STAB: u8 = 0xe0;

// =============================================================================
// STABS debug symbol type constants from stab.def
//
// Each constant was originally defined via the C macro:
//   __define_stab(NAME, CODE, "STRING")
// =============================================================================

/// Global variable. Only the name is significant.
/// To find the address, look in the corresponding external symbol.
///
/// C equivalent: `__define_stab(N_GSYM, 0x20, "GSYM")`
pub(crate) const N_GSYM: u8 = 0x20;

/// Function name for BSD Fortran. Only the name is significant.
/// To find the address, look in the corresponding external symbol.
///
/// C equivalent: `__define_stab(N_FNAME, 0x22, "FNAME")`
pub(crate) const N_FNAME: u8 = 0x22;

/// Function name or text-segment variable for C. Value is its address.
/// Desc is supposedly the starting line number, but GCC doesn't set it
/// and DBX seems not to miss it.
///
/// C equivalent: `__define_stab(N_FUN, 0x24, "FUN")`
pub(crate) const N_FUN: u8 = 0x24;

/// Data-segment variable with internal linkage. Value is its address.
/// "Static Sym".
///
/// C equivalent: `__define_stab(N_STSYM, 0x26, "STSYM")`
pub(crate) const N_STSYM: u8 = 0x26;

/// BSS-segment variable with internal linkage. Value is its address.
///
/// C equivalent: `__define_stab(N_LCSYM, 0x28, "LCSYM")`
pub(crate) const N_LCSYM: u8 = 0x28;

/// Name of main routine. Only the name is significant.
/// This is not used in C.
///
/// C equivalent: `__define_stab(N_MAIN, 0x2a, "MAIN")`
pub(crate) const N_MAIN: u8 = 0x2a;

/// Global symbol in Pascal.
/// Supposedly the value is its line number.
///
/// C equivalent: `__define_stab(N_PC, 0x30, "PC")`
pub(crate) const N_PC: u8 = 0x30;

/// Number of symbols: 0, files, funcs, lines according to Ultrix V4.0.
///
/// C equivalent: `__define_stab(N_NSYMS, 0x32, "NSYMS")`
pub(crate) const N_NSYMS: u8 = 0x32;

/// "No DST map for sym: name, ,0,type,ignored" according to Ultrix V4.0.
///
/// C equivalent: `__define_stab(N_NOMAP, 0x34, "NOMAP")`
pub(crate) const N_NOMAP: u8 = 0x34;

/// New stab from Solaris. Does not seem to contain useful information.
///
/// C equivalent: `__define_stab(N_OBJ, 0x38, "OBJ")`
pub(crate) const N_OBJ: u8 = 0x38;

/// New stab from Solaris. Possibly related to optimization flags used
/// in this module.
///
/// C equivalent: `__define_stab(N_OPT, 0x3c, "OPT")`
pub(crate) const N_OPT: u8 = 0x3c;

/// Register variable. Value is number of register.
///
/// C equivalent: `__define_stab(N_RSYM, 0x40, "RSYM")`
pub(crate) const N_RSYM: u8 = 0x40;

/// Modula-2 compilation unit.
///
/// C equivalent: `__define_stab(N_M2C, 0x42, "M2C")`
pub(crate) const N_M2C: u8 = 0x42;

/// Line number in text segment. Desc is the line number;
/// value is the corresponding address.
///
/// C equivalent: `__define_stab(N_SLINE, 0x44, "SLINE")`
pub(crate) const N_SLINE: u8 = 0x44;

/// Similar to `N_SLINE`, for the data segment.
///
/// C equivalent: `__define_stab(N_DSLINE, 0x46, "DSLINE")`
pub(crate) const N_DSLINE: u8 = 0x46;

/// Similar to `N_SLINE`, for the bss segment.
///
/// **Note:** This value (0x48) overlaps with `N_BROWS`.
///
/// C equivalent: `__define_stab(N_BSLINE, 0x48, "BSLINE")`
pub(crate) const N_BSLINE: u8 = 0x48;

/// Sun's source-code browser stabs. Field is "path to associated .cb file".
///
/// **Note:** This value (0x48) overlaps with `N_BSLINE`.
///
/// C equivalent: `__define_stab(N_BROWS, 0x48, "BROWS")`
pub(crate) const N_BROWS: u8 = 0x48;

/// GNU Modula-2 definition module dependency. Value is the modification
/// time of the definition file.
///
/// C equivalent: `__define_stab(N_DEFD, 0x4a, "DEFD")`
pub(crate) const N_DEFD: u8 = 0x4a;

/// GNU C++ exception variable. Name is variable name.
///
/// **Note:** This value (0x50) conflicts with `N_MOD2`.
///
/// C equivalent: `__define_stab(N_EHDECL, 0x50, "EHDECL")`
pub(crate) const N_EHDECL: u8 = 0x50;

/// Modula2 info "for imc" according to Ultrix V4.0.
///
/// **Note:** This value (0x50) conflicts with `N_EHDECL`.
///
/// C equivalent: `__define_stab(N_MOD2, 0x50, "MOD2")`
pub(crate) const N_MOD2: u8 = 0x50;

/// GNU C++ `catch` clause. Value is its address. Desc is nonzero if
/// this entry is immediately followed by a CAUGHT stab saying what
/// exception was caught.
///
/// C equivalent: `__define_stab(N_CATCH, 0x54, "CATCH")`
pub(crate) const N_CATCH: u8 = 0x54;

/// Structure or union element. Value is offset in the structure.
///
/// C equivalent: `__define_stab(N_SSYM, 0x60, "SSYM")`
pub(crate) const N_SSYM: u8 = 0x60;

/// Name of main source file.
/// Value is starting text address of the compilation.
///
/// C equivalent: `__define_stab(N_SO, 0x64, "SO")`
pub(crate) const N_SO: u8 = 0x64;

/// Automatic variable in the stack. Value is offset from frame pointer.
/// Also used for type descriptions.
///
/// C equivalent: `__define_stab(N_LSYM, 0x80, "LSYM")`
pub(crate) const N_LSYM: u8 = 0x80;

/// Beginning of an include file. Only Sun uses this.
/// In an object file, only the name is significant.
///
/// C equivalent: `__define_stab(N_BINCL, 0x82, "BINCL")`
pub(crate) const N_BINCL: u8 = 0x82;

/// Name of sub-source file (#include file).
/// Value is starting text address of the compilation.
///
/// C equivalent: `__define_stab(N_SOL, 0x84, "SOL")`
pub(crate) const N_SOL: u8 = 0x84;

/// Parameter variable. Value is offset from argument pointer.
/// (On most machines the argument pointer is the same as the frame pointer.)
///
/// C equivalent: `__define_stab(N_PSYM, 0xa0, "PSYM")`
pub(crate) const N_PSYM: u8 = 0xa0;

/// End of an include file. No name.
/// This and `N_BINCL` act as brackets around the file's output.
///
/// C equivalent: `__define_stab(N_EINCL, 0xa2, "EINCL")`
pub(crate) const N_EINCL: u8 = 0xa2;

/// Alternate entry point. Value is its address.
///
/// C equivalent: `__define_stab(N_ENTRY, 0xa4, "ENTRY")`
pub(crate) const N_ENTRY: u8 = 0xa4;

/// Beginning of lexical block. The desc is the nesting level in lexical
/// blocks. The value is the address of the start of the text for the block.
/// The variables declared inside the block *precede* the `N_LBRAC` symbol.
///
/// C equivalent: `__define_stab(N_LBRAC, 0xc0, "LBRAC")`
pub(crate) const N_LBRAC: u8 = 0xc0;

/// Place holder for deleted include file. Replaces a `N_BINCL` and
/// everything up to the corresponding `N_EINCL`. The Sun linker generates
/// these when it finds multiple identical copies of the symbols from an
/// include file.
///
/// C equivalent: `__define_stab(N_EXCL, 0xc2, "EXCL")`
pub(crate) const N_EXCL: u8 = 0xc2;

/// Modula-2 scope information.
///
/// C equivalent: `__define_stab(N_SCOPE, 0xc4, "SCOPE")`
pub(crate) const N_SCOPE: u8 = 0xc4;

/// End of a lexical block. Desc matches the `N_LBRAC`'s desc.
/// The value is the address of the end of the text for the block.
///
/// C equivalent: `__define_stab(N_RBRAC, 0xe0, "RBRAC")`
pub(crate) const N_RBRAC: u8 = 0xe0;

/// Begin named common block. Only the name is significant.
///
/// C equivalent: `__define_stab(N_BCOMM, 0xe2, "BCOMM")`
pub(crate) const N_BCOMM: u8 = 0xe2;

/// End named common block. Only the name is significant
/// (and it should match the `N_BCOMM`).
///
/// C equivalent: `__define_stab(N_ECOMM, 0xe4, "ECOMM")`
pub(crate) const N_ECOMM: u8 = 0xe4;

/// End common (local name): value is address.
///
/// C equivalent: `__define_stab(N_ECOML, 0xe8, "ECOML")`
pub(crate) const N_ECOML: u8 = 0xe8;

// Gould-system Non-Base register symbols.
// Values assigned historically; may not match real Gould hardware.

/// Gould Non-Base register text symbol.
///
/// C equivalent: `__define_stab(N_NBTEXT, 0xF0, "NBTEXT")`
pub(crate) const N_NBTEXT: u8 = 0xF0;

/// Gould Non-Base register data symbol.
///
/// C equivalent: `__define_stab(N_NBDATA, 0xF2, "NBDATA")`
pub(crate) const N_NBDATA: u8 = 0xF2;

/// Gould Non-Base register BSS symbol.
///
/// C equivalent: `__define_stab(N_NBBSS, 0xF4, "NBBSS")`
pub(crate) const N_NBBSS: u8 = 0xF4;

/// Gould Non-Base register static symbol.
///
/// C equivalent: `__define_stab(N_NBSTS, 0xF6, "NBSTS")`
pub(crate) const N_NBSTS: u8 = 0xF6;

/// Gould Non-Base register local/common symbol.
///
/// C equivalent: `__define_stab(N_NBLCS, 0xF8, "NBLCS")`
pub(crate) const N_NBLCS: u8 = 0xF8;

/// Second symbol entry containing a length-value for the preceding entry.
/// The value is the length.
///
/// C equivalent: `__define_stab(N_LENG, 0xfe, "LENG")`
pub(crate) const N_LENG: u8 = 0xfe;

// =============================================================================
// Nlist struct — BSD/STABS symbol table entry
// =============================================================================

/// BSD/STABS symbol table entry.
///
/// Each stab entry in the `.stab` section has this 12-byte layout.
/// This matches the C `struct nlist` used by STABS debug format.
///
/// # Fields
///
/// | Field     | Size | Description                                      |
/// |-----------|------|--------------------------------------------------|
/// | `n_strx`  | 4    | Index into string table for symbol name           |
/// | `n_type`  | 1    | Symbol type (one of the `N_*` constants above)    |
/// | `n_other` | 1    | Miscellaneous information (usually 0)             |
/// | `n_desc`  | 2    | Description field (line numbers, nesting, etc.)   |
/// | `n_value` | 4    | Value (address, line number, register, etc.)      |
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Nlist {
    /// Index into the `.stabstr` string table for the symbol name.
    pub n_strx: u32,
    /// Type of symbol — one of the `N_*` constants defined in this module.
    pub n_type: u8,
    /// Miscellaneous information (usually 0).
    pub n_other: u8,
    /// Description field. Usage depends on `n_type`:
    /// - For `N_SLINE`: the source line number.
    /// - For `N_LBRAC`/`N_RBRAC`: the lexical block nesting depth.
    /// - For `N_FUN`: the starting line number (sometimes unused).
    pub n_desc: u16,
    /// Value of the symbol. Usage depends on `n_type`:
    /// - For function/variable stabs: the address.
    /// - For `N_SLINE`: the code address for that line.
    /// - For `N_LSYM`/`N_PSYM`: the stack frame offset.
    /// - For `N_RSYM`: the register number.
    pub n_value: u32,
}

/// Size of an `Nlist` entry in bytes (4 + 1 + 1 + 2 + 4 = 12).
///
/// This constant can be used for manual serialization/deserialization
/// of stab entries from raw byte buffers.
pub(crate) const NLIST_SIZE: usize = 12;

// =============================================================================
// String name lookup helper
// =============================================================================

/// Returns the canonical string name of a STABS debug symbol type code.
///
/// This corresponds to the STRING parameter of the original
/// `__define_stab(NAME, CODE, STRING)` macro entries in `stab.def`.
///
/// Returns `"UNKNOWN"` for unrecognized codes.
///
/// # Examples
///
/// ```ignore
/// assert_eq!(stab_name(N_FUN), "FUN");
/// assert_eq!(stab_name(N_SLINE), "SLINE");
/// assert_eq!(stab_name(0xFF), "UNKNOWN");
/// ```
#[inline]
pub(crate) fn stab_name(code: u8) -> &'static str {
    match code {
        N_GSYM => "GSYM",
        N_FNAME => "FNAME",
        N_FUN => "FUN",
        N_STSYM => "STSYM",
        N_LCSYM => "LCSYM",
        N_MAIN => "MAIN",
        N_PC => "PC",
        N_NSYMS => "NSYMS",
        N_NOMAP => "NOMAP",
        N_OBJ => "OBJ",
        N_OPT => "OPT",
        N_RSYM => "RSYM",
        N_M2C => "M2C",
        N_SLINE => "SLINE",
        N_DSLINE => "DSLINE",
        // N_BSLINE and N_BROWS share 0x48. First match wins; prefer BSLINE
        // as the more commonly referenced symbol in STABS debug generation.
        N_BSLINE => "BSLINE",
        N_DEFD => "DEFD",
        // N_EHDECL and N_MOD2 share 0x50. First match wins; prefer EHDECL
        // as the C++ exception symbol is more widely encountered.
        N_EHDECL => "EHDECL",
        N_CATCH => "CATCH",
        N_SSYM => "SSYM",
        N_SO => "SO",
        N_LSYM => "LSYM",
        N_BINCL => "BINCL",
        N_SOL => "SOL",
        N_PSYM => "PSYM",
        N_EINCL => "EINCL",
        N_ENTRY => "ENTRY",
        N_LBRAC => "LBRAC",
        N_EXCL => "EXCL",
        N_SCOPE => "SCOPE",
        N_RBRAC => "RBRAC",
        N_BCOMM => "BCOMM",
        N_ECOMM => "ECOMM",
        N_ECOML => "ECOML",
        N_NBTEXT => "NBTEXT",
        N_NBDATA => "NBDATA",
        N_NBBSS => "NBBSS",
        N_NBSTS => "NBSTS",
        N_NBLCS => "NBLCS",
        N_LENG => "LENG",
        _ => "UNKNOWN",
    }
}

// =============================================================================
// Compile-time assertions
// =============================================================================

// Verify that the Nlist struct has the expected size for binary compatibility.
const _: () = assert!(core::mem::size_of::<Nlist>() == NLIST_SIZE);
