//! Shared type definitions for the TinyCC Rust compiler.
//!
//! This module translates the monolithic `tcc.h` header into Rust types,
//! replacing C structs, unions, bitfields, and `#define` constants with
//! idiomatic Rust equivalents.  Every type here follows the AAP §0.8.1
//! global refactoring rules:
//!
//! - **No raw pointers** — linked structures use `SymId` (= `usize`) indices
//!   or `Option<usize>` for nullable cross-references.
//! - **Owned types** — `Vec<u8>` for data buffers, `String` for names,
//!   `PathBuf` for file paths.
//! - **No `unsafe`** — pure data-structure definitions only.
//! - **Integer safety** — sized integer types (`u8`, `u16`, `u32`, `i32`,
//!   `i64`, `u64`) matching the original C intent.
//!
//! C equivalent: `tcc.h` (2,016 lines — monolithic internal header)

// Shared type definitions — struct fields preserve the original tcc.h naming
// conventions for traceability. Debug impls may omit large/binary fields.
#![allow(clippy::missing_fields_in_debug)]
#![allow(clippy::struct_excessive_bools)]
#![allow(clippy::struct_field_names)]

use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;

use crate::tokens::Token;

// ---------------------------------------------------------------------------
// Symbol identifier type — replaces all raw `Sym *` pointers
// ---------------------------------------------------------------------------

/// Index into a symbol table `Vec<Symbol>`.
///
/// Replaces raw `struct Sym *` pointers throughout the C codebase.
/// AAP §0.8.1: "No raw pointers — all linked structures use indices."
pub type SymId = usize;

// ===========================================================================
//  Core Type Definitions (tcc.h:461-566)
// ===========================================================================

/// Byte-string buffer — replaces C `CString` (tcc.h:461-465).
///
/// In the original C code this is a growable byte buffer used for
/// string concatenation during preprocessing.  The Rust version uses
/// `Vec<u8>` instead of a manually-managed `char *data` + `size` pair.
///
/// C equivalent: `CString` in tcc.h:461-465
#[derive(Debug, Clone, Default)]
pub struct CString {
    /// Raw byte content of the string buffer.
    pub data: Vec<u8>,
    /// Logical size (number of meaningful bytes).  May be less than
    /// `data.len()` when the buffer is over-allocated.
    pub size: usize,
}

/// C type representation.
///
/// C equivalent: `CType` in tcc.h:468-471.
///
/// The `t` field carries a combination of `VT_*` type flags (base type,
/// qualifiers, storage class) packed into a single `i32`.  The `ref_sym`
/// field replaces the raw `struct Sym *ref` pointer with an optional
/// index into the symbol table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CType {
    /// Type flags and base type (`VT_*` constants).
    pub t: i32,
    /// Reference to a symbol for composite/function/pointer types.
    /// `None` when the type is a simple scalar.
    pub ref_sym: Option<SymId>,
}

impl Default for CType {
    fn default() -> Self {
        Self {
            t: VT_INT,
            ref_sym: None,
        }
    }
}

/// Constant value — replaces C `union CValue` (tcc.h:474-484).
///
/// The C code uses a union of `long double`, `double`, `float`, `uint64_t`,
/// and a `{char*, int}` struct.  In Rust this becomes a discriminated enum
/// so the active variant is always known at runtime.
///
/// C equivalent: `CValue` in tcc.h:474-484
#[derive(Debug, Clone, PartialEq)]
pub enum CValue {
    /// Long-double constant.  Rust has no native `long double`; we use `f64`.
    LongDouble(f64),
    /// IEEE 754 double-precision constant.
    Double(f64),
    /// IEEE 754 single-precision constant.
    Float(f32),
    /// Integer constant (covers all C integer widths up to 64 bits).
    Int(u64),
    /// String literal data.
    Str {
        /// Raw byte content (may include embedded NUL bytes for wide strings).
        data: Vec<u8>,
        /// Logical size in bytes.
        size: usize,
    },
}

impl Default for CValue {
    fn default() -> Self {
        Self::Int(0)
    }
}

// ---------------------------------------------------------------------------
// SValue — value on the codegen stack (tcc.h:487-501)
// ---------------------------------------------------------------------------

/// Discriminated data payload for [`SValue`].
///
/// Replaces the anonymous `union { struct { int jtrue, jfalse; }; CValue c; }`
/// in the C `SValue` definition (tcc.h:492-495).
#[derive(Debug, Clone, PartialEq)]
pub enum SValueData {
    /// Forward-jump targets when the value is `VT_JMP` / `VT_JMPI`.
    Jump {
        /// Jump label for the *true* branch.
        jtrue: i32,
        /// Jump label for the *false* branch.
        jfalse: i32,
    },
    /// A compile-time constant value.
    Constant(CValue),
}

impl Default for SValueData {
    fn default() -> Self {
        Self::Constant(CValue::default())
    }
}

/// Symbol-reference or comparison metadata for [`SValue`].
///
/// Replaces the anonymous `union { struct { unsigned short cmp_op, cmp_r; };
/// struct Sym *sym; }` in the C `SValue` (tcc.h:497-499).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SValueSymInfo {
    /// Comparison operation metadata when `r` has `VT_CMP`.
    Cmp {
        /// Comparison opcode.
        cmp_op: u16,
        /// Register holding the comparison result.
        cmp_r: u16,
    },
    /// Optional symbol reference when `r` has `VT_SYM | VT_CONST`.
    Sym(Option<SymId>),
}

impl Default for SValueSymInfo {
    fn default() -> Self {
        Self::Sym(None)
    }
}

/// Value on the codegen stack.
///
/// C equivalent: `SValue` in tcc.h:487-501.
///
/// In the original TCC, a fixed-size array `SValue vstack[VSTACK_SIZE]`
/// is used.  Per AAP §0.4.4 this becomes `Vec<SValue>` in the Rust port,
/// eliminating the fixed upper bound and potential stack overflow.
#[derive(Debug, Clone, PartialEq)]
pub struct SValue {
    /// The C type of this value.
    pub ctype: CType,
    /// Register index + flags (combination of `VT_CONST`, `VT_LOCAL`,
    /// `VT_LVAL`, `VT_SYM`, etc.).
    pub r: u16,
    /// Second register for `long long` values; set to `VT_CONST` when unused.
    pub r2: u16,
    /// Constant value or forward-jump targets.
    pub value: SValueData,
    /// Symbol reference or comparison info.
    pub sym_info: SValueSymInfo,
}

impl Default for SValue {
    fn default() -> Self {
        Self {
            ctype: CType::default(),
            r: VT_CONST,
            r2: VT_CONST,
            value: SValueData::default(),
            sym_info: SValueSymInfo::default(),
        }
    }
}

// ===========================================================================
//  Symbol Attributes (tcc.h:504-529)
// ===========================================================================

/// Symbol attributes — replaces C bitfield struct (tcc.h:504-516).
///
/// Each field corresponds to one bitfield in the original `struct SymAttr`.
/// Boolean fields replace single-bit bitfields; `u8` fields replace
/// multi-bit bitfields.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SymAttr {
    /// Alignment as `log2 + 1` (0 = unspecified).  5 bits in C.
    pub aligned: u8,
    /// `__attribute__((packed))`.
    pub packed: bool,
    /// `__attribute__((weak))`.
    pub weak: bool,
    /// ELF visibility (2 bits: `STV_DEFAULT` / `STV_HIDDEN` / …).
    pub visibility: u8,
    /// `__declspec(dllexport)` (Windows).
    pub dllexport: bool,
    /// Symbol should not be decorated (Windows name mangling).
    pub nodecorate: bool,
    /// `__declspec(dllimport)` (Windows).
    pub dllimport: bool,
    /// Address of symbol has been taken.
    pub addrtaken: bool,
    /// `__attribute__((nodebug))`.
    pub nodebug: bool,
}

/// Function attributes (tcc.h:519-529).
///
/// Stores calling convention, function prototype style, and various
/// `__attribute__` flags that apply specifically to function symbols.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FuncAttr {
    /// Calling convention — 0..6 mapping to `FUNC_CDECL` … `FUNC_THISCALL`.
    pub func_call: u8,
    /// Function prototype type: `FUNC_OLD` / `FUNC_NEW` / `FUNC_ELLIPSIS`.
    pub func_type: u8,
    /// `__attribute__((noreturn))`.
    pub func_noreturn: bool,
    /// `__attribute__((constructor))`.
    pub func_ctor: bool,
    /// `__attribute__((destructor))`.
    pub func_dtor: bool,
    /// Number of PE `__stdcall` arguments.
    pub func_args: u8,
    /// `__attribute__((always_inline))`.
    pub func_alwinl: bool,
}

// ===========================================================================
//  Symbol Table Entry (tcc.h:532-566)
// ===========================================================================

/// Symbol table entry — replaces C `Sym` (tcc.h:532-566).
///
/// The original C struct uses several anonymous unions to overlay fields
/// that are mutually exclusive depending on the symbol kind.  In the Rust
/// version we keep the full set of fields with sensible defaults, avoiding
/// `unsafe` transmutes.
///
/// AAP §0.4.4: "Symbol hash table → `HashMap<String, Symbol>`"
/// AAP §0.8.1: Linked list `next`/`prev_tok` pointers → `Option<SymId>`.
#[derive(Debug, Clone, Default)]
pub struct Symbol {
    /// Symbol token identifier.
    pub v: i64,
    /// Associated register or `VT_CONST` / `VT_LOCAL` + lvalue type.
    pub r: u16,
    /// Symbol attributes (alignment, visibility, DLL flags, …).
    pub attr: SymAttr,
    /// Function attributes (calling convention, noreturn, …).
    pub func_attr: FuncAttr,
    /// Associated number, ELF symbol index, or local variable offset.
    pub c: i32,
    /// Scope level for local symbols, or next-jump label index.
    pub sym_scope: i32,
    /// Next jump label (overlaps with `sym_scope` in C union).
    pub jnext: i32,
    /// Label position (overlaps with `sym_scope` in C union).
    pub jind: i32,
    /// Auxiliary type info for bitfield access (overlaps in C union).
    pub auxtype: i32,
    /// Enum constant value when `IS_ENUM_VAL` (overlaps in C union).
    pub enum_val: i64,
    /// The C type associated with this symbol.
    pub ctype: CType,
    /// Next related symbol (fields, anonymous members).
    pub next: Option<SymId>,
    /// Previous symbol for this token (symbol stack chain).
    pub prev_tok: Option<SymId>,
}

// ===========================================================================
//  ELF Section (tcc.h:569-590)
// ===========================================================================

/// ELF section — data stored as `Vec<u8>`.
///
/// C equivalent: `Section` in tcc.h:569-590.
///
/// Key transformation (AAP §0.4.4):
/// - `unsigned char *data` (raw buffer) → `Vec<u8>` (growable, bounds-checked)
/// - `struct Section *link`/`reloc`/`hash`/`prev` (raw pointers) → `Option<usize>` indices
/// - `char name[1]` (flexible array member) → `String`
#[derive(Debug, Clone)]
pub struct Section {
    /// Section data — growable byte buffer replacing raw `malloc`'d pointer.
    pub data: Vec<u8>,
    /// Current write offset within `data`.
    pub data_offset: usize,
    /// ELF section name string-table index (used during output).
    pub sh_name: u32,
    /// ELF section number.
    pub sh_num: usize,
    /// ELF section type (`SHT_*`).
    pub sh_type: u32,
    /// ELF section flags (`SHF_*`).
    pub sh_flags: u64,
    /// ELF section info field.
    pub sh_info: u32,
    /// ELF section alignment.
    pub sh_addralign: u64,
    /// ELF entry size.
    pub sh_entsize: u64,
    /// Section size (used during output).
    pub sh_size: u64,
    /// Address at which the section is relocated.
    pub sh_addr: u64,
    /// File offset within the output.
    pub sh_offset: u64,
    /// Number of hashed symbols (used to resize hash table).
    pub nb_hashed_syms: i32,
    /// Index of a linked section (e.g. strtab for symtab).
    pub link: Option<usize>,
    /// Index of the corresponding relocation section.
    pub reloc: Option<usize>,
    /// Index of the hash table section for symbols.
    pub hash: Option<usize>,
    /// Previous section on the section stack.
    pub prev: Option<usize>,
    /// Section name (replaces C flexible array member `char name[1]`).
    pub name: String,
}

impl Default for Section {
    fn default() -> Self {
        Self {
            data: Vec::new(),
            data_offset: 0,
            sh_name: 0,
            sh_num: 0,
            sh_type: 0,
            sh_flags: 0,
            sh_info: 0,
            sh_addralign: 1,
            sh_entsize: 0,
            sh_size: 0,
            sh_addr: 0,
            sh_offset: 0,
            nb_hashed_syms: 0,
            link: None,
            reloc: None,
            hash: None,
            prev: None,
            name: String::new(),
        }
    }
}

// ===========================================================================
//  DLL Reference (tcc.h:592-597)
// ===========================================================================

/// Loaded DLL reference — replaces C `DLLReference` (tcc.h:592-597).
///
/// The `void *handle` field from C (dlopen handle) is replaced by `index`
/// which identifies the DLL in a runtime-specific table.
#[derive(Debug, Clone, Default)]
pub struct DllReference {
    /// Nesting level at which this DLL was loaded.
    pub level: i32,
    /// Whether the DLL was actually found/loaded.
    pub found: bool,
    /// Index for runtime handle management.
    pub index: u8,
    /// DLL filename (replaces C flexible array member `char name[1]`).
    pub name: String,
}

// ===========================================================================
//  Source File / Buffered I/O (tcc.h:639-655)
// ===========================================================================

/// Source file with buffered reading.
///
/// C equivalent: `BufferedFile` in tcc.h:639-655.
///
/// AAP §0.4.4: "`BufferedFile` (8192-byte I/O) → `BufReader<File>`"
///
/// The fixed 1024-byte `filename` array becomes `PathBuf`, the manual
/// 8192-byte I/O buffer becomes `BufReader<File>`, and the raw `fd` integer
/// becomes the inner `File` owned by the `BufReader`.
pub struct SourceFile {
    /// Buffered reader wrapping the underlying file descriptor.
    pub reader: BufReader<File>,
    /// Path to the source file.
    pub filename: PathBuf,
    /// Current line number (1-based).
    pub line_num: u32,
    /// Last printed line reference (for `tcc -E`).
    pub line_ref: u32,
    /// Current read position within an internal token buffer.
    pub buf_ptr: usize,
    /// `#ifndef` macro guarding this file (0 if none).
    pub ifndef_macro: i32,
    /// Saved `ifndef_macro` for nested include handling.
    pub ifndef_macro_saved: i32,
    /// `ifdef_stack` depth at the start of this file.
    pub ifdef_stack_ptr: usize,
    /// Next search-path index for `#include_next`.
    pub include_next_index: i32,
    /// Saved `tok_flags` from before this file was opened.
    pub prev_tok_flags: i32,
    /// True filename (not modified by `# line` directives).
    pub true_filename: PathBuf,
}

// SourceFile contains BufReader<File> which does not implement Debug,
// so we provide a manual impl.
impl std::fmt::Debug for SourceFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SourceFile")
            .field("filename", &self.filename)
            .field("line_num", &self.line_num)
            .field("line_ref", &self.line_ref)
            .field("buf_ptr", &self.buf_ptr)
            .field("ifndef_macro", &self.ifndef_macro)
            .field("ifndef_macro_saved", &self.ifndef_macro_saved)
            .field("ifdef_stack_ptr", &self.ifdef_stack_ptr)
            .field("include_next_index", &self.include_next_index)
            .field("prev_tok_flags", &self.prev_tok_flags)
            .field("true_filename", &self.true_filename)
            .finish()
    }
}

// ===========================================================================
//  Token String (tcc.h:661-672)
// ===========================================================================

/// Tokenized macro string — replaces C `TokenString` (tcc.h:661-672).
///
/// In the original C code, tokens are stored as a flat `int *str` array.
/// In Rust we use `Vec<Token>` for type safety.
///
/// CVE-2019-9754 remediation note: the macro stack built from
/// `TokenString` chains uses `Vec<MacroEntry>` in the preprocessor;
/// `Vec::pop()` returns `None` on empty stack, preventing the
/// underflow that caused the original vulnerability.
#[derive(Debug, Clone, Default)]
pub struct TokenString {
    /// Token sequence stored in this string.
    pub tokens: Vec<Token>,
    /// Whether a space is needed before the next appended token.
    pub need_spc: bool,
    /// Line number of the last token added.
    pub last_line_num: i32,
    /// Saved line number for restoring after macro expansion.
    pub save_line_num: i32,
    /// Whether this `TokenString` owns its storage (controls deallocation).
    pub alloc: bool,
}

// ===========================================================================
//  GNUC Attribute Definition (tcc.h:675-683)
// ===========================================================================

/// GNUC attribute definition — replaces C `AttributeDef` (tcc.h:675-683).
///
/// Used during declaration parsing to accumulate attributes from
/// `__attribute__((...))` syntax before they are applied to a symbol.
#[derive(Debug, Clone, Default)]
pub struct AttributeDef {
    /// Symbol attributes (alignment, visibility, etc.).
    pub a: SymAttr,
    /// Function attributes (calling convention, noreturn, etc.).
    pub f: FuncAttr,
    /// Target section index for `__attribute__((section("...")))`.
    pub section: Option<usize>,
    /// Cleanup function symbol for `__attribute__((cleanup(...)))`.
    pub cleanup_func: Option<SymId>,
    /// Alias target token for `__attribute__((alias("...")))`.
    pub alias_target: i32,
    /// Assembly label token for `__asm__("...")` on a declaration.
    pub asm_label: i32,
    /// `__attribute__((__mode__(...)))` value.
    pub attr_mode: i8,
}

// ===========================================================================
//  Cached Include (tcc.h:694-699)
// ===========================================================================

/// Include file cache entry — replaces C `CachedInclude` (tcc.h:694-699).
///
/// Tracks whether a header file is guarded by `#ifndef MACRO` and can
/// be skipped on subsequent inclusions.
///
/// AAP §0.4.4: "`CachedInclude` hash table → `HashMap<PathBuf, CachedInclude>`"
#[derive(Debug, Clone)]
pub struct CachedInclude {
    /// Token of the `#ifndef` guard macro (0 if none).
    pub ifndef_macro: i32,
    /// Whether `#pragma once` was seen.
    pub once: bool,
    /// Hash-chain link for the include cache (-1 if none).
    pub hash_next: i32,
    /// Include path as specified in `#include` (replaces C flexible array).
    pub filename: PathBuf,
}

impl Default for CachedInclude {
    fn default() -> Self {
        Self {
            ifndef_macro: 0,
            once: false,
            hash_next: -1,
            filename: PathBuf::new(),
        }
    }
}

// ===========================================================================
//  Inline Function (tcc.h:686-690)
// ===========================================================================

/// Inline function record — replaces C `InlineFunc` (tcc.h:686-690).
///
/// Inline functions are stored as token lists and compiled only when
/// actually referenced.
#[derive(Debug, Clone, Default)]
pub struct InlineFunc {
    /// Tokenized function body.
    pub func_str: TokenString,
    /// Symbol index of the function.
    pub sym: Option<SymId>,
    /// Filename where the function was defined.
    pub filename: String,
}

// ===========================================================================
//  File Spec (tcc.h:1022-1025)
// ===========================================================================

/// Command-line file specification — replaces C `filespec` (tcc.h:1022-1025).
#[derive(Debug, Clone)]
pub struct FileSpec {
    /// File basename or path.
    pub name: String,
    /// File type code (one of `AFF_TYPE_*` constants).
    pub file_type: u8,
}

impl Default for FileSpec {
    fn default() -> Self {
        Self {
            name: String::new(),
            file_type: AFF_TYPE_NONE,
        }
    }
}

// ===========================================================================
//  Token Symbol (tcc.h:444-453)
// ===========================================================================

/// Token symbol — replaces C `TokenSym` (tcc.h:444-453).
///
/// Each unique identifier/keyword in the source maps to a `TokenSym` entry
/// in the token hash table.
#[derive(Debug, Clone, Default)]
pub struct TokenSym {
    /// Direct pointer to the `#define` symbol for this token.
    pub sym_define: Option<SymId>,
    /// Direct pointer to the label symbol for this token.
    pub sym_label: Option<SymId>,
    /// Direct pointer to the struct/union/enum symbol for this token.
    pub sym_struct: Option<SymId>,
    /// Direct pointer to the identifier symbol for this token.
    pub sym_identifier: Option<SymId>,
    /// Numeric token ID.
    pub tok: i32,
    /// Length of the string representation.
    pub len: usize,
    /// String value of the token (replaces C flexible array `char str[1]`).
    pub str_val: String,
}

// ===========================================================================
//  Assembler Types (tcc.h:704-724)
// ===========================================================================

/// Assembly expression value — replaces C `ExprValue` (tcc.h:704-708).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ExprValue {
    /// Numeric value of the expression.
    pub v: u64,
    /// Optional associated symbol.
    pub sym: Option<SymId>,
    /// Whether the value is PC-relative.
    pub pcrel: i32,
}

/// Assembly operand — replaces C `ASMOperand` (tcc.h:711-724).
///
/// Stores the parsed representation of one inline-assembly operand
/// including its constraint string, allocated register, and flags.
#[derive(Debug, Clone)]
pub struct ASMOperand {
    /// GCC 3 optional identifier (0 if number-only).
    pub id: i32,
    /// Constraint string (e.g. `"=r"`, `"+m"`).
    pub constraint: String,
    /// Computed assembly string for this operand.
    pub asm_str: String,
    /// Index into the value stack for the C expression.
    pub vt: Option<usize>,
    /// If ≥ 0, reference to an output constraint.
    pub ref_index: i32,
    /// If ≥ 0, reference to an input constraint.
    pub input_index: i32,
    /// Priority used for register allocation.
    pub priority: i32,
    /// Assigned register number (-1 if unassigned).
    pub reg: i32,
    /// `true` if the value occupies two registers (long long).
    pub is_llong: bool,
    /// `true` if this is a memory operand.
    pub is_memory: bool,
    /// `true` for `'+'` read-write modifier.
    pub is_rw: bool,
    /// `true` for `asm goto` label operand.
    pub is_label: bool,
}

impl Default for ASMOperand {
    fn default() -> Self {
        Self {
            id: 0,
            constraint: String::new(),
            asm_str: String::new(),
            vt: None,
            ref_index: -1,
            input_index: -1,
            priority: 0,
            reg: -1,
            is_llong: false,
            is_memory: false,
            is_rw: false,
            is_label: false,
        }
    }
}

// ===========================================================================
//  Extra Symbol Attributes (tcc.h:728-736)
// ===========================================================================

/// Extra symbol attributes (not stored in the main symbol table).
///
/// C equivalent: `struct sym_attr` in tcc.h:728-736.
///
/// These are indexed separately from `Symbol` and hold GOT/PLT offsets
/// for the ELF linker.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SymAttrExt {
    /// Offset into the GOT section.
    pub got_offset: u32,
    /// Offset into the PLT section.
    pub plt_offset: u32,
    /// PLT symbol index.
    pub plt_sym: i32,
    /// Dynamic symbol table index.
    pub dyn_index: i32,
}

// ===========================================================================
//  STABS Debug Symbol (tcc.h:1534-1540)
// ===========================================================================

/// STABS debug symbol entry — replaces C `Stab_Sym` (tcc.h:1534-1540).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StabSym {
    /// Index into the string table for the symbol name.
    pub n_strx: u32,
    /// Symbol type.
    pub n_type: u8,
    /// Miscellaneous info (usually empty).
    pub n_other: u8,
    /// Description field.
    pub n_desc: u16,
    /// Symbol value (address).
    pub n_value: u32,
}


// ===========================================================================
//  VT_* Value Location Constants (tcc.h:1028-1044)
// ===========================================================================

/// Mask for value location -- register index or special codes.
///
/// C equivalent: `#define VT_VALMASK 0x003f` (tcc.h:1028)
pub const VT_VALMASK: u16 = 0x003f;

/// Constant value stored in `SValue::value`.
///
/// C equivalent: `#define VT_CONST 0x0030` (tcc.h:1029)
pub const VT_CONST: u16 = 0x0030;

/// Lvalue with offset on stack.
///
/// C equivalent: `#define VT_LLOCAL 0x0031` (tcc.h:1030)
pub const VT_LLOCAL: u16 = 0x0031;

/// Offset on stack (local variable).
///
/// C equivalent: `#define VT_LOCAL 0x0032` (tcc.h:1031)
pub const VT_LOCAL: u16 = 0x0032;

/// Value stored in processor flags (comparison result).
///
/// C equivalent: `#define VT_CMP 0x0033` (tcc.h:1032)
pub const VT_CMP: u16 = 0x0033;

/// Value is the consequence of a forward jump (true branch, even).
///
/// C equivalent: `#define VT_JMP 0x0034` (tcc.h:1033)
pub const VT_JMP: u16 = 0x0034;

/// Value is the consequence of a forward jump (false branch, odd).
///
/// C equivalent: `#define VT_JMPI 0x0035` (tcc.h:1034)
pub const VT_JMPI: u16 = 0x0035;

/// Variable is an lvalue.
///
/// C equivalent: `#define VT_LVAL 0x0100` (tcc.h:1035)
pub const VT_LVAL: u16 = 0x0100;

/// A symbol value is added.
///
/// C equivalent: `#define VT_SYM 0x0200` (tcc.h:1036)
pub const VT_SYM: u16 = 0x0200;

/// Value must be cast to be correct (char/short stored in int registers).
///
/// C equivalent: `#define VT_MUSTCAST 0x0C00` (tcc.h:1037-1038)
pub const VT_MUSTCAST: u16 = 0x0C00;

/// `VT_CONST` but not a (C standard) integer constant expression.
///
/// C equivalent: `#define VT_NONCONST 0x1000` (tcc.h:1039-1040)
pub const VT_NONCONST: u16 = 0x1000;

/// Bound checking must be done before dereferencing.
///
/// C equivalent: `#define VT_MUSTBOUND 0x4000` (tcc.h:1041-1042)
pub const VT_MUSTBOUND: u16 = 0x4000;

/// Value is bounded -- bounding function call address is in vc.
///
/// C equivalent: `#define VT_BOUNDED 0x8000` (tcc.h:1043-1044)
pub const VT_BOUNDED: u16 = 0x8000;

// ===========================================================================
//  VT_* Base Type Constants (tcc.h:1046-1060)
// ===========================================================================

/// Mask for base type.
pub const VT_BTYPE: i32 = 0x000f;
/// `void` type.
pub const VT_VOID: i32 = 0;
/// Signed byte type (`char`).
pub const VT_BYTE: i32 = 1;
/// `short` type.
pub const VT_SHORT: i32 = 2;
/// `int` type.
pub const VT_INT: i32 = 3;
/// 64-bit integer (`long long`).
pub const VT_LLONG: i32 = 4;
/// Pointer type.
pub const VT_PTR: i32 = 5;
/// Function type.
pub const VT_FUNC: i32 = 6;
/// `struct` / `union` definition.
pub const VT_STRUCT: i32 = 7;
/// IEEE `float`.
pub const VT_FLOAT: i32 = 8;
/// IEEE `double`.
pub const VT_DOUBLE: i32 = 9;
/// IEEE `long double`.
pub const VT_LDOUBLE: i32 = 10;
/// `_Bool` type (C99).
pub const VT_BOOL: i32 = 11;
/// 128-bit integer (x86-64 ABI only).
pub const VT_QLONG: i32 = 13;
/// 128-bit float (x86-64 ABI only).
pub const VT_QFLOAT: i32 = 14;

// ===========================================================================
//  VT_* Type Modifier Constants (tcc.h:1062-1069)
// ===========================================================================

/// `unsigned` modifier.
pub const VT_UNSIGNED: i32 = 0x0010;
/// Explicitly signed or unsigned.
pub const VT_DEFSIGN: i32 = 0x0020;
/// Array type (also has `VT_PTR`).
pub const VT_ARRAY: i32 = 0x0040;
/// Bitfield modifier.
pub const VT_BITFIELD: i32 = 0x0080;
/// `const` qualifier.
pub const VT_CONSTANT: i32 = 0x0100;
/// `volatile` qualifier.
pub const VT_VOLATILE: i32 = 0x0200;
/// Variable-length array (also has `VT_PTR` and `VT_ARRAY`).
pub const VT_VLA: i32 = 0x0400;
/// `long` type modifier.
pub const VT_LONG: i32 = 0x0800;

// ===========================================================================
//  VT_* Storage Class Constants (tcc.h:1072-1075)
// ===========================================================================

/// `extern` definition.
pub const VT_EXTERN: i32 = 0x0000_1000;
/// `static` variable.
pub const VT_STATIC: i32 = 0x0000_2000;
/// `typedef` definition.
pub const VT_TYPEDEF: i32 = 0x0000_4000;
/// `inline` definition.
pub const VT_INLINE: i32 = 0x0000_8000;

// ===========================================================================
//  VT_* Struct/Bitfield Layout Constants (tcc.h:1078-1095)
// ===========================================================================

/// Bit shift for bitfield position/size encoding.
pub const VT_STRUCT_SHIFT: i32 = 20;
/// Mask covering bitfield position and size bits.
pub const VT_STRUCT_MASK: i32 = (((1_i32 << 12) - 1) << VT_STRUCT_SHIFT) | VT_BITFIELD;
/// `union` type tag (combined with `VT_STRUCT`).
pub const VT_UNION: i32 = (1 << VT_STRUCT_SHIFT) | VT_STRUCT;
/// Enum type tag.
pub const VT_ENUM: i32 = 2 << VT_STRUCT_SHIFT;
/// Enum-constant value tag.
pub const VT_ENUM_VAL: i32 = 3 << VT_STRUCT_SHIFT;
/// `_Atomic` qualifier — aliased to `VT_VOLATILE` in TCC.
pub const VT_ATOMIC: i32 = VT_VOLATILE;
/// Storage class mask.
pub const VT_STORAGE: i32 = VT_EXTERN | VT_STATIC | VT_TYPEDEF | VT_INLINE;
/// Type mask (everything except storage and struct layout).
pub const VT_TYPE: i32 = !(VT_STORAGE | VT_STRUCT_MASK);

// ===========================================================================
//  Symbol Namespace Constants (tcc.h:601-603)
// ===========================================================================

/// Struct/union/enum symbol-space flag.
pub const SYM_STRUCT: i32 = 0x4000_0000;
/// Struct/union field symbol-space flag.
pub const SYM_FIELD: i32 = 0x2000_0000;
/// First anonymous symbol identifier.
pub const SYM_FIRST_ANOM: i32 = 0x1000_0000;

// ===========================================================================
//  Function Type / Calling Convention Constants (tcc.h:606-617)
// ===========================================================================

/// Standard C calling convention (`cdecl`).
pub const FUNC_CDECL: u8 = 0;
/// Pascal calling convention (`stdcall`).
pub const FUNC_STDCALL: u8 = 1;
/// First parameter in `%eax`.
pub const FUNC_FASTCALL1: u8 = 2;
/// First two parameters in `%eax`, `%edx`.
pub const FUNC_FASTCALL2: u8 = 3;
/// First three parameters in `%eax`, `%edx`, `%ecx`.
pub const FUNC_FASTCALL3: u8 = 4;
/// First parameter in `%ecx`, `%edx` (Windows fastcall variant).
pub const FUNC_FASTCALLW: u8 = 5;
/// `this` pointer in `%ecx` (thiscall).
pub const FUNC_THISCALL: u8 = 6;
/// ANSI function prototype.
pub const FUNC_NEW: u8 = 1;
/// Old-style (K&R) function prototype.
pub const FUNC_OLD: u8 = 2;
/// ANSI function prototype with `...` (variadic).
pub const FUNC_ELLIPSIS: u8 = 3;

// ===========================================================================
//  Macro Type Constants (tcc.h:620-622)
// ===========================================================================

/// Object-like macro.
pub const MACRO_OBJ: i32 = 0;
/// Function-like macro.
pub const MACRO_FUNC: i32 = 1;
/// Macro uses `##` (token pasting).
pub const MACRO_JOIN: i32 = 2;

// ===========================================================================
//  Label State Constants (tcc.h:625-629)
// ===========================================================================

/// Label is defined.
pub const LABEL_DEFINED: i32 = 0;
/// Label is forward-defined (not yet seen).
pub const LABEL_FORWARD: i32 = 1;
/// Label is declared but never used.
pub const LABEL_DECLARED: i32 = 2;
/// Label is out of scope but not yet popped (statement expressions).
pub const LABEL_GONE: i32 = 3;

// ===========================================================================
//  Type Declaration Mode Constants (tcc.h:632-635)
// ===========================================================================

/// Abstract type (without variable).
pub const TYPE_ABSTRACT: i32 = 1;
/// Direct type (with variable).
pub const TYPE_DIRECT: i32 = 2;
/// Type declares a function parameter.
pub const TYPE_PARAM: i32 = 4;
/// Nested call to `post_type`.
pub const TYPE_NEST: i32 = 8;

// ===========================================================================
//  Stack / Buffer Size Constants (tcc.h:432-441)
// ===========================================================================

/// Maximum depth of the `#include` stack.
pub const INCLUDE_STACK_SIZE: usize = 32;
/// Maximum depth of the `#ifdef` / `#ifndef` stack.
pub const IFDEF_STACK_SIZE: usize = 64;
/// Size of the codegen value stack.
pub const VSTACK_SIZE: usize = 512;
/// I/O buffer size (now `BufReader` capacity hint).
pub const IO_BUF_SIZE: usize = 8192;
/// Token hash table size (must be a power of two).
pub const TOK_HASH_SIZE: usize = 16384;
/// Maximum number of inline-assembly operands.
pub const MAX_ASM_OPERANDS: usize = 30;

// ===========================================================================
//  AFF_* File Type / Flags Constants (tcc.h:1279-1298)
// ===========================================================================

/// No file type specified.
pub const AFF_TYPE_NONE: u8 = 0;
/// C source file.
pub const AFF_TYPE_C: u8 = 1;
/// Assembly file.
pub const AFF_TYPE_ASM: u8 = 2;
/// Assembly file with preprocessing.
pub const AFF_TYPE_ASMPP: u8 = 4;
/// Library file.
pub const AFF_TYPE_LIB: u8 = 8;
/// Binary file.
pub const AFF_TYPE_BIN: u8 = 0x40;
/// File type mask (includes `AFF_TYPE_BIN`).
pub const AFF_TYPE_MASK: u8 = 7 | AFF_TYPE_BIN;
/// Print error if file not found.
pub const AFF_PRINT_ERROR: u8 = 0x10;
/// Load a referenced DLL from another DLL.
pub const AFF_REFERENCED_DLL: u8 = 0x20;
/// Load all objects from archive.
pub const AFF_WHOLE_ARCHIVE: u8 = 0x80;
/// Relocatable object file.
pub const AFF_BINTYPE_REL: u8 = 1;
/// Dynamic shared object.
pub const AFF_BINTYPE_DYN: u8 = 2;
/// Archive file.
pub const AFF_BINTYPE_AR: u8 = 3;
/// C67 COFF object.
pub const AFF_BINTYPE_C67: u8 = 4;

/// Return value: file not found.
pub const FILE_NOT_FOUND: i32 = -2;
/// Return value: file type not recognized.
pub const FILE_NOT_RECOGNIZED: i32 = -3;

// ===========================================================================
//  TOK_FLAG_* / PARSE_FLAG_* Constants (tcc.h:1348-1360)
// ===========================================================================

/// Token is at the beginning of a line.
pub const TOK_FLAG_BOL: i32 = 0x0001;
/// Token is at the beginning of the file.
pub const TOK_FLAG_BOF: i32 = 0x0002;
/// An `#endif` was found matching the starting `#ifdef`.
pub const TOK_FLAG_ENDIF: i32 = 0x0004;

/// Activate preprocessing.
pub const PARSE_FLAG_PREPROCESS: i32 = 0x0001;
/// Return numbers instead of `TOK_PPNUM`.
pub const PARSE_FLAG_TOK_NUM: i32 = 0x0002;
/// Return line feed as a token (also at EOF).
pub const PARSE_FLAG_LINEFEED: i32 = 0x0004;
/// Processing an assembly file (`#` used for line comment).
pub const PARSE_FLAG_ASM_FILE: i32 = 0x0008;
/// `next()` returns space tokens (for `-E` mode).
pub const PARSE_FLAG_SPACES: i32 = 0x0010;
/// `next()` returns `'\\'` stray token.
pub const PARSE_FLAG_ACCEPT_STRAYS: i32 = 0x0020;
/// Return parsed strings instead of `TOK_PPSTR`.
pub const PARSE_FLAG_TOK_STR: i32 = 0x0040;

// ===========================================================================
//  TCC_OUTPUT_* Constants (libtcc.h:68-72, tcc.h:1527-1529)
// ===========================================================================

/// Output will be run in memory.
pub const TCC_OUTPUT_MEMORY: i32 = 1;
/// Executable file output.
pub const TCC_OUTPUT_EXE: i32 = 2;
/// Object file output.
pub const TCC_OUTPUT_OBJ: i32 = 3;
/// Dynamic library output.
pub const TCC_OUTPUT_DLL: i32 = 4;
/// Preprocess only.
pub const TCC_OUTPUT_PREPROCESS: i32 = 5;

/// Compiler output type — specifies what the compiler should produce.
///
/// C equivalent: `TCC_OUTPUT_MEMORY` / `TCC_OUTPUT_EXE` / `TCC_OUTPUT_OBJ` /
/// `TCC_OUTPUT_DLL` / `TCC_OUTPUT_PREPROCESS` constants from `libtcc.h:68-72`.
///
/// Used by [`TccContext::set_output_type()`](crate) to configure the
/// compilation pipeline before adding files.
///
/// AAP §0.8.5: Required enum type for the `TccContext::set_output_type()` method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OutputType {
    /// Compile and run in memory (default).
    /// C equivalent: `TCC_OUTPUT_MEMORY` (value 1).
    Memory = 1,
    /// Generate a native executable.
    /// C equivalent: `TCC_OUTPUT_EXE` (value 2).
    Exe = 2,
    /// Generate a relocatable object file (`.o`).
    /// C equivalent: `TCC_OUTPUT_OBJ` (value 3).
    Obj = 3,
    /// Generate a dynamic shared library (`.so` / `.dll` / `.dylib`).
    /// C equivalent: `TCC_OUTPUT_DLL` (value 4).
    Dll = 4,
    /// Preprocess only — emit preprocessed source to stdout.
    /// C equivalent: `TCC_OUTPUT_PREPROCESS` (value 5).
    Preprocess = 5,
}

impl OutputType {
    /// Returns the integer constant matching the C `TCC_OUTPUT_*` value.
    pub const fn as_i32(self) -> i32 {
        self as i32
    }
}

impl TryFrom<i32> for OutputType {
    type Error = crate::error::TccError;

    /// Convert from a C-style `TCC_OUTPUT_*` integer constant.
    ///
    /// Returns `Err(TccError::UnsupportedTarget)` for values outside the
    /// valid range `1..=5`.
    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            TCC_OUTPUT_MEMORY => Ok(Self::Memory),
            TCC_OUTPUT_EXE => Ok(Self::Exe),
            TCC_OUTPUT_OBJ => Ok(Self::Obj),
            TCC_OUTPUT_DLL => Ok(Self::Dll),
            TCC_OUTPUT_PREPROCESS => Ok(Self::Preprocess),
            _ => Err(crate::error::TccError::UnsupportedTarget(
                format!("invalid output type: {value}"),
            )),
        }
    }
}

impl std::fmt::Display for OutputType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Memory => write!(f, "memory"),
            Self::Exe => write!(f, "exe"),
            Self::Obj => write!(f, "obj"),
            Self::Dll => write!(f, "dll"),
            Self::Preprocess => write!(f, "preprocess"),
        }
    }
}

/// ELF output format (default).
pub const TCC_OUTPUT_FORMAT_ELF: i32 = 0;
/// Binary image output format.
pub const TCC_OUTPUT_FORMAT_BINARY: i32 = 1;
/// COFF output format.
pub const TCC_OUTPUT_FORMAT_COFF: i32 = 2;

/// Output file format — specifies the binary format for the generated output.
///
/// C equivalent: `TCC_OUTPUT_FORMAT_ELF` / `TCC_OUTPUT_FORMAT_BINARY` /
/// `TCC_OUTPUT_FORMAT_COFF` constants from `tcc.h:1527-1529`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OutputFormat {
    /// ELF output format (default on Unix-like systems).
    /// C equivalent: `TCC_OUTPUT_FORMAT_ELF` (value 0).
    Elf = 0,
    /// Raw binary image output format.
    /// C equivalent: `TCC_OUTPUT_FORMAT_BINARY` (value 1).
    Binary = 1,
    /// COFF output format (used by C67 target).
    /// C equivalent: `TCC_OUTPUT_FORMAT_COFF` (value 2).
    Coff = 2,
}

impl OutputFormat {
    /// Returns the integer constant matching the C `TCC_OUTPUT_FORMAT_*` value.
    pub const fn as_i32(self) -> i32 {
        self as i32
    }
}

impl TryFrom<i32> for OutputFormat {
    type Error = crate::error::TccError;

    /// Convert from a C-style `TCC_OUTPUT_FORMAT_*` integer constant.
    ///
    /// Returns `Err(TccError::UnsupportedTarget)` for values outside the
    /// valid range `0..=2`.
    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            TCC_OUTPUT_FORMAT_ELF => Ok(Self::Elf),
            TCC_OUTPUT_FORMAT_BINARY => Ok(Self::Binary),
            TCC_OUTPUT_FORMAT_COFF => Ok(Self::Coff),
            _ => Err(crate::error::TccError::UnsupportedTarget(
                format!("invalid output format: {value}"),
            )),
        }
    }
}

impl std::fmt::Display for OutputFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Elf => write!(f, "elf"),
            Self::Binary => write!(f, "binary"),
            Self::Coff => write!(f, "coff"),
        }
    }
}

