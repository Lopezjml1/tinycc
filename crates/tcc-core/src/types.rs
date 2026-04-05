// Copyright (c) TinyCC contributors. LGPL licensed.
// Ported from tcc.h to Rust as part of the TCC C-to-Rust migration.
//
//! Core type definitions for the TCC compiler.
//!
//! This module defines the fundamental data structures and constants shared
//! across all compiler modules. Ported from `tcc.h` (2,016 lines).
//!
//! Design decisions:
//! - **PORT-01**: All types use explicit fixed-width Rust types (`i32`, `u64`, `f64`, etc.).
//!   No implicit `int` assumptions — everything is explicitly sized.
//! - **PORT-02**: `usize` is used for sizes and offsets instead of C `int`.
//! - **PORT-03**: `f64` is used for `long double` on most targets (IEEE 754).
//!   Documented limitation for exotic FP formats.
//! - **BUG-07**: `Display` trait for `CType` correctly renders function pointer syntax
//!   with proper parenthesization.

use std::ffi::c_void;
use std::fmt;

// ---------------------------------------------------------------------------
// Basic type flag constants (stored in CType.t lower bits)
// From tcc.h lines 1046-1069
// ---------------------------------------------------------------------------

/// Void type — no value.
pub const VT_VOID: i32 = 0;
/// Signed byte (int8_t).
pub const VT_BYTE: i32 = 1;
/// Short integer.
pub const VT_SHORT: i32 = 2;
/// Integer (default C `int`).
pub const VT_INT: i32 = 3;
/// Long long (int64_t).
pub const VT_LLONG: i32 = 4;
/// Pointer type.
pub const VT_PTR: i32 = 5;
/// Function type.
pub const VT_FUNC: i32 = 6;
/// Struct or union type.
pub const VT_STRUCT: i32 = 7;
/// Float type.
pub const VT_FLOAT: i32 = 8;
/// Double type.
pub const VT_DOUBLE: i32 = 9;
/// Long double type (uses f64 — see PORT-03).
pub const VT_LDOUBLE: i32 = 10;
/// C99 `_Bool` type.
pub const VT_BOOL: i32 = 11;
/// 128-bit integer (__int128).
pub const VT_QLONG: i32 = 13;
/// 128-bit float (long double on x86_64 with 80-bit extended).
pub const VT_QFLOAT: i32 = 14;

/// Mask for extracting basic type from CType.t.
pub const VT_BTYPE: i32 = 0x000f;
/// Unsigned type modifier.
pub const VT_UNSIGNED: i32 = 0x0010;
/// Default signedness specified.
pub const VT_DEFSIGN: i32 = 0x0020;
/// Array type modifier.
pub const VT_ARRAY: i32 = 0x0040;
/// Bitfield modifier.
pub const VT_BITFIELD: i32 = 0x0080;
/// `const` qualifier.
pub const VT_CONSTANT: i32 = 0x0100;
/// `volatile` qualifier.
pub const VT_VOLATILE: i32 = 0x0200;
/// Variable Length Array.
pub const VT_VLA: i32 = 0x0400;
/// `long` type modifier.
pub const VT_LONG: i32 = 0x0800;
/// C11 `_Atomic` qualifier (mapped to volatile semantics in TCC).
pub const VT_ATOMIC: i32 = VT_VOLATILE;

// ---------------------------------------------------------------------------
// Storage class constants (stored in CType.t upper bits)
// From tcc.h lines 1072-1075
// ---------------------------------------------------------------------------

/// `extern` storage class.
pub const VT_EXTERN: i32 = 0x0000_1000;
/// `static` storage class.
pub const VT_STATIC: i32 = 0x0000_2000;
/// `typedef` storage class.
pub const VT_TYPEDEF: i32 = 0x0000_4000;
/// `inline` function specifier.
pub const VT_INLINE: i32 = 0x0000_8000;

/// C99 `_Complex` type modifier (FEAT-04).
///
/// Applied in combination with `VT_FLOAT`, `VT_DOUBLE`, or `VT_LDOUBLE` to
/// represent `_Complex float`, `_Complex double`, or `_Complex long double`.
/// Bit 16 is chosen because bits 0–15 are occupied by base-type, sign,
/// array, bitfield, const, volatile, VLA, long, extern, static, typedef,
/// and inline flags, while bit 20+ is reserved for struct/union/enum
/// encoding.  Bit 16 sits in the available gap.
pub const VT_COMPLEX: i32 = 0x0001_0000;

// ---------------------------------------------------------------------------
// Struct/union/enum bitfield encoding in CType.t
// From tcc.h lines 1078-1085
// ---------------------------------------------------------------------------

/// Bit position where struct/union/enum tag info starts.
pub const VT_STRUCT_SHIFT: i32 = 20;
/// Mask for struct/union/enum encoding: `(((1 << 12) - 1) << 20) | VT_BITFIELD`.
/// Equals 0xFFF00080 interpreted as i32.
pub const VT_STRUCT_MASK: i32 = ((((1u32 << 12) - 1) << 20) | VT_BITFIELD as u32) as i32;
/// Union type: `(1 << VT_STRUCT_SHIFT) | VT_STRUCT`.
pub const VT_UNION: i32 = (1 << VT_STRUCT_SHIFT) | VT_STRUCT;
/// Enum type: `2 << VT_STRUCT_SHIFT`.
pub const VT_ENUM: i32 = 2 << VT_STRUCT_SHIFT;
/// Enum constant value: `3 << VT_STRUCT_SHIFT`.
pub const VT_ENUM_VAL: i32 = 3 << VT_STRUCT_SHIFT;

// ---------------------------------------------------------------------------
// Derived type masks
// From tcc.h lines 1094-1095
// ---------------------------------------------------------------------------

/// Mask for all storage class specifiers.
pub const VT_STORAGE: i32 = VT_EXTERN | VT_STATIC | VT_TYPEDEF | VT_INLINE;
/// Mask for the type portion of CType.t (everything except storage and struct encoding).
pub const VT_TYPE: i32 = !(VT_STORAGE | VT_STRUCT_MASK);

// ---------------------------------------------------------------------------
// Assembler symbol type constants
// From tcc.h lines ~1086-1087
// ---------------------------------------------------------------------------

/// Symbol generated by the assembler.
pub const VT_ASM: i32 = 0x0080_0000;
/// Assembler-generated function symbol (e.g., from inline asm labels).
pub const VT_ASM_FUNC: i32 = 0x0100_0000;

// ---------------------------------------------------------------------------
// Type query helper functions
// Equivalent to C macros: IS_ENUM, IS_UNION, BIT_POS, BIT_SIZE, etc.
// From tcc.h lines ~600-650
// ---------------------------------------------------------------------------

/// Returns `true` if the CType flags `t` represent a union type.
///
/// In TCC, union types have `btype == VT_STRUCT` (7) with the union tag
/// bit set at `VT_STRUCT_SHIFT` (bit 20). This function extracts only
/// the tag bits above `VT_STRUCT_SHIFT` and checks for the union marker.
///
/// # BUG-07 Fix
/// The previous implementation compared masked bits against `VT_UNION`
/// directly, but `VT_UNION` includes `VT_STRUCT` in its low bits, causing
/// the comparison to always fail. This function correctly isolates the tag bits.
#[inline]
pub fn is_union(t: i32) -> bool {
    // VT_UNION = (1 << VT_STRUCT_SHIFT) | VT_STRUCT
    // Extract the tag bits above VT_STRUCT_SHIFT: for union, tag = 1
    let tag = (t >> VT_STRUCT_SHIFT) & 0xFFF;
    let union_tag = (VT_UNION >> VT_STRUCT_SHIFT) & 0xFFF; // == 1
    (t & VT_BTYPE) == VT_STRUCT && tag == union_tag
}

/// Returns `true` if the CType flags `t` represent an enum type.
///
/// In TCC, enum types have `btype == VT_INT` (3) — NOT `VT_STRUCT` (7) —
/// with the enum tag encoded in bits above `VT_STRUCT_SHIFT`.
/// `VT_ENUM = 2 << VT_STRUCT_SHIFT`.
///
/// # BUG-07 Fix
/// The previous implementation only checked for enums inside the `VT_STRUCT`
/// match arm, which is unreachable for enum types (btype is VT_INT, not VT_STRUCT).
/// This function correctly checks the tag bits regardless of btype.
#[inline]
pub fn is_enum(t: i32) -> bool {
    let tag = (t >> VT_STRUCT_SHIFT) & 0xFFF;
    let enum_tag = (VT_ENUM >> VT_STRUCT_SHIFT) & 0xFFF; // == 2
    tag == enum_tag
}

/// Returns `true` if the CType flags `t` represent an enum constant value.
///
/// Enum constant values use `VT_ENUM_VAL = 3 << VT_STRUCT_SHIFT`.
#[inline]
pub fn is_enum_val(t: i32) -> bool {
    let tag = (t >> VT_STRUCT_SHIFT) & 0xFFF;
    let enum_val_tag = (VT_ENUM_VAL >> VT_STRUCT_SHIFT) & 0xFFF; // == 3
    tag == enum_val_tag
}

/// Extracts the bit-field position from a CType.t value.
///
/// Bitfield position is encoded in bits 20..32 (shifted by `VT_STRUCT_SHIFT`)
/// when `VT_BITFIELD` is set. Returns the position in bits.
/// Equivalent to C macro `BIT_POS(t)`.
#[inline]
pub fn bit_pos(t: i32) -> i32 {
    (t >> VT_STRUCT_SHIFT) & 0x3f
}

/// Extracts the bit-field size from a CType.t value.
///
/// Bitfield size is encoded in bits 26..32 when `VT_BITFIELD` is set.
/// Returns the size in bits.
/// Equivalent to C macro `BIT_SIZE(t)`.
#[inline]
pub fn bit_size(t: i32) -> i32 {
    (t >> (VT_STRUCT_SHIFT + 6)) & 0x3f
}

/// Constructs a bitfield value encoding from position and size.
/// Equivalent to C macro `BFVAL(s, n)`.
#[inline]
pub fn bfval(pos: i32, size: i32) -> i32 {
    ((pos & 0x3f) | ((size & 0x3f) << 6)) << VT_STRUCT_SHIFT
}

/// Extracts the lower sub-field from a bitfield-encoded value.
/// Equivalent to C macro `BFGET(t, s)` — extracts bits `s..s+6`.
#[inline]
pub fn bfget(t: i32, shift: i32) -> i32 {
    (t >> (VT_STRUCT_SHIFT + shift)) & 0x3f
}

/// Sets a sub-field within a bitfield-encoded value.
/// Equivalent to C macro `BFSET(t, s, v)`.
#[inline]
pub fn bfset(t: i32, shift: i32, val: i32) -> i32 {
    let mask = 0x3f << (VT_STRUCT_SHIFT + shift);
    (t & !mask) | ((val & 0x3f) << (VT_STRUCT_SHIFT + shift))
}

// ---------------------------------------------------------------------------
// OutputType — Compiler output mode
// From libtcc.h: TCC_OUTPUT_MEMORY, TCC_OUTPUT_EXE, TCC_OUTPUT_OBJ,
//               TCC_OUTPUT_DLL, TCC_OUTPUT_PREPROCESS
// ---------------------------------------------------------------------------

/// The type of output the compiler should produce.
///
/// Maps directly to the `TCC_OUTPUT_*` constants defined in `libtcc.h`.
/// Used by `TCCState` to determine the compilation mode, and by the
/// `tcc_set_output_type()` API function.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum OutputType {
    /// Compile and run in memory (for `tcc -run` or `tcc_run()` API).
    Memory = 1,
    /// Produce an executable binary.
    Exe = 2,
    /// Produce a relocatable object file (`.o`).
    Obj = 3,
    /// Produce a shared library / DLL (`.so` / `.dll`).
    Dll = 4,
    /// Run preprocessor only (for `tcc -E`).
    Preprocess = 5,
}

impl OutputType {
    /// Converts an integer to an `OutputType`, returning `None` for invalid values.
    pub fn from_i32(value: i32) -> Option<OutputType> {
        match value {
            1 => Some(OutputType::Memory),
            2 => Some(OutputType::Exe),
            3 => Some(OutputType::Obj),
            4 => Some(OutputType::Dll),
            5 => Some(OutputType::Preprocess),
            _ => None,
        }
    }
}

impl From<OutputType> for i32 {
    fn from(ot: OutputType) -> i32 {
        ot as i32
    }
}

impl TryFrom<i32> for OutputType {
    type Error = ();
    fn try_from(value: i32) -> Result<Self, Self::Error> {
        OutputType::from_i32(value).ok_or(())
    }
}

// ---------------------------------------------------------------------------
// Value location / register flag constants (stored in SValue.r)
// From tcc.h lines 1028-1044
// These are i32 for consistency; cast to u16 when storing into SValue.r.
// ---------------------------------------------------------------------------

/// Mask for value location in SValue.r (lower 6 bits: register number or special).
pub const VT_VALMASK: i32 = 0x003f;
/// Constant value stored in SValue.c.
pub const VT_CONST: i32 = 0x0030;
/// Local variable via secondary register indirection (llocal).
pub const VT_LLOCAL: i32 = 0x0031;
/// Local variable relative to frame pointer.
pub const VT_LOCAL: i32 = 0x0032;
/// Comparison result (condition code).
pub const VT_CMP: i32 = 0x0033;
/// Forward jump (true branch).
pub const VT_JMP: i32 = 0x0034;
/// Inverse forward jump (false branch).
pub const VT_JMPI: i32 = 0x0035;
/// L-value (memory location, must be dereferenced).
pub const VT_LVAL: i32 = 0x0100;
/// Symbol associated with value.
pub const VT_SYM: i32 = 0x0200;
/// Value needs a cast before use.
pub const VT_MUSTCAST: i32 = 0x0C00;
/// `VT_CONST` but not an anonymous constant.
pub const VT_NONCONST: i32 = 0x1000;
/// Value must have bounds-checking applied.
pub const VT_MUSTBOUND: i32 = 0x4000;
/// Value has already been bounds-checked.
pub const VT_BOUNDED: i32 = 0x8000;

// ---------------------------------------------------------------------------
// Stack and buffer size constants
// From tcc.h lines 432-437
// ---------------------------------------------------------------------------

/// Maximum depth of `#include` nesting.
pub const INCLUDE_STACK_SIZE: usize = 32;
/// Maximum depth of `#ifdef` nesting.
pub const IFDEF_STACK_SIZE: usize = 64;
/// Value stack depth (for expression evaluation).
pub const VSTACK_SIZE: usize = 512;
/// Maximum string literal size.
pub const STRING_MAX_SIZE: usize = 1024;
/// Maximum token string buffer size.
pub const TOKSTR_MAX_SIZE: usize = 256;
/// Maximum depth of `#pragma pack` nesting.
pub const PACK_STACK_SIZE: usize = 8;
/// File I/O buffer size.
pub const IO_BUF_SIZE: usize = 8192;

// ---------------------------------------------------------------------------
// Token table constants
// From tcc.h lines 439-441
// ---------------------------------------------------------------------------

/// Size of the token hash table (must be power of two).
pub const TOK_HASH_SIZE: usize = 16384;
/// Token allocation increment (must be power of two).
pub const TOK_ALLOC_INCR: usize = 512;
/// Token maximum size in i32 units.
pub const TOK_MAX_SIZE: usize = 4;

// ---------------------------------------------------------------------------
// Cached includes hash table
// From tcc.h line 701
// ---------------------------------------------------------------------------

/// Number of buckets in the cached-includes hash table.
pub const CACHED_INCLUDES_HASH_SIZE: usize = 32;

// ---------------------------------------------------------------------------
// Special character constants
// From tcc.h lines 657-658
// ---------------------------------------------------------------------------

/// End-of-buffer sentinel character (backslash `\`).
pub const CH_EOB: u8 = b'\\';
/// End-of-file sentinel (-1 as i32, stored in i32 context).
pub const CH_EOF: i32 = -1;

// ---------------------------------------------------------------------------
// Symbol space constants
// From tcc.h lines 601-603
// ---------------------------------------------------------------------------

/// Marker: symbol is a struct/union/enum tag.
pub const SYM_STRUCT: i32 = 0x4000_0000;
/// Marker: symbol is a struct/union field.
pub const SYM_FIELD: i32 = 0x2000_0000;
/// First anonymous symbol number.
pub const SYM_FIRST_ANOM: i32 = 0x1000_0000;

// ---------------------------------------------------------------------------
// Function type constants
// From tcc.h lines 606-609
// ---------------------------------------------------------------------------

/// New-style (prototyped) function.
pub const FUNC_NEW: u8 = 1;
/// Old-style (K&R) function.
pub const FUNC_OLD: u8 = 2;
/// Function with ellipsis (variadic).
pub const FUNC_ELLIPSIS: u8 = 3;

// ---------------------------------------------------------------------------
// Calling convention constants
// From tcc.h lines 612-618
// ---------------------------------------------------------------------------

/// Default C calling convention (`cdecl`).
pub const FUNC_CDECL: u8 = 0;
/// Windows `__stdcall` calling convention.
pub const FUNC_STDCALL: u8 = 1;
/// `__fastcall` with 1 register parameter.
pub const FUNC_FASTCALL1: u8 = 2;
/// `__fastcall` with 2 register parameters.
pub const FUNC_FASTCALL2: u8 = 3;
/// `__fastcall` with 3 register parameters.
pub const FUNC_FASTCALL3: u8 = 4;
/// Windows `__fastcall` variant.
pub const FUNC_FASTCALLW: u8 = 5;
/// C++ `__thiscall` calling convention.
pub const FUNC_THISCALL: u8 = 6;

// ---------------------------------------------------------------------------
// Macro type constants
// From tcc.h lines 620-622
// ---------------------------------------------------------------------------

/// Object-like macro (no parameters).
pub const MACRO_OBJ: i32 = 0;
/// Function-like macro (with parameters).
pub const MACRO_FUNC: i32 = 1;
/// Token-pasting (`##`) macro.
pub const MACRO_JOIN: i32 = 2;

// ---------------------------------------------------------------------------
// Label state constants
// From tcc.h lines 625-629
// ---------------------------------------------------------------------------

/// Label has been defined (address known).
pub const LABEL_DEFINED: i32 = 0;
/// Label referenced but not yet defined.
pub const LABEL_FORWARD: i32 = 1;
/// Label declared (e.g., via `__label__`) but not defined.
pub const LABEL_DECLARED: i32 = 2;
/// Label has gone out of scope.
pub const LABEL_GONE: i32 = 3;

// ---------------------------------------------------------------------------
// Type declaration mode constants
// From tcc.h lines 632-635
// ---------------------------------------------------------------------------

/// Abstract declarator (no name, e.g., in casts/sizeof).
pub const TYPE_ABSTRACT: i32 = 1;
/// Direct declarator (with name).
pub const TYPE_DIRECT: i32 = 2;
/// Parameter declarator.
pub const TYPE_PARAM: i32 = 4;
/// Nested declarator (inside parentheses).
pub const TYPE_NEST: i32 = 8;

// ===========================================================================
// Struct Definitions
// ===========================================================================

// ---------------------------------------------------------------------------
// SymAttr — Symbol attributes (bitfield equivalent)
// From tcc.h lines 504-516
// ---------------------------------------------------------------------------

/// Symbol attributes controlling alignment, linkage visibility, and import/export behavior.
///
/// In C this is a bitfield struct. In Rust we use individual typed fields.
/// The `aligned` field stores alignment as `log2(alignment) + 1` (0 means unspecified).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SymAttr {
    /// Alignment as `log2(alignment) + 1`. Zero means unspecified.
    /// Original C: 5-bit bitfield, stores values 0..31.
    pub aligned: u8,
    /// Whether the symbol has `__attribute__((packed))`.
    pub packed: bool,
    /// Whether the symbol has `__attribute__((weak))` linkage.
    pub weak: bool,
    /// ELF symbol visibility (STV_DEFAULT=0, STV_INTERNAL=1, STV_HIDDEN=2, STV_PROTECTED=3).
    /// Original C: 2-bit bitfield.
    pub visibility: u8,
    /// Windows `__declspec(dllexport)`.
    pub dllexport: bool,
    /// Suppress name decoration (Windows).
    pub nodecorate: bool,
    /// Windows `__declspec(dllimport)`.
    pub dllimport: bool,
    /// Address of this symbol has been taken (affects optimization).
    pub addrtaken: bool,
    /// Suppress debug info emission for this symbol.
    pub nodebug: bool,
}

// ---------------------------------------------------------------------------
// FuncAttr — Function-specific attributes
// From tcc.h lines 519-529
// ---------------------------------------------------------------------------

/// Function-specific attributes controlling calling convention, type classification,
/// and special behaviors.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FuncAttr {
    /// Calling convention: one of `FUNC_CDECL` .. `FUNC_THISCALL`.
    /// Original C: 3-bit bitfield.
    pub func_call: u8,
    /// Function type: `FUNC_NEW`, `FUNC_OLD`, or `FUNC_ELLIPSIS`.
    /// Original C: 2-bit bitfield.
    pub func_type: u8,
    /// `__attribute__((noreturn))` — function does not return.
    pub func_noreturn: bool,
    /// `__attribute__((constructor))` — run before `main()`.
    pub func_ctor: bool,
    /// `__attribute__((destructor))` — run after `main()`.
    pub func_dtor: bool,
    /// Number of arguments for `__stdcall` name decoration (PE).
    /// Original C: 8-bit field.
    pub func_args: u8,
    /// `__attribute__((always_inline))`.
    pub func_alwinl: bool,
}

// ---------------------------------------------------------------------------
// CType — C type representation
// From tcc.h lines 468-471
// ---------------------------------------------------------------------------

/// Represents a C type in TCC's type system.
///
/// The `t` field encodes the base type, qualifiers, and storage class via
/// bitwise OR of `VT_*` constants. For compound types (pointer, function,
/// struct/union), `ref_sym` points to additional type information stored
/// in a `Sym` node.
///
/// # BUG-07 Fix
/// The `Display` implementation correctly renders function pointer syntax
/// with proper parenthesization, e.g., `void (*)(int)`.
#[derive(Debug, Clone)]
pub struct CType {
    /// Type flags — bitwise OR of `VT_*` constants.
    pub t: i32,
    /// Reference to a `Sym` for complex types (pointers, functions, structs).
    /// `None` for simple scalar types.
    pub ref_sym: Option<Box<Sym>>,
}

impl Default for CType {
    fn default() -> Self {
        CType {
            t: VT_INT,
            ref_sym: None,
        }
    }
}

// ---------------------------------------------------------------------------
// CStringValue — String value within CValue union
// From tcc.h lines 478-479 (anonymous struct inside CValue union)
// ---------------------------------------------------------------------------

/// Represents a string constant value as a raw pointer and size.
/// Used inside `CValue` to carry string literal data.
#[derive(Clone, Copy, Debug)]
pub struct CStringValue {
    /// Pointer to the string data bytes.
    pub data: *const u8,
    /// Size of the string data in bytes.
    pub size: i32,
}

impl Default for CStringValue {
    fn default() -> Self {
        CStringValue {
            data: std::ptr::null(),
            size: 0,
        }
    }
}

// Safety: CStringValue contains a raw pointer but is only used within the
// single-threaded compiler context. The pointer is never sent across threads.
unsafe impl Send for CStringValue {}
unsafe impl Sync for CStringValue {}

// ---------------------------------------------------------------------------
// CValue — Constant value union
// From tcc.h lines 474-484
// ---------------------------------------------------------------------------

/// Union representing a constant value during compilation.
///
/// Mirrors the C union where different fields share the same memory.
/// Only one field is valid at a time, determined by the associated `CType`.
#[derive(Clone, Copy)]
pub union CValue {
    /// Long double value (simplified to f64 — see PORT-03).
    pub ld: f64,
    /// Double-precision floating-point value.
    pub d: f64,
    /// Single-precision floating-point value.
    pub f: f32,
    /// Unsigned 64-bit integer value (covers all integer types).
    pub i: u64,
    /// String constant value (pointer + size).
    pub str_val: CStringValue,
    /// Raw storage for long double (`LDOUBLE_SIZE / 4` i32 elements).
    pub tab: [i32; 4],
}

impl Default for CValue {
    fn default() -> Self {
        // Zero-initialize (all bits zero)
        CValue { i: 0 }
    }
}

impl fmt::Debug for CValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Safety: reading `i` from the union is always valid as it's the widest simple field.
        let raw = unsafe { self.i };
        f.debug_struct("CValue").field("i", &raw).finish()
    }
}

// ---------------------------------------------------------------------------
// Sym — Symbol table entry
// From tcc.h lines 532-566
// ---------------------------------------------------------------------------

/// A symbol table entry representing variables, functions, types, labels,
/// struct fields, macro definitions, etc.
///
/// The `Sym` struct is the core of TCC's symbol management. Different fields
/// are used depending on the symbol kind (reflected by `v` flags):
///
/// - **Variables/functions**: `type_`, `r`, `c` (section offset or register)
/// - **Struct/union fields**: `c` (byte offset), `type_`, `next` (next field)
/// - **Enum constants**: `enum_val` (the constant value)
/// - **Macros**: `d` (token stream for the macro body)
/// - **Labels**: `c` (code offset), label state in `r`
///
/// The `next`, `prev`, and `prev_tok` links form various linked lists
/// (scope chains, overload chains, hash bucket chains).
///
/// # C Layout Correspondence — Field Aliasing
///
/// In the original C `Sym` struct (tcc.h lines 532-566), several fields share
/// storage via anonymous unions:
///
/// - **`jnext` / `next`**: In C, `jnext` (i32) and `next` (Sym*) occupy the
///   same memory. `jnext` is used for label forward-reference chains (stores a
///   jump target offset), while `next` is used for parameter/field linked lists.
///   In Rust, these are separate fields; code must use the correct field based
///   on symbol kind (labels use `c` for jump offsets, other symbols use `next`).
///
/// - **`type.ref` / `enum_val` / `d`**: In C, these overlap in a union. For
///   variables/functions, `type_.ref_sym` carries the type's reference chain.
///   For enum constants, `enum_val` carries the constant's integer value. For
///   macros, `d` carries the token stream. In Rust, all three are separate
///   fields; only the field corresponding to the symbol kind should be read.
#[derive(Default)]
pub struct Sym {
    /// Symbol token identifier (includes `SYM_STRUCT`, `SYM_FIELD` flags in upper bits).
    pub v: i32,
    /// Associated register or location (`VT_CONST`, `VT_LOCAL`, or register number).
    pub r: u16,
    /// Symbol attributes (alignment, visibility, linkage modifiers).
    pub a: SymAttr,
    /// Associated number: ELF symbol index, section offset, stack offset, etc.
    pub c: i32,
    /// The C type of this symbol.
    pub type_: CType,
    /// Next symbol in the chain (e.g., next struct field, next parameter).
    pub next: Option<Box<Sym>>,
    /// Previous symbol in the scope stack.
    pub prev: Option<Box<Sym>>,
    /// Previous symbol with the same token (hash chain for shadowing).
    pub prev_tok: Option<Box<Sym>>,
    /// Scope level (for local symbols, tracks block nesting depth).
    pub sym_scope: i32,
    /// Function-specific attributes (calling convention, noreturn, etc.).
    pub f: FuncAttr,
    /// Enum constant value (when this symbol is an enum member).
    pub enum_val: i64,
    /// Define token stream (when this symbol is a macro definition).
    /// Each `i32` encodes a token.
    pub d: Option<Vec<i32>>,
    /// Assembly label number (for `__asm__("label")` attribute).
    pub asm_label: i32,
}

impl fmt::Debug for Sym {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sym")
            .field("v", &self.v)
            .field("r", &self.r)
            .field("a", &self.a)
            .field("c", &self.c)
            .field("type_", &self.type_)
            .field("sym_scope", &self.sym_scope)
            .field("f", &self.f)
            .field("enum_val", &self.enum_val)
            .field("asm_label", &self.asm_label)
            .finish()
    }
}

impl Clone for Sym {
    fn clone(&self) -> Self {
        Sym {
            v: self.v,
            r: self.r,
            a: self.a,
            c: self.c,
            type_: self.type_.clone(),
            next: self.next.clone(),
            prev: self.prev.clone(),
            prev_tok: self.prev_tok.clone(),
            sym_scope: self.sym_scope,
            f: self.f,
            enum_val: self.enum_val,
            d: self.d.clone(),
            asm_label: self.asm_label,
        }
    }
}

// ---------------------------------------------------------------------------
// SValue — Value stack entry
// From tcc.h lines 487-501
// ---------------------------------------------------------------------------

/// An entry on the value stack (vstack), used during expression evaluation.
///
/// TCC uses a value stack of depth `VSTACK_SIZE` (512) to evaluate expressions.
/// Each entry holds a type, a storage location (register/const/local), and
/// optional associated data (constant value, symbol reference, comparison info).
#[derive(Clone, Default)]
pub struct SValue {
    /// The C type of this value.
    pub type_: CType,
    /// Register or storage location flags (bitwise OR of `VT_*` value-location constants).
    pub r: u16,
    /// Second register (used for 64-bit values on 32-bit targets, e.g., `long long`).
    pub r2: u16,
    /// Constant value (valid when `r & VT_VALMASK == VT_CONST`).
    pub c: CValue,
    /// Associated symbol (valid when `VT_SYM` flag is set).
    pub sym: Option<Box<Sym>>,
    /// Comparison operator (when `r & VT_VALMASK == VT_CMP`).
    pub cmp_op: u16,
    /// Register holding comparison result.
    pub cmp_r: u16,
    /// Forward jump target for true branch (when `VT_JMP`).
    pub jtrue: i32,
    /// Forward jump target for false branch (when `VT_JMPI`).
    pub jfalse: i32,
}

impl fmt::Debug for SValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SValue")
            .field("type_", &self.type_)
            .field("r", &self.r)
            .field("r2", &self.r2)
            .field("sym", &self.sym)
            .field("cmp_op", &self.cmp_op)
            .field("cmp_r", &self.cmp_r)
            .field("jtrue", &self.jtrue)
            .field("jfalse", &self.jfalse)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Section — ELF section representation
// From tcc.h lines 569-590
// ---------------------------------------------------------------------------

/// Represents an ELF section in the compiler's internal model.
///
/// Each section holds raw bytes (`data`), metadata corresponding to ELF
/// section header fields (`sh_*`), and links to related sections (relocation,
/// hash table, etc.).
///
/// PORT-02: Uses `usize` for sizes and offsets instead of C `int`.
#[derive(Debug, Clone)]
pub struct Section {
    /// Section data buffer.
    pub data: Vec<u8>,
    /// Current write position in the data buffer.
    pub data_offset: usize,
    /// ELF section name string-table index.
    pub sh_name: i32,
    /// ELF section number (index in the section table).
    pub sh_num: i32,
    /// ELF section type (`SHT_PROGBITS`, `SHT_SYMTAB`, etc.).
    pub sh_type: i32,
    /// ELF section flags (`SHF_WRITE`, `SHF_ALLOC`, `SHF_EXECINSTR`, etc.).
    pub sh_flags: i32,
    /// ELF section info field (type-dependent: e.g., symbol table local count).
    pub sh_info: i32,
    /// Required alignment (power of 2).
    pub sh_addralign: i32,
    /// Entry size for fixed-size entry sections (e.g., symbol table, relocation).
    pub sh_entsize: i32,
    /// Section size in the output file.
    pub sh_size: usize,
    /// Virtual address of the section when loaded.
    pub sh_addr: u64,
    /// File offset of the section in the output file.
    pub sh_offset: usize,
    /// Number of hashed symbols (for dynamic hash table resizing).
    pub nb_hashed_syms: i32,
    /// Index of the linked section (e.g., string table for symbol table).
    pub link: Option<usize>,
    /// Index of the associated relocation section.
    pub reloc: Option<usize>,
    /// Index of the associated hash table section.
    pub hash: Option<usize>,
    /// Section name string.
    pub name: String,
}

impl Default for Section {
    fn default() -> Self {
        Section {
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
            name: String::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// BufferedFile — Source file input buffer
// From tcc.h lines 639-655
// ---------------------------------------------------------------------------

/// Represents a buffered source file being read by the lexer/preprocessor.
///
/// Each open source file (including files opened via `#include`) gets its own
/// `BufferedFile` instance. A stack of these is maintained to handle nested
/// includes (up to `INCLUDE_STACK_SIZE` depth).
#[derive(Debug, Clone)]
pub struct BufferedFile {
    /// Current read position index within `buffer`.
    pub buf_ptr: usize,
    /// End-of-valid-data index within `buffer`.
    pub buf_end: usize,
    /// File descriptor (-1 if this is a string-based input).
    pub fd: i32,
    /// Current line number (1-based).
    pub line_num: i32,
    /// Last line number printed in `-E` (preprocess-only) mode.
    pub line_ref: i32,
    /// Token of the `#ifndef` guard macro (0 if not detected).
    pub ifndef_macro: i32,
    /// Saved `ifndef_macro` value for nested processing.
    pub ifndef_macro_saved: i32,
    /// `ifdef_stack` depth when this file was opened.
    pub ifdef_stack_ptr: usize,
    /// Next search path index for `#include_next`.
    pub include_next_index: i32,
    /// Saved token flags from before this file was opened.
    pub prev_tok_flags: u32,
    /// Display filename (may be modified by `#line` directives).
    pub filename: String,
    /// Original, unmodified filename.
    pub true_filename: String,
    /// Small unget buffer for pushing back characters (up to 4 bytes).
    pub unget: [u8; 4],
    /// File content buffer.
    pub buffer: Vec<u8>,
}

impl Default for BufferedFile {
    fn default() -> Self {
        BufferedFile {
            buf_ptr: 0,
            buf_end: 0,
            fd: -1,
            line_num: 1,
            line_ref: 0,
            ifndef_macro: 0,
            ifndef_macro_saved: 0,
            ifdef_stack_ptr: 0,
            include_next_index: 0,
            prev_tok_flags: 0,
            filename: String::new(),
            true_filename: String::new(),
            unget: [0; 4],
            buffer: Vec::with_capacity(IO_BUF_SIZE),
        }
    }
}

// ---------------------------------------------------------------------------
// CString — Dynamically sized string buffer
// From tcc.h lines 461-465
// ---------------------------------------------------------------------------

/// A dynamically-sized byte buffer used for string literals, token strings,
/// and assembler output during compilation.
///
/// Replaces C's `CString { int size; void *data; int size_allocated; }` with
/// a `Vec<u8>` that handles allocation automatically.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CString {
    /// The raw byte data. Null terminator is included when used for C strings.
    pub data: Vec<u8>,
}

impl CString {
    /// Creates a new empty `CString`.
    pub fn new() -> Self {
        CString { data: Vec::new() }
    }

    /// Creates a `CString` from a byte slice (does not add null terminator).
    pub fn from_bytes(bytes: &[u8]) -> Self {
        CString {
            data: bytes.to_vec(),
        }
    }

    /// Returns the length of the data in bytes.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns `true` if the string is empty.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

// ---------------------------------------------------------------------------
// TokenSym — Token symbol table entry
// From tcc.h lines 444-453
// ---------------------------------------------------------------------------

/// Entry in the token symbol hash table.
///
/// Each unique identifier, keyword, or preprocessor symbol gets a `TokenSym`
/// entry. The `hash_next` field chains entries in the same hash bucket.
/// Associated symbol definitions (define, label, struct tag, identifier) are
/// linked via optional `Sym` pointers.
#[derive(Debug, Clone)]
pub struct TokenSym {
    /// Next entry in the same hash bucket (-1 if end of chain).
    pub hash_next: i32,
    /// Preprocessor macro definition (`#define`), if any.
    pub sym_define: Option<Box<Sym>>,
    /// Label definition (for `goto` targets), if any.
    pub sym_label: Option<Box<Sym>>,
    /// Struct/union/enum tag definition, if any.
    pub sym_struct: Option<Box<Sym>>,
    /// Identifier definition (variable, function, typedef), if any.
    pub sym_identifier: Option<Box<Sym>>,
    /// Token value (unique integer identifying this token).
    pub tok: i32,
    /// Length of the token string in bytes.
    pub len: i32,
    /// The token string data (identifier name, keyword text, etc.).
    pub str_data: String,
}

impl Default for TokenSym {
    fn default() -> Self {
        TokenSym {
            hash_next: -1,
            sym_define: None,
            sym_label: None,
            sym_struct: None,
            sym_identifier: None,
            tok: 0,
            len: 0,
            str_data: String::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// TokenString — Saved token stream
// From tcc.h lines 661-672
// ---------------------------------------------------------------------------

/// A saved stream of tokens, used for macro bodies, inline function bodies,
/// and deferred parsing.
///
/// Each `i32` in `str_data` encodes a token (token value, followed by optional
/// token-specific payload like integer constants or string offsets).
#[derive(Debug, Clone, Default)]
pub struct TokenString {
    /// Encoded token stream data.
    pub str_data: Vec<i32>,
    /// Whether a space is needed before the next token (for stringify).
    pub need_spc: bool,
    /// Line number at the last token in this stream.
    pub last_line_num: i32,
    /// Saved line number (for restoring after replay).
    pub save_line_num: i32,
    /// Whether this `TokenString` owns its data (for cleanup).
    pub alloc: bool,
}

// ---------------------------------------------------------------------------
// AttributeDef — Collected declaration attributes
// From tcc.h lines 675-683
// ---------------------------------------------------------------------------

/// Collects all attributes parsed from a declaration, including
/// `__attribute__((...))`, `__declspec(...)`, alignment pragmas, and
/// assembly labels.
///
/// Built up during declaration parsing and then applied to the resulting symbol.
#[derive(Debug, Clone, Default)]
pub struct AttributeDef {
    /// Symbol-level attributes (alignment, visibility, etc.).
    pub a: SymAttr,
    /// Function-level attributes (calling convention, noreturn, etc.).
    pub f: FuncAttr,
    /// Section index for `__attribute__((section("name")))`.
    pub section: Option<usize>,
    /// Cleanup function for `__attribute__((cleanup(func)))`.
    pub cleanup_func: Option<Box<Sym>>,
    /// Alias target token for `__attribute__((alias("target")))`.
    pub alias_target: i32,
    /// Assembly label for `__asm__("label")`.
    pub asm_label: i32,
    /// Attribute mode (for `__attribute__((mode(...)))`) specifying type width.
    pub attr_mode: u8,
    /// BUG-03: `__attribute__((transparent_union))` flag.
    ///
    /// When set on a union parameter, allows any union member type to be
    /// passed directly in function call argument position without an explicit
    /// cast.  This is required for POSIX `sys/socket.h` (e.g. `sendmsg`).
    pub transparent_union: bool,
}

// ---------------------------------------------------------------------------
// InlineFunc — Saved inline function definition
// From tcc.h lines 686-690
// ---------------------------------------------------------------------------

/// Stores the token stream and metadata for an inline function definition.
///
/// Inline functions are saved during their first encounter and replayed
/// (re-parsed and compiled) at each call site or at the end of the translation
/// unit if the address is taken.
#[derive(Debug, Clone)]
pub struct InlineFunc {
    /// Token stream of the function body.
    pub func_str: TokenString,
    /// The function symbol.
    pub sym: Box<Sym>,
    /// Source filename where the function was defined.
    pub filename: String,
}

// ---------------------------------------------------------------------------
// CachedInclude — Cached include file entry
// From tcc.h lines 694-699
// ---------------------------------------------------------------------------

/// Caches information about a previously-included header file to enable
/// the `#ifndef` guard optimization and `#pragma once` support.
///
/// Stored in a hash table of `CACHED_INCLUDES_HASH_SIZE` (32) buckets.
#[derive(Debug, Clone)]
pub struct CachedInclude {
    /// Token of the `#ifndef` guard macro (0 if not detected).
    pub ifndef_macro: i32,
    /// Whether `#pragma once` was used.
    pub once: bool,
    /// Next entry in the same hash bucket (-1 if end of chain).
    pub hash_next: i32,
    /// Full path of the included file.
    pub filename: String,
}

impl Default for CachedInclude {
    fn default() -> Self {
        CachedInclude {
            ifndef_macro: 0,
            once: false,
            hash_next: -1,
            filename: String::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// DLLReference — Dynamically loaded library reference
// From tcc.h lines 592-597
// ---------------------------------------------------------------------------

/// Tracks a dynamically loaded shared library (`.so` / `.dll`) used during
/// linking or runtime symbol resolution.
///
/// The `handle` field holds an opaque OS handle obtained via `dlopen()` (POSIX)
/// or `LoadLibrary()` (Windows).
#[derive(Default)]
pub struct DLLReference {
    /// Library dependency level (depth in the dependency graph).
    pub level: i32,
    /// Opaque handle from `dlopen` / `LoadLibrary` (or `None` if not loaded).
    pub handle: Option<*mut c_void>,
    /// Whether the library was successfully found/loaded.
    pub found: bool,
    /// Index for ordering or identification.
    pub index: u8,
    /// Library name (e.g., `"libm.so.6"`).
    pub name: String,
}

impl fmt::Debug for DLLReference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DLLReference")
            .field("level", &self.level)
            .field("handle", &self.handle.map(|p| p as usize))
            .field("found", &self.found)
            .field("index", &self.index)
            .field("name", &self.name)
            .finish()
    }
}

impl Clone for DLLReference {
    fn clone(&self) -> Self {
        DLLReference {
            level: self.level,
            handle: self.handle,
            found: self.found,
            index: self.index,
            name: self.name.clone(),
        }
    }
}

// Safety: DLLReference contains a raw pointer (`handle`) but is only used
// within the single-threaded compiler context.
unsafe impl Send for DLLReference {}
unsafe impl Sync for DLLReference {}

// ===========================================================================
// Display trait implementation for CType — BUG-07 Fix
// ===========================================================================

/// Helper: writes the base type name for the given `VT_*` basic type value.
fn write_base_type(f: &mut fmt::Formatter<'_>, btype: i32, is_unsigned: bool) -> fmt::Result {
    match btype {
        VT_VOID => write!(f, "void"),
        VT_BYTE => {
            if is_unsigned {
                write!(f, "unsigned char")
            } else {
                write!(f, "signed char")
            }
        }
        VT_SHORT => {
            if is_unsigned {
                write!(f, "unsigned short")
            } else {
                write!(f, "short")
            }
        }
        VT_INT => {
            if is_unsigned {
                write!(f, "unsigned int")
            } else {
                write!(f, "int")
            }
        }
        VT_LLONG => {
            if is_unsigned {
                write!(f, "unsigned long long")
            } else {
                write!(f, "long long")
            }
        }
        VT_FLOAT => write!(f, "float"),
        VT_DOUBLE => write!(f, "double"),
        VT_LDOUBLE => write!(f, "long double"),
        VT_BOOL => write!(f, "_Bool"),
        VT_QLONG => write!(f, "__int128"),
        VT_QFLOAT => write!(f, "__float128"),
        VT_PTR => write!(f, "<ptr>"),
        VT_FUNC => write!(f, "<func>"),
        VT_STRUCT => write!(f, "<struct>"),
        _ => write!(f, "<unknown type {}>", btype),
    }
}

/// Helper: writes type qualifiers (const, volatile) preceding a type name.
fn write_qualifiers(f: &mut fmt::Formatter<'_>, t: i32) -> fmt::Result {
    if t & VT_CONSTANT != 0 {
        write!(f, "const ")?;
    }
    if t & VT_VOLATILE != 0 {
        write!(f, "volatile ")?;
    }
    Ok(())
}

/// BUG-07 Fix: Correct function pointer type display with proper parenthesization.
///
/// This implementation handles the full complexity of C type declaration syntax:
/// - Simple types: `int`, `unsigned long long`, `const char`
/// - Pointer types: `int *`, `const char *`
/// - Function types: `int (int, char *)`
/// - Function pointer types: `int (*)(int, char *)` — the key BUG-07 fix
/// - Nested function pointers: `void (*(*)(int))(double)`
/// - Struct/union/enum types: `struct <tag>`, `union <tag>`, `enum <tag>`
/// - Array types: `int [10]`
///
/// The C type system requires inside-out declaration reading. A function pointer
/// `void (*fp)(int)` has the pointer declaration wrapped in parentheses to bind
/// the `*` to the name rather than the return type. TCC's original C code
/// (BUG-07) failed to parenthesize correctly, producing `void *()` instead.
impl fmt::Display for CType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let t = self.t;
        let btype = t & VT_BTYPE;
        let is_unsigned = (t & VT_UNSIGNED) != 0;

        // Write storage class specifiers
        if t & VT_EXTERN != 0 {
            write!(f, "extern ")?;
        }
        if t & VT_STATIC != 0 {
            write!(f, "static ")?;
        }
        if t & VT_TYPEDEF != 0 {
            write!(f, "typedef ")?;
        }
        if t & VT_INLINE != 0 {
            write!(f, "inline ")?;
        }

        // Write qualifiers
        write_qualifiers(f, t)?;

        // BUG-07 fix: Check for enum types BEFORE the btype match.
        // In TCC, enum types have btype = VT_INT (3), not VT_STRUCT (7), but carry
        // the VT_ENUM tag in bits above VT_STRUCT_SHIFT. Without this pre-check,
        // the VT_STRUCT match arm would never be reached for enum types, causing
        // them to incorrectly display as "int" instead of "enum <tag>".
        if is_enum(t) {
            write!(f, "enum")?;
            if let Some(ref sym) = self.ref_sym {
                if sym.v != 0 {
                    write!(f, " <tag:{}>", sym.v & !(SYM_STRUCT | SYM_FIELD))?;
                }
            }
        } else {
            match btype {
                VT_PTR => {
                    // Pointer type: display what we point to, then '*'
                    if let Some(ref sym) = self.ref_sym {
                        let pointed_to = &sym.type_;
                        let pointed_btype = pointed_to.t & VT_BTYPE;

                        if pointed_btype == VT_FUNC {
                            // Function pointer: need parenthesization
                            // Display return type, then "(*)", then parameters
                            // e.g., void (*)(int, char *)
                            write_func_ptr_type(f, pointed_to)?;
                        } else {
                            // Regular pointer: recurse on pointed-to type, append *
                            write!(f, "{} *", pointed_to)?;
                        }
                    } else {
                        write!(f, "void *")?;
                    }
                }
                VT_FUNC => {
                    // Function type (not pointer): display return type + params
                    write_func_type(f, self)?;
                }
                VT_STRUCT => {
                    // BUG-07 fix: Correctly distinguish struct vs union.
                    // Extract only the tag bits above VT_STRUCT_SHIFT, not the low VT_BTYPE bits.
                    // VT_UNION = (1 << VT_STRUCT_SHIFT) | VT_STRUCT, so the tag portion
                    // (bits 20+) is 1. VT_STRUCT alone has tag portion 0.
                    if is_union(t) {
                        write!(f, "union")?;
                    } else {
                        write!(f, "struct")?;
                    }
                    // If we have a ref_sym, show its name token
                    if let Some(ref sym) = self.ref_sym {
                        if sym.v != 0 {
                            write!(f, " <tag:{}>", sym.v & !(SYM_STRUCT | SYM_FIELD))?;
                        }
                    }
                }
                _ => {
                    // Simple scalar type
                    if (t & VT_LONG) != 0 && btype == VT_INT {
                        // long or unsigned long
                        if is_unsigned {
                            write!(f, "unsigned long")?;
                        } else {
                            write!(f, "long")?;
                        }
                    } else {
                        write_base_type(f, btype, is_unsigned)?;
                    }
                }
            }
        }

        // Array modifier
        if (t & VT_ARRAY) != 0 {
            if let Some(ref sym) = self.ref_sym {
                write!(f, " [{}]", sym.c)?;
            } else {
                write!(f, " []")?;
            }
        }

        Ok(())
    }
}

/// Helper: writes a function type (return_type (params...)).
fn write_func_type(f: &mut fmt::Formatter<'_>, ctype: &CType) -> fmt::Result {
    if let Some(ref func_sym) = ctype.ref_sym {
        // Write return type
        write!(f, "{}", func_sym.type_)?;
        // Write parameter list
        write!(f, " (")?;
        write_param_list(f, func_sym)?;
        write!(f, ")")?;
    } else {
        write!(f, "void ()")?;
    }
    Ok(())
}

/// Helper: writes a function pointer type with correct parenthesization.
/// Produces: `return_type (*)(params...)` — the BUG-07 fix.
fn write_func_ptr_type(f: &mut fmt::Formatter<'_>, func_type: &CType) -> fmt::Result {
    if let Some(ref func_sym) = func_type.ref_sym {
        // Write return type, then (*), then parameters
        write!(f, "{}", func_sym.type_)?;
        write!(f, " (*)")?;
        write!(f, "(")?;
        write_param_list(f, func_sym)?;
        write!(f, ")")?;
    } else {
        write!(f, "void (*)()")?;
    }
    Ok(())
}

/// Helper: writes function parameter types separated by commas.
/// Walks the `next` chain of the function symbol to enumerate parameters.
fn write_param_list(f: &mut fmt::Formatter<'_>, func_sym: &Sym) -> fmt::Result {
    let mut first = true;
    let mut param = &func_sym.next;
    while let Some(ref p) = param {
        if !first {
            write!(f, ", ")?;
        }
        write!(f, "{}", p.type_)?;
        first = false;
        param = &p.next;
    }
    // Handle variadic (ellipsis)
    if func_sym.f.func_type == FUNC_ELLIPSIS {
        if !first {
            write!(f, ", ")?;
        }
        write!(f, "...")?;
    }
    if first {
        write!(f, "void")?;
    }
    Ok(())
}

// ===========================================================================
// Unit Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vt_btype_mask() {
        // VT_BTYPE should extract the basic type from a compound flags value
        assert_eq!(VT_INT & VT_BTYPE, VT_INT);
        assert_eq!((VT_INT | VT_UNSIGNED) & VT_BTYPE, VT_INT);
        assert_eq!((VT_PTR | VT_CONSTANT) & VT_BTYPE, VT_PTR);
        assert_eq!(VT_VOID & VT_BTYPE, VT_VOID);
    }

    #[test]
    fn test_vt_struct_mask() {
        // VT_STRUCT_MASK should cover struct/union/enum bits and VT_BITFIELD
        assert_ne!(VT_STRUCT_MASK & VT_BITFIELD, 0);
        // VT_UNION should combine struct shift and VT_STRUCT
        assert_eq!(VT_UNION & VT_BTYPE, VT_STRUCT);
        assert_ne!(VT_UNION & VT_STRUCT_MASK, 0);
        // VT_ENUM should be distinct from VT_UNION
        assert_ne!(VT_ENUM, VT_UNION);
        assert_ne!(VT_ENUM_VAL, VT_ENUM);
    }

    #[test]
    fn test_vt_storage() {
        assert_eq!(
            VT_STORAGE,
            VT_EXTERN | VT_STATIC | VT_TYPEDEF | VT_INLINE
        );
        // VT_TYPE should exclude storage and struct mask
        assert_eq!(VT_TYPE & VT_STORAGE, 0);
        assert_eq!(VT_TYPE & VT_STRUCT_MASK, 0);
    }

    #[test]
    fn test_vt_atomic_equals_volatile() {
        assert_eq!(VT_ATOMIC, VT_VOLATILE);
    }

    #[test]
    fn test_sym_attr_default() {
        let a = SymAttr::default();
        assert_eq!(a.aligned, 0);
        assert!(!a.packed);
        assert!(!a.weak);
        assert_eq!(a.visibility, 0);
        assert!(!a.dllexport);
        assert!(!a.dllimport);
        assert!(!a.addrtaken);
        assert!(!a.nodebug);
        assert!(!a.nodecorate);
    }

    #[test]
    fn test_func_attr_default() {
        let f = FuncAttr::default();
        assert_eq!(f.func_call, 0);
        assert_eq!(f.func_type, 0);
        assert!(!f.func_noreturn);
        assert!(!f.func_ctor);
        assert!(!f.func_dtor);
        assert_eq!(f.func_args, 0);
        assert!(!f.func_alwinl);
    }

    #[test]
    fn test_ctype_default() {
        let ct = CType::default();
        assert_eq!(ct.t, VT_INT);
        assert!(ct.ref_sym.is_none());
    }

    #[test]
    fn test_cvalue_default() {
        let cv = CValue::default();
        assert_eq!(unsafe { cv.i }, 0);
    }

    #[test]
    fn test_svalue_default() {
        let sv = SValue::default();
        assert_eq!(sv.r, 0);
        assert_eq!(sv.r2, 0);
        assert_eq!(sv.jtrue, 0);
        assert_eq!(sv.jfalse, 0);
        assert!(sv.sym.is_none());
    }

    #[test]
    fn test_sym_default() {
        let s = Sym::default();
        assert_eq!(s.v, 0);
        assert_eq!(s.r, 0);
        assert_eq!(s.c, 0);
        assert_eq!(s.sym_scope, 0);
        assert_eq!(s.enum_val, 0);
        assert_eq!(s.asm_label, 0);
        assert!(s.next.is_none());
        assert!(s.prev.is_none());
        assert!(s.prev_tok.is_none());
        assert!(s.d.is_none());
    }

    #[test]
    fn test_section_default() {
        let sec = Section::default();
        assert!(sec.data.is_empty());
        assert_eq!(sec.data_offset, 0);
        assert_eq!(sec.sh_addralign, 1);
        assert!(sec.link.is_none());
        assert!(sec.reloc.is_none());
        assert!(sec.hash.is_none());
        assert!(sec.name.is_empty());
    }

    #[test]
    fn test_buffered_file_default() {
        let bf = BufferedFile::default();
        assert_eq!(bf.fd, -1);
        assert_eq!(bf.line_num, 1);
        assert!(bf.filename.is_empty());
        assert_eq!(bf.unget, [0; 4]);
    }

    #[test]
    fn test_cstring_operations() {
        let empty = CString::new();
        assert!(empty.is_empty());
        assert_eq!(empty.len(), 0);

        let cs = CString::from_bytes(b"hello");
        assert_eq!(cs.len(), 5);
        assert!(!cs.is_empty());
        assert_eq!(&cs.data, b"hello");
    }

    #[test]
    fn test_token_sym_default() {
        let ts = TokenSym::default();
        assert_eq!(ts.hash_next, -1);
        assert!(ts.sym_define.is_none());
        assert!(ts.sym_label.is_none());
        assert!(ts.sym_struct.is_none());
        assert!(ts.sym_identifier.is_none());
        assert_eq!(ts.tok, 0);
    }

    #[test]
    fn test_cached_include_default() {
        let ci = CachedInclude::default();
        assert_eq!(ci.ifndef_macro, 0);
        assert!(!ci.once);
        assert_eq!(ci.hash_next, -1);
        assert!(ci.filename.is_empty());
    }

    #[test]
    fn test_dll_reference_default() {
        let dll = DLLReference::default();
        assert_eq!(dll.level, 0);
        assert!(dll.handle.is_none());
        assert!(!dll.found);
        assert_eq!(dll.index, 0);
        assert!(dll.name.is_empty());
    }

    #[test]
    fn test_attribute_def_default() {
        let ad = AttributeDef::default();
        assert_eq!(ad.alias_target, 0);
        assert_eq!(ad.asm_label, 0);
        assert_eq!(ad.attr_mode, 0);
        assert!(ad.section.is_none());
        assert!(ad.cleanup_func.is_none());
    }

    #[test]
    fn test_stack_size_constants() {
        assert_eq!(INCLUDE_STACK_SIZE, 32);
        assert_eq!(IFDEF_STACK_SIZE, 64);
        assert_eq!(VSTACK_SIZE, 512);
        assert_eq!(STRING_MAX_SIZE, 1024);
        assert_eq!(TOKSTR_MAX_SIZE, 256);
        assert_eq!(PACK_STACK_SIZE, 8);
        assert_eq!(IO_BUF_SIZE, 8192);
    }

    #[test]
    fn test_token_constants() {
        assert_eq!(TOK_HASH_SIZE, 16384);
        assert_eq!(TOK_ALLOC_INCR, 512);
        assert_eq!(TOK_MAX_SIZE, 4);
        assert_eq!(CACHED_INCLUDES_HASH_SIZE, 32);
    }

    #[test]
    fn test_char_constants() {
        assert_eq!(CH_EOB, b'\\');
        assert_eq!(CH_EOF, -1);
    }

    #[test]
    fn test_sym_constants() {
        assert_eq!(SYM_STRUCT, 0x40000000);
        assert_eq!(SYM_FIELD, 0x20000000);
        assert_eq!(SYM_FIRST_ANOM, 0x10000000);
    }

    #[test]
    fn test_func_constants() {
        assert_eq!(FUNC_NEW, 1);
        assert_eq!(FUNC_OLD, 2);
        assert_eq!(FUNC_ELLIPSIS, 3);
        assert_eq!(FUNC_CDECL, 0);
        assert_eq!(FUNC_STDCALL, 1);
        assert_eq!(FUNC_FASTCALL1, 2);
        assert_eq!(FUNC_FASTCALL2, 3);
        assert_eq!(FUNC_FASTCALL3, 4);
        assert_eq!(FUNC_FASTCALLW, 5);
        assert_eq!(FUNC_THISCALL, 6);
    }

    #[test]
    fn test_macro_constants() {
        assert_eq!(MACRO_OBJ, 0);
        assert_eq!(MACRO_FUNC, 1);
        assert_eq!(MACRO_JOIN, 2);
    }

    #[test]
    fn test_label_constants() {
        assert_eq!(LABEL_DEFINED, 0);
        assert_eq!(LABEL_FORWARD, 1);
        assert_eq!(LABEL_DECLARED, 2);
        assert_eq!(LABEL_GONE, 3);
    }

    #[test]
    fn test_type_decl_constants() {
        assert_eq!(TYPE_ABSTRACT, 1);
        assert_eq!(TYPE_DIRECT, 2);
        assert_eq!(TYPE_PARAM, 4);
        assert_eq!(TYPE_NEST, 8);
    }

    // BUG-07: Test Display for CType
    #[test]
    fn test_ctype_display_simple_int() {
        let ct = CType { t: VT_INT, ref_sym: None };
        assert_eq!(format!("{}", ct), "int");
    }

    #[test]
    fn test_ctype_display_unsigned_int() {
        let ct = CType {
            t: VT_INT | VT_UNSIGNED,
            ref_sym: None,
        };
        assert_eq!(format!("{}", ct), "unsigned int");
    }

    #[test]
    fn test_ctype_display_void() {
        let ct = CType { t: VT_VOID, ref_sym: None };
        assert_eq!(format!("{}", ct), "void");
    }

    #[test]
    fn test_ctype_display_const_int() {
        let ct = CType {
            t: VT_INT | VT_CONSTANT,
            ref_sym: None,
        };
        assert_eq!(format!("{}", ct), "const int");
    }

    #[test]
    fn test_ctype_display_pointer() {
        // int * — pointer to int
        let int_sym = Sym {
            type_: CType { t: VT_INT, ref_sym: None },
            ..Sym::default()
        };
        let ct = CType {
            t: VT_PTR,
            ref_sym: Some(Box::new(int_sym)),
        };
        assert_eq!(format!("{}", ct), "int *");
    }

    #[test]
    fn test_ctype_display_func_pointer() {
        // void (*)(int) — function pointer returning void, taking int
        // Build: param sym (int), then func sym (returning void with param chain)
        let param_sym = Sym {
            type_: CType { t: VT_INT, ref_sym: None },
            next: None,
            ..Sym::default()
        };
        let func_sym = Sym {
            type_: CType { t: VT_VOID, ref_sym: None },
            next: Some(Box::new(param_sym)),
            f: FuncAttr { func_type: FUNC_NEW, ..FuncAttr::default() },
            ..Sym::default()
        };
        let func_type = CType {
            t: VT_FUNC,
            ref_sym: Some(Box::new(func_sym)),
        };
        // Now make a pointer to the function type
        let ptr_inner_sym = Sym {
            type_: func_type,
            ..Sym::default()
        };
        let ptr_ct = CType {
            t: VT_PTR,
            ref_sym: Some(Box::new(ptr_inner_sym)),
        };
        let display = format!("{}", ptr_ct);
        assert_eq!(display, "void (*)(int)");
    }

    #[test]
    fn test_ctype_display_long() {
        let ct = CType {
            t: VT_INT | VT_LONG,
            ref_sym: None,
        };
        assert_eq!(format!("{}", ct), "long");
    }

    #[test]
    fn test_ctype_display_unsigned_long() {
        let ct = CType {
            t: VT_INT | VT_LONG | VT_UNSIGNED,
            ref_sym: None,
        };
        assert_eq!(format!("{}", ct), "unsigned long");
    }

    #[test]
    fn test_ctype_display_double() {
        let ct = CType { t: VT_DOUBLE, ref_sym: None };
        assert_eq!(format!("{}", ct), "double");
    }

    #[test]
    fn test_ctype_display_long_double() {
        let ct = CType { t: VT_LDOUBLE, ref_sym: None };
        assert_eq!(format!("{}", ct), "long double");
    }

    #[test]
    fn test_ctype_display_bool() {
        let ct = CType { t: VT_BOOL, ref_sym: None };
        assert_eq!(format!("{}", ct), "_Bool");
    }

    #[test]
    fn test_cstring_value_default() {
        let csv = CStringValue::default();
        assert!(csv.data.is_null());
        assert_eq!(csv.size, 0);
    }

    #[test]
    fn test_token_string_default() {
        let ts = TokenString::default();
        assert!(ts.str_data.is_empty());
        assert!(!ts.need_spc);
        assert_eq!(ts.last_line_num, 0);
        assert_eq!(ts.save_line_num, 0);
        assert!(!ts.alloc);
    }

    #[test]
    fn test_sym_clone() {
        let s = Sym {
            v: 42,
            r: VT_CONST as u16,
            c: 100,
            enum_val: -5,
            ..Sym::default()
        };
        let cloned = s.clone();
        assert_eq!(cloned.v, 42);
        assert_eq!(cloned.r, VT_CONST as u16);
        assert_eq!(cloned.c, 100);
        assert_eq!(cloned.enum_val, -5);
    }

    #[test]
    fn test_dll_reference_clone() {
        let dll = DLLReference {
            level: 2,
            handle: None,
            found: true,
            index: 3,
            name: "libtest.so".to_string(),
        };
        let cloned = dll.clone();
        assert_eq!(cloned.level, 2);
        assert!(cloned.found);
        assert_eq!(cloned.index, 3);
        assert_eq!(cloned.name, "libtest.so");
    }

    #[test]
    fn test_cvalue_union_fields() {
        // Test that union fields overlap correctly
        let mut cv = CValue::default();
        cv.i = 0x4008_0000_0000_0000; // 3.0 as f64 IEEE 754 bits
        let d = unsafe { cv.d };
        assert!((d - 3.0f64).abs() < f64::EPSILON);

        cv = CValue { f: 2.5f32 };
        let f_val = unsafe { cv.f };
        assert!((f_val - 2.5f32).abs() < f32::EPSILON);
    }

    #[test]
    fn test_vt_value_constants() {
        assert_eq!(VT_VALMASK, 0x003f);
        assert_eq!(VT_CONST, 0x0030);
        assert_eq!(VT_LLOCAL, 0x0031);
        assert_eq!(VT_LOCAL, 0x0032);
        assert_eq!(VT_CMP, 0x0033);
        assert_eq!(VT_JMP, 0x0034);
        assert_eq!(VT_JMPI, 0x0035);
        assert_eq!(VT_LVAL, 0x0100);
        assert_eq!(VT_SYM, 0x0200);
        assert_eq!(VT_MUSTCAST, 0x0C00);
        assert_eq!(VT_NONCONST, 0x1000);
        assert_eq!(VT_MUSTBOUND, 0x4000);
        assert_eq!(VT_BOUNDED, 0x8000);
    }

    // BUG-07 fix verification: union/enum Display tests
    #[test]
    fn test_ctype_display_struct() {
        // A plain struct type: btype = VT_STRUCT, no union/enum tag bits
        let tag_sym = Sym {
            v: SYM_STRUCT | 42,
            ..Sym::default()
        };
        let ct = CType {
            t: VT_STRUCT,
            ref_sym: Some(Box::new(tag_sym)),
        };
        assert_eq!(format!("{}", ct), "struct <tag:42>");
    }

    #[test]
    fn test_ctype_display_union() {
        // A union type: VT_UNION = (1 << VT_STRUCT_SHIFT) | VT_STRUCT
        let tag_sym = Sym {
            v: SYM_STRUCT | 99,
            ..Sym::default()
        };
        let ct = CType {
            t: VT_UNION,
            ref_sym: Some(Box::new(tag_sym)),
        };
        assert_eq!(format!("{}", ct), "union <tag:99>");
    }

    #[test]
    fn test_ctype_display_enum() {
        // An enum type: VT_ENUM = 2 << VT_STRUCT_SHIFT (btype is VT_INT, NOT VT_STRUCT)
        let tag_sym = Sym {
            v: SYM_STRUCT | 55,
            ..Sym::default()
        };
        let ct = CType {
            // VT_ENUM has bits above VT_STRUCT_SHIFT, and the btype is actually VT_INT
            // because enums are integer types in C. But Display should still show "enum".
            t: VT_ENUM | VT_INT,
            ref_sym: Some(Box::new(tag_sym)),
        };
        assert_eq!(format!("{}", ct), "enum <tag:55>");
    }

    // Tests for new helper functions
    #[test]
    fn test_is_union() {
        assert!(is_union(VT_UNION));
        assert!(!is_union(VT_STRUCT));
        assert!(!is_union(VT_INT));
        assert!(!is_union(VT_ENUM | VT_INT));
    }

    #[test]
    fn test_is_enum() {
        assert!(is_enum(VT_ENUM | VT_INT));
        assert!(is_enum(VT_ENUM));
        assert!(!is_enum(VT_INT));
        assert!(!is_enum(VT_STRUCT));
        assert!(!is_enum(VT_UNION));
    }

    #[test]
    fn test_is_enum_val() {
        assert!(is_enum_val(VT_ENUM_VAL | VT_INT));
        assert!(!is_enum_val(VT_ENUM | VT_INT));
        assert!(!is_enum_val(VT_INT));
    }

    #[test]
    fn test_bit_pos_and_size() {
        // Encode position=5, size=8
        let t = bfval(5, 8) | VT_BITFIELD | VT_INT;
        assert_eq!(bit_pos(t), 5);
        assert_eq!(bit_size(t), 8);
    }

    #[test]
    fn test_bfval_bfget_bfset() {
        let t = bfval(3, 16);
        assert_eq!(bfget(t, 0), 3);
        assert_eq!(bfget(t, 6), 16);

        let t2 = bfset(t, 0, 7);
        assert_eq!(bfget(t2, 0), 7);
        assert_eq!(bfget(t2, 6), 16); // unchanged
    }

    // Tests for VT_ASM constants
    #[test]
    fn test_vt_asm_constants() {
        assert_eq!(VT_ASM, 0x0080_0000);
        assert_eq!(VT_ASM_FUNC, 0x0100_0000);
        // VT_ASM should not overlap with VT_BTYPE or VT_STRUCT_SHIFT range
        assert_eq!(VT_ASM & VT_BTYPE, 0);
    }

    // Tests for OutputType
    #[test]
    fn test_output_type_values() {
        assert_eq!(OutputType::Memory as i32, 1);
        assert_eq!(OutputType::Exe as i32, 2);
        assert_eq!(OutputType::Obj as i32, 3);
        assert_eq!(OutputType::Dll as i32, 4);
        assert_eq!(OutputType::Preprocess as i32, 5);
    }

    #[test]
    fn test_output_type_from_i32() {
        assert_eq!(OutputType::from_i32(1), Some(OutputType::Memory));
        assert_eq!(OutputType::from_i32(2), Some(OutputType::Exe));
        assert_eq!(OutputType::from_i32(3), Some(OutputType::Obj));
        assert_eq!(OutputType::from_i32(4), Some(OutputType::Dll));
        assert_eq!(OutputType::from_i32(5), Some(OutputType::Preprocess));
        assert_eq!(OutputType::from_i32(0), None);
        assert_eq!(OutputType::from_i32(6), None);
        assert_eq!(OutputType::from_i32(-1), None);
    }

    #[test]
    fn test_output_type_into_i32() {
        let v: i32 = OutputType::Exe.into();
        assert_eq!(v, 2);
    }

    #[test]
    fn test_output_type_try_from() {
        assert_eq!(OutputType::try_from(3), Ok(OutputType::Obj));
        assert_eq!(OutputType::try_from(99), Err(()));
    }
}
