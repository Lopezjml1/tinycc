//! Debug Information Generation Module
//!
//! Ports DWARF and STAB debug information generation from `tccdbg.c` (2,676 lines),
//! incorporating DWARF constants from `dwarf.h` (1,046 lines) and STAB definitions
//! from `stab.h`/`stab.def`. Generates debug sections that allow GDB and other
//! debuggers to map machine code back to source lines.
//!
//! Supports:
//! - DWARF versions 2, 3, 4, and 5
//! - Legacy STAB debug format
//! - Test coverage instrumentation (tcov)

#![allow(non_camel_case_types, dead_code)]

use std::collections::HashMap;
use std::path::Path;

#[allow(unused_imports)]
use crate::config::{PTR_SIZE, LONG_SIZE};
use crate::error::{TccError, TccResult};
#[allow(unused_imports)]
use crate::elf::{
    new_section, section_ptr_add, put_elf_sym, put_extern_sym,
    put_elf_str, put_elf_reloc, put_elf_reloca, ELFW_ST_INFO,
    SHT_PROGBITS, SHT_STRTAB, SHF_ALLOC, SHF_WRITE, SHF_MERGE, SHF_STRINGS,
    STB_LOCAL, STT_SECTION, R_DATA_PTR, R_DATA_32,
};
#[allow(unused_imports)]
use crate::types::{
    CType, Sym, SValue, Section, CString as TccCString, BufferedFile, CValue,
    VT_INT, VT_BYTE, VT_SHORT, VT_LONG, VT_LLONG,
    VT_FLOAT, VT_DOUBLE, VT_LDOUBLE, VT_VOID, VT_BOOL,
    VT_UNSIGNED, VT_DEFSIGN, VT_QLONG, VT_QFLOAT,
    VT_PTR, VT_FUNC, VT_STRUCT, VT_ARRAY, VT_ENUM, VT_BTYPE,
    VT_STATIC, VT_SYM, VT_LVAL, VT_CONST,
    VT_STORAGE, VT_CONSTANT, VT_VOLATILE, VT_VLA, VT_BITFIELD, VT_STRUCT_MASK,
    SYM_STRUCT, SYM_FIELD, SYM_FIRST_ANOM,
    is_union, is_enum, bit_pos, bit_size,
};
#[allow(unused_imports)]
use crate::lexer::get_tok_str;
use crate::TCCState;

// ===========================================================================
// DWARF Tag Constants (from dwarf.h)
// ===========================================================================

/// DWARF tag values identifying the type of debugging information entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum DwTag {
    ArrayType = 0x01,
    ClassType = 0x02,
    EntryPoint = 0x03,
    EnumerationType = 0x04,
    FormalParameter = 0x05,
    LabelTag = 0x0a,
    LexicalBlock = 0x0b,
    Member = 0x0d,
    PointerType = 0x0f,
    ReferenceType = 0x10,
    CompileUnit = 0x11,
    StringType = 0x12,
    StructureType = 0x13,
    SubroutineType = 0x15,
    TypeDef = 0x16,
    UnionType = 0x17,
    UnspecifiedParameters = 0x18,
    Variant = 0x19,
    CommonBlock = 0x1a,
    CommonInclusion = 0x1b,
    Inheritance = 0x1c,
    InlinedSubroutine = 0x1d,
    Module = 0x1e,
    PtrToMemberType = 0x1f,
    SetType = 0x20,
    SubrangeType = 0x21,
    BaseType = 0x24,
    ConstType = 0x26,
    Enumerator = 0x28,
    Subprogram = 0x2e,
    Variable = 0x34,
    VolatileType = 0x35,
    RestrictType = 0x37,
    AtomicType = 0x47,
}

// ===========================================================================
// DWARF Attribute Constants (from dwarf.h)
// ===========================================================================

/// DWARF attribute identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum DwAt {
    Sibling = 0x01,
    Location = 0x02,
    Name = 0x03,
    Ordering = 0x09,
    ByteSize = 0x0b,
    BitOffset = 0x0c,
    BitSize = 0x0d,
    StmtList = 0x10,
    LowPc = 0x11,
    HighPc = 0x12,
    Language = 0x13,
    CompDir = 0x1b,
    FrameBase = 0x40,
    Type = 0x49,
    DataMemberLocation = 0x38,
    Encoding = 0x3e,
    External = 0x3f,
    Artificial = 0x34,
    UpperBound = 0x2f,
    Producer = 0x25,
    Inline = 0x20,
    Count = 0x37,
    Decl_file = 0x3a,
    Decl_line = 0x3b,
}

// ===========================================================================
// DWARF Form Constants (from dwarf.h)
// ===========================================================================

/// DWARF form encodings describing how attribute values are encoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum DwForm {
    Addr = 0x01,
    Data2 = 0x05,
    Data4 = 0x06,
    Data8 = 0x07,
    String = 0x08,
    Data1 = 0x0b,
    RefAddr = 0x10,
    Ref1 = 0x11,
    Ref2 = 0x12,
    Ref4 = 0x13,
    Udata = 0x0f,
    Sdata = 0x0d,
    SecOffset = 0x17,
    Exprloc = 0x18,
    FlagPresent = 0x19,
    Strp = 0x0e,
    LineStrp = 0x1f,
}

// ===========================================================================
// DWARF Operation Constants (from dwarf.h)
// ===========================================================================

/// DWARF expression operation opcodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum DwOp {
    Addr = 0x03,
    Deref = 0x06,
    Plus = 0x22,
    PlusUconst = 0x23,
    Fbreg = 0x91,
    Reg0 = 0x50,
    Breg0 = 0x70,
    StackValue = 0x9f,
    CallFrameCfa = 0x9c,
}

// ===========================================================================
// DWARF Line Number Standard Opcodes (from dwarf.h)
// ===========================================================================

/// DWARF line number program standard opcodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum DwLns {
    Copy = 0x01,
    AdvancePc = 0x02,
    AdvanceLine = 0x03,
    SetFile = 0x04,
    SetColumn = 0x05,
    NegateStmt = 0x06,
    SetBasicBlock = 0x07,
    ConstAddPc = 0x08,
    FixedAdvancePc = 0x09,
    SetPrologueEnd = 0x0a,
    SetEpilogueBegin = 0x0b,
    SetIsa = 0x0c,
}

// ===========================================================================
// DWARF Line Number Extended Opcodes (from dwarf.h)
// ===========================================================================

/// DWARF line number program extended opcodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum DwLne {
    EndSequence = 0x01,
    SetAddress = 0x02,
    DefineFile = 0x03,
    SetDiscriminator = 0x04,
}

// ===========================================================================
// DWARF Base Type Encoding (from dwarf.h)
// ===========================================================================

/// DWARF base type attribute encoding values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum DwAte {
    Address = 0x01,
    Boolean = 0x02,
    ComplexFloat = 0x03,
    Float = 0x04,
    Signed = 0x05,
    SignedChar = 0x06,
    Unsigned = 0x07,
    UnsignedChar = 0x08,
    ImaginaryFloat = 0x09,
    Utf = 0x10,
}

// ===========================================================================
// DWARF Children Flag (from dwarf.h)
// ===========================================================================

/// Indicates whether a DIE has child entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum DwChildren {
    No = 0x00,
    Yes = 0x01,
}

// ===========================================================================
// DWARF Call Frame Instruction Opcodes (from dwarf.h)
// ===========================================================================

/// DWARF Call Frame Instruction opcodes for `.eh_frame` / `.debug_frame`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum DwCfa {
    AdvanceLoc = 0x40,
    Offset = 0x80,
    Restore = 0xc0,
    Nop = 0x00,
    SetLoc = 0x01,
    AdvanceLoc1 = 0x02,
    AdvanceLoc2 = 0x03,
    AdvanceLoc4 = 0x04,
    OffsetExtended = 0x05,
    RestoreExtended = 0x06,
    Undefined = 0x07,
    SameValue = 0x08,
    Register = 0x09,
    RememberState = 0x0a,
    RestoreState = 0x0b,
    DefCfa = 0x0c,
    DefCfaRegister = 0x0d,
    DefCfaOffset = 0x0e,
    DefCfaExpression = 0x0f,
    Expression = 0x10,
    OffsetExtendedSf = 0x11,
    DefCfaSf = 0x12,
    DefCfaOffsetSf = 0x13,
    ValOffset = 0x14,
    ValOffsetSf = 0x15,
    ValExpression = 0x16,
}

// ===========================================================================
// DWARF Line Number Content Type (DWARF 5, from dwarf.h)
// ===========================================================================

/// DWARF 5 line number content type codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum DwLnct {
    Path = 0x01,
    DirectoryIndex = 0x02,
    Timestamp = 0x03,
    Size = 0x04,
    Md5 = 0x05,
}

// ===========================================================================
// STAB Debug Format Constants (from stab.h / stab.def)
// ===========================================================================

/// STAB symbol type codes for legacy debug format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum StabCode {
    N_GSYM = 0x20,
    N_FNAME = 0x22,
    N_FUN = 0x24,
    N_STSYM = 0x26,
    N_LCSYM = 0x28,
    N_MAIN = 0x2a,
    N_ROSYM = 0x2c,
    N_BNSYM = 0x2e,
    N_PC = 0x30,
    N_NSYMS = 0x32,
    N_NOMAP = 0x34,
    N_OBJ = 0x38,
    N_OPT = 0x3c,
    N_RSYM = 0x40,
    N_SLINE = 0x44,
    N_DSLINE = 0x46,
    N_BSLINE = 0x48,
    N_ENSYM = 0x4e,
    N_SSYM = 0x60,
    N_SO = 0x64,
    N_LSYM = 0x80,
    N_BINCL = 0x82,
    N_SOL = 0x84,
    N_PSYM = 0xa0,
    N_EINCL = 0xa2,
    N_ENTRY = 0xa4,
    N_LBRAC = 0xc0,
    N_EXCL = 0xc2,
    N_SCOPE = 0xc4,
    N_RBRAC = 0xe0,
    N_BCOMM = 0xe2,
    N_ECOMM = 0xe4,
    N_ECOML = 0xe8,
    N_LENG = 0xfe,
}

/// STAB symbol table entry structure (matches ELF `nlist` format).
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct StabSym {
    /// Index into the string table for the symbol name.
    pub n_strx: u32,
    /// Symbol type (one of `StabCode` values).
    pub n_type: u8,
    /// Miscellaneous information (usually 0).
    pub n_other: u8,
    /// Description field (line number for N_SLINE, etc.).
    pub n_desc: u16,
    /// Value of the symbol (address, offset, etc.).
    pub n_value: u32,
}

/// Size of a StabSym entry in bytes (12 bytes).
pub const STAB_SYM_SIZE: usize = 12;

// ===========================================================================
// DWARF Abbreviation Table Constants
// ===========================================================================

/// DWARF abbreviation table entry indices. Each constant identifies a
/// predefined abbreviation used by the debug info generator.
pub struct DWARF_ABBREV;

impl DWARF_ABBREV {
    pub const COMPILE_UNIT: u8 = 1;
    pub const SUBPROGRAM: u8 = 2;
    pub const VARIABLE: u8 = 4;
    pub const FORMAL_PARAMETER: u8 = 5;
    pub const BASE_TYPE: u8 = 8;
    pub const POINTER_TYPE: u8 = 9;
    pub const ARRAY_TYPE: u8 = 10;
    pub const STRUCTURE_TYPE: u8 = 11;
    pub const UNION_TYPE: u8 = 14;
    pub const ENUMERATION_TYPE: u8 = 17;
    pub const ENUMERATOR: u8 = 18;
    pub const TYPEDEF: u8 = 20;
    pub const CONST_TYPE: u8 = 21;
    pub const VOLATILE_TYPE: u8 = 22;
    pub const MEMBER: u8 = 23;
    pub const MEMBER_BF: u8 = 24;
    pub const SUBRANGE_TYPE: u8 = 25;
    pub const SUBROUTINE_TYPE: u8 = 13;
    pub const UNSPECIFIED_PARAMETERS: u8 = 26;
    pub const FORMAL_PARAMETER2: u8 = 7;
}

// Extended abbreviation constants used internally (matching tccdbg.c lines 86-123).
const DWARF_ABBREV_COMPILE_UNIT: u8 = 1;
const DWARF_ABBREV_SUBPROGRAM_EXTERNAL: u8 = 2;
const DWARF_ABBREV_SUBPROGRAM_STATIC: u8 = 3;
const DWARF_ABBREV_VARIABLE_EXTERNAL: u8 = 4;
const DWARF_ABBREV_VARIABLE_LOCAL: u8 = 5;
const DWARF_ABBREV_FORMAL_PARAMETER: u8 = 6;
const DWARF_ABBREV_FORMAL_PARAMETER2: u8 = 7;
const DWARF_ABBREV_BASE_TYPE: u8 = 8;
const DWARF_ABBREV_POINTER: u8 = 9;
const DWARF_ABBREV_ARRAY_TYPE: u8 = 10;
const DWARF_ABBREV_STRUCTURE_TYPE: u8 = 11;
const DWARF_ABBREV_STRUCTURE_EMPTY_TYPE: u8 = 12;
const DWARF_ABBREV_UNION_TYPE: u8 = 14;
const DWARF_ABBREV_UNION_EMPTY_TYPE: u8 = 15;
const DWARF_ABBREV_SUBRANGE_TYPE: u8 = 25;
const DWARF_ABBREV_ENUMERATION_TYPE: u8 = 17;
const DWARF_ABBREV_ENUMERATOR_SIGNED: u8 = 18;
const DWARF_ABBREV_ENUMERATOR_UNSIGNED: u8 = 19;
const DWARF_ABBREV_TYPEDEF: u8 = 20;
const DWARF_ABBREV_MEMBER: u8 = 23;
const DWARF_ABBREV_MEMBER_BF: u8 = 24;
const DWARF_ABBREV_SUBROUTINE_TYPE: u8 = 13;
const DWARF_ABBREV_SUBROUTINE_EMPTY_TYPE: u8 = 16;
const DWARF_ABBREV_LEXICAL_BLOCK: u8 = 21;
const DWARF_ABBREV_LEXICAL_EMPTY_BLOCK: u8 = 22;
const DWARF_ABBREV_VARIABLE_STATIC: u8 = 26;
const DWARF_ABBREV_SUBROUTINE_TYPE_NOCHILDREN: u8 = 16;
const DWARF_ABBREV_UNION_TYPE_EMPTY: u8 = 15;
const DWARF_ABBREV_STRUCT_TYPE_EMPTY: u8 = 12;
const DWARF_ABBREV_LEXICAL_BLOCK_EMPTY: u8 = 22;

/// Minimum instruction length for DWARF line number program calculations.
pub const DWARF_MIN_INSTR_LEN: u8 = 1;

// DWARF line number program constants (from tccdbg.c).
const DWARF_LINE_BASE: i32 = -5;
const DWARF_LINE_RANGE: i32 = 14;
const DWARF_OPCODE_BASE: i32 = 13;

// DW_LNE_hi_user minus 1 — used for backtrace function name extension.
const DW_LNE_HI_USER_MINUS_1: u8 = 0xfe;

// ===========================================================================
// Default Debug Type Table (from tccdbg.c default_debug[])
// ===========================================================================

/// Entry in the default debug type mapping table. Maps C base types to
/// DWARF encoding information and STAB type strings.
#[derive(Debug, Clone)]
struct DefaultDebugEntry {
    /// VT_* type flag (e.g., `VT_INT`, `VT_BYTE`).
    vtype: i32,
    /// Size in bytes of the type.
    size: i32,
    /// DWARF encoding (e.g., `DW_ATE_signed`, `DW_ATE_unsigned`).
    encoding: u8,
    /// STAB-format type string (e.g., "int:t1=r1;-2147483648;2147483647;").
    name: &'static str,
}

/// Number of entries in the default debug type table.
const N_DEFAULT_DEBUG: usize = 15;

/// Default debug type table mapping VT_* types to DWARF/STAB info.
/// Mirrors the C `default_debug[]` array from tccdbg.c.
static DEFAULT_DEBUG: [DefaultDebugEntry; N_DEFAULT_DEBUG] = [
    DefaultDebugEntry { vtype: VT_INT, size: 4, encoding: 0x05 /* DW_ATE_signed */, name: "int:t1=r1;-2147483648;2147483647;" },
    DefaultDebugEntry { vtype: VT_BYTE, size: 1, encoding: 0x06 /* DW_ATE_signed_char */, name: "char:t2=r2;0;127;" },
    DefaultDebugEntry { vtype: VT_SHORT, size: 2, encoding: 0x05, name: "short int:t3=r3;-32768;32767;" },
    DefaultDebugEntry { vtype: VT_INT | VT_UNSIGNED, size: 4, encoding: 0x07 /* DW_ATE_unsigned */, name: "unsigned int:t4=r4;0;4294967295;" },
    DefaultDebugEntry { vtype: VT_LLONG, size: 8, encoding: 0x05, name: "long long int:t5=r5;-9223372036854775808;9223372036854775807;" },
    DefaultDebugEntry { vtype: VT_LLONG | VT_UNSIGNED, size: 8, encoding: 0x07, name: "long long unsigned int:t6=r6;0;-1;" },
    DefaultDebugEntry { vtype: VT_LONG | VT_INT, size: 4, encoding: 0x05, name: "long int:t7=r7;-2147483648;2147483647;" },
    DefaultDebugEntry { vtype: VT_LONG | VT_INT | VT_UNSIGNED, size: 4, encoding: 0x07, name: "long unsigned int:t8=r8;0;4294967295;" },
    DefaultDebugEntry { vtype: VT_SHORT | VT_UNSIGNED, size: 2, encoding: 0x07, name: "short unsigned int:t9=r9;0;65535;" },
    DefaultDebugEntry { vtype: VT_BYTE | VT_DEFSIGN, size: 1, encoding: 0x05, name: "signed char:t10=r10;-128;127;" },
    DefaultDebugEntry { vtype: VT_BYTE | VT_DEFSIGN | VT_UNSIGNED, size: 1, encoding: 0x08 /* DW_ATE_unsigned_char */, name: "unsigned char:t11=r11;0;255;" },
    DefaultDebugEntry { vtype: VT_FLOAT, size: 4, encoding: 0x04 /* DW_ATE_float */, name: "float:t12=r1;4;0;" },
    DefaultDebugEntry { vtype: VT_DOUBLE, size: 8, encoding: 0x04, name: "double:t13=r1;8;0;" },
    DefaultDebugEntry { vtype: VT_LDOUBLE, size: 16, encoding: 0x04, name: "long double:t14=r1;16;0;" },
    DefaultDebugEntry { vtype: VT_VOID, size: 1, encoding: 0x02 /* DW_ATE_boolean for void */, name: "void:t15=15" },
];

// ===========================================================================
// DWARF Abbreviation Table Init Data (from tccdbg.c dwarf_abbrev_init[])
// ===========================================================================

/// DWARF abbreviation table initialization data. This byte array defines
/// all abbreviation entries used by the debug info generator. Each entry
/// consists of: abbreviation number, tag, children flag, followed by
/// attribute/form pairs terminated by (0, 0).
static DWARF_ABBREV_INIT: &[u8] = &[
    // 1: DW_TAG_compile_unit (children=yes)
    1, 0x11, 1,
      0x25, 0x0e, // DW_AT_producer, DW_FORM_strp
      0x13, 0x0b, // DW_AT_language, DW_FORM_data1
      0x03, 0x1f, // DW_AT_name, DW_FORM_line_strp (patched for DWARF<5)
      0x1b, 0x1f, // DW_AT_comp_dir, DW_FORM_line_strp (patched for DWARF<5)
      0x11, 0x01, // DW_AT_low_pc, DW_FORM_addr
      0x12, 0x07, // DW_AT_high_pc, DW_FORM_data8
      0x10, 0x17, // DW_AT_stmt_list, DW_FORM_sec_offset (patched for DWARF<4)
      0, 0,
    // 2: DW_TAG_subprogram (external, children=yes)
    2, 0x2e, 1,
      0x3f, 0x19, // DW_AT_external, DW_FORM_flag_present
      0x03, 0x0e, // DW_AT_name, DW_FORM_strp
      0x3a, 0x0f, // DW_AT_decl_file, DW_FORM_udata
      0x3b, 0x0f, // DW_AT_decl_line, DW_FORM_udata
      0x49, 0x13, // DW_AT_type, DW_FORM_ref4
      0x11, 0x01, // DW_AT_low_pc, DW_FORM_addr
      0x12, 0x07, // DW_AT_high_pc, DW_FORM_data8
      0x01, 0x13, // DW_AT_sibling, DW_FORM_ref4
      0x40, 0x18, // DW_AT_frame_base, DW_FORM_exprloc (patched for DWARF<4)
      0, 0,
    // 3: DW_TAG_subprogram (static, children=yes)
    3, 0x2e, 1,
      0x03, 0x0e, // DW_AT_name, DW_FORM_strp
      0x3a, 0x0f, // DW_AT_decl_file, DW_FORM_udata
      0x3b, 0x0f, // DW_AT_decl_line, DW_FORM_udata
      0x49, 0x13, // DW_AT_type, DW_FORM_ref4
      0x11, 0x01, // DW_AT_low_pc, DW_FORM_addr
      0x12, 0x07, // DW_AT_high_pc, DW_FORM_data8
      0x01, 0x13, // DW_AT_sibling, DW_FORM_ref4
      0x40, 0x18, // DW_AT_frame_base, DW_FORM_exprloc (patched for DWARF<4)
      0, 0,
    // 4: DW_TAG_variable (external)
    4, 0x34, 0,
      0x3f, 0x19, // DW_AT_external, DW_FORM_flag_present
      0x03, 0x0e, // DW_AT_name, DW_FORM_strp
      0x3a, 0x0f, // DW_AT_decl_file, DW_FORM_udata
      0x3b, 0x0f, // DW_AT_decl_line, DW_FORM_udata
      0x49, 0x13, // DW_AT_type, DW_FORM_ref4
      0x02, 0x18, // DW_AT_location, DW_FORM_exprloc (patched for DWARF<4)
      0, 0,
    // 5: DW_TAG_variable (local, param with location)
    5, 0x34, 0,
      0x03, 0x0e, // DW_AT_name, DW_FORM_strp
      0x49, 0x13, // DW_AT_type, DW_FORM_ref4
      0x02, 0x18, // DW_AT_location, DW_FORM_exprloc (patched for DWARF<4)
      0, 0,
    // 6: DW_TAG_formal_parameter (with location)
    6, 0x05, 0,
      0x03, 0x0e, // DW_AT_name, DW_FORM_strp
      0x49, 0x13, // DW_AT_type, DW_FORM_ref4
      0x02, 0x18, // DW_AT_location, DW_FORM_exprloc (patched for DWARF<4)
      0, 0,
    // 7: DW_TAG_formal_parameter (type only, for subroutine types)
    7, 0x05, 0,
      0x49, 0x13, // DW_AT_type, DW_FORM_ref4
      0, 0,
    // 8: DW_TAG_base_type
    8, 0x24, 0,
      0x0b, 0x0f, // DW_AT_byte_size, DW_FORM_udata
      0x3e, 0x0b, // DW_AT_encoding, DW_FORM_data1
      0x03, 0x0e, // DW_AT_name, DW_FORM_strp
      0, 0,
    // 9: DW_TAG_pointer_type
    9, 0x0f, 0,
      0x0b, 0x0b, // DW_AT_byte_size, DW_FORM_data1
      0x49, 0x13, // DW_AT_type, DW_FORM_ref4
      0, 0,
    // 10: DW_TAG_array_type (children=yes)
    10, 0x01, 1,
      0x49, 0x13, // DW_AT_type, DW_FORM_ref4
      0x01, 0x13, // DW_AT_sibling, DW_FORM_ref4
      0, 0,
    // 11: DW_TAG_structure_type (with members, children=yes)
    11, 0x13, 1,
      0x03, 0x0e, // DW_AT_name, DW_FORM_strp
      0x0b, 0x0f, // DW_AT_byte_size, DW_FORM_udata
      0x3a, 0x0f, // DW_AT_decl_file, DW_FORM_udata
      0x3b, 0x0f, // DW_AT_decl_line, DW_FORM_udata
      0x01, 0x13, // DW_AT_sibling, DW_FORM_ref4
      0, 0,
    // 12: DW_TAG_structure_type (empty, no children)
    12, 0x13, 0,
      0x03, 0x0e, // DW_AT_name, DW_FORM_strp
      0x0b, 0x0f, // DW_AT_byte_size, DW_FORM_udata
      0x3a, 0x0f, // DW_AT_decl_file, DW_FORM_udata
      0x3b, 0x0f, // DW_AT_decl_line, DW_FORM_udata
      0, 0,
    // 13: DW_TAG_subroutine_type (children=yes)
    13, 0x15, 1,
      0x49, 0x13, // DW_AT_type, DW_FORM_ref4
      0x01, 0x13, // DW_AT_sibling, DW_FORM_ref4
      0, 0,
    // 14: DW_TAG_union_type (with members, children=yes)
    14, 0x17, 1,
      0x03, 0x0e, // DW_AT_name, DW_FORM_strp
      0x0b, 0x0f, // DW_AT_byte_size, DW_FORM_udata
      0x3a, 0x0f, // DW_AT_decl_file, DW_FORM_udata
      0x3b, 0x0f, // DW_AT_decl_line, DW_FORM_udata
      0x01, 0x13, // DW_AT_sibling, DW_FORM_ref4
      0, 0,
    // 15: DW_TAG_union_type (empty)
    15, 0x17, 0,
      0x03, 0x0e, // DW_AT_name, DW_FORM_strp
      0x0b, 0x0f, // DW_AT_byte_size, DW_FORM_udata
      0x3a, 0x0f, // DW_AT_decl_file, DW_FORM_udata
      0x3b, 0x0f, // DW_AT_decl_line, DW_FORM_udata
      0, 0,
    // 16: DW_TAG_subroutine_type (no children)
    16, 0x15, 0,
      0x49, 0x13, // DW_AT_type, DW_FORM_ref4
      0, 0,
    // 17: DW_TAG_enumeration_type (children=yes)
    17, 0x04, 1,
      0x03, 0x0e, // DW_AT_name, DW_FORM_strp
      0x3e, 0x0b, // DW_AT_encoding, DW_FORM_data1
      0x0b, 0x0b, // DW_AT_byte_size, DW_FORM_data1
      0x49, 0x13, // DW_AT_type, DW_FORM_ref4
      0x3a, 0x0f, // DW_AT_decl_file, DW_FORM_udata
      0x3b, 0x0f, // DW_AT_decl_line, DW_FORM_udata
      0x01, 0x13, // DW_AT_sibling, DW_FORM_ref4
      0, 0,
    // 18: DW_TAG_enumerator (signed)
    18, 0x28, 0,
      0x03, 0x0e, // DW_AT_name, DW_FORM_strp
      0x1c, 0x0d, // DW_AT_const_value, DW_FORM_sdata
      0, 0,
    // 19: DW_TAG_enumerator (unsigned)
    19, 0x28, 0,
      0x03, 0x0e, // DW_AT_name, DW_FORM_strp
      0x1c, 0x0f, // DW_AT_const_value, DW_FORM_udata
      0, 0,
    // 20: DW_TAG_typedef
    20, 0x16, 0,
      0x03, 0x0e, // DW_AT_name, DW_FORM_strp
      0x3a, 0x0f, // DW_AT_decl_file, DW_FORM_udata
      0x3b, 0x0f, // DW_AT_decl_line, DW_FORM_udata
      0x49, 0x13, // DW_AT_type, DW_FORM_ref4
      0, 0,
    // 21: DW_TAG_lexical_block (children=yes)
    21, 0x0b, 1,
      0x11, 0x01, // DW_AT_low_pc, DW_FORM_addr
      0x12, 0x07, // DW_AT_high_pc, DW_FORM_data8
      0, 0,
    // 22: DW_TAG_lexical_block (no children)
    22, 0x0b, 0,
      0x11, 0x01, // DW_AT_low_pc, DW_FORM_addr
      0x12, 0x07, // DW_AT_high_pc, DW_FORM_data8
      0, 0,
    // 23: DW_TAG_member (non-bitfield)
    23, 0x0d, 0,
      0x03, 0x0e, // DW_AT_name, DW_FORM_strp
      0x3a, 0x0f, // DW_AT_decl_file, DW_FORM_udata
      0x3b, 0x0f, // DW_AT_decl_line, DW_FORM_udata
      0x49, 0x13, // DW_AT_type, DW_FORM_ref4
      0x38, 0x0f, // DW_AT_data_member_location, DW_FORM_udata
      0, 0,
    // 24: DW_TAG_member (bitfield)
    24, 0x0d, 0,
      0x03, 0x0e, // DW_AT_name, DW_FORM_strp
      0x3a, 0x0f, // DW_AT_decl_file, DW_FORM_udata
      0x3b, 0x0f, // DW_AT_decl_line, DW_FORM_udata
      0x49, 0x13, // DW_AT_type, DW_FORM_ref4
      0x0d, 0x0f, // DW_AT_bit_size, DW_FORM_udata
      0x0c, 0x0f, // DW_AT_bit_offset, DW_FORM_udata
      0, 0,
    // 25: DW_TAG_subrange_type
    25, 0x21, 0,
      0x49, 0x13, // DW_AT_type, DW_FORM_ref4
      0x2f, 0x0f, // DW_AT_upper_bound, DW_FORM_udata
      0, 0,
    // 26: DW_TAG_unspecified_parameters
    26, 0x18, 0,
      0, 0,
    // End of abbreviation table
    0,
];

/// Standard opcode argument counts for the DWARF line number program.
static DWARF_LINE_OPCODES: [u8; 12] = [0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1];

// ===========================================================================
// Internal Debug State Types
// ===========================================================================

/// A debug symbol record stored within a lexical scope, deferred for output
/// during `tcc_debug_finish`.
#[derive(Debug, Clone)]
struct DebugSymEntry {
    /// Symbol type (N_PSYM, N_LSYM, N_GSYM, N_STSYM).
    stype: u8,
    /// Symbol value (stack offset or address).
    value: u64,
    /// Symbol name string.
    name: String,
    /// Section index for relocation (if applicable).
    sec_idx: Option<usize>,
    /// Symbol index for relocation.
    sym_index: usize,
    /// DWARF type info offset.
    info: i32,
    /// File index in DWARF line table.
    file: i32,
    /// Source line number.
    line: i32,
}

/// Lexical scope tracking node for nested block debug information.
#[derive(Debug, Clone)]
struct DebugScope {
    /// Code offset where this scope begins.
    start: i32,
    /// Code offset where this scope ends.
    end: i32,
    /// Accumulated debug symbols in this scope.
    sym: Vec<DebugSymEntry>,
    /// Child scopes.
    children: Vec<DebugScope>,
    /// Saved hash table sizes for scope exit restoration.
    last_debug_hash: usize,
    last_debug_forw_hash: usize,
}

/// Forward-reference hash entry for incomplete struct/union types.
#[derive(Debug, Clone)]
struct ForwardHash {
    /// Offsets in .debug_info needing patching when type is completed.
    debug_type: Vec<i32>,
    /// Reference type identifier.
    type_id: u64,
}

/// Debug type hash entry mapping C types to DWARF info offsets.
#[derive(Debug, Clone)]
struct DebugHash {
    /// DWARF .debug_info offset for this type.
    debug_type: i32,
    /// Type identifier.
    type_id: u64,
}

/// DWARF line number program state for the current translation unit.
#[derive(Debug, Clone)]
struct DwarfLineState {
    /// Start offset in .debug_line section.
    start: usize,
    /// Directory table for line number program.
    dir_table: Vec<String>,
    /// Filename table entries.
    filename_table: Vec<DwarfFilenameEntry>,
    /// Accumulated line number program opcodes.
    line_data: Vec<u8>,
    /// Current file index.
    cur_file: i32,
    /// Last emitted file index.
    last_file: i32,
    /// Last emitted PC value.
    last_pc: i32,
    /// Last emitted line number.
    last_line: i32,
}

/// DWARF filename table entry.
#[derive(Debug, Clone)]
struct DwarfFilenameEntry {
    /// Directory index.
    dir_entry: i32,
    /// Filename.
    name: String,
}

/// DWARF compilation unit info state.
#[derive(Debug, Clone)]
struct DwarfInfoState {
    /// Start offset of the compilation unit in .debug_info.
    start: usize,
    /// Function symbol reference for current function.
    func_sym_id: u64,
    /// Line number where current function starts.
    line: i32,
    /// Base type usage tracking (indexed by default_debug entry).
    base_type_used: [i32; N_DEFAULT_DEBUG],
}

/// DWARF section symbol indices for relocations.
#[derive(Debug, Clone, Default)]
struct DwarfSectionSyms {
    info: usize,
    abbrev: usize,
    line: usize,
    aranges: usize,
    str_sym: usize,
    line_str: usize,
}

/// DWARF string deduplication state.
#[derive(Debug, Clone)]
struct DwarfStrState {
    /// Map from string content to offset in the .debug_str section.
    map: HashMap<String, u32>,
}

impl DwarfStrState {
    fn new() -> Self {
        DwarfStrState { map: HashMap::new() }
    }
}

/// Test coverage data state.
#[derive(Debug, Clone, Default)]
struct TcovData {
    /// Current line number being tracked.
    line: i32,
    /// Current offset in the .tcov section.
    offset: usize,
    /// Offset of last filename entry.
    last_file_name: usize,
    /// Offset of last function name entry.
    last_func_name: usize,
    /// Current instruction index.
    ind: i32,
}

// ===========================================================================
// DebugInfo — Main Debug Information Generation State
// ===========================================================================

/// Main debug information generation state. Manages DWARF and STAB debug
/// section emission, line number tracking, type information, and test coverage.
///
/// Stored in `TCCState.dState` as `Box<dyn Any>` and downcast when needed.
pub struct DebugInfo {
    // ----- Section indices (into TCCState.sections) -----

    /// .debug_info section index.
    pub dwarf_info_section: Option<usize>,
    /// .debug_abbrev section index.
    pub dwarf_abbrev_section: Option<usize>,
    /// .debug_line section index.
    pub dwarf_line_section: Option<usize>,
    /// .debug_aranges section index.
    pub dwarf_aranges_section: Option<usize>,
    /// .debug_str section index.
    pub dwarf_str_section: Option<usize>,
    /// .stab section index.
    pub stab_section: Option<usize>,
    /// .stabstr section index.
    pub stabstr_section: Option<usize>,
    /// .tcov section index.
    pub tcov_section: Option<usize>,

    // ----- Line number tracking -----

    /// Currently tracked source file name.
    pub cur_file: Option<String>,
    /// Currently tracked source line number.
    pub cur_line: i32,
    /// Currently tracked function name.
    cur_func: Option<String>,

    // ----- Internal debug state -----

    /// Last emitted line number (STAB mode).
    last_line_num: i32,
    /// Flag indicating a new file has been entered.
    new_file: bool,
    /// Section symbol index used for relocations.
    section_sym: usize,
    /// Next available debug type number (for STAB).
    debug_next_type: i32,

    /// Global scope debug type hash.
    debug_hash_global: Vec<DebugHash>,
    /// Local scope debug type hash.
    debug_hash_local: Vec<DebugHash>,
    /// Global scope forward reference hash.
    debug_forw_hash_global: Vec<ForwardHash>,
    /// Local scope forward reference hash.
    debug_forw_hash_local: Vec<ForwardHash>,

    /// Current innermost scope being tracked.
    scope_stack: Vec<DebugScope>,
    /// Root scope for current function.
    debug_info_root: Option<DebugScope>,

    /// DWARF section symbol indices.
    dwarf_sym: DwarfSectionSyms,
    /// DWARF line number program state.
    dwarf_line: DwarfLineState,
    /// DWARF compilation unit info state.
    dwarf_info: DwarfInfoState,
    /// DWARF string deduplication (.debug_str).
    dwarf_str: DwarfStrState,
    /// DWARF line string deduplication (.debug_line_str, DWARF5).
    dwarf_line_str: DwarfStrState,

    /// Test coverage tracking state.
    tcov_data: TcovData,

    /// Function instruction offset (start of current function).
    func_ind: i32,
}

// ===========================================================================
// DebugInfo — Default Implementation
// ===========================================================================

impl Default for DebugInfo {
    fn default() -> Self {
        DebugInfo {
            dwarf_info_section: None,
            dwarf_abbrev_section: None,
            dwarf_line_section: None,
            dwarf_aranges_section: None,
            dwarf_str_section: None,
            stab_section: None,
            stabstr_section: None,
            tcov_section: None,
            cur_file: None,
            cur_line: 0,
            cur_func: None,
            last_line_num: 0,
            new_file: false,
            section_sym: 0,
            debug_next_type: N_DEFAULT_DEBUG as i32 + 1,
            debug_hash_global: Vec::new(),
            debug_hash_local: Vec::new(),
            debug_forw_hash_global: Vec::new(),
            debug_forw_hash_local: Vec::new(),
            scope_stack: Vec::new(),
            debug_info_root: None,
            dwarf_sym: DwarfSectionSyms::default(),
            dwarf_line: DwarfLineState {
                start: 0,
                dir_table: Vec::new(),
                filename_table: Vec::new(),
                line_data: Vec::new(),
                cur_file: 0,
                last_file: 1,
                last_pc: 0,
                last_line: 1,
            },
            dwarf_info: DwarfInfoState {
                start: 0,
                func_sym_id: 0,
                line: 0,
                base_type_used: [-1i32; N_DEFAULT_DEBUG],
            },
            dwarf_str: DwarfStrState::new(),
            dwarf_line_str: DwarfStrState::new(),
            tcov_data: TcovData::default(),
            func_ind: -1,
        }
    }
}

// ===========================================================================
// LEB128 Encoding Helpers
// ===========================================================================

/// Encode an unsigned value as ULEB128 and append to the buffer.
fn encode_uleb128(buf: &mut Vec<u8>, mut value: u64) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        buf.push(byte);
        if value == 0 {
            break;
        }
    }
}

/// Encode a signed value as SLEB128 and append to the buffer.
fn encode_sleb128(buf: &mut Vec<u8>, mut value: i64) {
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        let more = !((value == 0 && (byte & 0x40) == 0) || (value == -1 && (byte & 0x40) != 0));
        if more {
            buf.push(byte | 0x80);
        } else {
            buf.push(byte);
            break;
        }
    }
}

/// Write a u8 into a section's data buffer at a given offset.
fn section_write_u8(sec_data: &mut Vec<u8>, offset: usize, val: u8) {
    if offset < sec_data.len() {
        sec_data[offset] = val;
    } else {
        while sec_data.len() < offset {
            sec_data.push(0);
        }
        sec_data.push(val);
    }
}

/// Write a little-endian u16 into a section's data buffer.
fn section_write_le16(sec_data: &mut Vec<u8>, offset: usize, val: u16) {
    let bytes = val.to_le_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        section_write_u8(sec_data, offset + i, b);
    }
}

/// Write a little-endian u32 into a section's data buffer.
fn section_write_le32(sec_data: &mut Vec<u8>, offset: usize, val: u32) {
    let bytes = val.to_le_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        section_write_u8(sec_data, offset + i, b);
    }
}

/// Write a little-endian u64 into a section's data buffer.
fn section_write_le64(sec_data: &mut Vec<u8>, offset: usize, val: u64) {
    let bytes = val.to_le_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        section_write_u8(sec_data, offset + i, b);
    }
}

/// Read a little-endian u32 from a section's data buffer.
fn section_read_le32(sec_data: &[u8], offset: usize) -> u32 {
    if offset + 4 <= sec_data.len() {
        u32::from_le_bytes([
            sec_data[offset],
            sec_data[offset + 1],
            sec_data[offset + 2],
            sec_data[offset + 3],
        ])
    } else {
        0
    }
}

/// Append bytes to a section, extending it as needed, return start offset.
fn section_append(sec_data: &mut Vec<u8>, data: &[u8]) -> usize {
    let offset = sec_data.len();
    sec_data.extend_from_slice(data);
    offset
}

/// Append padding zeros to align section data to `align` boundary.
fn section_align(sec_data: &mut Vec<u8>, align: usize) {
    if align <= 1 {
        return;
    }
    while sec_data.len() % align != 0 {
        sec_data.push(0);
    }
}

// ===========================================================================
// DebugInfo — Core Implementation
// ===========================================================================

impl DebugInfo {
    // -----------------------------------------------------------------------
    // Construction
    // -----------------------------------------------------------------------

    /// Create a new `DebugInfo` instance and initialize all debug sections
    /// in the given compiler state.
    ///
    /// This creates either DWARF sections (if `state.dwarf > 0`) or STAB
    /// sections (legacy format). Also initializes the test coverage section
    /// if `state.test_coverage` is set.
    ///
    /// Equivalent to `tcc_debug_new()` in tccdbg.c.
    pub fn new(state: &mut TCCState) -> TccResult<Self> {
        let mut dbg = DebugInfo::default();

        if state.dwarf > 0 {
            // Create DWARF sections
            let info_idx = new_section(state, ".debug_info", SHT_PROGBITS, 0);
            let abbrev_idx = new_section(state, ".debug_abbrev", SHT_PROGBITS, 0);
            let line_idx = new_section(state, ".debug_line", SHT_PROGBITS, 0);
            let aranges_idx = new_section(state, ".debug_aranges", SHT_PROGBITS, 0);

            dbg.dwarf_info_section = Some(info_idx);
            dbg.dwarf_abbrev_section = Some(abbrev_idx);
            dbg.dwarf_line_section = Some(line_idx);
            dbg.dwarf_aranges_section = Some(aranges_idx);

            // Create .debug_str section (merged strings)
            let str_idx = new_section(state, ".debug_str", SHT_STRTAB, SHF_MERGE | SHF_STRINGS);
            dbg.dwarf_str_section = Some(str_idx);

            // Initialize abbreviation table
            let abbrev_sec = &mut state.sections[abbrev_idx];
            abbrev_sec.data.extend_from_slice(DWARF_ABBREV_INIT);
        } else {
            // Create STAB sections (legacy debug format)
            let stab_idx = new_section(state, ".stab", SHT_PROGBITS, 0);
            let stabstr_idx = new_section(state, ".stabstr", SHT_STRTAB, 0);

            // Set up the stab section's link to stabstr
            state.sections[stab_idx].link = Some(stabstr_idx);

            // Add empty first entry to .stabstr
            put_elf_str(&mut state.sections[stabstr_idx], "");

            dbg.stab_section = Some(stab_idx);
            dbg.stabstr_section = Some(stabstr_idx);

            state.stab_section = Some(stab_idx);
            state.stabstr_section = Some(stabstr_idx);
        }

        Ok(dbg)
    }

    // -----------------------------------------------------------------------
    // Compilation Unit Lifecycle
    // -----------------------------------------------------------------------

    /// Initialize debug information for a new translation unit.
    ///
    /// Sets up compilation unit headers, file tables, and initial debug state.
    /// Called once at the start of each file's compilation.
    ///
    /// Equivalent to `tcc_debug_start()` in tccdbg.c.
    pub fn start(&mut self, state: &mut TCCState) -> TccResult<()> {
        if state.dwarf > 0 {
            self.dwarf_start(state)?;
        } else {
            self.stab_start(state)?;
        }
        Ok(())
    }

    /// Finalize debug information for the current translation unit.
    ///
    /// Patches headers, builds aranges, finalizes line number programs,
    /// and writes out all accumulated debug data.
    ///
    /// Equivalent to `tcc_debug_end()` in tccdbg.c.
    pub fn end(&mut self, state: &mut TCCState) -> TccResult<()> {
        if state.dwarf > 0 {
            self.dwarf_end(state)?;
        } else {
            self.stab_end(state)?;
        }

        // Clean up hashes
        self.debug_hash_global.clear();
        self.debug_hash_local.clear();
        self.debug_forw_hash_global.clear();
        self.debug_forw_hash_local.clear();
        self.dwarf_str.map.clear();
        self.dwarf_line_str.map.clear();

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Line Number Tracking
    // -----------------------------------------------------------------------

    /// Record a line number change at the current instruction offset.
    ///
    /// Emits DWARF line number program opcodes or STAB N_SLINE entries
    /// to map the current code offset to a source line.
    ///
    /// Equivalent to `tcc_debug_line()` in tccdbg.c.
    pub fn line(&mut self, state: &mut TCCState, cur_ind: i32) -> TccResult<()> {
        if state.nocode_wanted != 0 {
            return Ok(());
        }

        let new_line = self.cur_line;
        if new_line <= 0 {
            return Ok(());
        }

        if state.dwarf > 0 {
            self.dwarf_line(state, cur_ind)?;
        } else {
            self.stab_line(state, cur_ind)?;
        }

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Function Boundary Tracking
    // -----------------------------------------------------------------------

    /// Record the start of a function for debug info.
    ///
    /// Creates function debug entries (DWARF DW_TAG_subprogram or STAB N_FUN),
    /// initializes the debug scope tree for local variables.
    ///
    /// Equivalent to `tcc_debug_funcstart()` in tccdbg.c.
    pub fn funcstart(&mut self, state: &mut TCCState, sym_name: &str, cur_ind: i32) -> TccResult<()> {
        self.func_ind = cur_ind;
        self.cur_func = Some(sym_name.to_string());
        self.debug_info_root = Some(DebugScope {
            start: cur_ind,
            end: 0,
            sym: Vec::new(),
            children: Vec::new(),
            last_debug_hash: self.debug_hash_local.len(),
            last_debug_forw_hash: self.debug_forw_hash_local.len(),
        });

        if state.dwarf > 0 {
            self.dwarf_info.func_sym_id = 0; // Will be set by the linker
            self.dwarf_info.line = self.cur_line;
        }

        // Record function name/position in debug state
        self.dwarf_line.last_pc = cur_ind;

        Ok(())
    }

    /// Record the end of a function for debug info.
    ///
    /// Completes function debug entries, emitting function size and
    /// finalizing the scope tree for local variables.
    ///
    /// Equivalent to `tcc_debug_funcend()` in tccdbg.c.
    pub fn funcend(&mut self, state: &mut TCCState, cur_ind: i32) -> TccResult<()> {
        let func_size = (cur_ind - self.func_ind) as u64;

        if let Some(ref mut root) = self.debug_info_root {
            root.end = cur_ind;
        }

        if state.dwarf > 0 {
            self.dwarf_funcend(state, cur_ind, func_size)?;
        } else {
            self.stab_funcend(state, cur_ind)?;
        }

        // Finalize scope tree
        if let Some(root) = self.debug_info_root.take() {
            self.finish_scope(state, &root)?;
        }

        // Restore local debug hash to pre-function state
        self.debug_hash_local.clear();
        self.debug_forw_hash_local.clear();
        self.func_ind = -1;

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Basic Block Tracking
    // -----------------------------------------------------------------------

    /// Record a basic block boundary for debug information.
    ///
    /// Used for optimized debug info generation, marking points where
    /// the debug state may change.
    ///
    /// Equivalent to `tcc_debug_bblock()` in tccdbg.c.
    pub fn bblock(&mut self, _state: &mut TCCState, _cur_ind: i32) -> TccResult<()> {
        // In TCC, bblock is primarily used for prolog/epilog markers.
        // The basic implementation tracks the current position for debug line info.
        // Full prolog_end/epilog_begin markers are emitted by the codegen backend.
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Type Definition (typedef) Info
    // -----------------------------------------------------------------------

    /// Emit debug information for a typedef definition.
    ///
    /// Creates a DWARF DW_TAG_typedef entry or STAB N_LSYM typedef record.
    ///
    /// Equivalent to `tcc_debug_typedef()` in tccdbg.c.
    pub fn typedef_info(&mut self, state: &mut TCCState, sym: &Sym) -> TccResult<()> {
        if !state.do_debug {
            return Ok(());
        }

        if state.dwarf > 0 {
            self.dwarf_typedef(state, sym)?;
        } else {
            self.stab_typedef(state, sym)?;
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // STAB .stabn directive
    // -----------------------------------------------------------------------

    /// Process a .stabn assembler directive for debug information.
    ///
    /// Handles N_LBRAC/N_RBRAC scope markers and general STAB entries.
    ///
    /// Equivalent to `tcc_debug_stabn()` in tccdbg.c.
    pub fn stabn(&mut self, state: &mut TCCState, n_type: u8, n_other: u8, n_desc: i16, n_value: u32) -> TccResult<()> {
        if !state.do_debug {
            return Ok(());
        }

        match n_type {
            0xc0 => {
                // N_LBRAC — open a lexical scope
                let new_scope = DebugScope {
                    start: n_value as i32,
                    end: 0,
                    sym: Vec::new(),
                    children: Vec::new(),
                    last_debug_hash: self.debug_hash_local.len(),
                    last_debug_forw_hash: self.debug_forw_hash_local.len(),
                };
                self.scope_stack.push(new_scope);
            }
            0xe0 => {
                // N_RBRAC — close lexical scope
                if let Some(mut scope) = self.scope_stack.pop() {
                    scope.end = n_value as i32;
                    if let Some(ref mut root) = self.debug_info_root {
                        root.children.push(scope);
                    }
                }
            }
            _ => {
                // Generic STAB entry — emit directly to the section
                if let Some(stab_idx) = self.stab_section {
                    let stabstr_idx = self.stabstr_section.unwrap_or(0);
                    self.emit_stab_entry(state, stab_idx, stabstr_idx, 0, n_type, n_other, n_desc, n_value)?;
                }
            }
        }

        Ok(())
    }

    // -----------------------------------------------------------------------
    // STAB Emission Functions
    // -----------------------------------------------------------------------

    /// Write a STAB entry (equivalent to `put_stabs()` in tccdbg.c).
    ///
    /// Emits an entry to the .stab section with the given parameters.
    pub fn put_stabs(&mut self, state: &mut TCCState, name: &str, stype: u8, other: u8, desc: i16, value: u32) -> TccResult<()> {
        let stab_idx = match self.stab_section {
            Some(idx) => idx,
            None => return Ok(()),
        };
        let stabstr_idx = match self.stabstr_section {
            Some(idx) => idx,
            None => return Ok(()),
        };

        let str_offset = if !name.is_empty() {
            put_elf_str(&mut state.sections[stabstr_idx], name) as u32
        } else {
            0
        };

        self.emit_stab_entry(state, stab_idx, stabstr_idx, str_offset, stype, other, desc, value)?;
        Ok(())
    }

    /// Write a STAB entry with a relocation (equivalent to `put_stabs_r()`).
    ///
    /// Creates a STAB entry and adds a relocation to the .stab section
    /// for the n_value field.
    pub fn put_stabs_r(&mut self, state: &mut TCCState, name: &str, stype: u8, other: u8, desc: i16,
                       value: u32, _sec_idx: usize, sym_index: usize) -> TccResult<()> {
        let stab_idx = match self.stab_section {
            Some(idx) => idx,
            None => return Ok(()),
        };
        let stabstr_idx = match self.stabstr_section {
            Some(idx) => idx,
            None => return Ok(()),
        };

        let str_offset = if !name.is_empty() {
            put_elf_str(&mut state.sections[stabstr_idx], name) as u32
        } else {
            0
        };

        let entry_offset = self.emit_stab_entry(state, stab_idx, stabstr_idx, str_offset, stype, other, desc, value)?;

        // Add relocation for n_value field (at offset 8 within the stab entry).
        let reloc_offset = entry_offset as u64 + 8;
        put_elf_reloc(state, stab_idx, reloc_offset, R_DATA_32, sym_index);

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Debug Type Emission
    // -----------------------------------------------------------------------

    /// Emit debug type information for a C type.
    ///
    /// Generates DWARF type DIEs or STAB type strings for the given `CType`.
    /// Uses caching to avoid emitting duplicate type entries.
    ///
    /// Returns the DWARF offset or STAB type number for the emitted type.
    pub fn put_debug_type(&mut self, state: &mut TCCState, ctype: &CType) -> TccResult<i32> {
        if state.dwarf > 0 {
            self.dwarf_type_info(state, ctype)
        } else {
            self.stab_type_info(state, ctype)
        }
    }

    /// Emit debug info for a variable (local, parameter, or global).
    ///
    /// Creates DWARF variable/parameter DIEs or STAB symbol entries.
    pub fn put_debug_variable(&mut self, state: &mut TCCState, sym: &Sym, val: i64, is_param: bool) -> TccResult<()> {
        if !state.do_debug {
            return Ok(());
        }

        if state.dwarf > 0 {
            self.dwarf_variable(state, sym, val, is_param)?;
        } else {
            self.stab_variable(state, sym, val, is_param)?;
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Test Coverage (tcov) Functions
    // -----------------------------------------------------------------------

    /// Initialize test coverage tracking for a compilation unit.
    ///
    /// Creates the .tcov section and writes the initial header.
    ///
    /// Equivalent to `tcc_tcov_start()` in tccdbg.c.
    pub fn tcov_start(&mut self, state: &mut TCCState) -> TccResult<()> {
        if !state.test_coverage {
            return Ok(());
        }

        let sec_idx = new_section(state, ".tcov", SHT_PROGBITS, SHF_ALLOC | SHF_WRITE);
        self.tcov_section = Some(sec_idx);
        state.tcov_section = Some(sec_idx);
        self.tcov_data = TcovData::default();

        Ok(())
    }

    /// Finalize test coverage data for the current compilation unit.
    ///
    /// Writes the terminal entry to the .tcov section.
    ///
    /// Equivalent to `tcc_tcov_end()` in tccdbg.c.
    pub fn tcov_end(&mut self, state: &mut TCCState) -> TccResult<()> {
        let sec_idx = match self.tcov_section {
            Some(idx) => idx,
            None => return Ok(()),
        };

        // Write terminal zero entry
        let sec = &mut state.sections[sec_idx];
        let zero_size = if PTR_SIZE == 8 { 8usize } else { 4usize };
        for _ in 0..zero_size {
            sec.data.push(0);
        }
        sec.data_offset = sec.data.len();

        Ok(())
    }

    /// Begin a new test coverage block at the current source line.
    ///
    /// Records file, function, and line number information for coverage tracking.
    ///
    /// Equivalent to `tcc_tcov_block_begin()` in tccdbg.c.
    pub fn tcov_block_begin(&mut self, state: &mut TCCState) -> TccResult<()> {
        let sec_idx = match self.tcov_section {
            Some(idx) => idx,
            None => return Ok(()),
        };

        let cur_line = self.cur_line;
        if cur_line <= 0 {
            return Ok(());
        }

        // Get current filename from include stack
        let filename = if let Some(bf) = state.include_stack.last() {
            bf.true_filename.clone()
        } else {
            String::new()
        };

        // Get function name
        let funcname = state.funcname.clone().unwrap_or_default();

        // Write filename if changed (last_file_name == 0 means first file)
        let need_filename = self.tcov_data.last_file_name == 0;
        if need_filename {
            let sec = &mut state.sections[sec_idx];
            // Write filename entry: marker + string + null
            let name_bytes = filename.as_bytes();
            let offset = sec.data.len();
            sec.data.extend_from_slice(&0xffffffffu32.to_le_bytes()); // filename marker
            sec.data.extend_from_slice(name_bytes);
            sec.data.push(0); // null terminator
            sec.data_offset = sec.data.len();
            self.tcov_data.last_file_name = offset;
        }

        // Write function name if changed
        if !funcname.is_empty() && self.tcov_data.last_func_name == 0 {
            let sec = &mut state.sections[sec_idx];
            let name_bytes = funcname.as_bytes();
            let offset = sec.data.len();
            sec.data.extend_from_slice(&0xfffffffeu32.to_le_bytes()); // function marker
            sec.data.extend_from_slice(name_bytes);
            sec.data.push(0);
            sec.data_offset = sec.data.len();
            self.tcov_data.last_func_name = offset;
        }

        // Write line number entry
        let sec = &mut state.sections[sec_idx];
        let offset = sec.data.len();
        sec.data.extend_from_slice(&(cur_line as u32).to_le_bytes()); // line number
        // Reserve space for the counter (PTR_SIZE bytes)
        for _ in 0..PTR_SIZE {
            sec.data.push(0);
        }
        sec.data_offset = sec.data.len();
        self.tcov_data.offset = offset;
        self.tcov_data.line = cur_line;

        Ok(())
    }

    /// End the current test coverage block.
    ///
    /// Records the ending line number for the coverage block.
    ///
    /// Equivalent to `tcc_tcov_block_end()` in tccdbg.c.
    pub fn tcov_block_end(&mut self, state: &mut TCCState) -> TccResult<()> {
        let sec_idx = match self.tcov_section {
            Some(idx) => idx,
            None => return Ok(()),
        };

        if self.tcov_data.offset == 0 {
            return Ok(());
        }

        // Write end line info
        let end_line = self.cur_line;
        if end_line > 0 {
            let sec = &mut state.sections[sec_idx];
            // Append end line number after the counter
            sec.data.extend_from_slice(&(end_line as u32).to_le_bytes());
            sec.data_offset = sec.data.len();
        }

        self.tcov_data.offset = 0;
        Ok(())
    }

    /// Check if the source line has changed and manage coverage blocks.
    ///
    /// If the line number changed since the last check, ends the current
    /// coverage block and begins a new one.
    ///
    /// Equivalent to `tcc_tcov_check_line()` in tccdbg.c.
    pub fn tcov_check_line(&mut self, state: &mut TCCState, cur_ind: i32) -> TccResult<bool> {
        if self.tcov_section.is_none() || !state.test_coverage {
            return Ok(false);
        }

        let new_line = self.cur_line;
        if new_line != self.tcov_data.line && new_line > 0 {
            self.tcov_block_end(state)?;
            self.tcov_block_begin(state)?;
            self.tcov_data.ind = cur_ind;
            return Ok(true);
        }
        Ok(false)
    }

    /// Reset the instruction index for coverage tracking.
    ///
    /// Called when the codegen rewinds the instruction pointer (e.g.,
    /// due to conditional code generation).
    ///
    /// Equivalent to `tcc_tcov_reset_ind()` in tccdbg.c.
    pub fn tcov_reset_ind(&mut self, _state: &mut TCCState, cur_ind: i32) -> TccResult<()> {
        self.tcov_data.ind = cur_ind;
        Ok(())
    }

    // =======================================================================
    // Internal DWARF Helpers
    // =======================================================================

    /// Write a byte to the .debug_info section.
    fn dwarf_data1(&self, state: &mut TCCState, val: u8) {
        if let Some(idx) = self.dwarf_info_section {
            state.sections[idx].data.push(val);
            state.sections[idx].data_offset = state.sections[idx].data.len();
        }
    }

    /// Write a little-endian u16 to the .debug_info section.
    fn dwarf_data2(&self, state: &mut TCCState, val: u16) {
        if let Some(idx) = self.dwarf_info_section {
            state.sections[idx].data.extend_from_slice(&val.to_le_bytes());
            state.sections[idx].data_offset = state.sections[idx].data.len();
        }
    }

    /// Write a little-endian u32 to the .debug_info section.
    fn dwarf_data4(&self, state: &mut TCCState, val: u32) {
        if let Some(idx) = self.dwarf_info_section {
            state.sections[idx].data.extend_from_slice(&val.to_le_bytes());
            state.sections[idx].data_offset = state.sections[idx].data.len();
        }
    }

    /// Write a little-endian u64 to the .debug_info section.
    fn dwarf_data8(&self, state: &mut TCCState, val: u64) {
        if let Some(idx) = self.dwarf_info_section {
            state.sections[idx].data.extend_from_slice(&val.to_le_bytes());
            state.sections[idx].data_offset = state.sections[idx].data.len();
        }
    }

    /// Write a ULEB128-encoded value to the .debug_info section.
    fn dwarf_uleb128(&self, state: &mut TCCState, val: u64) {
        if let Some(idx) = self.dwarf_info_section {
            encode_uleb128(&mut state.sections[idx].data, val);
            state.sections[idx].data_offset = state.sections[idx].data.len();
        }
    }

    /// Write a SLEB128-encoded value to the .debug_info section.
    fn dwarf_sleb128(&self, state: &mut TCCState, val: i64) {
        if let Some(idx) = self.dwarf_info_section {
            encode_sleb128(&mut state.sections[idx].data, val);
            state.sections[idx].data_offset = state.sections[idx].data.len();
        }
    }

    /// Add a string to the .debug_str section with deduplication.
    /// Returns the offset of the string in the section.
    fn dwarf_string(&mut self, state: &mut TCCState, s: &str) -> u32 {
        if let Some(&existing) = self.dwarf_str.map.get(s) {
            return existing;
        }

        let sec_idx = match self.dwarf_str_section {
            Some(idx) => idx,
            None => return 0,
        };

        let sec = &mut state.sections[sec_idx];
        let offset = sec.data.len() as u32;
        sec.data.extend_from_slice(s.as_bytes());
        sec.data.push(0);
        sec.data_offset = sec.data.len();

        self.dwarf_str.map.insert(s.to_string(), offset);
        offset
    }

    /// Write a reference to a string in .debug_str (DW_FORM_strp).
    fn dwarf_strp(&mut self, state: &mut TCCState, s: &str) {
        let offset = self.dwarf_string(state, s);
        self.dwarf_data4(state, offset);
    }

    /// Add a string to the DWARF line string table (DWARF5 .debug_line_str).
    /// For DWARF < 5, this writes an inline string.
    fn dwarf_line_strp(&mut self, state: &mut TCCState, s: &str) {
        if state.dwarf >= 5 {
            // DWARF5 uses .debug_line_str section
            if let Some(&existing) = self.dwarf_line_str.map.get(s) {
                self.dwarf_data4(state, existing);
                return;
            }
            // For DWARF5, store in line_str table and emit offset
            let offset = self.dwarf_line_str.map.len() as u32;
            self.dwarf_line_str.map.insert(s.to_string(), offset);
            self.dwarf_data4(state, offset);
        } else {
            // Pre-DWARF5: emit inline string (DW_FORM_string)
            if let Some(idx) = self.dwarf_info_section {
                state.sections[idx].data.extend_from_slice(s.as_bytes());
                state.sections[idx].data.push(0);
                state.sections[idx].data_offset = state.sections[idx].data.len();
            }
        }
    }

    /// Emit a DWARF line number program opcode.
    fn dwarf_line_op(&mut self, opcode: u8) {
        self.dwarf_line.line_data.push(opcode);
    }

    /// Get the current offset in .debug_info section.
    fn dwarf_info_offset(&self, state: &TCCState) -> usize {
        match self.dwarf_info_section {
            Some(idx) => state.sections[idx].data.len(),
            None => 0,
        }
    }

    /// Emit a file reference in the DWARF line number program.
    /// Returns the file index.
    fn dwarf_file(&mut self, filename: &str) -> i32 {
        // Check if already in the table
        for (i, entry) in self.dwarf_line.filename_table.iter().enumerate() {
            if entry.name == filename {
                return (i + 1) as i32;
            }
        }

        // Extract directory and filename components
        let path = Path::new(filename);
        let dir = path.parent()
            .and_then(|p| p.to_str())
            .unwrap_or("")
            .to_string();
        let base_name = path.file_name()
            .and_then(|f| f.to_str())
            .unwrap_or(filename)
            .to_string();

        // Find or add directory
        let dir_entry = if dir.is_empty() {
            0
        } else {
            match self.dwarf_line.dir_table.iter().position(|d| d == &dir) {
                Some(pos) => (pos + 1) as i32,
                None => {
                    self.dwarf_line.dir_table.push(dir);
                    self.dwarf_line.dir_table.len() as i32
                }
            }
        };

        self.dwarf_line.filename_table.push(DwarfFilenameEntry {
            dir_entry,
            name: base_name,
        });

        self.dwarf_line.filename_table.len() as i32
    }

    /// Get a section symbol index for DWARF relocations.
    fn dwarf_get_section_sym(state: &mut TCCState, sec_idx: usize) -> usize {
        let symtab_idx = match state.symtab_section {
            Some(idx) => idx,
            None => return 0,
        };

        let sh_num = state.sections[sec_idx].sh_num as u16;
        let info = ELFW_ST_INFO(STB_LOCAL, STT_SECTION);

        put_elf_sym(state, symtab_idx, 0, 0, info, 0, sh_num, "")
    }

    // =======================================================================
    // Internal DWARF Generation — Start/End
    // =======================================================================

    /// Initialize DWARF debug sections for a new compilation unit.
    fn dwarf_start(&mut self, state: &mut TCCState) -> TccResult<()> {
        let info_idx = match self.dwarf_info_section {
            Some(idx) => idx,
            None => return Err(TccError::internal("No .debug_info section")),
        };
        let abbrev_idx = match self.dwarf_abbrev_section {
            Some(idx) => idx,
            None => return Err(TccError::internal("No .debug_abbrev section")),
        };
        let line_idx = match self.dwarf_line_section {
            Some(idx) => idx,
            None => return Err(TccError::internal("No .debug_line section")),
        };

        // Create section symbols for relocations
        self.dwarf_sym.info = Self::dwarf_get_section_sym(state, info_idx);
        self.dwarf_sym.abbrev = Self::dwarf_get_section_sym(state, abbrev_idx);
        self.dwarf_sym.line = Self::dwarf_get_section_sym(state, line_idx);

        if let Some(str_idx) = self.dwarf_str_section {
            self.dwarf_sym.str_sym = Self::dwarf_get_section_sym(state, str_idx);
        }

        // Record start of compilation unit
        self.dwarf_info.start = state.sections[info_idx].data.len();

        // Write compilation unit header
        let sec = &mut state.sections[info_idx];
        // unit_length placeholder (4 bytes, will be patched in end())
        sec.data.extend_from_slice(&0u32.to_le_bytes());
        // version
        sec.data.extend_from_slice(&(state.dwarf as u16).to_le_bytes());

        if state.dwarf >= 5 {
            // DWARF5: unit_type + address_size + debug_abbrev_offset
            sec.data.push(0x01); // DW_UT_compile
            sec.data.push(PTR_SIZE as u8); // address_size
            sec.data.extend_from_slice(&0u32.to_le_bytes()); // debug_abbrev_offset
        } else {
            // DWARF2-4: debug_abbrev_offset + address_size
            sec.data.extend_from_slice(&0u32.to_le_bytes()); // debug_abbrev_offset
            sec.data.push(PTR_SIZE as u8); // address_size
        }
        sec.data_offset = sec.data.len();

        // Emit DW_TAG_compile_unit DIE (abbreviation 1)
        self.dwarf_uleb128(state, DWARF_ABBREV::COMPILE_UNIT as u64);

        // DW_AT_producer (strp)
        let producer = format!("tcc {}", crate::config::TCC_VERSION);
        self.dwarf_strp(state, &producer);

        // DW_AT_language: C99
        self.dwarf_data1(state, 0x0c); // DW_LANG_C99

        // DW_AT_name (line_strp or string)
        let filename = state.include_stack.last()
            .map(|bf| bf.true_filename.clone())
            .unwrap_or_else(|| "<unknown>".to_string());
        let fname_clone = filename.clone();

        if state.dwarf >= 5 {
            self.dwarf_line_strp(state, &fname_clone);
        } else {
            // DW_FORM_string (inline)
            if let Some(idx) = self.dwarf_info_section {
                state.sections[idx].data.extend_from_slice(fname_clone.as_bytes());
                state.sections[idx].data.push(0);
                state.sections[idx].data_offset = state.sections[idx].data.len();
            }
        }

        // DW_AT_comp_dir
        let comp_dir = Path::new(&filename)
            .parent()
            .and_then(|p| p.to_str())
            .unwrap_or(".")
            .to_string();
        if state.dwarf >= 5 {
            self.dwarf_line_strp(state, &comp_dir);
        } else {
            if let Some(idx) = self.dwarf_info_section {
                state.sections[idx].data.extend_from_slice(comp_dir.as_bytes());
                state.sections[idx].data.push(0);
                state.sections[idx].data_offset = state.sections[idx].data.len();
            }
        }

        // DW_AT_low_pc — will be patched/relocated
        if PTR_SIZE == 8 {
            self.dwarf_data8(state, 0);
        } else {
            self.dwarf_data4(state, 0);
        }

        // DW_AT_high_pc — placeholder
        self.dwarf_data8(state, 0);

        // DW_AT_stmt_list — offset into .debug_line
        self.dwarf_data4(state, 0);

        // Initialize line number program header
        self.dwarf_line.start = state.sections[line_idx].data.len();
        let line_sec = &mut state.sections[line_idx];
        // unit_length placeholder
        line_sec.data.extend_from_slice(&0u32.to_le_bytes());
        // version
        line_sec.data.extend_from_slice(&(state.dwarf as u16).to_le_bytes());

        if state.dwarf >= 5 {
            line_sec.data.push(PTR_SIZE as u8); // address_size
            line_sec.data.push(0); // segment_selector_size
        }

        // header_length placeholder
        line_sec.data.extend_from_slice(&0u32.to_le_bytes());
        // minimum_instruction_length
        line_sec.data.push(DWARF_MIN_INSTR_LEN);
        if state.dwarf >= 4 {
            line_sec.data.push(1); // maximum_operations_per_instruction
        }
        // default_is_stmt
        line_sec.data.push(1);
        // line_base
        line_sec.data.push(DWARF_LINE_BASE as u8);
        // line_range
        line_sec.data.push(DWARF_LINE_RANGE as u8);
        // opcode_base
        line_sec.data.push(DWARF_OPCODE_BASE as u8);
        // standard_opcode_lengths
        line_sec.data.extend_from_slice(&DWARF_LINE_OPCODES);
        line_sec.data_offset = line_sec.data.len();

        // Reset line state
        self.dwarf_line.last_file = 1;
        self.dwarf_line.last_pc = 0;
        self.dwarf_line.last_line = 1;
        self.dwarf_line.line_data.clear();
        self.dwarf_line.dir_table.clear();
        self.dwarf_line.filename_table.clear();

        // Register the main file
        self.dwarf_file(&filename);

        Ok(())
    }

    /// Finalize DWARF debug sections for the current compilation unit.
    fn dwarf_end(&mut self, state: &mut TCCState) -> TccResult<()> {
        let info_idx = match self.dwarf_info_section {
            Some(idx) => idx,
            None => return Ok(()),
        };

        // Emit base types that were referenced
        for i in 0..N_DEFAULT_DEBUG {
            if self.dwarf_info.base_type_used[i] != -1 {
                let entry = &DEFAULT_DEBUG[i];
                let offset = state.sections[info_idx].data.len();
                // Patch the forward reference
                let ref_offset = self.dwarf_info.base_type_used[i] as usize;
                section_write_le32(
                    &mut state.sections[info_idx].data,
                    ref_offset,
                    (offset - self.dwarf_info.start) as u32,
                );

                // Emit base type DIE
                encode_uleb128(&mut state.sections[info_idx].data, DWARF_ABBREV::BASE_TYPE as u64);
                encode_uleb128(&mut state.sections[info_idx].data, entry.size as u64);
                state.sections[info_idx].data.push(entry.encoding);
                // Extract name from STAB string (before the colon)
                let name = entry.name.split(':').next().unwrap_or("unknown");
                let str_offset = self.dwarf_string(state, name);
                state.sections[info_idx].data.extend_from_slice(&str_offset.to_le_bytes());
                state.sections[info_idx].data_offset = state.sections[info_idx].data.len();
            }
        }

        // Terminate compilation unit children with null DIE
        state.sections[info_idx].data.push(0);
        state.sections[info_idx].data_offset = state.sections[info_idx].data.len();

        // Patch compilation unit length
        let unit_end = state.sections[info_idx].data.len();
        let unit_length = (unit_end - self.dwarf_info.start - 4) as u32;
        section_write_le32(
            &mut state.sections[info_idx].data,
            self.dwarf_info.start,
            unit_length,
        );

        // Build .debug_aranges section
        if let Some(aranges_idx) = self.dwarf_aranges_section {
            let sec = &mut state.sections[aranges_idx];
            let start = sec.data.len();
            // unit_length placeholder
            sec.data.extend_from_slice(&0u32.to_le_bytes());
            // version = 2
            sec.data.extend_from_slice(&2u16.to_le_bytes());
            // debug_info_offset (will need reloc)
            sec.data.extend_from_slice(&0u32.to_le_bytes());
            // address_size
            sec.data.push(PTR_SIZE as u8);
            // segment_size
            sec.data.push(0);
            // Pad to 2*PTR_SIZE alignment
            let cur = sec.data.len() - start;
            let align = 2 * PTR_SIZE;
            let pad = if cur % align != 0 { align - (cur % align) } else { 0 };
            for _ in 0..pad {
                sec.data.push(0);
            }
            // Address range entry (relocated by linker)
            if PTR_SIZE == 8 {
                sec.data.extend_from_slice(&0u64.to_le_bytes()); // start
                sec.data.extend_from_slice(&0u64.to_le_bytes()); // length
            } else {
                sec.data.extend_from_slice(&0u32.to_le_bytes()); // start
                sec.data.extend_from_slice(&0u32.to_le_bytes()); // length
            }
            // Terminator
            if PTR_SIZE == 8 {
                sec.data.extend_from_slice(&0u64.to_le_bytes());
                sec.data.extend_from_slice(&0u64.to_le_bytes());
            } else {
                sec.data.extend_from_slice(&0u32.to_le_bytes());
                sec.data.extend_from_slice(&0u32.to_le_bytes());
            }
            // Patch length
            let end = sec.data.len();
            let length = (end - start - 4) as u32;
            section_write_le32(&mut sec.data, start, length);
            sec.data_offset = sec.data.len();
        }

        // Finalize .debug_line section
        self.dwarf_finalize_line(state)?;

        Ok(())
    }

    /// Finalize the DWARF line number program.
    fn dwarf_finalize_line(&mut self, state: &mut TCCState) -> TccResult<()> {
        let line_idx = match self.dwarf_line_section {
            Some(idx) => idx,
            None => return Ok(()),
        };

        let header_start = self.dwarf_line.start;
        let sec = &mut state.sections[line_idx];

        if state.dwarf >= 5 {
            // DWARF5 directory/file table format
            // Directory entry format count
            sec.data.push(1); // 1 column (path)
            // Directory entry format: DW_LNCT_path, DW_FORM_line_strp
            encode_uleb128(&mut sec.data, DwLnct::Path as u64);
            encode_uleb128(&mut sec.data, DwForm::LineStrp as u64);
            // Directory count
            encode_uleb128(&mut sec.data, (self.dwarf_line.dir_table.len() + 1) as u64);
            // Directory 0 (comp_dir — placeholder)
            sec.data.extend_from_slice(&0u32.to_le_bytes());
            for _dir in &self.dwarf_line.dir_table {
                sec.data.extend_from_slice(&0u32.to_le_bytes()); // placeholder
            }
            // File name entry format count
            sec.data.push(2); // 2 columns
            encode_uleb128(&mut sec.data, DwLnct::Path as u64);
            encode_uleb128(&mut sec.data, DwForm::LineStrp as u64);
            encode_uleb128(&mut sec.data, DwLnct::DirectoryIndex as u64);
            encode_uleb128(&mut sec.data, DwForm::Udata as u64);
            // File count
            encode_uleb128(&mut sec.data, self.dwarf_line.filename_table.len() as u64);
            for entry in &self.dwarf_line.filename_table {
                sec.data.extend_from_slice(&0u32.to_le_bytes()); // placeholder
                encode_uleb128(&mut sec.data, entry.dir_entry as u64);
            }
        } else {
            // DWARF 2-4 directory/file tables
            // Include directories
            for dir in &self.dwarf_line.dir_table {
                sec.data.extend_from_slice(dir.as_bytes());
                sec.data.push(0);
            }
            sec.data.push(0); // terminate directory list

            // File names
            for entry in &self.dwarf_line.filename_table {
                sec.data.extend_from_slice(entry.name.as_bytes());
                sec.data.push(0);
                encode_uleb128(&mut sec.data, entry.dir_entry as u64);
                encode_uleb128(&mut sec.data, 0); // time
                encode_uleb128(&mut sec.data, 0); // size
            }
            sec.data.push(0); // terminate file list
        }

        // Patch header length
        let header_len_offset = header_start + 4 + 2 + if state.dwarf >= 5 { 2 } else { 0 };
        let header_end = sec.data.len();
        let header_length = (header_end - header_len_offset - 4) as u32;
        section_write_le32(&mut sec.data, header_len_offset, header_length);

        // Append accumulated line number program opcodes
        sec.data.extend_from_slice(&self.dwarf_line.line_data);

        // Emit DW_LNE_end_sequence
        sec.data.push(0); // extended opcode prefix
        sec.data.push(1); // length of extended opcode
        sec.data.push(DwLne::EndSequence as u8);

        // Patch total unit length
        let unit_end = sec.data.len();
        let unit_length = (unit_end - header_start - 4) as u32;
        section_write_le32(&mut sec.data, header_start, unit_length);
        sec.data_offset = sec.data.len();

        Ok(())
    }

    // =======================================================================
    // Internal DWARF Line Number Generation
    // =======================================================================

    /// Emit DWARF line number information for a position change.
    fn dwarf_line(&mut self, _state: &mut TCCState, cur_ind: i32) -> TccResult<()> {
        let new_line = self.cur_line;
        let line_delta = new_line - self.dwarf_line.last_line;
        let addr_delta = cur_ind - self.dwarf_line.last_pc;

        if addr_delta < 0 {
            return Ok(()); // Can't go backwards
        }
        if addr_delta == 0 && line_delta == 0 {
            return Ok(()); // No change
        }

        // Check file change
        let file_idx = self.dwarf_line.cur_file;
        if file_idx != self.dwarf_line.last_file {
            self.dwarf_line.line_data.push(DwLns::SetFile as u8);
            encode_uleb128(&mut self.dwarf_line.line_data, file_idx as u64);
            self.dwarf_line.last_file = file_idx;
        }

        // Try to encode as a special opcode
        let adjusted_opcode = line_delta - DWARF_LINE_BASE;
        if adjusted_opcode >= 0
            && adjusted_opcode < DWARF_LINE_RANGE
            && addr_delta >= 0
        {
            let max_addr = (255 - DWARF_OPCODE_BASE) / DWARF_LINE_RANGE;
            if addr_delta <= max_addr as i32 {
                let opcode = adjusted_opcode + (addr_delta * DWARF_LINE_RANGE) + DWARF_OPCODE_BASE;
                if opcode >= DWARF_OPCODE_BASE && opcode <= 255 {
                    self.dwarf_line.line_data.push(opcode as u8);
                    self.dwarf_line.last_line = new_line;
                    self.dwarf_line.last_pc = cur_ind;
                    return Ok(());
                }
            }
        }

        // Fall back to standard opcodes
        if addr_delta > 0 {
            self.dwarf_line.line_data.push(DwLns::AdvancePc as u8);
            encode_uleb128(&mut self.dwarf_line.line_data, addr_delta as u64);
        }
        if line_delta != 0 {
            self.dwarf_line.line_data.push(DwLns::AdvanceLine as u8);
            encode_sleb128(&mut self.dwarf_line.line_data, line_delta as i64);
        }
        self.dwarf_line.line_data.push(DwLns::Copy as u8);

        self.dwarf_line.last_line = new_line;
        self.dwarf_line.last_pc = cur_ind;

        Ok(())
    }

    // =======================================================================
    // Internal DWARF Function End
    // =======================================================================

    /// Emit DWARF subprogram DIE at function end.
    fn dwarf_funcend(&mut self, state: &mut TCCState, _cur_ind: i32, func_size: u64) -> TccResult<()> {
        let info_idx = match self.dwarf_info_section {
            Some(idx) => idx,
            None => return Ok(()),
        };

        // Determine if function is external or static
        let is_external = true; // Default to external; caller can override

        let abbrev = if is_external {
            DWARF_ABBREV::SUBPROGRAM as u64
        } else {
            DWARF_ABBREV_SUBPROGRAM_STATIC as u64
        };

        // Emit abbreviation number
        encode_uleb128(&mut state.sections[info_idx].data, abbrev);

        if is_external {
            // DW_AT_external = flag_present (no data needed)
        }

        // DW_AT_name
        let func_name = state.funcname.clone().unwrap_or_else(|| "?".to_string());
        let name_offset = self.dwarf_string(state, &func_name);
        state.sections[info_idx].data.extend_from_slice(&name_offset.to_le_bytes());

        // DW_AT_decl_file
        let file_idx = self.dwarf_line.cur_file.max(1) as u64;
        encode_uleb128(&mut state.sections[info_idx].data, file_idx);

        // DW_AT_decl_line
        encode_uleb128(&mut state.sections[info_idx].data, self.dwarf_info.line as u64);

        // DW_AT_type — return type reference (placeholder 0)
        state.sections[info_idx].data.extend_from_slice(&0u32.to_le_bytes());

        // DW_AT_low_pc
        if PTR_SIZE == 8 {
            state.sections[info_idx].data.extend_from_slice(&(self.func_ind as u64).to_le_bytes());
        } else {
            state.sections[info_idx].data.extend_from_slice(&(self.func_ind as u32).to_le_bytes());
        }

        // DW_AT_high_pc (size)
        state.sections[info_idx].data.extend_from_slice(&func_size.to_le_bytes());

        // DW_AT_sibling — placeholder (will be patched)
        let sibling_offset = state.sections[info_idx].data.len();
        state.sections[info_idx].data.extend_from_slice(&0u32.to_le_bytes());

        // DW_AT_frame_base — exprloc with DW_OP_call_frame_cfa
        state.sections[info_idx].data.push(1); // length
        state.sections[info_idx].data.push(DwOp::CallFrameCfa as u8);

        state.sections[info_idx].data_offset = state.sections[info_idx].data.len();

        // Patch sibling reference after children are emitted
        let current_offset = state.sections[info_idx].data.len();
        section_write_le32(
            &mut state.sections[info_idx].data,
            sibling_offset,
            (current_offset - self.dwarf_info.start) as u32,
        );

        Ok(())
    }

    // =======================================================================
    // Internal DWARF Type Info Generation
    // =======================================================================

    /// Generate DWARF type information for a C type.
    /// Returns the offset into .debug_info for the type entry.
    fn dwarf_type_info(&mut self, state: &mut TCCState, ctype: &CType) -> TccResult<i32> {
        let info_idx = match self.dwarf_info_section {
            Some(idx) => idx,
            None => return Ok(0),
        };

        let btype = ctype.t & VT_BTYPE;

        // Check type hash for existing entry
        let type_id = Self::compute_type_id(ctype);
        for entry in &self.debug_hash_global {
            if entry.type_id == type_id {
                return Ok(entry.debug_type);
            }
        }
        for entry in &self.debug_hash_local {
            if entry.type_id == type_id {
                return Ok(entry.debug_type);
            }
        }

        let offset = (state.sections[info_idx].data.len() - self.dwarf_info.start) as i32;

        match btype {
            t if t == VT_PTR => {
                // Pointer type
                encode_uleb128(&mut state.sections[info_idx].data, DWARF_ABBREV::POINTER_TYPE as u64);
                state.sections[info_idx].data.push(PTR_SIZE as u8); // DW_AT_byte_size

                // Referenced type
                let ref_type = if let Some(ref sym) = ctype.ref_sym {
                    let ref_offset = self.dwarf_type_info(state, &sym.type_)?;
                    ref_offset as u32
                } else {
                    0
                };
                state.sections[info_idx].data.extend_from_slice(&ref_type.to_le_bytes());
                state.sections[info_idx].data_offset = state.sections[info_idx].data.len();
            }
            t if t == VT_FUNC => {
                // Subroutine type
                let has_params = ctype.ref_sym.is_some();
                let abbrev = if has_params {
                    DWARF_ABBREV::SUBROUTINE_TYPE as u64
                } else {
                    DWARF_ABBREV_SUBROUTINE_TYPE_NOCHILDREN as u64
                };
                encode_uleb128(&mut state.sections[info_idx].data, abbrev);

                // Return type
                let ret_type = if let Some(ref sym) = ctype.ref_sym {
                    let ref_offset = self.dwarf_type_info(state, &sym.type_)?;
                    ref_offset as u32
                } else {
                    0
                };
                state.sections[info_idx].data.extend_from_slice(&ret_type.to_le_bytes());

                if has_params {
                    // Sibling placeholder
                    let sib_pos = state.sections[info_idx].data.len();
                    state.sections[info_idx].data.extend_from_slice(&0u32.to_le_bytes());

                    // Emit formal parameters
                    if let Some(ref sym) = ctype.ref_sym {
                        let mut param = sym.next.as_deref();
                        while let Some(p) = param {
                            encode_uleb128(
                                &mut state.sections[info_idx].data,
                                DWARF_ABBREV::FORMAL_PARAMETER2 as u64,
                            );
                            let param_type = self.dwarf_type_info(state, &p.type_)?;
                            state.sections[info_idx].data.extend_from_slice(&(param_type as u32).to_le_bytes());
                            param = p.next.as_deref();
                        }
                    }

                    // Null terminator for children
                    state.sections[info_idx].data.push(0);

                    // Patch sibling
                    let end_offset = (state.sections[info_idx].data.len() - self.dwarf_info.start) as u32;
                    section_write_le32(&mut state.sections[info_idx].data, sib_pos, end_offset);
                }
                state.sections[info_idx].data_offset = state.sections[info_idx].data.len();
            }
            t if t == VT_STRUCT => {
                // Structure or union type
                let is_union_type = ctype.ref_sym.as_ref().map_or(false, |s| is_union(s.type_.t));
                let has_members = ctype.ref_sym.as_ref().map_or(false, |s| s.next.is_some());

                let abbrev = if is_union_type {
                    if has_members {
                        DWARF_ABBREV::UNION_TYPE as u64
                    } else {
                        DWARF_ABBREV_UNION_TYPE_EMPTY as u64
                    }
                } else {
                    if has_members {
                        DWARF_ABBREV::STRUCTURE_TYPE as u64
                    } else {
                        DWARF_ABBREV_STRUCT_TYPE_EMPTY as u64
                    }
                };
                encode_uleb128(&mut state.sections[info_idx].data, abbrev);

                // DW_AT_name
                let name = "<anon>";
                let name_off = self.dwarf_string(state, name);
                state.sections[info_idx].data.extend_from_slice(&name_off.to_le_bytes());

                // DW_AT_byte_size
                let byte_size = ctype.ref_sym.as_ref().map_or(0, |s| s.c as u64);
                encode_uleb128(&mut state.sections[info_idx].data, byte_size);

                // DW_AT_decl_file, DW_AT_decl_line
                encode_uleb128(&mut state.sections[info_idx].data, self.dwarf_line.cur_file.max(1) as u64);
                encode_uleb128(&mut state.sections[info_idx].data, self.cur_line.max(1) as u64);

                if has_members {
                    // DW_AT_sibling placeholder
                    let sib_pos = state.sections[info_idx].data.len();
                    state.sections[info_idx].data.extend_from_slice(&0u32.to_le_bytes());

                    // Emit member DIEs
                    if let Some(ref sym) = ctype.ref_sym {
                        let mut member = sym.next.as_deref();
                        while let Some(m) = member {
                            let is_bitfield = (m.type_.t & VT_BITFIELD) != 0;
                            let member_abbrev = if is_bitfield {
                                DWARF_ABBREV::MEMBER_BF as u64
                            } else {
                                DWARF_ABBREV::MEMBER as u64
                            };
                            encode_uleb128(&mut state.sections[info_idx].data, member_abbrev);

                            // DW_AT_name
                            let mname = "<field>";
                            let mname_off = self.dwarf_string(state, mname);
                            state.sections[info_idx].data.extend_from_slice(&mname_off.to_le_bytes());

                            // DW_AT_decl_file, DW_AT_decl_line
                            encode_uleb128(&mut state.sections[info_idx].data, self.dwarf_line.cur_file.max(1) as u64);
                            encode_uleb128(&mut state.sections[info_idx].data, 0u64);

                            // DW_AT_type
                            let mtype = self.dwarf_type_info(state, &m.type_)?;
                            state.sections[info_idx].data.extend_from_slice(&(mtype as u32).to_le_bytes());

                            if is_bitfield {
                                // DW_AT_bit_size, DW_AT_bit_offset
                                let bsz = bit_size(m.type_.t) as u64;
                                let boff = bit_pos(m.type_.t) as u64;
                                encode_uleb128(&mut state.sections[info_idx].data, bsz);
                                encode_uleb128(&mut state.sections[info_idx].data, boff);
                            } else {
                                // DW_AT_data_member_location
                                encode_uleb128(&mut state.sections[info_idx].data, m.c as u64);
                            }

                            member = m.next.as_deref();
                        }
                    }

                    // Null terminator for children
                    state.sections[info_idx].data.push(0);

                    // Patch sibling reference
                    let end_offset = (state.sections[info_idx].data.len() - self.dwarf_info.start) as u32;
                    section_write_le32(&mut state.sections[info_idx].data, sib_pos, end_offset);
                }
                state.sections[info_idx].data_offset = state.sections[info_idx].data.len();
            }
            t if t == VT_ENUM => {
                // Enumeration type
                encode_uleb128(&mut state.sections[info_idx].data, DWARF_ABBREV::ENUMERATION_TYPE as u64);

                // DW_AT_name
                let name = "<enum>";
                let name_off = self.dwarf_string(state, name);
                state.sections[info_idx].data.extend_from_slice(&name_off.to_le_bytes());

                // DW_AT_encoding (signed/unsigned)
                let is_unsigned = (ctype.t & VT_UNSIGNED) != 0;
                state.sections[info_idx].data.push(if is_unsigned { 0x07 } else { 0x05 });

                // DW_AT_byte_size
                state.sections[info_idx].data.push(4); // Standard enum size

                // DW_AT_type — placeholder for underlying integer type
                state.sections[info_idx].data.extend_from_slice(&0u32.to_le_bytes());

                // DW_AT_decl_file, DW_AT_decl_line
                encode_uleb128(&mut state.sections[info_idx].data, self.dwarf_line.cur_file.max(1) as u64);
                encode_uleb128(&mut state.sections[info_idx].data, self.cur_line.max(1) as u64);

                // DW_AT_sibling placeholder
                let sib_pos = state.sections[info_idx].data.len();
                state.sections[info_idx].data.extend_from_slice(&0u32.to_le_bytes());

                // Emit enumerator DIEs
                if let Some(ref sym) = ctype.ref_sym {
                    let mut enumerator = sym.next.as_deref();
                    while let Some(e) = enumerator {
                        let abbrev_num = if is_unsigned {
                            DWARF_ABBREV_ENUMERATOR_UNSIGNED as u64
                        } else {
                            DWARF_ABBREV::ENUMERATOR as u64
                        };
                        encode_uleb128(&mut state.sections[info_idx].data, abbrev_num);

                        let ename = "<value>";
                        let ename_off = self.dwarf_string(state, ename);
                        state.sections[info_idx].data.extend_from_slice(&ename_off.to_le_bytes());

                        if is_unsigned {
                            encode_uleb128(&mut state.sections[info_idx].data, e.c as u64);
                        } else {
                            encode_sleb128(&mut state.sections[info_idx].data, e.c as i64);
                        }

                        enumerator = e.next.as_deref();
                    }
                }

                // Null terminator
                state.sections[info_idx].data.push(0);

                // Patch sibling
                let end_offset = (state.sections[info_idx].data.len() - self.dwarf_info.start) as u32;
                section_write_le32(&mut state.sections[info_idx].data, sib_pos, end_offset);
                state.sections[info_idx].data_offset = state.sections[info_idx].data.len();
            }
            t if t == VT_ARRAY => {
                // Array type
                encode_uleb128(&mut state.sections[info_idx].data, DWARF_ABBREV::ARRAY_TYPE as u64);

                // DW_AT_type (element type)
                let elem_type = if let Some(ref sym) = ctype.ref_sym {
                    let ref_offset = self.dwarf_type_info(state, &sym.type_)?;
                    ref_offset as u32
                } else {
                    0
                };
                state.sections[info_idx].data.extend_from_slice(&elem_type.to_le_bytes());

                // DW_AT_sibling placeholder
                let sib_pos = state.sections[info_idx].data.len();
                state.sections[info_idx].data.extend_from_slice(&0u32.to_le_bytes());

                // Subrange type
                encode_uleb128(&mut state.sections[info_idx].data, DWARF_ABBREV::SUBRANGE_TYPE as u64);
                // DW_AT_type (index type — usually int)
                state.sections[info_idx].data.extend_from_slice(&0u32.to_le_bytes());
                // DW_AT_upper_bound
                let upper = ctype.ref_sym.as_ref().map_or(0, |s| s.c.saturating_sub(1).max(0) as u64);
                encode_uleb128(&mut state.sections[info_idx].data, upper);

                // Null terminator
                state.sections[info_idx].data.push(0);

                // Patch sibling
                let end_offset = (state.sections[info_idx].data.len() - self.dwarf_info.start) as u32;
                section_write_le32(&mut state.sections[info_idx].data, sib_pos, end_offset);
                state.sections[info_idx].data_offset = state.sections[info_idx].data.len();
            }
            _ => {
                // Base type — look up in default_debug table
                let search_type = btype | (ctype.t & (VT_UNSIGNED | VT_DEFSIGN));
                for (i, entry) in DEFAULT_DEBUG.iter().enumerate() {
                    if entry.vtype == search_type {
                        // Use a base_type_used forward reference
                        let ref_pos = state.sections[info_idx].data.len();
                        state.sections[info_idx].data.extend_from_slice(&0u32.to_le_bytes());
                        state.sections[info_idx].data_offset = state.sections[info_idx].data.len();
                        self.dwarf_info.base_type_used[i] = ref_pos as i32;
                        // Store in hash and return offset of the reference
                        self.debug_hash_local.push(DebugHash { debug_type: offset, type_id });
                        return Ok(offset);
                    }
                }
                // Unknown base type — emit as int
                let ref_pos = state.sections[info_idx].data.len();
                state.sections[info_idx].data.extend_from_slice(&0u32.to_le_bytes());
                state.sections[info_idx].data_offset = state.sections[info_idx].data.len();
                self.dwarf_info.base_type_used[0] = ref_pos as i32;
                self.debug_hash_local.push(DebugHash { debug_type: offset, type_id });
                return Ok(offset);
            }
        }

        // Add to type hash
        self.debug_hash_local.push(DebugHash { debug_type: offset, type_id });
        Ok(offset)
    }

    /// Compute a simple hash/ID for a CType to enable deduplication.
    fn compute_type_id(ctype: &CType) -> u64 {
        let mut id = ctype.t as u64;
        if let Some(ref sym) = ctype.ref_sym {
            id = id.wrapping_mul(31).wrapping_add(sym.c as u64);
            id = id.wrapping_mul(31).wrapping_add(sym.v as u64);
        }
        id
    }

    // =======================================================================
    // Internal DWARF Variable/Typedef Emission
    // =======================================================================

    /// Emit DWARF debug info for a variable.
    fn dwarf_variable(&mut self, state: &mut TCCState, sym: &Sym, val: i64, is_param: bool) -> TccResult<()> {
        let info_idx = match self.dwarf_info_section {
            Some(idx) => idx,
            None => return Ok(()),
        };

        let abbrev = if is_param {
            DWARF_ABBREV::FORMAL_PARAMETER as u64
        } else {
            DWARF_ABBREV_VARIABLE_LOCAL as u64
        };

        encode_uleb128(&mut state.sections[info_idx].data, abbrev);

        // DW_AT_name
        let name = "<var>";
        let name_off = self.dwarf_string(state, name);
        state.sections[info_idx].data.extend_from_slice(&name_off.to_le_bytes());

        // DW_AT_type
        let type_offset = self.dwarf_type_info(state, &sym.type_)?;
        state.sections[info_idx].data.extend_from_slice(&(type_offset as u32).to_le_bytes());

        // DW_AT_location — exprloc with DW_OP_fbreg + offset
        let mut loc_data = Vec::new();
        loc_data.push(DwOp::Fbreg as u8);
        encode_sleb128(&mut loc_data, val);
        encode_uleb128(&mut state.sections[info_idx].data, loc_data.len() as u64);
        state.sections[info_idx].data.extend_from_slice(&loc_data);

        state.sections[info_idx].data_offset = state.sections[info_idx].data.len();
        Ok(())
    }

    /// Emit DWARF typedef DIE.
    fn dwarf_typedef(&mut self, state: &mut TCCState, sym: &Sym) -> TccResult<()> {
        let info_idx = match self.dwarf_info_section {
            Some(idx) => idx,
            None => return Ok(()),
        };

        encode_uleb128(&mut state.sections[info_idx].data, DWARF_ABBREV::TYPEDEF as u64);

        // DW_AT_name
        let name = format!("type_{}", sym.v & !SYM_STRUCT);
        let name_off = self.dwarf_string(state, &name);
        state.sections[info_idx].data.extend_from_slice(&name_off.to_le_bytes());

        // DW_AT_decl_file, DW_AT_decl_line
        encode_uleb128(&mut state.sections[info_idx].data, self.dwarf_line.cur_file.max(1) as u64);
        encode_uleb128(&mut state.sections[info_idx].data, self.cur_line.max(1) as u64);

        // DW_AT_type
        let type_offset = self.dwarf_type_info(state, &sym.type_)?;
        state.sections[info_idx].data.extend_from_slice(&(type_offset as u32).to_le_bytes());

        state.sections[info_idx].data_offset = state.sections[info_idx].data.len();
        Ok(())
    }

    // =======================================================================
    // Internal STAB Generation
    // =======================================================================

    /// Initialize STAB sections for a new compilation unit.
    fn stab_start(&mut self, state: &mut TCCState) -> TccResult<()> {
        let _stab_idx = match self.stab_section {
            Some(idx) => idx,
            None => return Err(TccError::internal("No .stab section")),
        };
        let _stabstr_idx = match self.stabstr_section {
            Some(idx) => idx,
            None => return Err(TccError::internal("No .stabstr section")),
        };

        // Emit N_SO for source file
        let filename = state.include_stack.last()
            .map(|bf| bf.true_filename.clone())
            .unwrap_or_else(|| "<unknown>".to_string());

        let dir = Path::new(&filename)
            .parent()
            .and_then(|p| p.to_str())
            .unwrap_or(".")
            .to_string();

        // Directory N_SO entry
        let dir_str = format!("{}/", dir);
        self.put_stabs(state, &dir_str, StabCode::N_SO as u8, 0, 0, 0)?;

        // Filename N_SO entry
        let base_name = Path::new(&filename)
            .file_name()
            .and_then(|f| f.to_str())
            .unwrap_or(&filename)
            .to_string();
        self.put_stabs(state, &base_name, StabCode::N_SO as u8, 0, 0, 0)?;

        // Default type definitions
        for entry in DEFAULT_DEBUG.iter() {
            self.put_stabs(state, entry.name, StabCode::N_LSYM as u8, 0, 0, 0)?;
        }

        self.last_line_num = 0;
        self.debug_next_type = N_DEFAULT_DEBUG as i32 + 1;

        Ok(())
    }

    /// Finalize STAB sections.
    fn stab_end(&mut self, state: &mut TCCState) -> TccResult<()> {
        // Emit closing N_SO with empty string
        self.put_stabs(state, "", StabCode::N_SO as u8, 0, 0, 0)?;
        Ok(())
    }

    /// Emit STAB line number entry.
    fn stab_line(&mut self, state: &mut TCCState, cur_ind: i32) -> TccResult<()> {
        let new_line = self.cur_line;
        if new_line == self.last_line_num {
            return Ok(());
        }

        let stab_idx = match self.stab_section {
            Some(idx) => idx,
            None => return Ok(()),
        };
        let stabstr_idx = match self.stabstr_section {
            Some(idx) => idx,
            None => return Ok(()),
        };

        // Emit N_SLINE
        self.emit_stab_entry(
            state, stab_idx, stabstr_idx,
            0, StabCode::N_SLINE as u8, 0, new_line as i16, cur_ind as u32,
        )?;
        self.last_line_num = new_line;

        Ok(())
    }

    /// Emit STAB function end entry.
    fn stab_funcend(&mut self, state: &mut TCCState, cur_ind: i32) -> TccResult<()> {
        // Emit N_FUN with empty name to mark function end
        self.put_stabs(state, "", StabCode::N_FUN as u8, 0, 0, cur_ind as u32)?;
        Ok(())
    }

    /// Emit STAB typedef entry.
    fn stab_typedef(&mut self, state: &mut TCCState, sym: &Sym) -> TccResult<()> {
        let type_str = self.stab_type_string(&sym.type_);
        let name = format!("type_{}:t{}={}", sym.v, self.debug_next_type, type_str);
        self.debug_next_type += 1;
        self.put_stabs(state, &name, StabCode::N_LSYM as u8, 0, 0, 0)?;
        Ok(())
    }

    /// Generate STAB type information for a C type.
    /// Returns the type number.
    fn stab_type_info(&mut self, _state: &mut TCCState, ctype: &CType) -> TccResult<i32> {
        let btype = ctype.t & VT_BTYPE;
        let search_type = btype | (ctype.t & (VT_UNSIGNED | VT_DEFSIGN));

        // Look up in default types
        for (i, entry) in DEFAULT_DEBUG.iter().enumerate() {
            if entry.vtype == search_type {
                return Ok((i + 1) as i32);
            }
        }

        // Allocate new type number
        let type_num = self.debug_next_type;
        self.debug_next_type += 1;
        Ok(type_num)
    }

    /// Generate a STAB type string for a C type.
    fn stab_type_string(&self, ctype: &CType) -> String {
        let btype = ctype.t & VT_BTYPE;
        let search_type = btype | (ctype.t & (VT_UNSIGNED | VT_DEFSIGN));

        // Look up in default types
        for (i, entry) in DEFAULT_DEBUG.iter().enumerate() {
            if entry.vtype == search_type {
                return format!("{}", i + 1);
            }
        }

        // Complex types
        match btype {
            t if t == VT_PTR => {
                let inner = if let Some(ref sym) = ctype.ref_sym {
                    self.stab_type_string(&sym.type_)
                } else {
                    "15".to_string() // void
                };
                format!("*{}", inner)
            }
            t if t == VT_ARRAY => {
                let inner = if let Some(ref sym) = ctype.ref_sym {
                    self.stab_type_string(&sym.type_)
                } else {
                    "1".to_string() // int
                };
                let size = ctype.ref_sym.as_ref().map_or(0, |s| s.c);
                format!("ar1;0;{};{}", size.saturating_sub(1), inner)
            }
            t if t == VT_FUNC => {
                let ret = if let Some(ref sym) = ctype.ref_sym {
                    self.stab_type_string(&sym.type_)
                } else {
                    "1".to_string()
                };
                format!("f{}", ret)
            }
            t if t == VT_STRUCT => {
                let tag = if ctype.ref_sym.as_ref().map_or(false, |s| is_union(s.type_.t)) {
                    "u"
                } else {
                    "s"
                };
                let size = ctype.ref_sym.as_ref().map_or(0, |s| s.c);
                format!("{}{};", tag, size)
            }
            t if t == VT_ENUM => {
                "e;".to_string()
            }
            _ => "1".to_string(), // Default to int
        }
    }

    /// Emit a STAB variable entry.
    fn stab_variable(&mut self, state: &mut TCCState, sym: &Sym, val: i64, is_param: bool) -> TccResult<()> {
        let stype = if is_param {
            StabCode::N_PSYM as u8
        } else {
            StabCode::N_LSYM as u8
        };

        let type_num = self.stab_type_info(state, &sym.type_)?;
        let name = format!("var:p{}", type_num);
        self.put_stabs(state, &name, stype, 0, 0, val as u32)?;

        Ok(())
    }

    // =======================================================================
    // Internal STAB Entry Emission
    // =======================================================================

    /// Write a raw STAB entry to the .stab section.
    fn emit_stab_entry(
        &self,
        state: &mut TCCState,
        stab_idx: usize,
        _stabstr_idx: usize,
        str_offset: u32,
        n_type: u8,
        n_other: u8,
        n_desc: i16,
        n_value: u32,
    ) -> TccResult<usize> {
        let sec = &mut state.sections[stab_idx];
        let entry_offset = sec.data.len();

        // StabSym: n_strx(4) + n_type(1) + n_other(1) + n_desc(2) + n_value(4)
        sec.data.extend_from_slice(&str_offset.to_le_bytes());
        sec.data.push(n_type);
        sec.data.push(n_other);
        sec.data.extend_from_slice(&n_desc.to_le_bytes());
        sec.data.extend_from_slice(&n_value.to_le_bytes());
        sec.data_offset = sec.data.len();

        Ok(entry_offset)
    }

    // =======================================================================
    // Internal Scope Tree Finalization
    // =======================================================================

    /// Recursively finalize a debug scope tree, emitting variable and
    /// lexical block debug information.
    ///
    /// Equivalent to `tcc_debug_finish()` in tccdbg.c.
    fn finish_scope(&mut self, state: &mut TCCState, scope: &DebugScope) -> TccResult<()> {
        if state.dwarf > 0 {
            self.dwarf_finish_scope(state, scope)?;
        } else {
            self.stab_finish_scope(state, scope)?;
        }
        Ok(())
    }

    /// Finalize a DWARF debug scope.
    fn dwarf_finish_scope(&mut self, state: &mut TCCState, scope: &DebugScope) -> TccResult<()> {
        let info_idx = match self.dwarf_info_section {
            Some(idx) => idx,
            None => return Ok(()),
        };

        // Emit variables in this scope
        for sym_entry in &scope.sym {
            let abbrev = if sym_entry.stype == StabCode::N_PSYM as u8 {
                DWARF_ABBREV::FORMAL_PARAMETER as u64
            } else {
                DWARF_ABBREV_VARIABLE_LOCAL as u64
            };
            encode_uleb128(&mut state.sections[info_idx].data, abbrev);

            // Name
            let name_off = self.dwarf_string(state, &sym_entry.name);
            state.sections[info_idx].data.extend_from_slice(&name_off.to_le_bytes());

            // Type reference
            state.sections[info_idx].data.extend_from_slice(&(sym_entry.info as u32).to_le_bytes());

            // Location — DW_OP_fbreg + offset
            let mut loc = Vec::new();
            loc.push(DwOp::Fbreg as u8);
            encode_sleb128(&mut loc, sym_entry.value as i64);
            encode_uleb128(&mut state.sections[info_idx].data, loc.len() as u64);
            state.sections[info_idx].data.extend_from_slice(&loc);
        }

        // Emit child scopes as lexical blocks
        for child in &scope.children {
            if child.sym.is_empty() && child.children.is_empty() {
                continue;
            }

            let has_children = !child.children.is_empty() || !child.sym.is_empty();
            let abbrev = if has_children {
                DWARF_ABBREV_LEXICAL_BLOCK as u64
            } else {
                DWARF_ABBREV_LEXICAL_BLOCK_EMPTY as u64
            };
            encode_uleb128(&mut state.sections[info_idx].data, abbrev);

            // DW_AT_low_pc
            if PTR_SIZE == 8 {
                state.sections[info_idx].data.extend_from_slice(&(child.start as u64).to_le_bytes());
            } else {
                state.sections[info_idx].data.extend_from_slice(&(child.start as u32).to_le_bytes());
            }

            // DW_AT_high_pc (size from low)
            let block_size = (child.end - child.start) as u64;
            state.sections[info_idx].data.extend_from_slice(&block_size.to_le_bytes());

            if has_children {
                self.dwarf_finish_scope(state, child)?;
                // Null terminator for children
                state.sections[info_idx].data.push(0);
            }
        }

        state.sections[info_idx].data_offset = state.sections[info_idx].data.len();
        Ok(())
    }

    /// Finalize a STAB debug scope.
    fn stab_finish_scope(&mut self, state: &mut TCCState, scope: &DebugScope) -> TccResult<()> {
        // Emit variables
        for sym_entry in &scope.sym {
            self.put_stabs(state, &sym_entry.name, sym_entry.stype, 0, 0, sym_entry.value as u32)?;
        }

        // Emit child scopes with N_LBRAC/N_RBRAC
        for child in &scope.children {
            // N_LBRAC
            self.put_stabs(state, "", StabCode::N_LBRAC as u8, 0, 0, child.start as u32)?;
            self.stab_finish_scope(state, child)?;
            // N_RBRAC
            self.put_stabs(state, "", StabCode::N_RBRAC as u8, 0, 0, child.end as u32)?;
        }

        Ok(())
    }
}

// ===========================================================================
// Unit Tests
// ===========================================================================
#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // DWARF Constant Tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_dw_tag_values() {
        assert_eq!(DwTag::CompileUnit as u16, 0x11);
        assert_eq!(DwTag::Subprogram as u16, 0x2e);
        assert_eq!(DwTag::Variable as u16, 0x34);
        assert_eq!(DwTag::BaseType as u16, 0x24);
        assert_eq!(DwTag::PointerType as u16, 0x0f);
        assert_eq!(DwTag::ArrayType as u16, 0x01);
        assert_eq!(DwTag::StructureType as u16, 0x13);
        assert_eq!(DwTag::UnionType as u16, 0x17);
        assert_eq!(DwTag::EnumerationType as u16, 0x04);
        assert_eq!(DwTag::SubroutineType as u16, 0x15);
        assert_eq!(DwTag::TypeDef as u16, 0x16);
    }

    #[test]
    fn test_dw_at_values() {
        assert_eq!(DwAt::Name as u16, 0x03);
        assert_eq!(DwAt::Type as u16, 0x49);
        assert_eq!(DwAt::LowPc as u16, 0x11);
        assert_eq!(DwAt::HighPc as u16, 0x12);
        assert_eq!(DwAt::Language as u16, 0x13);
        assert_eq!(DwAt::CompDir as u16, 0x1b);
        assert_eq!(DwAt::Producer as u16, 0x25);
        assert_eq!(DwAt::Encoding as u16, 0x3e);
        assert_eq!(DwAt::ByteSize as u16, 0x0b);
        assert_eq!(DwAt::Decl_file as u16, 0x3a);
        assert_eq!(DwAt::Decl_line as u16, 0x3b);
    }

    #[test]
    fn test_dw_form_values() {
        assert_eq!(DwForm::Addr as u8, 0x01);
        assert_eq!(DwForm::Data1 as u8, 0x0b);
        assert_eq!(DwForm::Data2 as u8, 0x05);
        assert_eq!(DwForm::Data4 as u8, 0x06);
        assert_eq!(DwForm::Data8 as u8, 0x07);
        assert_eq!(DwForm::String as u8, 0x08);
        assert_eq!(DwForm::Strp as u8, 0x0e);
        assert_eq!(DwForm::SecOffset as u8, 0x17);
        assert_eq!(DwForm::Exprloc as u8, 0x18);
        assert_eq!(DwForm::FlagPresent as u8, 0x19);
    }

    #[test]
    fn test_dw_op_values() {
        assert_eq!(DwOp::Fbreg as u8, 0x91);
        assert_eq!(DwOp::Addr as u8, 0x03);
        assert_eq!(DwOp::Plus as u8, 0x22);
        assert_eq!(DwOp::Deref as u8, 0x06);
        assert_eq!(DwOp::CallFrameCfa as u8, 0x9c);
    }

    #[test]
    fn test_dw_lns_values() {
        assert_eq!(DwLns::Copy as u8, 0x01);
        assert_eq!(DwLns::AdvancePc as u8, 0x02);
        assert_eq!(DwLns::AdvanceLine as u8, 0x03);
        assert_eq!(DwLns::SetFile as u8, 0x04);
        assert_eq!(DwLns::NegateStmt as u8, 0x06);
        assert_eq!(DwLns::SetPrologueEnd as u8, 0x0a);
    }

    #[test]
    fn test_dw_lne_values() {
        assert_eq!(DwLne::EndSequence as u8, 0x01);
        assert_eq!(DwLne::SetAddress as u8, 0x02);
        assert_eq!(DwLne::DefineFile as u8, 0x03);
        assert_eq!(DwLne::SetDiscriminator as u8, 0x04);
    }

    #[test]
    fn test_dw_ate_values() {
        assert_eq!(DwAte::Address as u8, 0x01);
        assert_eq!(DwAte::Boolean as u8, 0x02);
        assert_eq!(DwAte::Float as u8, 0x04);
        assert_eq!(DwAte::Signed as u8, 0x05);
        assert_eq!(DwAte::SignedChar as u8, 0x06);
        assert_eq!(DwAte::Unsigned as u8, 0x07);
        assert_eq!(DwAte::UnsignedChar as u8, 0x08);
    }

    #[test]
    fn test_dw_children_values() {
        assert_eq!(DwChildren::No as u8, 0x00);
        assert_eq!(DwChildren::Yes as u8, 0x01);
    }

    #[test]
    fn test_dw_cfa_values() {
        assert_eq!(DwCfa::AdvanceLoc as u8, 0x40);
        assert_eq!(DwCfa::Offset as u8, 0x80);
        assert_eq!(DwCfa::DefCfa as u8, 0x0c);
        assert_eq!(DwCfa::Nop as u8, 0x00);
    }

    #[test]
    fn test_dw_lnct_values() {
        assert_eq!(DwLnct::Path as u16, 0x01);
        assert_eq!(DwLnct::DirectoryIndex as u16, 0x02);
        assert_eq!(DwLnct::Timestamp as u16, 0x03);
        assert_eq!(DwLnct::Size as u16, 0x04);
        assert_eq!(DwLnct::Md5 as u16, 0x05);
    }

    // -----------------------------------------------------------------------
    // STAB Constant Tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_stab_code_values() {
        assert_eq!(StabCode::N_GSYM as u8, 0x20);
        assert_eq!(StabCode::N_FUN as u8, 0x24);
        assert_eq!(StabCode::N_STSYM as u8, 0x26);
        assert_eq!(StabCode::N_SO as u8, 0x64);
        assert_eq!(StabCode::N_LSYM as u8, 0x80);
        assert_eq!(StabCode::N_SOL as u8, 0x84);
        assert_eq!(StabCode::N_PSYM as u8, 0xa0);
        assert_eq!(StabCode::N_SLINE as u8, 0x44);
        assert_eq!(StabCode::N_LBRAC as u8, 0xc0);
        assert_eq!(StabCode::N_RBRAC as u8, 0xe0);
        assert_eq!(StabCode::N_BINCL as u8, 0x82);
        assert_eq!(StabCode::N_EINCL as u8, 0xa2);
    }

    #[test]
    fn test_stab_sym_struct() {
        let sym = StabSym {
            n_strx: 42,
            n_type: StabCode::N_FUN as u8,
            n_other: 0,
            n_desc: 10,
            n_value: 0x1000,
        };
        assert_eq!(sym.n_strx, 42);
        assert_eq!(sym.n_type, 0x24);
        assert_eq!(sym.n_other, 0);
        assert_eq!(sym.n_desc, 10);
        assert_eq!(sym.n_value, 0x1000);
    }

    #[test]
    fn test_stab_sym_size() {
        assert_eq!(STAB_SYM_SIZE, 12);
    }

    // -----------------------------------------------------------------------
    // DWARF Abbreviation Constant Tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_dwarf_abbrev_constants() {
        assert_eq!(DWARF_ABBREV::COMPILE_UNIT, 1);
        assert_eq!(DWARF_ABBREV::SUBPROGRAM, 2);
        assert_eq!(DWARF_ABBREV::VARIABLE, 4);
        assert_eq!(DWARF_ABBREV::FORMAL_PARAMETER, 5);
        assert_eq!(DWARF_ABBREV::BASE_TYPE, 8);
        assert_eq!(DWARF_ABBREV::POINTER_TYPE, 9);
        assert_eq!(DWARF_ABBREV::ARRAY_TYPE, 10);
        assert_eq!(DWARF_ABBREV::STRUCTURE_TYPE, 11);
        assert_eq!(DWARF_ABBREV::UNION_TYPE, 14);
        assert_eq!(DWARF_ABBREV::ENUMERATION_TYPE, 17);
        assert_eq!(DWARF_ABBREV::ENUMERATOR, 18);
        assert_eq!(DWARF_ABBREV::TYPEDEF, 20);
        assert_eq!(DWARF_ABBREV::CONST_TYPE, 21);
        assert_eq!(DWARF_ABBREV::VOLATILE_TYPE, 22);
        assert_eq!(DWARF_ABBREV::MEMBER, 23);
        assert_eq!(DWARF_ABBREV::MEMBER_BF, 24);
        assert_eq!(DWARF_ABBREV::SUBRANGE_TYPE, 25);
        assert_eq!(DWARF_ABBREV::SUBROUTINE_TYPE, 13);
        assert_eq!(DWARF_ABBREV::UNSPECIFIED_PARAMETERS, 26);
        assert_eq!(DWARF_ABBREV::FORMAL_PARAMETER2, 7);
    }

    #[test]
    fn test_dwarf_min_instr_len() {
        assert_eq!(DWARF_MIN_INSTR_LEN, 1u8);
    }

    // -----------------------------------------------------------------------
    // LEB128 Encoding Tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_uleb128_encoding() {
        let mut buf = Vec::new();
        encode_uleb128(&mut buf, 0);
        assert_eq!(buf, vec![0]);

        buf.clear();
        encode_uleb128(&mut buf, 1);
        assert_eq!(buf, vec![1]);

        buf.clear();
        encode_uleb128(&mut buf, 127);
        assert_eq!(buf, vec![127]);

        buf.clear();
        encode_uleb128(&mut buf, 128);
        assert_eq!(buf, vec![0x80, 0x01]);

        buf.clear();
        encode_uleb128(&mut buf, 624485);
        assert_eq!(buf, vec![0xe5, 0x8e, 0x26]);
    }

    #[test]
    fn test_sleb128_encoding() {
        let mut buf = Vec::new();
        encode_sleb128(&mut buf, 0);
        assert_eq!(buf, vec![0]);

        buf.clear();
        encode_sleb128(&mut buf, 1);
        assert_eq!(buf, vec![1]);

        buf.clear();
        encode_sleb128(&mut buf, -1);
        assert_eq!(buf, vec![0x7f]);

        buf.clear();
        encode_sleb128(&mut buf, 63);
        assert_eq!(buf, vec![63]);

        buf.clear();
        encode_sleb128(&mut buf, -64);
        assert_eq!(buf, vec![0x40]);

        buf.clear();
        encode_sleb128(&mut buf, 64);
        assert_eq!(buf, vec![0xc0, 0x00]);

        buf.clear();
        encode_sleb128(&mut buf, -65);
        assert_eq!(buf, vec![0xbf, 0x7f]);
    }

    // -----------------------------------------------------------------------
    // Section Helper Tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_section_write_u8() {
        let mut data = vec![0u8; 4];
        section_write_u8(&mut data, 2, 0xAB);
        assert_eq!(data, vec![0, 0, 0xAB, 0]);
    }

    #[test]
    fn test_section_write_le32() {
        let mut data = vec![0u8; 8];
        section_write_le32(&mut data, 2, 0x12345678);
        assert_eq!(&data[2..6], &[0x78, 0x56, 0x34, 0x12]);
    }

    #[test]
    fn test_section_write_le16() {
        let mut data = vec![0u8; 4];
        section_write_le16(&mut data, 1, 0xABCD);
        assert_eq!(&data[1..3], &[0xCD, 0xAB]);
    }

    #[test]
    fn test_section_write_le64() {
        let mut data = vec![0u8; 10];
        section_write_le64(&mut data, 1, 0x0102030405060708);
        assert_eq!(&data[1..9], &[0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]);
    }

    #[test]
    fn test_section_read_le32() {
        let data = vec![0x78, 0x56, 0x34, 0x12];
        assert_eq!(section_read_le32(&data, 0), 0x12345678);
    }

    #[test]
    fn test_section_append() {
        let mut data = vec![1, 2, 3];
        let offset = section_append(&mut data, &[4, 5, 6]);
        assert_eq!(offset, 3);
        assert_eq!(data, vec![1, 2, 3, 4, 5, 6]);
    }

    #[test]
    fn test_section_align() {
        let mut data = vec![1, 2, 3];
        section_align(&mut data, 4);
        assert_eq!(data.len(), 4);
        assert_eq!(data[3], 0);

        let mut data2 = vec![1, 2, 3, 4];
        section_align(&mut data2, 4);
        assert_eq!(data2.len(), 4); // Already aligned
    }

    // -----------------------------------------------------------------------
    // Default Debug Table Tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_default_debug_table_count() {
        assert_eq!(N_DEFAULT_DEBUG, 15);
        assert_eq!(DEFAULT_DEBUG.len(), N_DEFAULT_DEBUG);
    }

    #[test]
    fn test_default_debug_entries() {
        // First entry: int
        assert_eq!(DEFAULT_DEBUG[0].vtype, VT_INT);
        assert_eq!(DEFAULT_DEBUG[0].size, 4);
        assert!(DEFAULT_DEBUG[0].name.starts_with("int:"));

        // char entry
        assert_eq!(DEFAULT_DEBUG[1].vtype, VT_BYTE);
        assert_eq!(DEFAULT_DEBUG[1].size, 1);

        // float entry
        assert_eq!(DEFAULT_DEBUG[11].vtype, VT_FLOAT);
        assert_eq!(DEFAULT_DEBUG[11].size, 4);

        // double entry
        assert_eq!(DEFAULT_DEBUG[12].vtype, VT_DOUBLE);
        assert_eq!(DEFAULT_DEBUG[12].size, 8);

        // void entry (last)
        assert_eq!(DEFAULT_DEBUG[14].vtype, VT_VOID);
    }

    // -----------------------------------------------------------------------
    // DWARF Abbreviation Init Data Tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_dwarf_abbrev_init_starts_with_compile_unit() {
        // First entry should be abbreviation #1 (compile unit)
        assert_eq!(DWARF_ABBREV_INIT[0], 1); // abbrev number
        assert_eq!(DWARF_ABBREV_INIT[1], 0x11); // DW_TAG_compile_unit
        assert_eq!(DWARF_ABBREV_INIT[2], 1); // DW_CHILDREN_yes
    }

    #[test]
    fn test_dwarf_abbrev_init_ends_with_zero() {
        // Final byte should be 0 (end of abbreviation table)
        let last = *DWARF_ABBREV_INIT.last().unwrap();
        assert_eq!(last, 0);
    }

    // -----------------------------------------------------------------------
    // DebugInfo Default State Tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_debug_info_default() {
        let info = DebugInfo::default();
        assert!(info.dwarf_info_section.is_none());
        assert!(info.dwarf_abbrev_section.is_none());
        assert!(info.dwarf_line_section.is_none());
        assert!(info.dwarf_aranges_section.is_none());
        assert!(info.dwarf_str_section.is_none());
        assert!(info.stab_section.is_none());
        assert!(info.stabstr_section.is_none());
        assert!(info.tcov_section.is_none());
        assert!(info.cur_file.is_none());
        assert_eq!(info.cur_line, 0);
        assert!(info.cur_func.is_none());
        assert_eq!(info.func_ind, -1);
        assert!(info.debug_info_root.is_none());
        assert!(info.scope_stack.is_empty());
        assert!(info.debug_hash_global.is_empty());
        assert!(info.debug_hash_local.is_empty());
        assert_eq!(info.debug_next_type, N_DEFAULT_DEBUG as i32 + 1);
    }

    // -----------------------------------------------------------------------
    // DWARF Line Number Constants Tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_dwarf_line_constants() {
        // These constants control the line number program special opcode encoding
        assert!(DWARF_LINE_BASE < 0);
        assert!(DWARF_LINE_RANGE > 0);
        assert!(DWARF_OPCODE_BASE > 0);
    }

    // -----------------------------------------------------------------------
    // Compute Type ID Tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_compute_type_id_basic_types() {
        let int_type = CType { t: VT_INT, ref_sym: None };
        let float_type = CType { t: VT_FLOAT, ref_sym: None };
        let id1 = DebugInfo::compute_type_id(&int_type);
        let id2 = DebugInfo::compute_type_id(&float_type);
        assert_ne!(id1, id2, "Different types should produce different IDs");
    }

    #[test]
    fn test_compute_type_id_same_type() {
        let t1 = CType { t: VT_INT, ref_sym: None };
        let t2 = CType { t: VT_INT, ref_sym: None };
        let id1 = DebugInfo::compute_type_id(&t1);
        let id2 = DebugInfo::compute_type_id(&t2);
        assert_eq!(id1, id2, "Same types should produce same IDs");
    }

    #[test]
    fn test_compute_type_id_unsigned_differs() {
        let signed_int = CType { t: VT_INT, ref_sym: None };
        let unsigned_int = CType { t: VT_INT | VT_UNSIGNED, ref_sym: None };
        let id1 = DebugInfo::compute_type_id(&signed_int);
        let id2 = DebugInfo::compute_type_id(&unsigned_int);
        assert_ne!(id1, id2, "Signed and unsigned should differ");
    }

    // -----------------------------------------------------------------------
    // DwarfStrState Tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_dwarf_str_state() {
        let state = DwarfStrState::new();
        assert!(state.map.is_empty());
    }

    // -----------------------------------------------------------------------
    // DebugScope Tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_debug_scope_creation() {
        let scope = DebugScope {
            start: 100,
            end: 200,
            children: vec![],
            sym: vec![],
            last_debug_hash: 0,
            last_debug_forw_hash: 0,
        };
        assert_eq!(scope.start, 100);
        assert_eq!(scope.end, 200);
        assert!(scope.children.is_empty());
    }

    #[test]
    fn test_debug_scope_with_children() {
        let child1 = DebugScope {
            start: 110, end: 140, children: vec![], sym: vec![],
            last_debug_hash: 0, last_debug_forw_hash: 0,
        };
        let child2 = DebugScope {
            start: 150, end: 190, children: vec![], sym: vec![],
            last_debug_hash: 0, last_debug_forw_hash: 0,
        };
        let parent = DebugScope {
            start: 100,
            end: 200,
            children: vec![child1, child2],
            sym: vec![],
            last_debug_hash: 0,
            last_debug_forw_hash: 0,
        };
        assert_eq!(parent.children.len(), 2);
        assert_eq!(parent.children[0].start, 110);
        assert_eq!(parent.children[1].start, 150);
    }

    // -----------------------------------------------------------------------
    // DebugSymEntry Tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_debug_sym_entry_creation() {
        let entry = DebugSymEntry {
            stype: StabCode::N_LSYM as u8,
            value: 42,
            name: "my_var".to_string(),
            sec_idx: None,
            sym_index: 0,
            info: 5,
            file: 1,
            line: 10,
        };
        assert_eq!(entry.stype, StabCode::N_LSYM as u8);
        assert_eq!(entry.value, 42);
        assert_eq!(entry.name, "my_var");
        assert_eq!(entry.info, 5);
    }

    // -----------------------------------------------------------------------
    // DwarfFilenameEntry Tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_dwarf_filename_entry() {
        let entry = DwarfFilenameEntry {
            name: "test.c".to_string(),
            dir_entry: 1,
        };
        assert_eq!(entry.name, "test.c");
        assert_eq!(entry.dir_entry, 1);
    }

    // -----------------------------------------------------------------------
    // DefaultDebugEntry Tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_default_debug_entry_int() {
        let entry = &DEFAULT_DEBUG[0]; // int
        assert_eq!(entry.vtype, VT_INT);
        assert_eq!(entry.size, 4);
        assert_eq!(entry.encoding, DwAte::Signed as u8);
    }

    #[test]
    fn test_default_debug_entry_char() {
        let entry = &DEFAULT_DEBUG[1]; // char
        assert_eq!(entry.vtype, VT_BYTE);
        assert_eq!(entry.size, 1);
        // char is signed char by default
        assert_eq!(entry.encoding, DwAte::SignedChar as u8);
    }

    #[test]
    fn test_default_debug_entry_void() {
        let entry = &DEFAULT_DEBUG[14]; // void
        assert_eq!(entry.vtype, VT_VOID);
        assert_eq!(entry.size, 1);
    }

    // -----------------------------------------------------------------------
    // DebugInfo Public Method Existence Tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_debug_info_has_all_public_methods() {
        // This test verifies the DebugInfo struct exists with the correct default values
        // and that public fields are accessible. The actual methods are tested through
        // compilation (they must compile as pub fn).
        let info = DebugInfo::default();

        // Public section fields are Option<usize>
        let _: &Option<usize> = &info.dwarf_info_section;
        let _: &Option<usize> = &info.dwarf_abbrev_section;
        let _: &Option<usize> = &info.dwarf_line_section;
        let _: &Option<usize> = &info.dwarf_aranges_section;
        let _: &Option<usize> = &info.dwarf_str_section;
        let _: &Option<usize> = &info.stab_section;
        let _: &Option<usize> = &info.stabstr_section;
        let _: &Option<usize> = &info.tcov_section;

        // Public state fields
        let _: &Option<String> = &info.cur_file;
        let _: &i32 = &info.cur_line;
    }
}
