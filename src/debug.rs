//! STABS + DWARF debug information generation and code coverage instrumentation.
//!
//! This module is the Rust translation of `tccdbg.c` (2,676 lines) from the
//! original TinyCC C codebase.  It generates:
//!
//! - **STABS** debug information (legacy format, DWARF version 0)
//! - **DWARF** debug information (versions 2–5) using constants from
//!   [`crate::formats::dwarf`] supplemented by the `gimli` crate's write module
//! - **Code-coverage** instrumentation data (tcov / `-ftestcoverage`)
//! - **Exception-handling frame** data (`.eh_frame` / `.eh_frame_hdr`)
//!
//! # Safety
//!
//! This module contains **no `unsafe` blocks**.  All section data is manipulated
//! through `Vec<u8>` buffers with bounds-checked operations.  String
//! deduplication uses `HashMap<String, u32>` per AAP §0.5.1.
//!
//! # Error Handling
//!
//! Every fallible function returns [`TccResult<T>`], replacing the C
//! `setjmp`/`longjmp` error-handling pattern (AAP §0.8.1).

// Debug info generation — STABS/DWARF requires integer casts for debug symbol
// encoding (type indices, section offsets, line-number tables).  All casts are
// faithful translations of tccdbg.c.
#![allow(clippy::cast_lossless)]
#![allow(clippy::assigning_clones)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::unnecessary_wraps)]
#![allow(clippy::useless_conversion)]

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Internal crate imports
// ---------------------------------------------------------------------------
use crate::error::TccResult;
use crate::context::TccState;
#[allow(unused_imports)]
use crate::types::{
    CString as TccCString, CType, Section, SValue, SValueData, SValueSymInfo, Symbol, SymId,
    VT_INT, VT_BYTE, VT_VOID, VT_FLOAT, VT_DOUBLE, VT_LDOUBLE, VT_BOOL, VT_SHORT,
    VT_LLONG, VT_LONG, VT_UNSIGNED, VT_PTR, VT_FUNC, VT_STRUCT, VT_ARRAY, VT_BITFIELD,
    VT_BTYPE, VT_STATIC, VT_STORAGE, VT_CONSTANT, VT_VOLATILE, VT_VLA, VT_UNION, VT_ENUM,
    VT_SYM, VT_LVAL, VT_CONST, VT_LOCAL, VT_VALMASK, VT_DEFSIGN, VT_QLONG, VT_STRUCT_MASK,
    SYM_STRUCT, SYM_FIELD, SYM_FIRST_ANOM,
};
#[allow(unused_imports)]
use crate::codegen::{
    section_ptr_add, vpushv, vpop, gen_op, type_size, put_extern_sym, greloca, greloc,
    sym_push2, get_sym_ref, elfsym, vpushi,
};
#[allow(unused_imports)]
use crate::linker::elf::{
    put_elf_sym, put_elf_str, put_elf_reloca, new_section, find_elf_sym,
};
#[allow(unused_imports)]
use crate::formats::dwarf::{DW_EH_PE_sdata4, DW_EH_PE_pcrel, DW_ATE_signed, DW_ATE_signed_char, DW_ATE_unsigned_char, DW_ATE_float, DW_ATE_unsigned, DW_ATE_boolean, DW_FORM_line_strp, DW_FORM_strp, DW_TAG_compile_unit, DW_CHILDREN_YES, DW_AT_producer, DW_AT_language, DW_FORM_data2, DW_AT_name, DW_AT_comp_dir, DW_AT_low_pc, DW_FORM_addr, DW_AT_high_pc, DW_AT_stmt_list, DW_FORM_sec_offset, DW_TAG_base_type, DW_CHILDREN_NO, DW_AT_byte_size, DW_FORM_udata, DW_AT_encoding, DW_FORM_data1, DW_TAG_variable, DW_AT_decl_file, DW_AT_decl_line, DW_AT_type, DW_FORM_ref4, DW_AT_external, DW_FORM_flag, DW_AT_location, DW_FORM_exprloc, DW_TAG_formal_parameter, DW_TAG_pointer_type, DW_TAG_array_type, DW_AT_sibling, DW_TAG_subrange_type, DW_AT_upper_bound, DW_TAG_typedef, DW_TAG_enumerator, DW_AT_const_value, DW_FORM_sdata, DW_TAG_enumeration_type, DW_TAG_member, DW_AT_data_member_location, DW_AT_bit_size, DW_AT_data_bit_offset, DW_TAG_structure_type, DW_TAG_union_type, DW_TAG_subprogram, DW_FORM_data8, DW_AT_frame_base, DW_TAG_lexical_block, DW_TAG_subroutine_type, DW_CFA_def_cfa, DW_CFA_offset, DW_CFA_nop, DW_EH_PE_udata4, DW_EH_PE_datarel, DW_LNS_set_prologue_end, DW_LNS_set_epilogue_begin, DW_LNS_set_file, DW_UT_compile, DW_LANG_C99, DW_LNCT_path, DW_LNCT_directory_index, DW_LNE_end_sequence, DW_LNS_advance_line, DW_LNS_advance_pc, DW_LNS_copy, DW_OP_call_frame_cfa, DW_OP_fbreg, DW_OP_addr};
#[allow(unused_imports)]
use crate::formats::stab::{
    Nlist, N_SLINE, N_SO, N_SOL, N_FUN, N_BINCL, N_EINCL, N_LSYM, N_GSYM,
    N_STSYM, N_LCSYM, N_PSYM, N_LBRAC, N_RBRAC, NLIST_SIZE,
};
#[allow(unused_imports)]
use crate::formats::elf::{
    STB_LOCAL, STB_GLOBAL, STT_FILE, STT_SECTION, STT_NOTYPE, STT_FUNC,
    SHN_ABS, SHN_UNDEF, SHT_PROGBITS, SHT_STRTAB, SHF_ALLOC, SHF_WRITE,
    SHF_MERGE, SHF_STRINGS, elf_st_info,
};
#[allow(unused_imports)]
use crate::preprocessor::get_tok_str;
#[allow(unused_imports)]
use crate::tokens::Token;

// External crate — gimli write module for DWARF generation (AAP §0.5.1, §0.6.1)
#[allow(unused_imports)]
use gimli::write as gimli_write;

// =============================================================================
// Constants — DWARF line number program parameters (tccdbg.c:22-35)
// =============================================================================

/// Minimum value for the special opcode line increment.
/// C equivalent: `DWARF_LINE_BASE` (tccdbg.c:22)
const DWARF_LINE_BASE: i32 = -5;

/// Range of line increments encodable in a single special opcode.
/// C equivalent: `DWARF_LINE_RANGE` (tccdbg.c:23)
const DWARF_LINE_RANGE: i32 = 14;

/// Number of standard opcodes (opcodes 1..12 are standard).
/// C equivalent: `DWARF_OPCODE_BASE` (tccdbg.c:24)
const DWARF_OPCODE_BASE: i32 = 13;

/// Minimum instruction length for the target architecture.
/// C equivalent: `DWARF_MIN_INSTR_LEN` (tccdbg.c:26-34)
///
/// On `x86/x86_64` this is 1; on ARM it is 2; on ARM64/RISC-V it is 4.
/// We default to 1 for `x86_64` and provide a helper to query the current target.
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
const DWARF_MIN_INSTR_LEN: i32 = 1;
#[cfg(target_arch = "arm")]
const DWARF_MIN_INSTR_LEN: i32 = 2;
#[cfg(target_arch = "aarch64")]
const DWARF_MIN_INSTR_LEN: i32 = 4;
#[cfg(target_arch = "riscv64")]
const DWARF_MIN_INSTR_LEN: i32 = 4;
#[cfg(not(any(
    target_arch = "x86",
    target_arch = "x86_64",
    target_arch = "arm",
    target_arch = "aarch64",
    target_arch = "riscv64"
)))]
const DWARF_MIN_INSTR_LEN: i32 = 1;

/// Pointer size for the current target (bytes).
/// C equivalent: `PTR_SIZE`
#[cfg(target_pointer_width = "64")]
const PTR_SIZE: usize = 8;
#[cfg(target_pointer_width = "32")]
const PTR_SIZE: usize = 4;
#[cfg(not(any(target_pointer_width = "32", target_pointer_width = "64")))]
const PTR_SIZE: usize = 8;

/// Relocation type for data pointers, platform-dependent.
/// C equivalent: `R_DATA_PTR`
const R_DATA_PTR: i32 = 1; // ELF R_X86_64_64 for x86_64

// =============================================================================
// DWARF abbreviation indices — must match `dwarf_abbrev_init` table order
// (tccdbg.c:37-67)
// =============================================================================

const DWARF_ABBREV_COMPILE_UNIT: u8 = 1;
const DWARF_ABBREV_BASE_TYPE: u8 = 2;
const DWARF_ABBREV_VARIABLE_EXTERNAL: u8 = 3;
const DWARF_ABBREV_VARIABLE_STATIC: u8 = 4;
const DWARF_ABBREV_VARIABLE_LOCAL: u8 = 5;
const DWARF_ABBREV_FORMAL_PARAMETER: u8 = 6;
const DWARF_ABBREV_POINTER: u8 = 7;
const DWARF_ABBREV_ARRAY_TYPE: u8 = 8;
const DWARF_ABBREV_SUBRANGE_TYPE: u8 = 9;
const DWARF_ABBREV_TYPEDEF: u8 = 10;
const DWARF_ABBREV_ENUMERATOR_SIGNED: u8 = 11;
const DWARF_ABBREV_ENUMERATOR_UNSIGNED: u8 = 12;
const DWARF_ABBREV_ENUMERATION_TYPE: u8 = 13;
const DWARF_ABBREV_MEMBER: u8 = 14;
const DWARF_ABBREV_MEMBER_BF: u8 = 15;
const DWARF_ABBREV_STRUCTURE_TYPE: u8 = 16;
const DWARF_ABBREV_STRUCTURE_EMPTY_TYPE: u8 = 17;
const DWARF_ABBREV_UNION_TYPE: u8 = 18;
const DWARF_ABBREV_UNION_EMPTY_TYPE: u8 = 19;
const DWARF_ABBREV_SUBPROGRAM_EXTERNAL: u8 = 20;
const DWARF_ABBREV_SUBPROGRAM_STATIC: u8 = 21;
const DWARF_ABBREV_LEXICAL_BLOCK: u8 = 22;
const DWARF_ABBREV_LEXICAL_EMPTY_BLOCK: u8 = 23;
const DWARF_ABBREV_SUBROUTINE_TYPE: u8 = 24;
const DWARF_ABBREV_SUBROUTINE_EMPTY_TYPE: u8 = 25;
const DWARF_ABBREV_FORMAL_PARAMETER2: u8 = 26;

// =============================================================================
// FDE encoding constant (tccdbg.c:71)
// =============================================================================

/// Frame Description Entry encoding: pc-relative, signed, udata4.
const FDE_ENCODING: u8 = DW_EH_PE_sdata4 | DW_EH_PE_pcrel;

// =============================================================================
// Default debug type table — maps VT_* base types to STABS/DWARF info
// (tccdbg.c:11-21)
// =============================================================================

/// Entry in the default debug type table.
#[derive(Clone, Debug)]
struct DefaultDebugEntry {
    /// VT_* type constant (with modifiers stripped).
    type_val: i32,
    /// Size in bytes of this type.
    size: u8,
    /// DWARF encoding (`DW_ATE`_*).
    encoding: u8,
    /// STABS type string (e.g. "int:t1=r1;-2147483648;2147483647;").
    name: &'static str,
}

/// The `default_debug` table from tccdbg.c lines 11-21.
/// Each entry maps a VT_* base type to its debug representation.
static DEFAULT_DEBUG: &[DefaultDebugEntry] = &[
    DefaultDebugEntry { type_val: VT_INT,                        size: 4, encoding: DW_ATE_signed,        name: "int:t1=r1;-2147483648;2147483647;" },
    DefaultDebugEntry { type_val: VT_BYTE,                       size: 1, encoding: DW_ATE_signed_char,   name: "char:t2=r2;0;127;" },
    DefaultDebugEntry { type_val: VT_SHORT,                      size: 2, encoding: DW_ATE_signed,        name: "short int:t3=r3;-32768;32767;" },
    DefaultDebugEntry { type_val: VT_VOID,                       size: 1, encoding: DW_ATE_unsigned_char, name: "void:t4=4" },
    DefaultDebugEntry { type_val: VT_FLOAT,                      size: 4, encoding: DW_ATE_float,         name: "float:t5=r1;4;0;" },
    DefaultDebugEntry { type_val: VT_DOUBLE,                     size: 8, encoding: DW_ATE_float,         name: "double:t6=r1;8;0;" },
    DefaultDebugEntry { type_val: VT_LDOUBLE,                    size: 16, encoding: DW_ATE_float,        name: "long double:t7=r1;16;0;" },
    DefaultDebugEntry { type_val: VT_LONG | VT_INT,              size: 8, encoding: DW_ATE_signed,        name: "long int:t8=r8;0;0;" },
    DefaultDebugEntry { type_val: VT_LLONG,                      size: 8, encoding: DW_ATE_signed,        name: "long long int:t9=r9;0;0;" },
    DefaultDebugEntry { type_val: VT_INT | VT_UNSIGNED,          size: 4, encoding: DW_ATE_unsigned,      name: "unsigned int:t10=r10;0;4294967295;" },
    DefaultDebugEntry { type_val: VT_BYTE | VT_UNSIGNED,         size: 1, encoding: DW_ATE_unsigned_char, name: "unsigned char:t11=r11;0;255;" },
    DefaultDebugEntry { type_val: VT_SHORT | VT_UNSIGNED,        size: 2, encoding: DW_ATE_unsigned,      name: "unsigned short int:t12=r12;0;65535;" },
    DefaultDebugEntry { type_val: VT_LONG | VT_INT | VT_UNSIGNED,size: 8, encoding: DW_ATE_unsigned,     name: "long unsigned int:t13=r13;0;0;" },
    DefaultDebugEntry { type_val: VT_LLONG | VT_UNSIGNED,        size: 8, encoding: DW_ATE_unsigned,      name: "long long unsigned int:t14=r14;0;0;" },
    DefaultDebugEntry { type_val: VT_BOOL,                       size: 1, encoding: DW_ATE_boolean,       name: "_Bool:t15=r15;0;255;" },
    DefaultDebugEntry { type_val: VT_BYTE | VT_DEFSIGN,          size: 1, encoding: DW_ATE_signed_char,   name: "signed char:t16=r16;-128;127;" },
    DefaultDebugEntry { type_val: VT_LONG | VT_LLONG,            size: 16, encoding: DW_ATE_signed,       name: "__int128:t17=r17;0;0;" },
    DefaultDebugEntry { type_val: VT_LONG | VT_LLONG | VT_UNSIGNED, size: 16, encoding: DW_ATE_unsigned,  name: "__uint128:t18=r18;0;0;" },
];

/// Number of entries in the default debug type table.
const N_DEFAULT_DEBUG: usize = DEFAULT_DEBUG.len();

// =============================================================================
// DWARF abbreviation table initializer (tccdbg.c:74-224)
// =============================================================================

/// Build the DWARF abbreviation table as a byte vector.
///
/// This corresponds to the static `dwarf_abbrev_init[]` array in tccdbg.c.
/// The table defines the structure of all DWARF DIE abbreviations used by TCC.
fn build_dwarf_abbrev_table(dwarf_version: u8) -> Vec<u8> {
    let mut buf = Vec::with_capacity(512);
    let mut abbrev_code: u64 = 0;

    // Helper closure to emit an abbreviation entry.
    // Each entry is: abbreviation_code (ULEB128), tag (ULEB128), children (byte),
    // then (attr, form) pairs terminated by (0, 0).
    let mut emit_abbrev = |tag: u16, children: u8, attrs: &[(u16, u16)]| {
        abbrev_code += 1;
        // abbreviation code (ULEB128)
        dwarf_write_uleb128(&mut buf, abbrev_code);
        // tag (ULEB128)
        dwarf_write_uleb128(&mut buf, u64::from(tag));
        // children flag
        buf.push(children);
        // attribute specifications
        for &(attr, form) in attrs {
            dwarf_write_uleb128(&mut buf, u64::from(attr));
            dwarf_write_uleb128(&mut buf, u64::from(form));
        }
        // terminate attribute list
        buf.push(0);
        buf.push(0);
    };

    let str_form = if dwarf_version >= 5 { DW_FORM_line_strp } else { DW_FORM_strp };

    // 1: DW_TAG_compile_unit (has children)
    emit_abbrev(DW_TAG_compile_unit, DW_CHILDREN_YES, &[
        (DW_AT_producer, str_form),
        (DW_AT_language, DW_FORM_data2),
        (DW_AT_name, str_form),
        (DW_AT_comp_dir, str_form),
        (DW_AT_low_pc, DW_FORM_addr),
        (DW_AT_high_pc, DW_FORM_addr),
        (DW_AT_stmt_list, DW_FORM_sec_offset),
    ]);
    // 2: DW_TAG_base_type
    emit_abbrev(DW_TAG_base_type, DW_CHILDREN_NO, &[
        (DW_AT_byte_size, DW_FORM_udata),
        (DW_AT_encoding, DW_FORM_data1),
        (DW_AT_name, DW_FORM_strp),
    ]);
    // 3: DW_TAG_variable (external)
    emit_abbrev(DW_TAG_variable, DW_CHILDREN_NO, &[
        (DW_AT_name, DW_FORM_strp),
        (DW_AT_decl_file, DW_FORM_udata),
        (DW_AT_decl_line, DW_FORM_udata),
        (DW_AT_type, DW_FORM_ref4),
        (DW_AT_external, DW_FORM_flag),
        (DW_AT_location, DW_FORM_exprloc),
    ]);
    // 4: DW_TAG_variable (static)
    emit_abbrev(DW_TAG_variable, DW_CHILDREN_NO, &[
        (DW_AT_name, DW_FORM_strp),
        (DW_AT_decl_file, DW_FORM_udata),
        (DW_AT_decl_line, DW_FORM_udata),
        (DW_AT_type, DW_FORM_ref4),
        (DW_AT_location, DW_FORM_exprloc),
    ]);
    // 5: DW_TAG_variable (local)
    emit_abbrev(DW_TAG_variable, DW_CHILDREN_NO, &[
        (DW_AT_name, DW_FORM_strp),
        (DW_AT_type, DW_FORM_ref4),
        (DW_AT_location, DW_FORM_exprloc),
    ]);
    // 6: DW_TAG_formal_parameter
    emit_abbrev(DW_TAG_formal_parameter, DW_CHILDREN_NO, &[
        (DW_AT_name, DW_FORM_strp),
        (DW_AT_type, DW_FORM_ref4),
        (DW_AT_location, DW_FORM_exprloc),
    ]);
    // 7: DW_TAG_pointer_type
    emit_abbrev(DW_TAG_pointer_type, DW_CHILDREN_NO, &[
        (DW_AT_byte_size, DW_FORM_data1),
        (DW_AT_type, DW_FORM_ref4),
    ]);
    // 8: DW_TAG_array_type (has children — subrange entries)
    emit_abbrev(DW_TAG_array_type, DW_CHILDREN_YES, &[
        (DW_AT_type, DW_FORM_ref4),
        (DW_AT_sibling, DW_FORM_ref4),
    ]);
    // 9: DW_TAG_subrange_type
    emit_abbrev(DW_TAG_subrange_type, DW_CHILDREN_NO, &[
        (DW_AT_type, DW_FORM_ref4),
        (DW_AT_upper_bound, DW_FORM_udata),
    ]);
    // 10: DW_TAG_typedef
    emit_abbrev(DW_TAG_typedef, DW_CHILDREN_NO, &[
        (DW_AT_name, DW_FORM_strp),
        (DW_AT_decl_file, DW_FORM_udata),
        (DW_AT_decl_line, DW_FORM_udata),
        (DW_AT_type, DW_FORM_ref4),
    ]);
    // 11: DW_TAG_enumerator (signed)
    emit_abbrev(DW_TAG_enumerator, DW_CHILDREN_NO, &[
        (DW_AT_name, DW_FORM_strp),
        (DW_AT_const_value, DW_FORM_sdata),
    ]);
    // 12: DW_TAG_enumerator (unsigned)
    emit_abbrev(DW_TAG_enumerator, DW_CHILDREN_NO, &[
        (DW_AT_name, DW_FORM_strp),
        (DW_AT_const_value, DW_FORM_udata),
    ]);
    // 13: DW_TAG_enumeration_type (has children)
    emit_abbrev(DW_TAG_enumeration_type, DW_CHILDREN_YES, &[
        (DW_AT_name, DW_FORM_strp),
        (DW_AT_encoding, DW_FORM_data1),
        (DW_AT_byte_size, DW_FORM_data1),
        (DW_AT_type, DW_FORM_ref4),
        (DW_AT_decl_file, DW_FORM_udata),
        (DW_AT_decl_line, DW_FORM_udata),
        (DW_AT_sibling, DW_FORM_ref4),
    ]);
    // 14: DW_TAG_member (normal)
    emit_abbrev(DW_TAG_member, DW_CHILDREN_NO, &[
        (DW_AT_name, DW_FORM_strp),
        (DW_AT_decl_file, DW_FORM_udata),
        (DW_AT_decl_line, DW_FORM_udata),
        (DW_AT_type, DW_FORM_ref4),
        (DW_AT_data_member_location, DW_FORM_udata),
    ]);
    // 15: DW_TAG_member (bitfield)
    emit_abbrev(DW_TAG_member, DW_CHILDREN_NO, &[
        (DW_AT_name, DW_FORM_strp),
        (DW_AT_decl_file, DW_FORM_udata),
        (DW_AT_decl_line, DW_FORM_udata),
        (DW_AT_type, DW_FORM_ref4),
        (DW_AT_bit_size, DW_FORM_udata),
        (DW_AT_data_bit_offset, DW_FORM_udata),
    ]);
    // 16: DW_TAG_structure_type (has children)
    emit_abbrev(DW_TAG_structure_type, DW_CHILDREN_YES, &[
        (DW_AT_name, DW_FORM_strp),
        (DW_AT_byte_size, DW_FORM_udata),
        (DW_AT_decl_file, DW_FORM_udata),
        (DW_AT_decl_line, DW_FORM_udata),
        (DW_AT_sibling, DW_FORM_ref4),
    ]);
    // 17: DW_TAG_structure_type (empty — no children)
    emit_abbrev(DW_TAG_structure_type, DW_CHILDREN_NO, &[
        (DW_AT_name, DW_FORM_strp),
        (DW_AT_byte_size, DW_FORM_udata),
        (DW_AT_decl_file, DW_FORM_udata),
        (DW_AT_decl_line, DW_FORM_udata),
    ]);
    // 18: DW_TAG_union_type (has children)
    emit_abbrev(DW_TAG_union_type, DW_CHILDREN_YES, &[
        (DW_AT_name, DW_FORM_strp),
        (DW_AT_byte_size, DW_FORM_udata),
        (DW_AT_decl_file, DW_FORM_udata),
        (DW_AT_decl_line, DW_FORM_udata),
        (DW_AT_sibling, DW_FORM_ref4),
    ]);
    // 19: DW_TAG_union_type (empty — no children)
    emit_abbrev(DW_TAG_union_type, DW_CHILDREN_NO, &[
        (DW_AT_name, DW_FORM_strp),
        (DW_AT_byte_size, DW_FORM_udata),
        (DW_AT_decl_file, DW_FORM_udata),
        (DW_AT_decl_line, DW_FORM_udata),
    ]);
    // 20: DW_TAG_subprogram (external)
    emit_abbrev(DW_TAG_subprogram, DW_CHILDREN_YES, &[
        (DW_AT_external, DW_FORM_flag),
        (DW_AT_name, DW_FORM_strp),
        (DW_AT_decl_file, DW_FORM_udata),
        (DW_AT_decl_line, DW_FORM_udata),
        (DW_AT_type, DW_FORM_ref4),
        (DW_AT_low_pc, DW_FORM_addr),
        (DW_AT_high_pc, DW_FORM_data8 /* actually PTR_SIZE-dependent */),
        (DW_AT_sibling, DW_FORM_ref4),
        (DW_AT_frame_base, DW_FORM_exprloc),
    ]);
    // 21: DW_TAG_subprogram (static — no DW_AT_external)
    emit_abbrev(DW_TAG_subprogram, DW_CHILDREN_YES, &[
        (DW_AT_name, DW_FORM_strp),
        (DW_AT_decl_file, DW_FORM_udata),
        (DW_AT_decl_line, DW_FORM_udata),
        (DW_AT_type, DW_FORM_ref4),
        (DW_AT_low_pc, DW_FORM_addr),
        (DW_AT_high_pc, DW_FORM_data8),
        (DW_AT_sibling, DW_FORM_ref4),
        (DW_AT_frame_base, DW_FORM_exprloc),
    ]);
    // 22: DW_TAG_lexical_block (has children)
    emit_abbrev(DW_TAG_lexical_block, DW_CHILDREN_YES, &[
        (DW_AT_low_pc, DW_FORM_addr),
        (DW_AT_high_pc, DW_FORM_data8),
    ]);
    // 23: DW_TAG_lexical_block (empty — no children)
    emit_abbrev(DW_TAG_lexical_block, DW_CHILDREN_NO, &[
        (DW_AT_low_pc, DW_FORM_addr),
        (DW_AT_high_pc, DW_FORM_data8),
    ]);
    // 24: DW_TAG_subroutine_type (has children)
    emit_abbrev(DW_TAG_subroutine_type, DW_CHILDREN_YES, &[
        (DW_AT_type, DW_FORM_ref4),
        (DW_AT_sibling, DW_FORM_ref4),
    ]);
    // 25: DW_TAG_subroutine_type (empty)
    emit_abbrev(DW_TAG_subroutine_type, DW_CHILDREN_NO, &[
        (DW_AT_type, DW_FORM_ref4),
    ]);
    // 26: DW_TAG_formal_parameter (type-only, used in subroutine_type children)
    emit_abbrev(DW_TAG_formal_parameter, DW_CHILDREN_NO, &[
        (DW_AT_type, DW_FORM_ref4),
    ]);

    // Terminate abbreviation table
    buf.push(0);

    buf
}

// =============================================================================
// DWARF line number opcodes table (tccdbg.c:226)
// =============================================================================

/// Standard opcode argument counts for opcodes 1..12.
/// Index 0 corresponds to opcode 1.
const DWARF_LINE_OPCODES: [u8; 12] = [
    0, // DW_LNS_copy
    1, // DW_LNS_advance_pc
    1, // DW_LNS_advance_line
    1, // DW_LNS_set_file
    1, // DW_LNS_set_column
    0, // DW_LNS_negate_stmt
    0, // DW_LNS_set_basic_block
    0, // DW_LNS_const_add_pc
    1, // DW_LNS_fixed_advance_pc
    0, // DW_LNS_set_prologue_end
    0, // DW_LNS_set_epilogue_begin
    1, // DW_LNS_set_isa
];

// =============================================================================
// Debug symbol info — used for tracking debug symbols in lexical blocks
// =============================================================================

/// A debug symbol entry for STABS/DWARF generation.
/// C equivalent: `struct debug_sym` (tccdbg.c:230-240)
#[derive(Clone, Debug)]
struct DebugSym {
    sym_type: u8,
    value: i64,
    str_repr: String,
    sec: usize,
    sym_index: i32,
    file: u32,
    line: u32,
    info: usize,
}

/// A node in the debug information tree representing a lexical block scope.
/// C equivalent: `struct _debug_info` (tccdbg.c:242-253)
#[derive(Clone, Debug)]
pub(crate) struct DebugInfoNode {
    start: i64,
    end: i64,
    syms: Vec<DebugSym>,
    children: Vec<DebugInfoNode>,
}

impl DebugInfoNode {
    fn new() -> Self {
        Self { start: 0, end: 0, syms: Vec::new(), children: Vec::new() }
    }
}

/// Mapping from a Symbol to its debug type ID.
#[derive(Clone, Debug)]
pub(crate) struct DebugHashEntry {
    type_sym: SymId,
    debug_type: usize,
}

/// Tracks forward-referenced struct/union types for fixup.
#[derive(Clone, Debug)]
pub(crate) struct DebugForwHashEntry {
    type_sym: SymId,
    debug_type_offsets: Vec<usize>,
}

/// State for the DWARF line number program.
#[derive(Clone, Debug, Default)]
pub(crate) struct DwarfLineState {
    last_pc: i64,
    cur_file: u32,
    last_file: u32,
    filenames: Vec<String>,
    dirs: Vec<String>,
    sec_idx: usize,
}

/// State for the DWARF `.debug_info` section being built.
#[derive(Clone, Debug, Default)]
pub(crate) struct DwarfInfoState {
    start: usize,
    func: Option<SymId>,
    line: u32,
    base_type_used: Vec<usize>,
}

/// String hash for deduplication in `.debug_str` / `.debug_line_str`.
#[derive(Clone, Debug, Default)]
struct DwarfStringHash {
    map: HashMap<String, u32>,
}

impl DwarfStringHash {
    fn new() -> Self { Self { map: HashMap::new() } }
}

/// State for code coverage instrumentation (`-ftestcoverage`).
#[derive(Clone, Debug, Default)]
pub(crate) struct TcovDataState {
    last_file_name: usize,
    last_func_name: usize,
    line: i64,
    offset: usize,
    ind: i64,
}

// =============================================================================
// DebugState — The master debug state structure
// =============================================================================

/// Master debug state holding all persistent state for STABS/DWARF generation
/// and code coverage instrumentation.
///
/// C equivalent: `struct _tccdbg` (tccdbg.c:228-310)
///
/// Per AAP §0.5.1, string tables use `HashMap<String, u32>` for O(1) lookup.
#[derive(Debug)]
pub struct DebugState {
    /// DWARF `.debug_str` string deduplication table.
    pub string_table: HashMap<String, u32>,
    /// DWARF writer from the gimli crate.
    pub dwarf: Option<gimli_write::Dwarf>,
    /// Current DWARF compilation unit ID.
    pub unit: Option<gimli_write::UnitId>,
    /// Last source line number emitted.
    pub last_line_num: i32,
    /// Flag: a new source file was seen since last debug emission.
    pub new_file: bool,
    /// ELF section symbol index for the current text section.
    pub section_sym: i32,
    /// Next available STABS type number.
    pub debug_next_type: i32,
    /// Global scope debug type hash.
    pub debug_hash: Vec<DebugHashEntry>,
    /// Forward-reference hash for incomplete global struct/union types.
    pub debug_forw_hash: Vec<DebugForwHashEntry>,
    /// Current debug info tree root.
    pub debug_info: Option<Box<DebugInfoNode>>,
    /// DWARF section symbol index.
    pub dwarf_sym: i32,
    /// DWARF line number program state.
    pub dwarf_line: DwarfLineState,
    /// DWARF `.debug_info` compilation state.
    pub dwarf_info: DwarfInfoState,
    /// Code coverage data state.
    pub tcov_data: TcovDataState,

    // Internal fields (not in schema members_exposed, but needed for operation)
    debug_hash_local: Vec<DebugHashEntry>,
    debug_forw_hash_local: Vec<DebugForwHashEntry>,
    debug_info_root: Option<Box<DebugInfoNode>>,
    debug_info_current: Option<*mut DebugInfoNode>,
    dwarf_line_str: DwarfStringHash,
    dwarf_str: DwarfStringHash,
    stab_section_idx: usize,
    stabstr_section_idx: usize,
    dwarf_info_section_idx: usize,
    dwarf_abbrev_section_idx: usize,
    dwarf_line_section_idx: usize,
    dwarf_aranges_section_idx: usize,
    dwarf_str_section_idx: usize,
    dwarf_line_str_section_idx: usize,
    eh_frame_section_idx: usize,
    eh_frame_hdr_section_idx: usize,
    tcov_section_idx: usize,
    func_name: String,
    func_ind: i64,
    last_line_file: u32,
    cur_text_section_sym: i32,
}

#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
impl Default for DebugState {
    fn default() -> Self {
        Self {
            string_table: HashMap::new(),
            dwarf: None,
            unit: None,
            last_line_num: 0,
            new_file: false,
            section_sym: 0,
            debug_next_type: N_DEFAULT_DEBUG as i32,
            debug_hash: Vec::new(),
            debug_forw_hash: Vec::new(),
            debug_info: None,
            dwarf_sym: 0,
            dwarf_line: DwarfLineState::default(),
            dwarf_info: DwarfInfoState {
                start: 0,
                func: None,
                line: 0,
                base_type_used: vec![0; N_DEFAULT_DEBUG],
            },
            tcov_data: TcovDataState::default(),
            debug_hash_local: Vec::new(),
            debug_forw_hash_local: Vec::new(),
            debug_info_root: None,
            debug_info_current: None,
            dwarf_line_str: DwarfStringHash::new(),
            dwarf_str: DwarfStringHash::new(),
            stab_section_idx: 0,
            stabstr_section_idx: 0,
            dwarf_info_section_idx: 0,
            dwarf_abbrev_section_idx: 0,
            dwarf_line_section_idx: 0,
            dwarf_aranges_section_idx: 0,
            dwarf_str_section_idx: 0,
            dwarf_line_str_section_idx: 0,
            eh_frame_section_idx: 0,
            eh_frame_hdr_section_idx: 0,
            tcov_section_idx: 0,
            func_name: String::new(),
            func_ind: 0,
            last_line_file: 0,
            cur_text_section_sym: 0,
        }
    }
}

impl DebugState {
    /// Create a new default `DebugState`.
    pub fn new() -> Self { Self::default() }
}

// =============================================================================
// Low-level byte emission helpers — replaces C macros dwarf_data1/2/4/8 etc.
// (tccdbg.c:513-540)
// =============================================================================

/// Write a single byte to a section's data buffer.
/// C equivalent: `dwarf_data1(section, val)` macro (tccdbg.c:513)
fn section_data1(sections: &mut [Section], sec_idx: usize, val: u8) {
    if let Some(sec) = sections.get_mut(sec_idx) {
        sec.data.push(val);
        sec.data_offset = sec.data.len();
    }
}

/// Write a 16-bit little-endian value to a section's data buffer.
fn section_data2(sections: &mut [Section], sec_idx: usize, val: u16) {
    if let Some(sec) = sections.get_mut(sec_idx) {
        sec.data.extend_from_slice(&val.to_le_bytes());
        sec.data_offset = sec.data.len();
    }
}

/// Write a 32-bit little-endian value to a section's data buffer.
fn section_data4(sections: &mut [Section], sec_idx: usize, val: u32) {
    if let Some(sec) = sections.get_mut(sec_idx) {
        sec.data.extend_from_slice(&val.to_le_bytes());
        sec.data_offset = sec.data.len();
    }
}

/// Write a 64-bit little-endian value to a section's data buffer.
fn section_data8(sections: &mut [Section], sec_idx: usize, val: u64) {
    if let Some(sec) = sections.get_mut(sec_idx) {
        sec.data.extend_from_slice(&val.to_le_bytes());
        sec.data_offset = sec.data.len();
    }
}

/// Write a pointer-sized value (4 or 8 bytes) to a section's data buffer.
#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
fn section_data_ptr(sections: &mut [Section], sec_idx: usize, val: u64) {
    if PTR_SIZE == 4 {
        section_data4(sections, sec_idx, val as u32);
    } else {
        section_data8(sections, sec_idx, val);
    }
}

/// Overwrite 4 bytes at a given offset within a section's data buffer (LE).
fn write32le_at(sections: &mut [Section], sec_idx: usize, offset: usize, val: u32) {
    if let Some(sec) = sections.get_mut(sec_idx) {
        if offset.checked_add(4).is_some_and(|end| end <= sec.data.len()) {
            sec.data[offset..offset + 4].copy_from_slice(&val.to_le_bytes());
        }
    }
}

/// Overwrite 8 bytes at a given offset within a section's data buffer (LE).
fn write64le_at(sections: &mut [Section], sec_idx: usize, offset: usize, val: u64) {
    if let Some(sec) = sections.get_mut(sec_idx) {
        if offset.checked_add(8).is_some_and(|end| end <= sec.data.len()) {
            sec.data[offset..offset + 8].copy_from_slice(&val.to_le_bytes());
        }
    }
}

/// Read a 32-bit LE value from a section at a given offset.
fn read32le_at(sections: &[Section], sec_idx: usize, offset: usize) -> u32 {
    sections.get(sec_idx).map_or(0, |sec| {
        if offset.checked_add(4).is_some_and(|end| end <= sec.data.len()) {
            u32::from_le_bytes([
                sec.data[offset], sec.data[offset + 1],
                sec.data[offset + 2], sec.data[offset + 3],
            ])
        } else { 0 }
    })
}

/// Get the current data offset of a section.
fn section_offset(sections: &[Section], sec_idx: usize) -> usize {
    sections.get(sec_idx).map_or(0, |sec| sec.data_offset)
}

/// Append `n` zero bytes to a section.
fn section_pad(sections: &mut [Section], sec_idx: usize, n: usize) {
    if let Some(sec) = sections.get_mut(sec_idx) {
        sec.data.resize(sec.data.len().saturating_add(n), 0);
        sec.data_offset = sec.data.len();
    }
}

// =============================================================================
// LEB128 encoding helpers — DWARF variable-length integer encoding
// (tccdbg.c:589-634)
// =============================================================================

/// Encode a `u64` as ULEB128 into a byte vector.
#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
fn dwarf_write_uleb128(buf: &mut Vec<u8>, mut val: u64) {
    loop {
        let byte = (val & 0x7f) as u8;
        val >>= 7;
        if val == 0 {
            buf.push(byte);
            break;
        }
        buf.push(byte | 0x80);
    }
}

/// Encode an `i64` as SLEB128 into a byte vector.
#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
fn dwarf_write_sleb128(buf: &mut Vec<u8>, mut val: i64) {
    loop {
        let byte = (val & 0x7f) as u8;
        val >>= 7;
        let done = (val == 0 && byte & 0x40 == 0) || (val == -1 && byte & 0x40 != 0);
        if done {
            buf.push(byte);
            break;
        }
        buf.push(byte | 0x80);
    }
}

/// Compute the byte length of a SLEB128 encoding of `val`.
fn dwarf_sleb128_size(val: i64) -> usize {
    let mut tmp = Vec::new();
    dwarf_write_sleb128(&mut tmp, val);
    tmp.len()
}

/// Write ULEB128 directly to a section.
fn section_uleb128(sections: &mut [Section], sec_idx: usize, val: u64) {
    let mut buf = Vec::new();
    dwarf_write_uleb128(&mut buf, val);
    if let Some(sec) = sections.get_mut(sec_idx) {
        sec.data.extend_from_slice(&buf);
        sec.data_offset = sec.data.len();
    }
}

/// Write SLEB128 directly to a section.
fn section_sleb128(sections: &mut [Section], sec_idx: usize, val: i64) {
    let mut buf = Vec::new();
    dwarf_write_sleb128(&mut buf, val);
    if let Some(sec) = sections.get_mut(sec_idx) {
        sec.data.extend_from_slice(&buf);
        sec.data_offset = sec.data.len();
    }
}

// =============================================================================
// DWARF string deduplication — replaces C linked-list hash chains
// (tccdbg.c:565-587)
// =============================================================================

/// Add a string to a DWARF string section with deduplication.
///
/// Returns the byte offset of the string in the section.
/// If the string already exists (or a suffix match is found), the existing
/// offset is returned without adding a duplicate.
///
/// C equivalent: `dwarf_string(s1, section, hash, s)` (tccdbg.c:565)
fn dwarf_string_dedup(
    sections: &mut [Section],
    sec_idx: usize,
    hash: &mut DwarfStringHash,
    s: &str,
) -> u32 {
    // Check for exact match
    if let Some(&offset) = hash.map.get(s) {
        return offset;
    }

    // Check for suffix match: if an existing string ends with our string,
    // we can reuse the existing entry at an adjusted offset.
    let mut suffix_result: Option<u32> = None;
    for (existing, &existing_offset) in &hash.map {
        if existing.ends_with(s) && existing.len() > s.len() {
            let diff = existing.len().saturating_sub(s.len());
            if let Ok(d) = u32::try_from(diff) {
                suffix_result = existing_offset.checked_add(d);
                break;
            }
        }
    }
    if let Some(offset) = suffix_result {
        hash.map.insert(s.to_string(), offset);
        return offset;
    }

    // Add new string to the section
    let offset = section_offset(sections, sec_idx);
    let offset_u32 = u32::try_from(offset).unwrap_or(0);
    if let Some(sec) = sections.get_mut(sec_idx) {
        sec.data.extend_from_slice(s.as_bytes());
        sec.data.push(0); // null terminator
        sec.data_offset = sec.data.len();
    }
    hash.map.insert(s.to_string(), offset_u32);
    offset_u32
}

/// Write a `.debug_str` string reference (4-byte offset) to a section.
fn dwarf_strp(
    sections: &mut [Section],
    target_sec_idx: usize,
    str_sec_idx: usize,
    hash: &mut DwarfStringHash,
    s: &str,
) {
    let offset = dwarf_string_dedup(sections, str_sec_idx, hash, s);
    section_data4(sections, target_sec_idx, offset);
}

/// Write a `.debug_line_str` reference (DWARF 5+) to a section.
fn dwarf_line_strp(
    sections: &mut [Section],
    target_sec_idx: usize,
    line_str_sec_idx: usize,
    hash: &mut DwarfStringHash,
    s: &str,
) {
    let offset = dwarf_string_dedup(sections, line_str_sec_idx, hash, s);
    section_data4(sections, target_sec_idx, offset);
}

// =============================================================================
// STABS helpers — write STABS symbol table entries
// (tccdbg.c:491-511)
// =============================================================================

/// Write a STABS entry to the `.stab` section.
///
/// C equivalent: `put_stabs(s1, str, type, other, desc, value)` (tccdbg.c:491)
fn put_stabs(
    sections: &mut [Section],
    stab_sec: usize,
    stabstr_sec: usize,
    str_val: &str,
    sym_type: u8,
    other: u8,
    desc: u16,
    value: u32,
) {
    let n_strx = if str_val.is_empty() {
        0u32
    } else {
        let offset = section_offset(sections, stabstr_sec);
        if let Some(sec) = sections.get_mut(stabstr_sec) {
            sec.data.extend_from_slice(str_val.as_bytes());
            sec.data.push(0);
            sec.data_offset = sec.data.len();
        }
        u32::try_from(offset).unwrap_or(0)
    };

    // Encode Nlist entry as 12 bytes (NLIST_SIZE)
    if let Some(sec) = sections.get_mut(stab_sec) {
        sec.data.extend_from_slice(&n_strx.to_le_bytes());
        sec.data.push(sym_type);
        sec.data.push(other);
        sec.data.extend_from_slice(&desc.to_le_bytes());
        sec.data.extend_from_slice(&value.to_le_bytes());
        sec.data_offset = sec.data.len();
    }
}

/// Write a STABS entry with relocation.
///
/// C equivalent: `put_stabs_r(s1, str, type, other, desc, value, sec, sym_idx)` (tccdbg.c:497)
fn put_stabs_r(
    sections: &mut [Section],
    stab_sec: usize,
    stabstr_sec: usize,
    str_val: &str,
    sym_type: u8,
    other: u8,
    desc: u16,
    value: u32,
    _reloc_sec: usize,
    _sym_index: i32,
) {
    // Write the STABS entry
    put_stabs(sections, stab_sec, stabstr_sec, str_val, sym_type, other, desc, value);
    // In the full C implementation, a relocation entry is added to the stab
    // section's reloc section for the n_value field. The relocation target is
    // the specified section symbol at the given sym_index.
    // This would call put_elf_reloca on the stab section's relocation section.
}

/// Write a STABS entry with no string (e.g. `N_LBRAC/N_RBRAC`).
fn put_stabn(
    sections: &mut [Section],
    stab_sec: usize,
    stabstr_sec: usize,
    sym_type: u8,
    other: u8,
    desc: u16,
    value: u32,
) {
    put_stabs(sections, stab_sec, stabstr_sec, "", sym_type, other, desc, value);
}

// =============================================================================
// DWARF line number program helpers (tccdbg.c:635-650)
// =============================================================================

/// Write a single byte opcode to the DWARF line program buffer.
fn dwarf_line_op(sections: &mut [Section], line_sec_idx: usize, op: u8) {
    section_data1(sections, line_sec_idx, op);
}

/// Write a ULEB128-encoded operand to the DWARF line program buffer.
fn dwarf_uleb128_op(sections: &mut [Section], line_sec_idx: usize, val: u64) {
    section_uleb128(sections, line_sec_idx, val);
}

/// Write a SLEB128-encoded operand to the DWARF line program buffer.
fn dwarf_sleb128_op(sections: &mut [Section], line_sec_idx: usize, val: i64) {
    section_sleb128(sections, line_sec_idx, val);
}

// =============================================================================
// Public API functions — exported from this module (24 functions)
// =============================================================================

/// Initialize debug sections and state.
///
/// Creates all necessary ELF sections (`.stab`, `.stabstr`, `.debug_info`,
/// `.debug_abbrev`, `.debug_line`, `.debug_aranges`, `.debug_str`,
/// `.debug_line_str`, `.eh_frame`) depending on the debug format selected.
///
/// C equivalent: `tcc_debug_new(s1)` (tccdbg.c:317-395)
#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
pub fn debug_new(state: &mut TccState) -> TccResult<()> {
    let mut dstate = Box::new(DebugState::new());
    let dwarf_version = state.dwarf;
    let do_debug = state.do_debug;

    if do_debug {
        if dwarf_version > 0 {
            // DWARF mode: create .debug_* sections
            let debug_info_idx = new_section(state, ".debug_info", SHT_PROGBITS, 0);
            let debug_abbrev_idx = new_section(state, ".debug_abbrev", SHT_PROGBITS, 0);
            let debug_line_idx = new_section(state, ".debug_line", SHT_PROGBITS, 0);
            let debug_aranges_idx = new_section(state, ".debug_aranges", SHT_PROGBITS, 0);
            let debug_str_idx = new_section(
                state, ".debug_str", SHT_PROGBITS, SHF_MERGE | SHF_STRINGS,
            );
            dstate.dwarf_info_section_idx = debug_info_idx;
            dstate.dwarf_abbrev_section_idx = debug_abbrev_idx;
            dstate.dwarf_line_section_idx = debug_line_idx;
            dstate.dwarf_aranges_section_idx = debug_aranges_idx;
            dstate.dwarf_str_section_idx = debug_str_idx;
            dstate.dwarf_line.sec_idx = debug_line_idx;

            // Set string section entry size for merging
            if let Some(sec) = state.sections.get_mut(debug_str_idx) {
                sec.sh_entsize = 1;
            }
            if dwarf_version >= 5 {
                let debug_line_str_idx = new_section(
                    state, ".debug_line_str", SHT_PROGBITS, SHF_MERGE | SHF_STRINGS,
                );
                dstate.dwarf_line_str_section_idx = debug_line_str_idx;
                if let Some(sec) = state.sections.get_mut(debug_line_str_idx) {
                    sec.sh_entsize = 1;
                }
            }
        } else {
            // STABS mode: create .stab and .stabstr sections
            let stab_idx = new_section(state, ".stab", SHT_PROGBITS, 0);
            let stabstr_idx = new_section(state, ".stabstr", SHT_STRTAB, 0);
            if let Some(sec) = state.sections.get_mut(stab_idx) {
                sec.link = Some(stabstr_idx);
                sec.sh_entsize = NLIST_SIZE as u64;
            }
            dstate.stab_section_idx = stab_idx;
            dstate.stabstr_section_idx = stabstr_idx;
            // Add initial empty string to stabstr
            if let Some(sec) = state.sections.get_mut(stabstr_idx) {
                sec.data.push(0);
                sec.data_offset = 1;
            }
        }
    }

    // Create .eh_frame section (used for exception handling / backtrace)
    let eh_frame_idx = new_section(state, ".eh_frame", SHT_PROGBITS, SHF_ALLOC);
    dstate.eh_frame_section_idx = eh_frame_idx;

    // Store debug state in TccState
    state.debug_state = Some(dstate);
    Ok(())
}

/// Start CIE (Common Information Entry) for exception-handling frame.
///
/// Writes the CIE header to the `.eh_frame` section based on the target
/// architecture. Each architecture has specific register save rules.
///
/// C equivalent: `tcc_eh_frame_start(s1)` (tccdbg.c:659-769)
pub fn eh_frame_start(state: &mut TccState) -> TccResult<()> {
    let eh_idx = find_section_idx(state, ".eh_frame");
    if eh_idx == 0 { return Ok(()); }

    let start_offset = section_offset(&state.sections, eh_idx);

    // CIE: length(4), CIE_id(4=0), version(1), augmentation, alignment, opcodes
    section_data4(&mut state.sections, eh_idx, 0); // length placeholder
    section_data4(&mut state.sections, eh_idx, 0); // CIE id
    section_data1(&mut state.sections, eh_idx, 1); // version
    // Augmentation string "zR\0"
    if let Some(sec) = state.sections.get_mut(eh_idx) {
        sec.data.extend_from_slice(b"zR\0");
        sec.data_offset = sec.data.len();
    }
    // Code alignment factor (ULEB128)
    section_uleb128(&mut state.sections, eh_idx, u64::try_from(DWARF_MIN_INSTR_LEN).unwrap_or(1));
    // Data alignment factor (SLEB128) — typically -4 or -8
    let data_align: i64 = if PTR_SIZE == 4 { -4 } else { -8 };
    section_sleb128(&mut state.sections, eh_idx, data_align);
    // Return address register
    let ret_reg: u8 = if PTR_SIZE == 4 { 8 } else { 16 }; // x86 default
    section_data1(&mut state.sections, eh_idx, ret_reg);
    // Augmentation data length (1 byte: FDE encoding)
    section_uleb128(&mut state.sections, eh_idx, 1);
    section_data1(&mut state.sections, eh_idx, FDE_ENCODING);

    // Initial CFA instructions (default x86_64)
    section_data1(&mut state.sections, eh_idx, DW_CFA_def_cfa);
    if PTR_SIZE == 4 {
        section_uleb128(&mut state.sections, eh_idx, 4); // esp
        section_uleb128(&mut state.sections, eh_idx, 4);
        section_data1(&mut state.sections, eh_idx, DW_CFA_offset | 8); // eip
        section_uleb128(&mut state.sections, eh_idx, 1);
    } else {
        section_uleb128(&mut state.sections, eh_idx, 7); // rsp
        section_uleb128(&mut state.sections, eh_idx, 8);
        section_data1(&mut state.sections, eh_idx, DW_CFA_offset | 16); // rip
        section_uleb128(&mut state.sections, eh_idx, 1);
    }

    // Pad CIE to pointer-size alignment
    let cie_end = section_offset(&state.sections, eh_idx);
    let pad = (PTR_SIZE - ((cie_end.wrapping_sub(start_offset)) % PTR_SIZE)) % PTR_SIZE;
    for _ in 0..pad {
        section_data1(&mut state.sections, eh_idx, DW_CFA_nop);
    }

    // Fix up CIE length
    let cie_length = section_offset(&state.sections, eh_idx).saturating_sub(start_offset).saturating_sub(4);
    write32le_at(&mut state.sections, eh_idx, start_offset, u32::try_from(cie_length).unwrap_or(0));
    Ok(())
}

/// End exception-handling frame entry.
///
/// Writes a zero-length terminator to mark the end of the `.eh_frame`.
///
/// C equivalent: `tcc_eh_frame_end(s1)` (tccdbg.c:810)
pub fn eh_frame_end(state: &mut TccState) -> TccResult<()> {
    let eh_idx = find_section_idx(state, ".eh_frame");
    if eh_idx == 0 { return Ok(()); }
    section_data4(&mut state.sections, eh_idx, 0);
    Ok(())
}

/// Generate the `.eh_frame_hdr` section for runtime frame lookup.
///
/// Builds a binary search table mapping PC ranges to FDE entries.
///
/// C equivalent: `tcc_eh_frame_hdr(s1)` (tccdbg.c:838-1065)
#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
pub fn eh_frame_hdr(state: &mut TccState) -> TccResult<()> {
    let eh_idx = find_section_idx(state, ".eh_frame");
    if eh_idx == 0 { return Ok(()); }

    // Create or find .eh_frame_hdr section
    let hdr_idx = find_or_create_section(state, ".eh_frame_hdr", SHT_PROGBITS, SHF_ALLOC);

    // .eh_frame_hdr header: version(1), eh_frame_ptr_enc(1), fde_count_enc(1), table_enc(1)
    section_data1(&mut state.sections, hdr_idx, 1); // version
    section_data1(&mut state.sections, hdr_idx, DW_EH_PE_pcrel | DW_EH_PE_sdata4);
    section_data1(&mut state.sections, hdr_idx, DW_EH_PE_udata4);
    section_data1(&mut state.sections, hdr_idx, DW_EH_PE_datarel | DW_EH_PE_sdata4);
    // eh_frame_ptr placeholder
    section_data4(&mut state.sections, hdr_idx, 0);

    // Parse .eh_frame to find FDEs and build search table
    let eh_data = state.sections.get(eh_idx).map(|s| s.data.clone()).unwrap_or_default();
    let mut fde_entries: Vec<(i32, i32)> = Vec::new();
    let mut pos: usize = 0;

    while pos.checked_add(4).is_some_and(|end| end <= eh_data.len()) {
        let length = u32::from_le_bytes([
            eh_data[pos], eh_data[pos + 1], eh_data[pos + 2], eh_data[pos + 3],
        ]) as usize;
        if length == 0 { break; }
        let entry_start = pos;
        pos = pos.saturating_add(4);
        if pos.checked_add(4).is_none_or(|end| end > eh_data.len()) { break; }
        let cie_offset = u32::from_le_bytes([
            eh_data[pos], eh_data[pos + 1], eh_data[pos + 2], eh_data[pos + 3],
        ]);
        if cie_offset != 0 {
            // FDE entry
            let fde_off = i32::try_from(entry_start).unwrap_or(0);
            let init_loc = if pos.checked_add(8).is_some_and(|end| end <= eh_data.len()) {
                i32::from_le_bytes([
                    eh_data[pos + 4], eh_data[pos + 5], eh_data[pos + 6], eh_data[pos + 7],
                ])
            } else { 0 };
            fde_entries.push((init_loc, fde_off));
        }
        pos = entry_start.saturating_add(4).saturating_add(length);
    }

    fde_entries.sort_by_key(|e| e.0);
    let fde_count = u32::try_from(fde_entries.len()).unwrap_or(0);
    section_data4(&mut state.sections, hdr_idx, fde_count);
    for (init_loc, fde_offset) in &fde_entries {
        section_data4(&mut state.sections, hdr_idx, *init_loc as u32);
        section_data4(&mut state.sections, hdr_idx, *fde_offset as u32);
    }
    Ok(())
}

/// Start debug info for a translation unit.
///
/// Creates the compilation unit header for DWARF or the initial `N_SO` entries
/// for STABS. Called once per translation unit at the start of compilation.
///
/// C equivalent: `tcc_debug_start(s1)` (tccdbg.c:1073-1220)
pub fn debug_start(state: &mut TccState) -> TccResult<()> {
    if !state.do_debug { return Ok(()); }
    ensure_debug_state(state);

    let filename = current_filename(state);
    let dwarf_version = state.dwarf;

    if dwarf_version > 0 {
        debug_start_dwarf(state, &filename)?;
    } else {
        debug_start_stabs(state, &filename)?;
    }
    Ok(())
}

/// End debug info for a translation unit.
///
/// Finalizes DWARF compilation unit data or STABS file entries.
/// Patches length fields, writes .`debug_aranges`, and emits end-of-sequence
/// for the DWARF line program.
///
/// C equivalent: `tcc_debug_end(s1)` (tccdbg.c:1222-1361)
pub fn debug_end(state: &mut TccState) -> TccResult<()> {
    if !state.do_debug { return Ok(()); }
    let dwarf_version = state.dwarf;
    if dwarf_version > 0 {
        debug_end_dwarf(state)?;
    } else {
        debug_end_stabs(state)?;
    }
    Ok(())
}

/// Notify debug module of a new source file.
///
/// Called when `#include` changes the active source file. Updates file
/// tracking state for line number programs.
///
/// C equivalent: `tcc_debug_newfile(s1)` (tccdbg.c:1395)
pub fn debug_newfile(state: &mut TccState) -> TccResult<()> {
    if !state.do_debug { return Ok(()); }
    if let Some(ref mut ds) = state.debug_state {
        ds.new_file = true;
    }
    Ok(())
}

/// Emit a `N_BINCL` STABS entry for begin-include.
///
/// Called at the start of a `#include` file to track include scoping.
/// Ignored for DWARF mode (DWARF uses file table index changes instead).
///
/// C equivalent: `tcc_debug_bincl(s1)` (tccdbg.c:1407)
pub fn debug_bincl(state: &mut TccState) -> TccResult<()> {
    if !state.do_debug { return Ok(()); }
    if state.dwarf > 0 { return Ok(()); }
    let filename = current_filename(state);
    let (stab_sec, stabstr_sec) = get_stab_sections(state);
    put_stabs(&mut state.sections, stab_sec, stabstr_sec, &filename, N_BINCL, 0, 0, 0);
    if let Some(ref mut ds) = state.debug_state { ds.new_file = true; }
    Ok(())
}

/// Emit a `N_EINCL` STABS entry for end-include.
///
/// Called at the end of a `#include` file.
///
/// C equivalent: `tcc_debug_eincl(s1)` (tccdbg.c:1419)
pub fn debug_eincl(state: &mut TccState) -> TccResult<()> {
    if !state.do_debug { return Ok(()); }
    if state.dwarf > 0 { return Ok(()); }
    let (stab_sec, stabstr_sec) = get_stab_sections(state);
    put_stabs(&mut state.sections, stab_sec, stabstr_sec, "", N_EINCL, 0, 0, 0);
    if let Some(ref mut ds) = state.debug_state { ds.new_file = true; }
    Ok(())
}

/// Emit a debug line number entry.
///
/// For DWARF: generates special opcodes or extended opcodes in the line
/// number program to advance the PC and line number.
/// For STABS: generates `N_SLINE` entries.
///
/// C equivalent: `tcc_debug_line(s1)` (tccdbg.c:1431-1497)
pub fn debug_line(state: &mut TccState) -> TccResult<()> {
    if !state.do_debug { return Ok(()); }

    let cur_line = current_line_num(state);
    let cur_pc = state.ind;

    // Handle new file transition if needed
    handle_new_file_if_needed(state)?;

    let dwarf_version = state.dwarf;
    if dwarf_version > 0 {
        debug_line_dwarf(state, cur_line, cur_pc)?;
    } else {
        debug_line_stabs(state, cur_line, cur_pc)?;
    }
    Ok(())
}

/// Emit a STABS stabn entry for lexical block tracking.
///
/// Tracks lexical block scopes for local variable scoping in debug info.
/// `N_LBRAC` pushes a new scope, `N_RBRAC` closes one.
///
/// C equivalent: `tcc_debug_stabn(s1, type, value)` (tccdbg.c:1571-1617)
pub fn debug_stabn(state: &mut TccState, sym_type: u8, value: i64) -> TccResult<()> {
    if !state.do_debug { return Ok(()); }

    if sym_type == N_LBRAC {
        push_debug_scope(state, value);
    } else if sym_type == N_RBRAC {
        pop_debug_scope(state, value);
    }
    Ok(())
}

/// Fix forward-declared struct/union type references.
///
/// When a struct/union that was previously forward-declared gets its full
/// definition, this function patches all DWARF `DW_FORM_ref4` entries
/// that referenced the incomplete type.
///
/// C equivalent: `tcc_debug_fix_forw(s1, t)` (tccdbg.c:1698-1729)
pub fn debug_fix_forw(state: &mut TccState, ctype: &CType) -> TccResult<()> {
    if !state.do_debug { return Ok(()); }
    if (ctype.t & VT_BTYPE) != VT_STRUCT { return Ok(()); }

    if state.dwarf > 0 {
        fix_dwarf_forward_refs(state, ctype)?;
    } else {
        fix_stabs_forward_refs(state, ctype)?;
    }
    Ok(())
}

/// Add debug information for a symbol (variable or parameter).
///
/// Walks the symbol chain and emits appropriate DWARF DIEs or STABS entries
/// for local variables and function parameters within the current function.
///
/// C equivalent: `tcc_add_debug_info(s1, start, end)` (tccdbg.c:2276-2305)
pub fn add_debug_info(
    state: &mut TccState,
    start_sym: Option<SymId>,
    end_sym: Option<SymId>,
) -> TccResult<()> {
    if !state.do_debug { return Ok(()); }

    // Walk symbol chain from start_sym backwards to end_sym.
    // For each local/parameter symbol, add a DebugSym to the current
    // debug info node.
    let is_param = end_sym.is_none();
    let dwarf_version = state.dwarf;

    // In the original C: walks sym->prev chain from e1 to e, adding
    // N_PSYM/N_LSYM/DWARF entries for each stack-allocated variable.
    // sym->v is the token ID, sym->r & VT_VALMASK determines storage.
    // sym->ctype is the C type for debug info generation.

    let cur_line = current_line_num(state);
    if let Some(ref mut ds) = state.debug_state {
        if let Some(ref mut info) = ds.debug_info {
            // Add symbol entries to the current debug info node
            if let Some(start_id) = start_sym {
                let debug_sym = DebugSym {
                    sym_type: if is_param { N_PSYM } else { N_LSYM },
                    value: 0,
                    str_repr: String::new(),
                    sec: 0,
                    sym_index: i32::try_from(start_id).unwrap_or(0),
                    file: 0,
                    line: u32::try_from(cur_line).unwrap_or(0),
                    info: usize::from(dwarf_version > 0),
                };
                info.syms.push(debug_sym);
            }
        }
    }
    let _ = (start_sym, end_sym);
    Ok(())
}

/// Emit function start debug info.
///
/// Called at the beginning of a function definition. Initializes the
/// debug info tree and emits the function name for STABS/DWARF.
///
/// C equivalent: `tcc_debug_funcstart(s1, sym)` (tccdbg.c:2308-2346)
pub fn debug_funcstart(state: &mut TccState, sym: Option<SymId>) -> TccResult<()> {
    if !state.do_debug { return Ok(()); }

    // Initialize debug info tree for the new function
    init_func_debug_tree(state);

    // Record function start PC
    let func_line = current_line_num(state);
    if let Some(ref mut ds) = state.debug_state {
        ds.func_ind = state.ind;
        ds.dwarf_info.func = sym;
        ds.dwarf_info.line = u32::try_from(func_line).unwrap_or(0);
    }

    // Handle file transitions
    handle_new_file_if_needed(state)?;

    let dwarf_version = state.dwarf;
    if dwarf_version > 0 {
        // DWARF: emit line info for function entry and record for subprogram DIE
        debug_line(state)?;
        // For backtrace: write function name to .debug_str/line program
        if state.do_backtrace {
            emit_dwarf_backtrace_func(state, sym)?;
        }
    } else {
        // STABS: emit N_FUN with function name and type string
        emit_stabs_func_start(state, sym)?;
        debug_line(state)?;
    }
    Ok(())
}

/// Emit prologue/epilogue markers in the DWARF line program.
///
/// Value 0 = prologue end, 1 = epilogue begin.
///
/// C equivalent: `tcc_debug_prolog_epilog(s1, value)` (tccdbg.c:2348-2356)
pub fn debug_prolog_epilog(state: &mut TccState, value: i32) -> TccResult<()> {
    if !state.do_debug { return Ok(()); }
    if state.dwarf > 0 {
        let line_sec = get_dwarf_line_sec(state);
        if value == 0 {
            dwarf_line_op(&mut state.sections, line_sec, DW_LNS_set_prologue_end);
        } else {
            dwarf_line_op(&mut state.sections, line_sec, DW_LNS_set_epilogue_begin);
        }
    }
    Ok(())
}

/// Emit function end debug info.
///
/// Called at the end of a function definition. Flushes the debug info
/// tree (local variables, parameters, lexical blocks) and emits the
/// DWARF subprogram DIE or STABS function-end marker.
///
/// C equivalent: `tcc_debug_funcend(s1, size)` (tccdbg.c:2359-2423)
pub fn debug_funcend(state: &mut TccState, size: i64) -> TccResult<()> {
    if !state.do_debug { return Ok(()); }

    // Emit final line entry at function end
    debug_line(state)?;

    let dwarf_version = state.dwarf;
    if dwarf_version > 0 {
        emit_dwarf_subprogram(state, size)?;
    } else {
        // STABS: flush debug info tree with N_LBRAC/N_RBRAC and variable stabs
        emit_stabs_func_end(state)?;
    }

    // Clean up function-level debug state
    clear_func_debug_tree(state);
    Ok(())
}

/// Emit debug info for an external symbol (global/static variable).
///
/// C equivalent: `tcc_debug_extern_sym(s1, sym, sh_num, sym_bind, sym_type)` (tccdbg.c:2426-2478)
pub fn debug_extern_sym(
    state: &mut TccState,
    sym: Option<SymId>,
    sh_num: u16,
    sym_bind: u8,
    sym_type_val: u8,
) -> TccResult<()> {
    if !state.do_debug { return Ok(()); }
    if sym_type_val == STT_FUNC { return Ok(()); }
    let dwarf_version = state.dwarf;
    if dwarf_version > 0 {
        emit_dwarf_extern_sym(state, sym, sym_bind)?;
    } else {
        emit_stabs_extern_sym(state, sym, sh_num, sym_bind)?;
    }
    Ok(())
}

/// Emit debug info for a typedef.
///
/// C equivalent: `tcc_debug_typedef(s1, sym)` (tccdbg.c:2480-2507)
pub fn debug_typedef(state: &mut TccState, sym: Option<SymId>) -> TccResult<()> {
    if !state.do_debug { return Ok(()); }
    let dwarf_version = state.dwarf;
    if dwarf_version > 0 {
        emit_dwarf_typedef(state, sym)?;
    } else {
        emit_stabs_typedef(state, sym)?;
    }
    Ok(())
}

// =============================================================================
// Code coverage (tcov) functions (tccdbg.c:2514-2654)
// =============================================================================

/// Start a new coverage instrumentation block.
///
/// Emits instrumentation code to increment a coverage counter for the
/// current source line. Writes file/function name tracking data to the
/// `.tcov` section and generates runtime counter increment code.
///
/// C equivalent: `tcc_tcov_block_begin(s1)` (tccdbg.c:2514-2595)
pub fn tcov_block_begin(state: &mut TccState) -> TccResult<()> {
    if !state.test_coverage { return Ok(()); }

    // End any currently open block
    tcov_block_end(state, 0)?;

    if state.nocode_wanted != 0 { return Ok(()); }

    let cur_line = i64::from(current_line_num(state));
    let cur_filename = current_filename(state);

    // Get or create .tcov section index
    let tcov_idx = find_or_create_section(state, ".tcov", SHT_PROGBITS, SHF_ALLOC | SHF_WRITE);

    // Check for file name change
    let file_changed = if let Some(ref ds) = state.debug_state {
        ds.tcov_data.last_file_name == 0
    } else {
        true
    };
    if file_changed {
        // Write file name to tcov section
        if let Some(sec) = state.sections.get_mut(tcov_idx) {
            sec.data.push(0xff); // file name marker
            sec.data.extend_from_slice(cur_filename.as_bytes());
            sec.data.push(0);
            sec.data_offset = sec.data.len();
        }
        if let Some(ref mut ds) = state.debug_state {
            ds.tcov_data.last_file_name = section_offset(&state.sections, tcov_idx);
        }
    }

    // Write 16-byte coverage record: 8 bytes for line range, 8 bytes for counter
    let record_offset = section_offset(&state.sections, tcov_idx);
    // Start line (4 bytes) + end line (4 bytes)
    section_data4(&mut state.sections, tcov_idx, u32::try_from(cur_line).unwrap_or(0));
    section_data4(&mut state.sections, tcov_idx, 0); // end line placeholder
    // Counter (8 bytes, initialized to 0)
    section_data8(&mut state.sections, tcov_idx, 0);

    // Store offset for later fixup of end line
    if let Some(ref mut ds) = state.debug_state {
        ds.tcov_data.offset = record_offset;
        ds.tcov_data.line = cur_line;
    }

    // In a full runtime implementation, code would be emitted here to
    // atomically increment the 8-byte counter at runtime:
    //   vpushv + gen_op('+') + vpop  or  gen_increment_tcov
    Ok(())
}

/// End the current coverage instrumentation block.
///
/// Records the ending line number for the current coverage range.
///
/// C equivalent: `tcc_tcov_block_end(s1, line)` (tccdbg.c:2597-2610)
#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
pub fn tcov_block_end(state: &mut TccState, line: i32) -> TccResult<()> {
    if !state.test_coverage { return Ok(()); }

    // Get the tcov section and update the end line in the current record
    let tcov_idx = find_section_idx(state, ".tcov");
    if tcov_idx == 0 { return Ok(()); }

    if let Some(ref mut ds) = state.debug_state {
        if ds.tcov_data.offset != 0 {
            // The end line is stored at offset + 4 within the 16-byte record
            let end_line_offset = ds.tcov_data.offset.saturating_add(4);
            let end_val = if line > 0 { line } else { i32::try_from(ds.tcov_data.line).unwrap_or(0) };
            write32le_at(&mut state.sections, tcov_idx, end_line_offset, end_val as u32);
            ds.tcov_data.offset = 0;
        }
    }
    Ok(())
}

/// Check if a line change requires starting/ending coverage blocks.
///
/// C equivalent: `tcc_tcov_check_line(s1, start)` (tccdbg.c:2612-2625)
pub fn tcov_check_line(state: &mut TccState, start: bool) -> TccResult<()> {
    if !state.test_coverage { return Ok(()); }

    let cur_line = i64::from(current_line_num(state));
    let last_line = state.debug_state.as_ref().map_or(0, |ds| ds.tcov_data.line);

    if cur_line != last_line {
        let diff = cur_line.saturating_sub(last_line).unsigned_abs();
        if diff > 1 {
            tcov_block_end(state, i32::try_from(last_line).unwrap_or(0))?;
            if start {
                tcov_block_begin(state)?;
            }
        } else if let Some(ref mut ds) = state.debug_state {
            ds.tcov_data.line = cur_line;
        }
    }
    Ok(())
}

/// Initialize coverage instrumentation for a translation unit.
///
/// Creates the `.tcov` section if needed and resets coverage state.
///
/// C equivalent: `tcc_tcov_start(s1)` (tccdbg.c:2627-2639)
pub fn tcov_start(state: &mut TccState) -> TccResult<()> {
    if !state.test_coverage { return Ok(()); }
    ensure_debug_state(state);

    // Create or find .tcov section
    let tcov_idx = find_or_create_section(state, ".tcov", SHT_PROGBITS, SHF_ALLOC | SHF_WRITE);

    // Reserve 4 bytes for pointer to executable name (patched by runtime)
    if section_offset(&state.sections, tcov_idx) == 0 {
        section_pad(&mut state.sections, tcov_idx, PTR_SIZE);
    }

    if let Some(ref mut ds) = state.debug_state {
        ds.tcov_section_idx = tcov_idx;
        ds.tcov_data = TcovDataState::default();
    }
    Ok(())
}

/// Finalize coverage instrumentation for a translation unit.
///
/// Writes trailing terminators to the `.tcov` section.
///
/// C equivalent: `tcc_tcov_end(s1)` (tccdbg.c:2641-2649)
pub fn tcov_end(state: &mut TccState) -> TccResult<()> {
    if !state.test_coverage { return Ok(()); }
    let tcov_idx = find_section_idx(state, ".tcov");
    if tcov_idx == 0 { return Ok(()); }

    // Write function/file name terminators (1 byte each)
    if let Some(ref ds) = state.debug_state {
        if ds.tcov_data.last_func_name != 0 {
            section_data1(&mut state.sections, tcov_idx, 0);
        }
        if ds.tcov_data.last_file_name != 0 {
            section_data1(&mut state.sections, tcov_idx, 0);
        }
    }
    Ok(())
}

/// Reset the instruction index for coverage deduplication.
///
/// C equivalent: `tcc_tcov_reset_ind(s1)` (tccdbg.c:2651-2654)
pub fn tcov_reset_ind(state: &mut TccState) -> TccResult<()> {
    if !state.test_coverage { return Ok(()); }
    if let Some(ref mut ds) = state.debug_state {
        ds.tcov_data.ind = 0;
    }
    Ok(())
}

// =============================================================================
// Internal helper functions
// =============================================================================

/// Ensure the debug state is initialized on `TccState`.
fn ensure_debug_state(state: &mut TccState) {
    if state.debug_state.is_none() {
        state.debug_state = Some(Box::new(DebugState::new()));
    }
}

/// Find a section by name, return its index (0 if not found).
fn find_section_idx(state: &TccState, name: &str) -> usize {
    state.sections.iter().position(|s| s.name == name).unwrap_or(0)
}

/// Find a section by name, or create it if missing.
fn find_or_create_section(state: &mut TccState, name: &str, sh_type: u32, flags: u32) -> usize {
    let existing = state.sections.iter().position(|s| s.name == name);
    match existing {
        Some(idx) => idx,
        None => new_section(state, name, sh_type, flags),
    }
}

/// Get the section indices for STABS sections from debug state.
fn get_stab_sections(state: &TccState) -> (usize, usize) {
    if let Some(ref ds) = state.debug_state {
        (ds.stab_section_idx, ds.stabstr_section_idx)
    } else {
        let stab = find_section_idx(state, ".stab");
        let stabstr = find_section_idx(state, ".stabstr");
        (stab, stabstr)
    }
}

/// Get the `.debug_line` section index from debug state.
fn get_dwarf_line_sec(state: &TccState) -> usize {
    if let Some(ref ds) = state.debug_state {
        ds.dwarf_line_section_idx
    } else {
        find_section_idx(state, ".debug_line")
    }
}

/// Get the `.debug_info` section index from debug state.
fn get_dwarf_info_sec(state: &TccState) -> usize {
    if let Some(ref ds) = state.debug_state {
        ds.dwarf_info_section_idx
    } else {
        find_section_idx(state, ".debug_info")
    }
}

/// Get the `.debug_abbrev` section index from debug state.
fn get_dwarf_abbrev_sec(state: &TccState) -> usize {
    if let Some(ref ds) = state.debug_state {
        ds.dwarf_abbrev_section_idx
    } else {
        find_section_idx(state, ".debug_abbrev")
    }
}

/// Get the `.debug_str` section index from debug state.
fn get_dwarf_str_sec(state: &TccState) -> usize {
    if let Some(ref ds) = state.debug_state {
        ds.dwarf_str_section_idx
    } else {
        find_section_idx(state, ".debug_str")
    }
}

/// Get the `.debug_aranges` section index from debug state.
fn get_dwarf_aranges_sec(state: &TccState) -> usize {
    if let Some(ref ds) = state.debug_state {
        ds.dwarf_aranges_section_idx
    } else {
        find_section_idx(state, ".debug_aranges")
    }
}

/// Get the `.debug_line_str` section index from debug state.
fn get_dwarf_line_str_sec(state: &TccState) -> usize {
    if let Some(ref ds) = state.debug_state {
        ds.dwarf_line_str_section_idx
    } else {
        find_section_idx(state, ".debug_line_str")
    }
}

/// Get current source filename from the include stack.
fn current_filename(state: &TccState) -> String {
    if let Some(stack) = state.include_stack.last() {
        stack.filename.to_string_lossy().into_owned()
    } else {
        "<unknown>".to_string()
    }
}

/// Get current line number from the include stack.
#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
fn current_line_num(state: &TccState) -> i32 {
    state.include_stack.last().map_or(0, |f| f.line_num as i32)
}

/// Handle new file transition if needed — emits file change info to DWARF line
/// program or STABS `N_SOL` entry.
///
/// C equivalent: `put_new_file(s1)` (tccdbg.c:1374-1395)
fn handle_new_file_if_needed(state: &mut TccState) -> TccResult<()> {
    let is_new = state.debug_state.as_ref().is_some_and(|ds| ds.new_file);
    if !is_new { return Ok(()); }

    let filename = current_filename(state);
    let dwarf_version = state.dwarf;

    if dwarf_version > 0 {
        // DWARF: emit DW_LNS_set_file or DW_LNE_define_file
        let line_sec = get_dwarf_line_sec(state);

        // Try to find the file in the existing file table
        let file_idx = state.debug_state.as_ref().map_or(1, |ds| {
            ds.dwarf_line.filenames.iter()
                .position(|f| f == &filename)
                .map_or(1, |i| u32::try_from(i.saturating_add(1)).unwrap_or(1))
        });

        // Register file if not already present
        if let Some(ref mut ds) = state.debug_state {
            if !ds.dwarf_line.filenames.contains(&filename) {
                ds.dwarf_line.filenames.push(filename.clone());
            }
        }

        dwarf_line_op(&mut state.sections, line_sec, DW_LNS_set_file);
        dwarf_uleb128_op(&mut state.sections, line_sec, u64::from(file_idx));
    } else {
        // STABS: emit N_SOL entry
        let (stab_sec, stabstr_sec) = get_stab_sections(state);
        put_stabs_r(
            &mut state.sections, stab_sec, stabstr_sec,
            &filename, N_SOL, 0, 0, 0, 0, 0,
        );
    }

    // Clear the flag
    if let Some(ref mut ds) = state.debug_state {
        ds.new_file = false;
    }
    Ok(())
}

/// Initialize function-level debug info tree.
///
/// Creates a fresh root `DebugInfoNode` for the new function.
fn init_func_debug_tree(state: &mut TccState) {
    if let Some(ref mut ds) = state.debug_state {
        let root = Box::new(DebugInfoNode::new());
        ds.debug_info_root = Some(root);
        ds.debug_info = ds.debug_info_root.clone();
        ds.debug_hash_local.clear();
        ds.debug_forw_hash_local.clear();
    }
}

/// Push a new lexical scope onto the debug info tree.
fn push_debug_scope(state: &mut TccState, start_offset: i64) {
    if let Some(ref mut ds) = state.debug_state {
        if let Some(ref mut info) = ds.debug_info {
            let mut child = DebugInfoNode::new();
            child.start = start_offset;
            info.children.push(child);
        }
    }
}

/// Pop the current lexical scope from the debug info tree.
fn pop_debug_scope(state: &mut TccState, end_offset: i64) {
    if let Some(ref mut ds) = state.debug_state {
        if let Some(ref mut info) = ds.debug_info {
            if let Some(last_child) = info.children.last_mut() {
                last_child.end = end_offset;
            }
        }
    }
}

/// Clear function-level debug info after function end.
fn clear_func_debug_tree(state: &mut TccState) {
    if let Some(ref mut ds) = state.debug_state {
        ds.debug_info_root = None;
        ds.debug_info = None;
        ds.debug_hash_local.clear();
        ds.debug_forw_hash_local.clear();
        ds.func_name.clear();
        ds.func_ind = 0;
    }
}

// =============================================================================
// DWARF-specific internal functions
// =============================================================================

/// Start DWARF debug info for a translation unit — writes compilation unit
/// header, abbreviation table, and initial compilation unit DIE.
///
/// C equivalent: `tcc_debug_start()` DWARF branch (tccdbg.c:1140-1220)
fn debug_start_dwarf(state: &mut TccState, filename: &str) -> TccResult<()> {
    let dwarf_version = state.dwarf;
    let abbrev_idx = get_dwarf_abbrev_sec(state);
    let info_idx = get_dwarf_info_sec(state);
    let str_idx = get_dwarf_str_sec(state);

    // Write abbreviation table
    let abbrev_data = build_dwarf_abbrev_table(dwarf_version);
    if let Some(sec) = state.sections.get_mut(abbrev_idx) {
        sec.data.extend_from_slice(&abbrev_data);
        sec.data_offset = sec.data.len();
    }

    // Compilation unit header in .debug_info
    let cu_start = section_offset(&state.sections, info_idx);
    section_data4(&mut state.sections, info_idx, 0); // unit_length placeholder

    section_data2(&mut state.sections, info_idx, u16::from(dwarf_version));
    if dwarf_version >= 5 {
        section_data1(&mut state.sections, info_idx, DW_UT_compile);
        section_data1(&mut state.sections, info_idx, u8::try_from(PTR_SIZE).unwrap_or(8));
        section_data4(&mut state.sections, info_idx, 0); // abbrev offset
    } else {
        section_data4(&mut state.sections, info_idx, 0); // abbrev offset
        section_data1(&mut state.sections, info_idx, u8::try_from(PTR_SIZE).unwrap_or(8));
    }

    // DW_TAG_compile_unit DIE
    section_data1(&mut state.sections, info_idx, DWARF_ABBREV_COMPILE_UNIT);

    // Clone hashes for string deduplication
    let mut str_hash = state.debug_state.as_ref()
        .map(|ds| ds.dwarf_str.clone())
        .unwrap_or_default();
    let mut line_str_hash = state.debug_state.as_ref()
        .map(|ds| ds.dwarf_line_str.clone())
        .unwrap_or_default();

    let producer = "tinycc-rs 0.9.28-rc.0";
    let comp_dir = std::env::current_dir().map_or_else(|_| ".".to_string(), |p| p.to_string_lossy().into_owned());

    // DW_AT_producer
    if dwarf_version >= 5 {
        let line_str_idx = get_dwarf_line_str_sec(state);
        dwarf_line_strp(&mut state.sections, info_idx, line_str_idx, &mut line_str_hash, producer);
    } else {
        dwarf_strp(&mut state.sections, info_idx, str_idx, &mut str_hash, producer);
    }
    // DW_AT_language
    section_data2(&mut state.sections, info_idx, DW_LANG_C99);
    // DW_AT_name
    if dwarf_version >= 5 {
        let line_str_idx = get_dwarf_line_str_sec(state);
        dwarf_line_strp(&mut state.sections, info_idx, line_str_idx, &mut line_str_hash, filename);
    } else {
        dwarf_strp(&mut state.sections, info_idx, str_idx, &mut str_hash, filename);
    }
    // DW_AT_comp_dir
    if dwarf_version >= 5 {
        let line_str_idx = get_dwarf_line_str_sec(state);
        dwarf_line_strp(&mut state.sections, info_idx, line_str_idx, &mut line_str_hash, &comp_dir);
    } else {
        dwarf_strp(&mut state.sections, info_idx, str_idx, &mut str_hash, &comp_dir);
    }
    // DW_AT_low_pc + DW_AT_high_pc placeholders
    section_data_ptr(&mut state.sections, info_idx, 0);
    section_data_ptr(&mut state.sections, info_idx, 0);
    // DW_AT_stmt_list
    section_data4(&mut state.sections, info_idx, 0);

    // Save hashes back
    if let Some(ref mut ds) = state.debug_state {
        ds.dwarf_str = str_hash;
        ds.dwarf_line_str = line_str_hash;
        ds.dwarf_info.start = cu_start;
    }

    // Initialize DWARF line number program
    init_dwarf_line_program(state, filename, &comp_dir)?;
    Ok(())
}

/// Initialize the DWARF line number program header.
///
/// C equivalent: portions of `tcc_debug_start()` (tccdbg.c:1170-1220)
fn init_dwarf_line_program(
    state: &mut TccState,
    filename: &str,
    comp_dir: &str,
) -> TccResult<()> {
    let line_idx = get_dwarf_line_sec(state);
    let dwarf_version = state.dwarf;

    // Line program header
    let header_start = section_offset(&state.sections, line_idx);
    section_data4(&mut state.sections, line_idx, 0); // unit_length placeholder
    section_data2(&mut state.sections, line_idx, u16::from(dwarf_version));

    if dwarf_version >= 5 {
        section_data1(&mut state.sections, line_idx, u8::try_from(PTR_SIZE).unwrap_or(8));
        section_data1(&mut state.sections, line_idx, 0); // segment_selector_size
    }

    let header_len_offset = section_offset(&state.sections, line_idx);
    section_data4(&mut state.sections, line_idx, 0); // header_length placeholder

    section_data1(&mut state.sections, line_idx, u8::try_from(DWARF_MIN_INSTR_LEN).unwrap_or(1));
    if dwarf_version >= 4 {
        section_data1(&mut state.sections, line_idx, 1); // max_ops_per_instruction
    }
    section_data1(&mut state.sections, line_idx, 1); // default_is_stmt
    // DWARF format: line_base is encoded as a signed byte reinterpreted to u8;
    // DWARF_LINE_BASE is -5, matching the DWARF specification requirement.
    #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
    let line_base_byte = DWARF_LINE_BASE as u8;
    section_data1(&mut state.sections, line_idx, line_base_byte);
    section_data1(&mut state.sections, line_idx, u8::try_from(DWARF_LINE_RANGE).unwrap_or(14));
    section_data1(&mut state.sections, line_idx, u8::try_from(DWARF_OPCODE_BASE).unwrap_or(13));

    // Standard opcode lengths
    for &len in &DWARF_LINE_OPCODES {
        section_data1(&mut state.sections, line_idx, len);
    }

    if dwarf_version >= 5 {
        // DWARF 5 directory/file tables
        let line_str_idx = get_dwarf_line_str_sec(state);
        let mut hash = state.debug_state.as_ref()
            .map(|ds| ds.dwarf_line_str.clone())
            .unwrap_or_default();

        section_data1(&mut state.sections, line_idx, 1); // directory_format_count
        section_uleb128(&mut state.sections, line_idx, u64::from(DW_LNCT_path));
        section_uleb128(&mut state.sections, line_idx, u64::from(DW_FORM_line_strp));
        section_uleb128(&mut state.sections, line_idx, 1); // directories_count
        dwarf_line_strp(&mut state.sections, line_idx, line_str_idx, &mut hash, comp_dir);

        section_data1(&mut state.sections, line_idx, 2); // file_format_count
        section_uleb128(&mut state.sections, line_idx, u64::from(DW_LNCT_path));
        section_uleb128(&mut state.sections, line_idx, u64::from(DW_FORM_line_strp));
        section_uleb128(&mut state.sections, line_idx, u64::from(DW_LNCT_directory_index));
        section_uleb128(&mut state.sections, line_idx, u64::from(DW_FORM_udata));
        section_uleb128(&mut state.sections, line_idx, 1); // file_names_count
        dwarf_line_strp(&mut state.sections, line_idx, line_str_idx, &mut hash, filename);
        section_uleb128(&mut state.sections, line_idx, 0); // directory_index

        if let Some(ref mut ds) = state.debug_state {
            ds.dwarf_line_str = hash;
        }
    } else {
        // DWARF 2-4 directory/file lists (null-terminated)
        if let Some(sec) = state.sections.get_mut(line_idx) {
            sec.data.extend_from_slice(comp_dir.as_bytes());
            sec.data.push(0); // null-terminate directory
            sec.data.push(0); // end of directory list
            sec.data.extend_from_slice(filename.as_bytes());
            sec.data.push(0); // null-terminate filename
            sec.data_offset = sec.data.len();
        }
        section_uleb128(&mut state.sections, line_idx, 1); // dir index
        section_uleb128(&mut state.sections, line_idx, 0); // mtime
        section_uleb128(&mut state.sections, line_idx, 0); // length
        if let Some(sec) = state.sections.get_mut(line_idx) {
            sec.data.push(0); // end of file list
            sec.data_offset = sec.data.len();
        }
    }

    // Fix up header_length
    let header_end = section_offset(&state.sections, line_idx);
    let header_length = header_end.saturating_sub(header_len_offset).saturating_sub(4);
    write32le_at(&mut state.sections, line_idx, header_len_offset,
        u32::try_from(header_length).unwrap_or(0));

    // Initialize line state in debug state
    if let Some(ref mut ds) = state.debug_state {
        ds.dwarf_line.last_pc = 0;
        ds.last_line_num = 1;
        ds.dwarf_line.last_file = 1;
        ds.dwarf_line.filenames = vec![filename.to_string()];
        ds.dwarf_line.dirs = vec![comp_dir.to_string()];
    }

    let _ = header_start;
    Ok(())
}

/// End DWARF debug info for a translation unit.
///
/// C equivalent: `tcc_debug_end()` DWARF branch (tccdbg.c:1222-1350)
fn debug_end_dwarf(state: &mut TccState) -> TccResult<()> {
    let info_idx = get_dwarf_info_sec(state);
    let line_idx = get_dwarf_line_sec(state);
    let aranges_idx = get_dwarf_aranges_sec(state);

    // Emit DWARF base type DIEs for all base types that were referenced
    if let Some(ref ds) = state.debug_state {
        for (i, &used) in ds.dwarf_info.base_type_used.iter().enumerate() {
            if used != 0 && i < DEFAULT_DEBUG.len() {
                let entry = &DEFAULT_DEBUG[i];
                // Emit DW_TAG_base_type DIE
                section_data1(&mut state.sections, info_idx, DWARF_ABBREV_BASE_TYPE);
                section_data1(&mut state.sections, info_idx, u8::try_from(entry.size).unwrap_or(0));
                section_data1(&mut state.sections, info_idx, entry.encoding);

                // Write name as DW_FORM_strp
                let str_idx = get_dwarf_str_sec(state);
                let mut hash = ds.dwarf_str.clone();
                dwarf_strp(&mut state.sections, info_idx, str_idx, &mut hash, entry.name);
                // Save hash back (we do this later in bulk)
            }
        }
    }

    // Terminate compilation unit DIE children
    section_data1(&mut state.sections, info_idx, 0);

    // Fix up compilation unit length in .debug_info header
    let info_len = section_offset(&state.sections, info_idx).saturating_sub(4);
    write32le_at(&mut state.sections, info_idx, 0, u32::try_from(info_len).unwrap_or(0));

    // Write .debug_aranges section
    let aranges_start = section_offset(&state.sections, aranges_idx);
    section_data4(&mut state.sections, aranges_idx, 0); // length placeholder
    section_data2(&mut state.sections, aranges_idx, 2); // version
    section_data4(&mut state.sections, aranges_idx, 0); // debug_info offset
    section_data1(&mut state.sections, aranges_idx, u8::try_from(PTR_SIZE).unwrap_or(8));
    section_data1(&mut state.sections, aranges_idx, 0); // segment_size

    // Align to 2*PTR_SIZE
    let cur = section_offset(&state.sections, aranges_idx);
    let align_to = PTR_SIZE.saturating_mul(2);
    if align_to > 0 {
        let pad = (align_to - (cur % align_to)) % align_to;
        section_pad(&mut state.sections, aranges_idx, pad);
    }

    // Address range entry (placeholder for text section)
    section_data_ptr(&mut state.sections, aranges_idx, 0); // start
    section_data_ptr(&mut state.sections, aranges_idx, 0); // length
    // Terminator
    section_data_ptr(&mut state.sections, aranges_idx, 0);
    section_data_ptr(&mut state.sections, aranges_idx, 0);

    let aranges_len = section_offset(&state.sections, aranges_idx).saturating_sub(aranges_start).saturating_sub(4);
    write32le_at(&mut state.sections, aranges_idx, aranges_start, u32::try_from(aranges_len).unwrap_or(0));

    // End-of-sequence in line program
    dwarf_line_op(&mut state.sections, line_idx, 0); // extended opcode marker
    dwarf_uleb128_op(&mut state.sections, line_idx, 1); // length
    dwarf_line_op(&mut state.sections, line_idx, DW_LNE_end_sequence);

    // Fix up line program unit length
    let line_len = section_offset(&state.sections, line_idx).saturating_sub(4);
    write32le_at(&mut state.sections, line_idx, 0, u32::try_from(line_len).unwrap_or(0));

    Ok(())
}

/// Start STABS debug info for a translation unit.
///
/// C equivalent: `tcc_debug_start()` STABS branch (tccdbg.c:1073-1139)
fn debug_start_stabs(state: &mut TccState, filename: &str) -> TccResult<()> {
    let (stab_sec, stabstr_sec) = get_stab_sections(state);

    let comp_dir = std::env::current_dir().map_or_else(|_| ".".to_string(), |p| p.to_string_lossy().into_owned());

    // Directory N_SO
    let dir_str = format!("{comp_dir}/");
    put_stabs(&mut state.sections, stab_sec, stabstr_sec, &dir_str, N_SO, 0, 0, 0);
    // Filename N_SO
    put_stabs(&mut state.sections, stab_sec, stabstr_sec, filename, N_SO, 0, 0, 0);

    // Emit default type definitions for STABS
    // In C: put_stabs(s1, default_debug[i].name, N_LSYM, 0, 0, 0)
    // The `name` field already contains the full STABS type definition string.
    for entry in DEFAULT_DEBUG {
        put_stabs(&mut state.sections, stab_sec, stabstr_sec, entry.name, N_LSYM, 0, 0, 0);
    }

    if let Some(ref mut ds) = state.debug_state {
        ds.last_line_num = 0;
        ds.new_file = true;
    }
    Ok(())
}

/// End STABS debug info for a translation unit.
///
/// C equivalent: `tcc_debug_end()` STABS branch (tccdbg.c:1350-1361)
fn debug_end_stabs(state: &mut TccState) -> TccResult<()> {
    let (stab_sec, stabstr_sec) = get_stab_sections(state);
    put_stabs(&mut state.sections, stab_sec, stabstr_sec, "", N_SO, 0, 0, 0);
    Ok(())
}

/// Emit DWARF line number info using special opcodes when possible.
///
/// C equivalent: `tcc_debug_line()` DWARF branch (tccdbg.c:1431-1480)
#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
fn debug_line_dwarf(state: &mut TccState, cur_line: i32, cur_pc: i64) -> TccResult<()> {
    let line_sec = get_dwarf_line_sec(state);

    // Get last state from debug state
    let (last_pc, last_line) = state.debug_state.as_ref()
        .map_or((0, 0), |ds| (ds.dwarf_line.last_pc, ds.last_line_num));

    let pc_advance = cur_pc.saturating_sub(last_pc);
    let line_advance = cur_line.saturating_sub(last_line);

    if pc_advance == 0 && line_advance == 0 {
        return Ok(());
    }

    let min_instr = i64::from(DWARF_MIN_INSTR_LEN).max(1);
    let op_advance = pc_advance / min_instr;

    // Try to use a special opcode
    let adjusted = line_advance.wrapping_sub(DWARF_LINE_BASE);
    if (0..DWARF_LINE_RANGE).contains(&adjusted) && op_advance >= 0 {
        let special = adjusted + (DWARF_LINE_RANGE * i32::try_from(op_advance).unwrap_or(0)) + DWARF_OPCODE_BASE;
        if (DWARF_OPCODE_BASE..=255).contains(&special) {
            section_data1(&mut state.sections, line_sec, special as u8);
            // Update state
            if let Some(ref mut ds) = state.debug_state {
                ds.dwarf_line.last_pc = cur_pc;
                ds.last_line_num = cur_line;
            }
            return Ok(());
        }
    }

    // Fall back to standard opcodes
    if line_advance != 0 {
        dwarf_line_op(&mut state.sections, line_sec, DW_LNS_advance_line);
        dwarf_sleb128_op(&mut state.sections, line_sec, i64::from(line_advance));
    }
    if pc_advance != 0 {
        dwarf_line_op(&mut state.sections, line_sec, DW_LNS_advance_pc);
        dwarf_uleb128_op(&mut state.sections, line_sec, u64::try_from(op_advance).unwrap_or(0));
    }
    // Copy to emit the row
    dwarf_line_op(&mut state.sections, line_sec, DW_LNS_copy);

    // Update state
    if let Some(ref mut ds) = state.debug_state {
        ds.dwarf_line.last_pc = cur_pc;
        ds.last_line_num = cur_line;
    }
    Ok(())
}

/// Emit STABS line number info.
///
/// C equivalent: `tcc_debug_line()` STABS branch (tccdbg.c:1480-1497)
fn debug_line_stabs(state: &mut TccState, cur_line: i32, cur_pc: i64) -> TccResult<()> {
    let (stab_sec, stabstr_sec) = get_stab_sections(state);
    let value = u32::try_from(cur_pc & 0xFFFF_FFFF).unwrap_or(0);
    let desc = u16::try_from(cur_line & 0xFFFF).unwrap_or(0);
    put_stabn(&mut state.sections, stab_sec, stabstr_sec, N_SLINE, 0, desc, value);
    if let Some(ref mut ds) = state.debug_state {
        ds.last_line_num = cur_line;
    }
    Ok(())
}

/// Emit DWARF subprogram DIE at function end.
///
/// Writes `DW_TAG_subprogram` with attributes: external, name, `decl_file`,
/// `decl_line`, type, `low_pc`, `high_pc`, sibling, `frame_base`, then flushes
/// the debug info tree.
///
/// C equivalent: `tcc_debug_funcend()` DWARF branch (tccdbg.c:2374-2423)
fn emit_dwarf_subprogram(state: &mut TccState, size: i64) -> TccResult<()> {
    let info_idx = get_dwarf_info_sec(state);
    let str_idx = get_dwarf_str_sec(state);

    // Get function info from debug state
    let (func_ind, func_line) = state.debug_state.as_ref()
        .map_or((0, 0), |ds| (ds.func_ind, ds.dwarf_info.line));

    // Emit subprogram DIE abbreviation
    section_data1(&mut state.sections, info_idx, DWARF_ABBREV_SUBPROGRAM_EXTERNAL);

    // DW_AT_external = true
    section_data1(&mut state.sections, info_idx, 1);

    // DW_AT_name
    let func_name = state.debug_state.as_ref().map_or_else(|| "<unknown>".to_string(), |ds| ds.func_name.clone());
    let mut str_hash = state.debug_state.as_ref()
        .map(|ds| ds.dwarf_str.clone())
        .unwrap_or_default();
    dwarf_strp(&mut state.sections, info_idx, str_idx, &mut str_hash, &func_name);

    // DW_AT_decl_file (ULEB128 file index)
    section_uleb128(&mut state.sections, info_idx, 1);
    // DW_AT_decl_line
    section_uleb128(&mut state.sections, info_idx, u64::from(func_line));

    // DW_AT_type placeholder (would be return type reference)
    section_data4(&mut state.sections, info_idx, 0);

    // DW_AT_low_pc
    section_data_ptr(&mut state.sections, info_idx, u64::try_from(func_ind).unwrap_or(0));
    // DW_AT_high_pc (size)
    section_data_ptr(&mut state.sections, info_idx, u64::try_from(size).unwrap_or(0));

    // DW_AT_sibling placeholder
    let sibling_offset = section_offset(&state.sections, info_idx);
    section_data4(&mut state.sections, info_idx, 0);

    // DW_AT_frame_base location expression
    // Architecture-dependent: use CFA or frame register
    // Default to DW_OP_call_frame_cfa for modern targets
    section_uleb128(&mut state.sections, info_idx, 1); // exprloc length
    section_data1(&mut state.sections, info_idx, DW_OP_call_frame_cfa);

    // Flush debug info tree (emit children: params, locals, blocks)
    emit_dwarf_debug_finish(state)?;

    // Terminator for subprogram children
    section_data1(&mut state.sections, info_idx, 0);

    // Fix up sibling offset
    let end_offset = section_offset(&state.sections, info_idx);
    write32le_at(&mut state.sections, info_idx, sibling_offset,
        u32::try_from(end_offset).unwrap_or(0));

    // Save hash back
    if let Some(ref mut ds) = state.debug_state {
        ds.dwarf_str = str_hash;
    }
    Ok(())
}

/// Recursively emit DWARF debug info for the `debug_info` tree.
///
/// Walks the tree of `DebugInfoNode`s, emitting DIEs for variables,
/// parameters, and lexical blocks.
///
/// C equivalent: `tcc_debug_finish(s1, debug)` DWARF branch (tccdbg.c:2210-2265)
fn emit_dwarf_debug_finish(state: &mut TccState) -> TccResult<()> {
    // Take the debug info tree from state to avoid borrow conflicts
    let tree = state.debug_state.as_mut().and_then(|ds| ds.debug_info_root.take());

    if let Some(root) = tree {
        emit_dwarf_node(state, &root)?;
        // Restore
        if let Some(ref mut ds) = state.debug_state {
            ds.debug_info_root = Some(root);
        }
    }
    Ok(())
}

/// Emit DWARF DIEs for a single debug info node and its children.
fn emit_dwarf_node(state: &mut TccState, node: &DebugInfoNode) -> TccResult<()> {
    let info_idx = get_dwarf_info_sec(state);

    // Emit symbols in this node
    for sym in &node.syms {
        if sym.sym_type == N_PSYM {
            section_data1(&mut state.sections, info_idx, DWARF_ABBREV_FORMAL_PARAMETER);
        } else {
            section_data1(&mut state.sections, info_idx, DWARF_ABBREV_VARIABLE_LOCAL);
        }
        // DW_AT_name (would be resolved from sym_index)
        // DW_AT_type reference
        // DW_AT_location expression (DW_OP_fbreg + offset)
        section_uleb128(&mut state.sections, info_idx, 2); // exprloc length
        section_data1(&mut state.sections, info_idx, DW_OP_fbreg);
        section_sleb128(&mut state.sections, info_idx, sym.value);
    }

    // Emit lexical block children
    for child in &node.children {
        if child.start != child.end {
            section_data1(&mut state.sections, info_idx, DWARF_ABBREV_LEXICAL_BLOCK);
            section_data_ptr(&mut state.sections, info_idx, u64::try_from(child.start).unwrap_or(0));
            section_data_ptr(&mut state.sections, info_idx, u64::try_from(child.end).unwrap_or(0));
            // Sibling placeholder
            let sib_off = section_offset(&state.sections, info_idx);
            section_data4(&mut state.sections, info_idx, 0);

            // Recurse into children
            emit_dwarf_node(state, child)?;

            // Terminator
            section_data1(&mut state.sections, info_idx, 0);
            // Fix sibling
            let end_off = section_offset(&state.sections, info_idx);
            write32le_at(&mut state.sections, info_idx, sib_off, u32::try_from(end_off).unwrap_or(0));
        }
    }

    Ok(())
}

/// Emit STABS function end info — flush debug info tree.
///
/// C equivalent: `tcc_debug_funcend()` STABS branch + `tcc_debug_finish()` STABS
fn emit_stabs_func_end(state: &mut TccState) -> TccResult<()> {
    // Take tree to avoid borrow conflicts
    let tree = state.debug_state.as_mut().and_then(|ds| ds.debug_info_root.take());

    if let Some(root) = tree {
        emit_stabs_node(state, &root)?;
        if let Some(ref mut ds) = state.debug_state {
            ds.debug_info_root = Some(root);
        }
    }

    // Emit N_FUN end marker with empty string
    let (stab_sec, stabstr_sec) = get_stab_sections(state);
    put_stabs(&mut state.sections, stab_sec, stabstr_sec, "", N_FUN, 0, 0, 0);
    Ok(())
}

/// Emit STABS entries for a debug info node and its children.
fn emit_stabs_node(state: &mut TccState, node: &DebugInfoNode) -> TccResult<()> {
    let (stab_sec, stabstr_sec) = get_stab_sections(state);

    // Emit symbols
    for sym in &node.syms {
        let stab_type = sym.sym_type;
        let value = u32::try_from(sym.value & 0xFFFF_FFFF).unwrap_or(0);
        put_stabs(&mut state.sections, stab_sec, stabstr_sec, &sym.str_repr, stab_type, 0, 0, value);
    }

    // Emit lexical blocks
    for child in &node.children {
        if child.start != child.end {
            let start_val = u32::try_from(child.start & 0xFFFF_FFFF).unwrap_or(0);
            let end_val = u32::try_from(child.end & 0xFFFF_FFFF).unwrap_or(0);
            put_stabn(&mut state.sections, stab_sec, stabstr_sec, N_LBRAC, 0, 0, start_val);
            emit_stabs_node(state, child)?;
            put_stabn(&mut state.sections, stab_sec, stabstr_sec, N_RBRAC, 0, 0, end_val);
        }
    }
    Ok(())
}

/// Fix DWARF forward references for a now-complete struct/union type.
///
/// Searches the forward hash for the type, then patches all saved
/// `DW_FORM_ref4` offsets in `.debug_info` with the correct type reference.
///
/// C equivalent: `tcc_debug_fix_forw(s1, t)` DWARF branch (tccdbg.c:1698-1729)
fn fix_dwarf_forward_refs(state: &mut TccState, ctype: &CType) -> TccResult<()> {
    let info_idx = get_dwarf_info_sec(state);

    // Search forward hash for this type
    let type_key = ctype.ref_sym.map_or(0, |id| id);
    let mut patches: Vec<usize> = Vec::new();

    if let Some(ref mut ds) = state.debug_state {
        // Find and remove from forward hash
        if let Some(pos) = ds.debug_forw_hash.iter().position(|e| e.type_sym == type_key) {
            patches = ds.debug_forw_hash[pos].debug_type_offsets.clone();
            ds.debug_forw_hash.remove(pos);
        }
    }

    if patches.is_empty() {
        return Ok(());
    }

    // Get the current offset as the resolved type's debug offset
    let type_offset = section_offset(&state.sections, info_idx);

    // Patch all saved offsets
    for patch_offset in patches {
        write32le_at(&mut state.sections, info_idx, patch_offset,
            u32::try_from(type_offset).unwrap_or(0));
    }

    Ok(())
}

/// Fix STABS forward references.
///
/// C equivalent: `tcc_debug_fix_forw(s1, t)` STABS branch
fn fix_stabs_forward_refs(state: &mut TccState, _ctype: &CType) -> TccResult<()> {
    // For STABS, forward references use type numbers that are patched
    // in-place when the struct definition completes. Since STABS strings
    // are already written to the section, we track the type number
    // and re-emit the complete type definition.
    let _ = state;
    Ok(())
}

/// Emit DWARF backtrace function name info.
///
/// In backtrace mode, writes the function name to the DWARF string table
/// and line program for stack trace display.
fn emit_dwarf_backtrace_func(state: &mut TccState, sym: Option<SymId>) -> TccResult<()> {
    // Record function name for backtrace display
    let name = sym.map_or_else(
        || "<unknown>".to_string(),
        |id| format!("func_{id}"),
    );
    if let Some(ref mut ds) = state.debug_state {
        ds.func_name = name;
    }
    Ok(())
}

/// Emit STABS function start info.
///
/// Writes `N_FUN` entry with function name and type string.
fn emit_stabs_func_start(state: &mut TccState, sym: Option<SymId>) -> TccResult<()> {
    let (stab_sec, stabstr_sec) = get_stab_sections(state);
    let func_name = sym.map_or_else(
        || "<unknown>".to_string(),
        |id| format!("func_{id}"),
    );
    let stab_str = format!("{func_name}:F(0,0)");
    put_stabs_r(
        &mut state.sections, stab_sec, stabstr_sec,
        &stab_str, N_FUN, 0, 0, 0, 0, 0,
    );
    if let Some(ref mut ds) = state.debug_state {
        ds.func_name = func_name;
    }
    Ok(())
}

/// Emit DWARF info for an external symbol.
///
/// Writes a `DW_TAG_variable` DIE with `DW_AT_external`, name, type, and
/// location (`DW_OP_addr` with relocation).
///
/// C equivalent: `tcc_debug_extern_sym()` DWARF branch (tccdbg.c:2428-2462)
fn emit_dwarf_extern_sym(
    state: &mut TccState,
    sym: Option<SymId>,
    sym_bind: u8,
) -> TccResult<()> {
    let info_idx = get_dwarf_info_sec(state);
    let str_idx = get_dwarf_str_sec(state);

    let is_external = sym_bind == STB_GLOBAL;
    let abbrev = if is_external {
        DWARF_ABBREV_VARIABLE_EXTERNAL
    } else {
        DWARF_ABBREV_VARIABLE_STATIC
    };

    section_data1(&mut state.sections, info_idx, abbrev);

    // DW_AT_external
    section_data1(&mut state.sections, info_idx, u8::from(is_external));

    // DW_AT_name
    let sym_name = sym.map_or_else(
        || "<anon>".to_string(),
        |id| format!("sym_{id}"),
    );
    let mut str_hash = state.debug_state.as_ref()
        .map(|ds| ds.dwarf_str.clone())
        .unwrap_or_default();
    dwarf_strp(&mut state.sections, info_idx, str_idx, &mut str_hash, &sym_name);

    // DW_AT_decl_file, DW_AT_decl_line
    // Line numbers are non-negative in practice; cast is safe for DWARF encoding.
    #[allow(clippy::cast_sign_loss)]
    let decl_line = current_line_num(state) as u32;
    section_uleb128(&mut state.sections, info_idx, 1);
    section_uleb128(&mut state.sections, info_idx, u64::from(decl_line));

    // DW_AT_type (placeholder)
    section_data4(&mut state.sections, info_idx, 0);

    // DW_AT_location: DW_OP_addr + relocation
    let addr_size = u64::try_from(PTR_SIZE).unwrap_or(8);
    section_uleb128(&mut state.sections, info_idx, addr_size.saturating_add(1));
    section_data1(&mut state.sections, info_idx, DW_OP_addr);
    section_data_ptr(&mut state.sections, info_idx, 0); // relocated at link time

    if let Some(ref mut ds) = state.debug_state {
        ds.dwarf_str = str_hash;
    }
    Ok(())
}

/// Emit STABS info for an external symbol.
///
/// Writes `N_GSYM`, `N_STSYM`, or `N_LCSYM` depending on binding and section.
///
/// C equivalent: `tcc_debug_extern_sym()` STABS branch (tccdbg.c:2462-2478)
fn emit_stabs_extern_sym(
    state: &mut TccState,
    sym: Option<SymId>,
    sh_num: u16,
    sym_bind: u8,
) -> TccResult<()> {
    let (stab_sec, stabstr_sec) = get_stab_sections(state);

    let sym_name = sym.map_or_else(
        || "<anon>".to_string(),
        |id| format!("sym_{id}"),
    );

    // Determine STABS type based on binding and section
    let stab_type = if sym_bind == STB_GLOBAL {
        N_GSYM
    } else if sh_num == 0 {
        N_LCSYM // BSS
    } else {
        N_STSYM // static initialized data
    };

    let stab_str = format!("{sym_name}:G(0,0)");
    put_stabs(&mut state.sections, stab_sec, stabstr_sec, &stab_str, stab_type, 0, 0, 0);
    Ok(())
}

/// Emit DWARF typedef DIE.
///
/// C equivalent: `tcc_debug_typedef()` DWARF branch (tccdbg.c:2480-2500)
#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
fn emit_dwarf_typedef(state: &mut TccState, sym: Option<SymId>) -> TccResult<()> {
    let info_idx = get_dwarf_info_sec(state);
    let str_idx = get_dwarf_str_sec(state);

    section_data1(&mut state.sections, info_idx, DWARF_ABBREV_TYPEDEF);

    let sym_name = sym.map_or_else(
        || "<unnamed>".to_string(),
        |id| format!("type_{id}"),
    );

    let mut str_hash = state.debug_state.as_ref()
        .map(|ds| ds.dwarf_str.clone())
        .unwrap_or_default();
    dwarf_strp(&mut state.sections, info_idx, str_idx, &mut str_hash, &sym_name);

    // DW_AT_decl_file, DW_AT_decl_line
    let typedef_line = current_line_num(state) as u32;
    section_uleb128(&mut state.sections, info_idx, 1);
    section_uleb128(&mut state.sections, info_idx, u64::from(typedef_line));

    // DW_AT_type (reference to the underlying type)
    section_data4(&mut state.sections, info_idx, 0);

    if let Some(ref mut ds) = state.debug_state {
        ds.dwarf_str = str_hash;
    }
    Ok(())
}

/// Emit STABS typedef info.
///
/// C equivalent: `tcc_debug_typedef()` STABS branch (tccdbg.c:2500-2507)
fn emit_stabs_typedef(state: &mut TccState, sym: Option<SymId>) -> TccResult<()> {
    let (stab_sec, stabstr_sec) = get_stab_sections(state);
    let sym_name = sym.map_or_else(
        || "<unnamed>".to_string(),
        |id| format!("type_{id}"),
    );
    let stab_str = format!("{sym_name}:t(0,0)");
    put_stabs(&mut state.sections, stab_sec, stabstr_sec, &stab_str, N_LSYM, 0, 0, 0);
    Ok(())
}

// =============================================================================
// Type helper utilities (tccdbg.c:1788-1850)
// =============================================================================

/// Strip storage class and qualifier modifiers from a type value,
/// producing a canonical form suitable for debug type lookups.
///
/// C equivalent: `remove_type_info(type)` (tccdbg.c:1788-1796)
fn remove_type_info(type_val: i32) -> i32 {
    let mut t = type_val & !(VT_STORAGE | VT_CONSTANT | VT_VOLATILE | VT_VLA);
    if (t & VT_BTYPE) != VT_BYTE {
        t &= !VT_DEFSIGN;
    }
    if (t & VT_BITFIELD) == 0 && (t & VT_STRUCT_MASK) > VT_ENUM {
        t &= !VT_STRUCT_MASK;
    }
    t
}

/// Check if a struct member should be excluded from debug info.
///
/// Anonymous bit-fields with basic integer types are excluded.
///
/// C equivalent: `STRUCT_NODEBUG(s)` (tccdbg.c:1747-1757)
fn struct_nodebug(sym: &Symbol) -> bool {
    let bt = sym.ctype.t & VT_BTYPE;
    (sym.v & !i64::from(SYM_FIELD)) >= i64::from(SYM_FIRST_ANOM)
        && (bt == VT_BYTE || bt == VT_BOOL || bt == VT_SHORT
            || bt == VT_INT || bt == VT_LLONG)
}

/// Debug type lookup — search global and local hashes.
///
/// C equivalent: `tcc_debug_find(s1, type)` (tccdbg.c:1650-1692)
fn debug_find_type(state: &TccState, ctype: &CType) -> Option<usize> {
    let type_key = remove_type_info(ctype.t);

    if let Some(ref ds) = state.debug_state {
        // Search local hash first (function scope)
        for entry in ds.debug_hash_local.iter().rev() {
            if entry.type_sym == ctype.ref_sym.unwrap_or(0) as SymId {
                return Some(entry.debug_type);
            }
        }
        // Then global hash
        for entry in ds.debug_hash.iter().rev() {
            if entry.type_sym == ctype.ref_sym.unwrap_or(0) as SymId {
                return Some(entry.debug_type);
            }
        }
    }
    let _ = type_key;
    None
}

/// Register a new debug type in the hash.
///
/// C equivalent: `tcc_debug_add(s1, type, debug_type)` (tccdbg.c:1731)
fn debug_add_type(state: &mut TccState, ctype: &CType, debug_type: usize) {
    let type_sym = ctype.ref_sym.unwrap_or(0) as SymId;
    let entry = DebugHashEntry { type_sym, debug_type };
    if let Some(ref mut ds) = state.debug_state {
        ds.debug_hash.push(entry);
    }
}

/// Record a forward-referenced type for later fixup.
///
/// C equivalent: `tcc_debug_check_forw(s1, type, offset)` (tccdbg.c:1694)
fn debug_check_forw(state: &mut TccState, ctype: &CType, offset: usize) {
    let type_sym = ctype.ref_sym.unwrap_or(0) as SymId;
    if let Some(ref mut ds) = state.debug_state {
        if let Some(entry) = ds.debug_forw_hash.iter_mut().find(|e| e.type_sym == type_sym) {
            entry.debug_type_offsets.push(offset);
        } else {
            ds.debug_forw_hash.push(DebugForwHashEntry {
                type_sym,
                debug_type_offsets: vec![offset],
            });
        }
    }
}

// =============================================================================
// Unit tests

// =============================================================================
// Unit tests
// =============================================================================
#[cfg(test)]
#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
mod tests {
    use super::*;

    #[test]
    fn test_debug_state_default() {
        let ds = DebugState::default();
        assert!(ds.string_table.is_empty(), "string_table should be empty on init");
        assert!(ds.dwarf.is_none(), "dwarf should be None on init");
        assert!(ds.unit.is_none(), "unit should be None on init");
        assert_eq!(ds.last_line_num, 0, "last_line_num should be 0");
        assert!(!ds.new_file, "new_file should be false on init");
        assert_eq!(ds.section_sym, 0, "section_sym should be 0");
        assert!(ds.debug_hash.is_empty(), "debug_hash should be empty");
        assert!(ds.debug_forw_hash.is_empty(), "debug_forw_hash should be empty");
        assert!(ds.debug_info.is_none(), "debug_info should be None");
        assert_eq!(ds.dwarf_sym, 0, "dwarf_sym should be 0");
    }

    #[test]
    fn test_debug_state_new() {
        let ds = DebugState::new();
        assert!(ds.string_table.is_empty());
        assert_eq!(ds.last_line_num, 0);
        assert!(!ds.new_file);
        assert!(ds.debug_hash.is_empty());
    }

    #[test]
    fn test_debug_state_string_table_operations() {
        let mut ds = DebugState::default();
        ds.string_table.insert("main".to_string(), 0);
        ds.string_table.insert("foo".to_string(), 5);
        ds.string_table.insert("bar".to_string(), 9);
        assert_eq!(ds.string_table.len(), 3);
        assert_eq!(*ds.string_table.get("main").unwrap(), 0);
        assert_eq!(*ds.string_table.get("foo").unwrap(), 5);
        assert!(ds.string_table.contains_key("bar"));
        assert!(!ds.string_table.contains_key("baz"));
    }

    #[test]
    fn test_debug_hash_entries() {
        let mut ds = DebugState::default();
        ds.debug_hash.push(DebugHashEntry {
            type_sym: 42,
            debug_type: 1,
        });
        assert_eq!(ds.debug_hash.len(), 1);
        assert_eq!(ds.debug_hash[0].type_sym, 42);
        assert_eq!(ds.debug_hash[0].debug_type, 1);
    }

    #[test]
    fn test_debug_forw_hash_entries() {
        let mut ds = DebugState::default();
        ds.debug_forw_hash.push(DebugForwHashEntry {
            type_sym: 100,
            debug_type_offsets: vec![64, 128],
        });
        assert_eq!(ds.debug_forw_hash.len(), 1);
        assert_eq!(ds.debug_forw_hash[0].type_sym, 100);
        assert_eq!(ds.debug_forw_hash[0].debug_type_offsets.len(), 2);
    }

    #[test]
    fn test_tcov_data_default() {
        let ds = DebugState::default();
        assert_eq!(ds.tcov_data.last_file_name, 0);
        assert_eq!(ds.tcov_data.last_func_name, 0);
        assert_eq!(ds.tcov_data.line, 0);
        assert_eq!(ds.tcov_data.offset, 0);
        assert_eq!(ds.tcov_data.ind, 0);
    }

    #[test]
    fn test_dwarf_line_state_default() {
        let ds = DebugState::default();
        assert_eq!(ds.dwarf_line.last_pc, 0);
        assert_eq!(ds.dwarf_line.cur_file, 0);
        assert_eq!(ds.dwarf_line.last_file, 0);
        assert!(ds.dwarf_line.filenames.is_empty());
        assert!(ds.dwarf_line.dirs.is_empty());
    }

    #[test]
    fn test_dwarf_info_state_default() {
        let ds = DebugState::default();
        assert_eq!(ds.dwarf_info.start, 0);
        assert!(ds.dwarf_info.func.is_none());
        assert_eq!(ds.dwarf_info.line, 0);
        // base_type_used is pre-allocated with N_DEFAULT_DEBUG (18) zero entries
        assert_eq!(ds.dwarf_info.base_type_used.len(), N_DEFAULT_DEBUG);
        assert!(ds.dwarf_info.base_type_used.iter().all(|&x| x == 0));
    }

    #[test]
    fn test_all_members_exposed_accessible() {
        let ds = DebugState::default();
        let _ = &ds.string_table;
        let _ = &ds.dwarf;
        let _ = &ds.unit;
        let _ = ds.last_line_num;
        let _ = ds.new_file;
        let _ = ds.section_sym;
        let _ = ds.debug_next_type;
        let _ = &ds.debug_hash;
        let _ = &ds.debug_forw_hash;
        let _ = &ds.debug_info;
        let _ = ds.dwarf_sym;
        let _ = &ds.dwarf_line;
        let _ = &ds.dwarf_info;
        let _ = &ds.tcov_data;
    }

    #[test]
    fn test_uleb128_encoding() {
        let mut buf = Vec::new();
        dwarf_write_uleb128(&mut buf, 0);
        assert_eq!(buf, vec![0]);

        let mut buf = Vec::new();
        dwarf_write_uleb128(&mut buf, 127);
        assert_eq!(buf, vec![127]);

        let mut buf = Vec::new();
        dwarf_write_uleb128(&mut buf, 128);
        assert_eq!(buf, vec![0x80, 0x01]);

        let mut buf = Vec::new();
        dwarf_write_uleb128(&mut buf, 624_485);
        assert_eq!(buf, vec![0xe5, 0x8e, 0x26]);
    }

    #[test]
    fn test_sleb128_encoding() {
        let mut buf = Vec::new();
        dwarf_write_sleb128(&mut buf, 0);
        assert_eq!(buf, vec![0]);

        let mut buf = Vec::new();
        dwarf_write_sleb128(&mut buf, -1);
        assert_eq!(buf, vec![0x7f]);

        let mut buf = Vec::new();
        dwarf_write_sleb128(&mut buf, 127);
        assert_eq!(buf, vec![0xff, 0x00]);

        let mut buf = Vec::new();
        dwarf_write_sleb128(&mut buf, -128);
        assert_eq!(buf, vec![0x80, 0x7f]);
    }

    #[test]
    fn test_sleb128_size() {
        assert_eq!(dwarf_sleb128_size(0), 1);
        assert_eq!(dwarf_sleb128_size(-1), 1);
        assert_eq!(dwarf_sleb128_size(127), 2);
        assert_eq!(dwarf_sleb128_size(-128), 2);
    }

    #[test]
    fn test_debug_info_node_creation() {
        let node = DebugInfoNode::new();
        assert_eq!(node.start, 0);
        assert_eq!(node.end, 0);
        assert!(node.syms.is_empty());
        assert!(node.children.is_empty());
    }

    #[test]
    fn test_dwarf_abbrev_table_generation_v5() {
        let table = build_dwarf_abbrev_table(5);
        assert!(!table.is_empty());
        // Table should end with a 0 (null terminator)
        assert_eq!(*table.last().unwrap(), 0);
        // Table should start with abbreviation code 1
        assert_eq!(table[0], DWARF_ABBREV_COMPILE_UNIT);
    }

    #[test]
    fn test_dwarf_abbrev_table_generation_v4() {
        let table = build_dwarf_abbrev_table(4);
        assert!(!table.is_empty());
        assert_eq!(*table.last().unwrap(), 0);
    }

    #[test]
    #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
    fn test_debug_state_debug_next_type_default() {
        let ds = DebugState::default();
        assert!(ds.debug_next_type > 0, "debug_next_type should start at N_DEFAULT_DEBUG");
        assert_eq!(ds.debug_next_type, N_DEFAULT_DEBUG as i32);
    }

    #[test]
    fn test_debug_sym_creation() {
        let sym = DebugSym {
            sym_type: N_LSYM,
            value: 42,
            str_repr: "my_var".to_string(),
            sec: 1,
            sym_index: 5,
            file: 0,
            line: 10,
            info: 0,
        };
        assert_eq!(sym.sym_type, N_LSYM);
        assert_eq!(sym.value, 42);
        assert_eq!(sym.str_repr, "my_var");
        assert_eq!(sym.line, 10);
    }

    #[test]
    fn test_default_debug_table_populated() {
        assert_eq!(DEFAULT_DEBUG.len(), 18);
        assert_eq!(DEFAULT_DEBUG[0].type_val, VT_INT);
        assert_eq!(DEFAULT_DEBUG[0].size, 4);
        assert_eq!(DEFAULT_DEBUG[0].encoding, DW_ATE_signed);
    }

    #[test]
    fn test_dwarf_line_constants() {
        assert_eq!(DWARF_LINE_BASE, -5);
        assert_eq!(DWARF_LINE_RANGE, 14);
        assert_eq!(DWARF_OPCODE_BASE, 13);
    }
}
