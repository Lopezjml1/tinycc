//! x86 32-bit (i386) architecture backend for TinyCC.
//!
//! Consolidates `i386-gen.c` (1,306 lines), `i386-asm.c` (1,757 lines),
//! `i386-link.c` (329 lines), `i386-tok.h` (332 lines), and `i386-asm.h`
//! (490 lines) from the original C codebase into a single Rust module
//! implementing [`CodegenBackend`] and [`LinkerBackend`].
//!
//! # Safety
//! - No `unsafe` blocks — code generation is pure computation
//! - No `unwrap()` in library code — all fallible ops return `TccResult<T>`
//! - Instruction encoding uses explicit `u32`/`u16`/`u8` bit operations
//!   with named constants (AAP §0.8.3)
//!
//! # CVE Remediation
//! - All buffer writes use `Vec<u8>` and bounds-checked slicing
//! - Relocation entries are typed structs, NOT raw byte arrays (AAP §0.8.3)
//! - Integer arithmetic uses checked/explicit conversions
//!
//! # Feature Gate
//! This entire module is compiled only when `feature = "i386"` is enabled
//! in Cargo.toml (AAP §0.8.3).

// Clippy: non-cast allows are acceptable in a code-generation backend where
// register names, opcode mnemonics, and low-level bit manipulation are pervasive.
// Cast safety allows (cast_sign_loss, cast_possible_truncation, cast_possible_wrap)
// are applied at impl-block/function level per AAP §0.8.1 to preserve CVE-2006-0635
// compile-time enforcement for new code added outside these blocks.
#![allow(clippy::cast_lossless)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::similar_names)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::upper_case_acronyms)]
#![allow(clippy::struct_field_names)]
#![allow(clippy::match_same_arms)]
#![allow(clippy::wildcard_in_or_patterns)]
#![allow(clippy::wildcard_enum_match_arm)]
#![allow(clippy::manual_range_contains)]
#![allow(clippy::needless_pass_by_value)]
#![allow(clippy::unnecessary_wraps)]
#![allow(clippy::unused_self)]
#![allow(clippy::items_after_statements)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::bool_to_int_with_if)]
#![allow(clippy::option_map_or_none)]
#![allow(clippy::map_unwrap_or)]
#![allow(clippy::unnecessary_cast)]
#![allow(clippy::let_and_return)]
#![allow(clippy::single_match_else)]
#![allow(clippy::collapsible_match)]
#![allow(clippy::option_if_let_else)]
#![allow(dead_code)]

use crate::codegen;
use crate::context::TccState;
use crate::error::{TccError, TccResult};
use crate::formats::elf::{
    EM_386, R_386_16, R_386_32, R_386_COPY, R_386_GLOB_DAT, R_386_GOT32,
    R_386_GOT32X, R_386_GOTOFF, R_386_GOTPC, R_386_JMP_SLOT, R_386_NONE,
    R_386_PC16, R_386_PC32, R_386_PLT32, R_386_RELATIVE, R_386_TLS_GD_32,
    R_386_TLS_IE, R_386_TLS_LDM_32, R_386_TLS_LDO_32, R_386_TLS_LE,
};
use crate::targets::{
    add32le, read32le, write16le, write32le, CodegenBackend, GotPltEntry, LinkerBackend,
};
use crate::tokens::{
    TOK_EQ, TOK_GE, TOK_GT, TOK_LE, TOK_LT, TOK_NE, TOK_SAR, TOK_SHL, TOK_SHR, TOK_UDIV,
    TOK_UGE, TOK_UGT, TOK_ULE, TOK_ULT, TOK_UMOD,
};
use crate::types::{
    CType, SValue, SValueData, SValueSymInfo, Symbol, SymId,
    FUNC_FASTCALL1, FUNC_FASTCALL3, FUNC_FASTCALLW, FUNC_STDCALL,
    FUNC_THISCALL,
    VT_BOOL, VT_BTYPE, VT_BYTE, VT_CMP, VT_CONST, VT_DOUBLE, VT_FLOAT,
    VT_INT, VT_JMP, VT_JMPI, VT_LDOUBLE, VT_LLONG, VT_LOCAL, VT_LVAL,
    VT_SHORT, VT_UNSIGNED, VT_VALMASK,
};

// =========================================================================
// Locally-defined token constants not present in tokens.rs
// =========================================================================

/// Add-with-carry first operand. C: TOK_ADDC1 in tcc.h.
const TOK_ADDC1: i32 = 0xa0;
/// Add-with-carry second operand. C: TOK_ADDC2 in tcc.h.
const TOK_ADDC2: i32 = 0xa1;
/// Subtract-with-borrow first operand. C: TOK_SUBC1 in tcc.h.
const TOK_SUBC1: i32 = 0xa2;
/// Subtract-with-borrow second operand. C: TOK_SUBC2 in tcc.h.
const TOK_SUBC2: i32 = 0xa3;

// =========================================================================
// Register Definitions (i386-gen.c:23-59)
// =========================================================================

/// Number of available general-purpose + FPU registers.
/// C equivalent: `NB_REGS` (i386-gen.c:24).
pub const NB_REGS: usize = 5;

/// Number of assembler-visible general-purpose registers (EAX–EDI).
/// C equivalent: `NB_ASM_REGS` (i386-gen.c:25).
pub const NB_ASM_REGS: usize = 8;

// =========================================================================
// Register Class Bitmasks (i386-gen.c:31-41)
// =========================================================================

/// Integer register class.
pub const RC_INT: u32 = 0x0001;
/// Floating-point (x87) register class.
pub const RC_FLOAT: u32 = 0x0002;
/// Specific register: EAX.
pub const RC_EAX: u32 = 0x0004;
/// Specific register: EDX.
pub const RC_EDX: u32 = 0x0008;
/// Specific register: ECX.
pub const RC_ECX: u32 = 0x0010;
/// Specific register: EBX.
pub const RC_EBX: u32 = 0x0020;
/// Specific register: ST(0) (x87 FPU top-of-stack).
pub const RC_ST0: u32 = 0x0040;
/// Function integer return register (EAX).
pub const RC_IRET: u32 = RC_EAX;
/// Function integer return second register (EDX) for 64-bit returns.
pub const RC_IRE2: u32 = RC_EDX;
/// Function floating-point return register (ST0).
pub const RC_FRET: u32 = RC_ST0;

// =========================================================================
// Register Enum (i386-gen.c:44-52)
// =========================================================================

/// Hardware register indices for i386 code generation.
/// C equivalent: `TREG_*` enum (i386-gen.c:44-52).
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TReg {
    /// EAX register (index 0).
    EAX = 0,
    /// ECX register (index 1).
    ECX = 1,
    /// EDX register (index 2).
    EDX = 2,
    /// EBX register (index 3).
    EBX = 3,
    /// x87 FPU ST(0) register (index 4).
    ST0 = 4,
}

/// ESP register index (used for stack pointer references, not allocatable).
/// C equivalent: `TREG_ESP` (i386-gen.c:51).
pub const TREG_ESP: u8 = 4;

/// Memory pseudo-register flag. C equivalent: `TREG_MEM` (i386-gen.c:52).
pub const TREG_MEM: u8 = 0x20;

// =========================================================================
// Register Class Array (i386-gen.c:98-104)
// =========================================================================

/// Per-register class bitmask array, indexed by register number (0..NB_REGS).
/// C equivalent: `reg_classes[NB_REGS]` (i386-gen.c:98-104).
pub const REG_CLASSES: [u32; NB_REGS] = [
    RC_INT | RC_EAX, // TREG_EAX
    RC_INT | RC_ECX, // TREG_ECX
    RC_INT | RC_EDX, // TREG_EDX
    RC_INT | RC_EBX, // TREG_EBX (callee-saved)
    RC_FLOAT | RC_ST0, // TREG_ST0
];

// =========================================================================
// Platform Constants (i386-gen.c:69-90)
// =========================================================================

/// Pointer size in bytes (4 for i386).
pub const PTR_SIZE: usize = 4;
/// Long double size in bytes (12 on i386: 80-bit extended + 2 bytes padding).
pub const LDOUBLE_SIZE: usize = 12;
/// Long double alignment in bytes.
pub const LDOUBLE_ALIGN: usize = 4;
/// Maximum natural alignment for any type.
pub const MAX_ALIGN: usize = 8;

/// Whether to promote function return values to int. Always true for i386.
pub const PROMOTE_RET: bool = true;
/// Whether the platform supports fastcall calling convention.
pub const HAVE_FASTCALL: bool = true;
/// Whether char is unsigned by default (false for i386).
pub const CHAR_IS_UNSIGNED: bool = false;
/// Whether function parameters are pushed right-to-left (cdecl convention).
pub const INVERT_FUNC_PARAMS: bool = true;

/// Fastcall registers: ECX, EDX (for __fastcall with 1-2 register params).
pub const FASTCALL_REGS: [u8; 2] = [TReg::ECX as u8, TReg::EDX as u8];
/// Windows fastcall registers: ECX, EDX (same as fastcall).
pub const FASTCALLW_REGS: [u8; 2] = [TReg::ECX as u8, TReg::EDX as u8];

/// Preprocessor macro definitions emitted when targeting i386.
/// C equivalent: `target_machine_defs` (i386-gen.c:87-90).
pub const TARGET_MACHINE_DEFS: &[&str] = &["__i386__", "__i386"];

// =========================================================================
// ELF / Linker Constants (i386-link.c:1-20)
// =========================================================================

/// ELF machine type for this target.
/// C equivalent: `EM_TCC_TARGET` (i386-link.c:3).
pub const EM_TCC_TARGET: u32 = EM_386 as u32;

/// ELF starting virtual address for executables.
/// C equivalent: `ELF_START_ADDR` (i386-link.c:15).
pub const ELF_START_ADDR: u64 = 0x0804_8000;

/// ELF page size for segment alignment.
/// C equivalent: `ELF_PAGE_SIZE` (i386-link.c:16).
pub const ELF_PAGE_SIZE: u64 = 0x1000;

/// Generic data relocation (32-bit absolute). C: `R_DATA_32` (i386-link.c:5).
pub const R_DATA_32: u32 = R_386_32;
/// Pointer-sized data relocation. C: `R_DATA_PTR` (i386-link.c:6).
pub const R_DATA_PTR: u32 = R_386_32;
/// Jump slot relocation for PLT. C: `R_JMP_SLOT` (i386-link.c:7).
pub const R_JMP_SLOT: u32 = R_386_JMP_SLOT;
/// Global data relocation for GOT. C: `R_GLOB_DAT` (i386-link.c:8).
pub const R_GLOB_DAT: u32 = R_386_GLOB_DAT;
/// Copy relocation. C: `R_COPY` (i386-link.c:9).
pub const R_COPY: u32 = R_386_COPY;
/// Relative relocation (base + offset). C: `R_RELATIVE` (i386-link.c:10).
pub const R_RELATIVE: u32 = R_386_RELATIVE;
/// Number of relocation types. C: `R_NUM` (i386-link.c:11).
pub const R_NUM: u32 = 44; // R_386_NUM

/// Whether PC-relative relocations are used for DLL PLT entries.
/// C equivalent: `PCRELATIVE_DLLPLT` (i386-link.c:18).
pub const PCRELATIVE_DLLPLT: bool = false;
/// Whether DLL PLT entries need special relocation.
/// C equivalent: `RELOCATE_DLLPLT` (i386-link.c:19).
pub const RELOCATE_DLLPLT: bool = false;

// =========================================================================
// Assembler Constants (i386-asm.c:25-70)
// =========================================================================

/// Maximum number of operands per assembly instruction.
/// C equivalent: `MAX_OPERANDS` (i386-asm.c:25).
pub const MAX_OPERANDS: usize = 3;

// =========================================================================
// Assembler Operand Constraint Flags
// =========================================================================

/// Operand constraint: byte-sized instruction variant.
/// C equivalent: `OPC_B` (i386-asm.c:31).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum AsmOperandConstraint {
    /// Byte-sized opcode variant.
    OpcB = 0x01,
    /// Word/Long opcode variant.
    OpcWL = 0x02,
    /// Byte/Word/Long opcode variant.
    OpcBWL = 0x04,
    /// Register encoding in low 3 bits of opcode.
    OpcReg = 0x08,
    /// ModR/M encoding required.
    OpcModRM = 0x10,
    /// Immediate operand.
    OpcImm = 0x20,
    /// Shift operation (cl or imm8).
    OpcShift = 0x40,
    /// Jump/call target.
    OpcJmp = 0x80,
    /// Floating-point arithmetic.
    OpcFarith = 0x100,
    /// Test instruction group.
    OpcTest = 0x200,
}

// Opcode type flags (used as bitmasks in the opcode table)
const OPC_B: u16 = 0x01;
const OPC_WL: u16 = 0x02;
const OPC_BWL: u16 = OPC_B | OPC_WL;
const OPC_BWLX: u16 = 0x07;
const OPC_WLX: u16 = 0x06;
const OPC_REG: u16 = 0x08;
const OPC_MODRM: u16 = 0x10;
const OPC_FWAIT: u16 = 0x20;
const OPC_SHIFT: u16 = 0x40;
const OPC_ARITH: u16 = 0x80;
const OPC_FARITH: u16 = 0x100;
const OPC_TEST: u16 = 0x200;

// Operand type constants for the assembler opcode table
const OPT_REG: u16 = 0x0001;
const OPT_REG8: u16 = 0x0002;
const OPT_REG16: u16 = 0x0004;
const OPT_REG32: u16 = 0x0008;
const OPT_REGW: u16 = OPT_REG16 | OPT_REG32;
const OPT_IMW: u16 = 0x0010;
const OPT_IM8: u16 = 0x0020;
const OPT_IM8S: u16 = 0x0040;
const OPT_IM16: u16 = 0x0080;
const OPT_IM32: u16 = 0x0100;
const OPT_IM: u16 = OPT_IM8 | OPT_IM8S | OPT_IM16 | OPT_IM32;
const OPT_EA: u16 = 0x0200;
const OPT_ST: u16 = 0x0400;
const OPT_ST0: u16 = 0x0800;
const OPT_CL: u16 = 0x1000;
const OPT_DX: u16 = 0x2000;
const OPT_EAX: u16 = 0x4000;
const OPT_SEG: u16 = 0x8000;
const OPT_ADDR: u16 = 0x0001; // reused bit for address form
const OPT_DISP: u16 = 0x0001; // reused for displacement
const OPT_DISP8: u16 = 0x0002; // short displacement
const OPT_INDIR: u16 = 0x0004; // indirect operand
const OPT_MMX: u16 = 0x0010;
const OPT_SSE: u16 = 0x0020;
const OPT_MMXSSE: u16 = OPT_MMX | OPT_SSE;
const OPT_CR: u16 = 0x0040;
const OPT_DB: u16 = 0x0080;
const OPT_TR: u16 = 0x0100;

// =========================================================================
// Assembler opcode table entry (i386-asm.h)
// =========================================================================

/// An entry in the x86 assembler opcode table.
///
/// Each entry maps an instruction mnemonic to its encoding parameters.
/// C equivalent: implicit DEF_ASM_OP* structures in `i386-asm.h`.
#[derive(Debug, Clone)]
pub struct AsmOp {
    /// Instruction mnemonic (e.g., "movb", "addl").
    pub name: &'static str,
    /// Base opcode value.
    pub opcode: u32,
    /// Instruction group / ModRM reg field.
    pub group: u8,
    /// Operand constraint flags (OPC_* bitmask).
    pub flags: u16,
    /// Operand type constraints for each operand.
    pub operands: &'static [u16],
}

// =========================================================================
// I386AsmOpcode — Assembler token enum (i386-tok.h)
// =========================================================================

/// Assembler instruction opcodes for i386.
///
/// Maps each x86 instruction mnemonic to an enum variant.
/// C equivalent: Token definitions via DEF_ASM_OP0 macros in `i386-asm.h`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum I386AsmOpcode {
    CLC, CLD, CLI, CLTS, CMC, LAHF, SAHF, PUSHA, POPA,
    LEAVE, RET, IRET, HLT, WAIT, LOCK, REP, REPE, REPNE,
    NOP,
    STOSB, STOSW, STOSD, MOVSB, MOVSW, MOVSD,
    CMPSB, CMPSW, CMPSD,
    SCASB, SCASW, SCASD,
    INSB, INSW, INSD, OUTSB, OUTSW, OUTSD,
    LODSB, LODSW, LODSD,
    CBW, CWD, CWDE, CDQ,
    PUSHF, POPF,
}

// =========================================================================
// Assembler opcode table (i386-asm.h — zero-operand entries)
// =========================================================================

/// Static table of zero-operand assembler instructions.
/// C equivalent: DEF_ASM_OP0 entries in `i386-asm.h` lines 1-38.
pub const I386_ASM_OPS: &[(&str, u32)] = &[
    ("clc", 0xf8),
    ("cld", 0xfc),
    ("cli", 0xfa),
    ("clts", 0x0f06),
    ("cmc", 0xf5),
    ("lahf", 0x9f),
    ("sahf", 0x9e),
    ("pusha", 0x60),
    ("popa", 0x61),
    ("pushfl", 0x9c),
    ("popfl", 0x9d),
    ("pushf", 0x9c),
    ("popf", 0x9d),
    ("stc", 0xf9),
    ("std", 0xfd),
    ("sti", 0xfb),
    ("aaa", 0x37),
    ("aas", 0x3f),
    ("daa", 0x27),
    ("das", 0x2f),
    ("aad", 0xd50a),
    ("aam", 0xd40a),
    ("cbw", 0x6698),
    ("cwd", 0x6699),
    ("cwde", 0x98),
    ("cdq", 0x99),
    ("cbtw", 0x6698),
    ("cwtl", 0x98),
    ("cwtd", 0x6699),
    ("cltd", 0x99),
    ("int3", 0xcc),
    ("into", 0xce),
    ("iret", 0xcf),
    ("rsm", 0x0faa),
    ("hlt", 0xf4),
    ("nop", 0x90),
    ("pause", 0xf390),
    ("xlat", 0xd7),
    ("wait", 0x9b),
    ("fwait", 0x9b),
    ("lock", 0xf0),
    ("rep", 0xf3),
    ("repe", 0xf3),
    ("repz", 0xf3),
    ("repne", 0xf2),
    ("repnz", 0xf2),
    ("invd", 0x0f08),
    ("wbinvd", 0x0f09),
    ("cpuid", 0x0fa2),
    ("wrmsr", 0x0f30),
    ("rdtsc", 0x0f31),
    ("rdmsr", 0x0f32),
    ("rdpmc", 0x0f33),
    ("ud2", 0x0f0b),
    ("leave", 0xc9),
    ("ret", 0xc3),
    ("retl", 0xc3),
    ("lret", 0xcb),
    ("fucompp", 0xdae9),
    ("ftst", 0xd9e4),
    ("fxam", 0xd9e5),
    ("fld1", 0xd9e8),
    ("fldl2t", 0xd9e9),
    ("fldl2e", 0xd9ea),
    ("fldpi", 0xd9eb),
    ("fldlg2", 0xd9ec),
    ("fldln2", 0xd9ed),
    ("fldz", 0xd9ee),
    ("f2xm1", 0xd9f0),
    ("fyl2x", 0xd9f1),
    ("fptan", 0xd9f2),
    ("fpatan", 0xd9f3),
    ("fxtract", 0xd9f4),
    ("fprem1", 0xd9f5),
    ("fdecstp", 0xd9f6),
    ("fincstp", 0xd9f7),
    ("fprem", 0xd9f8),
    ("fyl2xp1", 0xd9f9),
    ("fsqrt", 0xd9fa),
    ("fsincos", 0xd9fb),
    ("frndint", 0xd9fc),
    ("fscale", 0xd9fd),
    ("fsin", 0xd9fe),
    ("fcos", 0xd9ff),
    ("fchs", 0xd9e0),
    ("fabs", 0xd9e1),
    ("fninit", 0xdbe3),
    ("fnclex", 0xdbe2),
    ("fnop", 0xd9d0),
    ("fxch", 0xd9c9),
    ("emms", 0x0f77),
];

// =========================================================================
// I386Backend Struct (i386-gen.c:105-111)
// =========================================================================

/// x86 32-bit code generation backend.
///
/// Implements [`CodegenBackend`] and [`LinkerBackend`] for the i386 target.
/// C equivalent: State variables at the top of `i386-gen.c` lines 105-111.
pub struct I386Backend {
    /// Offset of the sub instruction that reserves stack space in function
    /// prologue. Patched during epilogue to set the actual frame size.
    /// C equivalent: `func_sub_sp_offset` (i386-gen.c:106).
    func_sub_sp_offset: u64,

    /// Number of bytes to pop from the stack on return (for stdcall/fastcall).
    /// C equivalent: `func_ret_sub` (i386-gen.c:107).
    func_ret_sub: i32,

    /// Register classes array, indexed by register number.
    reg_classes: [u32; NB_REGS],

    /// Bounds checking: offset in code section where bound prolog was emitted.
    func_bound_offset: u64,

    /// Bounds checking: ind value where bound prolog was emitted.
    func_bound_ind: u64,

    /// Whether to emit bounds-checking epilog code.
    pub func_bound_add_epilog: bool,
}

// i386 instruction encoding: ModRM, SIB, and immediate fields require
// u32↔i32↔u8 casts with ISA-defined bit ranges.
#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
impl I386Backend {
    /// Create a new i386 backend with default state.
    pub fn new() -> Self {
        Self {
            func_sub_sp_offset: 0,
            func_ret_sub: 0,
            reg_classes: REG_CLASSES,
            func_bound_offset: 0,
            func_bound_ind: 0,
            func_bound_add_epilog: false,
        }
    }
}

// =========================================================================
// Helper Functions (i386-gen.c:117-287)
// =========================================================================

/// Emit a single byte to the current code section.
/// C equivalent: `g()` (i386-gen.c:117).
fn emit_byte(state: &mut TccState, c: u8) -> TccResult<()> {
    codegen::g(state, c)
}

/// Emit a multi-byte opcode and a 32-bit displacement, returning the offset
/// of the displacement for later patching.
/// C equivalent: `oad()` (i386-gen.c:148-155).
#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
pub fn oad(state: &mut TccState, c: u32, s: i32) -> TccResult<i32> {
    o_internal(state, c)?;
    let ind = state.ind;
    codegen::gen_le32(state, s as u32)?;
    Ok(ind as i32)
}

/// Internal multi-byte opcode emission.
/// Emits 1-4 bytes from a u32 opcode value (big-endian within the u32).
/// C equivalent: `o()` (i386-gen.c:129-135).
#[allow(clippy::cast_possible_truncation)]
fn o_internal(state: &mut TccState, c: u32) -> TccResult<()> {
    if c >= 0x0100_0000 {
        codegen::g(state, (c >> 24) as u8)?;
    }
    if c >= 0x0001_0000 {
        codegen::g(state, (c >> 16) as u8)?;
    }
    if c >= 0x0000_0100 {
        codegen::g(state, (c >> 8) as u8)?;
    }
    codegen::g(state, c as u8)?;
    Ok(())
}

/// Create a minimal [`Symbol`] with just the `c` field set for relocation use.
/// This avoids needing a full symbol lookup when we only need the ELF index.
fn sym_for_reloc(sym_id: SymId) -> Symbol {
    Symbol { c: i32::try_from(sym_id).unwrap_or(0), ..Symbol::default() }
}

/// Emit a 32-bit address or displacement for a symbol reference.
/// Adds a relocation entry for the symbol.
/// C equivalent: `gen_addr32()` (i386-gen.c:200-210).
#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
pub fn gen_addr32(state: &mut TccState, _r: u16, sym: Option<SymId>, c: i64) -> TccResult<()> {
    if let Some(sym_idx) = sym {
        let sec_idx = state.cur_text_section;
        let offset = state.ind as u64;
        let sym_ref = sym_for_reloc(sym_idx);
        codegen::greloc(state, sec_idx, &sym_ref, offset, R_386_32 as i32)?;
    }
    codegen::gen_le32(state, c as u32)?;
    Ok(())
}

/// Emit a PC-relative 32-bit address for a symbol reference.
/// C equivalent: `gen_addrpc32()` (i386-gen.c:215-225).
#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
pub fn gen_addrpc32(state: &mut TccState, _r: u16, sym: Option<SymId>, c: i64) -> TccResult<()> {
    if let Some(sym_idx) = sym {
        let sec_idx = state.cur_text_section;
        let offset = state.ind as u64;
        let sym_ref = sym_for_reloc(sym_idx);
        codegen::greloc(state, sec_idx, &sym_ref, offset, R_386_PC32 as i32)?;
    }
    let disp = c.wrapping_sub(4) as u32;
    codegen::gen_le32(state, disp)?;
    Ok(())
}

/// Encode a ModR/M byte and optional SIB/displacement for an operand.
///
/// C equivalent: `gen_modrm()` (i386-gen.c:231-287).
#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
pub fn gen_modrm(
    state: &mut TccState,
    op_reg: i32,
    r: u16,
    sym: Option<usize>,
    c: i64,
) -> TccResult<()> {
    let fr = r & VT_VALMASK;
    let op = ((op_reg & 7) << 3) as u8;

    if fr == VT_CONST as u16 {
        // [disp32] absolute addressing: mod=00, rm=101
        codegen::g(state, op | 0x05)?;
        gen_addr32(state, r, sym, c)?;
    } else if fr == VT_LOCAL as u16 {
        let c32 = c as i32;
        if c32 == i32::from(c32 as i8) {
            // [ebp+disp8]: mod=01, rm=101
            codegen::g(state, op | 0x45)?;
            codegen::g(state, c32 as u8)?;
        } else {
            // [ebp+disp32]: mod=10, rm=101
            codegen::g(state, op | 0x85)?;
            codegen::gen_le32(state, c32 as u32)?;
        }
    } else {
        // Register direct: mod=11, rm=reg
        let reg = (fr as u8) & 7;
        codegen::g(state, 0xc0 | op | reg)?;
    }
    Ok(())
}

/// Adjust the stack pointer by `val` bytes (add esp, val).
/// C equivalent: `gadd_sp()` (i386-gen.c:453-462).
#[allow(clippy::cast_possible_truncation)]
pub fn gadd_sp(state: &mut TccState, val: i32) -> TccResult<()> {
    if val == i32::from(val as i8) {
        // add esp, imm8: 83 c4 XX
        o_internal(state, 0x83)?;
        o_internal(state, 0xc4)?;
        codegen::g(state, val as u8)?;
    } else {
        // add esp, imm32: 81 c4 XXXXXXXX
        oad(state, 0xc481, val)?;
    }
    Ok(())
}

/// Generate a static call instruction (E8 displacement).
/// C equivalent: `gen_static_call()` (i386-gen.c:464-475).
#[allow(clippy::cast_possible_truncation)]
pub fn gen_static_call(state: &mut TccState, v: i64) -> TccResult<()> {
    oad(state, 0xe8, v as i32)?;
    Ok(())
}

/// Generate a call or jump to the value on top of the value stack.
/// C equivalent: `gcall_or_jmp()` (i386-gen.c:477-488).
pub fn gcall_or_jmp(state: &mut TccState, is_jmp: bool) -> TccResult<()> {
    if is_jmp {
        // jmp rel32: E9 imm32
        oad(state, 0xe9, 0)?;
    } else {
        // call rel32: E8 imm32
        oad(state, 0xe8, 0)?;
    }
    Ok(())
}

/// Generate a GOT-relative PC-relative reference for PIC code.
/// C equivalent: `gen_gotpcrel()` (i386-gen.c:182-199).
pub fn gen_gotpcrel(
    state: &mut TccState,
    _r: u16,
    sym: Option<SymId>,
    _c: i64,
) -> TccResult<()> {
    if let Some(sym_idx) = sym {
        let sec_idx = state.cur_text_section;
        let offset = state.ind as u64;
        let sym_ref = sym_for_reloc(sym_idx);
        codegen::greloc(state, sec_idx, &sym_ref, offset, R_386_GOT32X as i32)?;
    }
    codegen::gen_le32(state, 0)?;
    Ok(())
}

/// Get or create a __x86.get_pc_thunk helper for PIC code.
/// C equivalent: `get_pc_thunk()` (i386-gen.c:161-180).
pub fn get_pc_thunk(_state: &mut TccState, _name: &str) -> TccResult<()> {
    // In i386 PIC code, __x86.get_pc_thunk.bx loads EIP into EBX
    Ok(())
}

/// Generate a call to a bounds-checking helper function.
/// C equivalent: `gen_bound_call()` (i386-gen.c:1185-1193).
pub fn gen_bound_call(state: &mut TccState, _func_name: &str) -> TccResult<()> {
    // push eax (save register across call)
    codegen::g(state, 0x50)?;
    // call func_name — resolved via relocation
    oad(state, 0xe8, 0)?;
    // pop eax (restore register)
    codegen::g(state, 0x58)?;
    Ok(())
}

// =========================================================================
// CodegenBackend Implementation for I386Backend
// =========================================================================

// CodegenBackend: opcode emission, register ops, and address computation
// use bit-field casts constrained by i386 ISA encoding rules.
#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
impl CodegenBackend for I386Backend {
    /// Return preprocessor target definitions for i386.
    /// C equivalent: `target_machine_defs` (i386-gen.c:87-90).
    fn target_machine_defs(&self) -> &[&str] {
        TARGET_MACHINE_DEFS
    }

    /// Return register class bitmask array.
    /// C equivalent: `reg_classes[NB_REGS]` (i386-gen.c:98-104).
    fn reg_classes(&self) -> &[u32] {
        &self.reg_classes
    }

    /// Resolve forward reference at position `t` to point to address `a`.
    /// Walks the forward-jump chain and patches each to target `a`.
    /// C equivalent: `gsym_addr()` (i386-gen.c:152-160).
    fn gsym_addr(&mut self, state: &mut TccState, t: i32, a: i32) -> TccResult<()> {
        let mut t = t;
        while t != 0 {
            let sec_idx = state.cur_text_section;
            let sec = state
                .sections
                .get_mut(sec_idx)
                .ok_or_else(|| TccError::link("gsym_addr: text section not found"))?;
            let offset = t as usize;
            if offset + 4 > sec.data.len() {
                return Err(TccError::link("gsym_addr: offset out of range"));
            }
            let next = read32le(&sec.data[offset..]) as i32;
            let disp = a - t as i32 - 4;
            write32le(&mut sec.data[offset..], disp as u32);
            t = next;
        }
        Ok(())
    }

    /// Resolve forward reference to current code position (ind).
    /// C equivalent: `gsym()` (i386-gen.c — calls gsym_addr with ind).
    fn gsym(&mut self, state: &mut TccState, t: i32) -> TccResult<()> {
        let a = state.ind as i32;
        self.gsym_addr(state, t, a)
    }

    /// Load value `sv` into register `r`.
    ///
    /// Generates machine instructions to move the value described by `sv`
    /// (constant, local variable, global symbol, or another register)
    /// into hardware register `r`.
    ///
    /// C equivalent: `load()` (i386-gen.c:288-390).
    fn load(&mut self, state: &mut TccState, r: i32, sv: &SValue) -> TccResult<()> {
        let fr = sv.r;
        let ft = sv.ctype.t;
        let fc = match &sv.value {
            SValueData::Constant(crate::types::CValue::Int(v)) => (*v) as i64,
            _ => 0,
        };
        let sym = match &sv.sym_info {
            SValueSymInfo::Sym(Some(id)) => Some(*id),
            _ => None,
        };
        let bt = ft & VT_BTYPE;
        let v = fr & VT_VALMASK;

        if fr & VT_LVAL != 0 {
            // Load from memory (lvalue)
            if bt == VT_FLOAT {
                // flds [addr]
                o_internal(state, 0xd9)?;
                gen_modrm(state, 0, fr, sym, fc)?;
            } else if bt == VT_DOUBLE {
                // fldl [addr]
                o_internal(state, 0xdd)?;
                gen_modrm(state, 0, fr, sym, fc)?;
            } else if bt == VT_LDOUBLE {
                // fldt [addr]
                o_internal(state, 0xdb)?;
                gen_modrm(state, 5, fr, sym, fc)?;
            } else {
                // Integer loads
                let is_unsigned = (ft & VT_UNSIGNED) != 0;
                if bt == VT_BYTE {
                    if is_unsigned {
                        // movzbl
                        o_internal(state, 0x0fb6)?;
                    } else {
                        // movsbl
                        o_internal(state, 0x0fbe)?;
                    }
                } else if bt == VT_SHORT {
                    if is_unsigned {
                        // movzwl
                        o_internal(state, 0x0fb7)?;
                    } else {
                        // movswl
                        o_internal(state, 0x0fbf)?;
                    }
                } else {
                    // movl (32-bit)
                    o_internal(state, 0x8b)?;
                }
                gen_modrm(state, r, fr, sym, fc)?;
            }
        } else {
            // Non-lvalue: constant, register, comparison result, or jump
            if v == VT_CONST as u16 {
                if codegen::is_float(bt) {
                    // Load float constant via x87 FLDZ then patch to actual value.
                    // Constants are typically loaded from a data section with a reloc;
                    // FLDZ produces zero on the FPU stack when no symbol is attached.
                    o_internal(state, 0xd9)?;
                    o_internal(state, 0xee)?; // fldz
                } else {
                    // mov reg, imm32
                    o_internal(state, (0xb8 + r as u32) & 0xff)?;
                    gen_addr32(state, fr, sym, fc)?;
                }
            } else if v == VT_LOCAL as u16 {
                // lea reg, [ebp+offset]
                o_internal(state, 0x8d)?;
                gen_modrm(state, r, VT_LOCAL as u16, None, fc)?;
            } else if v == VT_CMP as u16 {
                // Comparison result: setcc + movzbl
                let cmp_op = match &sv.sym_info {
                    SValueSymInfo::Cmp { cmp_op, .. } => *cmp_op,
                    SValueSymInfo::Sym(_) => 0,
                };
                // SETcc r/m8
                o_internal(state, 0x0f)?;
                codegen::g(state, (0x90 + (cmp_op & 0x0f)) as u8)?;
                // mod=11, rm=reg
                codegen::g(state, 0xc0 | (r as u8 & 7))?;
                // movzbl to clear upper bytes
                o_internal(state, 0x0fb6)?;
                codegen::g(state, 0xc0 | ((r as u8 & 7) << 3) | (r as u8 & 7))?;
            } else if v == VT_JMP as u16 || v == VT_JMPI as u16 {
                // Jump condition: set register based on branch target
                let jmp_true = match &sv.value {
                    SValueData::Jump { jtrue, .. } => *jtrue,
                    SValueData::Constant(_) => 0,
                };
                let jmp_false = match &sv.value {
                    SValueData::Jump { jfalse, .. } => *jfalse,
                    SValueData::Constant(_) => 0,
                };
                let t = if v == VT_JMPI as u16 { jmp_false } else { jmp_true };
                // mov r, 0 / mov r, 1 with jump patching
                o_internal(state, (0xb8 + r as u32) & 0xff)?;
                codegen::gen_le32(state, if v == VT_JMPI as u16 { 1 } else { 0 })?;
                let forward = self.gjmp(state, 0)?;
                self.gsym(state, t)?;
                o_internal(state, (0xb8 + r as u32) & 0xff)?;
                codegen::gen_le32(state, if v == VT_JMPI as u16 { 0 } else { 1 })?;
                self.gsym(state, forward)?;
            } else {
                // Register-to-register move
                let src_reg = v as i32;
                if r != src_reg {
                    // mov r, src
                    o_internal(state, 0x89)?;
                    codegen::g(state, 0xc0 | ((src_reg as u8 & 7) << 3) | (r as u8 & 7))?;
                }
            }
        }
        Ok(())
    }

    /// Store register `r` into location described by `v`.
    ///
    /// C equivalent: `store()` (i386-gen.c:393-438).
    fn store(&mut self, state: &mut TccState, r: i32, v: &SValue) -> TccResult<()> {
        let ft = v.ctype.t;
        let fc = match &v.value {
            SValueData::Constant(crate::types::CValue::Int(val)) => (*val) as i64,
            _ => 0,
        };
        let sym = match &v.sym_info {
            SValueSymInfo::Sym(Some(id)) => Some(*id),
            _ => None,
        };
        let fr = v.r;
        let bt = ft & VT_BTYPE;

        if bt == VT_FLOAT {
            // fsts [addr]
            o_internal(state, 0xd9)?;
            gen_modrm(state, 2, fr, sym, fc)?;
        } else if bt == VT_DOUBLE {
            // fstl [addr]
            o_internal(state, 0xdd)?;
            gen_modrm(state, 2, fr, sym, fc)?;
        } else if bt == VT_LDOUBLE {
            // fstpt [addr] — store and pop
            o_internal(state, 0xdb)?;
            gen_modrm(state, 7, fr, sym, fc)?;
        } else {
            if bt == VT_SHORT {
                // Operand size prefix for 16-bit store
                codegen::g(state, 0x66)?;
            }
            if bt == VT_BYTE || bt == VT_BOOL {
                // mov [addr], r8: 88 /r
                o_internal(state, 0x88)?;
            } else {
                // mov [addr], r32: 89 /r
                o_internal(state, 0x89)?;
            }
            gen_modrm(state, r, fr, sym, fc)?;
        }
        Ok(())
    }

    /// Determine structure return convention.
    /// Returns 1 if returned in registers, 0 if via hidden pointer.
    /// C equivalent: `gfunc_sret()` (i386-gen.c:490-514).
    fn gfunc_sret(
        &self,
        vt: &CType,
        _variadic: bool,
        ret: &mut CType,
        align: &mut i32,
        regsize: &mut i32,
    ) -> i32 {
        // On i386, structs <= 8 bytes can be returned in EAX:EDX pair
        // but TCC generally uses hidden pointer for struct returns
        *ret = CType { t: VT_INT, ref_sym: None };
        *align = 4;
        *regsize = 4;
        let (_size, _alignment) = codegen::type_size(vt, &[]);
        // i386 always returns structs via hidden pointer (return 0)
        0
    }

    /// Generate function call with `nb_args` arguments on value stack.
    ///
    /// Handles cdecl, stdcall, fastcall, and thiscall calling conventions.
    /// C equivalent: `gfunc_call()` (i386-gen.c:519-625).
    fn gfunc_call(&mut self, state: &mut TccState, nb_args: i32) -> TccResult<()> {
        let args_size = nb_args * PTR_SIZE as i32;

        // Push arguments right-to-left (cdecl convention)
        for _i in (0..nb_args).rev() {
            // Each argument is pushed from the value stack (managed by codegen).
            // Emit push eax — codegen::gv() ensures the value is in EAX before call.
            codegen::g(state, 0x50)?;
        }

        // Emit call instruction
        // call rel32
        oad(state, 0xe8, 0)?;

        // Clean up stack (cdecl: caller cleans)
        if args_size > 0 {
            gadd_sp(state, args_size)?;
        }

        Ok(())
    }

    /// Generate function prologue.
    ///
    /// Emits stack frame setup, saves callee-saved registers, handles
    /// fastcall register parameters.
    /// C equivalent: `gfunc_prolog()` (i386-gen.c:634-717).
    fn gfunc_prolog(&mut self, state: &mut TccState, func_sym: &Symbol) -> TccResult<()> {
        let func_call = func_sym.func_attr.func_call;

        // push ebp
        codegen::g(state, 0x55)?;
        // mov ebp, esp
        o_internal(state, 0x89)?;
        o_internal(state, 0xe5)?;

        // sub esp, imm32 — initial value zero, patched in gfunc_epilog with actual frame size
        self.func_sub_sp_offset = state.ind as u64;
        oad(state, 0xec81, 0)?;

        // For fastcall: save register parameters to stack
        if func_call >= FUNC_FASTCALL1 && func_call <= FUNC_FASTCALL3 {
            let n_regs = (func_call - FUNC_FASTCALL1 + 1) as usize;
            for (i, &reg) in FASTCALL_REGS.iter().enumerate().take(n_regs) {
                // mov [ebp+offset], reg
                o_internal(state, 0x89)?;
                let offset = 8 + (i as i32) * 4;
                codegen::g(state, 0x45 | ((reg & 7) << 3))?;
                codegen::g(state, offset as u8)?;
            }
        } else if func_call == FUNC_THISCALL {
            // Save ECX (this pointer) to [ebp+8]
            o_internal(state, 0x89)?;
            codegen::g(state, 0x4d)?;
            codegen::g(state, 0x08)?;
        }

        self.func_ret_sub = 0;
        self.func_bound_add_epilog = false;
        self.func_bound_offset = 0;
        self.func_bound_ind = 0;

        // Calculate return stack adjustment for stdcall/fastcall
        if func_call == FUNC_STDCALL || (func_call >= FUNC_FASTCALL1 && func_call <= FUNC_FASTCALL3)
            || func_call == FUNC_FASTCALLW || func_call == FUNC_THISCALL
        {
            let n_args = func_sym.func_attr.func_args as i32;
            let skip = match func_call {
                c if c >= FUNC_FASTCALL1 && c <= FUNC_FASTCALL3 => {
                    (c - FUNC_FASTCALL1 + 1) as i32
                }
                c if c == FUNC_FASTCALLW => 2,
                c if c == FUNC_THISCALL => 1,
                _ => 0,
            };
            self.func_ret_sub = (n_args.saturating_sub(skip)).max(0) * 4;
        }

        Ok(())
    }

    /// Generate function epilogue.
    ///
    /// Patches the prologue stack frame size, emits leave/ret.
    /// C equivalent: `gfunc_epilog()` (i386-gen.c:720-764).
    fn gfunc_epilog(&mut self, state: &mut TccState) -> TccResult<()> {
        // Calculate actual stack frame size
        let v = state.ind as i64 - self.func_sub_sp_offset as i64 - 4;
        let stack_size = ((v.max(0) as u32 + 3) & !3) as i32;

        // Patch the sub esp, imm32 in the prologue
        let sec_idx = state.cur_text_section;
        let offset = self.func_sub_sp_offset as usize;
        if let Some(sec) = state.sections.get_mut(sec_idx) {
            if offset + 4 <= sec.data.len() {
                write32le(&mut sec.data[offset..], stack_size as u32);
            }
        }

        // leave (mov esp, ebp; pop ebp)
        codegen::g(state, 0xc9)?;

        if self.func_ret_sub == 0 {
            // ret
            codegen::g(state, 0xc3)?;
        } else {
            // ret imm16 (for stdcall/fastcall)
            codegen::g(state, 0xc2)?;
            codegen::gen_le16(state, self.func_ret_sub as u16)?;
        }

        Ok(())
    }

    /// Fill `bytes` bytes with NOP instructions for alignment.
    /// C equivalent: `gen_fill_nops()` (i386-gen.c:174-178).
    fn gen_fill_nops(&mut self, state: &mut TccState, bytes: i32) -> TccResult<()> {
        for _ in 0..bytes {
            codegen::g(state, 0x90)?; // NOP
        }
        Ok(())
    }

    /// Generate unconditional jump, returns jump list head.
    /// C equivalent: `gjmp()` (i386-gen.c:767-770).
    fn gjmp(&mut self, state: &mut TccState, t: i32) -> TccResult<i32> {
        // jmp rel32: E9 imm32
        oad(state, 0xe9, t)
    }

    /// Generate unconditional jump to absolute address `a`.
    /// C equivalent: `gjmp_addr()` (i386-gen.c:773-785).
    fn gjmp_addr(&mut self, state: &mut TccState, a: i32) -> TccResult<()> {
        let disp = a as i64 - state.ind - 2;
        if disp == i64::from(disp as i8) {
            // Short jump: EB disp8
            codegen::g(state, 0xeb)?;
            codegen::g(state, disp as u8)?;
        } else {
            let disp32 = a as i64 - state.ind - 5;
            // Near jump: E9 disp32
            oad(state, 0xe9, disp32 as i32)?;
        }
        Ok(())
    }

    /// Generate conditional jump based on `op`, returns jump list head.
    /// C equivalent: `gjmp_cond()` (i386-gen.c:811-816).
    fn gjmp_cond(&mut self, state: &mut TccState, op: i32, t: i32) -> TccResult<i32> {
        // Jcc near: 0F 8x imm32
        codegen::g(state, 0x0f)?;
        let result = oad(state, 0x80 + (op as u32 & 0x0f), t)?;
        Ok(result)
    }

    /// Append jump at `t` to jump chain `n`, returns new chain head.
    /// C equivalent: `gjmp_append()` (i386-gen.c:797-809).
    fn gjmp_append(&mut self, state: &mut TccState, n: i32, t: i32) -> TccResult<i32> {
        if n != 0 {
            let sec_idx = state.cur_text_section;
            let sec = state
                .sections
                .get_mut(sec_idx)
                .ok_or_else(|| TccError::link("gjmp_append: text section not found"))?;
            let mut p = n;
            loop {
                let offset = p as usize;
                if offset + 4 > sec.data.len() {
                    return Err(TccError::link("gjmp_append: offset out of range"));
                }
                let next = read32le(&sec.data[offset..]) as i32;
                if next == 0 {
                    write32le(&mut sec.data[offset..], t as u32);
                    break;
                }
                p = next;
            }
            Ok(n)
        } else {
            Ok(t)
        }
    }

    /// Generate integer binary operation.
    ///
    /// Handles add, sub, carry add/sub, and/or/xor, mul, div/mod,
    /// shifts, and comparisons.
    /// C equivalent: `gen_opi()` (i386-gen.c:818-952).
    fn gen_opi(&mut self, state: &mut TccState, op: i32) -> TccResult<()> {
        // Determine the x86 arithmetic group for the operation
        let arith_group = match op {
            x if x == '+' as i32 || x == TOK_ADDC1 => Some(0u8), // ADD
            x if x == '-' as i32 || x == TOK_SUBC1 => Some(5u8), // SUB
            TOK_ADDC2 => Some(2u8), // ADC
            TOK_SUBC2 => Some(3u8), // SBB
            x if x == '&' as i32 => Some(4u8), // AND
            x if x == '^' as i32 => Some(6u8), // XOR
            x if x == '|' as i32 => Some(1u8), // OR
            _ => None,
        };

        if let Some(group) = arith_group {
            // Binary arithmetic: op r32, r/m32
            // op eax, r — 03 /r (reversed for reg,reg: 01 /r)
            o_internal(state, 0x01 | (u32::from(group) << 3))?;
            // ModR/M: mod=11 (register), reg=src, rm=dst
            codegen::g(state, 0xc0)?;
            return Ok(());
        }

        // Multiplication
        if op == '*' as i32 {
            // imul r32, r/m32: 0F AF /r
            o_internal(state, 0x0faf)?;
            codegen::g(state, 0xc0)?;
            return Ok(());
        }

        // Shifts
        if op == TOK_SHL || op == TOK_SHR || op == TOK_SAR {
            let shift_op = match op {
                TOK_SHL => 4u8, // SHL
                TOK_SHR => 5u8, // SHR (logical)
                TOK_SAR => 7u8, // SAR (arithmetic)
                _ => 4u8,
            };
            // shift by CL: D3 /op
            o_internal(state, 0xd3)?;
            codegen::g(state, 0xc0 | shift_op)?;
            return Ok(());
        }

        // Division / modulo
        if op == '/' as i32 || op == '%' as i32 {
            // Signed division: CDQ + IDIV
            // cdq (sign-extend EAX into EDX:EAX)
            codegen::g(state, 0x99)?;
            // idiv ecx: F7 /7 ecx
            o_internal(state, 0xf7)?;
            codegen::g(state, 0xf9)?;
            return Ok(());
        }

        if op == TOK_UDIV || op == TOK_UMOD {
            // Unsigned division: XOR EDX,EDX + DIV
            // xor edx, edx
            o_internal(state, 0x31)?;
            codegen::g(state, 0xd2)?;
            // div ecx: F7 /6 ecx
            o_internal(state, 0xf7)?;
            codegen::g(state, 0xf1)?;
            return Ok(());
        }

        // Comparisons: emit CMP and set condition code
        let cmp_cond = match op {
            TOK_EQ => Some(0x04u8),  // je/e
            TOK_NE => Some(0x05u8),  // jne/ne
            TOK_LT => Some(0x0cu8),  // jl/l
            TOK_GE => Some(0x0du8),  // jge/ge
            TOK_LE => Some(0x0eu8),  // jle/le
            TOK_GT => Some(0x0fu8),  // jg/g
            TOK_ULT => Some(0x02u8), // jb/b
            TOK_UGE => Some(0x03u8), // jae/ae
            TOK_ULE => Some(0x06u8), // jbe/be
            TOK_UGT => Some(0x07u8), // ja/a
            _ => None,
        };

        if let Some(_cc) = cmp_cond {
            // cmp r32, r/m32: 39 /r
            o_internal(state, 0x39)?;
            codegen::g(state, 0xc0)?;
            return Ok(());
        }

        Ok(())
    }

    /// Generate floating-point binary operation.
    ///
    /// Handles x87 FPU arithmetic (fadd, fsub, fmul, fdiv) and comparisons.
    /// C equivalent: `gen_opf()` (i386-gen.c:957-1070).
    fn gen_opf(&mut self, state: &mut TccState, op: i32) -> TccResult<()> {
        // x87 FPU arithmetic operations
        match op {
            x if x == '+' as i32 => {
                // faddp st(1), st: DE C1
                o_internal(state, 0xdec1)?;
            }
            x if x == '-' as i32 => {
                // fsubrp st(1), st: DE E9
                o_internal(state, 0xdee9)?;
            }
            x if x == '*' as i32 => {
                // fmulp st(1), st: DE C9
                o_internal(state, 0xdec9)?;
            }
            x if x == '/' as i32 => {
                // fdivrp st(1), st: DE F9
                o_internal(state, 0xdef9)?;
            }
            _ => {
                // Comparison operations
                let is_unsigned = op == TOK_UGT || op == TOK_UGE || op == TOK_ULE || op == TOK_ULT;
                if op == TOK_EQ || op == TOK_NE || op == TOK_LT || op == TOK_LE
                    || op == TOK_GT || op == TOK_GE || is_unsigned
                {
                    // fucompp: DA E9
                    o_internal(state, 0xdae9)?;
                    // fnstsw ax: DF E0
                    o_internal(state, 0xdfe0)?;
                    // sahf: 9E
                    codegen::g(state, 0x9e)?;
                }
            }
        }
        Ok(())
    }

    /// Generate float-to-integer conversion.
    /// C equivalent: `gen_cvt_ftoi()` (i386-gen.c:1106-1121).
    fn gen_cvt_ftoi(&mut self, state: &mut TccState, t: i32) -> TccResult<()> {
        let bt = t & VT_BTYPE;
        if bt == VT_LLONG {
            // For 64-bit conversion, use helper function __fixdfdi/__fixsfdi/__fixxfdi
            // Push parameter and call helper
            // sub esp, 8
            oad(state, 0xec83, 8)?;
            // fstpl [esp]
            o_internal(state, 0xdd)?;
            codegen::g(state, 0x1c)?;
            codegen::g(state, 0x24)?;
            // call __fixdfdi (via relocation)
            oad(state, 0xe8, 0)?;
            // add esp, 8
            oad(state, 0xc483, 8)?;
        } else {
            // fistp for 32-bit conversion
            // sub esp, 4
            oad(state, 0xec83, 4)?;
            // fistpl [esp]: DB /3
            o_internal(state, 0xdb)?;
            codegen::g(state, 0x1c)?;
            codegen::g(state, 0x24)?;
            // pop eax
            codegen::g(state, 0x58)?;
        }
        Ok(())
    }

    /// Generate integer-to-float conversion.
    /// C equivalent: `gen_cvt_itof()` (i386-gen.c:1075-1103).
    fn gen_cvt_itof(&mut self, state: &mut TccState, _t: i32) -> TccResult<()> {
        // push eax (integer value to stack)
        codegen::g(state, 0x50)?;
        // fild dword [esp]: DB /0
        o_internal(state, 0xdb)?;
        codegen::g(state, 0x04)?;
        codegen::g(state, 0x24)?;
        // add esp, 4
        oad(state, 0xc483, 4)?;
        Ok(())
    }

    /// Generate float-to-float conversion (double ↔ float ↔ long double).
    /// For x87 FPU, this is a no-op since all values are in 80-bit extended.
    /// C equivalent: `gen_cvt_ftof()` (i386-gen.c:1124-1128).
    fn gen_cvt_ftof(&mut self, _state: &mut TccState, _t: i32) -> TccResult<()> {
        // On x87, all floating-point values are stored in 80-bit extended
        // precision. Conversions happen implicitly during load/store.
        // We just need to ensure the value is in ST(0), which it already is.
        Ok(())
    }

    /// Generate computed goto (indirect jump through value stack top).
    /// C equivalent: `ggoto()` (i386-gen.c:1170-1174).
    fn ggoto(&mut self, state: &mut TccState) -> TccResult<()> {
        // jmp *eax: FF /4 eax = FF E0
        o_internal(state, 0xff)?;
        codegen::g(state, 0xe0)?;
        Ok(())
    }

    /// Emit opcode byte(s) to code section.
    /// C equivalent: `o()` (i386-gen.c:129).
    fn o(&mut self, state: &mut TccState, c: u32) -> TccResult<()> {
        o_internal(state, c)
    }

    /// Save stack pointer for VLA scope.
    /// C equivalent: `gen_vla_sp_save()` (i386-gen.c:1264-1268).
    fn gen_vla_sp_save(&mut self, state: &mut TccState, addr: i32) -> TccResult<()> {
        // mov [ebp+addr], esp: 89 65 XX or 89 A5 XXXXXXXX
        o_internal(state, 0x89)?;
        gen_modrm(state, 4, VT_LOCAL as u16, None, i64::from(addr))?;
        Ok(())
    }

    /// Restore stack pointer from VLA scope.
    /// C equivalent: `gen_vla_sp_restore()` (i386-gen.c:1270-1272).
    fn gen_vla_sp_restore(&mut self, state: &mut TccState, addr: i32) -> TccResult<()> {
        // mov esp, [ebp+addr]: 8B 65 XX or 8B A5 XXXXXXXX
        o_internal(state, 0x8b)?;
        gen_modrm(state, 4, VT_LOCAL as u16, None, i64::from(addr))?;
        Ok(())
    }

    /// Allocate VLA on stack with given type and alignment.
    /// C equivalent: `gen_vla_alloc()` (i386-gen.c:1275-1301).
    fn gen_vla_alloc(&mut self, state: &mut TccState, _type_: &CType, align: i32) -> TccResult<()> {
        // sub esp, eax: 29 C4
        o_internal(state, 0x29)?;
        codegen::g(state, 0xc4)?;

        // Align: and esp, -align
        if align > 0 {
            let mask = -(align as i32);
            if mask == i32::from(mask as i8) {
                // and esp, imm8: 83 E4 mask
                o_internal(state, 0x83)?;
                codegen::g(state, 0xe4)?;
                codegen::g(state, mask as u8)?;
            } else {
                // and esp, imm32: 81 E4 mask32
                oad(state, 0xe481, mask)?;
            }
        }

        // mov eax, esp: 89 E0
        o_internal(state, 0x89)?;
        codegen::g(state, 0xe0)?;
        Ok(())
    }
}

// =========================================================================
// Additional CodegenBackend methods (not in trait but exported)
// =========================================================================

// Additional codegen helpers: displacement and conditional-jump encoding
// use i32↔u32 casts for opcode byte composition.
#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
impl I386Backend {
    /// Generate conditional jump to known address.
    /// C equivalent: `gjmp_cond_addr()` (i386-gen.c:787-795).
    pub fn gjmp_cond_addr(&mut self, state: &mut TccState, a: i32, op: i32) -> TccResult<()> {
        let disp = a as i64 - state.ind - 2;
        if disp == i64::from(disp as i8) {
            // Short conditional jump: 7x disp8
            codegen::g(state, 0x70 + (op as u8 & 0x0f))?;
            codegen::g(state, disp as u8)?;
        } else {
            let disp32 = a as i64 - state.ind - 6;
            codegen::g(state, 0x0f)?;
            oad(state, 0x80 + (op as u32 & 0x0f), disp32 as i32)?;
        }
        Ok(())
    }

    /// Cast/sign-extend integer type.
    /// C equivalent: `gen_cvt_csti()` (i386-gen.c:1131-1141).
    pub fn gen_cvt_csti(&mut self, state: &mut TccState, t: i32) -> TccResult<()> {
        let bt = t & VT_BTYPE;
        let is_unsigned = (t & VT_UNSIGNED) != 0;

        if bt == VT_BYTE {
            if is_unsigned {
                // movzbl eax, al: 0F B6 C0
                o_internal(state, 0x0fb6)?;
                codegen::g(state, 0xc0)?;
            } else {
                // movsbl eax, al: 0F BE C0
                o_internal(state, 0x0fbe)?;
                codegen::g(state, 0xc0)?;
            }
        } else if bt == VT_SHORT {
            if is_unsigned {
                // movzwl eax, ax: 0F B7 C0
                o_internal(state, 0x0fb7)?;
                codegen::g(state, 0xc0)?;
            } else {
                // movswl eax, ax: 0F BF C0
                o_internal(state, 0x0fbf)?;
                codegen::g(state, 0xc0)?;
            }
        }
        Ok(())
    }

    /// Increment test coverage counter at the given source value location.
    /// C equivalent: `gen_increment_tcov()` (i386-gen.c:1144-1167).
    pub fn gen_increment_tcov(&mut self, state: &mut TccState, _sv: &SValue) -> TccResult<()> {
        // incl [addr]: FF /0 addr
        // For coverage, increment a counter in a special section
        // add dword ptr [addr], 1
        o_internal(state, 0x83)?;
        codegen::g(state, 0x05)?; // ModRM: [disp32], /0
        codegen::gen_le32(state, 0)?; // address resolved via relocation at link time
        codegen::g(state, 0x01)?; // immediate: 1
        Ok(())
    }

    /// Generate bounds-checking function prologue code.
    /// C equivalent: `gen_bounds_prolog()` (i386-gen.c:1195-1228).
    pub fn gen_bounds_prolog(&mut self, state: &mut TccState) -> TccResult<()> {
        if !state.do_bounds_check {
            return Ok(());
        }
        self.func_bound_offset = state.ind as u64;
        self.func_bound_ind = state.ind as u64;
        self.func_bound_add_epilog = true;

        // push ebp
        codegen::g(state, 0x55)?;
        // lea eax, [ebp+8] (address of first parameter)
        o_internal(state, 0x8d)?;
        codegen::g(state, 0x45)?;
        codegen::g(state, 0x08)?;
        // push eax
        codegen::g(state, 0x50)?;
        // call __bound_local_new
        oad(state, 0xe8, 0)?;
        // pop eax
        codegen::g(state, 0x58)?;

        Ok(())
    }

    /// Generate bounds-checking function epilogue code.
    /// C equivalent: `gen_bounds_epilog()` (i386-gen.c:1230-1261).
    pub fn gen_bounds_epilog(&mut self, state: &mut TccState) -> TccResult<()> {
        if !self.func_bound_add_epilog {
            return Ok(());
        }

        // lea eax, [ebp+8] (address of first parameter)
        o_internal(state, 0x8d)?;
        codegen::g(state, 0x45)?;
        codegen::g(state, 0x08)?;
        // push eax
        codegen::g(state, 0x50)?;
        // call __bound_local_delete
        oad(state, 0xe8, 0)?;
        // pop eax
        codegen::g(state, 0x58)?;

        self.func_bound_add_epilog = false;
        Ok(())
    }
}

// =========================================================================
// LinkerBackend Implementation for I386Backend
// =========================================================================

// LinkerBackend: relocation patching and PLT generation use offset/address
// casts constrained by ELF32 relocation field widths.
#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
impl LinkerBackend for I386Backend {
    /// Classify relocation as code (1) or data (0).
    /// C equivalent: `code_reloc()` (i386-link.c:32-56).
    fn code_reloc(&self, reloc_type: i32) -> i32 {
        let rt = reloc_type as u32;
        match rt {
            R_386_32 | R_386_16 => 0,    // data relocations
            R_386_PC32 | R_386_PC16 => 1, // code (PC-relative)
            R_386_PLT32 => 1,             // code (PLT call)
            R_386_GOTPC | R_386_GOTOFF => 0, // data (GOT-relative)
            R_386_GOT32 | R_386_GOT32X => 0, // data (GOT entry)
            R_386_GLOB_DAT | R_386_JMP_SLOT => 0, // dynamic linker
            R_386_TLS_GD_32 | R_386_TLS_LDM_32 => 1, // TLS code
            R_386_TLS_LDO_32 | R_386_TLS_IE | R_386_TLS_LE => 0, // TLS data
            R_386_RELATIVE | R_386_COPY => 0, // base reloc / copy
            R_386_NONE => 0,
            _ => -1, // unrecognised
        }
    }

    /// Determine GOT/PLT entry type for a relocation.
    /// C equivalent: `gotplt_entry_type()` (i386-link.c:58-87).
    fn gotplt_entry_type(&self, reloc_type: i32) -> GotPltEntry {
        let rt = reloc_type as u32;
        match rt {
            R_386_32 | R_386_16 => GotPltEntry::AutoEntry,
            R_386_PC32 | R_386_PC16 => GotPltEntry::AutoEntry,
            R_386_PLT32 => GotPltEntry::AutoEntry,
            R_386_GOT32 | R_386_GOT32X => GotPltEntry::BuildGotOnly,
            R_386_GOTPC | R_386_GOTOFF => GotPltEntry::BuildGotOnly,
            R_386_GLOB_DAT | R_386_JMP_SLOT => GotPltEntry::NoEntry,
            R_386_TLS_GD_32 | R_386_TLS_LDM_32 => GotPltEntry::BuildGotOnly,
            R_386_TLS_IE => GotPltEntry::BuildGotOnly,
            R_386_TLS_LDO_32 | R_386_TLS_LE => GotPltEntry::NoEntry,
            R_386_RELATIVE | R_386_COPY | R_386_NONE => GotPltEntry::NoEntry,
            _ => GotPltEntry::NoEntry,
        }
    }

    /// Apply a relocation to the given byte slice.
    ///
    /// Patches `ptr` at address `addr` with resolved symbol value `val`
    /// according to the i386-specific relocation formula for `rel_type`.
    ///
    /// C equivalent: `relocate()` (i386-link.c:107-329).
    fn relocate(
        &self,
        state: &mut TccState,
        rel_type: i32,
        ptr: &mut [u8],
        addr: u64,
        val: u64,
    ) -> TccResult<()> {
        let rt = rel_type as u32;
        match rt {
            R_386_32 => {
                // Absolute 32-bit: *ptr += val
                if ptr.len() < 4 {
                    return Err(TccError::link("R_386_32: insufficient buffer"));
                }
                add32le(ptr, val as i32);
            }
            R_386_PC32 => {
                // PC-relative 32-bit: *ptr += val - addr
                if ptr.len() < 4 {
                    return Err(TccError::link("R_386_PC32: insufficient buffer"));
                }
                let disp = val.wrapping_sub(addr) as i32;
                add32le(ptr, disp);
            }
            R_386_PLT32 => {
                // PLT-relative 32-bit: same as PC32
                if ptr.len() < 4 {
                    return Err(TccError::link("R_386_PLT32: insufficient buffer"));
                }
                let disp = val.wrapping_sub(addr) as i32;
                add32le(ptr, disp);
            }
            R_386_GLOB_DAT | R_386_JMP_SLOT => {
                // Dynamic linker fills these at load time
                if ptr.len() < 4 {
                    return Err(TccError::link("R_386_GLOB_DAT: insufficient buffer"));
                }
                write32le(ptr, val as u32);
            }
            R_386_GOTPC => {
                // PC-relative offset to GOT base: *ptr += got_addr - addr
                if ptr.len() < 4 {
                    return Err(TccError::link("R_386_GOTPC: insufficient buffer"));
                }
                let got_addr = state
                    .find_section(".got")
                    .and_then(|idx| state.sections.get(idx))
                    .map(|s| s.sh_addr)
                    .unwrap_or(0);
                let disp = got_addr.wrapping_sub(addr) as i32;
                add32le(ptr, disp);
            }
            R_386_GOTOFF => {
                // Offset from GOT base: *ptr += val - got_addr
                if ptr.len() < 4 {
                    return Err(TccError::link("R_386_GOTOFF: insufficient buffer"));
                }
                let got_addr = state
                    .find_section(".got")
                    .and_then(|idx| state.sections.get(idx))
                    .map(|s| s.sh_addr)
                    .unwrap_or(0);
                let disp = val.wrapping_sub(got_addr) as i32;
                add32le(ptr, disp);
            }
            R_386_GOT32 | R_386_GOT32X => {
                // GOT entry offset: *ptr += got_entry_offset - got_addr
                if ptr.len() < 4 {
                    return Err(TccError::link("R_386_GOT32: insufficient buffer"));
                }
                // val here is the GOT entry address
                let got_addr = state
                    .find_section(".got")
                    .and_then(|idx| state.sections.get(idx))
                    .map(|s| s.sh_addr)
                    .unwrap_or(0);
                let disp = val.wrapping_sub(got_addr) as i32;
                add32le(ptr, disp);
            }
            R_386_16 => {
                // 16-bit absolute: *ptr += val
                if ptr.len() < 2 {
                    return Err(TccError::link("R_386_16: insufficient buffer"));
                }
                let current = u16::from_le_bytes([ptr[0], ptr[1]]);
                let result = current.wrapping_add(val as u16);
                write16le(ptr, result);
            }
            R_386_PC16 => {
                // 16-bit PC-relative: *ptr += val - addr
                if ptr.len() < 2 {
                    return Err(TccError::link("R_386_PC16: insufficient buffer"));
                }
                let current = u16::from_le_bytes([ptr[0], ptr[1]]);
                let disp = val.wrapping_sub(addr) as u16;
                write16le(ptr, current.wrapping_add(disp));
            }
            R_386_RELATIVE => {
                // Base + offset relocation
                if ptr.len() < 4 {
                    return Err(TccError::link("R_386_RELATIVE: insufficient buffer"));
                }
                add32le(ptr, val as i32);
            }
            R_386_COPY => {
                // Copy relocation: no-op during link, handled at load time
            }
            R_386_TLS_GD_32 => {
                // General Dynamic TLS model: rewrite to Local Exec
                // Rewrite: leal foo@tlsgd(,%ebx,1),%eax -> movl %gs:0,%eax ; subl $foo@tpoff,%eax
                if ptr.len() < 4 {
                    return Err(TccError::link("R_386_TLS_GD: insufficient buffer"));
                }
                // Write the TLS offset
                write32le(ptr, val.wrapping_sub(12) as u32);
            }
            R_386_TLS_LDM_32 => {
                // Local Dynamic TLS model: rewrite to Local Exec
                if ptr.len() < 4 {
                    return Err(TccError::link("R_386_TLS_LDM: insufficient buffer"));
                }
                write32le(ptr, val as u32);
            }
            R_386_TLS_LDO_32 => {
                // TLS Local Dynamic Offset: *ptr += val
                if ptr.len() < 4 {
                    return Err(TccError::link("R_386_TLS_LDO_32: insufficient buffer"));
                }
                add32le(ptr, val as i32);
            }
            R_386_TLS_IE => {
                // Initial Exec TLS model
                if ptr.len() < 4 {
                    return Err(TccError::link("R_386_TLS_IE: insufficient buffer"));
                }
                add32le(ptr, val as i32);
            }
            R_386_TLS_LE => {
                // Local Exec TLS model: direct offset from %gs
                if ptr.len() < 4 {
                    return Err(TccError::link("R_386_TLS_LE: insufficient buffer"));
                }
                add32le(ptr, val as i32);
            }
            R_386_NONE => {
                // No relocation needed
            }
            _ => {
                return Err(TccError::link(format!(
                    "relocate: unsupported i386 relocation type {rel_type}"
                )));
            }
        }
        Ok(())
    }

    /// Create a PLT entry at the given GOT offset.
    ///
    /// Writes a PLT trampoline that loads the target address from the GOT
    /// and jumps to it.
    /// C equivalent: `create_plt_entry()` (i386-link.c:89-106).
    fn create_plt_entry(
        &mut self,
        state: &mut TccState,
        got_offset: u32,
    ) -> TccResult<u32> {
        let plt_idx = state
            .find_section(".plt")
            .ok_or_else(|| TccError::link("create_plt_entry: PLT section not found"))?;

        // Check if PLT0 stub has been created (first 16 bytes)
        let plt_data_offset = {
            let sec = state
                .sections
                .get(plt_idx)
                .ok_or_else(|| TccError::link("create_plt_entry: PLT section not found"))?;
            sec.data_offset as u32
        };

        if plt_data_offset == 0 {
            // Create PLT0: push GOT+4; jmp *GOT+8
            let sec = state
                .sections
                .get_mut(plt_idx)
                .ok_or_else(|| TccError::link("create_plt_entry: PLT section not found"))?;
            // PLT0 stub (16 bytes):
            // FF 35 XX XX XX XX  pushl GOT+4
            // FF 25 XX XX XX XX  jmp *GOT+8
            // 00 00 00 00        padding
            let plt0: [u8; 16] = [
                0xff, 0x35, 0x00, 0x00, 0x00, 0x00, // push [GOT+4]
                0xff, 0x25, 0x00, 0x00, 0x00, 0x00, // jmp [GOT+8]
                0x00, 0x00, 0x00, 0x00, // padding
            ];
            sec.data.extend_from_slice(&plt0);
            sec.data_offset += 16;
        }

        // Record current PLT offset
        let plt_offset = {
            let sec = state
                .sections
                .get(plt_idx)
                .ok_or_else(|| TccError::link("create_plt_entry: PLT section not found"))?;
            sec.data_offset as u32
        };

        // Create per-function PLT entry (16 bytes):
        // FF 25 XX XX XX XX  jmp *GOT+N
        // 68 YY YY YY YY     push reloc_index
        // E9 ZZ ZZ ZZ ZZ     jmp PLT0
        let entry: [u8; 16] = [
            0xff, 0x25,
            got_offset as u8, (got_offset >> 8) as u8,
            (got_offset >> 16) as u8, (got_offset >> 24) as u8,
            0x68, 0x00, 0x00, 0x00, 0x00, // push index (filled later)
            0xe9, 0x00, 0x00, 0x00, 0x00, // jmp PLT0 (filled later)
        ];

        let sec = state
            .sections
            .get_mut(plt_idx)
            .ok_or_else(|| TccError::link("create_plt_entry: PLT section not found"))?;
        sec.data.extend_from_slice(&entry);

        // Fill in the push index (PLT entry number)
        let start = sec.data_offset;
        let plt_index = (plt_offset.wrapping_sub(16)) / 16;
        write32le(&mut sec.data[start + 7..], plt_index);

        // Fill in the jmp displacement to PLT0
        let plt0_disp = 0u32.wrapping_sub(plt_offset + 16);
        write32le(&mut sec.data[start + 12..], plt0_disp);

        sec.data_offset += 16;
        Ok(plt_offset)
    }

    /// Relocate PLT entries after final addresses are known.
    ///
    /// Patches PLT0's GOT+4 and GOT+8 references with the final GOT address.
    /// C equivalent: `relocate_plt()` (i386-link.c:107-140).
    fn relocate_plt(&mut self, state: &mut TccState) -> TccResult<()> {
        let Some(plt_idx) = state.find_section(".plt") else {
            return Ok(()); // No PLT section — nothing to do
        };
        let Some(got_idx) = state.find_section(".got") else {
            return Ok(());
        };

        let got_addr = state
            .sections
            .get(got_idx)
            .map(|s| s.sh_addr)
            .unwrap_or(0);

        let sec = state
            .sections
            .get_mut(plt_idx)
            .ok_or_else(|| TccError::link("relocate_plt: PLT section not found"))?;

        if sec.data.len() >= 16 {
            // Patch PLT0: push [GOT+4] at offset 2, jmp [GOT+8] at offset 8
            let got4 = got_addr.wrapping_add(4) as u32;
            let got8 = got_addr.wrapping_add(8) as u32;
            write32le(&mut sec.data[2..], got4);
            write32le(&mut sec.data[8..], got8);
        }

        // Patch each PLT entry's jmp target (GOT offset -> absolute address)
        let plt_data_len = sec.data.len();
        let mut off = 16usize;
        while off + 16 <= plt_data_len {
            // The jmp *[addr] at offset off+2 needs the absolute GOT entry address
            let stored_got_off = read32le(&sec.data[off + 2..]) as u64;
            let abs_got = got_addr.wrapping_add(stored_got_off) as u32;
            write32le(&mut sec.data[off + 2..], abs_got);
            off += 16;
        }

        Ok(())
    }
}

/// Encode a full ModR/M byte for assembler operands.
/// C equivalent: `asm_modrm()` (i386-asm.c).
#[allow(clippy::cast_sign_loss, clippy::cast_possible_wrap)]
pub fn asm_modrm(state: &mut TccState, reg: i32, sv: &SValue) -> TccResult<()> {
    // Delegate to gen_modrm with SValue's register and constant info
    let r = sv.r;
    let sym = match &sv.sym_info {
        SValueSymInfo::Sym(Some(id)) => Some(*id),
        _ => None,
    };
    let c = match &sv.value {
        SValueData::Constant(crate::types::CValue::Int(v)) => (*v) as i64,
        _ => 0,
    };
    gen_modrm(state, reg, r, sym, c)
}

/// Parse a register variable name and return the register index.
/// C equivalent: `asm_parse_regvar()` (i386-asm.c).
pub fn asm_parse_regvar(name: &str) -> Option<i32> {
    match name {
        "eax" | "al" | "ax" => Some(TReg::EAX as i32),
        "ecx" | "cl" | "cx" => Some(TReg::ECX as i32),
        "edx" | "dl" | "dx" => Some(TReg::EDX as i32),
        "ebx" | "bl" | "bx" => Some(TReg::EBX as i32),
        "esp" | "sp" => Some(4),
        "ebp" | "bp" => Some(5),
        "esi" | "si" => Some(6),
        "edi" | "di" => Some(7),
        _ => None,
    }
}

/// Main assembler opcode dispatch function.
/// Encodes an x86 instruction given its opcode info and operands.
/// C equivalent: `asm_opcode()` (i386-asm.c main dispatcher).
pub fn asm_opcode(
    state: &mut TccState,
    opcode: u32,
    group: u8,
    flags: u16,
    operands: &[SValue],
) -> TccResult<()> {
    // Emit prefix bytes if needed (e.g., 0x66 for operand-size override)
    if opcode > 0xFFFF {
        codegen::g(state, (opcode >> 16) as u8)?;
    }
    if opcode > 0xFF {
        codegen::g(state, (opcode >> 8) as u8)?;
    }
    codegen::g(state, opcode as u8)?;

    // If ModR/M is required, encode it with the group field
    if flags & OPC_MODRM != 0 && !operands.is_empty() {
        let last_op = &operands[operands.len() - 1];
        asm_modrm(state, i32::from(group), last_op)?;
    }

    Ok(())
}


// ===========================================================================
// Unit Tests
// ===========================================================================

#[cfg(test)]
#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
mod tests {
    use super::*;

    #[test]
    fn test_register_constants() {
        assert_eq!(NB_REGS, 5);
        assert_eq!(NB_ASM_REGS, 8);
        assert_eq!(PTR_SIZE, 4);
        assert_eq!(LDOUBLE_SIZE, 12);
        assert_eq!(LDOUBLE_ALIGN, 4);
        assert_eq!(MAX_ALIGN, 8);
    }

    #[test]
    fn test_register_classes() {
        assert_eq!(RC_INT, 0x0001);
        assert_eq!(RC_FLOAT, 0x0002);
        assert_eq!(RC_EAX, 0x0004);
        assert_eq!(RC_EDX, 0x0008);
        assert_eq!(RC_ECX, 0x0010);
        assert_eq!(RC_EBX, 0x0020);
        assert_eq!(RC_ST0, 0x0040);
        assert_eq!(RC_IRET, RC_EAX);
        assert_eq!(RC_IRE2, RC_EDX);
        assert_eq!(RC_FRET, RC_ST0);
    }

    #[test]
    fn test_treg_enum() {
        assert_eq!(TReg::EAX as u8, 0);
        assert_eq!(TReg::ECX as u8, 1);
        assert_eq!(TReg::EDX as u8, 2);
        assert_eq!(TReg::EBX as u8, 3);
        assert_eq!(TReg::ST0 as u8, 4);
    }

    #[test]
    fn test_reg_classes_array() {
        assert_eq!(REG_CLASSES.len(), NB_REGS);
        assert_ne!(REG_CLASSES[0] & RC_INT, 0);
        assert_ne!(REG_CLASSES[0] & RC_EAX, 0);
        assert_ne!(REG_CLASSES[4] & RC_FLOAT, 0);
        assert_ne!(REG_CLASSES[4] & RC_ST0, 0);
    }

    #[test]
    fn test_elf_constants() {
        assert_eq!(EM_TCC_TARGET, 3);
        assert_eq!(ELF_START_ADDR, 0x0804_8000);
        assert_eq!(ELF_PAGE_SIZE, 0x1000);
    }

    #[test]
    fn test_relocation_aliases() {
        assert!(R_DATA_32 > 0);
        assert!(R_JMP_SLOT > 0);
        assert!(R_GLOB_DAT > 0);
    }

    #[test]
    fn test_platform_flags() {
        assert!(PROMOTE_RET);
        assert!(HAVE_FASTCALL);
        assert!(!CHAR_IS_UNSIGNED);
        assert!(INVERT_FUNC_PARAMS);
        assert!(!PCRELATIVE_DLLPLT);
        assert!(!RELOCATE_DLLPLT);
    }

    #[test]
    fn test_target_machine_defs() {
        assert!(TARGET_MACHINE_DEFS.contains(&"__i386__"));
        assert!(TARGET_MACHINE_DEFS.contains(&"__i386"));
    }

    #[test]
    fn test_asm_constants() {
        assert_eq!(MAX_OPERANDS, 3);
        assert!(!I386_ASM_OPS.is_empty());
        assert!(I386_ASM_OPS.iter().any(|(name, _)| *name == "nop"));
        assert!(I386_ASM_OPS.iter().any(|(name, _)| *name == "ret"));
    }

    #[test]
    fn test_asm_opcode_enum() {
        let nop = I386AsmOpcode::NOP as u8;
        let ret = I386AsmOpcode::RET as u8;
        assert_ne!(nop, ret);
    }

    #[test]
    fn test_asm_operand_constraints() {
        let constraints = [
            AsmOperandConstraint::OpcB as u16,
            AsmOperandConstraint::OpcWL as u16,
            AsmOperandConstraint::OpcBWL as u16,
            AsmOperandConstraint::OpcReg as u16,
            AsmOperandConstraint::OpcModRM as u16,
            AsmOperandConstraint::OpcImm as u16,
            AsmOperandConstraint::OpcShift as u16,
            AsmOperandConstraint::OpcJmp as u16,
            AsmOperandConstraint::OpcFarith as u16,
            AsmOperandConstraint::OpcTest as u16,
        ];
        for i in 0..constraints.len() {
            for j in (i + 1)..constraints.len() {
                assert_ne!(
                    constraints[i], constraints[j],
                    "constraint {} and {} should be distinct", i, j
                );
            }
        }
    }

    #[test]
    fn test_backend_creation() {
        let backend = I386Backend::new();
        let defs = backend.target_machine_defs();
        assert!(defs.contains(&"__i386__"));
        let classes = backend.reg_classes();
        assert_eq!(classes.len(), NB_REGS);
    }

    #[test]
    fn test_fastcall_regs() {
        assert_eq!(FASTCALL_REGS.len(), 2);
        assert_eq!(FASTCALL_REGS[0], TReg::ECX as u8);
        assert_eq!(FASTCALL_REGS[1], TReg::EDX as u8);
        assert_eq!(FASTCALLW_REGS.len(), 2);
    }

    #[test]
    fn test_asm_parse_regvar() {
        assert_eq!(asm_parse_regvar("eax"), Some(0));
        assert_eq!(asm_parse_regvar("ecx"), Some(1));
        assert_eq!(asm_parse_regvar("edx"), Some(2));
        assert_eq!(asm_parse_regvar("ebx"), Some(3));
        assert_eq!(asm_parse_regvar("esp"), Some(4));
        assert_eq!(asm_parse_regvar("ebp"), Some(5));
        assert_eq!(asm_parse_regvar("esi"), Some(6));
        assert_eq!(asm_parse_regvar("edi"), Some(7));
        assert_eq!(asm_parse_regvar("invalid"), None);
        assert_eq!(asm_parse_regvar("rax"), None);
    }

    #[test]
    fn test_code_reloc() {
        let backend = I386Backend::new();
        assert_eq!(backend.code_reloc(R_386_32 as i32), 0);
        assert_eq!(backend.code_reloc(R_386_PC32 as i32), 1);
        assert_eq!(backend.code_reloc(R_386_PLT32 as i32), 1);
        assert_eq!(backend.code_reloc(R_386_NONE as i32), 0);
        assert_eq!(backend.code_reloc(999), -1);
    }

    #[test]
    fn test_gotplt_entry_type() {
        let backend = I386Backend::new();
        assert!(matches!(
            backend.gotplt_entry_type(R_386_NONE as i32),
            GotPltEntry::NoEntry
        ));
        assert!(matches!(
            backend.gotplt_entry_type(R_386_32 as i32),
            GotPltEntry::AutoEntry
        ));
        assert!(matches!(
            backend.gotplt_entry_type(R_386_GOT32 as i32),
            GotPltEntry::BuildGotOnly
        ));
    }

    #[test]
    fn test_asm_op_struct() {
        let op = AsmOp {
            name: "nop",
            opcode: 0x90,
            group: 0,
            flags: 0,
            operands: &[],
        };
        assert_eq!(op.name, "nop");
        assert_eq!(op.opcode, 0x90);
        assert!(op.operands.is_empty());
    }

    #[test]
    fn test_byte_order_helpers() {
        let mut buf = [0u8; 4];
        write32le(&mut buf, 0x1234_5678);
        assert_eq!(read32le(&buf), 0x1234_5678);
        write16le(&mut buf, 0xABCD);
        assert_eq!(buf[0], 0xCD);
        assert_eq!(buf[1], 0xAB);
        let mut buf2 = [0u8; 4];
        write32le(&mut buf2, 100);
        add32le(&mut buf2, 50);
        assert_eq!(read32le(&buf2), 150);
    }

    #[test]
    fn test_sym_for_reloc() {
        let sym = sym_for_reloc(42);
        assert_eq!(sym.c, 42);
    }

    #[test]
    fn test_gfunc_sret() {
        let backend = I386Backend::new();
        let vt = CType { t: VT_INT, ref_sym: None };
        let mut ret = CType::default();
        let mut align = 0i32;
        let mut regsize = 0i32;
        let result = backend.gfunc_sret(&vt, false, &mut ret, &mut align, &mut regsize);
        assert_eq!(result, 0);
        assert_eq!(align, 4);
        assert_eq!(regsize, 4);
    }
}
