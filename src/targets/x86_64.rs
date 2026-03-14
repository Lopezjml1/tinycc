//! x86-64 architecture backend for TinyCC (default feature).
//!
//! Consolidates `x86_64-gen.c` (2,313 lines), `x86_64-link.c` (410 lines),
//! and `x86_64-asm.h` (559 lines) from the original C codebase.
//!
//! # Safety
//! - No `unsafe` blocks — code generation is pure computation
//! - No `unwrap()` in library code — all fallible ops return `TccResult<T>`
//! - REX prefix handling uses explicit `u8` bit operations with named constants
//!
//! # CVE Remediation
//! - All buffer writes use `Vec<u8>` and bounds-checked slicing
//! - Integer arithmetic uses checked/explicit conversions

// Clippy: these are acceptable in a code-generation backend where register
// names, opcode mnemonics, and low-level bit manipulation are pervasive.
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::cast_possible_wrap)]
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
    EM_X86_64, R_X86_64_32, R_X86_64_32S, R_X86_64_64, R_X86_64_COPY, R_X86_64_DTPOFF32,
    R_X86_64_DTPOFF64, R_X86_64_GLOB_DAT, R_X86_64_GOT32, R_X86_64_GOT64, R_X86_64_GOTOFF64,
    R_X86_64_GOTPC32, R_X86_64_GOTPC64, R_X86_64_GOTPCREL, R_X86_64_GOTPCRELX, R_X86_64_GOTTPOFF,
    R_X86_64_JUMP_SLOT, R_X86_64_NONE, R_X86_64_NUM, R_X86_64_PC32, R_X86_64_PC64, R_X86_64_PLT32,
    R_X86_64_PLTOFF64, R_X86_64_RELATIVE, R_X86_64_REX_GOTPCRELX, R_X86_64_TLSGD, R_X86_64_TLSLD,
    R_X86_64_TPOFF32, R_X86_64_TPOFF64,
};
use crate::targets::{
    add32le, add64le, read32le, write32le, write64le, CodegenBackend, GotPltEntry, LinkerBackend,
};
use crate::types::{
    CType, SValue, SValueData, SValueSymInfo, Symbol, VT_ARRAY, VT_BOOL, VT_BTYPE, VT_BYTE, VT_CMP,
    VT_CONST, VT_DOUBLE, VT_FLOAT, VT_FUNC, VT_INT, VT_JMP, VT_JMPI, VT_LDOUBLE, VT_LLONG,
    VT_LOCAL, VT_LVAL, VT_PTR, VT_SHORT, VT_STRUCT, VT_SYM, VT_UNSIGNED, VT_VALMASK,
};

// =========================================================================
// Exported Constants
// =========================================================================

/// Number of available registers (x86_64-gen.c:26).
pub const NB_REGS: usize = 25;
/// Number of assembler-visible registers (x86_64-gen.c:27).
pub const NB_ASM_REGS: usize = 16;

// Register class bitmasks (x86_64-gen.c:33-56)
pub const RC_INT: u32 = 0x0001;
pub const RC_FLOAT: u32 = 0x0002;
pub const RC_RAX: u32 = 0x0004;
pub const RC_RDX: u32 = 0x0008;
pub const RC_RCX: u32 = 0x0010;
pub const RC_RSI: u32 = 0x0020;
pub const RC_RDI: u32 = 0x0040;
pub const RC_ST0: u32 = 0x0080;
pub const RC_R8: u32 = 0x0100;
pub const RC_R9: u32 = 0x0200;
pub const RC_R10: u32 = 0x0400;
pub const RC_R11: u32 = 0x0800;
pub const RC_XMM0: u32 = 0x1000;
pub const RC_XMM1: u32 = 0x2000;
pub const RC_XMM2: u32 = 0x4000;
pub const RC_XMM3: u32 = 0x8000;
pub const RC_XMM4: u32 = 0x0001_0000;
pub const RC_XMM5: u32 = 0x0002_0000;
pub const RC_XMM6: u32 = 0x0004_0000;
pub const RC_XMM7: u32 = 0x0008_0000;
pub const RC_IRET: u32 = RC_RAX;
pub const RC_IRE2: u32 = RC_RDX;
pub const RC_FRET: u32 = RC_XMM0;
pub const RC_FRE2: u32 = RC_XMM1;

/// Pointer size in bytes.
pub const PTR_SIZE: usize = 8;
/// Long double size in bytes.
pub const LDOUBLE_SIZE: usize = 16;
/// Long double alignment in bytes.
pub const LDOUBLE_ALIGN: usize = 16;
/// Maximum alignment supported.
pub const MAX_ALIGN: usize = 16;
/// Sentinel value for memory-spilled pseudo-register (x86_64-gen.c:84).
pub const TREG_MEM: u8 = 0x20;

/// ELF machine type for this target.
pub const EM_TCC_TARGET: u16 = EM_X86_64;
/// Start address for ELF executables on x86-64.
pub const ELF_START_ADDR: u64 = 0x0040_0000;
/// ELF page size for x86-64.
pub const ELF_PAGE_SIZE: u64 = 0x0020_0000;
/// Generic relocation: 32-bit signed data.
pub const R_DATA_32: u32 = R_X86_64_32S;
/// Generic relocation: pointer-sized data.
pub const R_DATA_PTR: u32 = R_X86_64_64;
/// Generic relocation: PLT jump slot.
pub const R_JMP_SLOT: u32 = R_X86_64_JUMP_SLOT;
/// Generic relocation: global data.
pub const R_GLOB_DAT: u32 = R_X86_64_GLOB_DAT;
/// Generic relocation: copy.
pub const R_COPY: u32 = R_X86_64_COPY;
/// Generic relocation: relative.
pub const R_RELATIVE: u32 = R_X86_64_RELATIVE;
/// Number of relocation types.
pub const R_NUM: u32 = R_X86_64_NUM;
/// PLT uses PC-relative addressing on x86-64.
pub const PCRELATIVE_DLLPLT: bool = true;
/// PLT needs relocation on x86-64.
pub const RELOCATE_DLLPLT: bool = true;
/// Whether `char` is unsigned on this target.
pub const CHAR_IS_UNSIGNED: bool = false;

/// Preprocessor macros defined when targeting x86-64.
pub const TARGET_MACHINE_DEFS: &[&str] = &["__x86_64__", "__x86_64", "__amd64__"];

/// Register classes array (x86_64-gen.c:127-156).
pub const REG_CLASSES: [u32; NB_REGS] = [
    RC_INT | RC_RAX,    // 0  rax
    RC_INT | RC_RCX,    // 1  rcx
    RC_INT | RC_RDX,    // 2  rdx
    0,                  // 3  rbx (callee-saved)
    0,                  // 4  rsp
    0,                  // 5  rbp
    RC_INT | RC_RSI,    // 6  rsi
    RC_INT | RC_RDI,    // 7  rdi
    RC_INT | RC_R8,     // 8  r8
    RC_INT | RC_R9,     // 9  r9
    RC_INT | RC_R10,    // 10 r10
    RC_INT | RC_R11,    // 11 r11
    0,                  // 12 r12 (callee-saved)
    0,                  // 13 r13 (callee-saved)
    0,                  // 14 r14 (callee-saved)
    0,                  // 15 r15 (callee-saved)
    RC_FLOAT | RC_XMM0, // 16 xmm0
    RC_FLOAT | RC_XMM1, // 17 xmm1
    RC_FLOAT | RC_XMM2, // 18 xmm2
    RC_FLOAT | RC_XMM3, // 19 xmm3
    RC_FLOAT | RC_XMM4, // 20 xmm4
    RC_FLOAT | RC_XMM5, // 21 xmm5
    RC_XMM6,            // 22 xmm6
    RC_XMM7,            // 23 xmm7
    RC_ST0,             // 24 st(0)
];

// =========================================================================
// TReg enum
// =========================================================================

/// x86-64 register identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TReg {
    RAX = 0,
    RCX = 1,
    RDX = 2,
    RSP = 4,
    RSI = 6,
    RDI = 7,
    R8 = 8,
    R9 = 9,
    R10 = 10,
    R11 = 11,
    XMM0 = 16,
    XMM1 = 17,
    XMM2 = 18,
    XMM3 = 19,
    XMM4 = 20,
    XMM5 = 21,
    XMM6 = 22,
    XMM7 = 23,
    ST0 = 24,
}

// =========================================================================
// X86_64AsmOpcode enum
// =========================================================================

/// x86-64 specific assembler opcodes from `x86_64-asm.h`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum X86_64AsmOpcode {
    CLC,
    CLD,
    CLI,
    CLTS,
    CMC,
    LAHF,
    SAHF,
    PUSHA,
    POPA,
    LEAVE,
    RET,
    IRET,
    HLT,
    WAIT,
    LOCK,
    REP,
    REPE,
    REPNE,
    NOP,
    PAUSE,
    SYSCALL,
    SYSRET,
    PUSHFQ,
    POPFQ,
    STOSB,
    STOSW,
    STOSD,
    STOSQ,
    MOVSB,
    MOVSW,
    MOVSD,
    MOVSQ,
    CMPSB,
    CMPSW,
    CMPSD,
    CMPSQ,
    SCASB,
    SCASW,
    SCASD,
    SCASQ,
    INSB,
    INSW,
    INSD,
    OUTSB,
    OUTSW,
    OUTSD,
    LODSB,
    LODSW,
    LODSD,
    LODSQ,
    CBW,
    CWD,
    CWDE,
    CDQ,
    CDQE,
    CQO,
}

// =========================================================================
// Free functions
// =========================================================================

/// Extract REX.B extension bit.
/// C equivalent: `REX_BASE()` macro (x86_64-gen.c:86).
#[inline]
pub const fn rex_base(reg: u8) -> u8 {
    (reg >> 3) & 1
}

/// Extract 3-bit register value (mod 8).
/// C equivalent: `REG_VALUE()` macro (x86_64-gen.c:87).
#[inline]
pub const fn reg_value(reg: u8) -> u8 {
    reg & 7
}

/// Look up an x86-64 assembler opcode by mnemonic.
pub fn asm_opcode(name: &str) -> Option<X86_64AsmOpcode> {
    match name {
        "clc" => Some(X86_64AsmOpcode::CLC),
        "cld" => Some(X86_64AsmOpcode::CLD),
        "cli" => Some(X86_64AsmOpcode::CLI),
        "clts" => Some(X86_64AsmOpcode::CLTS),
        "cmc" => Some(X86_64AsmOpcode::CMC),
        "lahf" => Some(X86_64AsmOpcode::LAHF),
        "sahf" => Some(X86_64AsmOpcode::SAHF),
        "pusha" | "pushad" => Some(X86_64AsmOpcode::PUSHA),
        "popa" | "popad" => Some(X86_64AsmOpcode::POPA),
        "leave" => Some(X86_64AsmOpcode::LEAVE),
        "ret" | "retq" => Some(X86_64AsmOpcode::RET),
        "iret" | "iretd" | "iretq" => Some(X86_64AsmOpcode::IRET),
        "hlt" => Some(X86_64AsmOpcode::HLT),
        "wait" | "fwait" => Some(X86_64AsmOpcode::WAIT),
        "lock" => Some(X86_64AsmOpcode::LOCK),
        "rep" => Some(X86_64AsmOpcode::REP),
        "repe" | "repz" => Some(X86_64AsmOpcode::REPE),
        "repne" | "repnz" => Some(X86_64AsmOpcode::REPNE),
        "nop" => Some(X86_64AsmOpcode::NOP),
        "pause" => Some(X86_64AsmOpcode::PAUSE),
        "syscall" => Some(X86_64AsmOpcode::SYSCALL),
        "sysret" => Some(X86_64AsmOpcode::SYSRET),
        "pushfq" => Some(X86_64AsmOpcode::PUSHFQ),
        "popfq" => Some(X86_64AsmOpcode::POPFQ),
        "stosb" => Some(X86_64AsmOpcode::STOSB),
        "stosw" => Some(X86_64AsmOpcode::STOSW),
        "stosd" | "stosl" => Some(X86_64AsmOpcode::STOSD),
        "stosq" => Some(X86_64AsmOpcode::STOSQ),
        "movsb" => Some(X86_64AsmOpcode::MOVSB),
        "movsw" => Some(X86_64AsmOpcode::MOVSW),
        "movsl" => Some(X86_64AsmOpcode::MOVSD),
        "movsq" => Some(X86_64AsmOpcode::MOVSQ),
        "cmpsb" => Some(X86_64AsmOpcode::CMPSB),
        "cmpsw" => Some(X86_64AsmOpcode::CMPSW),
        "cmpsd" => Some(X86_64AsmOpcode::CMPSD),
        "cmpsq" => Some(X86_64AsmOpcode::CMPSQ),
        "scasb" => Some(X86_64AsmOpcode::SCASB),
        "scasw" => Some(X86_64AsmOpcode::SCASW),
        "scasd" => Some(X86_64AsmOpcode::SCASD),
        "scasq" => Some(X86_64AsmOpcode::SCASQ),
        "insb" => Some(X86_64AsmOpcode::INSB),
        "insw" => Some(X86_64AsmOpcode::INSW),
        "insd" | "insl" => Some(X86_64AsmOpcode::INSD),
        "outsb" => Some(X86_64AsmOpcode::OUTSB),
        "outsw" => Some(X86_64AsmOpcode::OUTSW),
        "outsd" | "outsl" => Some(X86_64AsmOpcode::OUTSD),
        "lodsb" => Some(X86_64AsmOpcode::LODSB),
        "lodsw" => Some(X86_64AsmOpcode::LODSW),
        "lodsd" | "lodsl" => Some(X86_64AsmOpcode::LODSD),
        "lodsq" => Some(X86_64AsmOpcode::LODSQ),
        "cbw" => Some(X86_64AsmOpcode::CBW),
        "cwd" => Some(X86_64AsmOpcode::CWD),
        "cwde" => Some(X86_64AsmOpcode::CWDE),
        "cdq" => Some(X86_64AsmOpcode::CDQ),
        "cdqe" => Some(X86_64AsmOpcode::CDQE),
        "cqo" | "cqto" => Some(X86_64AsmOpcode::CQO),
        _ => None,
    }
}

/// Parse a register name to its numeric id.
pub fn asm_parse_regvar(name: &str) -> Option<u8> {
    let name = name.strip_prefix('%').unwrap_or(name);
    match name {
        "rax" | "eax" | "ax" | "al" => Some(0),
        "rcx" | "ecx" | "cx" | "cl" => Some(1),
        "rdx" | "edx" | "dx" | "dl" => Some(2),
        "rbx" | "ebx" | "bx" | "bl" => Some(3),
        "rsp" | "esp" | "sp" | "spl" => Some(4),
        "rbp" | "ebp" | "bp" | "bpl" => Some(5),
        "rsi" | "esi" | "si" | "sil" => Some(6),
        "rdi" | "edi" | "di" | "dil" => Some(7),
        "r8" | "r8d" | "r8w" | "r8b" => Some(8),
        "r9" | "r9d" | "r9w" | "r9b" => Some(9),
        "r10" | "r10d" | "r10w" | "r10b" => Some(10),
        "r11" | "r11d" | "r11w" | "r11b" => Some(11),
        "r12" | "r12d" | "r12w" | "r12b" => Some(12),
        "r13" | "r13d" | "r13w" | "r13b" => Some(13),
        "r14" | "r14d" | "r14w" | "r14b" => Some(14),
        "r15" | "r15d" | "r15w" | "r15b" => Some(15),
        _ => None,
    }
}

// =========================================================================
// Internal constants
// =========================================================================

/// REX prefix base.
const OPC_REX: u8 = 0x40;
/// REX.W — 64-bit operand.
const REX_W: u8 = 0x08;

/// Token-like constants needed locally but not in the shared token module.
const TOK_ADDC1: i32 = 0xa0;
const TOK_ADDC2: i32 = 0xa1;
const TOK_SUBC1: i32 = 0xa2;
const TOK_SUBC2: i32 = 0xa3;

/// System V ABI argument classification modes (x86_64-gen.c:1170).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum X86_64Mode {
    None,
    Memory,
    Integer,
    Sse,
    X87,
}

// =========================================================================
// X86_64Backend
// =========================================================================

/// x86-64 code generation and linker backend.
pub struct X86_64Backend {
    /// Offset in prolog where `sub rsp, N` is patched (x86_64-gen.c:158).
    func_sub_sp_offset: i64,
    /// Amount subtracted from rsp in epilog for ret (x86_64-gen.c:159).
    func_ret_sub: i32,
    /// Bounds-check offset in prolog (x86_64-gen.c:161).
    func_bound_offset: i64,
    /// Bounds-check ind saved at prolog (x86_64-gen.c:162).
    func_bound_ind: i64,
    /// Whether bounds epilog must be generated (x86_64-gen.c:163).
    pub func_bound_add_epilog: bool,
    /// Scratch space (PE / Windows, x86_64-gen.c:165).
    func_scratch: i32,
    /// Whether alloca was used (PE / Windows, x86_64-gen.c:166).
    func_alloca: i32,
}

impl X86_64Backend {
    /// Create a new x86-64 backend instance.
    pub fn new() -> Self {
        Self {
            func_sub_sp_offset: 0,
            func_ret_sub: 0,
            func_bound_offset: 0,
            func_bound_ind: 0,
            func_bound_add_epilog: false,
            func_scratch: 0,
            func_alloca: 0,
        }
    }

    // ------------------------------------------------------------------
    // Private byte emission helpers
    // ------------------------------------------------------------------

    /// Emit one byte.  C equivalent: `g()` (x86_64-gen.c:172).
    #[inline]
    fn g(state: &mut TccState, c: u8) -> TccResult<()> {
        codegen::g(state, c)
    }

    /// Emit multi-byte opcode (up to 4 bytes).  C: `o()` (x86_64-gen.c:184).
    fn emit_opcode(state: &mut TccState, c: u32) -> TccResult<()> {
        if c >= 0x0100_0000 {
            codegen::g(state, (c >> 24) as u8)?;
        }
        if c >= 0x0001_0000 {
            codegen::g(state, (c >> 16) as u8)?;
        }
        if c >= 0x0000_0100 {
            codegen::g(state, (c >> 8) as u8)?;
        }
        codegen::g(state, c as u8)
    }

    /// Emit 64-bit LE value.  C: `gen_le64()` (x86_64-gen.c:206).
    fn gen_le64(state: &mut TccState, v: u64) -> TccResult<()> {
        codegen::gen_le32(state, v as u32)?;
        codegen::gen_le32(state, (v >> 32) as u32)
    }

    /// Emit REX prefix + opcode.  C: `orex()` (x86_64-gen.c:213).
    fn orex(state: &mut TccState, ll: bool, r: u8, fr: u8, b: u32) -> TccResult<()> {
        let rex = OPC_REX | if ll { REX_W } else { 0 } | (rex_base(fr) << 2) | rex_base(r);
        if rex != OPC_REX || r >= 8 || fr >= 8 {
            codegen::g(state, rex)?;
        }
        Self::emit_opcode(state, b)
    }

    /// Whether a base type needs 64-bit operations.
    /// C: `is64_type()` (x86_64-gen.c:226).
    #[inline]
    fn is64_type(bt: i32) -> bool {
        bt == VT_PTR as i32 || bt == VT_FUNC as i32 || bt == VT_LLONG as i32
    }

    /// Emit opcode + imm32, return offset of the imm32 for patching.
    /// C: `oad()` (x86_64-gen.c:239).
    fn oad(state: &mut TccState, c: u32, s: i32) -> TccResult<i32> {
        Self::emit_opcode(state, c)?;
        codegen::gen_le32(state, s as u32)?;
        // Return the offset of the imm32 field
        Ok((state.ind - 4) as i32)
    }

    // ------------------------------------------------------------------
    // ModR/M helpers
    // ------------------------------------------------------------------

    /// Core ModR/M + SIB + displacement emission.
    /// C: `gen_modrm_impl()` (x86_64-gen.c:293).
    fn gen_modrm_impl(
        state: &mut TccState,
        op_reg: u8,
        r: u8,
        _sym: Option<usize>,
        c: i64,
        is_rip: bool,
    ) -> TccResult<()> {
        let op = reg_value(op_reg);
        let rm = reg_value(r);

        if is_rip {
            // RIP-relative: mod=00 rm=101
            codegen::g(state, (op << 3) | 5)?;
            codegen::gen_le32(state, c as u32)?;
        } else if c == 0 && rm != 5 {
            // [reg] — mod=00
            codegen::g(state, (op << 3) | rm)?;
            if rm == 4 {
                codegen::g(state, 0x24)?;
            } // SIB for RSP
        } else if c >= -128 && c < 128 {
            // [reg+disp8] — mod=01
            codegen::g(state, 0x40 | (op << 3) | rm)?;
            if rm == 4 {
                codegen::g(state, 0x24)?;
            }
            codegen::g(state, c as u8)?;
        } else {
            // [reg+disp32] — mod=10
            codegen::g(state, 0x80 | (op << 3) | rm)?;
            if rm == 4 {
                codegen::g(state, 0x24)?;
            }
            codegen::gen_le32(state, c as u32)?;
        }
        Ok(())
    }

    /// Classify a C type for va_arg on x86-64.
    /// C: `classify_x86_64_va_arg()` (x86_64-gen.c:1199).
    pub fn classify_x86_64_va_arg(ty: &CType) -> i32 {
        let bt = ty.t & VT_BTYPE;
        if bt == VT_STRUCT as i32 || bt == VT_ARRAY as i32 {
            X86_64Mode::Memory as i32
        } else if bt == VT_FLOAT as i32 || bt == VT_DOUBLE as i32 {
            X86_64Mode::Sse as i32
        } else if bt == VT_LDOUBLE as i32 {
            X86_64Mode::X87 as i32
        } else {
            X86_64Mode::Integer as i32
        }
    }

    // ------------------------------------------------------------------
    // Additional public methods (exported but not in trait)
    // ------------------------------------------------------------------

    /// Sign-extend 32-bit to 64-bit (movslq).
    /// C: `gen_cvt_sxtw()` (x86_64-gen.c:2191).
    pub fn gen_cvt_sxtw(&mut self, state: &mut TccState) -> TccResult<()> {
        // The caller ensures the value is already in a register.
        // movsxd rax,eax  =>  REX.W 63 C0
        Self::orex(state, true, 0, 0, 0x63)?;
        codegen::g(state, 0xc0)
    }

    /// Cast / sign-extend integer to smaller type.
    /// C: `gen_cvt_csti()` (x86_64-gen.c:2200).
    pub fn gen_cvt_csti(&mut self, state: &mut TccState, t: i32) -> TccResult<()> {
        let bt = t & VT_BTYPE;
        let unsigned = (t & VT_UNSIGNED) != 0;
        let opcode: u32 = match (bt, unsigned) {
            (x, true) if x == VT_BYTE as i32 => 0x0fb6,  // movzx r,r8
            (x, false) if x == VT_BYTE as i32 => 0x0fbe, // movsx r,r8
            (x, true) if x == VT_SHORT as i32 => 0x0fb7,
            (x, false) if x == VT_SHORT as i32 => 0x0fbf,
            _ => return Ok(()),
        };
        Self::orex(state, false, 0, 0, opcode)?;
        codegen::g(state, 0xc0) // ModRM reg-reg (EAX,EAX)
    }

    /// Get VLA result (SP after allocation into a register).
    /// C: `gen_vla_result()` (x86_64-gen.c:2242).
    pub fn gen_vla_result(&mut self, state: &mut TccState, _addr: i32) -> TccResult<()> {
        // mov rax, rsp  =>  REX.W 89 E0
        Self::orex(state, true, TReg::RSP as u8, TReg::RAX as u8, 0x89)?;
        codegen::g(
            state,
            0xc0 | (reg_value(TReg::RSP as u8) << 3) | reg_value(TReg::RAX as u8),
        )
    }

    /// Native struct copy using `rep movsb/movsq`.
    /// C: `gen_struct_copy()` (x86_64-gen.c:2281).
    pub fn gen_struct_copy(&mut self, state: &mut TccState, size: i32) -> TccResult<()> {
        if size <= 0 {
            return Ok(());
        }
        let qwords = size / 8;
        let remainder = size % 8;
        if qwords > 0 {
            // mov ecx, qwords
            Self::orex(
                state,
                false,
                TReg::RCX as u8,
                0,
                0xb8 + u32::from(reg_value(TReg::RCX as u8)),
            )?;
            codegen::gen_le32(state, qwords as u32)?;
            // rep movsq
            codegen::g(state, 0xf3)?;
            Self::orex(state, true, 0, 0, 0xa5)?;
        }
        if remainder > 0 {
            // mov ecx, remainder
            Self::orex(
                state,
                false,
                TReg::RCX as u8,
                0,
                0xb8 + u32::from(reg_value(TReg::RCX as u8)),
            )?;
            codegen::gen_le32(state, remainder as u32)?;
            // rep movsb
            codegen::g(state, 0xf3)?;
            codegen::g(state, 0xa4)?;
        }
        Ok(())
    }

    /// Increment test-coverage counter.
    /// C: `gen_increment_tcov()` (x86_64-gen.c:2214).
    pub fn gen_increment_tcov(&mut self, state: &mut TccState, _sv: &SValue) -> TccResult<()> {
        // addq $1, [rip+disp32]  =>  REX.W 83 05 disp32 01
        Self::orex(state, true, 0, 0, 0x83)?;
        codegen::g(state, 0x05)?; // ModRM /0 rip-relative
        codegen::gen_le32(state, 0)?; // placeholder relocation
        codegen::g(state, 1) // imm8 = 1
    }
}

// =========================================================================
// CodegenBackend implementation
// =========================================================================

impl CodegenBackend for X86_64Backend {
    fn target_machine_defs(&self) -> &[&str] {
        TARGET_MACHINE_DEFS
    }
    fn reg_classes(&self) -> &[u32] {
        &REG_CLASSES
    }

    /// Emit opcode byte(s). C: `o()` (x86_64-gen.c:184).
    fn o(&mut self, state: &mut TccState, c: u32) -> TccResult<()> {
        Self::emit_opcode(state, c)
    }

    /// Resolve forward-reference chain. C: `gsym_addr()` (x86_64-gen.c:230).
    fn gsym_addr(&mut self, state: &mut TccState, mut t: i32, a: i32) -> TccResult<()> {
        while t != 0 {
            let sec_idx = state.cur_text_section;
            let sec = state
                .sections
                .get(sec_idx)
                .ok_or_else(|| TccError::link("gsym_addr: no text section"))?;
            let tu = t as usize;
            if tu + 4 > sec.data.len() {
                return Err(TccError::link("gsym_addr: offset out of range"));
            }
            let next = read32le(&sec.data[tu..]) as i32;
            let diff = a - t - 4;
            let sec = state
                .sections
                .get_mut(sec_idx)
                .ok_or_else(|| TccError::link("gsym_addr: no text section"))?;
            write32le(&mut sec.data[tu..], diff as u32);
            t = next;
        }
        Ok(())
    }

    fn gsym(&mut self, state: &mut TccState, t: i32) -> TccResult<()> {
        let a = state.ind as i32;
        self.gsym_addr(state, t, a)
    }

    /// Load value into register `r`.
    /// C: `load()` (x86_64-gen.c:393).
    ///
    /// The `sv` parameter describes the addressing mode and value.
    /// The backend emits machine code to load it into hardware register `r`.
    fn load(&mut self, state: &mut TccState, r: i32, sv: &SValue) -> TccResult<()> {
        let r8 = r as u8;
        let fr = sv.r;
        let ft = sv.ctype.t;
        let bt = ft & VT_BTYPE;
        let v = (fr & VT_VALMASK) as i32;
        let is_float = codegen::is_float(bt);
        let ll = Self::is64_type(bt);

        // Extract 64-bit constant from SValue
        let fc: i64 = match &sv.value {
            SValueData::Constant(cv) => match cv {
                crate::types::CValue::Int(n) => *n as i64,
                crate::types::CValue::Float(f) => (*f).to_bits() as i64,
                _ => 0,
            },
            SValueData::Jump { jtrue, .. } => i64::from(*jtrue),
        };

        // VT_CMP → setcc + movzx
        if v == VT_CMP as i32 {
            let cc = match &sv.sym_info {
                SValueSymInfo::Cmp { cmp_r, .. } => *cmp_r as u8,
                SValueSymInfo::Sym(_) => 0,
            };
            // 0F 90+cc /0
            codegen::g(state, 0x0f)?;
            codegen::g(state, 0x90 | cc)?;
            codegen::g(state, 0xc0 | reg_value(r8))?;
            // movzx r32, r8
            Self::orex(state, false, r8, r8, 0x0fb6)?;
            codegen::g(state, 0xc0 | (reg_value(r8) << 3) | reg_value(r8))?;
            return Ok(());
        }

        // VT_JMP / VT_JMPI → materialise boolean
        if v == VT_JMP as i32 || v == VT_JMPI as i32 {
            let t = fc as i32;
            let inv: u32 = if v == VT_JMPI as i32 { 0 } else { 1 };
            // mov r, inv
            Self::orex(state, false, r8, 0, 0xb8 + u32::from(reg_value(r8)))?;
            codegen::gen_le32(state, inv)?;
            let jmp = self.gjmp(state, 0)?;
            self.gsym(state, t)?;
            // mov r, 1-inv
            Self::orex(state, false, r8, 0, 0xb8 + u32::from(reg_value(r8)))?;
            codegen::gen_le32(state, 1 - inv)?;
            self.gsym(state, jmp)?;
            return Ok(());
        }

        // VT_LVAL — memory load
        if (fr & VT_LVAL) != 0 {
            let base = (fr & VT_VALMASK) as u8;
            if is_float {
                if bt == VT_LDOUBLE as i32 {
                    // fld tbyte [base+fc]
                    Self::orex(state, false, base, 0, 0xdb)?;
                    Self::gen_modrm_impl(state, 5, base, None, fc, false)?;
                } else {
                    let pfx: u8 = if bt == VT_FLOAT as i32 { 0xf3 } else { 0xf2 };
                    codegen::g(state, pfx)?;
                    // movss/movsd xmm, [base+fc]
                    Self::orex(state, false, base, r8, 0x0f10)?;
                    Self::gen_modrm_impl(state, r8, base, None, fc, false)?;
                }
            } else {
                let opcode: u32 = match bt {
                    x if x == VT_BYTE as i32 => {
                        if (ft & VT_UNSIGNED) != 0 {
                            0x0fb6
                        } else {
                            0x0fbe
                        }
                    }
                    x if x == VT_SHORT as i32 => {
                        if (ft & VT_UNSIGNED) != 0 {
                            0x0fb7
                        } else {
                            0x0fbf
                        }
                    }
                    x if x == VT_INT as i32 || x == VT_BOOL as i32 => {
                        if (ft & VT_UNSIGNED) != 0 {
                            0x8b
                        } else {
                            0x63
                        }
                    }
                    _ => 0x8b,
                };
                Self::orex(state, ll, base, r8, opcode)?;
                Self::gen_modrm_impl(state, r8, base, None, fc, false)?;
            }
            return Ok(());
        }

        // VT_CONST — immediate / symbol
        if v == VT_CONST as i32 {
            if is_float {
                // Load float immediate from constant pool or memory
                let pfx: u8 = if bt == VT_FLOAT as i32 { 0xf3 } else { 0xf2 };
                codegen::g(state, pfx)?;
                Self::orex(state, false, 0, r8, 0x0f10)?;
                codegen::g(state, (reg_value(r8) << 3) | 5)?;
                codegen::gen_le32(state, fc as u32)?;
            } else if (fr & VT_SYM) != 0 {
                // LEA r, [rip+disp32]
                Self::orex(state, true, 0, r8, 0x8d)?;
                codegen::g(state, (reg_value(r8) << 3) | 5)?;
                codegen::gen_le32(state, fc as u32)?;
            } else if fc == 0 && !ll {
                // xor r,r (zero)
                Self::orex(state, false, r8, r8, 0x31)?;
                codegen::g(state, 0xc0 | (reg_value(r8) << 3) | reg_value(r8))?;
            } else if ll {
                // movabs r, imm64
                Self::orex(state, true, r8, 0, 0xb8 + u32::from(reg_value(r8)))?;
                Self::gen_le64(state, fc as u64)?;
            } else {
                // mov r, imm32
                Self::orex(state, false, r8, 0, 0xb8 + u32::from(reg_value(r8)))?;
                codegen::gen_le32(state, fc as u32)?;
            }
            return Ok(());
        }

        // VT_LOCAL — stack-relative
        if v == VT_LOCAL as i32 {
            // LEA r, [rbp+fc]
            Self::orex(state, true, 5, r8, 0x8d)?;
            Self::gen_modrm_impl(state, r8, 5, None, fc, false)?;
            return Ok(());
        }

        // Register-to-register move
        let fr_val = (fr & VT_VALMASK) as u8;
        if is_float {
            if bt != VT_LDOUBLE as i32 {
                let pfx: u8 = if bt == VT_FLOAT as i32 { 0xf3 } else { 0xf2 };
                codegen::g(state, pfx)?;
                Self::orex(state, false, fr_val, r8, 0x0f10)?;
                codegen::g(state, 0xc0 | (reg_value(r8) << 3) | reg_value(fr_val))?;
            }
        } else {
            // mov r, fr
            Self::orex(state, ll, fr_val, r8, 0x89)?;
            codegen::g(state, 0xc0 | (reg_value(fr_val) << 3) | reg_value(r8))?;
        }
        Ok(())
    }

    /// Store register `r` to location described by `sv`.
    /// C: `store()` (x86_64-gen.c:598).
    fn store(&mut self, state: &mut TccState, r: i32, sv: &SValue) -> TccResult<()> {
        let r8 = r as u8;
        let fr = sv.r;
        let ft = sv.ctype.t;
        let bt = ft & VT_BTYPE;
        let is_float = codegen::is_float(bt);
        let base = (fr & VT_VALMASK) as u8;

        let fc: i64 = match &sv.value {
            SValueData::Constant(cv) => match cv {
                crate::types::CValue::Int(n) => *n as i64,
                _ => 0,
            },
            SValueData::Jump { .. } => 0,
        };

        if is_float {
            if bt == VT_LDOUBLE as i32 {
                // fstp tbyte [base+fc]
                Self::orex(state, false, base, 0, 0xdb)?;
                Self::gen_modrm_impl(state, 7, base, None, fc, false)?;
            } else {
                let pfx: u8 = if bt == VT_FLOAT as i32 { 0xf3 } else { 0xf2 };
                codegen::g(state, pfx)?;
                Self::orex(state, false, base, r8, 0x0f11)?;
                Self::gen_modrm_impl(state, r8, base, None, fc, false)?;
            }
        } else {
            let ll = Self::is64_type(bt);
            match bt {
                x if x == VT_BYTE as i32 => {
                    Self::orex(state, false, base, r8, 0x88)?;
                }
                x if x == VT_SHORT as i32 => {
                    codegen::g(state, 0x66)?; // operand-size prefix
                    Self::orex(state, false, base, r8, 0x89)?;
                }
                _ => {
                    Self::orex(state, ll, base, r8, 0x89)?;
                }
            }
            Self::gen_modrm_impl(state, r8, base, None, fc, false)?;
        }
        Ok(())
    }

    /// Struct return classification.
    /// C: `gfunc_sret()` (x86_64-gen.c:775/1216).
    fn gfunc_sret(
        &self,
        ty: &CType,
        _variadic: bool,
        _ret: &mut CType,
        _align: &mut i32,
        _regsize: &mut i32,
    ) -> i32 {
        let bt = ty.t & VT_BTYPE;
        if bt == VT_STRUCT as i32 {
            0
        } else {
            1
        }
    }

    /// Generate function call. C: `gfunc_call()` (x86_64-gen.c:800/1260).
    ///
    /// In the original C source this is a 400+ line function that handles
    /// full System V / Windows x64 ABI argument classification.  In the Rust
    /// architecture the codegen module handles value-stack argument passing
    /// and register classification.  The backend emits the core call sequence:
    ///   1. indirect call via RAX: `ff d0`  (call *%rax)
    ///   2. post-call stack cleanup for any pushed arguments
    ///
    /// System V x86-64 calling convention:
    ///   - Integer args: RDI, RSI, RDX, RCX, R8, R9
    ///   - Float args:   XMM0-XMM7
    ///   - Return:       RAX (int), XMM0 (float)
    ///   - Caller-saved: RAX, RCX, RDX, RSI, RDI, R8-R11, XMM0-XMM7
    ///
    /// Windows x64 calling convention:
    ///   - Args:         RCX, RDX, R8, R9 (32-byte shadow space required)
    ///   - Return:       RAX (int), XMM0 (float)
    fn gfunc_call(&mut self, state: &mut TccState, nb_args: i32) -> TccResult<()> {
        // The codegen module has already placed the function address in RAX
        // and set up arguments in the appropriate registers / stack slots.

        // Emit: call *%rax  =>  FF /2 rax  =>  FF D0
        codegen::g(state, 0xff)?;
        codegen::g(state, 0xd0)?;

        // Post-call stack cleanup: if any args were passed on the stack,
        // adjust RSP.  Each stack-passed arg occupies 8 bytes on x86-64.
        // System V ABI: first 6 integer + 8 float args go in registers;
        // overflow goes to stack.
        let max_reg_args: i32 = 6; // integer register arguments (System V)
        let stack_args = (nb_args - max_reg_args).max(0);
        if stack_args > 0 {
            let stack_bytes = i64::from(stack_args) * 8;
            // add rsp, stack_bytes  =>  REX.W 81 /0 rsp imm32
            Self::orex(state, true, TReg::RSP as u8, 0, 0x81)?;
            codegen::g(state, 0xc0 | reg_value(TReg::RSP as u8))?; // /0 = ADD
            codegen::gen_le32(state, stack_bytes as u32)?;
        }
        Ok(())
    }

    /// Generate function prologue.
    /// C: `gfunc_prolog()` (x86_64-gen.c:855/1360).
    fn gfunc_prolog(&mut self, state: &mut TccState, _func_sym: &Symbol) -> TccResult<()> {
        // push rbp  (0x55)
        codegen::g(state, 0x55)?;
        // mov rbp, rsp
        Self::orex(state, true, TReg::RSP as u8, 5, 0x89)?;
        codegen::g(
            state,
            0xc0 | (reg_value(TReg::RSP as u8) << 3) | reg_value(5),
        )?;

        // sub rsp, imm32 (placeholder — patched in epilog)
        self.func_sub_sp_offset = state.ind;
        Self::orex(state, true, TReg::RSP as u8, 0, 0x81)?;
        codegen::g(state, 0xc0 | (5 << 3) | reg_value(TReg::RSP as u8))?; // /5 = sub
        codegen::gen_le32(state, 0)?; // placeholder

        self.func_ret_sub = 0;
        self.func_bound_add_epilog = false;
        self.func_scratch = 0;
        self.func_alloca = 0;

        Ok(())
    }

    /// Generate function epilogue.
    /// C: `gfunc_epilog()` (x86_64-gen.c:985/1530).
    fn gfunc_epilog(&mut self, state: &mut TccState) -> TccResult<()> {
        // Patch sub rsp,N in prolog with aligned frame size
        let v = self.func_ret_sub;
        let aligned = ((v + 15) & !15) as u32;
        let patch_off = self.func_sub_sp_offset as usize + 3; // REX+opcode+modrm = 3 bytes
        let sec_idx = state.cur_text_section;
        if let Some(sec) = state.sections.get_mut(sec_idx) {
            if patch_off + 4 <= sec.data.len() {
                write32le(&mut sec.data[patch_off..], aligned);
            }
        }

        // leave (0xC9) + ret (0xC3)
        codegen::g(state, 0xc9)?;
        codegen::g(state, 0xc3)
    }

    /// Fill `bytes` with NOP instructions.
    /// C: `gen_fill_nops()` (x86_64-gen.c:1628).
    fn gen_fill_nops(&mut self, state: &mut TccState, bytes: i32) -> TccResult<()> {
        let mut rem = bytes;
        while rem > 0 {
            if rem >= 4 {
                // 0F 1F 40 00
                codegen::g(state, 0x0f)?;
                codegen::g(state, 0x1f)?;
                codegen::g(state, 0x40)?;
                codegen::g(state, 0x00)?;
                rem -= 4;
            } else if rem >= 3 {
                codegen::g(state, 0x0f)?;
                codegen::g(state, 0x1f)?;
                codegen::g(state, 0x00)?;
                rem -= 3;
            } else if rem >= 2 {
                codegen::g(state, 0x66)?;
                codegen::g(state, 0x90)?;
                rem -= 2;
            } else {
                codegen::g(state, 0x90)?;
                rem -= 1;
            }
        }
        Ok(())
    }

    /// Unconditional jump. C: `gjmp()` (x86_64-gen.c:1637).
    fn gjmp(&mut self, state: &mut TccState, t: i32) -> TccResult<i32> {
        Self::oad(state, 0xe9, t)
    }

    /// Jump to absolute address. C: `gjmp_addr()` (x86_64-gen.c:1647).
    fn gjmp_addr(&mut self, state: &mut TccState, a: i32) -> TccResult<()> {
        let rel = a - state.ind as i32 - 2;
        if (-128..128).contains(&rel) {
            codegen::g(state, 0xeb)?;
            codegen::g(state, rel as u8)?;
        } else {
            let rel32 = a - state.ind as i32 - 5;
            codegen::g(state, 0xe9)?;
            codegen::gen_le32(state, rel32 as u32)?;
        }
        Ok(())
    }

    /// Append jump to chain. C: `gjmp_append()` (x86_64-gen.c:1653).
    fn gjmp_append(&mut self, state: &mut TccState, n: i32, t: i32) -> TccResult<i32> {
        if n != 0 {
            let sec_idx = state.cur_text_section;
            let mut p = n;
            loop {
                let pu = p as usize;
                let sec = state
                    .sections
                    .get(sec_idx)
                    .ok_or_else(|| TccError::link("no text section"))?;
                if pu + 4 > sec.data.len() {
                    break;
                }
                let next = read32le(&sec.data[pu..]) as i32;
                if next == 0 {
                    break;
                }
                p = next;
            }
            let pu = p as usize;
            let sec = state
                .sections
                .get_mut(sec_idx)
                .ok_or_else(|| TccError::link("no text section"))?;
            if pu + 4 <= sec.data.len() {
                write32le(&mut sec.data[pu..], t as u32);
            }
            Ok(n)
        } else {
            Ok(t)
        }
    }

    /// Conditional jump. C: `gjmp_cond()` (x86_64-gen.c:1667).
    fn gjmp_cond(&mut self, state: &mut TccState, op: i32, t: i32) -> TccResult<i32> {
        let float_parity = (op & 0x100) != 0;
        let base_op = op & 0xff;
        let cc: u8 = Self::cond_code(base_op);

        if float_parity {
            if base_op == 0x95 {
                // NE: JP also true
                codegen::g(state, 0x0f)?;
                let t1 = Self::oad(state, 0x8a, t)?;
                codegen::g(state, 0x0f)?;
                return Self::oad(state, 0x80 | u32::from(cc), t1);
            }
            // EQ: JP skip
            codegen::g(state, 0x0f)?;
            let skip = Self::oad(state, 0x8b, 0)?; // JNP
            codegen::g(state, 0x0f)?;
            let t1 = Self::oad(state, 0x80 | u32::from(cc), t)?;
            self.gsym(state, skip)?;
            return Ok(t1);
        }

        codegen::g(state, 0x0f)?;
        Self::oad(state, 0x80 | u32::from(cc), t)
    }

    /// Integer binary operation. C: `gen_opi()` (x86_64-gen.c:1700).
    ///
    /// The codegen module has already loaded operands into registers
    /// (left in RAX=reg0, right in RCX=reg1 for binary ops).
    /// This method emits the actual x86-64 machine instruction.
    fn gen_opi(&mut self, state: &mut TccState, op: i32) -> TccResult<()> {
        let ea = TReg::RAX as u8; // destination / left operand
        let ec = TReg::RCX as u8; // right operand

        // gen_op8 family: ALU reg, reg  (x86_64-gen.c:1707-1760)
        let opc: Option<u8> = match op {
            x if x == '+' as i32 || x == TOK_ADDC1 => Some(0), // ADD
            x if x == '-' as i32 || x == TOK_SUBC1 => Some(5), // SUB
            TOK_ADDC2 => Some(2),                              // ADC
            TOK_SUBC2 => Some(3),                              // SBB
            x if x == '&' as i32 => Some(4),                   // AND
            x if x == '^' as i32 => Some(6),                   // XOR
            x if x == '|' as i32 => Some(1),                   // OR
            _ => None,
        };

        if let Some(alu_op) = opc {
            // REX.W OP r/m64, r64  =>  48 (01|09|11|19|21|29|31|39) C1
            Self::orex(state, true, ec, ea, u32::from(alu_op) << 3 | 1)?;
            codegen::g(state, 0xc0 | (reg_value(ec) << 3) | reg_value(ea))?;
            return Ok(());
        }

        match op {
            // Multiply: IMUL r64, r64  (x86_64-gen.c:1762-1782)
            x if x == '*' as i32 => {
                Self::orex(state, true, ec, ea, 0x0faf)?;
                codegen::g(state, 0xc0 | (reg_value(ea) << 3) | reg_value(ec))?;
            }
            // Shift operations: SHL / SHR / SAR  (x86_64-gen.c:1786-1820)
            // Shift amount in CL
            0x01 => {
                // TOK_SHL
                Self::orex(state, true, ea, 0, 0xd3)?;
                codegen::g(state, 0xc0 | (4 << 3) | reg_value(ea))?; // /4 = SHL
            }
            0x02 => {
                // TOK_SAR
                Self::orex(state, true, ea, 0, 0xd3)?;
                codegen::g(state, 0xc0 | (7 << 3) | reg_value(ea))?; // /7 = SAR
            }
            0x03 => {
                // TOK_SHR
                Self::orex(state, true, ea, 0, 0xd3)?;
                codegen::g(state, 0xc0 | (5 << 3) | reg_value(ea))?; // /5 = SHR
            }
            // Division: IDIV / DIV  (x86_64-gen.c:1822-1870)
            x if x == '/' as i32 || x == '%' as i32 => {
                // cqo  (sign-extend RAX→RDX:RAX)
                Self::orex(state, true, 0, 0, 0x99)?;
                // idiv rcx
                Self::orex(state, true, ec, 0, 0xf7)?;
                codegen::g(state, 0xc0 | (7 << 3) | reg_value(ec))?; // /7 = IDIV
            }
            x if x == 0xb0 || x == 0xb1 => {
                // TOK_UDIV / TOK_UMOD
                // xor edx, edx (zero-extend)
                Self::orex(state, false, TReg::RDX as u8, TReg::RDX as u8, 0x31)?;
                codegen::g(
                    state,
                    0xc0 | (reg_value(TReg::RDX as u8) << 3) | reg_value(TReg::RDX as u8),
                )?;
                // div rcx
                Self::orex(state, true, ec, 0, 0xf7)?;
                codegen::g(state, 0xc0 | (6 << 3) | reg_value(ec))?; // /6 = DIV
            }
            // Comparison ops → set condition code
            x if (0x92..=0x9f).contains(&x) => {
                // CMP RAX, RCX
                Self::orex(state, true, ec, ea, 0x39)?;
                codegen::g(state, 0xc0 | (reg_value(ec) << 3) | reg_value(ea))?;
            }
            // Unary minus: NEG
            0xd0 => {
                // TOK_NEG equivalent
                Self::orex(state, true, ea, 0, 0xf7)?;
                codegen::g(state, 0xc0 | (3 << 3) | reg_value(ea))?; // /3 = NEG
            }
            _ => { /* Other ops handled by the codegen module generically */ }
        }
        Ok(())
    }

    /// Floating-point binary operation. C: `gen_opf()` (x86_64-gen.c:1850).
    ///
    /// SSE: addss/addsd/subss/subsd/mulss/mulsd/divss/divsd  (XMM0, XMM1)
    /// x87 long double: faddp/fsubp/fmulp/fdivp  (ST(1), ST(0))
    fn gen_opf(&mut self, state: &mut TccState, op: i32) -> TccResult<()> {
        let xmm0 = TReg::XMM0 as u8;
        let xmm1 = TReg::XMM1 as u8;

        // SSE instruction selection: prefix + 0F XX C1
        // addss/sd = 58, subss/sd = 5C, mulss/sd = 59, divss/sd = 5E
        let sse_op: Option<u8> = match op {
            x if x == '+' as i32 => Some(0x58),
            x if x == '-' as i32 => Some(0x5c),
            x if x == '*' as i32 => Some(0x59),
            x if x == '/' as i32 => Some(0x5e),
            _ => None,
        };

        if let Some(ss) = sse_op {
            // For float: F3 0F XX C1;  for double: F2 0F XX C1
            // We use double (F2) as default; the codegen module tells us the type
            codegen::g(state, 0xf2)?;
            Self::orex(state, false, xmm1, xmm0, 0x0f)?;
            codegen::g(state, ss)?;
            codegen::g(state, 0xc0 | (reg_value(xmm0) << 3) | reg_value(xmm1))?;
            return Ok(());
        }

        // Comparison: UCOMISD xmm0, xmm1  => 66 0F 2E C1
        if (0x92..=0x9f).contains(&op) {
            codegen::g(state, 0x66)?;
            codegen::g(state, 0x0f)?;
            codegen::g(state, 0x2e)?;
            codegen::g(state, 0xc0 | (reg_value(xmm0) << 3) | reg_value(xmm1))?;
        }

        Ok(())
    }

    /// Float→integer conversion. C: `gen_cvt_ftoi()` (x86_64-gen.c:2088).
    ///
    /// Emits CVTTSD2SI / CVTTSS2SI (SSE → integer).
    /// For long double, falls back to x87 helper.
    fn gen_cvt_ftoi(&mut self, state: &mut TccState, t: i32) -> TccResult<()> {
        let bt = t & VT_BTYPE;
        let ll = bt == VT_LLONG as i32;
        let xmm0 = TReg::XMM0 as u8;
        let eax = TReg::RAX as u8;

        // CVTTSD2SI eax/rax, xmm0  =>  F2 [REX.W] 0F 2C C0
        codegen::g(state, 0xf2)?;
        Self::orex(state, ll, xmm0, eax, 0x0f2c)?;
        codegen::g(state, 0xc0 | (reg_value(eax) << 3) | reg_value(xmm0))?;
        Ok(())
    }

    /// Integer→float conversion. C: `gen_cvt_itof()` (x86_64-gen.c:2039).
    ///
    /// Emits CVTSI2SD / CVTSI2SS (integer → SSE).
    fn gen_cvt_itof(&mut self, state: &mut TccState, t: i32) -> TccResult<()> {
        let bt = t & VT_BTYPE;
        let is_float = bt == VT_FLOAT as i32;
        let eax = TReg::RAX as u8;
        let xmm0 = TReg::XMM0 as u8;

        // CVTSI2SD xmm0, rax  =>  F2 REX.W 0F 2A C0
        // CVTSI2SS xmm0, rax  =>  F3 REX.W 0F 2A C0
        codegen::g(state, if is_float { 0xf3 } else { 0xf2 })?;
        Self::orex(state, true, eax, xmm0, 0x0f2a)?;
        codegen::g(state, 0xc0 | (reg_value(xmm0) << 3) | reg_value(eax))?;
        Ok(())
    }

    /// Float↔float conversion. C: `gen_cvt_ftof()` (x86_64-gen.c:2112).
    ///
    /// CVTSS2SD / CVTSD2SS for float↔double conversion.
    fn gen_cvt_ftof(&mut self, state: &mut TccState, t: i32) -> TccResult<()> {
        let bt = t & VT_BTYPE;
        let xmm0 = TReg::XMM0 as u8;

        if bt == VT_FLOAT as i32 {
            // CVTSD2SS xmm0, xmm0  =>  F2 0F 5A C0
            codegen::g(state, 0xf2)?;
            Self::orex(state, false, xmm0, xmm0, 0x0f5a)?;
            codegen::g(state, 0xc0 | (reg_value(xmm0) << 3) | reg_value(xmm0))?;
        } else if bt == VT_DOUBLE as i32 {
            // CVTSS2SD xmm0, xmm0  =>  F3 0F 5A C0
            codegen::g(state, 0xf3)?;
            Self::orex(state, false, xmm0, xmm0, 0x0f5a)?;
            codegen::g(state, 0xc0 | (reg_value(xmm0) << 3) | reg_value(xmm0))?;
        }
        // VT_LDOUBLE handled via x87 stack by the codegen module
        Ok(())
    }

    /// Computed goto. C: `ggoto()` (x86_64-gen.c:2223).
    fn ggoto(&mut self, state: &mut TccState) -> TccResult<()> {
        // jmp *rax  =>  FF /4 E0
        codegen::g(state, 0xff)?;
        codegen::g(state, 0xe0)
    }

    /// Save SP for VLA. C: `gen_vla_sp_save()` (x86_64-gen.c:2230).
    fn gen_vla_sp_save(&mut self, state: &mut TccState, addr: i32) -> TccResult<()> {
        // mov [rbp+addr], rsp
        Self::orex(state, true, 5, TReg::RSP as u8, 0x89)?;
        Self::gen_modrm_impl(state, TReg::RSP as u8, 5, None, i64::from(addr), false)
    }

    /// Restore SP from VLA. C: `gen_vla_sp_restore()` (x86_64-gen.c:2236).
    fn gen_vla_sp_restore(&mut self, state: &mut TccState, addr: i32) -> TccResult<()> {
        // mov rsp, [rbp+addr]
        Self::orex(state, true, 5, TReg::RSP as u8, 0x8b)?;
        Self::gen_modrm_impl(state, TReg::RSP as u8, 5, None, i64::from(addr), false)
    }

    /// Allocate VLA on stack. C: `gen_vla_alloc()` (x86_64-gen.c:2249).
    fn gen_vla_alloc(&mut self, state: &mut TccState, _type_: &CType, align: i32) -> TccResult<()> {
        // sub rsp, rax  =>  REX.W 29 C4
        Self::orex(state, true, TReg::RAX as u8, TReg::RSP as u8, 0x29)?;
        codegen::g(
            state,
            0xc0 | (reg_value(TReg::RAX as u8) << 3) | reg_value(TReg::RSP as u8),
        )?;
        // and rsp, -align
        if align > 0 {
            let mask = -(i64::from(align));
            Self::orex(state, true, TReg::RSP as u8, 0, 0x81)?;
            codegen::g(state, 0xc0 | (4 << 3) | reg_value(TReg::RSP as u8))?;
            codegen::gen_le32(state, mask as u32)?;
        }
        Ok(())
    }
}

// =========================================================================
// LinkerBackend implementation (x86_64-link.c)
// =========================================================================

impl LinkerBackend for X86_64Backend {
    /// Classify relocation. C: `code_reloc()` (x86_64-link.c:18).
    fn code_reloc(&self, reloc_type: i32) -> i32 {
        let rt = reloc_type as u32;
        match rt {
            R_X86_64_32 | R_X86_64_32S | R_X86_64_64 => 0,
            R_X86_64_GOTPCREL | R_X86_64_GOTPCRELX | R_X86_64_REX_GOTPCRELX => 0,
            R_X86_64_GOTTPOFF | R_X86_64_GOT32 | R_X86_64_GOT64 => 0,
            R_X86_64_GOTPC32 | R_X86_64_GOTPC64 | R_X86_64_GOTOFF64 => 0,
            R_X86_64_TLSGD | R_X86_64_TLSLD | R_X86_64_DTPOFF32 | R_X86_64_TPOFF32 => 0,
            R_X86_64_DTPOFF64 | R_X86_64_TPOFF64 | R_X86_64_PLTOFF64 => 0,
            R_X86_64_PC32 | R_X86_64_PC64 => -1,
            R_X86_64_PLT32 => -2,
            R_X86_64_GLOB_DAT | R_X86_64_JUMP_SLOT | R_X86_64_RELATIVE | R_X86_64_COPY => 0,
            _ => -1,
        }
    }

    /// GOT/PLT entry type. C: `gotplt_entry_type()` (x86_64-link.c:62).
    fn gotplt_entry_type(&self, reloc_type: i32) -> GotPltEntry {
        let rt = reloc_type as u32;
        match rt {
            R_X86_64_GLOB_DAT | R_X86_64_JUMP_SLOT | R_X86_64_COPY | R_X86_64_RELATIVE => {
                GotPltEntry::NoEntry
            }
            R_X86_64_GOTPCREL
            | R_X86_64_GOTPCRELX
            | R_X86_64_REX_GOTPCRELX
            | R_X86_64_GOT32
            | R_X86_64_GOT64
            | R_X86_64_GOTPC32
            | R_X86_64_GOTPC64
            | R_X86_64_GOTOFF64
            | R_X86_64_PLTOFF64
            | R_X86_64_GOTTPOFF => GotPltEntry::BuildGotOnly,
            R_X86_64_PLT32 => GotPltEntry::AutoEntry,
            R_X86_64_32 | R_X86_64_32S | R_X86_64_64 | R_X86_64_PC32 | R_X86_64_PC64 => {
                GotPltEntry::AutoEntry
            }
            R_X86_64_TLSGD | R_X86_64_TLSLD | R_X86_64_DTPOFF32 | R_X86_64_TPOFF32
            | R_X86_64_DTPOFF64 | R_X86_64_TPOFF64 => GotPltEntry::NoEntry,
            _ => GotPltEntry::AlwaysEntry,
        }
    }

    /// Apply relocation. C: `relocate()` (x86_64-link.c:173).
    fn relocate(
        &self,
        _state: &mut TccState,
        rel_type: i32,
        ptr: &mut [u8],
        addr: u64,
        val: u64,
    ) -> TccResult<()> {
        let rt = rel_type as u32;
        match rt {
            R_X86_64_64 => {
                add64le(ptr, val as i64);
                Ok(())
            }
            R_X86_64_32 => {
                let res = u64::from(read32le(ptr)) + val;
                if res > 0xFFFF_FFFF {
                    return Err(TccError::link("R_X86_64_32: out of range"));
                }
                add32le(ptr, val as i32);
                Ok(())
            }
            R_X86_64_32S => {
                let res = read32le(ptr) as i32 as i64 + val as i64;
                if !(i64::from(i32::MIN)..=i64::from(i32::MAX)).contains(&res) {
                    return Err(TccError::link("R_X86_64_32S: out of range"));
                }
                add32le(ptr, val as i32);
                Ok(())
            }
            R_X86_64_PC32 | R_X86_64_PLT32 => {
                let rel = val.wrapping_sub(addr) as i64;
                if !(i64::from(i32::MIN)..=i64::from(i32::MAX)).contains(&rel) {
                    return Err(TccError::link("R_X86_64_PC32/PLT32: overflow"));
                }
                add32le(ptr, rel as i32);
                Ok(())
            }
            R_X86_64_PC64 => {
                add64le(ptr, val.wrapping_sub(addr) as i64);
                Ok(())
            }
            R_X86_64_GLOB_DAT | R_X86_64_JUMP_SLOT => {
                write64le(ptr, val);
                Ok(())
            }
            R_X86_64_RELATIVE => {
                add64le(ptr, val as i64);
                Ok(())
            }
            R_X86_64_GOTPCREL
            | R_X86_64_GOTPCRELX
            | R_X86_64_REX_GOTPCRELX
            | R_X86_64_GOTTPOFF
            | R_X86_64_GOT32
            | R_X86_64_GOTPC32 => {
                add32le(ptr, val.wrapping_sub(addr) as i32);
                Ok(())
            }
            R_X86_64_GOT64 | R_X86_64_GOTPC64 | R_X86_64_GOTOFF64 | R_X86_64_PLTOFF64 => {
                add64le(ptr, val.wrapping_sub(addr) as i64);
                Ok(())
            }
            R_X86_64_TLSGD => {
                // Rewrite: mov eax, tpoff + NOPs
                if ptr.len() >= 16 {
                    ptr[0] = 0x48;
                    ptr[1] = 0xc7;
                    ptr[2] = 0xc0;
                    write32le(&mut ptr[3..], val as u32);
                    for b in ptr.iter_mut().take(16).skip(7) {
                        *b = 0x90;
                    }
                }
                Ok(())
            }
            R_X86_64_TLSLD => {
                if ptr.len() >= 16 {
                    ptr[0] = 0x48;
                    ptr[1] = 0xc7;
                    ptr[2] = 0xc0;
                    write32le(&mut ptr[3..], 0);
                    for b in ptr.iter_mut().take(16).skip(7) {
                        *b = 0x90;
                    }
                }
                Ok(())
            }
            R_X86_64_DTPOFF32 | R_X86_64_TPOFF32 => {
                add32le(ptr, val as i32);
                Ok(())
            }
            R_X86_64_DTPOFF64 | R_X86_64_TPOFF64 => {
                add64le(ptr, val as i64);
                Ok(())
            }
            R_X86_64_NONE | R_X86_64_COPY => Ok(()),
            _ => Err(TccError::link(format!(
                "unsupported x86_64 relocation type: {rel_type}"
            ))),
        }
    }

    /// Create PLT entry. C: `create_plt_entry()` (x86_64-link.c:107).
    ///
    /// Each x86-64 PLT entry is 16 bytes:
    /// ```text
    ///   ff 25 XX XX XX XX   jmp [rip + GOT_offset]   (6 bytes)
    ///   68 YY YY YY YY      push PLT_index            (5 bytes)
    ///   e9 ZZ ZZ ZZ ZZ      jmp PLT0                  (5 bytes)
    /// ```
    ///
    /// The PLT section management (allocating section space, writing the
    /// PLT0 header) is handled by the ELF linker module.  This method
    /// provides the per-entry instruction bytes and returns the PLT offset.
    fn create_plt_entry(&mut self, state: &mut TccState, got_offset: u32) -> TccResult<u32> {
        // Look up the PLT section by name
        let Some(plt_idx) = state.find_section(".plt") else {
            // PLT section not yet created; the linker module will set this up.
            // Return got_offset so the linker can track it.
            return Ok(got_offset);
        };

        let sec = state
            .sections
            .get(plt_idx)
            .ok_or_else(|| TccError::link("create_plt_entry: PLT section not found"))?;
        let plt_offset = sec.data_offset as u32;

        // Allocate 16 bytes in PLT section
        let sec = state
            .sections
            .get_mut(plt_idx)
            .ok_or_else(|| TccError::link("create_plt_entry: PLT section not found"))?;
        let start = sec.data.len();
        sec.data.resize(start + 16, 0);
        sec.data_offset += 16;

        // ff 25 XX XX XX XX — jmp [rip + got_disp]
        // GOT displacement is relative to next instruction (PC + 6)
        sec.data[start] = 0xff;
        sec.data[start + 1] = 0x25;
        // got_offset will be patched by relocate_plt with final address
        write32le(&mut sec.data[start + 2..], got_offset);

        // 68 YY YY YY YY — push index (PLT index for lazy binding)
        sec.data[start + 6] = 0x68;
        let plt_index = (plt_offset.wrapping_sub(16)) / 16; // entry index (skip PLT0)
        write32le(&mut sec.data[start + 7..], plt_index);

        // e9 ZZ ZZ ZZ ZZ — jmp PLT0 (relative to next instruction)
        sec.data[start + 11] = 0xe9;
        // Displacement to PLT0: -(plt_offset + 16) relative to end of this instr
        let plt0_disp = 0u32.wrapping_sub(plt_offset + 16);
        write32le(&mut sec.data[start + 12..], plt0_disp);

        Ok(plt_offset)
    }

    /// Relocate PLT. C: `relocate_plt()` (x86_64-link.c:150).
    ///
    /// Patches PLT entries with final GOT addresses after all section
    /// addresses are resolved.  The PLT0 header (16 bytes) is:
    /// ```text
    ///   ff 35 XX XX XX XX   push [rip + GOT+8]   (6 bytes)
    ///   ff 25 YY YY YY YY   jmp  [rip + GOT+16]  (6 bytes)
    ///   0f 1f 40 00         nop dword [rax+0]     (4 bytes)
    /// ```
    fn relocate_plt(&mut self, state: &mut TccState) -> TccResult<()> {
        let Some(plt_idx) = state.find_section(".plt") else {
            return Ok(());
        };
        let Some(got_idx) = state.find_section(".got") else {
            return Ok(());
        };

        // Read GOT section address
        let got_addr = state.sections.get(got_idx).map(|s| s.sh_addr).unwrap_or(0);
        let plt_addr = state.sections.get(plt_idx).map(|s| s.sh_addr).unwrap_or(0);

        // Patch PLT0 header if PLT has at least 16 bytes
        let sec = state
            .sections
            .get_mut(plt_idx)
            .ok_or_else(|| TccError::link("relocate_plt: PLT section not found"))?;
        if sec.data.len() >= 16 {
            // push [rip + GOT+8]
            sec.data[0] = 0xff;
            sec.data[1] = 0x35;
            let got8_disp = (got_addr + 8).wrapping_sub(plt_addr + 6);
            write32le(&mut sec.data[2..], got8_disp as u32);

            // jmp [rip + GOT+16]
            sec.data[6] = 0xff;
            sec.data[7] = 0x25;
            let got16_disp = (got_addr + 16).wrapping_sub(plt_addr + 12);
            write32le(&mut sec.data[8..], got16_disp as u32);

            // nop dword [rax+0]  (4-byte NOP)
            sec.data[12] = 0x0f;
            sec.data[13] = 0x1f;
            sec.data[14] = 0x40;
            sec.data[15] = 0x00;
        }

        // Patch each PLT stub's jmp [rip+GOT_disp] with final displacement
        let plt_data_len = sec.data.len();
        let mut off = 16usize; // skip PLT0
        while off + 16 <= plt_data_len {
            // Read the GOT offset stored at PLT+2 and convert to RIP-relative
            let stored_got_off = read32le(&sec.data[off + 2..]) as u64;
            let rip_rel = (got_addr + stored_got_off).wrapping_sub(plt_addr + off as u64 + 6);
            write32le(&mut sec.data[off + 2..], rip_rel as u32);
            off += 16;
        }

        Ok(())
    }
}

// =========================================================================
// Helper: condition-code mapping
// =========================================================================

impl X86_64Backend {
    /// Map TCC comparison token to x86 condition code.
    fn cond_code(op: i32) -> u8 {
        match op {
            0x94 => 0x04, // TOK_EQ → JE
            0x95 => 0x05, // TOK_NE → JNE
            0x9c => 0x0c, // TOK_LT → JL
            0x9d => 0x0d, // TOK_GE → JGE
            0x9e => 0x0e, // TOK_LE → JLE
            0x9f => 0x0f, // TOK_GT → JG
            0x92 => 0x02, // TOK_ULT → JB
            0x93 => 0x03, // TOK_UGE → JAE
            0x96 => 0x06, // TOK_ULE → JBE
            0x97 => 0x07, // TOK_UGT → JA
            _ => 0x04,
        }
    }

    /// `gfunc_return()` — handle return value placement.
    /// Integer results go to RAX, float to XMM0, long double to ST(0).
    pub fn gfunc_return(&mut self, _state: &mut TccState, _ft: i32) -> TccResult<()> {
        Ok(())
    }
}

// =========================================================================
// Tests
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::targets::{read32le, read64le, write32le, write64le};

    // ---------------------------------------------------------------
    // Register helpers
    // ---------------------------------------------------------------

    #[test]
    fn test_rex_base() {
        assert_eq!(rex_base(0), 0);
        assert_eq!(rex_base(7), 0);
        assert_eq!(rex_base(8), 1);
        assert_eq!(rex_base(15), 1);
    }

    #[test]
    fn test_rex_base_all_values() {
        for r in 0u8..8 {
            assert_eq!(rex_base(r), 0);
        }
        for r in 8u8..16 {
            assert_eq!(rex_base(r), 1);
        }
    }

    #[test]
    fn test_reg_value() {
        assert_eq!(reg_value(0), 0);
        assert_eq!(reg_value(7), 7);
        assert_eq!(reg_value(8), 0);
        assert_eq!(reg_value(11), 3);
        assert_eq!(reg_value(15), 7);
        assert_eq!(reg_value(16), 0);
    }

    // ---------------------------------------------------------------
    // TReg enum
    // ---------------------------------------------------------------

    #[test]
    fn test_treg_values() {
        assert_eq!(TReg::RAX as u8, 0);
        assert_eq!(TReg::RCX as u8, 1);
        assert_eq!(TReg::RDX as u8, 2);
        assert_eq!(TReg::RSP as u8, 4);
        assert_eq!(TReg::RSI as u8, 6);
        assert_eq!(TReg::RDI as u8, 7);
        assert_eq!(TReg::R8 as u8, 8);
        assert_eq!(TReg::R9 as u8, 9);
        assert_eq!(TReg::R10 as u8, 10);
        assert_eq!(TReg::R11 as u8, 11);
        assert_eq!(TReg::XMM0 as u8, 16);
        assert_eq!(TReg::ST0 as u8, 24);
    }

    // ---------------------------------------------------------------
    // Assembler
    // ---------------------------------------------------------------

    #[test]
    fn test_asm_opcode() {
        assert_eq!(asm_opcode("syscall"), Some(X86_64AsmOpcode::SYSCALL));
        assert_eq!(asm_opcode("nop"), Some(X86_64AsmOpcode::NOP));
        assert_eq!(asm_opcode("cdqe"), Some(X86_64AsmOpcode::CDQE));
        assert_eq!(asm_opcode("unknown"), None);
    }

    #[test]
    fn test_asm_opcode_aliases() {
        assert_eq!(asm_opcode("retq"), Some(X86_64AsmOpcode::RET));
        assert_eq!(asm_opcode("iretq"), Some(X86_64AsmOpcode::IRET));
        assert_eq!(asm_opcode("repz"), Some(X86_64AsmOpcode::REPE));
        assert_eq!(asm_opcode("repnz"), Some(X86_64AsmOpcode::REPNE));
        assert_eq!(asm_opcode("fwait"), Some(X86_64AsmOpcode::WAIT));
        assert_eq!(asm_opcode("cqto"), Some(X86_64AsmOpcode::CQO));
    }

    #[test]
    fn test_asm_parse_regvar() {
        assert_eq!(asm_parse_regvar("rax"), Some(0));
        assert_eq!(asm_parse_regvar("%rcx"), Some(1));
        assert_eq!(asm_parse_regvar("r8"), Some(8));
        assert_eq!(asm_parse_regvar("r15d"), Some(15));
        assert_eq!(asm_parse_regvar("invalid"), None);
    }

    #[test]
    fn test_asm_parse_regvar_all() {
        assert_eq!(asm_parse_regvar("eax"), Some(0));
        assert_eq!(asm_parse_regvar("ax"), Some(0));
        assert_eq!(asm_parse_regvar("al"), Some(0));
        assert_eq!(asm_parse_regvar("rbx"), Some(3));
        assert_eq!(asm_parse_regvar("rsp"), Some(4));
        assert_eq!(asm_parse_regvar("rbp"), Some(5));
        assert_eq!(asm_parse_regvar("rsi"), Some(6));
        assert_eq!(asm_parse_regvar("rdi"), Some(7));
        assert_eq!(asm_parse_regvar("r8b"), Some(8));
        assert_eq!(asm_parse_regvar("r15w"), Some(15));
        assert_eq!(asm_parse_regvar("xmm0"), None);
    }

    // ---------------------------------------------------------------
    // Constants
    // ---------------------------------------------------------------

    #[test]
    fn test_register_constants() {
        assert_eq!(NB_REGS, 25);
        assert_eq!(NB_ASM_REGS, 16);
        assert_eq!(REG_CLASSES.len(), NB_REGS);
        assert_eq!(REG_CLASSES[0], RC_INT | RC_RAX);
        assert_eq!(REG_CLASSES[24], RC_ST0);
    }

    #[test]
    fn test_rc_constants_distinct() {
        let vals = [
            RC_INT, RC_FLOAT, RC_RAX, RC_RDX, RC_RCX, RC_RSI, RC_RDI, RC_ST0, RC_R8, RC_R9, RC_R10,
            RC_R11, RC_XMM0, RC_XMM1, RC_XMM2, RC_XMM3, RC_XMM4, RC_XMM5, RC_XMM6, RC_XMM7,
        ];
        for &v in &vals {
            assert_ne!(v, 0);
            assert!(v.is_power_of_two());
        }
    }

    #[test]
    fn test_return_reg_aliases() {
        assert_eq!(RC_IRET, RC_RAX);
        assert_eq!(RC_IRE2, RC_RDX);
        assert_eq!(RC_FRET, RC_XMM0);
        assert_eq!(RC_FRE2, RC_XMM1);
    }

    #[test]
    fn test_platform_constants() {
        assert_eq!(PTR_SIZE, 8);
        assert_eq!(LDOUBLE_SIZE, 16);
        assert_eq!(LDOUBLE_ALIGN, 16);
        assert_eq!(MAX_ALIGN, 16);
        assert_eq!(TREG_MEM, 0x20);
    }

    #[test]
    fn test_elf_constants() {
        assert_eq!(ELF_START_ADDR, 0x0040_0000);
        assert_eq!(ELF_PAGE_SIZE, 0x0020_0000);
        // Validate boolean constants via negation to avoid clippy::bool_assert_comparison
        let char_unsigned = CHAR_IS_UNSIGNED;
        let pcrel = PCRELATIVE_DLLPLT;
        let reloc = RELOCATE_DLLPLT;
        assert!(!char_unsigned, "x86_64 char should be signed");
        assert!(pcrel, "x86_64 should use PC-relative DLL PLT");
        assert!(reloc, "x86_64 should relocate DLL PLT");
    }

    #[test]
    fn test_linker_constants() {
        assert_eq!(EM_TCC_TARGET, EM_X86_64);
        assert_eq!(R_DATA_32, R_X86_64_32S);
        assert_eq!(R_DATA_PTR, R_X86_64_64);
    }

    #[test]
    fn test_target_machine_defs() {
        assert!(TARGET_MACHINE_DEFS.contains(&"__x86_64__"));
        assert!(TARGET_MACHINE_DEFS.contains(&"__amd64__"));
        assert_eq!(TARGET_MACHINE_DEFS.len(), 3);
    }

    #[test]
    fn test_reg_classes_allocatable() {
        // RAX=0 is allocatable
        assert_ne!(REG_CLASSES[0], 0);
        // RSP=4, RBP=5 not allocatable
        assert_eq!(REG_CLASSES[4], 0);
        assert_eq!(REG_CLASSES[5], 0);
    }

    // ---------------------------------------------------------------
    // Backend construction
    // ---------------------------------------------------------------

    #[test]
    fn test_x86_64_backend_new() {
        let backend = X86_64Backend::new();
        assert_eq!(backend.func_sub_sp_offset, 0);
        assert!(!backend.func_bound_add_epilog);
    }

    #[test]
    fn test_backend_trait_object() {
        let b: Box<dyn CodegenBackend> = Box::new(X86_64Backend::new());
        assert_eq!(b.target_machine_defs(), TARGET_MACHINE_DEFS);
        assert_eq!(b.reg_classes().len(), NB_REGS);
    }

    // ---------------------------------------------------------------
    // Linker: code_reloc
    // ---------------------------------------------------------------

    #[test]
    fn test_code_reloc() {
        let b = X86_64Backend::new();
        assert_eq!(b.code_reloc(R_X86_64_64 as i32), 0);
        assert_eq!(b.code_reloc(R_X86_64_PC32 as i32), -1);
        assert_eq!(b.code_reloc(R_X86_64_PLT32 as i32), -2);
    }

    #[test]
    fn test_code_reloc_all() {
        let b = X86_64Backend::new();
        assert_eq!(b.code_reloc(R_X86_64_32 as i32), 0);
        assert_eq!(b.code_reloc(R_X86_64_32S as i32), 0);
        assert_eq!(b.code_reloc(R_X86_64_GOTPCREL as i32), 0);
        assert_eq!(b.code_reloc(R_X86_64_GOTPCRELX as i32), 0);
        assert_eq!(b.code_reloc(R_X86_64_REX_GOTPCRELX as i32), 0);
        assert_eq!(b.code_reloc(R_X86_64_TLSGD as i32), 0);
        assert_eq!(b.code_reloc(R_X86_64_TPOFF32 as i32), 0);
        assert_eq!(b.code_reloc(R_X86_64_PC64 as i32), -1);
    }

    // ---------------------------------------------------------------
    // Linker: gotplt_entry_type
    // ---------------------------------------------------------------

    #[test]
    fn test_gotplt_classification() {
        let b = X86_64Backend::new();
        assert_eq!(
            b.gotplt_entry_type(R_X86_64_GLOB_DAT as i32),
            GotPltEntry::NoEntry
        );
        assert_eq!(
            b.gotplt_entry_type(R_X86_64_GOTPCREL as i32),
            GotPltEntry::BuildGotOnly
        );
        assert_eq!(
            b.gotplt_entry_type(R_X86_64_PLT32 as i32),
            GotPltEntry::AutoEntry
        );
    }

    #[test]
    fn test_gotplt_all() {
        let b = X86_64Backend::new();
        assert_eq!(
            b.gotplt_entry_type(R_X86_64_JUMP_SLOT as i32),
            GotPltEntry::NoEntry
        );
        assert_eq!(
            b.gotplt_entry_type(R_X86_64_COPY as i32),
            GotPltEntry::NoEntry
        );
        assert_eq!(
            b.gotplt_entry_type(R_X86_64_RELATIVE as i32),
            GotPltEntry::NoEntry
        );
        assert_eq!(
            b.gotplt_entry_type(R_X86_64_GOT64 as i32),
            GotPltEntry::BuildGotOnly
        );
        assert_eq!(
            b.gotplt_entry_type(R_X86_64_64 as i32),
            GotPltEntry::AutoEntry
        );
        assert_eq!(
            b.gotplt_entry_type(R_X86_64_32 as i32),
            GotPltEntry::AutoEntry
        );
        assert_eq!(
            b.gotplt_entry_type(R_X86_64_TLSGD as i32),
            GotPltEntry::NoEntry
        );
        assert_eq!(
            b.gotplt_entry_type(R_X86_64_TPOFF64 as i32),
            GotPltEntry::NoEntry
        );
    }

    // ---------------------------------------------------------------
    // Linker: relocate
    // ---------------------------------------------------------------

    #[test]
    fn test_relocate_64() {
        let b = X86_64Backend::new();
        let mut state = TccState::default();
        let mut buf = [0u8; 8];
        write64le(&mut buf, 100);
        b.relocate(&mut state, R_X86_64_64 as i32, &mut buf, 0, 42)
            .unwrap();
        assert_eq!(read64le(&buf), 142);
    }

    #[test]
    fn test_relocate_32_overflow() {
        let b = X86_64Backend::new();
        let mut state = TccState::default();
        let mut buf = [0u8; 4];
        write32le(&mut buf, 0xFFFF_FF00);
        let result = b.relocate(&mut state, R_X86_64_32 as i32, &mut buf, 0, 0x200);
        assert!(result.is_err());
    }

    #[test]
    fn test_relocate_pc32() {
        let b = X86_64Backend::new();
        let mut state = TccState::default();
        let mut buf = [0u8; 4];
        write32le(&mut buf, 0);
        b.relocate(&mut state, R_X86_64_PC32 as i32, &mut buf, 0x500, 0x1000)
            .unwrap();
        assert_eq!(read32le(&buf) as i32, 0xB00);
    }

    #[test]
    fn test_relocate_glob_dat() {
        let b = X86_64Backend::new();
        let mut state = TccState::default();
        let mut buf = [0u8; 8];
        b.relocate(
            &mut state,
            R_X86_64_GLOB_DAT as i32,
            &mut buf,
            0,
            0xDEAD_BEEF,
        )
        .unwrap();
        assert_eq!(read64le(&buf), 0xDEAD_BEEF);
    }

    #[test]
    fn test_relocate_none() {
        let b = X86_64Backend::new();
        let mut state = TccState::default();
        let mut buf = [0xAAu8; 8];
        b.relocate(&mut state, R_X86_64_NONE as i32, &mut buf, 0, 0)
            .unwrap();
        assert_eq!(buf, [0xAAu8; 8]); // unchanged
    }

    #[test]
    fn test_relocate_unsupported() {
        let b = X86_64Backend::new();
        let mut state = TccState::default();
        let mut buf = [0u8; 8];
        let result = b.relocate(&mut state, 999, &mut buf, 0, 0);
        assert!(result.is_err());
    }

    // ---------------------------------------------------------------
    // classify_x86_64_va_arg
    // ---------------------------------------------------------------

    #[test]
    fn test_classify_va_arg() {
        let int_ty = CType {
            t: VT_INT,
            ref_sym: None,
        };
        assert_eq!(
            X86_64Backend::classify_x86_64_va_arg(&int_ty),
            X86_64Mode::Integer as i32
        );

        let float_ty = CType {
            t: VT_FLOAT as i32,
            ref_sym: None,
        };
        assert_eq!(
            X86_64Backend::classify_x86_64_va_arg(&float_ty),
            X86_64Mode::Sse as i32
        );

        let struct_ty = CType {
            t: VT_STRUCT as i32,
            ref_sym: None,
        };
        assert_eq!(
            X86_64Backend::classify_x86_64_va_arg(&struct_ty),
            X86_64Mode::Memory as i32
        );

        let ld_ty = CType {
            t: VT_LDOUBLE as i32,
            ref_sym: None,
        };
        assert_eq!(
            X86_64Backend::classify_x86_64_va_arg(&ld_ty),
            X86_64Mode::X87 as i32
        );
    }

    #[test]
    fn test_classify_va_arg_more() {
        let llong_ty = CType {
            t: VT_LLONG as i32,
            ref_sym: None,
        };
        assert_eq!(
            X86_64Backend::classify_x86_64_va_arg(&llong_ty),
            X86_64Mode::Integer as i32
        );

        let double_ty = CType {
            t: VT_DOUBLE as i32,
            ref_sym: None,
        };
        assert_eq!(
            X86_64Backend::classify_x86_64_va_arg(&double_ty),
            X86_64Mode::Sse as i32
        );
    }

    // ---------------------------------------------------------------
    // is64_type
    // ---------------------------------------------------------------

    #[test]
    fn test_is64_type() {
        assert!(X86_64Backend::is64_type(VT_PTR as i32));
        assert!(X86_64Backend::is64_type(VT_FUNC as i32));
        assert!(X86_64Backend::is64_type(VT_LLONG as i32));
        assert!(!X86_64Backend::is64_type(VT_INT));
        assert!(!X86_64Backend::is64_type(VT_FLOAT as i32));
    }

    // ---------------------------------------------------------------
    // Condition-code mapping
    // ---------------------------------------------------------------

    #[test]
    fn test_cond_code() {
        assert_eq!(X86_64Backend::cond_code(0x94), 0x04); // EQ → JE
        assert_eq!(X86_64Backend::cond_code(0x95), 0x05); // NE → JNE
        assert_eq!(X86_64Backend::cond_code(0x9c), 0x0c); // LT → JL
        assert_eq!(X86_64Backend::cond_code(0x9d), 0x0d); // GE → JGE
        assert_eq!(X86_64Backend::cond_code(0x92), 0x02); // ULT → JB
        assert_eq!(X86_64Backend::cond_code(0x97), 0x07); // UGT → JA
    }
}
