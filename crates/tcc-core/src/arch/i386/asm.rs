//! x86/x86_64 assembly encoding — instruction encoding, operand parsing,
//! opcode table lookup, inline assembly constraint handling.
//!
//! Port of `i386-asm.c` (1,757 lines) and `i386-asm.h` (490 lines).
//! This module is shared between i386 and x86_64 backends.
//! x86_64-specific features are gated behind `#[cfg(feature = "x86_64")]`.
//!
//! # Instruction Encoding
//!
//! x86 instructions are variable-length (1-15 bytes) and encoded as:
//! `[prefix] [REX] opcode [ModR/M] [SIB] [displacement] [immediate]`
//!
//! This module builds on the opcode tables defined in [`super::tokens`].

use crate::error::{TccError, TccResult};
use crate::types::{
    SValue, Section,
    VT_CONST, VT_LOCAL, VT_VALMASK,
};
use crate::arch::i386::{
    NB_ASM_REGS, TREG_EAX, TREG_ECX, TREG_EDX, TREG_EBX,
};
use crate::arch::i386::tokens::{
    OpcodeEntry, X86Instruction, X86Register,
    OPCODE_TABLE,
    instruction_name,
    lookup_all_opcodes, suffix_size,
    // OP_* bitmasks
    OP_MMX, OP_SSE, OP_CR, OP_TR, OP_DB, OP_SEG, OP_ST,
    OP_IM8, OP_IM8S, OP_IM16, OP_IM32,
    OP_EAX, OP_ST0, OP_CL, OP_DX,
};
use crate::assembler::{ExprValue, AsmOperand};
use crate::elf::{put_elf_reloca, R_DATA_32};
use crate::TCCState;

// Re-export constants that the schema requires as exports from this module.
// These are primarily defined in tokens.rs and re-exported here for consumers.
pub use crate::arch::i386::tokens::{
    MAX_OPERANDS, OPC_B, OPC_WL, OPC_BWL, OPC_REG, OPC_MODRM,
    OPC_SHIFT, OPC_ARITH, OPC_FARITH, OPC_TEST, OPC_0F01,
    OPC_0F, OPC_48, OPC_FWAIT, OPCT_MASK, OPC_GROUP_SHIFT,
    OP_REG8, OP_REG16, OP_REG32, OP_EA, OP_INDIR, OP_ADDR,
    TEST_BITS, NB_TEST_OPCODES, OP0_CODES,
    SEGMENT_PREFIXES,
};

// =============================================================================
// Module-level constants
// =============================================================================

/// Number of operand size suffixes + 1.
/// i386: b, w, l → NBWLX = 4
/// x86_64: b, w, l, q → NBWLX = 5
#[cfg(feature = "x86_64")]
pub const NBWLX: usize = 5;
#[cfg(not(feature = "x86_64"))]
pub const NBWLX: usize = 4;

/// x86_64-specific OPC_WLQ flag (accepts w, l, q suffixes).
#[cfg(feature = "x86_64")]
pub const OPC_WLQ: u16 = 0x1000;
/// x86_64-specific OPC_BWLQ flag (accepts b, w, l, q suffixes).
#[cfg(feature = "x86_64")]
pub const OPC_BWLQ: u16 = OPC_B | OPC_WLQ;

/// x86_64-specific operand types.
#[cfg(feature = "x86_64")]
pub const OPT_REG64: u8 = 3;
#[cfg(feature = "x86_64")]
pub const OP_REG64: u32 = 1 << (OPT_REG64 as u32);
#[cfg(feature = "x86_64")]
pub const OPT_REG8_LOW: u8 = 11;
#[cfg(feature = "x86_64")]
pub const OP_REG8_LOW: u32 = 1 << (OPT_REG8_LOW as u32);
#[cfg(feature = "x86_64")]
pub const OPT_IM64: u8 = 17;
#[cfg(feature = "x86_64")]
pub const OP_IM64: u32 = 1 << (OPT_IM64 as u32);

/// OPT_EA flag: combined effective-address indicator ORed with base type
/// in OpcodeEntry.op_type fields.
pub const OPT_EA: u32 = 0x80;

/// Combined operand type masks.
pub const OP_IM: u32 = OP_IM8 | OP_IM16 | OP_IM32;
pub const OP_REG: u32 = OP_REG8 | OP_REG16 | OP_REG32;
pub const OP_REGW: u32 = OP_REG16 | OP_REG32;
pub const OP_IMW: u32 = OP_IM16 | OP_IM32;
pub const OP_MMXSSE: u32 = OP_MMX | OP_SSE;

/// Map register type (OPT_REG8..OPT_ST) to operand byte size.
/// Index: register type enum value. Value: size in bytes (1, 2, 4, 8, 10).
/// From i386-asm.c line 170.
pub const REG_TO_SIZE: [u8; 9] = [
    0,  // OPT_REG8 → 2^0 = 1 byte
    1,  // OPT_REG16 → 2^1 = 2 bytes
    2,  // OPT_REG32 → 2^2 = 4 bytes
    3,  // x86_64: OPT_REG64 → 2^3 = 8 bytes (i386: unused)
    0,  // OPT_MMX → N/A (treated as 0)
    0,  // OPT_SSE → N/A (treated as 0)
    0,  // OPT_CR → N/A (treated as 0)
    0,  // OPT_TR → N/A (treated as 0)
    0,  // OPT_DB → N/A (treated as 0)
];

// =============================================================================
// OperandType — Assembly operand type classification
// =============================================================================

/// Assembly operand types (from i386-asm.c lines 63-105).
///
/// These are logical categories for assembly operand classification.
/// The actual bit indices used in OP_* bitmask constants are defined as
/// OPT_* constants in `tokens.rs` and may differ between i386 and x86_64
/// (x86_64 inserts Reg64 at index 3, shifting subsequent indices).
///
/// This enum provides named variants for documentation and matching purposes.
/// For bitmask operations, use the OPT_* constants and OP_* bitmask values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperandType {
    /// 8-bit register (al, cl, dl, bl, ah, ch, dh, bh)
    Reg8,
    /// 16-bit register (ax, cx, dx, bx, sp, bp, si, di)
    Reg16,
    /// 32-bit register (eax...edi)
    Reg32,
    /// 64-bit register (rax...rdi, r8-r15) — x86_64 only
    Reg64,
    /// MMX register (mm0-mm7)
    Mmx,
    /// SSE register (xmm0-xmm15)
    Sse,
    /// Control register (cr0-cr7)
    Cr,
    /// Test register (tr0-tr7)
    Tr,
    /// Debug register (db0-db7 / dr0-dr7)
    Db,
    /// Segment register (es, cs, ss, ds, fs, gs)
    Seg,
    /// FPU stack register (st(0)-st(7))
    St,
    /// 8-bit low register (spl, bpl, sil, dil) — x86_64 only
    Reg8Low,
    /// 8-bit immediate
    Im8,
    /// Sign-extended 8-bit immediate
    Im8S,
    /// 16-bit immediate
    Im16,
    /// 32-bit immediate
    Im32,
    /// 64-bit immediate — x86_64 only
    Im64,
    /// %al/%ax/%eax/%rax accumulator
    Eax,
    /// %st(0) FPU top
    St0,
    /// %cl register
    Cl,
    /// %dx register
    Dx,
    /// EA with only offset (direct address)
    Addr,
    /// *(expr) indirect
    Indir,
    /// IM8 | IM16 | IM32 (composite)
    Im,
    /// REG8 | REG16 | REG32 [| REG64] (composite)
    Reg,
    /// REG16 | REG32 [| REG64] (composite)
    RegW,
    /// IM16 | IM32 (composite)
    ImW,
    /// MMX | SSE (composite)
    MmxSse,
    /// Effective address (register or memory)
    Ea,
}

// =============================================================================
// AsmInstr — Assembly instruction table entry (type alias)
// =============================================================================

/// Assembly instruction table entry.
/// This is a type alias for `OpcodeEntry` from `tokens.rs` which
/// already defines the complete instruction encoding table.
pub type AsmInstr = OpcodeEntry;

/// Reference to the complete x86 instruction opcode table.
/// Source: i386-asm.h (490 lines) — all DEF_ASM_OP entries.
pub static ASM_INSTRS: &[AsmInstr] = OPCODE_TABLE;

// =============================================================================
// Operand — Parsed assembly operand
// =============================================================================

/// Parsed assembly operand with register, memory, and immediate info.
/// From i386-asm.c lines 162-168.
#[derive(Debug, Clone)]
pub struct Operand {
    /// Operand type bitmask (OP_REG8, OP_IM32, OP_EA, etc.)
    pub typ: u32,
    /// Register number (-1 if no register)
    pub reg: i32,
    /// Index register for SIB encoding (-1 if none)
    pub reg2: i32,
    /// SIB scale factor: 0=1x, 1=2x, 2=4x, 3=8x
    pub shift: u8,
    /// Expression value for immediates and displacements
    pub e: ExprValue,
}

impl Default for Operand {
    fn default() -> Self {
        Operand {
            typ: 0,
            reg: -1,
            reg2: -1,
            shift: 0,
            e: ExprValue::zero(),
        }
    }
}

impl Operand {
    /// Create a new default operand.
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if this operand is a register operand.
    pub fn is_reg(&self) -> bool {
        (self.typ & OP_REG) != 0
    }

    /// Check if this operand is an immediate operand.
    pub fn is_imm(&self) -> bool {
        (self.typ & OP_IM) != 0
    }

    /// Check if this operand is a memory operand.
    pub fn is_mem(&self) -> bool {
        (self.typ & (OP_ADDR | OP_INDIR)) != 0
    }
}

// =============================================================================
// REX prefix constants (x86_64 only)
// =============================================================================

/// REX prefix base value (0100xxxx)
#[cfg(feature = "x86_64")]
const REX_BASE: u8 = 0x40;
/// REX.W bit — 64-bit operand size
#[cfg(feature = "x86_64")]
const REX_W: u8 = 0x08;
/// REX.R bit — extends ModRM reg field
#[cfg(feature = "x86_64")]
const REX_R: u8 = 0x04;
/// REX.X bit — extends SIB index field
#[cfg(feature = "x86_64")]
const REX_X: u8 = 0x02;
/// REX.B bit — extends ModRM r/m, SIB base, or opcode reg field
#[cfg(feature = "x86_64")]
const REX_B: u8 = 0x01;

// =============================================================================
// Internal Helper: Emit bytes to section
// =============================================================================

/// Emit a single byte to the current text section at the current code offset.
/// Advances `ind` by 1.
fn emit_byte(section: &mut Section, ind: &mut usize, byte: u8) {
    if *ind >= section.data.len() {
        section.data.resize(*ind + 1, 0);
    }
    section.data[*ind] = byte;
    *ind += 1;
    section.data_offset = *ind;
}

/// Emit a 16-bit little-endian value to the current section.
fn emit_le16(section: &mut Section, ind: &mut usize, val: u16) {
    let bytes = val.to_le_bytes();
    for &b in &bytes {
        emit_byte(section, ind, b);
    }
}

/// Emit a 32-bit little-endian value to the current section.
fn emit_le32(section: &mut Section, ind: &mut usize, val: u32) {
    let bytes = val.to_le_bytes();
    for &b in &bytes {
        emit_byte(section, ind, b);
    }
}

/// Emit a 64-bit little-endian value to the current section.
#[cfg(feature = "x86_64")]
fn emit_le64(section: &mut Section, ind: &mut usize, val: u64) {
    let bytes = val.to_le_bytes();
    for &b in &bytes {
        emit_byte(section, ind, b);
    }
}

// =============================================================================
// Helper: get_reg_shift
// =============================================================================

/// Parse and return the scale factor shift (0-3) for SIB byte.
/// The scale factor in assembly syntax is 1, 2, 4, or 8, mapped to
/// shift values 0, 1, 2, 3 respectively.
/// Source: i386-asm.c line 260
fn get_reg_shift(scale: i64) -> TccResult<u8> {
    match scale {
        1 => Ok(0),
        2 => Ok(1),
        4 => Ok(2),
        8 => Ok(3),
        _ => Err(TccError::asm(
            String::new(), 0,
            format!("invalid scale factor: {}, expected 1, 2, 4, or 8", scale),
        )),
    }
}

// =============================================================================
// Helper: asm_parse_numeric_reg
// =============================================================================

/// Parse a numeric register specification.
/// Given a token value, determine if it corresponds to a register and
/// return (register_number, operand_type_mask).
/// Source: i386-asm.c line 286
#[allow(dead_code)]
fn asm_parse_numeric_reg(reg_name: &str) -> Option<(i32, u32)> {
    if let Some(reg) = X86Register::from_name(reg_name) {
        let num = reg.reg_number() as i32;
        let size = reg.size_class();
        let typ = match size {
            8 => OP_REG8,
            16 => OP_REG16,
            32 => OP_REG32,
            _ => return None,
        };
        Some((num, typ))
    } else {
        None
    }
}

// =============================================================================
// parse_operand — Parse a complete assembly operand
// =============================================================================

/// Parse a complete assembly operand from tokens.
///
/// Handles all x86 addressing modes:
/// - Register direct: `%eax`
/// - Immediate: `$42`, `$symbol`
/// - Memory direct: `symbol`, `0x1234`
/// - Memory indirect: `(%eax)`, `4(%ebp)`, `(%ebx,%ecx,4)`
/// - Indirect through register: `*%eax`, `*(%eax)`
///
/// Source: i386-asm.c line 354
#[allow(clippy::too_many_arguments)]
pub fn parse_operand(
    _tok: i32,
    _tok_str: &str,
    tokc_value: i64,
    has_percent: bool,
    has_dollar: bool,
    has_star: bool,
    base_reg: Option<(i32, u32)>,
    index_reg: Option<(i32, u32)>,
    scale: Option<i64>,
    displacement: Option<&ExprValue>,
) -> TccResult<Operand> {
    let mut op = Operand::new();

    if has_dollar {
        // Immediate operand: $expr
        if let Some(disp) = displacement {
            op.e = disp.clone();
        } else {
            op.e.v = tokc_value as u64;
        }
        // Classify immediate size
        let v = op.e.v as i64;
        op.typ = OP_IM32;
        if v == (v as i8) as i64 {
            op.typ |= OP_IM8 | OP_IM8S;
        }
        if v == (v as i16) as i64 {
            op.typ |= OP_IM16;
        }
        if v == (v as u8) as i64 {
            op.typ |= OP_IM8;
        }
        #[cfg(feature = "x86_64")]
        {
            op.typ |= OP_IM64;
        }
        return Ok(op);
    }

    if has_percent || base_reg.is_some() {
        // Register operand: %reg or register from already-parsed context
        if let Some((reg_num, reg_type)) = base_reg {
            op.reg = reg_num;
            op.typ = reg_type;
            // Check for special named registers
            if reg_type == OP_REG8 && reg_num == 0 {
                // al is also EAX for certain encodings
            }
            if reg_type == OP_REG32 && reg_num == 0 {
                op.typ |= OP_EAX;
            }
            if reg_type == OP_REG16 && reg_num == 0 {
                op.typ |= OP_EAX;
            }
            if reg_type == OP_REG8 && reg_num == 1 {
                op.typ |= OP_CL;
            }
            if reg_type == OP_REG16 && reg_num == 2 {
                op.typ |= OP_DX;
            }
            if reg_type == OP_ST && reg_num == 0 {
                op.typ |= OP_ST0;
            }
            return Ok(op);
        }
    }

    // Memory operand or address
    if let Some(disp) = displacement {
        op.e = disp.clone();
    }
    if let Some((breg, _)) = base_reg {
        op.reg = breg;
    }
    if let Some((ireg, _)) = index_reg {
        op.reg2 = ireg;
        if let Some(s) = scale {
            op.shift = get_reg_shift(s)?;
        }
    }

    if has_star || op.reg >= 0 || op.reg2 >= 0 {
        op.typ = OP_INDIR;
    } else {
        op.typ = OP_ADDR;
    }
    // Effective address includes the register-based types
    op.typ |= OP_EA;

    Ok(op)
}

// =============================================================================
// gen_expr32 — Generate 32-bit expression with relocation
// =============================================================================

/// Generate a 32-bit expression value, emitting bytes and creating
/// a relocation entry if the expression references a symbol.
///
/// Source: i386-asm.c line 487
pub fn gen_expr32(
    state: &mut TCCState,
    section: &mut Section,
    ind: &mut usize,
    pe: &ExprValue,
) -> TccResult<()> {
    if pe.sym.is_some() {
        // Need a relocation entry
        if let Some(ref sym) = pe.sym {
            let sym_index = sym.c as usize;
            let sec_idx = section.sh_num as usize;
            put_elf_reloca(
                state,
                sec_idx,
                *ind as u64,
                R_DATA_32,
                sym_index,
                pe.v as i64,
            );
        }
    }
    emit_le32(section, ind, pe.v as u32);
    Ok(())
}

// =============================================================================
// gen_expr64 — Generate 64-bit expression with relocation
// =============================================================================

/// Generate a 64-bit expression value, emitting bytes and creating
/// a relocation entry if the expression references a symbol.
///
/// Source: i386-asm.c line 498
#[cfg(feature = "x86_64")]
pub fn gen_expr64(
    state: &mut TCCState,
    section: &mut Section,
    ind: &mut usize,
    pe: &ExprValue,
) -> TccResult<()> {
    if pe.sym.is_some() {
        if let Some(ref sym) = pe.sym {
            let sym_index = sym.c as usize;
            let sec_idx = section.sh_num as usize;
            // R_X86_64_64 = 1
            put_elf_reloca(
                state,
                sec_idx,
                *ind as u64,
                1, // R_X86_64_64
                sym_index,
                pe.v as i64,
            );
        }
    }
    emit_le64(section, ind, pe.v);
    Ok(())
}

/// Stub for i386 (no 64-bit expression generation).
#[cfg(not(feature = "x86_64"))]
pub fn gen_expr64(
    _state: &mut TCCState,
    _section: &mut Section,
    _ind: &mut usize,
    _pe: &ExprValue,
) -> TccResult<()> {
    Err(TccError::asm(
        String::new(), 0,
        "64-bit expressions not supported on i386 target".to_string(),
    ))
}

// =============================================================================
// gen_disp32 — Generate displacement for jump/call targets
// =============================================================================

/// Generate a 32-bit displacement for jump/call targets.
/// If the target symbol is in the same section, the displacement is
/// computed directly. Otherwise, a PC-relative relocation is emitted.
///
/// Source: i386-asm.c line 505
#[allow(dead_code)]
fn gen_disp32(
    state: &mut TCCState,
    section: &mut Section,
    ind: &mut usize,
    pe: &ExprValue,
) -> TccResult<()> {
    let mut val = pe.v as i64;

    if let Some(ref sym) = pe.sym {
        // Check if the symbol is in the same section (for local PC-relative)
        let _sym_section = sym.type_.t;
        let _cur_sh_num = section.sh_num;

        // If symbol is in the same section, compute relative offset directly
        // (no relocation needed — the linker won't need to patch this)
        let same_section = if sym.c != 0 {
            // Symbol has an ELF index; check its section
            false // Conservative: always use relocation for ELF symbols
        } else {
            false
        };

        if same_section {
            // Direct offset computation
            val -= *ind as i64;
            val -= 4; // Account for the 4 bytes of the displacement itself
        } else {
            // Emit PC-relative relocation (R_386_PC32 = 2 for i386)
            let sym_index = sym.c as usize;
            #[cfg(feature = "x86_64")]
            let reloc_type: u32 = 2; // R_X86_64_PC32
            #[cfg(not(feature = "x86_64"))]
            let reloc_type: u32 = 2; // R_386_PC32

            let sec_idx = section.sh_num as usize;
            put_elf_reloca(
                state,
                sec_idx,
                *ind as u64,
                reloc_type,
                sym_index,
                val - 4,
            );
            val = 0;
        }
    } else if pe.pcrel {
        // PC-relative without symbol
        val -= *ind as i64;
        val -= 4;
    }

    emit_le32(section, ind, val as u32);
    Ok(())
}

// =============================================================================
// asm_modrm — Encode ModR/M byte with optional SIB and displacement
// =============================================================================

/// Encode the ModR/M byte (and optional SIB byte and displacement)
/// for a given register operand and effective address operand.
///
/// Returns the value emitted for the mod field.
///
/// Addressing modes handled:
/// - Register direct: mod=11, r/m=reg
/// - `[disp32]`: mod=00, r/m=101 (no base, 32-bit displacement)
/// - `[reg]`: mod=00 (zero displacement)
/// - `[reg+disp8]`: mod=01
/// - `[reg+disp32]`: mod=10
/// - `[base+index*scale+disp]`: SIB byte required
/// - Special: `[EBP]` → mod=01, disp8=0 (EBP without displacement needs disp8)
/// - Special: `[ESP]` → SIB byte with index=ESP (no-index sentinel)
///
/// Source: i386-asm.c line 531
fn asm_modrm(
    section: &mut Section,
    ind: &mut usize,
    reg: i32,
    op: &Operand,
) -> TccResult<()> {
    let reg_field = (reg & 7) << 3;

    // Register-direct mode: mod=11, r/m=reg
    if (op.typ & (OP_REG | OP_MMX | OP_SSE | OP_CR | OP_TR | OP_DB | OP_SEG | OP_ST)) != 0
        && (op.typ & (OP_ADDR | OP_INDIR)) == 0
    {
        let modrm = 0xC0 | reg_field as u8 | (op.reg & 7) as u8;
        emit_byte(section, ind, modrm);
        return Ok(());
    }

    let base = op.reg;
    let index = op.reg2;
    let has_sib = index >= 0 || (base >= 0 && (base & 7) == 4); // ESP needs SIB

    // Determine mod and displacement size
    let disp = op.e.v as i64;
    let has_sym = op.e.sym.is_some();

    if base < 0 && index < 0 {
        // [disp32] — absolute address, mod=00, r/m=101
        let modrm = reg_field as u8 | 0x05;
        emit_byte(section, ind, modrm);
        emit_le32(section, ind, disp as u32);
        return Ok(());
    }

    // Determine mod field based on displacement
    let mod_val;
    if !has_sym && disp == 0 && base >= 0 && (base & 7) != 5 {
        // mod=00: no displacement (but EBP always needs at least disp8)
        mod_val = 0x00;
    } else if !has_sym && (-128..=127).contains(&disp) {
        // mod=01: 8-bit displacement
        mod_val = 0x40;
    } else {
        // mod=10: 32-bit displacement
        mod_val = 0x80;
    }

    if has_sib {
        // Need SIB byte
        let rm = 0x04; // SIB indicator in ModR/M
        let modrm = mod_val | reg_field as u8 | rm;
        emit_byte(section, ind, modrm);

        // Build SIB byte: scale(7:6) | index(5:3) | base(2:0)
        let sib_base = if base >= 0 { (base & 7) as u8 } else { 5 }; // 5 = no base
        let sib_index = if index >= 0 {
            (index & 7) as u8
        } else {
            4 // 4 = no index (ESP sentinel)
        };
        let sib_scale = op.shift;
        let sib = (sib_scale << 6) | (sib_index << 3) | sib_base;
        emit_byte(section, ind, sib);

        if base < 0 {
            // No base: always 32-bit displacement
            emit_le32(section, ind, disp as u32);
        } else if mod_val == 0x40 {
            emit_byte(section, ind, disp as u8);
        } else if mod_val == 0x80 {
            emit_le32(section, ind, disp as u32);
        }
    } else {
        // No SIB needed
        let rm = (base & 7) as u8;
        let modrm = mod_val | reg_field as u8 | rm;
        emit_byte(section, ind, modrm);

        if mod_val == 0x40 {
            emit_byte(section, ind, disp as u8);
        } else if mod_val == 0x80 {
            emit_le32(section, ind, disp as u32);
        }
    }

    Ok(())
}

// =============================================================================
// asm_rex — Generate REX prefix (x86_64 only)
// =============================================================================

/// Generate REX prefix for x86_64 instructions.
/// The REX prefix is needed when:
/// - Using 64-bit operand size (REX.W)
/// - Accessing registers r8-r15 (REX.R, REX.X, REX.B)
/// - Accessing new byte registers (spl, bpl, sil, dil)
///
/// Source: i386-asm.c line 594
#[cfg(feature = "x86_64")]
fn asm_rex(
    section: &mut Section,
    ind: &mut usize,
    width64: bool,
    ops: &[Operand],
    nb_ops: usize,
    regi: i32,
) -> TccResult<()> {
    let mut rex: u8 = 0;

    if width64 {
        rex |= REX_W;
    }

    // Check register extension bits
    if regi >= 8 {
        rex |= REX_R;
    }

    if nb_ops > 0 {
        let op0 = &ops[0];
        if op0.reg >= 8 {
            rex |= REX_B;
        }
    }
    if nb_ops > 1 {
        let op1 = &ops[1];
        if op1.reg >= 8 {
            rex |= REX_R;
        }
        if op1.reg2 >= 8 {
            rex |= REX_X;
        }
    }

    if rex != 0 {
        emit_byte(section, ind, REX_BASE | rex);
    }

    Ok(())
}

/// No-op REX generation for i386.
#[cfg(not(feature = "x86_64"))]
#[allow(dead_code)]
fn asm_rex(
    _section: &mut Section,
    _ind: &mut usize,
    _width64: bool,
    _ops: &[Operand],
    _nb_ops: usize,
    _regi: i32,
) -> TccResult<()> {
    Ok(())
}

// =============================================================================
// asm_opcode — Main assembly instruction encoder
// =============================================================================

/// Main assembly instruction encoder — the core of the x86 assembler.
///
/// Given an instruction opcode token, parses operands and emits the
/// encoded instruction bytes to the current text section.
///
/// Source: i386-asm.c line 692 (~485 lines)
pub fn asm_opcode(
    state: &mut TCCState,
    section: &mut Section,
    ind: &mut usize,
    opcode: X86Instruction,
    ops: &[Operand],
    nb_ops: usize,
) -> TccResult<()> {
    // Phase 1: Handle zero-operand instructions from OP0_CODES table
    for &(instr, code) in OP0_CODES.iter() {
        if instr == opcode {
            if code > 0xFF {
                let hi = ((code >> 8) & 0xFF) as u8;
                let lo = (code & 0xFF) as u8;
                emit_byte(section, ind, hi);
                emit_byte(section, ind, lo);
            } else {
                emit_byte(section, ind, code as u8);
            }
            return Ok(());
        }
    }

    // Phase 2: Look up in the main opcode table
    let matching_entries = lookup_all_opcodes(opcode);
    if matching_entries.is_empty() {
        return Err(TccError::asm(
            String::new(), 0,
            format!("unknown instruction: '{}'", instruction_name(opcode)),
        ));
    }

    // Phase 3: Find matching entry by operand count and types
    let mut matched_entry: Option<&OpcodeEntry> = None;
    let mut best_match_score = -1i32;

    for entry in &matching_entries {
        if entry.nb_ops as usize != nb_ops {
            continue;
        }
        let mut score = 0i32;
        let mut compatible = true;
        for (i, cur_op) in ops[..nb_ops].iter().enumerate() {
            let required = entry.op_type[i];
            let actual = cur_op.typ;
            if required == 0 && actual == 0 {
                score += 1;
                continue;
            }
            if (actual & required) != 0 {
                score += 2;
            } else {
                compatible = false;
                break;
            }
        }
        if compatible && score > best_match_score {
            best_match_score = score;
            matched_entry = Some(entry);
        }
    }

    let entry = matched_entry.ok_or_else(|| {
        TccError::asm(
            String::new(), 0,
            format!(
                "invalid operand types for '{}' (got {} operands)",
                instruction_name(opcode), nb_ops,
            ),
        )
    })?;

    // Phase 4: Encode the instruction
    let instr_type = entry.instr_type;
    let base_opcode = entry.opcode;
    let opct = instr_type & OPCT_MASK;
    let group = ((instr_type >> OPC_GROUP_SHIFT) & 0x07) as u32;

    let op_size = suffix_size(opcode).unwrap_or(4);
    let is_16bit = op_size == 2;
    let is_8bit = op_size == 1;
    #[cfg(feature = "x86_64")]
    let is_64bit = op_size == 8;

    // Emit FWAIT prefix if needed
    if opct == OPC_FWAIT {
        emit_byte(section, ind, 0x9B);
    }

    // Emit operand-size prefix (0x66) for 16-bit operations
    if is_16bit {
        emit_byte(section, ind, 0x66);
    }

    // REX prefix for x86_64
    #[cfg(feature = "x86_64")]
    {
        if (instr_type & OPC_48) != 0 || is_64bit {
            asm_rex(section, ind, true, ops, nb_ops, -1)?;
        } else {
            let need_rex = ops[..nb_ops].iter().any(|op| op.reg >= 8 || op.reg2 >= 8);
            if need_rex {
                asm_rex(section, ind, false, ops, nb_ops, -1)?;
            }
        }
    }

    // Handle special encoding groups
    match opct {
        x if x == OPC_SHIFT => {
            return encode_shift_group(section, ind, group, ops, nb_ops, is_8bit);
        }
        x if x == OPC_ARITH => {
            return encode_arith_group(section, ind, group, ops, nb_ops, is_8bit, is_16bit);
        }
        x if x == OPC_FARITH => {
            return encode_farith_group(section, ind, group, ops, nb_ops, op_size as u32);
        }
        x if x == OPC_TEST => {
            return encode_test_group(state, section, ind, ops, nb_ops, is_8bit, is_16bit);
        }
        x if x == OPC_0F01 => {
            emit_byte(section, ind, 0x0F);
            emit_byte(section, ind, 0x01);
            if nb_ops > 0 {
                asm_modrm(section, ind, group as i32, &ops[0])?;
            } else {
                emit_byte(section, ind, base_opcode as u8);
            }
            return Ok(());
        }
        _ => { /* Standard encoding path continues below */ }
    }

    // Standard instruction encoding

    // Emit 0x0F prefix if needed
    if (instr_type & OPC_0F) != 0 {
        emit_byte(section, ind, 0x0F);
    }

    // Compute final opcode byte with w-bit adjustment
    let mut opc = base_opcode;
    if (instr_type & OPC_BWL) == OPC_BWL && !is_8bit {
        opc |= 1;
    }

    // Emit opcode, optionally with register encoded in low 3 bits
    if (instr_type & OPC_REG) != 0 && nb_ops > 0 {
        let reg_op_idx = if nb_ops >= 2 { nb_ops - 1 } else { 0 };
        let reg = (ops[reg_op_idx].reg & 7) as u32;
        if opc > 0xFF {
            emit_byte(section, ind, ((opc >> 8) & 0xFF) as u8);
            emit_byte(section, ind, ((opc & 0xF8) | reg) as u8);
        } else {
            emit_byte(section, ind, ((opc & 0xF8) | reg) as u8);
        }
    } else if opc > 0xFF {
        emit_byte(section, ind, ((opc >> 8) & 0xFF) as u8);
        emit_byte(section, ind, (opc & 0xFF) as u8);
    } else {
        emit_byte(section, ind, opc as u8);
    }

    // Emit ModR/M + SIB + displacement if needed
    if (instr_type & OPC_MODRM) != 0 && nb_ops > 0 {
        let (reg_val, rm_op_idx) = if group > 0 {
            (group as i32, if nb_ops >= 2 { nb_ops - 1 } else { 0 })
        } else if nb_ops >= 2 {
            if (ops[1].typ & OP_REG) != 0 && (ops[0].typ & (OP_EA | OP_REG)) != 0 {
                (ops[1].reg, 0usize)
            } else {
                (ops[0].reg, if nb_ops > 1 { 1 } else { 0 })
            }
        } else {
            (0i32, 0usize)
        };
        asm_modrm(section, ind, reg_val, &ops[rm_op_idx])?;
    }

    // Emit immediate operand(s) if present
    for cur_op in ops[..nb_ops].iter() {
        if (cur_op.typ & OP_IM) != 0 {
            if cur_op.e.sym.is_some() {
                gen_expr32(state, section, ind, &cur_op.e)?;
            } else {
                let imm = cur_op.e.v;
                if is_8bit || (cur_op.typ & (OP_IM8 | OP_IM8S)) != 0 {
                    emit_byte(section, ind, imm as u8);
                } else if is_16bit || (cur_op.typ & OP_IM16) != 0 {
                    emit_le16(section, ind, imm as u16);
                } else {
                    emit_le32(section, ind, imm as u32);
                }
            }
            break;
        }
    }

    Ok(())
}

// =============================================================================
// Encoding group helpers (called from asm_opcode)
// =============================================================================

/// Encode shift-group instructions (SHL, SHR, SAR, ROL, ROR, RCL, RCR).
fn encode_shift_group(
    section: &mut Section,
    ind: &mut usize,
    group: u32,
    ops: &[Operand],
    nb_ops: usize,
    is_8bit: bool,
) -> TccResult<()> {
    if nb_ops < 2 {
        return Err(TccError::asm(
            String::new(), 0,
            "shift instruction requires 2 operands",
        ));
    }
    if (ops[0].typ & OP_CL) != 0 {
        let opc = if is_8bit { 0xD2u8 } else { 0xD3u8 };
        emit_byte(section, ind, opc);
        asm_modrm(section, ind, group as i32, &ops[1])?;
    } else if (ops[0].typ & OP_IM) != 0 {
        let imm = ops[0].e.v as u8;
        if imm == 1 {
            let opc = if is_8bit { 0xD0u8 } else { 0xD1u8 };
            emit_byte(section, ind, opc);
            asm_modrm(section, ind, group as i32, &ops[1])?;
        } else {
            let opc = if is_8bit { 0xC0u8 } else { 0xC1u8 };
            emit_byte(section, ind, opc);
            asm_modrm(section, ind, group as i32, &ops[1])?;
            emit_byte(section, ind, imm);
        }
    } else {
        return Err(TccError::asm(
            String::new(), 0,
            "shift count must be CL or immediate",
        ));
    }
    Ok(())
}

/// Encode arithmetic-group instructions (ADD, OR, ADC, SBB, AND, SUB, XOR, CMP).
fn encode_arith_group(
    section: &mut Section,
    ind: &mut usize,
    group: u32,
    ops: &[Operand],
    nb_ops: usize,
    is_8bit: bool,
    is_16bit: bool,
) -> TccResult<()> {
    if nb_ops < 2 {
        return Err(TccError::asm(
            String::new(), 0,
            "arithmetic instruction requires 2 operands",
        ));
    }
    let src = &ops[0];
    let dst = &ops[1];

    if (src.typ & OP_IM) != 0 {
        let imm = src.e.v as i64;
        if (dst.typ & OP_EAX) != 0 {
            let opc = (group << 3) as u8 | if is_8bit { 0x04 } else { 0x05 };
            emit_byte(section, ind, opc);
        } else if !is_8bit && !is_16bit && (-128..=127).contains(&imm) {
            emit_byte(section, ind, 0x83);
            asm_modrm(section, ind, group as i32, dst)?;
            emit_byte(section, ind, imm as u8);
            return Ok(());
        } else {
            let opc = if is_8bit { 0x80u8 } else { 0x81u8 };
            emit_byte(section, ind, opc);
            asm_modrm(section, ind, group as i32, dst)?;
        }
        if is_8bit {
            emit_byte(section, ind, imm as u8);
        } else if is_16bit {
            emit_le16(section, ind, imm as u16);
        } else {
            emit_le32(section, ind, imm as u32);
        }
    } else if (src.typ & OP_REG) != 0 {
        let opc = (group << 3) as u8 | if is_8bit { 0x00 } else { 0x01 };
        emit_byte(section, ind, opc);
        asm_modrm(section, ind, src.reg, dst)?;
    } else if (dst.typ & OP_REG) != 0 {
        let opc = (group << 3) as u8 | if is_8bit { 0x02 } else { 0x03 };
        emit_byte(section, ind, opc);
        asm_modrm(section, ind, dst.reg, src)?;
    } else {
        return Err(TccError::asm(
            String::new(), 0,
            "invalid operand combination for arithmetic instruction",
        ));
    }
    Ok(())
}

/// Encode FPU arithmetic-group instructions.
fn encode_farith_group(
    section: &mut Section,
    ind: &mut usize,
    group: u32,
    ops: &[Operand],
    nb_ops: usize,
    op_size: u32,
) -> TccResult<()> {
    let fg = group as u8;
    if nb_ops == 0 {
        emit_byte(section, ind, 0xDE);
        emit_byte(section, ind, 0xC0 | (fg << 3) | 1);
    } else if nb_ops == 1 {
        if (ops[0].typ & OP_ST) != 0 {
            emit_byte(section, ind, 0xD8);
            emit_byte(section, ind, 0xC0 | (fg << 3) | (ops[0].reg as u8 & 7));
        } else {
            let base = if op_size == 8 { 0xDC } else { 0xD8 };
            emit_byte(section, ind, base);
            asm_modrm(section, ind, fg as i32, &ops[0])?;
        }
    } else if nb_ops == 2 {
        let (st_reg, d_bit) = if (ops[0].typ & OP_ST0) != 0 {
            (ops[1].reg as u8 & 7, 0u8)
        } else {
            (ops[0].reg as u8 & 7, 4u8)
        };
        emit_byte(section, ind, 0xD8 | d_bit);
        emit_byte(section, ind, 0xC0 | (fg << 3) | st_reg);
    }
    Ok(())
}

/// Encode TEST instruction group.
fn encode_test_group(
    state: &mut TCCState,
    section: &mut Section,
    ind: &mut usize,
    ops: &[Operand],
    nb_ops: usize,
    is_8bit: bool,
    is_16bit: bool,
) -> TccResult<()> {
    if nb_ops < 2 {
        return Err(TccError::asm(
            String::new(), 0,
            "test instruction requires 2 operands",
        ));
    }
    let src = &ops[0];
    let dst = &ops[1];

    if (src.typ & OP_IM) != 0 {
        if (dst.typ & OP_EAX) != 0 {
            let opc = if is_8bit { 0xA8u8 } else { 0xA9u8 };
            emit_byte(section, ind, opc);
        } else {
            let opc = if is_8bit { 0xF6u8 } else { 0xF7u8 };
            emit_byte(section, ind, opc);
            asm_modrm(section, ind, 0, dst)?;
        }
        if src.e.sym.is_some() {
            gen_expr32(state, section, ind, &src.e)?;
        } else if is_8bit {
            emit_byte(section, ind, src.e.v as u8);
        } else if is_16bit {
            emit_le16(section, ind, src.e.v as u16);
        } else {
            emit_le32(section, ind, src.e.v as u32);
        }
    } else {
        let opc = if is_8bit { 0x84u8 } else { 0x85u8 };
        emit_byte(section, ind, opc);
        asm_modrm(section, ind, src.reg, dst)?;
    }
    Ok(())
}

// =============================================================================
// Inline Assembly Support
// =============================================================================

/// Determine constraint priority for register allocation ordering.
/// Higher priority = more constrained = allocated first.
///
/// Priority levels (from i386-asm.c):
/// - 0: matching constraint ('0'-'9'), immediate ('i', 'n')
/// - 1: memory ('m', 'g', 'p')
/// - 2: any general register ('r')
/// - 3: register class ('q' = eax/ebx/ecx/edx)
/// - 4: specific named register ('a', 'b', 'c', 'd', 'S', 'D', 'A')
///
/// Source: i386-asm.c line 1179
fn constraint_priority(constraint: &str) -> i32 {
    let s = skip_constraint_modifiers(constraint);
    if s.is_empty() {
        return 0;
    }
    match s.as_bytes()[0] {
        b'a' | b'b' | b'c' | b'd' | b'S' | b'D' | b'A' => 4,
        b'q' => 3,
        b'r' => 2,
        b'g' | b'm' | b'p' => 1,
        b'i' | b'n' | b'I' | b'N' | b'0'..=b'9' => 0,
        _ => 0,
    }
}

/// Skip constraint modifier characters (=, +, &, %, !, *).
/// Returns the constraint string starting after any modifiers.
///
/// Source: i386-asm.c line 1229
fn skip_constraint_modifiers(p: &str) -> &str {
    let bytes = p.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'=' | b'+' | b'&' | b'%' | b'!' | b'*' => i += 1,
            _ => break,
        }
    }
    &p[i..]
}

// =============================================================================
// asm_parse_regvar
// =============================================================================

/// Parse a register variable name and return its register number.
/// Returns -1 if the token does not correspond to a valid register.
///
/// Used for `register int x asm("eax")` style register variable binding.
///
/// Source: i386-asm.c line 1238
pub fn asm_parse_regvar(reg_name: &str) -> i32 {
    if let Some(reg) = X86Register::from_name(reg_name) {
        let size = reg.size_class();
        if size == 32 {
            return reg.reg_number() as i32;
        }
        #[cfg(feature = "x86_64")]
        if size == 64 {
            return reg.reg_number() as i32;
        }
    }
    -1
}

// =============================================================================
// asm_compute_constraints
// =============================================================================

/// Compute register constraints for inline assembly operands.
///
/// Maps constraint letters to register assignments and performs
/// priority-sorted register allocation. ESP (4) and EBP (5) are
/// pre-marked as unavailable.
///
/// Source: i386-asm.c line 1264
pub fn asm_compute_constraints(
    operands: &mut [AsmOperand],
    nb_operands: usize,
    nb_outputs: usize,
    clobber_regs: &[u8],
    output_regs_used: &mut i32,
) -> TccResult<()> {
    let mut regs_allocated = [0u8; NB_ASM_REGS];

    // Reserve ESP (reg 4) and EBP (reg 5)
    if NB_ASM_REGS > 4 { regs_allocated[4] = 1; }
    if NB_ASM_REGS > 5 { regs_allocated[5] = 1; }

    // Mark clobbered registers as allocated
    for i in 0..NB_ASM_REGS.min(clobber_regs.len()) {
        if clobber_regs[i] != 0 {
            regs_allocated[i] = 1;
        }
    }

    // First pass: compute priorities and initialise fields
    for op in operands[..nb_operands].iter_mut() {
        op.priority = constraint_priority(&op.constraint);
        op.reg = -1;
        op.ref_index = -1;
        op.input_index = -1;
        op.is_memory = false;
        op.is_llong = false;
    }

    // Resolve digit-reference constraints (input matching output)
    for i in nb_outputs..nb_operands {
        let constraint = skip_constraint_modifiers(&operands[i].constraint).to_string();
        if let Some(first_byte) = constraint.bytes().next() {
            if first_byte.is_ascii_digit() {
                let ref_idx = (first_byte - b'0') as usize;
                if ref_idx < nb_outputs {
                    operands[i].ref_index = ref_idx as i32;
                    operands[ref_idx].input_index = i as i32;
                }
            }
        }
    }

    // Sort operands by priority (highest first) for allocation order
    let mut sorted_indices: Vec<usize> = (0..nb_operands).collect();
    sorted_indices.sort_by(|&a, &b| operands[b].priority.cmp(&operands[a].priority));

    // Second pass: allocate registers in priority order
    for &idx in &sorted_indices {
        let constraint = skip_constraint_modifiers(&operands[idx].constraint).to_string();
        if constraint.is_empty() {
            continue;
        }

        // Matching constraints use the referenced output's register
        if operands[idx].ref_index >= 0 {
            let ref_idx = operands[idx].ref_index as usize;
            operands[idx].reg = operands[ref_idx].reg;
            continue;
        }

        let first_char = constraint.as_bytes()[0];
        let reg = match first_char {
            b'a' => Some(TREG_EAX),
            b'b' => Some(TREG_EBX),
            b'c' => Some(TREG_ECX),
            b'd' => Some(TREG_EDX),
            b'S' => Some(6i32),  // ESI
            b'D' => Some(7i32),  // EDI
            b'A' => {
                operands[idx].is_llong = true;
                Some(TREG_EAX)
            }
            b'q' => {
                let candidates = [TREG_EAX, TREG_ECX, TREG_EDX, TREG_EBX];
                let mut found = None;
                for &r in &candidates {
                    let ru = r as usize;
                    if ru < NB_ASM_REGS && regs_allocated[ru] == 0 {
                        found = Some(r);
                        break;
                    }
                }
                found
            }
            b'r' => {
                regs_allocated[..NB_ASM_REGS]
                    .iter()
                    .position(|&v| v == 0)
                    .map(|r| r as i32)
            }
            b'g' | b'm' | b'p' => {
                operands[idx].is_memory = true;
                operands[idx].reg = -1;
                continue;
            }
            b'i' | b'n' | b'I' | b'N' => {
                operands[idx].reg = -1;
                continue;
            }
            _ => None,
        };

        if let Some(r) = reg {
            if r >= 0 && (r as usize) < NB_ASM_REGS {
                regs_allocated[r as usize] = 1;
                operands[idx].reg = r;
                if idx < nb_outputs {
                    *output_regs_used |= 1 << r;
                }
            }
        }
    }

    Ok(())
}

// =============================================================================
// subst_asm_operand
// =============================================================================

/// Substitute an inline assembly operand into the template string.
///
/// Handles operand references (%0, %1, ...) with optional modifiers:
/// - `%b0` → byte register name (al, cl, dl, bl)
/// - `%w0` → word register name (ax, cx, dx, bx, sp, bp, si, di)
/// - `%h0` → high byte register (ah, ch, dh, bh)
/// - `%k0` → dword register name (eax, ecx, ...)
/// - `%q0` → qword register name (rax, rcx, ...) [x86_64]
/// - Plain `%0` → default operand representation
///
/// Source: i386-asm.c line 1516
pub fn subst_asm_operand(
    output: &mut String,
    sv: &SValue,
    modifier: char,
    op: &AsmOperand,
    _is_input: bool,
) -> TccResult<()> {
    let reg = op.reg;

    if op.is_memory || reg < 0 {
        // Memory or immediate operand
        let r = sv.r as i32;
        let val_mask = r & VT_VALMASK;

        if val_mask == VT_LOCAL {
            // SAFETY: CValue.i is the canonical integer field of the union;
            // for VT_LOCAL values, c.i holds the frame-pointer-relative offset.
            let offset = unsafe { sv.c.i as i64 };
            if offset >= 0 {
                output.push_str(&format!("{}(%ebp)", offset));
            } else {
                output.push_str(&format!("-{}(%ebp)", -offset));
            }
        } else if val_mask == VT_CONST {
            // SAFETY: CValue.i is the canonical integer field; for VT_CONST
            // values, c.i holds the immediate constant value.
            output.push_str(&format!("${}", unsafe { sv.c.i as i64 }));
        } else if (val_mask as u32 as usize) < NB_ASM_REGS {
            let base_reg = val_mask as u32 as usize;
            // SAFETY: CValue.i is the canonical integer field; for register-
            // based addressing, c.i holds the displacement offset from the
            // base register.
            let offset = unsafe { sv.c.i as i64 };
            let reg_name = dword_reg_name(base_reg);
            if offset == 0 {
                output.push_str(&format!("(%{})", reg_name));
            } else if offset > 0 {
                output.push_str(&format!("{}(%{})", offset, reg_name));
            } else {
                output.push_str(&format!("-{}(%{})", -offset, reg_name));
            }
        }
        return Ok(());
    }

    // Register operand — format based on modifier
    let reg_idx = reg as usize;
    let name = match modifier {
        'b' => byte_reg_name(reg_idx),
        'h' => high_byte_reg_name(reg_idx),
        'w' => word_reg_name(reg_idx),
        'k' => dword_reg_name(reg_idx),
        #[cfg(feature = "x86_64")]
        'q' => qword_reg_name(reg_idx),
        _ => dword_reg_name(reg_idx),
    };

    output.push('%');
    output.push_str(name);
    Ok(())
}

/// Return byte register name for register index.
fn byte_reg_name(idx: usize) -> &'static str {
    match idx {
        0 => "al", 1 => "cl", 2 => "dl", 3 => "bl",
        4 => "ah", 5 => "ch", 6 => "dh", 7 => "bh",
        _ => "al",
    }
}

/// Return high byte register name for register index.
fn high_byte_reg_name(idx: usize) -> &'static str {
    match idx {
        0 => "ah", 1 => "ch", 2 => "dh", 3 => "bh",
        _ => "ah",
    }
}

/// Return word register name for register index.
fn word_reg_name(idx: usize) -> &'static str {
    match idx {
        0 => "ax", 1 => "cx", 2 => "dx", 3 => "bx",
        4 => "sp", 5 => "bp", 6 => "si", 7 => "di",
        _ => "ax",
    }
}

/// Return dword register name for register index.
fn dword_reg_name(idx: usize) -> &'static str {
    match idx {
        0 => "eax", 1 => "ecx", 2 => "edx", 3 => "ebx",
        4 => "esp", 5 => "ebp", 6 => "esi", 7 => "edi",
        _ => "eax",
    }
}

/// Return qword register name for register index (x86_64 only).
#[cfg(feature = "x86_64")]
fn qword_reg_name(idx: usize) -> &'static str {
    match idx {
        0 => "rax", 1 => "rcx", 2 => "rdx", 3 => "rbx",
        4 => "rsp", 5 => "rbp", 6 => "rsi", 7 => "rdi",
        8 => "r8", 9 => "r9", 10 => "r10", 11 => "r11",
        12 => "r12", 13 => "r13", 14 => "r14", 15 => "r15",
        _ => "rax",
    }
}

// =============================================================================
// asm_gen_code
// =============================================================================

/// Generate code for an inline assembly statement.
///
/// Generates the following sequence:
/// 1. Save registers that will be clobbered (push)
/// 2. (The template bytes are emitted by the assembler)
/// 3. Restore saved registers (pop, reverse order)
///
/// Source: i386-asm.c line 1627
#[allow(clippy::too_many_arguments)]
pub fn asm_gen_code(
    _state: &mut TCCState,
    section: &mut Section,
    ind: &mut usize,
    operands: &[AsmOperand],
    nb_operands: usize,
    nb_outputs: usize,
    _is_output: bool,
    clobber_regs: &[u8],
) -> TccResult<()> {
    let _ = nb_operands; // used indirectly through operands slice
    let mut reg_saved = [false; NB_ASM_REGS];

    for (i, &clobber) in clobber_regs.iter().enumerate().take(NB_ASM_REGS) {
        if clobber != 0 {
            let is_output_reg = operands[..nb_outputs]
                .iter()
                .any(|op| op.reg == i as i32);
            if !is_output_reg && i != 4 && i != 5 {
                reg_saved[i] = true;
            }
        }
    }

    // Push saved registers (ascending order)
    for (i, &saved) in reg_saved.iter().enumerate() {
        if saved {
            emit_byte(section, ind, 0x50 + i as u8);
        }
    }

    // The assembly template bytes are emitted by the assembler layer
    // when processing the substituted template string.

    // Pop saved registers (descending order)
    for (i, &saved) in reg_saved.iter().enumerate().rev() {
        if saved {
            emit_byte(section, ind, 0x58 + i as u8);
        }
    }

    Ok(())
}

// =============================================================================
// asm_clobber
// =============================================================================

/// Handle a clobber register specification in inline assembly.
///
/// Recognizes:
/// - General register names: "eax", "ecx", "edx", "ebx", "esi", "edi"
/// - 64-bit register names (x86_64): "rax", ..., "r8"-"r15"
/// - Short register names: "ax", "al", etc. (mapped to the full register)
/// - Special clobbers: "memory" (memory barrier), "cc"/"flags" (condition codes)
///
/// Source: i386-asm.c line 1731
pub fn asm_clobber(clobber_regs: &mut [u8], name: &str) -> TccResult<()> {
    match name {
        "memory" => return Ok(()),
        "cc" | "flags" => return Ok(()),
        _ => {}
    }

    if let Some(reg) = X86Register::from_name(name) {
        let reg_num = reg.reg_number() as usize;
        if reg_num < clobber_regs.len() {
            clobber_regs[reg_num] = 1;
            return Ok(());
        }
    }

    Err(TccError::asm(
        String::new(), 0,
        format!("invalid clobber register: '{}'", name),
    ))
}

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arch::i386::tokens::{
        OPC_B, OPC_WL, OPC_BWL, OPC_REG, OPC_MODRM,
        OPC_SHIFT, OPC_ARITH, OPC_FARITH, OPC_TEST, OPC_0F01,
        OPC_0F, OPC_48, OPC_FWAIT, OPCT_MASK, OPC_GROUP_SHIFT,
        OP_REG8, OP_REG16, OP_REG32, OP_EA,
        TEST_BITS, NB_TEST_OPCODES, OP0_CODES, SEGMENT_PREFIXES,
        MAX_OPERANDS, OPCODE_TABLE,
    };

    #[test]
    fn test_max_operands() {
        assert_eq!(MAX_OPERANDS, 3);
    }

    #[test]
    fn test_nbwlx() {
        #[cfg(feature = "x86_64")]
        assert_eq!(NBWLX, 5);
        #[cfg(not(feature = "x86_64"))]
        assert_eq!(NBWLX, 4);
    }

    #[test]
    fn test_opc_bwl_composition() {
        assert_eq!(OPC_BWL, OPC_B | OPC_WL);
    }

    #[test]
    fn test_opcode_flag_values() {
        assert_eq!(OPC_B, 0x01);
        assert_eq!(OPC_WL, 0x02);
        assert_eq!(OPC_REG, 0x04);
        assert_eq!(OPC_MODRM, 0x08);
        assert_eq!(OPC_0F, 0x100);
        assert_eq!(OPC_48, 0x200);
    }

    #[test]
    fn test_opct_mask() {
        assert_eq!(OPCT_MASK, 0x70);
        assert_eq!(OPC_FWAIT & OPCT_MASK, OPC_FWAIT);
        assert_eq!(OPC_SHIFT & OPCT_MASK, OPC_SHIFT);
        assert_eq!(OPC_ARITH & OPCT_MASK, OPC_ARITH);
        assert_eq!(OPC_FARITH & OPCT_MASK, OPC_FARITH);
        assert_eq!(OPC_TEST & OPCT_MASK, OPC_TEST);
        assert_eq!(OPC_0F01 & OPCT_MASK, OPC_0F01);
    }

    #[test]
    fn test_operand_type_values() {
        // Verify the enum variants exist and are distinct.
        // Exact ordinal values depend on cfg-gated variants, so we
        // only check the first three stable variants and that later
        // variants differ from each other.
        assert_eq!(OperandType::Reg8 as u8, 0);
        assert_eq!(OperandType::Reg16 as u8, 1);
        assert_eq!(OperandType::Reg32 as u8, 2);
        assert_ne!(OperandType::Eax as u8, OperandType::St0 as u8);
        assert_ne!(OperandType::St0 as u8, OperandType::Cl as u8);
        assert_ne!(OperandType::Cl as u8, OperandType::Dx as u8);
    }

    #[test]
    fn test_op_bitmask_values() {
        assert_eq!(OP_REG8, 1 << 0);
        assert_eq!(OP_REG16, 1 << 1);
        assert_eq!(OP_REG32, 1 << 2);
    }

    #[test]
    fn test_op_composite_constants() {
        assert_eq!(OP_IM, OP_IM8 | OP_IM16 | OP_IM32);
        assert_eq!(OP_REG, OP_REG8 | OP_REG16 | OP_REG32);
        assert_eq!(OP_REGW, OP_REG16 | OP_REG32);
        assert_eq!(OP_IMW, OP_IM16 | OP_IM32);
        assert_eq!(OP_MMXSSE, OP_MMX | OP_SSE);
    }

    #[test]
    fn test_reg_to_size() {
        assert_eq!(REG_TO_SIZE.len(), 9);
        // Values are log2(byte_size): REG8→0 (2^0=1), REG16→1 (2^1=2), REG32→2 (2^2=4)
        assert_eq!(REG_TO_SIZE[0], 0); // OPT_REG8
        assert_eq!(REG_TO_SIZE[1], 1); // OPT_REG16
        assert_eq!(REG_TO_SIZE[2], 2); // OPT_REG32
        assert_eq!(REG_TO_SIZE[3], 3); // OPT_REG64 (x86_64)
    }

    #[test]
    fn test_test_bits_size() {
        assert_eq!(TEST_BITS.len(), NB_TEST_OPCODES);
        assert_eq!(NB_TEST_OPCODES, 30);
    }

    #[test]
    fn test_segment_prefixes() {
        assert_eq!(SEGMENT_PREFIXES.len(), 6);
        assert_eq!(SEGMENT_PREFIXES[0], 0x26);
        assert_eq!(SEGMENT_PREFIXES[1], 0x2e);
        assert_eq!(SEGMENT_PREFIXES[2], 0x36);
        assert_eq!(SEGMENT_PREFIXES[3], 0x3e);
        assert_eq!(SEGMENT_PREFIXES[4], 0x64);
        assert_eq!(SEGMENT_PREFIXES[5], 0x65);
    }

    #[test]
    fn test_asm_instrs_is_opcode_table() {
        assert_eq!(ASM_INSTRS.len(), OPCODE_TABLE.len());
        assert!(ASM_INSTRS.len() > 100);
    }

    #[test]
    fn test_operand_default() {
        let op = Operand::new();
        assert_eq!(op.typ, 0);
        assert_eq!(op.reg, -1);
        assert_eq!(op.reg2, -1);
        assert_eq!(op.shift, 0);
    }

    #[test]
    fn test_asm_instr_type_alias() {
        let entry: AsmInstr = ASM_INSTRS[0].clone();
        let _token = entry.token;
        let _opcode = entry.opcode;
        let _instr_type = entry.instr_type;
        let _nb_ops = entry.nb_ops;
        let _op_type = entry.op_type;
    }

    #[test]
    fn test_opc_group_shift() {
        assert_eq!(OPC_GROUP_SHIFT, 13);
    }

    #[test]
    fn test_op0_codes_nonempty() {
        assert!(!OP0_CODES.is_empty());
    }

    #[test]
    fn test_constraint_priority_basic() {
        let p_a = constraint_priority("=a");
        let p_r = constraint_priority("=r");
        let p_m = constraint_priority("=m");
        assert!(p_a > 0);
        assert!(p_r > 0);
        assert!(p_m > 0);
    }

    #[test]
    fn test_skip_constraint_modifiers_basic() {
        assert_eq!(skip_constraint_modifiers("=r"), "r");
        assert_eq!(skip_constraint_modifiers("+r"), "r");
        assert_eq!(skip_constraint_modifiers("&r"), "r");
        assert_eq!(skip_constraint_modifiers("%r"), "r");
        assert_eq!(skip_constraint_modifiers("r"), "r");
        assert_eq!(skip_constraint_modifiers("=&r"), "r");
    }

    #[test]
    fn test_asm_parse_regvar_known() {
        assert_eq!(asm_parse_regvar("eax"), 0);
        assert_eq!(asm_parse_regvar("ecx"), 1);
        assert_eq!(asm_parse_regvar("edx"), 2);
        assert_eq!(asm_parse_regvar("ebx"), 3);
    }

    #[test]
    fn test_asm_parse_regvar_unknown() {
        assert_eq!(asm_parse_regvar("unknown"), -1);
    }

    #[test]
    fn test_asm_clobber_special() {
        let mut regs = [0u8; 16];
        assert!(asm_clobber(&mut regs, "memory").is_ok());
        assert!(asm_clobber(&mut regs, "cc").is_ok());
        assert!(asm_clobber(&mut regs, "flags").is_ok());
    }

    #[test]
    fn test_asm_clobber_registers() {
        let mut regs = [0u8; 16];
        assert!(asm_clobber(&mut regs, "eax").is_ok());
        assert_eq!(regs[0], 1);
        assert!(asm_clobber(&mut regs, "ecx").is_ok());
        assert_eq!(regs[1], 1);
    }

    #[test]
    fn test_asm_clobber_invalid() {
        let mut regs = [0u8; 16];
        assert!(asm_clobber(&mut regs, "invalidreg").is_err());
    }

    #[test]
    fn test_op_ea_composition() {
        // OP_EA is a standalone bitmask constant (0x4000_0000) from tokens.rs,
        // not a composition of other OP_* flags.
        assert_eq!(OP_EA, 0x4000_0000);
        assert_ne!(OP_EA, 0);
    }

    #[cfg(feature = "x86_64")]
    #[test]
    fn test_x86_64_constants() {
        assert_eq!(OPC_WLQ, 0x1000);
        assert_eq!(OPC_BWLQ, OPC_B | OPC_WLQ);
        assert_ne!(OP_REG64, 0);
        assert_ne!(OP_IM64, 0);
        assert_ne!(OP_REG8_LOW, 0);
    }
}
