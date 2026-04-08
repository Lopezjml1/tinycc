//! x86 (i386) register names and instruction mnemonics.
//!
//! Port of `i386-tok.h` (332 lines) and instruction table from `i386-asm.h` (490 lines).
//! Defines all x86 register name tokens and assembly instruction mnemonic tokens.
//!
//! # Token Ordering
//! The ordering of enum variants is CRITICAL and must match the C source exactly.
//! The C code depends on sequential numbering for:
//! - Register encoding arithmetic (`tok - TOK_ASM_eax` gives register number)
//! - Suffix variant groups (B/W/L/base must be contiguous)
//! - Condition code groups (30 variants per group for j/set/cmov)
//! - FP instruction groups (6 variants per group)

// =============================================================================
// Instruction type flags (OPC_* constants from i386-asm.c)
// =============================================================================

/// Byte operand size flag.
pub const OPC_B: u16 = 0x01;
/// Word/Long operand size flag.
pub const OPC_WL: u16 = 0x02;
/// Byte/Word/Long operand size flag.
pub const OPC_BWL: u16 = OPC_B | OPC_WL;
/// Register encoded in opcode low bits.
pub const OPC_REG: u16 = 0x04;
/// ModR/M byte present.
pub const OPC_MODRM: u16 = 0x08;
/// Instruction type mask for special groups.
pub const OPCT_MASK: u16 = 0x70;
/// FWAIT prefix required.
pub const OPC_FWAIT: u16 = 0x10;
/// Shift instruction group.
pub const OPC_SHIFT: u16 = 0x20;
/// Arithmetic instruction group.
pub const OPC_ARITH: u16 = 0x30;
/// FPU arithmetic instruction group.
pub const OPC_FARITH: u16 = 0x40;
/// Test/conditional instruction group.
pub const OPC_TEST: u16 = 0x50;
/// 0x0F01 group (group 7 instructions).
pub const OPC_0F01: u16 = 0x60;
/// Secondary opcode map (0x0F prefix).
pub const OPC_0F: u16 = 0x100;
/// Always has REX prefix (x86_64).
pub const OPC_48: u16 = 0x200;
/// Bit position for group field in instr_type.
pub const OPC_GROUP_SHIFT: u16 = 13;
/// Word/Long with extension (i386: same as OPC_WL).
pub const OPC_WLX: u16 = OPC_WL;
/// Byte/Word/Long with extension (i386: same as OPC_BWL).
pub const OPC_BWLX: u16 = OPC_BWL;

// =============================================================================
// Operand type enum values (OPT_* from i386-asm.c)
// =============================================================================

pub const OPT_REG8: u8 = 0;
pub const OPT_REG16: u8 = 1;
pub const OPT_REG32: u8 = 2;
pub const OPT_MMX: u8 = 3;
pub const OPT_SSE: u8 = 4;
pub const OPT_CR: u8 = 5;
pub const OPT_TR: u8 = 6;
pub const OPT_DB: u8 = 7;
pub const OPT_SEG: u8 = 8;
pub const OPT_ST: u8 = 9;
pub const OPT_IM8: u8 = 10;
pub const OPT_IM8S: u8 = 11;
pub const OPT_IM16: u8 = 12;
pub const OPT_IM32: u8 = 13;
pub const OPT_EAX: u8 = 14;
pub const OPT_ST0: u8 = 15;
pub const OPT_CL: u8 = 16;
pub const OPT_DX: u8 = 17;
pub const OPT_ADDR: u8 = 18;
pub const OPT_INDIR: u8 = 19;
pub const OPT_COMPOSITE_FIRST: u8 = 20;
pub const OPT_IM: u8 = 21;
pub const OPT_REG: u8 = 22;
pub const OPT_REGW: u8 = 23;
pub const OPT_IMW: u8 = 24;
pub const OPT_MMXSSE: u8 = 25;
pub const OPT_DISP: u8 = 26;
pub const OPT_DISP8: u8 = 27;
/// Effective address flag (OR'd with operand type).
pub const OPT_EA: u8 = 0x80;

// =============================================================================
// Operand type bitmask constants (OP_* from i386-asm.c)
// =============================================================================

pub const OP_REG8: u32 = 1 << 0;
pub const OP_REG16: u32 = 1 << 1;
pub const OP_REG32: u32 = 1 << 2;
pub const OP_MMX: u32 = 1 << 3;
pub const OP_SSE: u32 = 1 << 4;
pub const OP_CR: u32 = 1 << 5;
pub const OP_TR: u32 = 1 << 6;
pub const OP_DB: u32 = 1 << 7;
pub const OP_SEG: u32 = 1 << 8;
pub const OP_ST: u32 = 1 << 9;
pub const OP_IM8: u32 = 1 << 10;
pub const OP_IM8S: u32 = 1 << 11;
pub const OP_IM16: u32 = 1 << 12;
pub const OP_IM32: u32 = 1 << 13;
pub const OP_EAX: u32 = 1 << 14;
pub const OP_ST0: u32 = 1 << 15;
pub const OP_CL: u32 = 1 << 16;
pub const OP_DX: u32 = 1 << 17;
pub const OP_ADDR: u32 = 1 << 18;
pub const OP_INDIR: u32 = 1 << 19;
/// Effective address bitmask.
pub const OP_EA: u32 = 0x4000_0000;
/// Combined register bitmask (REG8 | REG16 | REG32).
pub const OP_REG: u32 = OP_REG8 | OP_REG16 | OP_REG32;

/// Number of condition code test opcodes (jo..jg = 30 variants).
pub const NB_TEST_OPCODES: usize = 30;
/// Maximum number of operands per instruction.
pub const MAX_OPERANDS: usize = 3;

/// Condition code test bits for encoding (maps cc index to opcode bits).
pub const TEST_BITS: [u8; NB_TEST_OPCODES] = [
    0x00, 0x01, 0x02, 0x02, 0x02, 0x03, 0x03, 0x03,  // o, no, b/c/nae, nb/nc/ae
    0x04, 0x04, 0x05, 0x05, 0x06, 0x06, 0x07, 0x07,  // e/z, ne/nz, be/na, nbe/a
    0x08, 0x09, 0x0a, 0x0a, 0x0b, 0x0b,              // s, ns, p/pe, np/po
    0x0c, 0x0c, 0x0d, 0x0d, 0x0e, 0x0e, 0x0f, 0x0f,  // l/nge, nl/ge, le/ng, nle/g
];

/// Segment register prefix bytes.
pub const SEGMENT_PREFIXES: [u8; 6] = [0x26, 0x2e, 0x36, 0x3e, 0x64, 0x65];
// =============================================================================
// X86Register — x86 register name tokens
// =============================================================================

/// x86 register names as assembly tokens.
///
/// Source: `i386-tok.h` lines 81–179 (register definitions)
///
/// ## Ordering Requirement
/// Order MUST be preserved exactly as in C source because register parsing
/// uses arithmetic on token values (e.g., `tok - TOK_ASM_eax` gives register 0–7).
///
/// ## Register Groups
/// - 8-bit low: al, cl, dl, bl (indices 0–3)
/// - 8-bit high: ah, ch, dh, bh (indices 4–7)
/// - 16-bit: ax, cx, dx, bx, sp, bp, si, di (indices 0–7)
/// - 32-bit: eax, ecx, edx, ebx, esp, ebp, esi, edi (indices 0–7)
/// - MMX: mm0–mm7
/// - SSE: xmm0–xmm7
/// - Control: cr0–cr7
/// - Test: tr0–tr7
/// - Debug (db): db0–db7
/// - Debug (dr): dr0–dr7
/// - Segment: es, cs, ss, ds, fs, gs
/// - FPU/Special: st, rip
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum X86Register {
    // 8-bit low registers (index = reg number 0-3)
    Al = 0, Cl, Dl, Bl,
    // 8-bit high registers (index - 4 = reg number 4-7)
    Ah, Ch, Dh, Bh,
    // 16-bit general purpose registers
    Ax, Cx, Dx, Bx, Sp, Bp, Si, Di,
    // 32-bit general purpose registers
    Eax, Ecx, Edx, Ebx, Esp, Ebp, Esi, Edi,
    // MMX registers
    Mm0, Mm1, Mm2, Mm3, Mm4, Mm5, Mm6, Mm7,
    // SSE registers
    Xmm0, Xmm1, Xmm2, Xmm3, Xmm4, Xmm5, Xmm6, Xmm7,
    // Control registers
    Cr0, Cr1, Cr2, Cr3, Cr4, Cr5, Cr6, Cr7,
    // Test registers
    Tr0, Tr1, Tr2, Tr3, Tr4, Tr5, Tr6, Tr7,
    // Debug registers (db* aliases)
    Db0, Db1, Db2, Db3, Db4, Db5, Db6, Db7,
    // Debug registers (dr* aliases — same hardware, different mnemonic)
    Dr0, Dr1, Dr2, Dr3, Dr4, Dr5, Dr6, Dr7,
    // Segment registers
    Es, Cs, Ss, Ds, Fs, Gs,
    // FPU stack top
    St,
    // Instruction pointer (used in x86_64 RIP-relative addressing)
    Rip,
}

/// Static table of all register definitions for name lookup.
static REGISTER_TABLE: &[(X86Register, &str)] = &[
    (X86Register::Al, "al"),
    (X86Register::Cl, "cl"),
    (X86Register::Dl, "dl"),
    (X86Register::Bl, "bl"),
    (X86Register::Ah, "ah"),
    (X86Register::Ch, "ch"),
    (X86Register::Dh, "dh"),
    (X86Register::Bh, "bh"),
    (X86Register::Ax, "ax"),
    (X86Register::Cx, "cx"),
    (X86Register::Dx, "dx"),
    (X86Register::Bx, "bx"),
    (X86Register::Sp, "sp"),
    (X86Register::Bp, "bp"),
    (X86Register::Si, "si"),
    (X86Register::Di, "di"),
    (X86Register::Eax, "eax"),
    (X86Register::Ecx, "ecx"),
    (X86Register::Edx, "edx"),
    (X86Register::Ebx, "ebx"),
    (X86Register::Esp, "esp"),
    (X86Register::Ebp, "ebp"),
    (X86Register::Esi, "esi"),
    (X86Register::Edi, "edi"),
    (X86Register::Mm0, "mm0"),
    (X86Register::Mm1, "mm1"),
    (X86Register::Mm2, "mm2"),
    (X86Register::Mm3, "mm3"),
    (X86Register::Mm4, "mm4"),
    (X86Register::Mm5, "mm5"),
    (X86Register::Mm6, "mm6"),
    (X86Register::Mm7, "mm7"),
    (X86Register::Xmm0, "xmm0"),
    (X86Register::Xmm1, "xmm1"),
    (X86Register::Xmm2, "xmm2"),
    (X86Register::Xmm3, "xmm3"),
    (X86Register::Xmm4, "xmm4"),
    (X86Register::Xmm5, "xmm5"),
    (X86Register::Xmm6, "xmm6"),
    (X86Register::Xmm7, "xmm7"),
    (X86Register::Cr0, "cr0"),
    (X86Register::Cr1, "cr1"),
    (X86Register::Cr2, "cr2"),
    (X86Register::Cr3, "cr3"),
    (X86Register::Cr4, "cr4"),
    (X86Register::Cr5, "cr5"),
    (X86Register::Cr6, "cr6"),
    (X86Register::Cr7, "cr7"),
    (X86Register::Tr0, "tr0"),
    (X86Register::Tr1, "tr1"),
    (X86Register::Tr2, "tr2"),
    (X86Register::Tr3, "tr3"),
    (X86Register::Tr4, "tr4"),
    (X86Register::Tr5, "tr5"),
    (X86Register::Tr6, "tr6"),
    (X86Register::Tr7, "tr7"),
    (X86Register::Db0, "db0"),
    (X86Register::Db1, "db1"),
    (X86Register::Db2, "db2"),
    (X86Register::Db3, "db3"),
    (X86Register::Db4, "db4"),
    (X86Register::Db5, "db5"),
    (X86Register::Db6, "db6"),
    (X86Register::Db7, "db7"),
    (X86Register::Dr0, "dr0"),
    (X86Register::Dr1, "dr1"),
    (X86Register::Dr2, "dr2"),
    (X86Register::Dr3, "dr3"),
    (X86Register::Dr4, "dr4"),
    (X86Register::Dr5, "dr5"),
    (X86Register::Dr6, "dr6"),
    (X86Register::Dr7, "dr7"),
    (X86Register::Es, "es"),
    (X86Register::Cs, "cs"),
    (X86Register::Ss, "ss"),
    (X86Register::Ds, "ds"),
    (X86Register::Fs, "fs"),
    (X86Register::Gs, "gs"),
    (X86Register::St, "st"),
    (X86Register::Rip, "rip"),
];

impl X86Register {
    /// Get the assembly name string for this register.
    pub fn name(&self) -> &'static str {
        for &(ref reg, name) in REGISTER_TABLE.iter() {
            if *reg == *self {
                return name;
            }
        }
        // All variants are covered by the table
        "unknown"
    }

    /// Look up register by assembly name string.
    ///
    /// Performs case-insensitive matching to support common assembler conventions.
    pub fn from_name(name: &str) -> Option<Self> {
        let lower = name.to_ascii_lowercase();
        for &(reg, reg_name) in REGISTER_TABLE.iter() {
            if reg_name == lower.as_str() {
                return Some(reg);
            }
        }
        None
    }

    /// Get the register number (0–7) for instruction encoding.
    ///
    /// For 8-bit low registers (al–bl): returns 0–3
    /// For 8-bit high registers (ah–bh): returns 4–7
    /// For 16/32-bit registers: returns 0–7 (ax/eax=0, cx/ecx=1, ...)
    /// For indexed register sets (mm, xmm, cr, tr, db, dr): returns 0–7
    /// For segment registers: returns 0–5 (es=0, cs=1, ss=2, ds=3, fs=4, gs=5)
    /// For st: returns 0 (stack top)
    /// For rip: returns 0
    pub fn reg_number(&self) -> u8 {
        match self {
            // 8-bit low: al=0, cl=1, dl=2, bl=3
            Self::Al => 0, Self::Cl => 1, Self::Dl => 2, Self::Bl => 3,
            // 8-bit high: ah=4, ch=5, dh=6, bh=7
            Self::Ah => 4, Self::Ch => 5, Self::Dh => 6, Self::Bh => 7,
            // 16-bit: ax=0..di=7
            Self::Ax => 0, Self::Cx => 1, Self::Dx => 2, Self::Bx => 3,
            Self::Sp => 4, Self::Bp => 5, Self::Si => 6, Self::Di => 7,
            // 32-bit: eax=0..edi=7
            Self::Eax => 0, Self::Ecx => 1, Self::Edx => 2, Self::Ebx => 3,
            Self::Esp => 4, Self::Ebp => 5, Self::Esi => 6, Self::Edi => 7,
            // MMX: mm0=0..mm7=7
            Self::Mm0 => 0, Self::Mm1 => 1, Self::Mm2 => 2, Self::Mm3 => 3,
            Self::Mm4 => 4, Self::Mm5 => 5, Self::Mm6 => 6, Self::Mm7 => 7,
            // SSE: xmm0=0..xmm7=7
            Self::Xmm0 => 0, Self::Xmm1 => 1, Self::Xmm2 => 2, Self::Xmm3 => 3,
            Self::Xmm4 => 4, Self::Xmm5 => 5, Self::Xmm6 => 6, Self::Xmm7 => 7,
            // Control: cr0=0..cr7=7
            Self::Cr0 => 0, Self::Cr1 => 1, Self::Cr2 => 2, Self::Cr3 => 3,
            Self::Cr4 => 4, Self::Cr5 => 5, Self::Cr6 => 6, Self::Cr7 => 7,
            // Test: tr0=0..tr7=7
            Self::Tr0 => 0, Self::Tr1 => 1, Self::Tr2 => 2, Self::Tr3 => 3,
            Self::Tr4 => 4, Self::Tr5 => 5, Self::Tr6 => 6, Self::Tr7 => 7,
            // Debug (db): db0=0..db7=7
            Self::Db0 => 0, Self::Db1 => 1, Self::Db2 => 2, Self::Db3 => 3,
            Self::Db4 => 4, Self::Db5 => 5, Self::Db6 => 6, Self::Db7 => 7,
            // Debug (dr): dr0=0..dr7=7
            Self::Dr0 => 0, Self::Dr1 => 1, Self::Dr2 => 2, Self::Dr3 => 3,
            Self::Dr4 => 4, Self::Dr5 => 5, Self::Dr6 => 6, Self::Dr7 => 7,
            // Segment: es=0, cs=1, ss=2, ds=3, fs=4, gs=5
            Self::Es => 0, Self::Cs => 1, Self::Ss => 2,
            Self::Ds => 3, Self::Fs => 4, Self::Gs => 5,
            // Special
            Self::St => 0,
            Self::Rip => 0,
        }
    }

    /// Get the register size class in bits.
    ///
    /// Returns the operand size for this register:
    /// - 8 for al, cl, dl, bl, ah, ch, dh, bh
    /// - 16 for ax, cx, dx, bx, sp, bp, si, di and segment registers
    /// - 32 for eax, ecx, edx, ebx, esp, ebp, esi, edi and control/debug regs
    /// - 64 for mm0–mm7 (MMX 64-bit)
    /// - 128 for xmm0–xmm7 (SSE 128-bit)
    /// - 80 for st (x87 80-bit extended precision)
    /// - 0 for rip (special, no direct size class)
    pub fn size_class(&self) -> u8 {
        match self {
            Self::Al | Self::Cl | Self::Dl | Self::Bl |
            Self::Ah | Self::Ch | Self::Dh | Self::Bh => 8,

            Self::Ax | Self::Cx | Self::Dx | Self::Bx |
            Self::Sp | Self::Bp | Self::Si | Self::Di |
            Self::Es | Self::Cs | Self::Ss | Self::Ds |
            Self::Fs | Self::Gs => 16,

            Self::Eax | Self::Ecx | Self::Edx | Self::Ebx |
            Self::Esp | Self::Ebp | Self::Esi | Self::Edi |
            Self::Cr0 | Self::Cr1 | Self::Cr2 | Self::Cr3 |
            Self::Cr4 | Self::Cr5 | Self::Cr6 | Self::Cr7 |
            Self::Tr0 | Self::Tr1 | Self::Tr2 | Self::Tr3 |
            Self::Tr4 | Self::Tr5 | Self::Tr6 | Self::Tr7 |
            Self::Db0 | Self::Db1 | Self::Db2 | Self::Db3 |
            Self::Db4 | Self::Db5 | Self::Db6 | Self::Db7 |
            Self::Dr0 | Self::Dr1 | Self::Dr2 | Self::Dr3 |
            Self::Dr4 | Self::Dr5 | Self::Dr6 | Self::Dr7 => 32,

            Self::Mm0 | Self::Mm1 | Self::Mm2 | Self::Mm3 |
            Self::Mm4 | Self::Mm5 | Self::Mm6 | Self::Mm7 => 64,

            Self::Xmm0 | Self::Xmm1 | Self::Xmm2 | Self::Xmm3 |
            Self::Xmm4 | Self::Xmm5 | Self::Xmm6 | Self::Xmm7 => 128,

            Self::St => 80,
            Self::Rip => 0,
        }
    }
}

// =============================================================================

// =============================================================================
// X86 Instruction Mnemonic Tokens
// =============================================================================

/// x86 assembly instruction mnemonic tokens.
///
/// Ported from `i386-tok.h` (332 lines) and `i386-asm.h` (490 lines).
/// The enum ordering is CRITICAL — it exactly mirrors the C token numbering:
///
/// 1. Lines 181-307 of `i386-tok.h`: macro-generated instruction tokens (400 entries)
///    - `DEF_BWLX(x)` → 4 variants: `xb`, `xw`, `xl`, `x`
///    - `DEF_WLX(x)` → 3 variants: `xw`, `xl`, `x`
///    - `DEF_BWL(x)` → 4 variants: `xb`, `xw`, `xl`, `x`
///    - `DEF_ASMTEST(j,)` → 30 conditional jump variants
///    - `DEF_FP(x)` → 6 FP variants: `fx`, `fxp`, `fxs`, `fi{root}l`, `fxl`, `fi{root}s`
/// 2. First pass of `i386-asm.h`: 95 OP0 tokens (zero-operand instructions)
/// 3. Second pass of `i386-asm.h`: 147 non-OP0 tokens (1-3 operand instructions)
///
/// Total: 643 unique instruction variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
#[allow(non_camel_case_types)]
pub enum X86Instruction {
    // --- Generic two-operand (mov, add, or, adc, sbb, and, sub, xor, cmp) ---
    MovB = 0,
    MovW,
    MovL,
    Mov,
    AddB,
    AddW,
    AddL,
    Add,
    OrB,
    OrW,
    OrL,
    Or,
    AdcB,
    AdcW,
    AdcL,
    Adc,
    SbbB,
    SbbW,
    SbbL,
    Sbb,
    AndB,
    AndW,
    AndL,
    And,
    SubB,
    SubW,
    SubL,
    Sub,
    XorB,
    XorW,
    XorL,
    Xor,
    CmpB,
    CmpW,
    CmpL,
    Cmp,
    // --- Unary ops (inc, dec, not, neg, mul, imul, div, idiv) ---
    IncB,
    IncW,
    IncL,
    Inc,
    DecB,
    DecW,
    DecL,
    Dec,
    NotB,
    NotW,
    NotL,
    Not,
    NegB,
    NegW,
    NegL,
    Neg,
    MulB,
    MulW,
    MulL,
    Mul,
    ImulB,
    ImulW,
    ImulL,
    Imul,
    DivB,
    DivW,
    DivL,
    Div,
    IdivB,
    IdivW,
    IdivL,
    Idiv,
    // --- Exchange/test (xchg, test) ---
    XchgB,
    XchgW,
    XchgL,
    Xchg,
    TestB,
    TestW,
    TestL,
    Test,
    // --- Shifts (rol, ror, rcl, rcr, shl, shr, sar) ---
    RolB,
    RolW,
    RolL,
    Rol,
    RorB,
    RorW,
    RorL,
    Ror,
    RclB,
    RclW,
    RclL,
    Rcl,
    RcrB,
    RcrW,
    RcrL,
    Rcr,
    ShlB,
    ShlW,
    ShlL,
    Shl,
    ShrB,
    ShrW,
    ShrL,
    Shr,
    SarB,
    SarW,
    SarL,
    Sar,
    // --- Double shifts (shld, shrd) ---
    ShldW,
    ShldL,
    Shld,
    ShrdW,
    ShrdL,
    Shrd,
    // --- Push/pop ---
    PushW,
    PushL,
    Push,
    PopW,
    PopL,
    Pop,
    // --- I/O (in, out) ---
    InB,
    InW,
    InL,
    In,
    OutB,
    OutW,
    OutL,
    Out,
    // --- Move with zero/sign extension ---
    MovzbW,
    MovzbL,
    Movzb,
    Movzwl,
    Movsbw,
    Movsbl,
    Movswl,
    LeaW,
    LeaL,
    Lea,
    // --- Load effective address ---
    Les,
    Lds,
    Lss,
    // --- Segment loads ---
    Lfs,
    Lgs,
    Call,
    Jmp,
    Lcall,
    // --- Call/jump ---
    Ljmp,
    JO,
    JNo,
    JB,
    // --- Conditional jumps (30 variants) ---
    JC,
    JNae,
    JNb,
    JNc,
    JAe,
    JE,
    JZ,
    JNe,
    JNz,
    JBe,
    JNa,
    JNbe,
    JA,
    JS,
    JNs,
    JP,
    JPe,
    JNp,
    JPo,
    JL,
    JNge,
    JNl,
    JGe,
    JLe,
    JNg,
    JNle,
    JG,
    SetO,
    SetNo,
    SetB,
    // --- Conditional set (30 variants) ---
    SetC,
    SetNae,
    SetNb,
    SetNc,
    SetAe,
    SetE,
    SetZ,
    SetNe,
    SetNz,
    SetBe,
    SetNa,
    SetNbe,
    SetA,
    SetS,
    SetNs,
    SetP,
    SetPe,
    SetNp,
    SetPo,
    SetL,
    SetNge,
    SetNl,
    SetGe,
    SetLe,
    SetNg,
    SetNle,
    SetG,
    SetOB,
    SetNoB,
    SetBB,
    // --- Conditional set with b suffix (30 variants) ---
    SetCB,
    SetNaeB,
    SetNbB,
    SetNcB,
    SetAeB,
    SetEB,
    SetZB,
    SetNeB,
    SetNzB,
    SetBeB,
    SetNaB,
    SetNbeB,
    SetAB,
    SetSB,
    SetNsB,
    SetPB,
    SetPeB,
    SetNpB,
    SetPoB,
    SetLB,
    SetNgeB,
    SetNlB,
    SetGeB,
    SetLeB,
    SetNgB,
    SetNleB,
    SetGB,
    CmovO,
    CmovNo,
    CmovB,
    // --- Conditional move (30 variants) ---
    CmovC,
    CmovNae,
    CmovNb,
    CmovNc,
    CmovAe,
    CmovE,
    CmovZ,
    CmovNe,
    CmovNz,
    CmovBe,
    CmovNa,
    CmovNbe,
    CmovA,
    CmovS,
    CmovNs,
    CmovP,
    CmovPe,
    CmovNp,
    CmovPo,
    CmovL,
    CmovNge,
    CmovNl,
    CmovGe,
    CmovLe,
    CmovNg,
    CmovNle,
    CmovG,
    BsfW,
    BsfL,
    Bsf,
    // --- Bit scan/test (bsf, bsr, bt, bts, btr, btc, popcnt, tzcnt, lzcnt) ---
    BsrW,
    BsrL,
    Bsr,
    BtW,
    BtL,
    Bt,
    BtsW,
    BtsL,
    Bts,
    BtrW,
    BtrL,
    Btr,
    BtcW,
    BtcL,
    Btc,
    PopcntW,
    PopcntL,
    Popcnt,
    TzcntW,
    TzcntL,
    Tzcnt,
    LzcntW,
    LzcntL,
    Lzcnt,
    LarW,
    LarL,
    Lar,
    // --- Segment descriptor (lar, lsl) ---
    LslW,
    LslL,
    Lsl,
    FAdd,
    FAddp,
    FAdds,
    // --- FPU arithmetic (DEF_FP expansions) ---
    FiAddl,
    FAddl,
    FiAdds,
    FMul,
    FMulp,
    FMuls,
    FiMull,
    FMull,
    FiMuls,
    Fcom,
    FcomX1,
    Fcoms,
    // --- FPU compare special (fcom, fcom_1 placeholder, DEF_FP1(com)) ---
    Ficoml,
    Fcoml,
    Ficoms,
    FComp,
    FCompp,
    FComps,
    // --- FPU compare with pop, sub, subr, div, divr (DEF_FP) ---
    FiCompl,
    FCompl,
    FiComps,
    FSub,
    FSubp,
    FSubs,
    FiSubl,
    FSubl,
    FiSubs,
    FSubr,
    FSubrp,
    FSubrs,
    FiSubrl,
    FSubrl,
    FiSubrs,
    FDiv,
    FDivp,
    FDivs,
    FiDivl,
    FDivl,
    FiDivs,
    FDivr,
    FDivrp,
    FDivrs,
    FiDivrl,
    FDivrl,
    FiDivrs,
    XaddB,
    XaddW,
    XaddL,
    // --- Extended exchange (xadd, cmpxchg) ---
    Xadd,
    CmpxchgB,
    CmpxchgW,
    CmpxchgL,
    Cmpxchg,
    CmpsB,
    CmpsW,
    CmpsL,
    // --- String operations ---
    Cmps,
    ScmpB,
    ScmpW,
    ScmpL,
    Scmp,
    InsB,
    InsW,
    InsL,
    Ins,
    OutsB,
    OutsW,
    OutsL,
    Outs,
    LodsB,
    LodsW,
    LodsL,
    Lods,
    SlodB,
    SlodW,
    SlodL,
    Slod,
    MovsB,
    MovsW,
    MovsL,
    Movs,
    SmovB,
    SmovW,
    SmovL,
    Smov,
    ScasB,
    ScasW,
    ScasL,
    Scas,
    SscaB,
    SscaW,
    SscaL,
    Ssca,
    StosB,
    StosW,
    StosL,
    Stos,
    SstoB,
    SstoW,
    SstoL,
    Ssto,

    // === First pass of i386-asm.h: OP0 tokens (95 entries) ===
    Clc,
    Cld,
    Cli,
    Clts,
    Cmc,
    Lahf,
    Sahf,
    Pusha,
    Popa,
    Pushfl,
    Popfl,
    Pushf,
    Popf,
    Stc,
    Std,
    Sti,
    Aaa,
    Aas,
    Daa,
    Das,
    Aad,
    Aam,
    Cbw,
    Cwd,
    Cwde,
    Cdq,
    Cbtw,
    Cwtl,
    Cwtd,
    Cltd,
    Int3,
    Into,
    Iret,
    Rsm,
    Hlt,
    Nop,
    Pause,
    Xlat,
    Wait_,
    Fwait,
    Aword,
    /// Operand-size prefix (0x66) — alias for `data16`.
    ///
    /// From C source `i386-asm.h`: `ALT(DEF_ASM_OP0(word, 0x66))`.
    /// This is the `word` instruction mnemonic, which emits the 0x66
    /// operand-size prefix byte, overriding the default operand size
    /// to 16 bits in 32-bit mode.
    Word,
    Addr16,
    Data16,
    Lock,
    Rep,
    Repe,
    Repz,
    Repne,
    Repnz,
    Invd,
    Wbinvd,
    Cpuid,
    Wrmsr,
    Rdtsc,
    Rdmsr,
    Rdpmc,
    Ud2,
    Leave,
    Ret,
    Retl,
    Lret,
    Fucompp,
    Ftst,
    Fxam,
    Fld1,
    Fldl2t,
    Fldl2e,
    Fldpi,
    Fldlg2,
    Fldln2,
    Fldz,
    F2xm1,
    Fyl2x,
    Fptan,
    Fpatan,
    Fxtract,
    Fprem1,
    Fdecstp,
    Fincstp,
    Fprem,
    Fyl2xp1,
    Fsqrt,
    Fsincos,
    Frndint,
    Fscale,
    Fsin,
    Fcos,
    Fchs,
    Fabs,
    Fninit,
    Fnclex,
    Fnop,
    Fxch,
    Fnstsw,
    Emms,

    // === Second pass of i386-asm.h: non-OP0 tokens (147 entries) ===
    Endbr32,
    Enter,
    Loopne,
    Loopnz,
    Loope,
    Loopz,
    Loop,
    Jecxz,
    Fld,
    Fldl,
    Flds,
    Fildl,
    Fildq,
    Fildll,
    Fldt,
    Fbld,
    Fst,
    Fstl,
    Fsts,
    Fstps,
    Fstpl,
    Fist,
    Fistp,
    Fistl,
    Fistpl,
    Fstp,
    Fistpq,
    Fistpll,
    Fstpt,
    Fbstp,
    Fucom,
    Fucomp,
    Finit,
    Fldcw,
    Fnstcw,
    Fstcw,
    Fstsw,
    Fclex,
    Fnstenv,
    Fstenv,
    Fldenv,
    Fnsave,
    Fsave,
    Frstor,
    Ffree,
    Ffreep,
    Fxsave,
    Fxrstor,
    Arpl,
    Lgdt,
    Lidt,
    Lldt,
    Lmsw,
    Ltr,
    Sgdt,
    Sidt,
    Sldt,
    Smsw,
    Str,
    Verr,
    Verw,
    Bswap,
    Invlpg,
    Boundl,
    Boundw,
    Cmpxchg8b,
    Fcmovb,
    Fcmove,
    Fcmovbe,
    Fcmovu,
    Fcmovnb,
    Fcmovne,
    Fcmovnbe,
    Fcmovnu,
    Fucomi,
    Fcomi,
    Fucomip,
    Fcomip,
    Movd,
    Movq,
    Packssdw,
    Packsswb,
    Packuswb,
    Paddb,
    Paddw,
    Paddd,
    Paddsb,
    Paddsw,
    Paddusb,
    Paddusw,
    Pand,
    Pandn,
    Pcmpeqb,
    Pcmpeqw,
    Pcmpeqd,
    Pcmpgtb,
    Pcmpgtw,
    Pcmpgtd,
    Pmaddwd,
    Pmulhw,
    Pmullw,
    Por,
    Psllw,
    Pslld,
    Psllq,
    Psraw,
    Psrad,
    Psrlw,
    Psrld,
    Psrlq,
    Psubb,
    Psubw,
    Psubd,
    Psubsb,
    Psubsw,
    Psubusb,
    Psubusw,
    Punpckhbw,
    Punpckhwd,
    Punpckhdq,
    Punpcklbw,
    Punpcklwd,
    Punpckldq,
    Pxor,
    Ldmxcsr,
    Stmxcsr,
    Movups,
    Movaps,
    Movhps,
    Addps,
    Cvtpi2ps,
    Cvtps2pi,
    Cvttps2pi,
    Divps,
    Maxps,
    Minps,
    Mulps,
    Pavgb,
    Pavgw,
    Pmaxsw,
    Pmaxub,
    Pminsw,
    Pminub,
    Rcpss,
    Rsqrtps,
    Sqrtps,
    Subps,
}

/// Lookup table mapping instruction enum discriminant to assembly name string.
/// Index corresponds to enum discriminant value.
static INSTRUCTION_TABLE: &[(X86Instruction, &str)] = &[
    (X86Instruction::MovB, "movb"),
    (X86Instruction::MovW, "movw"),
    (X86Instruction::MovL, "movl"),
    (X86Instruction::Mov, "mov"),
    (X86Instruction::AddB, "addb"),
    (X86Instruction::AddW, "addw"),
    (X86Instruction::AddL, "addl"),
    (X86Instruction::Add, "add"),
    (X86Instruction::OrB, "orb"),
    (X86Instruction::OrW, "orw"),
    (X86Instruction::OrL, "orl"),
    (X86Instruction::Or, "or"),
    (X86Instruction::AdcB, "adcb"),
    (X86Instruction::AdcW, "adcw"),
    (X86Instruction::AdcL, "adcl"),
    (X86Instruction::Adc, "adc"),
    (X86Instruction::SbbB, "sbbb"),
    (X86Instruction::SbbW, "sbbw"),
    (X86Instruction::SbbL, "sbbl"),
    (X86Instruction::Sbb, "sbb"),
    (X86Instruction::AndB, "andb"),
    (X86Instruction::AndW, "andw"),
    (X86Instruction::AndL, "andl"),
    (X86Instruction::And, "and"),
    (X86Instruction::SubB, "subb"),
    (X86Instruction::SubW, "subw"),
    (X86Instruction::SubL, "subl"),
    (X86Instruction::Sub, "sub"),
    (X86Instruction::XorB, "xorb"),
    (X86Instruction::XorW, "xorw"),
    (X86Instruction::XorL, "xorl"),
    (X86Instruction::Xor, "xor"),
    (X86Instruction::CmpB, "cmpb"),
    (X86Instruction::CmpW, "cmpw"),
    (X86Instruction::CmpL, "cmpl"),
    (X86Instruction::Cmp, "cmp"),
    (X86Instruction::IncB, "incb"),
    (X86Instruction::IncW, "incw"),
    (X86Instruction::IncL, "incl"),
    (X86Instruction::Inc, "inc"),
    (X86Instruction::DecB, "decb"),
    (X86Instruction::DecW, "decw"),
    (X86Instruction::DecL, "decl"),
    (X86Instruction::Dec, "dec"),
    (X86Instruction::NotB, "notb"),
    (X86Instruction::NotW, "notw"),
    (X86Instruction::NotL, "notl"),
    (X86Instruction::Not, "not"),
    (X86Instruction::NegB, "negb"),
    (X86Instruction::NegW, "negw"),
    (X86Instruction::NegL, "negl"),
    (X86Instruction::Neg, "neg"),
    (X86Instruction::MulB, "mulb"),
    (X86Instruction::MulW, "mulw"),
    (X86Instruction::MulL, "mull"),
    (X86Instruction::Mul, "mul"),
    (X86Instruction::ImulB, "imulb"),
    (X86Instruction::ImulW, "imulw"),
    (X86Instruction::ImulL, "imull"),
    (X86Instruction::Imul, "imul"),
    (X86Instruction::DivB, "divb"),
    (X86Instruction::DivW, "divw"),
    (X86Instruction::DivL, "divl"),
    (X86Instruction::Div, "div"),
    (X86Instruction::IdivB, "idivb"),
    (X86Instruction::IdivW, "idivw"),
    (X86Instruction::IdivL, "idivl"),
    (X86Instruction::Idiv, "idiv"),
    (X86Instruction::XchgB, "xchgb"),
    (X86Instruction::XchgW, "xchgw"),
    (X86Instruction::XchgL, "xchgl"),
    (X86Instruction::Xchg, "xchg"),
    (X86Instruction::TestB, "testb"),
    (X86Instruction::TestW, "testw"),
    (X86Instruction::TestL, "testl"),
    (X86Instruction::Test, "test"),
    (X86Instruction::RolB, "rolb"),
    (X86Instruction::RolW, "rolw"),
    (X86Instruction::RolL, "roll"),
    (X86Instruction::Rol, "rol"),
    (X86Instruction::RorB, "rorb"),
    (X86Instruction::RorW, "rorw"),
    (X86Instruction::RorL, "rorl"),
    (X86Instruction::Ror, "ror"),
    (X86Instruction::RclB, "rclb"),
    (X86Instruction::RclW, "rclw"),
    (X86Instruction::RclL, "rcll"),
    (X86Instruction::Rcl, "rcl"),
    (X86Instruction::RcrB, "rcrb"),
    (X86Instruction::RcrW, "rcrw"),
    (X86Instruction::RcrL, "rcrl"),
    (X86Instruction::Rcr, "rcr"),
    (X86Instruction::ShlB, "shlb"),
    (X86Instruction::ShlW, "shlw"),
    (X86Instruction::ShlL, "shll"),
    (X86Instruction::Shl, "shl"),
    (X86Instruction::ShrB, "shrb"),
    (X86Instruction::ShrW, "shrw"),
    (X86Instruction::ShrL, "shrl"),
    (X86Instruction::Shr, "shr"),
    (X86Instruction::SarB, "sarb"),
    (X86Instruction::SarW, "sarw"),
    (X86Instruction::SarL, "sarl"),
    (X86Instruction::Sar, "sar"),
    (X86Instruction::ShldW, "shldw"),
    (X86Instruction::ShldL, "shldl"),
    (X86Instruction::Shld, "shld"),
    (X86Instruction::ShrdW, "shrdw"),
    (X86Instruction::ShrdL, "shrdl"),
    (X86Instruction::Shrd, "shrd"),
    (X86Instruction::PushW, "pushw"),
    (X86Instruction::PushL, "pushl"),
    (X86Instruction::Push, "push"),
    (X86Instruction::PopW, "popw"),
    (X86Instruction::PopL, "popl"),
    (X86Instruction::Pop, "pop"),
    (X86Instruction::InB, "inb"),
    (X86Instruction::InW, "inw"),
    (X86Instruction::InL, "inl"),
    (X86Instruction::In, "in"),
    (X86Instruction::OutB, "outb"),
    (X86Instruction::OutW, "outw"),
    (X86Instruction::OutL, "outl"),
    (X86Instruction::Out, "out"),
    (X86Instruction::MovzbW, "movzbw"),
    (X86Instruction::MovzbL, "movzbl"),
    (X86Instruction::Movzb, "movzb"),
    (X86Instruction::Movzwl, "movzwl"),
    (X86Instruction::Movsbw, "movsbw"),
    (X86Instruction::Movsbl, "movsbl"),
    (X86Instruction::Movswl, "movswl"),
    (X86Instruction::LeaW, "leaw"),
    (X86Instruction::LeaL, "leal"),
    (X86Instruction::Lea, "lea"),
    (X86Instruction::Les, "les"),
    (X86Instruction::Lds, "lds"),
    (X86Instruction::Lss, "lss"),
    (X86Instruction::Lfs, "lfs"),
    (X86Instruction::Lgs, "lgs"),
    (X86Instruction::Call, "call"),
    (X86Instruction::Jmp, "jmp"),
    (X86Instruction::Lcall, "lcall"),
    (X86Instruction::Ljmp, "ljmp"),
    (X86Instruction::JO, "jo"),
    (X86Instruction::JNo, "jno"),
    (X86Instruction::JB, "jb"),
    (X86Instruction::JC, "jc"),
    (X86Instruction::JNae, "jnae"),
    (X86Instruction::JNb, "jnb"),
    (X86Instruction::JNc, "jnc"),
    (X86Instruction::JAe, "jae"),
    (X86Instruction::JE, "je"),
    (X86Instruction::JZ, "jz"),
    (X86Instruction::JNe, "jne"),
    (X86Instruction::JNz, "jnz"),
    (X86Instruction::JBe, "jbe"),
    (X86Instruction::JNa, "jna"),
    (X86Instruction::JNbe, "jnbe"),
    (X86Instruction::JA, "ja"),
    (X86Instruction::JS, "js"),
    (X86Instruction::JNs, "jns"),
    (X86Instruction::JP, "jp"),
    (X86Instruction::JPe, "jpe"),
    (X86Instruction::JNp, "jnp"),
    (X86Instruction::JPo, "jpo"),
    (X86Instruction::JL, "jl"),
    (X86Instruction::JNge, "jnge"),
    (X86Instruction::JNl, "jnl"),
    (X86Instruction::JGe, "jge"),
    (X86Instruction::JLe, "jle"),
    (X86Instruction::JNg, "jng"),
    (X86Instruction::JNle, "jnle"),
    (X86Instruction::JG, "jg"),
    (X86Instruction::SetO, "seto"),
    (X86Instruction::SetNo, "setno"),
    (X86Instruction::SetB, "setb"),
    (X86Instruction::SetC, "setc"),
    (X86Instruction::SetNae, "setnae"),
    (X86Instruction::SetNb, "setnb"),
    (X86Instruction::SetNc, "setnc"),
    (X86Instruction::SetAe, "setae"),
    (X86Instruction::SetE, "sete"),
    (X86Instruction::SetZ, "setz"),
    (X86Instruction::SetNe, "setne"),
    (X86Instruction::SetNz, "setnz"),
    (X86Instruction::SetBe, "setbe"),
    (X86Instruction::SetNa, "setna"),
    (X86Instruction::SetNbe, "setnbe"),
    (X86Instruction::SetA, "seta"),
    (X86Instruction::SetS, "sets"),
    (X86Instruction::SetNs, "setns"),
    (X86Instruction::SetP, "setp"),
    (X86Instruction::SetPe, "setpe"),
    (X86Instruction::SetNp, "setnp"),
    (X86Instruction::SetPo, "setpo"),
    (X86Instruction::SetL, "setl"),
    (X86Instruction::SetNge, "setnge"),
    (X86Instruction::SetNl, "setnl"),
    (X86Instruction::SetGe, "setge"),
    (X86Instruction::SetLe, "setle"),
    (X86Instruction::SetNg, "setng"),
    (X86Instruction::SetNle, "setnle"),
    (X86Instruction::SetG, "setg"),
    (X86Instruction::SetOB, "setob"),
    (X86Instruction::SetNoB, "setnob"),
    (X86Instruction::SetBB, "setbb"),
    (X86Instruction::SetCB, "setcb"),
    (X86Instruction::SetNaeB, "setnaeb"),
    (X86Instruction::SetNbB, "setnbb"),
    (X86Instruction::SetNcB, "setncb"),
    (X86Instruction::SetAeB, "setaeb"),
    (X86Instruction::SetEB, "seteb"),
    (X86Instruction::SetZB, "setzb"),
    (X86Instruction::SetNeB, "setneb"),
    (X86Instruction::SetNzB, "setnzb"),
    (X86Instruction::SetBeB, "setbeb"),
    (X86Instruction::SetNaB, "setnab"),
    (X86Instruction::SetNbeB, "setnbeb"),
    (X86Instruction::SetAB, "setab"),
    (X86Instruction::SetSB, "setsb"),
    (X86Instruction::SetNsB, "setnsb"),
    (X86Instruction::SetPB, "setpb"),
    (X86Instruction::SetPeB, "setpeb"),
    (X86Instruction::SetNpB, "setnpb"),
    (X86Instruction::SetPoB, "setpob"),
    (X86Instruction::SetLB, "setlb"),
    (X86Instruction::SetNgeB, "setngeb"),
    (X86Instruction::SetNlB, "setnlb"),
    (X86Instruction::SetGeB, "setgeb"),
    (X86Instruction::SetLeB, "setleb"),
    (X86Instruction::SetNgB, "setngb"),
    (X86Instruction::SetNleB, "setnleb"),
    (X86Instruction::SetGB, "setgb"),
    (X86Instruction::CmovO, "cmovo"),
    (X86Instruction::CmovNo, "cmovno"),
    (X86Instruction::CmovB, "cmovb"),
    (X86Instruction::CmovC, "cmovc"),
    (X86Instruction::CmovNae, "cmovnae"),
    (X86Instruction::CmovNb, "cmovnb"),
    (X86Instruction::CmovNc, "cmovnc"),
    (X86Instruction::CmovAe, "cmovae"),
    (X86Instruction::CmovE, "cmove"),
    (X86Instruction::CmovZ, "cmovz"),
    (X86Instruction::CmovNe, "cmovne"),
    (X86Instruction::CmovNz, "cmovnz"),
    (X86Instruction::CmovBe, "cmovbe"),
    (X86Instruction::CmovNa, "cmovna"),
    (X86Instruction::CmovNbe, "cmovnbe"),
    (X86Instruction::CmovA, "cmova"),
    (X86Instruction::CmovS, "cmovs"),
    (X86Instruction::CmovNs, "cmovns"),
    (X86Instruction::CmovP, "cmovp"),
    (X86Instruction::CmovPe, "cmovpe"),
    (X86Instruction::CmovNp, "cmovnp"),
    (X86Instruction::CmovPo, "cmovpo"),
    (X86Instruction::CmovL, "cmovl"),
    (X86Instruction::CmovNge, "cmovnge"),
    (X86Instruction::CmovNl, "cmovnl"),
    (X86Instruction::CmovGe, "cmovge"),
    (X86Instruction::CmovLe, "cmovle"),
    (X86Instruction::CmovNg, "cmovng"),
    (X86Instruction::CmovNle, "cmovnle"),
    (X86Instruction::CmovG, "cmovg"),
    (X86Instruction::BsfW, "bsfw"),
    (X86Instruction::BsfL, "bsfl"),
    (X86Instruction::Bsf, "bsf"),
    (X86Instruction::BsrW, "bsrw"),
    (X86Instruction::BsrL, "bsrl"),
    (X86Instruction::Bsr, "bsr"),
    (X86Instruction::BtW, "btw"),
    (X86Instruction::BtL, "btl"),
    (X86Instruction::Bt, "bt"),
    (X86Instruction::BtsW, "btsw"),
    (X86Instruction::BtsL, "btsl"),
    (X86Instruction::Bts, "bts"),
    (X86Instruction::BtrW, "btrw"),
    (X86Instruction::BtrL, "btrl"),
    (X86Instruction::Btr, "btr"),
    (X86Instruction::BtcW, "btcw"),
    (X86Instruction::BtcL, "btcl"),
    (X86Instruction::Btc, "btc"),
    (X86Instruction::PopcntW, "popcntw"),
    (X86Instruction::PopcntL, "popcntl"),
    (X86Instruction::Popcnt, "popcnt"),
    (X86Instruction::TzcntW, "tzcntw"),
    (X86Instruction::TzcntL, "tzcntl"),
    (X86Instruction::Tzcnt, "tzcnt"),
    (X86Instruction::LzcntW, "lzcntw"),
    (X86Instruction::LzcntL, "lzcntl"),
    (X86Instruction::Lzcnt, "lzcnt"),
    (X86Instruction::LarW, "larw"),
    (X86Instruction::LarL, "larl"),
    (X86Instruction::Lar, "lar"),
    (X86Instruction::LslW, "lslw"),
    (X86Instruction::LslL, "lsll"),
    (X86Instruction::Lsl, "lsl"),
    (X86Instruction::FAdd, "fadd"),
    (X86Instruction::FAddp, "faddp"),
    (X86Instruction::FAdds, "fadds"),
    (X86Instruction::FiAddl, "fiaddl"),
    (X86Instruction::FAddl, "faddl"),
    (X86Instruction::FiAdds, "fiadds"),
    (X86Instruction::FMul, "fmul"),
    (X86Instruction::FMulp, "fmulp"),
    (X86Instruction::FMuls, "fmuls"),
    (X86Instruction::FiMull, "fimull"),
    (X86Instruction::FMull, "fmull"),
    (X86Instruction::FiMuls, "fimuls"),
    (X86Instruction::Fcom, "fcom"),
    (X86Instruction::FcomX1, "fcom_1"),
    (X86Instruction::Fcoms, "fcoms"),
    (X86Instruction::Ficoml, "ficoml"),
    (X86Instruction::Fcoml, "fcoml"),
    (X86Instruction::Ficoms, "ficoms"),
    (X86Instruction::FComp, "fcomp"),
    (X86Instruction::FCompp, "fcompp"),
    (X86Instruction::FComps, "fcomps"),
    (X86Instruction::FiCompl, "ficompl"),
    (X86Instruction::FCompl, "fcompl"),
    (X86Instruction::FiComps, "ficomps"),
    (X86Instruction::FSub, "fsub"),
    (X86Instruction::FSubp, "fsubp"),
    (X86Instruction::FSubs, "fsubs"),
    (X86Instruction::FiSubl, "fisubl"),
    (X86Instruction::FSubl, "fsubl"),
    (X86Instruction::FiSubs, "fisubs"),
    (X86Instruction::FSubr, "fsubr"),
    (X86Instruction::FSubrp, "fsubrp"),
    (X86Instruction::FSubrs, "fsubrs"),
    (X86Instruction::FiSubrl, "fisubrl"),
    (X86Instruction::FSubrl, "fsubrl"),
    (X86Instruction::FiSubrs, "fisubrs"),
    (X86Instruction::FDiv, "fdiv"),
    (X86Instruction::FDivp, "fdivp"),
    (X86Instruction::FDivs, "fdivs"),
    (X86Instruction::FiDivl, "fidivl"),
    (X86Instruction::FDivl, "fdivl"),
    (X86Instruction::FiDivs, "fidivs"),
    (X86Instruction::FDivr, "fdivr"),
    (X86Instruction::FDivrp, "fdivrp"),
    (X86Instruction::FDivrs, "fdivrs"),
    (X86Instruction::FiDivrl, "fidivrl"),
    (X86Instruction::FDivrl, "fdivrl"),
    (X86Instruction::FiDivrs, "fidivrs"),
    (X86Instruction::XaddB, "xaddb"),
    (X86Instruction::XaddW, "xaddw"),
    (X86Instruction::XaddL, "xaddl"),
    (X86Instruction::Xadd, "xadd"),
    (X86Instruction::CmpxchgB, "cmpxchgb"),
    (X86Instruction::CmpxchgW, "cmpxchgw"),
    (X86Instruction::CmpxchgL, "cmpxchgl"),
    (X86Instruction::Cmpxchg, "cmpxchg"),
    (X86Instruction::CmpsB, "cmpsb"),
    (X86Instruction::CmpsW, "cmpsw"),
    (X86Instruction::CmpsL, "cmpsl"),
    (X86Instruction::Cmps, "cmps"),
    (X86Instruction::ScmpB, "scmpb"),
    (X86Instruction::ScmpW, "scmpw"),
    (X86Instruction::ScmpL, "scmpl"),
    (X86Instruction::Scmp, "scmp"),
    (X86Instruction::InsB, "insb"),
    (X86Instruction::InsW, "insw"),
    (X86Instruction::InsL, "insl"),
    (X86Instruction::Ins, "ins"),
    (X86Instruction::OutsB, "outsb"),
    (X86Instruction::OutsW, "outsw"),
    (X86Instruction::OutsL, "outsl"),
    (X86Instruction::Outs, "outs"),
    (X86Instruction::LodsB, "lodsb"),
    (X86Instruction::LodsW, "lodsw"),
    (X86Instruction::LodsL, "lodsl"),
    (X86Instruction::Lods, "lods"),
    (X86Instruction::SlodB, "slodb"),
    (X86Instruction::SlodW, "slodw"),
    (X86Instruction::SlodL, "slodl"),
    (X86Instruction::Slod, "slod"),
    (X86Instruction::MovsB, "movsb"),
    (X86Instruction::MovsW, "movsw"),
    (X86Instruction::MovsL, "movsl"),
    (X86Instruction::Movs, "movs"),
    (X86Instruction::SmovB, "smovb"),
    (X86Instruction::SmovW, "smovw"),
    (X86Instruction::SmovL, "smovl"),
    (X86Instruction::Smov, "smov"),
    (X86Instruction::ScasB, "scasb"),
    (X86Instruction::ScasW, "scasw"),
    (X86Instruction::ScasL, "scasl"),
    (X86Instruction::Scas, "scas"),
    (X86Instruction::SscaB, "sscab"),
    (X86Instruction::SscaW, "sscaw"),
    (X86Instruction::SscaL, "sscal"),
    (X86Instruction::Ssca, "ssca"),
    (X86Instruction::StosB, "stosb"),
    (X86Instruction::StosW, "stosw"),
    (X86Instruction::StosL, "stosl"),
    (X86Instruction::Stos, "stos"),
    (X86Instruction::SstoB, "sstob"),
    (X86Instruction::SstoW, "sstow"),
    (X86Instruction::SstoL, "sstol"),
    (X86Instruction::Ssto, "ssto"),
    (X86Instruction::Clc, "clc"),
    (X86Instruction::Cld, "cld"),
    (X86Instruction::Cli, "cli"),
    (X86Instruction::Clts, "clts"),
    (X86Instruction::Cmc, "cmc"),
    (X86Instruction::Lahf, "lahf"),
    (X86Instruction::Sahf, "sahf"),
    (X86Instruction::Pusha, "pusha"),
    (X86Instruction::Popa, "popa"),
    (X86Instruction::Pushfl, "pushfl"),
    (X86Instruction::Popfl, "popfl"),
    (X86Instruction::Pushf, "pushf"),
    (X86Instruction::Popf, "popf"),
    (X86Instruction::Stc, "stc"),
    (X86Instruction::Std, "std"),
    (X86Instruction::Sti, "sti"),
    (X86Instruction::Aaa, "aaa"),
    (X86Instruction::Aas, "aas"),
    (X86Instruction::Daa, "daa"),
    (X86Instruction::Das, "das"),
    (X86Instruction::Aad, "aad"),
    (X86Instruction::Aam, "aam"),
    (X86Instruction::Cbw, "cbw"),
    (X86Instruction::Cwd, "cwd"),
    (X86Instruction::Cwde, "cwde"),
    (X86Instruction::Cdq, "cdq"),
    (X86Instruction::Cbtw, "cbtw"),
    (X86Instruction::Cwtl, "cwtl"),
    (X86Instruction::Cwtd, "cwtd"),
    (X86Instruction::Cltd, "cltd"),
    (X86Instruction::Int3, "int3"),
    (X86Instruction::Into, "into"),
    (X86Instruction::Iret, "iret"),
    (X86Instruction::Rsm, "rsm"),
    (X86Instruction::Hlt, "hlt"),
    (X86Instruction::Nop, "nop"),
    (X86Instruction::Pause, "pause"),
    (X86Instruction::Xlat, "xlat"),
    (X86Instruction::Wait_, "wait"),
    (X86Instruction::Fwait, "fwait"),
    (X86Instruction::Aword, "aword"),
    (X86Instruction::Word, "word"),
    (X86Instruction::Addr16, "addr16"),
    (X86Instruction::Data16, "data16"),
    (X86Instruction::Lock, "lock"),
    (X86Instruction::Rep, "rep"),
    (X86Instruction::Repe, "repe"),
    (X86Instruction::Repz, "repz"),
    (X86Instruction::Repne, "repne"),
    (X86Instruction::Repnz, "repnz"),
    (X86Instruction::Invd, "invd"),
    (X86Instruction::Wbinvd, "wbinvd"),
    (X86Instruction::Cpuid, "cpuid"),
    (X86Instruction::Wrmsr, "wrmsr"),
    (X86Instruction::Rdtsc, "rdtsc"),
    (X86Instruction::Rdmsr, "rdmsr"),
    (X86Instruction::Rdpmc, "rdpmc"),
    (X86Instruction::Ud2, "ud2"),
    (X86Instruction::Leave, "leave"),
    (X86Instruction::Ret, "ret"),
    (X86Instruction::Retl, "retl"),
    (X86Instruction::Lret, "lret"),
    (X86Instruction::Fucompp, "fucompp"),
    (X86Instruction::Ftst, "ftst"),
    (X86Instruction::Fxam, "fxam"),
    (X86Instruction::Fld1, "fld1"),
    (X86Instruction::Fldl2t, "fldl2t"),
    (X86Instruction::Fldl2e, "fldl2e"),
    (X86Instruction::Fldpi, "fldpi"),
    (X86Instruction::Fldlg2, "fldlg2"),
    (X86Instruction::Fldln2, "fldln2"),
    (X86Instruction::Fldz, "fldz"),
    (X86Instruction::F2xm1, "f2xm1"),
    (X86Instruction::Fyl2x, "fyl2x"),
    (X86Instruction::Fptan, "fptan"),
    (X86Instruction::Fpatan, "fpatan"),
    (X86Instruction::Fxtract, "fxtract"),
    (X86Instruction::Fprem1, "fprem1"),
    (X86Instruction::Fdecstp, "fdecstp"),
    (X86Instruction::Fincstp, "fincstp"),
    (X86Instruction::Fprem, "fprem"),
    (X86Instruction::Fyl2xp1, "fyl2xp1"),
    (X86Instruction::Fsqrt, "fsqrt"),
    (X86Instruction::Fsincos, "fsincos"),
    (X86Instruction::Frndint, "frndint"),
    (X86Instruction::Fscale, "fscale"),
    (X86Instruction::Fsin, "fsin"),
    (X86Instruction::Fcos, "fcos"),
    (X86Instruction::Fchs, "fchs"),
    (X86Instruction::Fabs, "fabs"),
    (X86Instruction::Fninit, "fninit"),
    (X86Instruction::Fnclex, "fnclex"),
    (X86Instruction::Fnop, "fnop"),
    (X86Instruction::Fxch, "fxch"),
    (X86Instruction::Fnstsw, "fnstsw"),
    (X86Instruction::Emms, "emms"),
    (X86Instruction::Endbr32, "endbr32"),
    (X86Instruction::Enter, "enter"),
    (X86Instruction::Loopne, "loopne"),
    (X86Instruction::Loopnz, "loopnz"),
    (X86Instruction::Loope, "loope"),
    (X86Instruction::Loopz, "loopz"),
    (X86Instruction::Loop, "loop"),
    (X86Instruction::Jecxz, "jecxz"),
    (X86Instruction::Fld, "fld"),
    (X86Instruction::Fldl, "fldl"),
    (X86Instruction::Flds, "flds"),
    (X86Instruction::Fildl, "fildl"),
    (X86Instruction::Fildq, "fildq"),
    (X86Instruction::Fildll, "fildll"),
    (X86Instruction::Fldt, "fldt"),
    (X86Instruction::Fbld, "fbld"),
    (X86Instruction::Fst, "fst"),
    (X86Instruction::Fstl, "fstl"),
    (X86Instruction::Fsts, "fsts"),
    (X86Instruction::Fstps, "fstps"),
    (X86Instruction::Fstpl, "fstpl"),
    (X86Instruction::Fist, "fist"),
    (X86Instruction::Fistp, "fistp"),
    (X86Instruction::Fistl, "fistl"),
    (X86Instruction::Fistpl, "fistpl"),
    (X86Instruction::Fstp, "fstp"),
    (X86Instruction::Fistpq, "fistpq"),
    (X86Instruction::Fistpll, "fistpll"),
    (X86Instruction::Fstpt, "fstpt"),
    (X86Instruction::Fbstp, "fbstp"),
    (X86Instruction::Fucom, "fucom"),
    (X86Instruction::Fucomp, "fucomp"),
    (X86Instruction::Finit, "finit"),
    (X86Instruction::Fldcw, "fldcw"),
    (X86Instruction::Fnstcw, "fnstcw"),
    (X86Instruction::Fstcw, "fstcw"),
    (X86Instruction::Fstsw, "fstsw"),
    (X86Instruction::Fclex, "fclex"),
    (X86Instruction::Fnstenv, "fnstenv"),
    (X86Instruction::Fstenv, "fstenv"),
    (X86Instruction::Fldenv, "fldenv"),
    (X86Instruction::Fnsave, "fnsave"),
    (X86Instruction::Fsave, "fsave"),
    (X86Instruction::Frstor, "frstor"),
    (X86Instruction::Ffree, "ffree"),
    (X86Instruction::Ffreep, "ffreep"),
    (X86Instruction::Fxsave, "fxsave"),
    (X86Instruction::Fxrstor, "fxrstor"),
    (X86Instruction::Arpl, "arpl"),
    (X86Instruction::Lgdt, "lgdt"),
    (X86Instruction::Lidt, "lidt"),
    (X86Instruction::Lldt, "lldt"),
    (X86Instruction::Lmsw, "lmsw"),
    (X86Instruction::Ltr, "ltr"),
    (X86Instruction::Sgdt, "sgdt"),
    (X86Instruction::Sidt, "sidt"),
    (X86Instruction::Sldt, "sldt"),
    (X86Instruction::Smsw, "smsw"),
    (X86Instruction::Str, "str"),
    (X86Instruction::Verr, "verr"),
    (X86Instruction::Verw, "verw"),
    (X86Instruction::Bswap, "bswap"),
    (X86Instruction::Invlpg, "invlpg"),
    (X86Instruction::Boundl, "boundl"),
    (X86Instruction::Boundw, "boundw"),
    (X86Instruction::Cmpxchg8b, "cmpxchg8b"),
    (X86Instruction::Fcmovb, "fcmovb"),
    (X86Instruction::Fcmove, "fcmove"),
    (X86Instruction::Fcmovbe, "fcmovbe"),
    (X86Instruction::Fcmovu, "fcmovu"),
    (X86Instruction::Fcmovnb, "fcmovnb"),
    (X86Instruction::Fcmovne, "fcmovne"),
    (X86Instruction::Fcmovnbe, "fcmovnbe"),
    (X86Instruction::Fcmovnu, "fcmovnu"),
    (X86Instruction::Fucomi, "fucomi"),
    (X86Instruction::Fcomi, "fcomi"),
    (X86Instruction::Fucomip, "fucomip"),
    (X86Instruction::Fcomip, "fcomip"),
    (X86Instruction::Movd, "movd"),
    (X86Instruction::Movq, "movq"),
    (X86Instruction::Packssdw, "packssdw"),
    (X86Instruction::Packsswb, "packsswb"),
    (X86Instruction::Packuswb, "packuswb"),
    (X86Instruction::Paddb, "paddb"),
    (X86Instruction::Paddw, "paddw"),
    (X86Instruction::Paddd, "paddd"),
    (X86Instruction::Paddsb, "paddsb"),
    (X86Instruction::Paddsw, "paddsw"),
    (X86Instruction::Paddusb, "paddusb"),
    (X86Instruction::Paddusw, "paddusw"),
    (X86Instruction::Pand, "pand"),
    (X86Instruction::Pandn, "pandn"),
    (X86Instruction::Pcmpeqb, "pcmpeqb"),
    (X86Instruction::Pcmpeqw, "pcmpeqw"),
    (X86Instruction::Pcmpeqd, "pcmpeqd"),
    (X86Instruction::Pcmpgtb, "pcmpgtb"),
    (X86Instruction::Pcmpgtw, "pcmpgtw"),
    (X86Instruction::Pcmpgtd, "pcmpgtd"),
    (X86Instruction::Pmaddwd, "pmaddwd"),
    (X86Instruction::Pmulhw, "pmulhw"),
    (X86Instruction::Pmullw, "pmullw"),
    (X86Instruction::Por, "por"),
    (X86Instruction::Psllw, "psllw"),
    (X86Instruction::Pslld, "pslld"),
    (X86Instruction::Psllq, "psllq"),
    (X86Instruction::Psraw, "psraw"),
    (X86Instruction::Psrad, "psrad"),
    (X86Instruction::Psrlw, "psrlw"),
    (X86Instruction::Psrld, "psrld"),
    (X86Instruction::Psrlq, "psrlq"),
    (X86Instruction::Psubb, "psubb"),
    (X86Instruction::Psubw, "psubw"),
    (X86Instruction::Psubd, "psubd"),
    (X86Instruction::Psubsb, "psubsb"),
    (X86Instruction::Psubsw, "psubsw"),
    (X86Instruction::Psubusb, "psubusb"),
    (X86Instruction::Psubusw, "psubusw"),
    (X86Instruction::Punpckhbw, "punpckhbw"),
    (X86Instruction::Punpckhwd, "punpckhwd"),
    (X86Instruction::Punpckhdq, "punpckhdq"),
    (X86Instruction::Punpcklbw, "punpcklbw"),
    (X86Instruction::Punpcklwd, "punpcklwd"),
    (X86Instruction::Punpckldq, "punpckldq"),
    (X86Instruction::Pxor, "pxor"),
    (X86Instruction::Ldmxcsr, "ldmxcsr"),
    (X86Instruction::Stmxcsr, "stmxcsr"),
    (X86Instruction::Movups, "movups"),
    (X86Instruction::Movaps, "movaps"),
    (X86Instruction::Movhps, "movhps"),
    (X86Instruction::Addps, "addps"),
    (X86Instruction::Cvtpi2ps, "cvtpi2ps"),
    (X86Instruction::Cvtps2pi, "cvtps2pi"),
    (X86Instruction::Cvttps2pi, "cvttps2pi"),
    (X86Instruction::Divps, "divps"),
    (X86Instruction::Maxps, "maxps"),
    (X86Instruction::Minps, "minps"),
    (X86Instruction::Mulps, "mulps"),
    (X86Instruction::Pavgb, "pavgb"),
    (X86Instruction::Pavgw, "pavgw"),
    (X86Instruction::Pmaxsw, "pmaxsw"),
    (X86Instruction::Pmaxub, "pmaxub"),
    (X86Instruction::Pminsw, "pminsw"),
    (X86Instruction::Pminub, "pminub"),
    (X86Instruction::Rcpss, "rcpss"),
    (X86Instruction::Rsqrtps, "rsqrtps"),
    (X86Instruction::Sqrtps, "sqrtps"),
    (X86Instruction::Subps, "subps"),
];

impl X86Instruction {
    /// Returns the assembly mnemonic string for this instruction.
    pub fn name(&self) -> &'static str {
        let disc = *self as u16;
        if (disc as usize) < INSTRUCTION_TABLE.len() {
            INSTRUCTION_TABLE[disc as usize].1
        } else {
            "unknown"
        }
    }

    /// Looks up an instruction by its assembly mnemonic name.
    /// Performs a linear scan of the instruction table.
    pub fn from_name(name: &str) -> Option<Self> {
        for &(instr, n) in INSTRUCTION_TABLE.iter() {
            if n == name {
                return Some(instr);
            }
        }
        None
    }

    /// Returns the discriminant value as u16.
    #[inline]
    pub fn as_u16(self) -> u16 {
        self as u16
    }

    /// Total number of instruction variants in this enum.
    pub const INSTRUCTION_COUNT: usize = 643;

    /// Attempts to construct from a raw u16 discriminant.
    pub fn from_u16(val: u16) -> Option<Self> {
        if (val as usize) < Self::INSTRUCTION_COUNT {
            // SAFETY: val is within the range of valid discriminants (0..643)
            Some(unsafe { core::mem::transmute::<u16, Self>(val) })
        } else {
            None
        }
    }
}

// =============================================================================
// Opcode Table Entry and Complete Instruction Encoding Table
// =============================================================================

/// Opcode table entry — maps an instruction to its encoding information.
///
/// Used by the assembler (`asm.rs`) for x86 instruction encoding.
/// Each entry describes how to encode an instruction: the base opcode bytes,
/// the instruction type flags (modrm, size variants, etc.), the number of
/// operands, and the allowed operand types for each position.
#[derive(Debug, Clone, Copy)]
pub struct OpcodeEntry {
    /// Token identifier for this instruction
    pub token: X86Instruction,
    /// Base opcode value (1-2 bytes, may include 0x0F prefix indicator)
    pub opcode: u32,
    /// Instruction type flags (OPC_B, OPC_WL, OPC_MODRM, etc.)
    /// Combined with group number shifted by OPC_GROUP_SHIFT
    pub instr_type: u16,
    /// Number of operands (0-3)
    pub nb_ops: u8,
    /// Operand type constraints for each operand position.
    /// Each element is an `OPT_*` enum value (0-27), optionally ORed with
    /// `OPT_EA` (0x80) to indicate "effective address or base type".
    /// Unused operand slots are 0.
    pub op_type: [u32; 3],
}

/// Complete x86 instruction opcode table (`asm_instrs[]` equivalent).
///
/// Source: `i386-asm.h` — all `DEF_ASM_OP0L/OP1/OP2/OP3` entries (both
/// regular and ALT alternative-encoding forms). Simple `DEF_ASM_OP0` entries
/// are in the separate `OP0_CODES` table below.
///
/// The `token` field stores the FIRST suffix variant for suffixed instructions:
/// - For `OPC_BWLX` entries: token is the `*b` variant (e.g., `MovB` for mov)
/// - For `OPC_WLX` entries: token is the `*w` variant (e.g., `ShldW` for shld)
/// - For `OPC_TEST` entries: token is the first condition (e.g., `SetO` for set*)
/// - For `OPC_FARITH` entries: token is the base FP instruction (e.g., `FAdd`)
///
/// The `opcode` field stores the O()-transformed opcode (0x0F prefix stripped
/// and encoded in `instr_type` flags instead).
///
/// The `instr_type` field stores T()-transformed flags combining the instruction
/// type, group number (shifted by `OPC_GROUP_SHIFT`), and `OPC_0F` flag.
///
/// Operand types use `OPT_*` enum values (NOT `OP_*` bitmasks). `OPT_EA` (0x80)
/// can be ORed with a base type to indicate "effective address or register".
///
/// TOTAL: 308 entries (1 skipped: `int` is aliased to `TOK_INT`, not an ASM token).
pub static OPCODE_TABLE: &[OpcodeEntry] = &[
    OpcodeEntry { token: X86Instruction::Endbr32, opcode: 0xf31e, instr_type: 0xe108, nb_ops: 0, op_type: [0, 0, 0] }, // endbr32
    OpcodeEntry { token: X86Instruction::CmpsB, opcode: 0xa6, instr_type: 0x3, nb_ops: 0, op_type: [0, 0, 0] }, // cmpsb [ALT]
    OpcodeEntry { token: X86Instruction::ScmpB, opcode: 0xa6, instr_type: 0x3, nb_ops: 0, op_type: [0, 0, 0] }, // scmpb [ALT]
    OpcodeEntry { token: X86Instruction::InsB, opcode: 0x6c, instr_type: 0x3, nb_ops: 0, op_type: [0, 0, 0] }, // insb [ALT]
    OpcodeEntry { token: X86Instruction::OutsB, opcode: 0x6e, instr_type: 0x3, nb_ops: 0, op_type: [0, 0, 0] }, // outsb [ALT]
    OpcodeEntry { token: X86Instruction::LodsB, opcode: 0xac, instr_type: 0x3, nb_ops: 0, op_type: [0, 0, 0] }, // lodsb [ALT]
    OpcodeEntry { token: X86Instruction::SlodB, opcode: 0xac, instr_type: 0x3, nb_ops: 0, op_type: [0, 0, 0] }, // slodb [ALT]
    OpcodeEntry { token: X86Instruction::MovsB, opcode: 0xa4, instr_type: 0x3, nb_ops: 0, op_type: [0, 0, 0] }, // movsb [ALT]
    OpcodeEntry { token: X86Instruction::SmovB, opcode: 0xa4, instr_type: 0x3, nb_ops: 0, op_type: [0, 0, 0] }, // smovb [ALT]
    OpcodeEntry { token: X86Instruction::ScasB, opcode: 0xae, instr_type: 0x3, nb_ops: 0, op_type: [0, 0, 0] }, // scasb [ALT]
    OpcodeEntry { token: X86Instruction::SscaB, opcode: 0xae, instr_type: 0x3, nb_ops: 0, op_type: [0, 0, 0] }, // sscab [ALT]
    OpcodeEntry { token: X86Instruction::StosB, opcode: 0xaa, instr_type: 0x3, nb_ops: 0, op_type: [0, 0, 0] }, // stosb [ALT]
    OpcodeEntry { token: X86Instruction::SstoB, opcode: 0xaa, instr_type: 0x3, nb_ops: 0, op_type: [0, 0, 0] }, // sstob [ALT]
    OpcodeEntry { token: X86Instruction::BsfW, opcode: 0xbc, instr_type: 0x10a, nb_ops: 2, op_type: [151, 23, 0] }, // bsfw [ALT]
    OpcodeEntry { token: X86Instruction::BsrW, opcode: 0xbd, instr_type: 0x10a, nb_ops: 2, op_type: [151, 23, 0] }, // bsrw [ALT]
    OpcodeEntry { token: X86Instruction::BtW, opcode: 0xa3, instr_type: 0x10a, nb_ops: 2, op_type: [23, 151, 0] }, // btw [ALT]
    OpcodeEntry { token: X86Instruction::BtW, opcode: 0xba, instr_type: 0x810a, nb_ops: 2, op_type: [10, 151, 0] }, // btw [ALT]
    OpcodeEntry { token: X86Instruction::BtsW, opcode: 0xab, instr_type: 0x10a, nb_ops: 2, op_type: [23, 151, 0] }, // btsw [ALT]
    OpcodeEntry { token: X86Instruction::BtsW, opcode: 0xba, instr_type: 0xa10a, nb_ops: 2, op_type: [10, 151, 0] }, // btsw [ALT]
    OpcodeEntry { token: X86Instruction::BtrW, opcode: 0xb3, instr_type: 0x10a, nb_ops: 2, op_type: [23, 151, 0] }, // btrw [ALT]
    OpcodeEntry { token: X86Instruction::BtrW, opcode: 0xba, instr_type: 0xc10a, nb_ops: 2, op_type: [10, 151, 0] }, // btrw [ALT]
    OpcodeEntry { token: X86Instruction::BtcW, opcode: 0xbb, instr_type: 0x10a, nb_ops: 2, op_type: [23, 151, 0] }, // btcw [ALT]
    OpcodeEntry { token: X86Instruction::BtcW, opcode: 0xba, instr_type: 0xe10a, nb_ops: 2, op_type: [10, 151, 0] }, // btcw [ALT]
    OpcodeEntry { token: X86Instruction::PopcntW, opcode: 0xf3b8, instr_type: 0x10a, nb_ops: 2, op_type: [151, 23, 0] }, // popcntw [ALT]
    OpcodeEntry { token: X86Instruction::TzcntW, opcode: 0xf3bc, instr_type: 0x10a, nb_ops: 2, op_type: [151, 23, 0] }, // tzcntw [ALT]
    OpcodeEntry { token: X86Instruction::LzcntW, opcode: 0xf3bd, instr_type: 0x10a, nb_ops: 2, op_type: [151, 23, 0] }, // lzcntw [ALT]
    OpcodeEntry { token: X86Instruction::MovB, opcode: 0xa0, instr_type: 0x3, nb_ops: 2, op_type: [18, 14, 0] }, // movb [ALT]
    OpcodeEntry { token: X86Instruction::MovB, opcode: 0xa2, instr_type: 0x3, nb_ops: 2, op_type: [14, 18, 0] }, // movb [ALT]
    OpcodeEntry { token: X86Instruction::MovB, opcode: 0x88, instr_type: 0xb, nb_ops: 2, op_type: [22, 150, 0] }, // movb [ALT]
    OpcodeEntry { token: X86Instruction::MovB, opcode: 0x8a, instr_type: 0xb, nb_ops: 2, op_type: [150, 22, 0] }, // movb [ALT]
    OpcodeEntry { token: X86Instruction::MovB, opcode: 0xb0, instr_type: 0x7, nb_ops: 2, op_type: [21, 22, 0] }, // movb [ALT]
    OpcodeEntry { token: X86Instruction::MovB, opcode: 0xc6, instr_type: 0xb, nb_ops: 2, op_type: [21, 150, 0] }, // movb [ALT]
    OpcodeEntry { token: X86Instruction::MovW, opcode: 0x8c, instr_type: 0xa, nb_ops: 2, op_type: [8, 150, 0] }, // movw [ALT]
    OpcodeEntry { token: X86Instruction::MovW, opcode: 0x8e, instr_type: 0xa, nb_ops: 2, op_type: [150, 8, 0] }, // movw [ALT]
    OpcodeEntry { token: X86Instruction::MovW, opcode: 0x20, instr_type: 0x10a, nb_ops: 2, op_type: [5, 2, 0] }, // movw [ALT]
    OpcodeEntry { token: X86Instruction::MovW, opcode: 0x21, instr_type: 0x10a, nb_ops: 2, op_type: [7, 2, 0] }, // movw [ALT]
    OpcodeEntry { token: X86Instruction::MovW, opcode: 0x24, instr_type: 0x10a, nb_ops: 2, op_type: [6, 2, 0] }, // movw [ALT]
    OpcodeEntry { token: X86Instruction::MovW, opcode: 0x22, instr_type: 0x10a, nb_ops: 2, op_type: [2, 5, 0] }, // movw [ALT]
    OpcodeEntry { token: X86Instruction::MovW, opcode: 0x23, instr_type: 0x10a, nb_ops: 2, op_type: [2, 7, 0] }, // movw [ALT]
    OpcodeEntry { token: X86Instruction::MovW, opcode: 0x26, instr_type: 0x10a, nb_ops: 2, op_type: [2, 6, 0] }, // movw [ALT]
    OpcodeEntry { token: X86Instruction::Movsbl, opcode: 0xbe, instr_type: 0x108, nb_ops: 2, op_type: [128, 2, 0] }, // movsbl [ALT]
    OpcodeEntry { token: X86Instruction::Movsbw, opcode: 0x66be, instr_type: 0x108, nb_ops: 2, op_type: [128, 1, 0] }, // movsbw [ALT]
    OpcodeEntry { token: X86Instruction::Movswl, opcode: 0xbf, instr_type: 0x108, nb_ops: 2, op_type: [129, 2, 0] }, // movswl [ALT]
    OpcodeEntry { token: X86Instruction::MovzbW, opcode: 0xb6, instr_type: 0x10a, nb_ops: 2, op_type: [128, 23, 0] }, // movzbw [ALT]
    OpcodeEntry { token: X86Instruction::Movzwl, opcode: 0xb7, instr_type: 0x108, nb_ops: 2, op_type: [129, 2, 0] }, // movzwl [ALT]
    OpcodeEntry { token: X86Instruction::PushW, opcode: 0x50, instr_type: 0x6, nb_ops: 1, op_type: [23, 0, 0] }, // pushw [ALT]
    OpcodeEntry { token: X86Instruction::PushW, opcode: 0xff, instr_type: 0xc00a, nb_ops: 1, op_type: [151, 0, 0] }, // pushw [ALT]
    OpcodeEntry { token: X86Instruction::PushW, opcode: 0x6a, instr_type: 0x2, nb_ops: 1, op_type: [11, 0, 0] }, // pushw [ALT]
    OpcodeEntry { token: X86Instruction::PushW, opcode: 0x68, instr_type: 0x2, nb_ops: 1, op_type: [13, 0, 0] }, // pushw [ALT]
    OpcodeEntry { token: X86Instruction::PushW, opcode: 0x6, instr_type: 0x2, nb_ops: 1, op_type: [8, 0, 0] }, // pushw [ALT]
    OpcodeEntry { token: X86Instruction::PopW, opcode: 0x58, instr_type: 0x6, nb_ops: 1, op_type: [23, 0, 0] }, // popw [ALT]
    OpcodeEntry { token: X86Instruction::PopW, opcode: 0x8f, instr_type: 0xa, nb_ops: 1, op_type: [151, 0, 0] }, // popw [ALT]
    OpcodeEntry { token: X86Instruction::PopW, opcode: 0x7, instr_type: 0x2, nb_ops: 1, op_type: [8, 0, 0] }, // popw [ALT]
    OpcodeEntry { token: X86Instruction::XchgW, opcode: 0x90, instr_type: 0x6, nb_ops: 2, op_type: [23, 14, 0] }, // xchgw [ALT]
    OpcodeEntry { token: X86Instruction::XchgW, opcode: 0x90, instr_type: 0x6, nb_ops: 2, op_type: [14, 23, 0] }, // xchgw [ALT]
    OpcodeEntry { token: X86Instruction::XchgB, opcode: 0x86, instr_type: 0xb, nb_ops: 2, op_type: [22, 150, 0] }, // xchgb [ALT]
    OpcodeEntry { token: X86Instruction::XchgB, opcode: 0x86, instr_type: 0xb, nb_ops: 2, op_type: [150, 22, 0] }, // xchgb [ALT]
    OpcodeEntry { token: X86Instruction::InB, opcode: 0xe4, instr_type: 0x3, nb_ops: 2, op_type: [10, 14, 0] }, // inb [ALT]
    OpcodeEntry { token: X86Instruction::InB, opcode: 0xe4, instr_type: 0x3, nb_ops: 1, op_type: [10, 0, 0] }, // inb [ALT]
    OpcodeEntry { token: X86Instruction::InB, opcode: 0xec, instr_type: 0x3, nb_ops: 2, op_type: [17, 14, 0] }, // inb [ALT]
    OpcodeEntry { token: X86Instruction::InB, opcode: 0xec, instr_type: 0x3, nb_ops: 1, op_type: [17, 0, 0] }, // inb [ALT]
    OpcodeEntry { token: X86Instruction::OutB, opcode: 0xe6, instr_type: 0x3, nb_ops: 2, op_type: [14, 10, 0] }, // outb [ALT]
    OpcodeEntry { token: X86Instruction::OutB, opcode: 0xe6, instr_type: 0x3, nb_ops: 1, op_type: [10, 0, 0] }, // outb [ALT]
    OpcodeEntry { token: X86Instruction::OutB, opcode: 0xee, instr_type: 0x3, nb_ops: 2, op_type: [14, 17, 0] }, // outb [ALT]
    OpcodeEntry { token: X86Instruction::OutB, opcode: 0xee, instr_type: 0x3, nb_ops: 1, op_type: [17, 0, 0] }, // outb [ALT]
    OpcodeEntry { token: X86Instruction::LeaW, opcode: 0x8d, instr_type: 0xa, nb_ops: 2, op_type: [128, 22, 0] }, // leaw [ALT]
    OpcodeEntry { token: X86Instruction::Les, opcode: 0xc4, instr_type: 0x8, nb_ops: 2, op_type: [128, 2, 0] }, // les [ALT]
    OpcodeEntry { token: X86Instruction::Lds, opcode: 0xc5, instr_type: 0x8, nb_ops: 2, op_type: [128, 2, 0] }, // lds [ALT]
    OpcodeEntry { token: X86Instruction::Lss, opcode: 0xb2, instr_type: 0x108, nb_ops: 2, op_type: [128, 2, 0] }, // lss [ALT]
    OpcodeEntry { token: X86Instruction::Lfs, opcode: 0xb4, instr_type: 0x108, nb_ops: 2, op_type: [128, 2, 0] }, // lfs [ALT]
    OpcodeEntry { token: X86Instruction::Lgs, opcode: 0xb5, instr_type: 0x108, nb_ops: 2, op_type: [128, 2, 0] }, // lgs [ALT]
    OpcodeEntry { token: X86Instruction::AddB, opcode: 0x0, instr_type: 0x3b, nb_ops: 2, op_type: [22, 150, 0] }, // addb [ALT]
    OpcodeEntry { token: X86Instruction::AddB, opcode: 0x2, instr_type: 0x3b, nb_ops: 2, op_type: [150, 22, 0] }, // addb [ALT]
    OpcodeEntry { token: X86Instruction::AddB, opcode: 0x4, instr_type: 0x33, nb_ops: 2, op_type: [21, 14, 0] }, // addb [ALT]
    OpcodeEntry { token: X86Instruction::AddW, opcode: 0x83, instr_type: 0x3a, nb_ops: 2, op_type: [11, 151, 0] }, // addw [ALT]
    OpcodeEntry { token: X86Instruction::AddB, opcode: 0x80, instr_type: 0x3b, nb_ops: 2, op_type: [21, 150, 0] }, // addb [ALT]
    OpcodeEntry { token: X86Instruction::TestB, opcode: 0x84, instr_type: 0xb, nb_ops: 2, op_type: [22, 150, 0] }, // testb [ALT]
    OpcodeEntry { token: X86Instruction::TestB, opcode: 0x84, instr_type: 0xb, nb_ops: 2, op_type: [150, 22, 0] }, // testb [ALT]
    OpcodeEntry { token: X86Instruction::TestB, opcode: 0xa8, instr_type: 0x3, nb_ops: 2, op_type: [21, 14, 0] }, // testb [ALT]
    OpcodeEntry { token: X86Instruction::TestB, opcode: 0xf6, instr_type: 0xb, nb_ops: 2, op_type: [21, 150, 0] }, // testb [ALT]
    OpcodeEntry { token: X86Instruction::IncW, opcode: 0x40, instr_type: 0x6, nb_ops: 1, op_type: [23, 0, 0] }, // incw [ALT]
    OpcodeEntry { token: X86Instruction::IncB, opcode: 0xfe, instr_type: 0xb, nb_ops: 1, op_type: [150, 0, 0] }, // incb [ALT]
    OpcodeEntry { token: X86Instruction::DecW, opcode: 0x48, instr_type: 0x6, nb_ops: 1, op_type: [23, 0, 0] }, // decw [ALT]
    OpcodeEntry { token: X86Instruction::DecB, opcode: 0xfe, instr_type: 0x200b, nb_ops: 1, op_type: [150, 0, 0] }, // decb [ALT]
    OpcodeEntry { token: X86Instruction::NotB, opcode: 0xf6, instr_type: 0x400b, nb_ops: 1, op_type: [150, 0, 0] }, // notb [ALT]
    OpcodeEntry { token: X86Instruction::NegB, opcode: 0xf6, instr_type: 0x600b, nb_ops: 1, op_type: [150, 0, 0] }, // negb [ALT]
    OpcodeEntry { token: X86Instruction::MulB, opcode: 0xf6, instr_type: 0x800b, nb_ops: 1, op_type: [150, 0, 0] }, // mulb [ALT]
    OpcodeEntry { token: X86Instruction::ImulB, opcode: 0xf6, instr_type: 0xa00b, nb_ops: 1, op_type: [150, 0, 0] }, // imulb [ALT]
    OpcodeEntry { token: X86Instruction::ImulW, opcode: 0xaf, instr_type: 0x10a, nb_ops: 2, op_type: [150, 22, 0] }, // imulw [ALT]
    OpcodeEntry { token: X86Instruction::ImulW, opcode: 0x6b, instr_type: 0xa, nb_ops: 3, op_type: [11, 151, 23] }, // imulw [ALT]
    OpcodeEntry { token: X86Instruction::ImulW, opcode: 0x6b, instr_type: 0xa, nb_ops: 2, op_type: [11, 23, 0] }, // imulw [ALT]
    OpcodeEntry { token: X86Instruction::ImulW, opcode: 0x69, instr_type: 0xa, nb_ops: 3, op_type: [24, 151, 23] }, // imulw [ALT]
    OpcodeEntry { token: X86Instruction::ImulW, opcode: 0x69, instr_type: 0xa, nb_ops: 2, op_type: [24, 23, 0] }, // imulw [ALT]
    OpcodeEntry { token: X86Instruction::DivB, opcode: 0xf6, instr_type: 0xc00b, nb_ops: 1, op_type: [150, 0, 0] }, // divb [ALT]
    OpcodeEntry { token: X86Instruction::DivB, opcode: 0xf6, instr_type: 0xc00b, nb_ops: 2, op_type: [150, 14, 0] }, // divb [ALT]
    OpcodeEntry { token: X86Instruction::IdivB, opcode: 0xf6, instr_type: 0xe00b, nb_ops: 1, op_type: [150, 0, 0] }, // idivb [ALT]
    OpcodeEntry { token: X86Instruction::IdivB, opcode: 0xf6, instr_type: 0xe00b, nb_ops: 2, op_type: [150, 14, 0] }, // idivb [ALT]
    OpcodeEntry { token: X86Instruction::RolB, opcode: 0xc0, instr_type: 0x2b, nb_ops: 2, op_type: [10, 150, 0] }, // rolb [ALT]
    OpcodeEntry { token: X86Instruction::RolB, opcode: 0xd2, instr_type: 0x2b, nb_ops: 2, op_type: [16, 150, 0] }, // rolb [ALT]
    OpcodeEntry { token: X86Instruction::RolB, opcode: 0xd0, instr_type: 0x2b, nb_ops: 1, op_type: [150, 0, 0] }, // rolb [ALT]
    OpcodeEntry { token: X86Instruction::ShldW, opcode: 0xa4, instr_type: 0x10a, nb_ops: 3, op_type: [10, 23, 151] }, // shldw [ALT]
    OpcodeEntry { token: X86Instruction::ShldW, opcode: 0xa5, instr_type: 0x10a, nb_ops: 3, op_type: [16, 23, 151] }, // shldw [ALT]
    OpcodeEntry { token: X86Instruction::ShldW, opcode: 0xa5, instr_type: 0x10a, nb_ops: 2, op_type: [23, 151, 0] }, // shldw [ALT]
    OpcodeEntry { token: X86Instruction::ShrdW, opcode: 0xac, instr_type: 0x10a, nb_ops: 3, op_type: [10, 23, 151] }, // shrdw [ALT]
    OpcodeEntry { token: X86Instruction::ShrdW, opcode: 0xad, instr_type: 0x10a, nb_ops: 3, op_type: [16, 23, 151] }, // shrdw [ALT]
    OpcodeEntry { token: X86Instruction::ShrdW, opcode: 0xad, instr_type: 0x10a, nb_ops: 2, op_type: [23, 151, 0] }, // shrdw [ALT]
    OpcodeEntry { token: X86Instruction::Call, opcode: 0xff, instr_type: 0x4008, nb_ops: 1, op_type: [19, 0, 0] }, // call [ALT]
    OpcodeEntry { token: X86Instruction::Call, opcode: 0xe8, instr_type: 0x0, nb_ops: 1, op_type: [26, 0, 0] }, // call [ALT]
    OpcodeEntry { token: X86Instruction::Jmp, opcode: 0xff, instr_type: 0x8008, nb_ops: 1, op_type: [19, 0, 0] }, // jmp [ALT]
    OpcodeEntry { token: X86Instruction::Jmp, opcode: 0xeb, instr_type: 0x0, nb_ops: 1, op_type: [27, 0, 0] }, // jmp [ALT]
    OpcodeEntry { token: X86Instruction::Lcall, opcode: 0x9a, instr_type: 0x0, nb_ops: 2, op_type: [12, 13, 0] }, // lcall [ALT]
    OpcodeEntry { token: X86Instruction::Lcall, opcode: 0xff, instr_type: 0x6008, nb_ops: 1, op_type: [128, 0, 0] }, // lcall [ALT]
    OpcodeEntry { token: X86Instruction::Ljmp, opcode: 0xea, instr_type: 0x0, nb_ops: 2, op_type: [12, 13, 0] }, // ljmp [ALT]
    OpcodeEntry { token: X86Instruction::Ljmp, opcode: 0xff, instr_type: 0xa008, nb_ops: 1, op_type: [128, 0, 0] }, // ljmp [ALT]
    OpcodeEntry { token: X86Instruction::SetO, opcode: 0x90, instr_type: 0x158, nb_ops: 1, op_type: [128, 0, 0] }, // seto [ALT]
    OpcodeEntry { token: X86Instruction::SetOB, opcode: 0x90, instr_type: 0x158, nb_ops: 1, op_type: [128, 0, 0] }, // setob [ALT]
    OpcodeEntry { token: X86Instruction::Enter, opcode: 0xc8, instr_type: 0x0, nb_ops: 2, op_type: [12, 10, 0] }, // enter
    OpcodeEntry { token: X86Instruction::Retl, opcode: 0xc2, instr_type: 0x0, nb_ops: 1, op_type: [12, 0, 0] }, // retl [ALT]
    OpcodeEntry { token: X86Instruction::Ret, opcode: 0xc2, instr_type: 0x0, nb_ops: 1, op_type: [12, 0, 0] }, // ret [ALT]
    OpcodeEntry { token: X86Instruction::Lret, opcode: 0xca, instr_type: 0x0, nb_ops: 1, op_type: [12, 0, 0] }, // lret [ALT]
    OpcodeEntry { token: X86Instruction::JO, opcode: 0x70, instr_type: 0x50, nb_ops: 1, op_type: [27, 0, 0] }, // jo [ALT]
    OpcodeEntry { token: X86Instruction::Loopne, opcode: 0xe0, instr_type: 0x0, nb_ops: 1, op_type: [27, 0, 0] }, // loopne
    OpcodeEntry { token: X86Instruction::Loopnz, opcode: 0xe0, instr_type: 0x0, nb_ops: 1, op_type: [27, 0, 0] }, // loopnz
    OpcodeEntry { token: X86Instruction::Loope, opcode: 0xe1, instr_type: 0x0, nb_ops: 1, op_type: [27, 0, 0] }, // loope
    OpcodeEntry { token: X86Instruction::Loopz, opcode: 0xe1, instr_type: 0x0, nb_ops: 1, op_type: [27, 0, 0] }, // loopz
    OpcodeEntry { token: X86Instruction::Loop, opcode: 0xe2, instr_type: 0x0, nb_ops: 1, op_type: [27, 0, 0] }, // loop
    OpcodeEntry { token: X86Instruction::Jecxz, opcode: 0xe3, instr_type: 0x0, nb_ops: 1, op_type: [27, 0, 0] }, // jecxz
    OpcodeEntry { token: X86Instruction::FComp, opcode: 0xd8d9, instr_type: 0x0, nb_ops: 0, op_type: [0, 0, 0] }, // fcomp [ALT]
    OpcodeEntry { token: X86Instruction::FAdd, opcode: 0xd8c0, instr_type: 0x44, nb_ops: 1, op_type: [9, 0, 0] }, // fadd [ALT]
    OpcodeEntry { token: X86Instruction::FAdd, opcode: 0xd8c0, instr_type: 0x44, nb_ops: 2, op_type: [9, 15, 0] }, // fadd [ALT]
    OpcodeEntry { token: X86Instruction::FAdd, opcode: 0xdcc0, instr_type: 0x44, nb_ops: 2, op_type: [15, 9, 0] }, // fadd [ALT]
    OpcodeEntry { token: X86Instruction::FMul, opcode: 0xdcc8, instr_type: 0x44, nb_ops: 2, op_type: [15, 9, 0] }, // fmul [ALT]
    OpcodeEntry { token: X86Instruction::FAdd, opcode: 0xdec1, instr_type: 0x40, nb_ops: 0, op_type: [0, 0, 0] }, // fadd [ALT]
    OpcodeEntry { token: X86Instruction::FAddp, opcode: 0xdec0, instr_type: 0x44, nb_ops: 1, op_type: [9, 0, 0] }, // faddp [ALT]
    OpcodeEntry { token: X86Instruction::FAddp, opcode: 0xdec0, instr_type: 0x44, nb_ops: 2, op_type: [9, 15, 0] }, // faddp [ALT]
    OpcodeEntry { token: X86Instruction::FAddp, opcode: 0xdec0, instr_type: 0x44, nb_ops: 2, op_type: [15, 9, 0] }, // faddp [ALT]
    OpcodeEntry { token: X86Instruction::FAddp, opcode: 0xdec1, instr_type: 0x40, nb_ops: 0, op_type: [0, 0, 0] }, // faddp [ALT]
    OpcodeEntry { token: X86Instruction::FAdds, opcode: 0xd8, instr_type: 0x48, nb_ops: 1, op_type: [128, 0, 0] }, // fadds [ALT]
    OpcodeEntry { token: X86Instruction::FiAddl, opcode: 0xda, instr_type: 0x48, nb_ops: 1, op_type: [128, 0, 0] }, // fiaddl [ALT]
    OpcodeEntry { token: X86Instruction::FAddl, opcode: 0xdc, instr_type: 0x48, nb_ops: 1, op_type: [128, 0, 0] }, // faddl [ALT]
    OpcodeEntry { token: X86Instruction::FiAdds, opcode: 0xde, instr_type: 0x48, nb_ops: 1, op_type: [128, 0, 0] }, // fiadds [ALT]
    OpcodeEntry { token: X86Instruction::Fld, opcode: 0xd9c0, instr_type: 0x4, nb_ops: 1, op_type: [9, 0, 0] }, // fld
    OpcodeEntry { token: X86Instruction::Fldl, opcode: 0xd9c0, instr_type: 0x4, nb_ops: 1, op_type: [9, 0, 0] }, // fldl
    OpcodeEntry { token: X86Instruction::Flds, opcode: 0xd9, instr_type: 0x8, nb_ops: 1, op_type: [128, 0, 0] }, // flds
    OpcodeEntry { token: X86Instruction::Fldl, opcode: 0xdd, instr_type: 0x8, nb_ops: 1, op_type: [128, 0, 0] }, // fldl [ALT]
    OpcodeEntry { token: X86Instruction::Fildl, opcode: 0xdb, instr_type: 0x8, nb_ops: 1, op_type: [128, 0, 0] }, // fildl
    OpcodeEntry { token: X86Instruction::Fildq, opcode: 0xdf, instr_type: 0xa008, nb_ops: 1, op_type: [128, 0, 0] }, // fildq
    OpcodeEntry { token: X86Instruction::Fildll, opcode: 0xdf, instr_type: 0xa008, nb_ops: 1, op_type: [128, 0, 0] }, // fildll
    OpcodeEntry { token: X86Instruction::Fldt, opcode: 0xdb, instr_type: 0xa008, nb_ops: 1, op_type: [128, 0, 0] }, // fldt
    OpcodeEntry { token: X86Instruction::Fbld, opcode: 0xdf, instr_type: 0x8008, nb_ops: 1, op_type: [128, 0, 0] }, // fbld
    OpcodeEntry { token: X86Instruction::Fst, opcode: 0xddd0, instr_type: 0x4, nb_ops: 1, op_type: [9, 0, 0] }, // fst
    OpcodeEntry { token: X86Instruction::Fstl, opcode: 0xddd0, instr_type: 0x4, nb_ops: 1, op_type: [9, 0, 0] }, // fstl
    OpcodeEntry { token: X86Instruction::Fsts, opcode: 0xd9, instr_type: 0x4008, nb_ops: 1, op_type: [128, 0, 0] }, // fsts
    OpcodeEntry { token: X86Instruction::Fstps, opcode: 0xd9, instr_type: 0x6008, nb_ops: 1, op_type: [128, 0, 0] }, // fstps
    OpcodeEntry { token: X86Instruction::Fstl, opcode: 0xdd, instr_type: 0x4008, nb_ops: 1, op_type: [128, 0, 0] }, // fstl [ALT]
    OpcodeEntry { token: X86Instruction::Fstpl, opcode: 0xdd, instr_type: 0x6008, nb_ops: 1, op_type: [128, 0, 0] }, // fstpl
    OpcodeEntry { token: X86Instruction::Fist, opcode: 0xdf, instr_type: 0x4008, nb_ops: 1, op_type: [128, 0, 0] }, // fist
    OpcodeEntry { token: X86Instruction::Fistp, opcode: 0xdf, instr_type: 0x6008, nb_ops: 1, op_type: [128, 0, 0] }, // fistp
    OpcodeEntry { token: X86Instruction::Fistl, opcode: 0xdb, instr_type: 0x4008, nb_ops: 1, op_type: [128, 0, 0] }, // fistl
    OpcodeEntry { token: X86Instruction::Fistpl, opcode: 0xdb, instr_type: 0x6008, nb_ops: 1, op_type: [128, 0, 0] }, // fistpl
    OpcodeEntry { token: X86Instruction::Fstp, opcode: 0xddd8, instr_type: 0x4, nb_ops: 1, op_type: [9, 0, 0] }, // fstp
    OpcodeEntry { token: X86Instruction::Fistpq, opcode: 0xdf, instr_type: 0xe008, nb_ops: 1, op_type: [128, 0, 0] }, // fistpq
    OpcodeEntry { token: X86Instruction::Fistpll, opcode: 0xdf, instr_type: 0xe008, nb_ops: 1, op_type: [128, 0, 0] }, // fistpll
    OpcodeEntry { token: X86Instruction::Fstpt, opcode: 0xdb, instr_type: 0xe008, nb_ops: 1, op_type: [128, 0, 0] }, // fstpt
    OpcodeEntry { token: X86Instruction::Fbstp, opcode: 0xdf, instr_type: 0xc008, nb_ops: 1, op_type: [128, 0, 0] }, // fbstp
    OpcodeEntry { token: X86Instruction::Fxch, opcode: 0xd9c8, instr_type: 0x4, nb_ops: 1, op_type: [9, 0, 0] }, // fxch [ALT]
    OpcodeEntry { token: X86Instruction::Fucom, opcode: 0xdde0, instr_type: 0x4, nb_ops: 1, op_type: [9, 0, 0] }, // fucom
    OpcodeEntry { token: X86Instruction::Fucomp, opcode: 0xdde8, instr_type: 0x4, nb_ops: 1, op_type: [9, 0, 0] }, // fucomp
    OpcodeEntry { token: X86Instruction::Finit, opcode: 0xdbe3, instr_type: 0x10, nb_ops: 0, op_type: [0, 0, 0] }, // finit
    OpcodeEntry { token: X86Instruction::Fldcw, opcode: 0xd9, instr_type: 0xa008, nb_ops: 1, op_type: [128, 0, 0] }, // fldcw
    OpcodeEntry { token: X86Instruction::Fnstcw, opcode: 0xd9, instr_type: 0xe008, nb_ops: 1, op_type: [128, 0, 0] }, // fnstcw
    OpcodeEntry { token: X86Instruction::Fstcw, opcode: 0xd9, instr_type: 0xe018, nb_ops: 1, op_type: [128, 0, 0] }, // fstcw
    OpcodeEntry { token: X86Instruction::Fnstsw, opcode: 0xdfe0, instr_type: 0x0, nb_ops: 1, op_type: [14, 0, 0] }, // fnstsw [ALT]
    OpcodeEntry { token: X86Instruction::Fnstsw, opcode: 0xdd, instr_type: 0xe008, nb_ops: 1, op_type: [128, 0, 0] }, // fnstsw [ALT]
    OpcodeEntry { token: X86Instruction::Fstsw, opcode: 0xdfe0, instr_type: 0x10, nb_ops: 1, op_type: [14, 0, 0] }, // fstsw
    OpcodeEntry { token: X86Instruction::Fstsw, opcode: 0xdfe0, instr_type: 0x10, nb_ops: 0, op_type: [0, 0, 0] }, // fstsw [ALT]
    OpcodeEntry { token: X86Instruction::Fstsw, opcode: 0xdd, instr_type: 0xe018, nb_ops: 1, op_type: [128, 0, 0] }, // fstsw [ALT]
    OpcodeEntry { token: X86Instruction::Fclex, opcode: 0xdbe2, instr_type: 0x10, nb_ops: 0, op_type: [0, 0, 0] }, // fclex
    OpcodeEntry { token: X86Instruction::Fnstenv, opcode: 0xd9, instr_type: 0xc008, nb_ops: 1, op_type: [128, 0, 0] }, // fnstenv
    OpcodeEntry { token: X86Instruction::Fstenv, opcode: 0xd9, instr_type: 0xc018, nb_ops: 1, op_type: [128, 0, 0] }, // fstenv
    OpcodeEntry { token: X86Instruction::Fldenv, opcode: 0xd9, instr_type: 0x8008, nb_ops: 1, op_type: [128, 0, 0] }, // fldenv
    OpcodeEntry { token: X86Instruction::Fnsave, opcode: 0xdd, instr_type: 0xc008, nb_ops: 1, op_type: [128, 0, 0] }, // fnsave
    OpcodeEntry { token: X86Instruction::Fsave, opcode: 0xdd, instr_type: 0xc018, nb_ops: 1, op_type: [128, 0, 0] }, // fsave
    OpcodeEntry { token: X86Instruction::Frstor, opcode: 0xdd, instr_type: 0x8008, nb_ops: 1, op_type: [128, 0, 0] }, // frstor
    OpcodeEntry { token: X86Instruction::Ffree, opcode: 0xddc0, instr_type: 0x8004, nb_ops: 1, op_type: [9, 0, 0] }, // ffree
    OpcodeEntry { token: X86Instruction::Ffreep, opcode: 0xdfc0, instr_type: 0x8004, nb_ops: 1, op_type: [9, 0, 0] }, // ffreep
    OpcodeEntry { token: X86Instruction::Fxsave, opcode: 0xae, instr_type: 0x108, nb_ops: 1, op_type: [128, 0, 0] }, // fxsave
    OpcodeEntry { token: X86Instruction::Fxrstor, opcode: 0xae, instr_type: 0x2108, nb_ops: 1, op_type: [128, 0, 0] }, // fxrstor
    OpcodeEntry { token: X86Instruction::Arpl, opcode: 0x63, instr_type: 0x8, nb_ops: 2, op_type: [1, 129, 0] }, // arpl
    OpcodeEntry { token: X86Instruction::LarW, opcode: 0x2, instr_type: 0x10a, nb_ops: 2, op_type: [150, 22, 0] }, // larw [ALT]
    OpcodeEntry { token: X86Instruction::Lgdt, opcode: 0x1, instr_type: 0x4108, nb_ops: 1, op_type: [128, 0, 0] }, // lgdt
    OpcodeEntry { token: X86Instruction::Lidt, opcode: 0x1, instr_type: 0x6108, nb_ops: 1, op_type: [128, 0, 0] }, // lidt
    OpcodeEntry { token: X86Instruction::Lldt, opcode: 0x0, instr_type: 0x4108, nb_ops: 1, op_type: [150, 0, 0] }, // lldt
    OpcodeEntry { token: X86Instruction::Lmsw, opcode: 0x1, instr_type: 0xc108, nb_ops: 1, op_type: [150, 0, 0] }, // lmsw
    OpcodeEntry { token: X86Instruction::LslW, opcode: 0x3, instr_type: 0x10a, nb_ops: 2, op_type: [150, 22, 0] }, // lslw [ALT]
    OpcodeEntry { token: X86Instruction::Ltr, opcode: 0x0, instr_type: 0x6108, nb_ops: 1, op_type: [150, 0, 0] }, // ltr
    OpcodeEntry { token: X86Instruction::Sgdt, opcode: 0x1, instr_type: 0x108, nb_ops: 1, op_type: [128, 0, 0] }, // sgdt
    OpcodeEntry { token: X86Instruction::Sidt, opcode: 0x1, instr_type: 0x2108, nb_ops: 1, op_type: [128, 0, 0] }, // sidt
    OpcodeEntry { token: X86Instruction::Sldt, opcode: 0x0, instr_type: 0x108, nb_ops: 1, op_type: [150, 0, 0] }, // sldt
    OpcodeEntry { token: X86Instruction::Smsw, opcode: 0x1, instr_type: 0x8108, nb_ops: 1, op_type: [150, 0, 0] }, // smsw
    OpcodeEntry { token: X86Instruction::Str, opcode: 0x0, instr_type: 0x2108, nb_ops: 1, op_type: [129, 0, 0] }, // str
    OpcodeEntry { token: X86Instruction::Verr, opcode: 0x0, instr_type: 0x8108, nb_ops: 1, op_type: [150, 0, 0] }, // verr
    OpcodeEntry { token: X86Instruction::Verw, opcode: 0x0, instr_type: 0xa108, nb_ops: 1, op_type: [150, 0, 0] }, // verw
    OpcodeEntry { token: X86Instruction::Bswap, opcode: 0xc8, instr_type: 0x104, nb_ops: 1, op_type: [2, 0, 0] }, // bswap
    OpcodeEntry { token: X86Instruction::XaddB, opcode: 0xc0, instr_type: 0x10b, nb_ops: 2, op_type: [22, 150, 0] }, // xaddb [ALT]
    OpcodeEntry { token: X86Instruction::CmpxchgB, opcode: 0xb0, instr_type: 0x10b, nb_ops: 2, op_type: [22, 150, 0] }, // cmpxchgb [ALT]
    OpcodeEntry { token: X86Instruction::Invlpg, opcode: 0x1, instr_type: 0xe108, nb_ops: 1, op_type: [128, 0, 0] }, // invlpg
    OpcodeEntry { token: X86Instruction::Boundl, opcode: 0x62, instr_type: 0x8, nb_ops: 2, op_type: [2, 128, 0] }, // boundl
    OpcodeEntry { token: X86Instruction::Boundw, opcode: 0x6662, instr_type: 0x8, nb_ops: 2, op_type: [1, 128, 0] }, // boundw
    OpcodeEntry { token: X86Instruction::Cmpxchg8b, opcode: 0xc7, instr_type: 0x2108, nb_ops: 1, op_type: [128, 0, 0] }, // cmpxchg8b
    OpcodeEntry { token: X86Instruction::CmovO, opcode: 0x40, instr_type: 0x15a, nb_ops: 2, op_type: [151, 23, 0] }, // cmovo [ALT]
    OpcodeEntry { token: X86Instruction::Fcmovb, opcode: 0xdac0, instr_type: 0x4, nb_ops: 2, op_type: [9, 15, 0] }, // fcmovb
    OpcodeEntry { token: X86Instruction::Fcmove, opcode: 0xdac8, instr_type: 0x4, nb_ops: 2, op_type: [9, 15, 0] }, // fcmove
    OpcodeEntry { token: X86Instruction::Fcmovbe, opcode: 0xdad0, instr_type: 0x4, nb_ops: 2, op_type: [9, 15, 0] }, // fcmovbe
    OpcodeEntry { token: X86Instruction::Fcmovu, opcode: 0xdad8, instr_type: 0x4, nb_ops: 2, op_type: [9, 15, 0] }, // fcmovu
    OpcodeEntry { token: X86Instruction::Fcmovnb, opcode: 0xdbc0, instr_type: 0x4, nb_ops: 2, op_type: [9, 15, 0] }, // fcmovnb
    OpcodeEntry { token: X86Instruction::Fcmovne, opcode: 0xdbc8, instr_type: 0x4, nb_ops: 2, op_type: [9, 15, 0] }, // fcmovne
    OpcodeEntry { token: X86Instruction::Fcmovnbe, opcode: 0xdbd0, instr_type: 0x4, nb_ops: 2, op_type: [9, 15, 0] }, // fcmovnbe
    OpcodeEntry { token: X86Instruction::Fcmovnu, opcode: 0xdbd8, instr_type: 0x4, nb_ops: 2, op_type: [9, 15, 0] }, // fcmovnu
    OpcodeEntry { token: X86Instruction::Fucomi, opcode: 0xdbe8, instr_type: 0x4, nb_ops: 2, op_type: [9, 15, 0] }, // fucomi
    OpcodeEntry { token: X86Instruction::Fcomi, opcode: 0xdbf0, instr_type: 0x4, nb_ops: 2, op_type: [9, 15, 0] }, // fcomi
    OpcodeEntry { token: X86Instruction::Fucomip, opcode: 0xdfe8, instr_type: 0x4, nb_ops: 2, op_type: [9, 15, 0] }, // fucomip
    OpcodeEntry { token: X86Instruction::Fcomip, opcode: 0xdff0, instr_type: 0x4, nb_ops: 2, op_type: [9, 15, 0] }, // fcomip
    OpcodeEntry { token: X86Instruction::Movd, opcode: 0x6e, instr_type: 0x108, nb_ops: 2, op_type: [130, 25, 0] }, // movd
    OpcodeEntry { token: X86Instruction::Movq, opcode: 0x6f, instr_type: 0x108, nb_ops: 2, op_type: [131, 3, 0] }, // movq
    OpcodeEntry { token: X86Instruction::Movd, opcode: 0x7e, instr_type: 0x108, nb_ops: 2, op_type: [25, 130, 0] }, // movd [ALT]
    OpcodeEntry { token: X86Instruction::Movq, opcode: 0x7f, instr_type: 0x108, nb_ops: 2, op_type: [3, 131, 0] }, // movq [ALT]
    OpcodeEntry { token: X86Instruction::Movq, opcode: 0x66d6, instr_type: 0x108, nb_ops: 2, op_type: [4, 132, 0] }, // movq [ALT]
    OpcodeEntry { token: X86Instruction::Movq, opcode: 0xf37e, instr_type: 0x108, nb_ops: 2, op_type: [132, 4, 0] }, // movq [ALT]
    OpcodeEntry { token: X86Instruction::Packssdw, opcode: 0x6b, instr_type: 0x108, nb_ops: 2, op_type: [153, 25, 0] }, // packssdw
    OpcodeEntry { token: X86Instruction::Packsswb, opcode: 0x63, instr_type: 0x108, nb_ops: 2, op_type: [153, 25, 0] }, // packsswb
    OpcodeEntry { token: X86Instruction::Packuswb, opcode: 0x67, instr_type: 0x108, nb_ops: 2, op_type: [153, 25, 0] }, // packuswb
    OpcodeEntry { token: X86Instruction::Paddb, opcode: 0xfc, instr_type: 0x108, nb_ops: 2, op_type: [153, 25, 0] }, // paddb
    OpcodeEntry { token: X86Instruction::Paddw, opcode: 0xfd, instr_type: 0x108, nb_ops: 2, op_type: [153, 25, 0] }, // paddw
    OpcodeEntry { token: X86Instruction::Paddd, opcode: 0xfe, instr_type: 0x108, nb_ops: 2, op_type: [153, 25, 0] }, // paddd
    OpcodeEntry { token: X86Instruction::Paddsb, opcode: 0xec, instr_type: 0x108, nb_ops: 2, op_type: [153, 25, 0] }, // paddsb
    OpcodeEntry { token: X86Instruction::Paddsw, opcode: 0xed, instr_type: 0x108, nb_ops: 2, op_type: [153, 25, 0] }, // paddsw
    OpcodeEntry { token: X86Instruction::Paddusb, opcode: 0xdc, instr_type: 0x108, nb_ops: 2, op_type: [153, 25, 0] }, // paddusb
    OpcodeEntry { token: X86Instruction::Paddusw, opcode: 0xdd, instr_type: 0x108, nb_ops: 2, op_type: [153, 25, 0] }, // paddusw
    OpcodeEntry { token: X86Instruction::Pand, opcode: 0xdb, instr_type: 0x108, nb_ops: 2, op_type: [153, 25, 0] }, // pand
    OpcodeEntry { token: X86Instruction::Pandn, opcode: 0xdf, instr_type: 0x108, nb_ops: 2, op_type: [153, 25, 0] }, // pandn
    OpcodeEntry { token: X86Instruction::Pcmpeqb, opcode: 0x74, instr_type: 0x108, nb_ops: 2, op_type: [153, 25, 0] }, // pcmpeqb
    OpcodeEntry { token: X86Instruction::Pcmpeqw, opcode: 0x75, instr_type: 0x108, nb_ops: 2, op_type: [153, 25, 0] }, // pcmpeqw
    OpcodeEntry { token: X86Instruction::Pcmpeqd, opcode: 0x76, instr_type: 0x108, nb_ops: 2, op_type: [153, 25, 0] }, // pcmpeqd
    OpcodeEntry { token: X86Instruction::Pcmpgtb, opcode: 0x64, instr_type: 0x108, nb_ops: 2, op_type: [153, 25, 0] }, // pcmpgtb
    OpcodeEntry { token: X86Instruction::Pcmpgtw, opcode: 0x65, instr_type: 0x108, nb_ops: 2, op_type: [153, 25, 0] }, // pcmpgtw
    OpcodeEntry { token: X86Instruction::Pcmpgtd, opcode: 0x66, instr_type: 0x108, nb_ops: 2, op_type: [153, 25, 0] }, // pcmpgtd
    OpcodeEntry { token: X86Instruction::Pmaddwd, opcode: 0xf5, instr_type: 0x108, nb_ops: 2, op_type: [153, 25, 0] }, // pmaddwd
    OpcodeEntry { token: X86Instruction::Pmulhw, opcode: 0xe5, instr_type: 0x108, nb_ops: 2, op_type: [153, 25, 0] }, // pmulhw
    OpcodeEntry { token: X86Instruction::Pmullw, opcode: 0xd5, instr_type: 0x108, nb_ops: 2, op_type: [153, 25, 0] }, // pmullw
    OpcodeEntry { token: X86Instruction::Por, opcode: 0xeb, instr_type: 0x108, nb_ops: 2, op_type: [153, 25, 0] }, // por
    OpcodeEntry { token: X86Instruction::Psllw, opcode: 0xf1, instr_type: 0x108, nb_ops: 2, op_type: [153, 25, 0] }, // psllw
    OpcodeEntry { token: X86Instruction::Psllw, opcode: 0x71, instr_type: 0xc108, nb_ops: 2, op_type: [10, 25, 0] }, // psllw [ALT]
    OpcodeEntry { token: X86Instruction::Pslld, opcode: 0xf2, instr_type: 0x108, nb_ops: 2, op_type: [153, 25, 0] }, // pslld
    OpcodeEntry { token: X86Instruction::Pslld, opcode: 0x72, instr_type: 0xc108, nb_ops: 2, op_type: [10, 25, 0] }, // pslld [ALT]
    OpcodeEntry { token: X86Instruction::Psllq, opcode: 0xf3, instr_type: 0x108, nb_ops: 2, op_type: [153, 25, 0] }, // psllq
    OpcodeEntry { token: X86Instruction::Psllq, opcode: 0x73, instr_type: 0xc108, nb_ops: 2, op_type: [10, 25, 0] }, // psllq [ALT]
    OpcodeEntry { token: X86Instruction::Psraw, opcode: 0xe1, instr_type: 0x108, nb_ops: 2, op_type: [153, 25, 0] }, // psraw
    OpcodeEntry { token: X86Instruction::Psraw, opcode: 0x71, instr_type: 0x8108, nb_ops: 2, op_type: [10, 25, 0] }, // psraw [ALT]
    OpcodeEntry { token: X86Instruction::Psrad, opcode: 0xe2, instr_type: 0x108, nb_ops: 2, op_type: [153, 25, 0] }, // psrad
    OpcodeEntry { token: X86Instruction::Psrad, opcode: 0x72, instr_type: 0x8108, nb_ops: 2, op_type: [10, 25, 0] }, // psrad [ALT]
    OpcodeEntry { token: X86Instruction::Psrlw, opcode: 0xd1, instr_type: 0x108, nb_ops: 2, op_type: [153, 25, 0] }, // psrlw
    OpcodeEntry { token: X86Instruction::Psrlw, opcode: 0x71, instr_type: 0x4108, nb_ops: 2, op_type: [10, 25, 0] }, // psrlw [ALT]
    OpcodeEntry { token: X86Instruction::Psrld, opcode: 0xd2, instr_type: 0x108, nb_ops: 2, op_type: [153, 25, 0] }, // psrld
    OpcodeEntry { token: X86Instruction::Psrld, opcode: 0x72, instr_type: 0x4108, nb_ops: 2, op_type: [10, 25, 0] }, // psrld [ALT]
    OpcodeEntry { token: X86Instruction::Psrlq, opcode: 0xd3, instr_type: 0x108, nb_ops: 2, op_type: [153, 25, 0] }, // psrlq
    OpcodeEntry { token: X86Instruction::Psrlq, opcode: 0x73, instr_type: 0x4108, nb_ops: 2, op_type: [10, 25, 0] }, // psrlq [ALT]
    OpcodeEntry { token: X86Instruction::Psubb, opcode: 0xf8, instr_type: 0x108, nb_ops: 2, op_type: [153, 25, 0] }, // psubb
    OpcodeEntry { token: X86Instruction::Psubw, opcode: 0xf9, instr_type: 0x108, nb_ops: 2, op_type: [153, 25, 0] }, // psubw
    OpcodeEntry { token: X86Instruction::Psubd, opcode: 0xfa, instr_type: 0x108, nb_ops: 2, op_type: [153, 25, 0] }, // psubd
    OpcodeEntry { token: X86Instruction::Psubsb, opcode: 0xe8, instr_type: 0x108, nb_ops: 2, op_type: [153, 25, 0] }, // psubsb
    OpcodeEntry { token: X86Instruction::Psubsw, opcode: 0xe9, instr_type: 0x108, nb_ops: 2, op_type: [153, 25, 0] }, // psubsw
    OpcodeEntry { token: X86Instruction::Psubusb, opcode: 0xd8, instr_type: 0x108, nb_ops: 2, op_type: [153, 25, 0] }, // psubusb
    OpcodeEntry { token: X86Instruction::Psubusw, opcode: 0xd9, instr_type: 0x108, nb_ops: 2, op_type: [153, 25, 0] }, // psubusw
    OpcodeEntry { token: X86Instruction::Punpckhbw, opcode: 0x68, instr_type: 0x108, nb_ops: 2, op_type: [153, 25, 0] }, // punpckhbw
    OpcodeEntry { token: X86Instruction::Punpckhwd, opcode: 0x69, instr_type: 0x108, nb_ops: 2, op_type: [153, 25, 0] }, // punpckhwd
    OpcodeEntry { token: X86Instruction::Punpckhdq, opcode: 0x6a, instr_type: 0x108, nb_ops: 2, op_type: [153, 25, 0] }, // punpckhdq
    OpcodeEntry { token: X86Instruction::Punpcklbw, opcode: 0x60, instr_type: 0x108, nb_ops: 2, op_type: [153, 25, 0] }, // punpcklbw
    OpcodeEntry { token: X86Instruction::Punpcklwd, opcode: 0x61, instr_type: 0x108, nb_ops: 2, op_type: [153, 25, 0] }, // punpcklwd
    OpcodeEntry { token: X86Instruction::Punpckldq, opcode: 0x62, instr_type: 0x108, nb_ops: 2, op_type: [153, 25, 0] }, // punpckldq
    OpcodeEntry { token: X86Instruction::Pxor, opcode: 0xef, instr_type: 0x108, nb_ops: 2, op_type: [153, 25, 0] }, // pxor
    OpcodeEntry { token: X86Instruction::Ldmxcsr, opcode: 0xae, instr_type: 0x4108, nb_ops: 1, op_type: [128, 0, 0] }, // ldmxcsr
    OpcodeEntry { token: X86Instruction::Stmxcsr, opcode: 0xae, instr_type: 0x6108, nb_ops: 1, op_type: [128, 0, 0] }, // stmxcsr
    OpcodeEntry { token: X86Instruction::Movups, opcode: 0x10, instr_type: 0x108, nb_ops: 2, op_type: [130, 4, 0] }, // movups
    OpcodeEntry { token: X86Instruction::Movups, opcode: 0x11, instr_type: 0x108, nb_ops: 2, op_type: [4, 130, 0] }, // movups [ALT]
    OpcodeEntry { token: X86Instruction::Movaps, opcode: 0x28, instr_type: 0x108, nb_ops: 2, op_type: [130, 4, 0] }, // movaps
    OpcodeEntry { token: X86Instruction::Movaps, opcode: 0x29, instr_type: 0x108, nb_ops: 2, op_type: [4, 130, 0] }, // movaps [ALT]
    OpcodeEntry { token: X86Instruction::Movhps, opcode: 0x16, instr_type: 0x108, nb_ops: 2, op_type: [130, 4, 0] }, // movhps
    OpcodeEntry { token: X86Instruction::Movhps, opcode: 0x17, instr_type: 0x108, nb_ops: 2, op_type: [4, 130, 0] }, // movhps [ALT]
    OpcodeEntry { token: X86Instruction::Addps, opcode: 0x58, instr_type: 0x108, nb_ops: 2, op_type: [132, 4, 0] }, // addps
    OpcodeEntry { token: X86Instruction::Cvtpi2ps, opcode: 0x2a, instr_type: 0x108, nb_ops: 2, op_type: [131, 4, 0] }, // cvtpi2ps
    OpcodeEntry { token: X86Instruction::Cvtps2pi, opcode: 0x2d, instr_type: 0x108, nb_ops: 2, op_type: [132, 3, 0] }, // cvtps2pi
    OpcodeEntry { token: X86Instruction::Cvttps2pi, opcode: 0x2c, instr_type: 0x108, nb_ops: 2, op_type: [132, 3, 0] }, // cvttps2pi
    OpcodeEntry { token: X86Instruction::Divps, opcode: 0x5e, instr_type: 0x108, nb_ops: 2, op_type: [132, 4, 0] }, // divps
    OpcodeEntry { token: X86Instruction::Maxps, opcode: 0x5f, instr_type: 0x108, nb_ops: 2, op_type: [132, 4, 0] }, // maxps
    OpcodeEntry { token: X86Instruction::Minps, opcode: 0x5d, instr_type: 0x108, nb_ops: 2, op_type: [132, 4, 0] }, // minps
    OpcodeEntry { token: X86Instruction::Mulps, opcode: 0x59, instr_type: 0x108, nb_ops: 2, op_type: [132, 4, 0] }, // mulps
    OpcodeEntry { token: X86Instruction::Pavgb, opcode: 0xe0, instr_type: 0x108, nb_ops: 2, op_type: [132, 4, 0] }, // pavgb
    OpcodeEntry { token: X86Instruction::Pavgw, opcode: 0xe3, instr_type: 0x108, nb_ops: 2, op_type: [132, 4, 0] }, // pavgw
    OpcodeEntry { token: X86Instruction::Pmaxsw, opcode: 0xee, instr_type: 0x108, nb_ops: 2, op_type: [153, 25, 0] }, // pmaxsw
    OpcodeEntry { token: X86Instruction::Pmaxub, opcode: 0xde, instr_type: 0x108, nb_ops: 2, op_type: [153, 25, 0] }, // pmaxub
    OpcodeEntry { token: X86Instruction::Pminsw, opcode: 0xea, instr_type: 0x108, nb_ops: 2, op_type: [153, 25, 0] }, // pminsw
    OpcodeEntry { token: X86Instruction::Pminub, opcode: 0xda, instr_type: 0x108, nb_ops: 2, op_type: [153, 25, 0] }, // pminub
    OpcodeEntry { token: X86Instruction::Rcpss, opcode: 0x53, instr_type: 0x108, nb_ops: 2, op_type: [132, 4, 0] }, // rcpss
    OpcodeEntry { token: X86Instruction::Rsqrtps, opcode: 0x52, instr_type: 0x108, nb_ops: 2, op_type: [132, 4, 0] }, // rsqrtps
    OpcodeEntry { token: X86Instruction::Sqrtps, opcode: 0x51, instr_type: 0x108, nb_ops: 2, op_type: [132, 4, 0] }, // sqrtps
    OpcodeEntry { token: X86Instruction::Subps, opcode: 0x5c, instr_type: 0x108, nb_ops: 2, op_type: [132, 4, 0] }, // subps
];
/// Simple zero-operand instruction opcodes (DEF_ASM_OP0 entries from i386-asm.h).
/// Indexed by `(instruction_token - TOK_ASM_FIRST)` for direct lookup.
/// ALT-wrapped OP0 entries (like `word`) are excluded as in the C code.
pub static OP0_CODES: &[(X86Instruction, u32)] = &[
    (X86Instruction::Clc, 0x00f8), // clc
    (X86Instruction::Cld, 0x00fc), // cld
    (X86Instruction::Cli, 0x00fa), // cli
    (X86Instruction::Clts, 0x0f06), // clts
    (X86Instruction::Cmc, 0x00f5), // cmc
    (X86Instruction::Lahf, 0x009f), // lahf
    (X86Instruction::Sahf, 0x009e), // sahf
    (X86Instruction::Pusha, 0x0060), // pusha
    (X86Instruction::Popa, 0x0061), // popa
    (X86Instruction::Pushfl, 0x009c), // pushfl
    (X86Instruction::Popfl, 0x009d), // popfl
    (X86Instruction::Pushf, 0x009c), // pushf
    (X86Instruction::Popf, 0x009d), // popf
    (X86Instruction::Stc, 0x00f9), // stc
    (X86Instruction::Std, 0x00fd), // std
    (X86Instruction::Sti, 0x00fb), // sti
    (X86Instruction::Aaa, 0x0037), // aaa
    (X86Instruction::Aas, 0x003f), // aas
    (X86Instruction::Daa, 0x0027), // daa
    (X86Instruction::Das, 0x002f), // das
    (X86Instruction::Aad, 0xd50a), // aad
    (X86Instruction::Aam, 0xd40a), // aam
    (X86Instruction::Cbw, 0x6698), // cbw
    (X86Instruction::Cwd, 0x6699), // cwd
    (X86Instruction::Cwde, 0x0098), // cwde
    (X86Instruction::Cdq, 0x0099), // cdq
    (X86Instruction::Cbtw, 0x6698), // cbtw
    (X86Instruction::Cwtl, 0x0098), // cwtl
    (X86Instruction::Cwtd, 0x6699), // cwtd
    (X86Instruction::Cltd, 0x0099), // cltd
    (X86Instruction::Int3, 0x00cc), // int3
    (X86Instruction::Into, 0x00ce), // into
    (X86Instruction::Iret, 0x00cf), // iret
    (X86Instruction::Rsm, 0x0faa), // rsm
    (X86Instruction::Hlt, 0x00f4), // hlt
    (X86Instruction::Nop, 0x0090), // nop
    (X86Instruction::Pause, 0xf390), // pause
    (X86Instruction::Xlat, 0x00d7), // xlat
    (X86Instruction::Wait_, 0x009b), // wait
    (X86Instruction::Fwait, 0x009b), // fwait
    (X86Instruction::Aword, 0x0067), // aword
    (X86Instruction::Word, 0x0066), // word (operand-size prefix, alias for data16)
    (X86Instruction::Addr16, 0x0067), // addr16
    (X86Instruction::Data16, 0x0066), // data16
    (X86Instruction::Lock, 0x00f0), // lock
    (X86Instruction::Rep, 0x00f3), // rep
    (X86Instruction::Repe, 0x00f3), // repe
    (X86Instruction::Repz, 0x00f3), // repz
    (X86Instruction::Repne, 0x00f2), // repne
    (X86Instruction::Repnz, 0x00f2), // repnz
    (X86Instruction::Invd, 0x0f08), // invd
    (X86Instruction::Wbinvd, 0x0f09), // wbinvd
    (X86Instruction::Cpuid, 0x0fa2), // cpuid
    (X86Instruction::Wrmsr, 0x0f30), // wrmsr
    (X86Instruction::Rdtsc, 0x0f31), // rdtsc
    (X86Instruction::Rdmsr, 0x0f32), // rdmsr
    (X86Instruction::Rdpmc, 0x0f33), // rdpmc
    (X86Instruction::Ud2, 0x0f0b), // ud2
    (X86Instruction::Leave, 0x00c9), // leave
    (X86Instruction::Ret, 0x00c3), // ret
    (X86Instruction::Retl, 0x00c3), // retl
    (X86Instruction::Lret, 0x00cb), // lret
    (X86Instruction::Fucompp, 0xdae9), // fucompp
    (X86Instruction::Ftst, 0xd9e4), // ftst
    (X86Instruction::Fxam, 0xd9e5), // fxam
    (X86Instruction::Fld1, 0xd9e8), // fld1
    (X86Instruction::Fldl2t, 0xd9e9), // fldl2t
    (X86Instruction::Fldl2e, 0xd9ea), // fldl2e
    (X86Instruction::Fldpi, 0xd9eb), // fldpi
    (X86Instruction::Fldlg2, 0xd9ec), // fldlg2
    (X86Instruction::Fldln2, 0xd9ed), // fldln2
    (X86Instruction::Fldz, 0xd9ee), // fldz
    (X86Instruction::F2xm1, 0xd9f0), // f2xm1
    (X86Instruction::Fyl2x, 0xd9f1), // fyl2x
    (X86Instruction::Fptan, 0xd9f2), // fptan
    (X86Instruction::Fpatan, 0xd9f3), // fpatan
    (X86Instruction::Fxtract, 0xd9f4), // fxtract
    (X86Instruction::Fprem1, 0xd9f5), // fprem1
    (X86Instruction::Fdecstp, 0xd9f6), // fdecstp
    (X86Instruction::Fincstp, 0xd9f7), // fincstp
    (X86Instruction::Fprem, 0xd9f8), // fprem
    (X86Instruction::Fyl2xp1, 0xd9f9), // fyl2xp1
    (X86Instruction::Fsqrt, 0xd9fa), // fsqrt
    (X86Instruction::Fsincos, 0xd9fb), // fsincos
    (X86Instruction::Frndint, 0xd9fc), // frndint
    (X86Instruction::Fscale, 0xd9fd), // fscale
    (X86Instruction::Fsin, 0xd9fe), // fsin
    (X86Instruction::Fcos, 0xd9ff), // fcos
    (X86Instruction::Fchs, 0xd9e0), // fchs
    (X86Instruction::Fabs, 0xd9e1), // fabs
    (X86Instruction::Fninit, 0xdbe3), // fninit
    (X86Instruction::Fnclex, 0xdbe2), // fnclex
    (X86Instruction::Fnop, 0xd9d0), // fnop
    (X86Instruction::Fxch, 0xd9c9), // fxch
    (X86Instruction::Fnstsw, 0xdfe0), // fnstsw
    (X86Instruction::Emms, 0x0f77), // emms
];
// =============================================================================
// Token Range Constants
// =============================================================================

/// First token in the assembly instruction range (OP0 start).
/// Source: `i386-asm.c` line 27 — `#define TOK_ASM_first TOK_ASM_clc`
pub const TOK_ASM_FIRST: X86Instruction = X86Instruction::Clc;

/// Last token in the basic instruction range.
/// Source: `i386-asm.c` line 28 — `#define TOK_ASM_last TOK_ASM_emms`
pub const TOK_ASM_LAST: X86Instruction = X86Instruction::Emms;

/// Last token including SSE instructions.
/// Source: `i386-asm.c` line 29 — `#define TOK_ASM_alllast TOK_ASM_subps`
pub const TOK_ASM_ALLLAST: X86Instruction = X86Instruction::Subps;

// =============================================================================
// Instruction Lookup Functions
// =============================================================================

/// Look up instruction name string from instruction token.
/// Delegates to `X86Instruction::name()`.
#[inline]
pub fn instruction_name(instr: X86Instruction) -> &'static str {
    instr.name()
}

/// Look up instruction token from assembly mnemonic name string.
/// Delegates to `X86Instruction::from_name()`.
#[inline]
pub fn instruction_from_name(name: &str) -> Option<X86Instruction> {
    X86Instruction::from_name(name)
}

/// Look up the first opcode entry for a given instruction token.
///
/// Supports both exact matching and range-based matching:
/// - Exact: `lookup_opcode(MovB)` finds entries with `token == MovB`
/// - Range: `lookup_opcode(Mov)` finds entries stored under `MovB` because
///   `Mov` is in the suffix group `[MovB, MovW, MovL, Mov]` and the table
///   stores the first variant (`MovB`).
///
/// This mirrors the C assembler's range-based instruction matching logic.
pub fn lookup_opcode(token: X86Instruction) -> Option<&'static OpcodeEntry> {
    // First try exact match (fast path)
    if let Some(entry) = OPCODE_TABLE.iter().find(|e| e.token == token) {
        return Some(entry);
    }
    // Fall back to range match: find the group start for this token
    let group_start = find_group_start_token(token);
    if group_start != token {
        OPCODE_TABLE.iter().find(|e| e.token == group_start)
    } else {
        None
    }
}

/// Get all opcode entries for a given instruction token.
///
/// Some instructions have multiple encodings (ALT entries in `i386-asm.h`).
/// Supports range-based matching: passing a base or suffixed variant will
/// find all entries stored under the group's first variant token.
pub fn lookup_all_opcodes(token: X86Instruction) -> Vec<&'static OpcodeEntry> {
    // First try exact match
    let exact: Vec<&'static OpcodeEntry> = OPCODE_TABLE.iter().filter(|e| e.token == token).collect();
    if !exact.is_empty() {
        return exact;
    }
    // Fall back to range match
    let group_start = find_group_start_token(token);
    if group_start != token {
        OPCODE_TABLE.iter().filter(|e| e.token == group_start).collect()
    } else {
        Vec::new()
    }
}

/// Find the first token in a suffix group containing the given token.
/// For BWLX groups (4 variants: B, W, L, base), returns the B variant.
/// For WLX groups (3 variants: W, L, base), returns the W variant.
/// If the token is not part of a suffix group, returns itself.
fn find_group_start_token(token: X86Instruction) -> X86Instruction {
    let disc = token as u16;
    for &(start, count, _has_b) in SUFFIX_GROUPS.iter() {
        if disc >= start && disc < start + count {
            if let Some(first) = X86Instruction::from_u16(start) {
                return first;
            }
        }
    }
    token
}

// =============================================================================
// Operand Size Suffix Helpers
// =============================================================================

/// Given a base instruction, get the byte-suffixed variant.
/// For example, `X86Instruction::Mov` → `Some(X86Instruction::MovB)`.
/// Returns `None` if the instruction has no byte-suffix variant.
pub fn with_byte_suffix(base: X86Instruction) -> Option<X86Instruction> {
    let disc = base as u16;
    // BWLX groups: base is at offset 3 from start, B is at offset 0
    // Check if this is a BWLX base (every 4th, starting from group starts)
    // BWL groups: base is at offset 3, B is at offset 0
    // WLX groups have no byte variant
    for &(start, count, has_b) in SUFFIX_GROUPS.iter() {
        if has_b && count == 4 {
            // BWLX/BWL group: [B, W, L, base]
            if disc == start + 3 {
                return X86Instruction::from_u16(start);
            }
        }
    }
    None
}

/// Given a base instruction, get the word-suffixed variant.
/// For example, `X86Instruction::Mov` → `Some(X86Instruction::MovW)`.
pub fn with_word_suffix(base: X86Instruction) -> Option<X86Instruction> {
    let disc = base as u16;
    for &(start, count, _has_b) in SUFFIX_GROUPS.iter() {
        if count == 4 {
            // BWLX/BWL: [B, W, L, base] — W at offset 1
            if disc == start + 3 {
                return X86Instruction::from_u16(start + 1);
            }
        } else if count == 3 {
            // WLX: [W, L, base] — W at offset 0
            if disc == start + 2 {
                return X86Instruction::from_u16(start);
            }
        }
    }
    None
}

/// Given a base instruction, get the long-suffixed variant.
/// For example, `X86Instruction::Mov` → `Some(X86Instruction::MovL)`.
pub fn with_long_suffix(base: X86Instruction) -> Option<X86Instruction> {
    let disc = base as u16;
    for &(start, count, _has_b) in SUFFIX_GROUPS.iter() {
        if count == 4 {
            // BWLX/BWL: [B, W, L, base] — L at offset 2
            if disc == start + 3 {
                return X86Instruction::from_u16(start + 2);
            }
        } else if count == 3 {
            // WLX: [W, L, base] — L at offset 1
            if disc == start + 2 {
                return X86Instruction::from_u16(start + 1);
            }
        }
    }
    None
}

/// Given a suffixed instruction, get the base (unsuffixed) variant.
/// For example, `X86Instruction::MovB` → `X86Instruction::Mov`.
/// Returns the input if it is already an unsuffixed base instruction.
pub fn strip_suffix(instr: X86Instruction) -> X86Instruction {
    let disc = instr as u16;
    for &(start, count, _has_b) in SUFFIX_GROUPS.iter() {
        let end = start + count;  // exclusive
        if disc >= start && disc < end {
            // Base is always the last variant in the group
            return X86Instruction::from_u16(end - 1).unwrap_or(instr);
        }
    }
    instr
}

/// Get the operand size in bytes (1/2/4) from a suffixed instruction.
/// Returns `None` for unsuffixed base instructions or unrecognized inputs.
pub fn suffix_size(instr: X86Instruction) -> Option<u8> {
    let disc = instr as u16;
    for &(start, count, has_b) in SUFFIX_GROUPS.iter() {
        let end = start + count;
        if disc >= start && disc < end {
            let offset = disc - start;
            if count == 4 {
                // BWLX/BWL: [B=0, W=1, L=2, base=3]
                return match offset {
                    0 if has_b => Some(1),  // byte
                    1 => Some(2),            // word
                    2 => Some(4),            // long/dword
                    _ => None,               // base form
                };
            } else if count == 3 {
                // WLX: [W=0, L=1, base=2]
                return match offset {
                    0 => Some(2),  // word
                    1 => Some(4),  // long/dword
                    _ => None,     // base form
                };
            }
        }
    }
    None
}

/// Suffix group table: (start_discriminant, count, has_byte_variant)
///
/// Each entry describes a contiguous group of suffixed instruction variants.
/// - `start`: discriminant of first variant in group
/// - `count`: 4 for BWLX/BWL groups, 3 for WLX groups
/// - `has_b`: true if the group includes a byte-suffix variant
static SUFFIX_GROUPS: &[(u16, u16, bool)] = &[
    (0, 4, true), // mov
    (4, 4, true), // add
    (8, 4, true), // or
    (12, 4, true), // adc
    (16, 4, true), // sbb
    (20, 4, true), // and
    (24, 4, true), // sub
    (28, 4, true), // xor
    (32, 4, true), // cmp
    (36, 4, true), // inc
    (40, 4, true), // dec
    (44, 4, true), // not
    (48, 4, true), // neg
    (52, 4, true), // mul
    (56, 4, true), // imul
    (60, 4, true), // div
    (64, 4, true), // idiv
    (68, 4, true), // xchg
    (72, 4, true), // test
    (76, 4, true), // rol
    (80, 4, true), // ror
    (84, 4, true), // rcl
    (88, 4, true), // rcr
    (92, 4, true), // shl
    (96, 4, true), // shr
    (100, 4, true), // sar
    (104, 3, false), // shld
    (107, 3, false), // shrd
    (116, 4, true), // in
    (120, 4, true), // out
    (124, 3, false), // movzb
    (131, 3, false), // lea
    (263, 3, false), // bsf
    (266, 3, false), // bsr
    (269, 3, false), // bt
    (272, 3, false), // bts
    (275, 3, false), // btr
    (278, 3, false), // btc
    (281, 3, false), // popcnt
    (284, 3, false), // tzcnt
    (287, 3, false), // lzcnt
    (290, 3, false), // lar
    (293, 3, false), // lsl
    (344, 4, true), // xadd
    (348, 4, true), // cmpxchg
    (352, 4, true), // cmps
    (356, 4, true), // scmp
    (360, 4, true), // ins
    (364, 4, true), // outs
    (368, 4, true), // lods
    (372, 4, true), // slod
    (376, 4, true), // movs
    (380, 4, true), // smov
    (384, 4, true), // scas
    (388, 4, true), // ssca
    (392, 4, true), // stos
    (396, 4, true), // ssto
];

// =============================================================================
// Unit Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_name_roundtrip() {
        assert_eq!(X86Register::Al.name(), "al");
        assert_eq!(X86Register::Eax.name(), "eax");
        assert_eq!(X86Register::Xmm7.name(), "xmm7");
        assert_eq!(X86Register::St.name(), "st");
        assert_eq!(X86Register::from_name("eax"), Some(X86Register::Eax));
        assert_eq!(X86Register::from_name("xmm0"), Some(X86Register::Xmm0));
        assert_eq!(X86Register::from_name("nonexistent"), None);
    }

    #[test]
    fn test_register_number() {
        assert_eq!(X86Register::Al.reg_number(), 0);
        assert_eq!(X86Register::Cl.reg_number(), 1);
        assert_eq!(X86Register::Dl.reg_number(), 2);
        assert_eq!(X86Register::Bl.reg_number(), 3);
        assert_eq!(X86Register::Eax.reg_number(), 0);
        assert_eq!(X86Register::Ecx.reg_number(), 1);
        assert_eq!(X86Register::Edi.reg_number(), 7);
        assert_eq!(X86Register::Mm3.reg_number(), 3);
        assert_eq!(X86Register::Xmm5.reg_number(), 5);
        assert_eq!(X86Register::Cr4.reg_number(), 4);
    }

    #[test]
    fn test_register_size_class() {
        assert_eq!(X86Register::Al.size_class(), 8);
        assert_eq!(X86Register::Ah.size_class(), 8);
        assert_eq!(X86Register::Ax.size_class(), 16);
        assert_eq!(X86Register::Si.size_class(), 16);
        assert_eq!(X86Register::Eax.size_class(), 32);
        assert_eq!(X86Register::Edi.size_class(), 32);
    }

    #[test]
    fn test_instruction_name_roundtrip() {
        assert_eq!(X86Instruction::Mov.name(), "mov");
        assert_eq!(X86Instruction::MovB.name(), "movb");
        assert_eq!(X86Instruction::MovW.name(), "movw");
        assert_eq!(X86Instruction::MovL.name(), "movl");
        assert_eq!(X86Instruction::Nop.name(), "nop");
        assert_eq!(X86Instruction::Clc.name(), "clc");
        assert_eq!(X86Instruction::Emms.name(), "emms");
        assert_eq!(X86Instruction::Subps.name(), "subps");
        assert_eq!(X86Instruction::from_name("mov"), Some(X86Instruction::Mov));
        assert_eq!(X86Instruction::from_name("nop"), Some(X86Instruction::Nop));
        assert_eq!(X86Instruction::from_name("nonexistent"), None);
    }

    #[test]
    fn test_tok_asm_range_constants() {
        assert_eq!(TOK_ASM_FIRST, X86Instruction::Clc);
        assert_eq!(TOK_ASM_LAST, X86Instruction::Emms);
        assert_eq!(TOK_ASM_ALLLAST, X86Instruction::Subps);
        // Emms must come before Subps
        assert!((TOK_ASM_LAST as u16) < (TOK_ASM_ALLLAST as u16));
        // Clc must come before Emms
        assert!((TOK_ASM_FIRST as u16) < (TOK_ASM_LAST as u16));
    }

    #[test]
    fn test_instruction_contiguity() {
        // Verify BWLX group contiguity: MovB..Mov must be 4 consecutive values
        assert_eq!(X86Instruction::MovB as u16 + 1, X86Instruction::MovW as u16);
        assert_eq!(X86Instruction::MovW as u16 + 1, X86Instruction::MovL as u16);
        assert_eq!(X86Instruction::MovL as u16 + 1, X86Instruction::Mov as u16);
        // Verify WLX group contiguity for shld
        assert_eq!(X86Instruction::ShldW as u16 + 1, X86Instruction::ShldL as u16);
        assert_eq!(X86Instruction::ShldL as u16 + 1, X86Instruction::Shld as u16);
    }

    #[test]
    fn test_condition_code_contiguity() {
        // Conditional jumps must be 30 consecutive tokens
        let jo = X86Instruction::JO as u16;
        let jg = X86Instruction::JG as u16;
        assert_eq!(jg - jo, 29);
        // Conditional sets must be 30 consecutive tokens
        let seto = X86Instruction::SetO as u16;
        let setg = X86Instruction::SetG as u16;
        assert_eq!(setg - seto, 29);
        // Conditional moves must be 30 consecutive tokens
        let cmovo = X86Instruction::CmovO as u16;
        let cmovg = X86Instruction::CmovG as u16;
        assert_eq!(cmovg - cmovo, 29);
    }

    #[test]
    fn test_fp_ordering() {
        // DEF_FP(add): fadd, faddp, fadds, fiaddl, faddl, fiadds
        let fadd = X86Instruction::FAdd as u16;
        assert_eq!(X86Instruction::FAddp as u16, fadd + 1);
        assert_eq!(X86Instruction::FAdds as u16, fadd + 2);
        assert_eq!(X86Instruction::FiAddl as u16, fadd + 3);
        assert_eq!(X86Instruction::FAddl as u16, fadd + 4);
        assert_eq!(X86Instruction::FiAdds as u16, fadd + 5);
        // fcom special: fcom, fcom_1, fcoms, ficoml, fcoml, ficoms
        let fcom = X86Instruction::Fcom as u16;
        assert_eq!(X86Instruction::FcomX1 as u16, fcom + 1);
        assert_eq!(X86Instruction::Fcoms as u16, fcom + 2);
    }

    #[test]
    fn test_opcode_table_not_empty() {
        // OPCODE_TABLE contains DEF_ASM_OP0L/OP1/OP2/OP3 entries (~307 for i386)
        assert!(!OPCODE_TABLE.is_empty());
        assert!(OPCODE_TABLE.len() >= 300,
            "OPCODE_TABLE should have >= 300 entries, got {}", OPCODE_TABLE.len());
        // OP0_CODES contains simple zero-operand DEF_ASM_OP0 entries (~95)
        assert!(!OP0_CODES.is_empty());
        assert!(OP0_CODES.len() >= 90,
            "OP0_CODES should have >= 90 entries, got {}", OP0_CODES.len());
    }

    #[test]
    fn test_opcode_lookup() {
        // movb is in OPCODE_TABLE (DEF_ASM_OP2 entries)
        let entry = lookup_opcode(X86Instruction::MovB).unwrap();
        assert_eq!(entry.token, X86Instruction::MovB);
        assert_eq!(entry.nb_ops, 2);
        // addb is in OPCODE_TABLE (DEF_ASM_OP2 entries)
        let entry = lookup_opcode(X86Instruction::AddB).unwrap();
        assert_eq!(entry.token, X86Instruction::AddB);
        assert_eq!(entry.nb_ops, 2);
        // OP0 instructions are in OP0_CODES, not OPCODE_TABLE
        let clc_op0 = OP0_CODES.iter().find(|e| e.0 == X86Instruction::Clc);
        assert!(clc_op0.is_some(), "Clc should be in OP0_CODES");
        assert_eq!(clc_op0.unwrap().1, 0xf8);
        let nop_op0 = OP0_CODES.iter().find(|e| e.0 == X86Instruction::Nop);
        assert!(nop_op0.is_some(), "Nop should be in OP0_CODES");
        assert_eq!(nop_op0.unwrap().1, 0x90);
    }

    #[test]
    fn test_opcode_all_lookup() {
        // Exact match: MovB is the stored token for mov entries in the opcode table
        let movb_entries = lookup_all_opcodes(X86Instruction::MovB);
        assert!(movb_entries.len() >= 6, "movb should have at least 6 ALT encodings, got {}", movb_entries.len());
        for e in &movb_entries {
            assert_eq!(e.token, X86Instruction::MovB);
        }

        // Range match: Mov (base form) resolves to MovB via suffix group
        let mov_entries = lookup_all_opcodes(X86Instruction::Mov);
        assert!(!mov_entries.is_empty(), "Mov should resolve to MovB entries via range matching");
        assert_eq!(mov_entries.len(), movb_entries.len());

        // addb exact match: multiple encodings for arithmetic
        let addb_entries = lookup_all_opcodes(X86Instruction::AddB);
        assert!(addb_entries.len() >= 4, "addb should have at least 4 ALT encodings, got {}", addb_entries.len());
    }

    #[test]
    fn test_suffix_helpers() {
        // with_byte_suffix
        assert_eq!(with_byte_suffix(X86Instruction::Mov), Some(X86Instruction::MovB));
        assert_eq!(with_byte_suffix(X86Instruction::Add), Some(X86Instruction::AddB));
        assert_eq!(with_byte_suffix(X86Instruction::Shld), None); // WLX has no byte

        // with_word_suffix
        assert_eq!(with_word_suffix(X86Instruction::Mov), Some(X86Instruction::MovW));
        assert_eq!(with_word_suffix(X86Instruction::Shld), Some(X86Instruction::ShldW));

        // with_long_suffix
        assert_eq!(with_long_suffix(X86Instruction::Mov), Some(X86Instruction::MovL));
        assert_eq!(with_long_suffix(X86Instruction::Lea), Some(X86Instruction::LeaL));

        // strip_suffix
        assert_eq!(strip_suffix(X86Instruction::MovB), X86Instruction::Mov);
        assert_eq!(strip_suffix(X86Instruction::MovW), X86Instruction::Mov);
        assert_eq!(strip_suffix(X86Instruction::MovL), X86Instruction::Mov);
        assert_eq!(strip_suffix(X86Instruction::Mov), X86Instruction::Mov);
        assert_eq!(strip_suffix(X86Instruction::ShldW), X86Instruction::Shld);

        // suffix_size
        assert_eq!(suffix_size(X86Instruction::MovB), Some(1));
        assert_eq!(suffix_size(X86Instruction::MovW), Some(2));
        assert_eq!(suffix_size(X86Instruction::MovL), Some(4));
        assert_eq!(suffix_size(X86Instruction::Mov), None); // base = no size
        assert_eq!(suffix_size(X86Instruction::ShldW), Some(2));
        assert_eq!(suffix_size(X86Instruction::ShldL), Some(4));
    }

    #[test]
    fn test_instruction_total_count() {
        // Verify total instruction count matches expectations
        assert_eq!(INSTRUCTION_TABLE.len(), 643);
    }

    #[test]
    fn test_register_total_count() {
        assert_eq!(REGISTER_TABLE.len(), 80);
    }

    #[test]
    fn test_fcom_1_placeholder() {
        assert_eq!(X86Instruction::FcomX1.name(), "fcom_1");
    }

    #[test]
    fn test_string_ops_present() {
        // Verify ins/outs are present (they were previously missing)
        assert_eq!(X86Instruction::InsB.name(), "insb");
        assert_eq!(X86Instruction::InsW.name(), "insw");
        assert_eq!(X86Instruction::InsL.name(), "insl");
        assert_eq!(X86Instruction::Ins.name(), "ins");
        assert_eq!(X86Instruction::OutsB.name(), "outsb");
        assert_eq!(X86Instruction::Outs.name(), "outs");
    }

    #[test]
    fn test_op_bitmask_constants() {
        assert_eq!(OP_REG8, 1 << 0);
        assert_eq!(OP_REG16, 1 << 1);
        assert_eq!(OP_REG32, 1 << 2);
        assert_eq!(OP_EA, 0x40000000);
    }
}
