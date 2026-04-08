//! RISC-V 64-bit Assembly Token Definitions
//!
//! Port of `riscv64-tok.h` (491 lines) to idiomatic Rust. Defines all RISC-V
//! register names, instruction mnemonics, CSR names, pseudo-instructions, and
//! assembler directive values as a comprehensive enum with lookup tables.
//!
//! The ordering of enum variants preserves the C source ordering exactly, which
//! is critical because `asm_parse_regvar()` uses sequential range checks
//! (e.g., `t >= X0 as i32 && t < F0 as i32`) to classify registers.

use std::fmt;

/// All RISC-V 64-bit assembly tokens.
///
/// Variant ordering matches `riscv64-tok.h` exactly:
/// - x0..x31 (integer registers, contiguous)
/// - f0..f31 (float registers, contiguous, immediately after x-registers)
/// - ABI integer names zero..t6 (contiguous, follow f-registers)
/// - ABI float names ft0..ft11 (contiguous, follow ABI integer names)
/// - pc (follows last ABI float name)
/// - Instructions, CSR names, pseudo-instructions, atomics, fence operands
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
#[allow(non_camel_case_types)]
pub enum RiscvAsmToken {
    // ===== Integer Registers x0-x31 (DEF_ASM lines 19-50) =====
    X0 = 0, X1, X2, X3, X4, X5, X6, X7,
    X8, X9, X10, X11, X12, X13, X14, X15,
    X16, X17, X18, X19, X20, X21, X22, X23,
    X24, X25, X26, X27, X28, X29, X30, X31,

    // ===== Float Registers f0-f31 (DEF_ASM lines 52-83) =====
    F0, F1, F2, F3, F4, F5, F6, F7,
    F8, F9, F10, F11, F12, F13, F14, F15,
    F16, F17, F18, F19, F20, F21, F22, F23,
    F24, F25, F26, F27, F28, F29, F30, F31,

    // ===== ABI Integer Register Names (lines 87-118) =====
    // zero→x0, ra→x1, sp→x2, gp→x3, tp→x4
    Zero, Ra, Sp, Gp, Tp,
    // t0→x5, t1→x6, t2→x7
    T0, T1, T2,
    // s0→x8, s1→x9
    S0, S1,
    // a0→x10 .. a7→x17
    A0, A1, A2, A3, A4, A5, A6, A7,
    // s2→x18 .. s11→x27
    S2, S3, S4, S5, S6, S7, S8, S9, S10, S11,
    // t3→x28 .. t6→x31
    T3, T4, T5, T6,

    // ===== ABI Float Register Names (lines 120-151) =====
    Ft0, Ft1, Ft2, Ft3, Ft4, Ft5, Ft6, Ft7,
    Fs0, Fs1,
    Fa0, Fa1, Fa2, Fa3, Fa4, Fa5, Fa6, Fa7,
    Fs2, Fs3, Fs4, Fs5, Fs6, Fs7, Fs8, Fs9, Fs10, Fs11,
    Ft8, Ft9, Ft10, Ft11,

    // ===== Program Counter (line 153) =====
    Pc,

    // ===== Load Instructions =====
    Lb, Lh, Lw, Lbu, Lhu, Ld, Lwu,

    // ===== Store Instructions =====
    Sb, Sh, Sw, Sd,

    // ===== Shift Instructions =====
    Sll, Srl, Sra, Slli, Srli,
    Sllw, Slliw, Srlw, Srliw,
    Srai, Sraw, Sraiw,

    // ===== Arithmetic Instructions =====
    Add, Addi, Sub, Lui, Auipc, Addw, Addiw, Subw,

    // ===== Logical Instructions =====
    Xor, Xori, Or, Ori, And, Andi,

    // ===== Compare Instructions =====
    Slt, Slti, Sltu, Sltiu,

    // ===== Branch Instructions =====
    Beq, Bne, Blt, Bge, Bltu, Bgeu,

    // ===== Jump Instructions =====
    Jal, Jalr,

    // ===== Synchronization =====
    Fence, FenceI,

    // ===== System Instructions =====
    Ecall, Ebreak,

    // ===== Counter Instructions =====
    Rdcycle, Rdcycleh, Rdtime, Rdtimeh, Rdinstret, Rdinstreth,

    // ===== M Extension (Multiply/Divide) =====
    Mul, Mulh, Mulhsu, Mulhu, Div, Divu, Rem, Remu,
    Mulw, Divw, Divuw, Remw, Remuw,

    // ===== F/D Extension (DEF_ASM_WITH_SUFFIX) =====
    FsgnjS, FsgnjD,
    FmaddS, FmaddD,
    FmaxS, FmaxD,
    FminS, FminD,
    FsqrtS, FsqrtD,

    // ===== C Extension (Compressed, DEF_ASM_WITH_SUFFIX(c, ...)) =====
    CNop, CLi,
    CLw, CLwsp, CFlw, CFlwsp, CFld, CFldsp, CLd, CLdsp,
    CSw, CSd, CSwsp, CSdsp, CFsw, CFswsp, CFsd, CFsdsp,
    CSlli, CSrli, CSrai,
    CAdd, CAddi, CAddi16sp, CAddi4spn, CLui, CSub, CMv,
    CAddw, CAddiw, CSubw,
    CXor, COr, CAnd, CAndi,
    CBeqz, CBnez,
    CJ, CJr, CJal, CJalr, CEbreak,

    // ===== Zicsr Extension =====
    Csrrw, Csrrs, Csrrc, Csrrwi, Csrrsi, Csrrci,

    // ===== CSR Register Names =====
    Cycle, Fcsr, Fflags, Frm, Instret, Time, Cycleh, Instreth, Timeh,

    // ===== CSR Pseudo-Instructions =====
    Csrc, Csrci, Csrr, CsrsPseudo, Csrsi, Csrw, Csrwi,
    Frcsr, Frflags, Frrm, Fscsr, Fsflags, Fsrm,

    // ===== Privileged Instructions =====
    Mrts, Mrth, Hrts, Wfi,

    // ===== Pseudo-Instructions (Branch) =====
    Beqz, Bgez, Bgt, Bgtu, Bgtz, Ble, Bleu, Blez, Bltz, Bnez, Call,

    // ===== Pseudo-Instructions (Floating-Point) =====
    FabsD, FabsS,
    Fld_pseudo, Flw_pseudo,
    FmvD, FmvS,
    FnegD, FnegS,
    Fsd_pseudo, Fsw_pseudo,

    // ===== Pseudo-Instructions (General) =====
    J, Jump, Jr, La, Li, Lla, Mv, Neg, Negw,
    Nop, Not, Ret, Seqz, SextW, Sgtz, Sltz, Snez, Tail,

    // ===== .option Directive Values =====
    Arch, Rvc, Norvc, Pic, Nopic, Relax, Norelax, Push, Pop,

    // ===== A Extension (Atomics, DEF_ASM_WITH_SUFFIXES) =====
    LrW, LrWAq, LrWRl, LrWAqrl,
    LrD, LrDAq, LrDRl, LrDAqrl,
    ScW, ScWAq, ScWRl, ScWAqrl,
    ScD, ScDAq, ScDRl, ScDAqrl,

    // ===== Fence Operand Tokens (DEF_ASM_FENCE, _fence suffix) =====
    WFence, RFence, RwFence,
    OFence, OwFence, OrFence, OrwFence,
    IFence, IwFence, IrFence, IrwFence,
    IoFence, IowFence, IorFence, IorwFence,
}

/// Total number of RISC-V assembly token variants.
const TOKEN_COUNT: usize = RiscvAsmToken::IorwFence as usize + 1;

/// Assembly-language string names for each token, indexed by discriminant.
/// Order must exactly match the enum variant order.
static TOKEN_NAMES: [&str; TOKEN_COUNT] = [
    // Integer registers x0-x31
    "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7",
    "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15",
    "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23",
    "x24", "x25", "x26", "x27", "x28", "x29", "x30", "x31",
    // Float registers f0-f31
    "f0", "f1", "f2", "f3", "f4", "f5", "f6", "f7",
    "f8", "f9", "f10", "f11", "f12", "f13", "f14", "f15",
    "f16", "f17", "f18", "f19", "f20", "f21", "f22", "f23",
    "f24", "f25", "f26", "f27", "f28", "f29", "f30", "f31",
    // ABI integer names
    "zero", "ra", "sp", "gp", "tp",
    "t0", "t1", "t2",
    "s0", "s1",
    "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7",
    "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11",
    "t3", "t4", "t5", "t6",
    // ABI float names
    "ft0", "ft1", "ft2", "ft3", "ft4", "ft5", "ft6", "ft7",
    "fs0", "fs1",
    "fa0", "fa1", "fa2", "fa3", "fa4", "fa5", "fa6", "fa7",
    "fs2", "fs3", "fs4", "fs5", "fs6", "fs7", "fs8", "fs9", "fs10", "fs11",
    "ft8", "ft9", "ft10", "ft11",
    // pc
    "pc",
    // Load instructions
    "lb", "lh", "lw", "lbu", "lhu", "ld", "lwu",
    // Store instructions
    "sb", "sh", "sw", "sd",
    // Shift instructions
    "sll", "srl", "sra", "slli", "srli",
    "sllw", "slliw", "srlw", "srliw",
    "srai", "sraw", "sraiw",
    // Arithmetic
    "add", "addi", "sub", "lui", "auipc", "addw", "addiw", "subw",
    // Logical
    "xor", "xori", "or", "ori", "and", "andi",
    // Compare
    "slt", "slti", "sltu", "sltiu",
    // Branch
    "beq", "bne", "blt", "bge", "bltu", "bgeu",
    // Jump
    "jal", "jalr",
    // Sync
    "fence", "fence.i",
    // System
    "ecall", "ebreak",
    // Counters
    "rdcycle", "rdcycleh", "rdtime", "rdtimeh", "rdinstret", "rdinstreth",
    // M extension
    "mul", "mulh", "mulhsu", "mulhu", "div", "divu", "rem", "remu",
    "mulw", "divw", "divuw", "remw", "remuw",
    // F/D extension
    "fsgnj.s", "fsgnj.d",
    "fmadd.s", "fmadd.d",
    "fmax.s", "fmax.d",
    "fmin.s", "fmin.d",
    "fsqrt.s", "fsqrt.d",
    // C extension
    "c.nop", "c.li",
    "c.lw", "c.lwsp", "c.flw", "c.flwsp", "c.fld", "c.fldsp", "c.ld", "c.ldsp",
    "c.sw", "c.sd", "c.swsp", "c.sdsp", "c.fsw", "c.fswsp", "c.fsd", "c.fsdsp",
    "c.slli", "c.srli", "c.srai",
    "c.add", "c.addi", "c.addi16sp", "c.addi4spn", "c.lui", "c.sub", "c.mv",
    "c.addw", "c.addiw", "c.subw",
    "c.xor", "c.or", "c.and", "c.andi",
    "c.beqz", "c.bnez",
    "c.j", "c.jr", "c.jal", "c.jalr", "c.ebreak",
    // Zicsr
    "csrrw", "csrrs", "csrrc", "csrrwi", "csrrsi", "csrrci",
    // CSR register names
    "cycle", "fcsr", "fflags", "frm", "instret", "time", "cycleh", "instreth", "timeh",
    // CSR pseudo-instructions
    "csrc", "csrci", "csrr", "csrs", "csrsi", "csrw", "csrwi",
    "frcsr", "frflags", "frrm", "fscsr", "fsflags", "fsrm",
    // Privileged
    "mrts", "mrth", "hrts", "wfi",
    // Pseudo-instructions (branch)
    "beqz", "bgez", "bgt", "bgtu", "bgtz", "ble", "bleu", "blez", "bltz", "bnez", "call",
    // Pseudo-instructions (FP)
    "fabs.d", "fabs.s",
    "fld", "flw",
    "fmv.d", "fmv.s",
    "fneg.d", "fneg.s",
    "fsd", "fsw",
    // Pseudo-instructions (general)
    "j", "jump", "jr", "la", "li", "lla", "mv", "neg", "negw",
    "nop", "not", "ret", "seqz", "sext.w", "sgtz", "sltz", "snez", "tail",
    // .option values
    "arch", "rvc", "norvc", "pic", "nopic", "relax", "norelax", "push", "pop",
    // A extension (atomics)
    "lr.w", "lr.w.aq", "lr.w.rl", "lr.w.aqrl",
    "lr.d", "lr.d.aq", "lr.d.rl", "lr.d.aqrl",
    "sc.w", "sc.w.aq", "sc.w.rl", "sc.w.aqrl",
    "sc.d", "sc.d.aq", "sc.d.rl", "sc.d.aqrl",
    // Fence operands (with _fence suffix disambiguation)
    "w", "r", "rw",
    "o", "ow", "or", "orw",
    "i", "iw", "ir", "irw",
    "io", "iow", "ior", "iorw",
];

// ---------------------------------------------------------------------------
// Display trait — delegates to as_str() for human-readable output
// ---------------------------------------------------------------------------

impl fmt::Display for RiscvAsmToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Core methods on RiscvAsmToken
// ---------------------------------------------------------------------------

impl RiscvAsmToken {
    /// Returns the canonical assembly-language string representation of this token.
    ///
    /// Register tokens return their standard names (e.g., `"x0"`, `"fa7"`),
    /// instruction tokens return their mnemonic (e.g., `"add"`, `"fsgnj.s"`),
    /// and fence operand tokens return the operand characters (e.g., `"iorw"`).
    #[inline]
    pub fn as_str(&self) -> &'static str {
        TOKEN_NAMES[*self as usize]
    }

    /// Converts an integer token ID (discriminant value) back to a `RiscvAsmToken`.
    ///
    /// Returns `None` if `val` is out of range (negative or beyond the last variant).
    /// This is the inverse of casting `RiscvAsmToken as i32`.
    ///
    /// # Safety rationale
    /// The `transmute` is sound because:
    /// 1. `RiscvAsmToken` is `#[repr(i32)]` with sequential discriminants starting at 0.
    /// 2. We bounds-check `val` against `TOKEN_COUNT` before transmuting.
    /// 3. Every integer in `0..TOKEN_COUNT` corresponds to a valid enum variant.
    pub fn from_i32(val: i32) -> Option<RiscvAsmToken> {
        if val >= 0 && (val as usize) < TOKEN_COUNT {
            // SAFETY: val is within the valid range of sequential discriminants.
            Some(unsafe { core::mem::transmute::<i32, RiscvAsmToken>(val) })
        } else {
            None
        }
    }

    /// Returns `true` if this token represents an integer register (x0-x31 or ABI name).
    #[inline]
    pub fn is_int_register(&self) -> bool {
        let v = *self as i32;
        // x0..x31 range
        (v >= RiscvAsmToken::X0 as i32 && v <= RiscvAsmToken::X31 as i32)
        // ABI integer name range (zero..t6)
        || (v >= RiscvAsmToken::Zero as i32 && v <= RiscvAsmToken::T6 as i32)
    }

    /// Returns `true` if this token represents a float register (f0-f31 or ABI name).
    #[inline]
    pub fn is_float_register(&self) -> bool {
        let v = *self as i32;
        // f0..f31 range
        (v >= RiscvAsmToken::F0 as i32 && v <= RiscvAsmToken::F31 as i32)
        // ABI float name range (ft0..ft11)
        || (v >= RiscvAsmToken::Ft0 as i32 && v <= RiscvAsmToken::Ft11 as i32)
    }

    /// Returns `true` if this token represents any register (integer, float, or pc).
    #[inline]
    pub fn is_register(&self) -> bool {
        let v = *self as i32;
        v >= RiscvAsmToken::X0 as i32 && v <= RiscvAsmToken::Pc as i32
    }
}

// ---------------------------------------------------------------------------
// Constant arrays for register name lookup
// ---------------------------------------------------------------------------

/// String names for the 32 integer registers, indexed by register number (0-31).
pub const RISCV_INT_REGS: &[&str; 32] = &[
    "x0",  "x1",  "x2",  "x3",  "x4",  "x5",  "x6",  "x7",
    "x8",  "x9",  "x10", "x11", "x12", "x13", "x14", "x15",
    "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23",
    "x24", "x25", "x26", "x27", "x28", "x29", "x30", "x31",
];

/// String names for the 32 float registers, indexed by register number (0-31).
pub const RISCV_FLOAT_REGS: &[&str; 32] = &[
    "f0",  "f1",  "f2",  "f3",  "f4",  "f5",  "f6",  "f7",
    "f8",  "f9",  "f10", "f11", "f12", "f13", "f14", "f15",
    "f16", "f17", "f18", "f19", "f20", "f21", "f22", "f23",
    "f24", "f25", "f26", "f27", "f28", "f29", "f30", "f31",
];

/// ABI name aliases for integer registers: `(name, register_number)` pairs.
///
/// Maps standard RISC-V ABI names (zero, ra, sp, gp, tp, t0-t6, s0-s11, a0-a7)
/// to their underlying x-register numbers (0-31). Includes `fp` alias for `s0`.
pub const RISCV_ABI_INT_NAMES: &[(&str, u8)] = &[
    ("zero", 0),  ("ra", 1),   ("sp", 2),   ("gp", 3),   ("tp", 4),
    ("t0", 5),    ("t1", 6),   ("t2", 7),
    ("s0", 8),    ("s1", 9),
    ("a0", 10),   ("a1", 11),  ("a2", 12),  ("a3", 13),
    ("a4", 14),   ("a5", 15),  ("a6", 16),  ("a7", 17),
    ("s2", 18),   ("s3", 19),  ("s4", 20),  ("s5", 21),
    ("s6", 22),   ("s7", 23),  ("s8", 24),  ("s9", 25),
    ("s10", 26),  ("s11", 27),
    ("t3", 28),   ("t4", 29),  ("t5", 30),  ("t6", 31),
    ("fp", 8),
];

/// ABI name aliases for float registers: `(name, register_number)` pairs.
///
/// Maps standard RISC-V ABI names (ft0-ft11, fs0-fs11, fa0-fa7)
/// to their underlying f-register numbers (0-31).
pub const RISCV_ABI_FLOAT_NAMES: &[(&str, u8)] = &[
    ("ft0", 0),   ("ft1", 1),  ("ft2", 2),   ("ft3", 3),
    ("ft4", 4),   ("ft5", 5),  ("ft6", 6),   ("ft7", 7),
    ("fs0", 8),   ("fs1", 9),
    ("fa0", 10),  ("fa1", 11), ("fa2", 12),  ("fa3", 13),
    ("fa4", 14),  ("fa5", 15), ("fa6", 16),  ("fa7", 17),
    ("fs2", 18),  ("fs3", 19), ("fs4", 20),  ("fs5", 21),
    ("fs6", 22),  ("fs7", 23), ("fs8", 24),  ("fs9", 25),
    ("fs10", 26), ("fs11", 27),
    ("ft8", 28),  ("ft9", 29), ("ft10", 30), ("ft11", 31),
];

// ---------------------------------------------------------------------------
// Instruction lookup table
// ---------------------------------------------------------------------------

/// Complete mapping from instruction mnemonic string to `RiscvAsmToken`.
///
/// This table covers all non-register tokens: base ISA instructions, extensions
/// (M, F/D, C, A, Zicsr), CSR names, pseudo-instructions, .option values,
/// and fence operands. Used by the assembler parser to resolve mnemonic
/// strings to token IDs.
pub static RISCV_INSTRUCTIONS: &[(&str, RiscvAsmToken)] = &[
    // Load instructions
    ("lb", RiscvAsmToken::Lb), ("lh", RiscvAsmToken::Lh),
    ("lw", RiscvAsmToken::Lw), ("lbu", RiscvAsmToken::Lbu),
    ("lhu", RiscvAsmToken::Lhu), ("ld", RiscvAsmToken::Ld),
    ("lwu", RiscvAsmToken::Lwu),
    // Store instructions
    ("sb", RiscvAsmToken::Sb), ("sh", RiscvAsmToken::Sh),
    ("sw", RiscvAsmToken::Sw), ("sd", RiscvAsmToken::Sd),
    // Shift instructions
    ("sll", RiscvAsmToken::Sll), ("srl", RiscvAsmToken::Srl),
    ("sra", RiscvAsmToken::Sra), ("slli", RiscvAsmToken::Slli),
    ("srli", RiscvAsmToken::Srli), ("sllw", RiscvAsmToken::Sllw),
    ("slliw", RiscvAsmToken::Slliw), ("srlw", RiscvAsmToken::Srlw),
    ("srliw", RiscvAsmToken::Srliw), ("srai", RiscvAsmToken::Srai),
    ("sraw", RiscvAsmToken::Sraw), ("sraiw", RiscvAsmToken::Sraiw),
    // Arithmetic instructions
    ("add", RiscvAsmToken::Add), ("addi", RiscvAsmToken::Addi),
    ("sub", RiscvAsmToken::Sub), ("lui", RiscvAsmToken::Lui),
    ("auipc", RiscvAsmToken::Auipc), ("addw", RiscvAsmToken::Addw),
    ("addiw", RiscvAsmToken::Addiw), ("subw", RiscvAsmToken::Subw),
    // Logical instructions
    ("xor", RiscvAsmToken::Xor), ("xori", RiscvAsmToken::Xori),
    ("or", RiscvAsmToken::Or), ("ori", RiscvAsmToken::Ori),
    ("and", RiscvAsmToken::And), ("andi", RiscvAsmToken::Andi),
    // Compare instructions
    ("slt", RiscvAsmToken::Slt), ("slti", RiscvAsmToken::Slti),
    ("sltu", RiscvAsmToken::Sltu), ("sltiu", RiscvAsmToken::Sltiu),
    // Branch instructions
    ("beq", RiscvAsmToken::Beq), ("bne", RiscvAsmToken::Bne),
    ("blt", RiscvAsmToken::Blt), ("bge", RiscvAsmToken::Bge),
    ("bltu", RiscvAsmToken::Bltu), ("bgeu", RiscvAsmToken::Bgeu),
    // Jump instructions
    ("jal", RiscvAsmToken::Jal), ("jalr", RiscvAsmToken::Jalr),
    // Synchronization
    ("fence", RiscvAsmToken::Fence), ("fence.i", RiscvAsmToken::FenceI),
    // System instructions
    ("ecall", RiscvAsmToken::Ecall), ("ebreak", RiscvAsmToken::Ebreak),
    // Counter instructions
    ("rdcycle", RiscvAsmToken::Rdcycle), ("rdcycleh", RiscvAsmToken::Rdcycleh),
    ("rdtime", RiscvAsmToken::Rdtime), ("rdtimeh", RiscvAsmToken::Rdtimeh),
    ("rdinstret", RiscvAsmToken::Rdinstret), ("rdinstreth", RiscvAsmToken::Rdinstreth),
    // M extension (multiply/divide)
    ("mul", RiscvAsmToken::Mul), ("mulh", RiscvAsmToken::Mulh),
    ("mulhsu", RiscvAsmToken::Mulhsu), ("mulhu", RiscvAsmToken::Mulhu),
    ("div", RiscvAsmToken::Div), ("divu", RiscvAsmToken::Divu),
    ("rem", RiscvAsmToken::Rem), ("remu", RiscvAsmToken::Remu),
    ("mulw", RiscvAsmToken::Mulw), ("divw", RiscvAsmToken::Divw),
    ("divuw", RiscvAsmToken::Divuw), ("remw", RiscvAsmToken::Remw),
    ("remuw", RiscvAsmToken::Remuw),
    // F/D extension (floating-point with suffix)
    ("fsgnj.s", RiscvAsmToken::FsgnjS), ("fsgnj.d", RiscvAsmToken::FsgnjD),
    ("fmadd.s", RiscvAsmToken::FmaddS), ("fmadd.d", RiscvAsmToken::FmaddD),
    ("fmax.s", RiscvAsmToken::FmaxS), ("fmax.d", RiscvAsmToken::FmaxD),
    ("fmin.s", RiscvAsmToken::FminS), ("fmin.d", RiscvAsmToken::FminD),
    ("fsqrt.s", RiscvAsmToken::FsqrtS), ("fsqrt.d", RiscvAsmToken::FsqrtD),
    // C extension (compressed instructions)
    ("c.nop", RiscvAsmToken::CNop), ("c.li", RiscvAsmToken::CLi),
    ("c.lw", RiscvAsmToken::CLw), ("c.lwsp", RiscvAsmToken::CLwsp),
    ("c.flw", RiscvAsmToken::CFlw), ("c.flwsp", RiscvAsmToken::CFlwsp),
    ("c.fld", RiscvAsmToken::CFld), ("c.fldsp", RiscvAsmToken::CFldsp),
    ("c.ld", RiscvAsmToken::CLd), ("c.ldsp", RiscvAsmToken::CLdsp),
    ("c.sw", RiscvAsmToken::CSw), ("c.sd", RiscvAsmToken::CSd),
    ("c.swsp", RiscvAsmToken::CSwsp), ("c.sdsp", RiscvAsmToken::CSdsp),
    ("c.fsw", RiscvAsmToken::CFsw), ("c.fswsp", RiscvAsmToken::CFswsp),
    ("c.fsd", RiscvAsmToken::CFsd), ("c.fsdsp", RiscvAsmToken::CFsdsp),
    ("c.slli", RiscvAsmToken::CSlli), ("c.srli", RiscvAsmToken::CSrli),
    ("c.srai", RiscvAsmToken::CSrai),
    ("c.add", RiscvAsmToken::CAdd), ("c.addi", RiscvAsmToken::CAddi),
    ("c.addi16sp", RiscvAsmToken::CAddi16sp), ("c.addi4spn", RiscvAsmToken::CAddi4spn),
    ("c.lui", RiscvAsmToken::CLui), ("c.sub", RiscvAsmToken::CSub),
    ("c.mv", RiscvAsmToken::CMv),
    ("c.addw", RiscvAsmToken::CAddw), ("c.addiw", RiscvAsmToken::CAddiw),
    ("c.subw", RiscvAsmToken::CSubw),
    ("c.xor", RiscvAsmToken::CXor), ("c.or", RiscvAsmToken::COr),
    ("c.and", RiscvAsmToken::CAnd), ("c.andi", RiscvAsmToken::CAndi),
    ("c.beqz", RiscvAsmToken::CBeqz), ("c.bnez", RiscvAsmToken::CBnez),
    ("c.j", RiscvAsmToken::CJ), ("c.jr", RiscvAsmToken::CJr),
    ("c.jal", RiscvAsmToken::CJal), ("c.jalr", RiscvAsmToken::CJalr),
    ("c.ebreak", RiscvAsmToken::CEbreak),
    // Zicsr extension
    ("csrrw", RiscvAsmToken::Csrrw), ("csrrs", RiscvAsmToken::Csrrs),
    ("csrrc", RiscvAsmToken::Csrrc), ("csrrwi", RiscvAsmToken::Csrrwi),
    ("csrrsi", RiscvAsmToken::Csrrsi), ("csrrci", RiscvAsmToken::Csrrci),
    // CSR register names
    ("cycle", RiscvAsmToken::Cycle), ("fcsr", RiscvAsmToken::Fcsr),
    ("fflags", RiscvAsmToken::Fflags), ("frm", RiscvAsmToken::Frm),
    ("instret", RiscvAsmToken::Instret), ("time", RiscvAsmToken::Time),
    ("cycleh", RiscvAsmToken::Cycleh), ("instreth", RiscvAsmToken::Instreth),
    ("timeh", RiscvAsmToken::Timeh),
    // CSR pseudo-instructions
    ("csrc", RiscvAsmToken::Csrc), ("csrci", RiscvAsmToken::Csrci),
    ("csrr", RiscvAsmToken::Csrr), ("csrs", RiscvAsmToken::CsrsPseudo),
    ("csrsi", RiscvAsmToken::Csrsi), ("csrw", RiscvAsmToken::Csrw),
    ("csrwi", RiscvAsmToken::Csrwi),
    ("frcsr", RiscvAsmToken::Frcsr), ("frflags", RiscvAsmToken::Frflags),
    ("frrm", RiscvAsmToken::Frrm), ("fscsr", RiscvAsmToken::Fscsr),
    ("fsflags", RiscvAsmToken::Fsflags), ("fsrm", RiscvAsmToken::Fsrm),
    // Privileged instructions
    ("mrts", RiscvAsmToken::Mrts), ("mrth", RiscvAsmToken::Mrth),
    ("hrts", RiscvAsmToken::Hrts), ("wfi", RiscvAsmToken::Wfi),
    // Pseudo-instructions (branch)
    ("beqz", RiscvAsmToken::Beqz), ("bgez", RiscvAsmToken::Bgez),
    ("bgt", RiscvAsmToken::Bgt), ("bgtu", RiscvAsmToken::Bgtu),
    ("bgtz", RiscvAsmToken::Bgtz), ("ble", RiscvAsmToken::Ble),
    ("bleu", RiscvAsmToken::Bleu), ("blez", RiscvAsmToken::Blez),
    ("bltz", RiscvAsmToken::Bltz), ("bnez", RiscvAsmToken::Bnez),
    ("call", RiscvAsmToken::Call),
    // Pseudo-instructions (floating-point)
    ("fabs.d", RiscvAsmToken::FabsD), ("fabs.s", RiscvAsmToken::FabsS),
    ("fld", RiscvAsmToken::Fld_pseudo), ("flw", RiscvAsmToken::Flw_pseudo),
    ("fmv.d", RiscvAsmToken::FmvD), ("fmv.s", RiscvAsmToken::FmvS),
    ("fneg.d", RiscvAsmToken::FnegD), ("fneg.s", RiscvAsmToken::FnegS),
    ("fsd", RiscvAsmToken::Fsd_pseudo), ("fsw", RiscvAsmToken::Fsw_pseudo),
    // Pseudo-instructions (general)
    ("j", RiscvAsmToken::J), ("jump", RiscvAsmToken::Jump),
    ("jr", RiscvAsmToken::Jr), ("la", RiscvAsmToken::La),
    ("li", RiscvAsmToken::Li), ("lla", RiscvAsmToken::Lla),
    ("mv", RiscvAsmToken::Mv), ("neg", RiscvAsmToken::Neg),
    ("negw", RiscvAsmToken::Negw), ("nop", RiscvAsmToken::Nop),
    ("not", RiscvAsmToken::Not), ("ret", RiscvAsmToken::Ret),
    ("seqz", RiscvAsmToken::Seqz), ("sext.w", RiscvAsmToken::SextW),
    ("sgtz", RiscvAsmToken::Sgtz), ("sltz", RiscvAsmToken::Sltz),
    ("snez", RiscvAsmToken::Snez), ("tail", RiscvAsmToken::Tail),
    // .option directive values
    ("arch", RiscvAsmToken::Arch), ("rvc", RiscvAsmToken::Rvc),
    ("norvc", RiscvAsmToken::Norvc), ("pic", RiscvAsmToken::Pic),
    ("nopic", RiscvAsmToken::Nopic), ("relax", RiscvAsmToken::Relax),
    ("norelax", RiscvAsmToken::Norelax), ("push", RiscvAsmToken::Push),
    ("pop", RiscvAsmToken::Pop),
    // A extension (atomics) — load reserved
    ("lr.w", RiscvAsmToken::LrW), ("lr.w.aq", RiscvAsmToken::LrWAq),
    ("lr.w.rl", RiscvAsmToken::LrWRl), ("lr.w.aqrl", RiscvAsmToken::LrWAqrl),
    ("lr.d", RiscvAsmToken::LrD), ("lr.d.aq", RiscvAsmToken::LrDAq),
    ("lr.d.rl", RiscvAsmToken::LrDRl), ("lr.d.aqrl", RiscvAsmToken::LrDAqrl),
    // A extension (atomics) — store conditional
    ("sc.w", RiscvAsmToken::ScW), ("sc.w.aq", RiscvAsmToken::ScWAq),
    ("sc.w.rl", RiscvAsmToken::ScWRl), ("sc.w.aqrl", RiscvAsmToken::ScWAqrl),
    ("sc.d", RiscvAsmToken::ScD), ("sc.d.aq", RiscvAsmToken::ScDAq),
    ("sc.d.rl", RiscvAsmToken::ScDRl), ("sc.d.aqrl", RiscvAsmToken::ScDAqrl),
];

// ---------------------------------------------------------------------------
// Public lookup functions
// ---------------------------------------------------------------------------

/// Looks up a register by its assembly name and returns the register number.
///
/// Returns `Some(n)` where:
/// - `n` in `0..=31` identifies an integer register (x0-x31)
/// - `n` in `32..=63` identifies a float register (f0-f31, encoded as 32 + register_index)
///
/// Accepts all forms: numeric (`"x0"`-`"x31"`, `"f0"`-`"f31"`) and
/// ABI names (`"zero"`, `"ra"`, `"sp"`, `"a0"`, `"ft0"`, `"fa7"`, etc.).
///
/// Returns `None` for unknown names or `"pc"` (not a real GPR/FPR).
pub fn lookup_register(name: &str) -> Option<u8> {
    // Empty string is not a register
    if name.is_empty() {
        return None;
    }

    // Fast path: numeric integer register x0-x31
    if let Some(rest) = name.strip_prefix('x') {
        return rest.parse::<u8>().ok().filter(|&n| n <= 31);
    }

    // Numeric float register f0-f31 — match "f" + digits only (not "ft0", "fa0", "fs0")
    if name.starts_with('f') && name.len() >= 2 {
        let rest = &name[1..];
        if rest.as_bytes()[0].is_ascii_digit() {
            return rest.parse::<u8>().ok().filter(|&n| n <= 31).map(|n| 32 + n);
        }
    }

    // ABI integer register names (zero, ra, sp, gp, tp, t0-t6, s0-s11, a0-a7, fp)
    for &(abi_name, reg_num) in RISCV_ABI_INT_NAMES {
        if name == abi_name {
            return Some(reg_num);
        }
    }

    // ABI float register names (ft0-ft11, fs0-fs11, fa0-fa7) → 32 + index
    for &(abi_name, reg_num) in RISCV_ABI_FLOAT_NAMES {
        if name == abi_name {
            return Some(32 + reg_num);
        }
    }

    None
}

/// Looks up an instruction mnemonic and returns the corresponding `RiscvAsmToken`.
///
/// Searches the `RISCV_INSTRUCTIONS` table for an exact string match.
/// This covers all instruction mnemonics, CSR names, pseudo-instructions,
/// .option values, and atomic/fence tokens.
///
/// Returns `None` for register names (use [`lookup_register`] instead)
/// or unknown mnemonics.
pub fn lookup_instruction(name: &str) -> Option<RiscvAsmToken> {
    for &(mnemonic, token) in RISCV_INSTRUCTIONS {
        if mnemonic == name {
            return Some(token);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_integer_register_contiguous() {
        // x0-x31 must be contiguous starting at discriminant 0
        assert_eq!(RiscvAsmToken::X0 as i32, 0);
        assert_eq!(RiscvAsmToken::X31 as i32, 31);
        for i in 0..32 {
            let tok = RiscvAsmToken::from_i32(i).unwrap();
            assert!(tok.is_int_register(), "x{} should be int register", i);
            assert!(!tok.is_float_register(), "x{} should not be float register", i);
        }
    }

    #[test]
    fn test_float_register_contiguous() {
        // f0-f31 must be contiguous immediately after x-registers
        assert_eq!(RiscvAsmToken::F0 as i32, 32);
        assert_eq!(RiscvAsmToken::F31 as i32, 63);
        for i in 32..64 {
            let tok = RiscvAsmToken::from_i32(i).unwrap();
            assert!(tok.is_float_register(), "f{} should be float register", i - 32);
            assert!(!tok.is_int_register(), "f{} should not be int register", i - 32);
        }
    }

    #[test]
    fn test_abi_int_names_contiguous() {
        // ABI integer names must follow float registers
        assert_eq!(RiscvAsmToken::Zero as i32, 64);
        assert_eq!(RiscvAsmToken::T6 as i32, 95);
        // All ABI int names should report as int registers
        for i in 64..=95 {
            let tok = RiscvAsmToken::from_i32(i).unwrap();
            assert!(tok.is_int_register(), "{} should be int register", tok);
        }
    }

    #[test]
    fn test_abi_float_names_contiguous() {
        // ABI float names must follow ABI integer names
        assert_eq!(RiscvAsmToken::Ft0 as i32, 96);
        assert_eq!(RiscvAsmToken::Ft11 as i32, 127);
        // All ABI float names should report as float registers
        for i in 96..=127 {
            let tok = RiscvAsmToken::from_i32(i).unwrap();
            assert!(tok.is_float_register(), "{} should be float register", tok);
        }
    }

    #[test]
    fn test_pc_follows_abi_float() {
        assert_eq!(RiscvAsmToken::Pc as i32, RiscvAsmToken::Ft11 as i32 + 1);
        assert_eq!(RiscvAsmToken::Pc as i32, 128);
    }

    #[test]
    fn test_as_str_registers() {
        assert_eq!(RiscvAsmToken::X0.as_str(), "x0");
        assert_eq!(RiscvAsmToken::X15.as_str(), "x15");
        assert_eq!(RiscvAsmToken::X31.as_str(), "x31");
        assert_eq!(RiscvAsmToken::F0.as_str(), "f0");
        assert_eq!(RiscvAsmToken::F31.as_str(), "f31");
        assert_eq!(RiscvAsmToken::Zero.as_str(), "zero");
        assert_eq!(RiscvAsmToken::Ra.as_str(), "ra");
        assert_eq!(RiscvAsmToken::Sp.as_str(), "sp");
        assert_eq!(RiscvAsmToken::A7.as_str(), "a7");
        assert_eq!(RiscvAsmToken::S11.as_str(), "s11");
        assert_eq!(RiscvAsmToken::Ft0.as_str(), "ft0");
        assert_eq!(RiscvAsmToken::Fa7.as_str(), "fa7");
        assert_eq!(RiscvAsmToken::Fs11.as_str(), "fs11");
        assert_eq!(RiscvAsmToken::Ft11.as_str(), "ft11");
        assert_eq!(RiscvAsmToken::Pc.as_str(), "pc");
    }

    #[test]
    fn test_as_str_instructions() {
        assert_eq!(RiscvAsmToken::Lb.as_str(), "lb");
        assert_eq!(RiscvAsmToken::Add.as_str(), "add");
        assert_eq!(RiscvAsmToken::FenceI.as_str(), "fence.i");
        assert_eq!(RiscvAsmToken::Mul.as_str(), "mul");
        assert_eq!(RiscvAsmToken::FsgnjS.as_str(), "fsgnj.s");
        assert_eq!(RiscvAsmToken::FsgnjD.as_str(), "fsgnj.d");
        assert_eq!(RiscvAsmToken::CNop.as_str(), "c.nop");
        assert_eq!(RiscvAsmToken::CAddi16sp.as_str(), "c.addi16sp");
        assert_eq!(RiscvAsmToken::LrWAqrl.as_str(), "lr.w.aqrl");
        assert_eq!(RiscvAsmToken::ScDAq.as_str(), "sc.d.aq");
        assert_eq!(RiscvAsmToken::SextW.as_str(), "sext.w");
        assert_eq!(RiscvAsmToken::FabsD.as_str(), "fabs.d");
        assert_eq!(RiscvAsmToken::FmvS.as_str(), "fmv.s");
    }

    #[test]
    fn test_as_str_pseudo_fld_flw() {
        // fld/flw pseudo-instructions should return the plain name
        assert_eq!(RiscvAsmToken::Fld_pseudo.as_str(), "fld");
        assert_eq!(RiscvAsmToken::Flw_pseudo.as_str(), "flw");
        assert_eq!(RiscvAsmToken::Fsd_pseudo.as_str(), "fsd");
        assert_eq!(RiscvAsmToken::Fsw_pseudo.as_str(), "fsw");
    }

    #[test]
    fn test_display_trait() {
        let tok = RiscvAsmToken::Add;
        assert_eq!(format!("{}", tok), "add");
        let tok2 = RiscvAsmToken::FsgnjD;
        assert_eq!(format!("{}", tok2), "fsgnj.d");
        let tok3 = RiscvAsmToken::IorwFence;
        assert_eq!(format!("{}", tok3), "iorw");
    }

    #[test]
    fn test_from_i32_valid() {
        assert_eq!(RiscvAsmToken::from_i32(0), Some(RiscvAsmToken::X0));
        assert_eq!(RiscvAsmToken::from_i32(31), Some(RiscvAsmToken::X31));
        assert_eq!(RiscvAsmToken::from_i32(32), Some(RiscvAsmToken::F0));
        let last = RiscvAsmToken::IorwFence as i32;
        assert_eq!(RiscvAsmToken::from_i32(last), Some(RiscvAsmToken::IorwFence));
    }

    #[test]
    fn test_from_i32_invalid() {
        assert_eq!(RiscvAsmToken::from_i32(-1), None);
        assert_eq!(RiscvAsmToken::from_i32(-100), None);
        let beyond = RiscvAsmToken::IorwFence as i32 + 1;
        assert_eq!(RiscvAsmToken::from_i32(beyond), None);
        assert_eq!(RiscvAsmToken::from_i32(i32::MAX), None);
        assert_eq!(RiscvAsmToken::from_i32(i32::MIN), None);
    }

    #[test]
    fn test_from_i32_roundtrip() {
        // Every variant should roundtrip: tok as i32 -> from_i32 -> same tok
        for i in 0..TOKEN_COUNT as i32 {
            let tok = RiscvAsmToken::from_i32(i).unwrap();
            assert_eq!(tok as i32, i, "roundtrip failed for discriminant {}", i);
        }
    }

    #[test]
    fn test_lookup_register_numeric_int() {
        assert_eq!(lookup_register("x0"), Some(0));
        assert_eq!(lookup_register("x1"), Some(1));
        assert_eq!(lookup_register("x15"), Some(15));
        assert_eq!(lookup_register("x31"), Some(31));
        assert_eq!(lookup_register("x32"), None);
        assert_eq!(lookup_register("x256"), None);
    }

    #[test]
    fn test_lookup_register_numeric_float() {
        assert_eq!(lookup_register("f0"), Some(32));
        assert_eq!(lookup_register("f1"), Some(33));
        assert_eq!(lookup_register("f15"), Some(47));
        assert_eq!(lookup_register("f31"), Some(63));
        assert_eq!(lookup_register("f32"), None);
    }

    #[test]
    fn test_lookup_register_abi_int() {
        assert_eq!(lookup_register("zero"), Some(0));
        assert_eq!(lookup_register("ra"), Some(1));
        assert_eq!(lookup_register("sp"), Some(2));
        assert_eq!(lookup_register("gp"), Some(3));
        assert_eq!(lookup_register("tp"), Some(4));
        assert_eq!(lookup_register("t0"), Some(5));
        assert_eq!(lookup_register("t2"), Some(7));
        assert_eq!(lookup_register("s0"), Some(8));
        assert_eq!(lookup_register("fp"), Some(8)); // fp alias for s0
        assert_eq!(lookup_register("s1"), Some(9));
        assert_eq!(lookup_register("a0"), Some(10));
        assert_eq!(lookup_register("a7"), Some(17));
        assert_eq!(lookup_register("s2"), Some(18));
        assert_eq!(lookup_register("s11"), Some(27));
        assert_eq!(lookup_register("t3"), Some(28));
        assert_eq!(lookup_register("t6"), Some(31));
    }

    #[test]
    fn test_lookup_register_abi_float() {
        assert_eq!(lookup_register("ft0"), Some(32));
        assert_eq!(lookup_register("ft7"), Some(39));
        assert_eq!(lookup_register("fs0"), Some(40));
        assert_eq!(lookup_register("fs1"), Some(41));
        assert_eq!(lookup_register("fa0"), Some(42));
        assert_eq!(lookup_register("fa7"), Some(49));
        assert_eq!(lookup_register("fs2"), Some(50));
        assert_eq!(lookup_register("fs11"), Some(59));
        assert_eq!(lookup_register("ft8"), Some(60));
        assert_eq!(lookup_register("ft11"), Some(63));
    }

    #[test]
    fn test_lookup_register_unknown() {
        assert_eq!(lookup_register("pc"), None);
        assert_eq!(lookup_register("add"), None);
        assert_eq!(lookup_register(""), None);
        assert_eq!(lookup_register("xyz"), None);
        assert_eq!(lookup_register("x"), None);
        assert_eq!(lookup_register("f"), None);
    }

    #[test]
    fn test_lookup_instruction_basic() {
        assert_eq!(lookup_instruction("add"), Some(RiscvAsmToken::Add));
        assert_eq!(lookup_instruction("sub"), Some(RiscvAsmToken::Sub));
        assert_eq!(lookup_instruction("lb"), Some(RiscvAsmToken::Lb));
        assert_eq!(lookup_instruction("sd"), Some(RiscvAsmToken::Sd));
        assert_eq!(lookup_instruction("beq"), Some(RiscvAsmToken::Beq));
        assert_eq!(lookup_instruction("jal"), Some(RiscvAsmToken::Jal));
    }

    #[test]
    fn test_lookup_instruction_dotted() {
        assert_eq!(lookup_instruction("fence.i"), Some(RiscvAsmToken::FenceI));
        assert_eq!(lookup_instruction("fsgnj.s"), Some(RiscvAsmToken::FsgnjS));
        assert_eq!(lookup_instruction("c.nop"), Some(RiscvAsmToken::CNop));
        assert_eq!(lookup_instruction("lr.w.aqrl"), Some(RiscvAsmToken::LrWAqrl));
        assert_eq!(lookup_instruction("sext.w"), Some(RiscvAsmToken::SextW));
        assert_eq!(lookup_instruction("fabs.d"), Some(RiscvAsmToken::FabsD));
    }

    #[test]
    fn test_lookup_instruction_csr() {
        assert_eq!(lookup_instruction("csrrw"), Some(RiscvAsmToken::Csrrw));
        assert_eq!(lookup_instruction("csrrs"), Some(RiscvAsmToken::Csrrs));
        assert_eq!(lookup_instruction("csrrc"), Some(RiscvAsmToken::Csrrc));
        assert_eq!(lookup_instruction("csrs"), Some(RiscvAsmToken::CsrsPseudo));
        assert_eq!(lookup_instruction("csrw"), Some(RiscvAsmToken::Csrw));
        assert_eq!(lookup_instruction("cycle"), Some(RiscvAsmToken::Cycle));
        assert_eq!(lookup_instruction("frcsr"), Some(RiscvAsmToken::Frcsr));
    }

    #[test]
    fn test_lookup_instruction_pseudos() {
        assert_eq!(lookup_instruction("nop"), Some(RiscvAsmToken::Nop));
        assert_eq!(lookup_instruction("ret"), Some(RiscvAsmToken::Ret));
        assert_eq!(lookup_instruction("mv"), Some(RiscvAsmToken::Mv));
        assert_eq!(lookup_instruction("li"), Some(RiscvAsmToken::Li));
        assert_eq!(lookup_instruction("la"), Some(RiscvAsmToken::La));
        assert_eq!(lookup_instruction("call"), Some(RiscvAsmToken::Call));
        assert_eq!(lookup_instruction("tail"), Some(RiscvAsmToken::Tail));
        assert_eq!(lookup_instruction("j"), Some(RiscvAsmToken::J));
        assert_eq!(lookup_instruction("jr"), Some(RiscvAsmToken::Jr));
    }

    #[test]
    fn test_lookup_instruction_option_values() {
        assert_eq!(lookup_instruction("rvc"), Some(RiscvAsmToken::Rvc));
        assert_eq!(lookup_instruction("norvc"), Some(RiscvAsmToken::Norvc));
        assert_eq!(lookup_instruction("relax"), Some(RiscvAsmToken::Relax));
        assert_eq!(lookup_instruction("norelax"), Some(RiscvAsmToken::Norelax));
    }

    #[test]
    fn test_lookup_instruction_unknown() {
        assert_eq!(lookup_instruction("x0"), None); // register, not instruction
        assert_eq!(lookup_instruction(""), None);
        assert_eq!(lookup_instruction("notreal"), None);
    }

    #[test]
    fn test_token_names_array_length() {
        assert_eq!(TOKEN_NAMES.len(), TOKEN_COUNT);
    }

    #[test]
    fn test_csr_pseudo_disambiguation() {
        // csrrs (Zicsr instruction) vs csrs (pseudo-instruction) are distinct
        assert_ne!(RiscvAsmToken::Csrrs, RiscvAsmToken::CsrsPseudo);
        assert_eq!(RiscvAsmToken::Csrrs.as_str(), "csrrs");
        assert_eq!(RiscvAsmToken::CsrsPseudo.as_str(), "csrs");
    }

    #[test]
    fn test_fence_operand_strings() {
        assert_eq!(RiscvAsmToken::WFence.as_str(), "w");
        assert_eq!(RiscvAsmToken::RFence.as_str(), "r");
        assert_eq!(RiscvAsmToken::RwFence.as_str(), "rw");
        assert_eq!(RiscvAsmToken::OFence.as_str(), "o");
        assert_eq!(RiscvAsmToken::OrFence.as_str(), "or");
        assert_eq!(RiscvAsmToken::OrwFence.as_str(), "orw");
        assert_eq!(RiscvAsmToken::IFence.as_str(), "i");
        assert_eq!(RiscvAsmToken::IrwFence.as_str(), "irw");
        assert_eq!(RiscvAsmToken::IorwFence.as_str(), "iorw");
    }

    #[test]
    fn test_abi_int_names_register_numbers() {
        for &(name, reg) in RISCV_ABI_INT_NAMES {
            assert!(reg <= 31, "ABI int name '{}' has out-of-range reg {}", name, reg);
            assert_eq!(lookup_register(name), Some(reg),
                "ABI int name '{}' should map to register {}", name, reg);
        }
    }

    #[test]
    fn test_abi_float_names_register_numbers() {
        for &(name, reg) in RISCV_ABI_FLOAT_NAMES {
            assert!(reg <= 31, "ABI float name '{}' has out-of-range reg {}", name, reg);
            assert_eq!(lookup_register(name), Some(32 + reg),
                "ABI float name '{}' should map to register {}", name, 32 + reg);
        }
    }

    #[test]
    fn test_riscv_int_regs_array() {
        assert_eq!(RISCV_INT_REGS.len(), 32);
        for (i, name) in RISCV_INT_REGS.iter().enumerate() {
            assert_eq!(*name, format!("x{}", i));
        }
    }

    #[test]
    fn test_riscv_float_regs_array() {
        assert_eq!(RISCV_FLOAT_REGS.len(), 32);
        for (i, name) in RISCV_FLOAT_REGS.iter().enumerate() {
            assert_eq!(*name, format!("f{}", i));
        }
    }

    #[test]
    fn test_instruction_range_checks_for_assembler() {
        // The assembler relies on these sequential ranges for classification
        // Verify critical boundaries that asm_parse_regvar() depends on

        // x0-x31 then f0-f31 (no gap)
        assert_eq!(RiscvAsmToken::X31 as i32 + 1, RiscvAsmToken::F0 as i32);
        // f0-f31 then ABI int names (no gap)
        assert_eq!(RiscvAsmToken::F31 as i32 + 1, RiscvAsmToken::Zero as i32);
        // ABI int names then ABI float names (no gap)
        assert_eq!(RiscvAsmToken::T6 as i32 + 1, RiscvAsmToken::Ft0 as i32);
        // ABI float names then pc (no gap)
        assert_eq!(RiscvAsmToken::Ft11 as i32 + 1, RiscvAsmToken::Pc as i32);
        // pc then first instruction (no gap)
        assert_eq!(RiscvAsmToken::Pc as i32 + 1, RiscvAsmToken::Lb as i32);
    }

    #[test]
    fn test_all_instruction_entries_are_valid_lookups() {
        // Every entry in RISCV_INSTRUCTIONS should be found by lookup_instruction
        for &(name, expected_tok) in RISCV_INSTRUCTIONS {
            let found = lookup_instruction(name);
            assert_eq!(found, Some(expected_tok),
                "lookup_instruction('{}') should return {:?}", name, expected_tok);
        }
    }

    #[test]
    fn test_total_token_count() {
        // Verify total matches expected count:
        // 32 int regs + 32 float regs + 32 ABI int + 32 ABI float + 1 pc
        // + instructions + extensions + pseudos + atomics + fence operands
        assert!(TOKEN_COUNT > 300, "Should have 300+ tokens, got {}", TOKEN_COUNT);
        assert!(TOKEN_COUNT < 400, "Token count {} seems too high", TOKEN_COUNT);
    }
}
