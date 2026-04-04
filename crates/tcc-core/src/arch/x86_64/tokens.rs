//! x86_64 assembly token definitions, register set, and instruction opcode tables.
//!
//! This is the Rust port of `x86_64-asm.h` (559 lines) combined with relevant
//! definitions from `i386-asm.h`, `i386-tok.h`, and `i386-asm.c`. It defines the
//! x86_64-specific assembly instruction mnemonics, operand types, the extended
//! 64-bit register set, and the complete opcode table as Rust enums, constants,
//! and static lookup tables — replacing the C macro-based `DEF_ASM_OP*` system.
//!
//! # Key x86_64 vs i386 differences
//!
//! - `NBWLX = 5`: OPC_BWLX generates b/w/l/q suffixes (i386 has NBWLX=4, no q)
//! - Extended registers: r8–r15, r8d–r15d, r8w–r15w, r8b–r15b, xmm8–xmm15
//! - RIP-relative addressing is the default memory operand mode
//! - 64-bit push/pop only (pushq/popq), no 32-bit push/pop
//! - `movsxd`/`movslq`: 32→64 sign extension (absent on i386)
//! - `cqto`: quad-word to octo-word sign extension
//! - `iretq`: 64-bit interrupt return
//! - `syscall`/`sysret`/`sysretq` system call instructions
//! - `endbr64`: CET indirect-branch tracking

// ---------------------------------------------------------------------------
// Operand count classification
// ---------------------------------------------------------------------------

/// Classification for the number of operands an assembly instruction accepts.
/// Maps directly to the C `DEF_ASM_OP0`/`OP0L`/`OP1`/`OP2`/`OP3` macro family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AsmOpCount {
    /// Zero operands — simple opcode (e.g., `clc`, `nop`, `ret`).
    Op0,
    /// Zero operands with extended modifier flags (e.g., segment overrides).
    Op0L,
    /// Single operand (e.g., `push`, `inc`, `jmp`).
    Op1,
    /// Two operands (e.g., `mov`, `add`, `cmp`).
    Op2,
    /// Three operands (e.g., `shld`, `imul` 3-operand form).
    Op3,
}

// ---------------------------------------------------------------------------
// Register metadata types
// ---------------------------------------------------------------------------

/// Functional class of a CPU register.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RegisterClass {
    /// General-purpose register (rax…r15, eax…r15d, ax…r15w, al…r15b).
    Gpr,
    /// SSE vector register (xmm0–xmm15).
    Sse,
    /// x87 floating-point stack register (st0–st7).
    X87,
    /// MMX register (mm0–mm7).
    Mmx,
    /// Segment register (es, cs, ss, ds, fs, gs).
    Segment,
    /// Control register (cr0–cr7).
    Control,
    /// Debug register (dr0–dr7).
    Debug,
}

/// Bit-width of a register.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RegisterWidth {
    /// 8-bit (al, cl, etc.).
    Bit8,
    /// 16-bit (ax, cx, etc.).
    Bit16,
    /// 32-bit (eax, ecx, cr0, dr0, etc.).
    Bit32,
    /// 64-bit (rax, rcx, r8, etc.).
    Bit64,
    /// 128-bit (xmm0–xmm15).
    Bit128,
    /// 80-bit extended precision (st0–st7).
    Bit80,
}

// ---------------------------------------------------------------------------
// Assembly instruction definition struct
// ---------------------------------------------------------------------------

/// A single x86_64 assembly instruction definition.
///
/// Each instance corresponds to one `DEF_ASM_OP*` macro invocation in
/// `x86_64-asm.h`. The opcode field stores the *raw* opcode as it appears in
/// the C header; the `flags` field includes `OPC_0F` when the opcode has a
/// `0x0F` prefix byte (matching the C `T()` macro transformation).
#[derive(Debug, Clone, Copy)]
pub struct AsmOpDef {
    /// Instruction mnemonic (lowercase), e.g. `"clc"`, `"movq"`, `"addl"`.
    pub name: &'static str,
    /// Base opcode value. Multi-byte opcodes are stored as a single `u32`
    /// with the most-significant bytes in higher positions.
    /// When the opcode originally had a `0x0F` second byte, that byte is
    /// stripped here and tracked via `OPC_0F` in `flags` (matching the C
    /// `O()` macro).
    pub opcode: u32,
    /// ModRM extension group (`/digit`); 0 if none.
    pub group: u8,
    /// Instruction flags (OPC_MODRM, OPC_BWLX, OPC_ARITH, etc.) combined
    /// with `OPC_0F` when applicable.
    pub flags: u32,
    /// Operand count classification.
    pub op_count: AsmOpCount,
    /// Operand type constraints (up to 3 operands). Unused slots are 0.
    pub operands: [u32; 3],
    /// `true` when this entry is an alternative encoding for the same
    /// mnemonic (`ALT(...)` in the C source).
    pub is_alt: bool,
}

/// Static metadata for a single CPU register.
#[derive(Debug, Clone, Copy)]
pub struct RegisterDef {
    /// Lowercase register name, e.g. `"rax"`, `"xmm0"`, `"cr3"`.
    pub name: &'static str,
    /// Hardware encoding (0–15 for GPRs/SSE/MMX, 0–7 for others).
    pub encoding: u8,
    /// Functional class.
    pub class: RegisterClass,
    /// Bit-width.
    pub width: RegisterWidth,
}

// ---------------------------------------------------------------------------
// Opcode flag constants (from tcc.h / i386-asm.c, x86_64 variant)
// ---------------------------------------------------------------------------

/// Byte suffix support — only meaningful combined with `OPC_WL`.
pub const OPC_B: u32 = 0x01;
/// Word/Long suffix support (w, l).
pub const OPC_WL: u32 = 0x02;
/// Byte/Word/Long suffix support (b, w, l).
pub const OPC_BWL: u32 = OPC_B | OPC_WL;
/// Register encoded in low 3 bits of opcode byte.
pub const OPC_REG: u32 = 0x04;
/// Instruction requires a ModR/M byte.
pub const OPC_MODRM: u32 = 0x08;
/// Mask for the instruction-type sub-field (bits 4–6).
pub const OPCT_MASK: u32 = 0x70;
/// Emit `FWAIT` (0x9B) prefix before the opcode.
pub const OPC_FWAIT: u32 = 0x10;
/// Shift-family instruction (CL / imm8 operand variants).
pub const OPC_SHIFT: u32 = 0x20;
/// Arithmetic instruction family (add, or, adc, sbb, and, sub, xor, cmp).
pub const OPC_ARITH: u32 = 0x30;
/// FPU arithmetic instruction family (fadd, fmul, etc.).
pub const OPC_FARITH: u32 = 0x40;
/// TEST instruction family.
pub const OPC_TEST: u32 = 0x50;
/// `0F 01` prefix group (VMX, system instructions).
pub const OPC_0F01: u32 = 0x60;
/// Secondary opcode map — the `0x0F` prefix byte.
pub const OPC_0F: u32 = 0x100;
/// REX.W prefix (`0x48`) — forces 64-bit operand size.
pub const OPC_48: u32 = 0x200;
/// Word/Long/Quad suffix support (w, l, q) — x86_64 extension.
pub const OPC_WLQ: u32 = 0x1000;
/// Byte/Word/Long/Quad suffix support (b, w, l, q) — x86_64 extension.
pub const OPC_BWLQ: u32 = OPC_B | OPC_WLQ;
/// Alias for `OPC_WLQ` (platform-independent name).
pub const OPC_WLX: u32 = OPC_WLQ;
/// Alias for `OPC_BWLQ` (platform-independent name).
pub const OPC_BWLX: u32 = OPC_BWLQ;
/// Number of bits needed to encode the group in `flags`.
pub const OPC_GROUP_SHIFT: u32 = 13;
/// Number of byte/word/long/quad suffix variants on x86_64.
pub const NBWLX: u32 = 5;

// ---------------------------------------------------------------------------
// Operand type indices (enum values from i386-asm.c)
// ---------------------------------------------------------------------------

/// 8-bit general-purpose register operand.
pub const OPT_REG8: u32 = 0;
/// 16-bit general-purpose register operand.
pub const OPT_REG16: u32 = 1;
/// 32-bit general-purpose register operand.
pub const OPT_REG32: u32 = 2;
/// 64-bit general-purpose register operand (x86_64 only).
pub const OPT_REG64: u32 = 3;
/// MMX register operand (mm0–mm7).
pub const OPT_MMX: u32 = 4;
/// SSE register operand (xmm0–xmm15).
pub const OPT_SSE: u32 = 5;
/// Control register operand (cr0–cr7).
pub const OPT_CR: u32 = 6;
/// Test register operand (tr0–tr7).
pub const OPT_TR: u32 = 7;
/// Debug register operand (dr0–dr7).
pub const OPT_DB: u32 = 8;
/// Segment register operand (es, cs, ss, ds, fs, gs).
pub const OPT_SEG: u32 = 9;
/// x87 FPU stack register operand (st(i)).
pub const OPT_ST: u32 = 10;
/// 8-bit low register operand requiring REX prefix (spl, bpl, sil, dil).
pub const OPT_REG8_LOW: u32 = 11;
/// 8-bit unsigned immediate operand.
pub const OPT_IM8: u32 = 12;
/// 8-bit signed immediate operand.
pub const OPT_IM8S: u32 = 13;
/// 16-bit immediate operand.
pub const OPT_IM16: u32 = 14;
/// 32-bit immediate operand.
pub const OPT_IM32: u32 = 15;
/// 64-bit immediate operand (x86_64 only, used with `movabs`).
pub const OPT_IM64: u32 = 16;
/// EAX/RAX register (implicit accumulator operand).
pub const OPT_EAX: u32 = 17;
/// ST(0) — top of x87 FPU stack (implicit operand).
pub const OPT_ST0: u32 = 18;
/// CL register (implicit shift count operand).
pub const OPT_CL: u32 = 19;
/// DX register (implicit I/O port operand).
pub const OPT_DX: u32 = 20;
/// Absolute address operand.
pub const OPT_ADDR: u32 = 21;
/// Indirect (memory-indirect) operand `*operand`.
pub const OPT_INDIR: u32 = 22;
/// Any immediate operand (composite).
pub const OPT_IM: u32 = 23;
/// Any general-purpose register (composite).
pub const OPT_REG: u32 = 24;
/// Word-or-wider general-purpose register (16/32/64).
pub const OPT_REGW: u32 = 25;
/// Word-or-wider immediate (composite).
pub const OPT_IMW: u32 = 26;
/// MMX or SSE register (composite).
pub const OPT_MMXSSE: u32 = 27;
/// Displacement operand (for jmp/call relative targets).
pub const OPT_DISP: u32 = 28;
/// 8-bit displacement operand.
pub const OPT_DISP8: u32 = 29;
/// Effective address — memory operand flag (set in high bit).
pub const OPT_EA: u32 = 0x80;

// ---------------------------------------------------------------------------
// Operand type bit-mask constants (OP_*)
//
// Each OP_xxx = 1 << OPT_xxx, used in AsmOpDef.operands[] to express which
// operand types are accepted for a given operand slot.
// ---------------------------------------------------------------------------

/// 8-bit register accepted.
pub const OP_REG8: u32 = 1 << OPT_REG8;
/// 16-bit register accepted.
pub const OP_REG16: u32 = 1 << OPT_REG16;
/// 32-bit register accepted.
pub const OP_REG32: u32 = 1 << OPT_REG32;
/// 64-bit register accepted (x86_64 only).
pub const OP_REG64: u32 = 1 << OPT_REG64;
/// MMX register accepted.
pub const OP_MMX: u32 = 1 << OPT_MMX;
/// SSE register accepted.
pub const OP_SSE: u32 = 1 << OPT_SSE;
/// Control register accepted.
pub const OP_CR: u32 = 1 << OPT_CR;
/// Test register accepted.
pub const OP_TR: u32 = 1 << OPT_TR;
/// Debug register accepted.
pub const OP_DB: u32 = 1 << OPT_DB;
/// Segment register accepted.
pub const OP_SEG: u32 = 1 << OPT_SEG;
/// x87 FPU register accepted.
pub const OP_ST: u32 = 1 << OPT_ST;
/// 8-bit low register requiring REX prefix accepted (x86_64).
pub const OP_REG8_LOW: u32 = 1 << OPT_REG8_LOW;
/// 8-bit unsigned immediate accepted.
pub const OP_IM8: u32 = 1 << OPT_IM8;
/// 8-bit signed immediate accepted.
pub const OP_IM8S: u32 = 1 << OPT_IM8S;
/// 16-bit immediate accepted.
pub const OP_IM16: u32 = 1 << OPT_IM16;
/// 32-bit immediate accepted.
pub const OP_IM32: u32 = 1 << OPT_IM32;
/// 64-bit immediate accepted (x86_64, for `movabs`).
pub const OP_IM64: u32 = 1 << OPT_IM64;
/// Implicit EAX/RAX accepted.
pub const OP_EAX: u32 = 1 << OPT_EAX;
/// Implicit ST(0) accepted.
pub const OP_ST0: u32 = 1 << OPT_ST0;
/// Implicit CL accepted.
pub const OP_CL: u32 = 1 << OPT_CL;
/// Implicit DX accepted.
pub const OP_DX: u32 = 1 << OPT_DX;
/// Absolute address accepted.
pub const OP_ADDR: u32 = 1 << OPT_ADDR;
/// Indirect (memory-indirect) operand accepted.
pub const OP_INDIR: u32 = 1 << OPT_INDIR;
/// Effective address (memory) operand.
pub const OP_EA: u32 = 0x4000_0000;
/// 32-bit effective address with address-size override (x86_64).
pub const OP_EA32: u32 = OP_EA << 1;
/// Any general-purpose register (8|16|32|64).
pub const OP_REG: u32 = OP_REG8 | OP_REG16 | OP_REG32 | OP_REG64;

/// Maximum number of operands per instruction.
pub const MAX_OPERANDS: usize = 3;

// ---------------------------------------------------------------------------
// X86Register — complete x86_64 register set
// ---------------------------------------------------------------------------

/// Complete x86_64 register set.
///
/// Extends the i386 register file with 64-bit GPRs (`rax`–`r15`), extended
/// 32/16/8-bit variants (`r8d`–`r15d`, `r8w`–`r15w`, `r8b`–`r15b`), REX
/// low-byte registers (`spl`, `bpl`, `sil`, `dil`), and SSE registers
/// `xmm8`–`xmm15`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum X86Register {
    // 64-bit general-purpose registers
    Rax, Rcx, Rdx, Rbx, Rsp, Rbp, Rsi, Rdi,
    R8, R9, R10, R11, R12, R13, R14, R15,
    // 32-bit general-purpose registers
    Eax, Ecx, Edx, Ebx, Esp, Ebp, Esi, Edi,
    R8d, R9d, R10d, R11d, R12d, R13d, R14d, R15d,
    // 16-bit general-purpose registers
    Ax, Cx, Dx, Bx, Sp, Bp, Si, Di,
    R8w, R9w, R10w, R11w, R12w, R13w, R14w, R15w,
    // 8-bit low registers (legacy)
    Al, Cl, Dl, Bl,
    // 8-bit high registers (legacy, no REX)
    Ah, Ch, Dh, Bh,
    // 8-bit low registers requiring REX prefix (x86_64 only)
    Spl, Bpl, Sil, Dil,
    // 8-bit extended registers (x86_64 only)
    R8b, R9b, R10b, R11b, R12b, R13b, R14b, R15b,
    // SSE registers (xmm0–xmm15)
    Xmm0, Xmm1, Xmm2, Xmm3, Xmm4, Xmm5, Xmm6, Xmm7,
    Xmm8, Xmm9, Xmm10, Xmm11, Xmm12, Xmm13, Xmm14, Xmm15,
    // MMX registers (mm0–mm7)
    Mm0, Mm1, Mm2, Mm3, Mm4, Mm5, Mm6, Mm7,
    // x87 FPU stack registers (st0–st7)
    St0, St1, St2, St3, St4, St5, St6, St7,
    // Segment registers
    Es, Cs, Ss, Ds, Fs, Gs,
    // Control registers (cr0–cr7)
    Cr0, Cr1, Cr2, Cr3, Cr4, Cr5, Cr6, Cr7,
    // Debug registers (dr0–dr7)
    Dr0, Dr1, Dr2, Dr3, Dr4, Dr5, Dr6, Dr7,
    // Instruction pointer (RIP-relative addressing)
    Rip,
}

impl X86Register {
    /// Returns the lowercase assembly name of this register (e.g. `"rax"`).
    pub fn name(self) -> &'static str {
        match self {
            Self::Rax => "rax", Self::Rcx => "rcx", Self::Rdx => "rdx", Self::Rbx => "rbx",
            Self::Rsp => "rsp", Self::Rbp => "rbp", Self::Rsi => "rsi", Self::Rdi => "rdi",
            Self::R8 => "r8", Self::R9 => "r9", Self::R10 => "r10", Self::R11 => "r11",
            Self::R12 => "r12", Self::R13 => "r13", Self::R14 => "r14", Self::R15 => "r15",
            Self::Eax => "eax", Self::Ecx => "ecx", Self::Edx => "edx", Self::Ebx => "ebx",
            Self::Esp => "esp", Self::Ebp => "ebp", Self::Esi => "esi", Self::Edi => "edi",
            Self::R8d => "r8d", Self::R9d => "r9d", Self::R10d => "r10d", Self::R11d => "r11d",
            Self::R12d => "r12d", Self::R13d => "r13d", Self::R14d => "r14d", Self::R15d => "r15d",
            Self::Ax => "ax", Self::Cx => "cx", Self::Dx => "dx", Self::Bx => "bx",
            Self::Sp => "sp", Self::Bp => "bp", Self::Si => "si", Self::Di => "di",
            Self::R8w => "r8w", Self::R9w => "r9w", Self::R10w => "r10w", Self::R11w => "r11w",
            Self::R12w => "r12w", Self::R13w => "r13w", Self::R14w => "r14w", Self::R15w => "r15w",
            Self::Al => "al", Self::Cl => "cl", Self::Dl => "dl", Self::Bl => "bl",
            Self::Ah => "ah", Self::Ch => "ch", Self::Dh => "dh", Self::Bh => "bh",
            Self::Spl => "spl", Self::Bpl => "bpl", Self::Sil => "sil", Self::Dil => "dil",
            Self::R8b => "r8b", Self::R9b => "r9b", Self::R10b => "r10b", Self::R11b => "r11b",
            Self::R12b => "r12b", Self::R13b => "r13b", Self::R14b => "r14b", Self::R15b => "r15b",
            Self::Xmm0 => "xmm0", Self::Xmm1 => "xmm1", Self::Xmm2 => "xmm2", Self::Xmm3 => "xmm3",
            Self::Xmm4 => "xmm4", Self::Xmm5 => "xmm5", Self::Xmm6 => "xmm6", Self::Xmm7 => "xmm7",
            Self::Xmm8 => "xmm8", Self::Xmm9 => "xmm9", Self::Xmm10 => "xmm10", Self::Xmm11 => "xmm11",
            Self::Xmm12 => "xmm12", Self::Xmm13 => "xmm13", Self::Xmm14 => "xmm14", Self::Xmm15 => "xmm15",
            Self::Mm0 => "mm0", Self::Mm1 => "mm1", Self::Mm2 => "mm2", Self::Mm3 => "mm3",
            Self::Mm4 => "mm4", Self::Mm5 => "mm5", Self::Mm6 => "mm6", Self::Mm7 => "mm7",
            Self::St0 => "st0", Self::St1 => "st1", Self::St2 => "st2", Self::St3 => "st3",
            Self::St4 => "st4", Self::St5 => "st5", Self::St6 => "st6", Self::St7 => "st7",
            Self::Es => "es", Self::Cs => "cs", Self::Ss => "ss",
            Self::Ds => "ds", Self::Fs => "fs", Self::Gs => "gs",
            Self::Cr0 => "cr0", Self::Cr1 => "cr1", Self::Cr2 => "cr2", Self::Cr3 => "cr3",
            Self::Cr4 => "cr4", Self::Cr5 => "cr5", Self::Cr6 => "cr6", Self::Cr7 => "cr7",
            Self::Dr0 => "dr0", Self::Dr1 => "dr1", Self::Dr2 => "dr2", Self::Dr3 => "dr3",
            Self::Dr4 => "dr4", Self::Dr5 => "dr5", Self::Dr6 => "dr6", Self::Dr7 => "dr7",
            Self::Rip => "rip",
        }
    }

    /// Returns the hardware encoding (0–15 for GPR/SSE, 0–7 for others).
    pub fn encoding(self) -> u8 {
        match self {
            Self::Rax | Self::Eax | Self::Ax | Self::Al | Self::Xmm0 | Self::Mm0
                | Self::St0 | Self::Es | Self::Cr0 | Self::Dr0 => 0,
            Self::Rcx | Self::Ecx | Self::Cx | Self::Cl | Self::Xmm1 | Self::Mm1
                | Self::St1 | Self::Cs | Self::Cr1 | Self::Dr1 => 1,
            Self::Rdx | Self::Edx | Self::Dx | Self::Dl | Self::Xmm2 | Self::Mm2
                | Self::St2 | Self::Ss | Self::Cr2 | Self::Dr2 => 2,
            Self::Rbx | Self::Ebx | Self::Bx | Self::Bl | Self::Xmm3 | Self::Mm3
                | Self::St3 | Self::Ds | Self::Cr3 | Self::Dr3 => 3,
            Self::Rsp | Self::Esp | Self::Sp | Self::Ah | Self::Spl | Self::Xmm4 | Self::Mm4
                | Self::St4 | Self::Fs | Self::Cr4 | Self::Dr4 => 4,
            Self::Rbp | Self::Ebp | Self::Bp | Self::Ch | Self::Bpl | Self::Xmm5 | Self::Mm5
                | Self::St5 | Self::Gs | Self::Cr5 | Self::Dr5 => 5,
            Self::Rsi | Self::Esi | Self::Si | Self::Dh | Self::Sil | Self::Xmm6 | Self::Mm6
                | Self::St6 | Self::Cr6 | Self::Dr6 => 6,
            Self::Rdi | Self::Edi | Self::Di | Self::Bh | Self::Dil | Self::Xmm7 | Self::Mm7
                | Self::St7 | Self::Cr7 | Self::Dr7 => 7,
            Self::R8 | Self::R8d | Self::R8w | Self::R8b | Self::Xmm8 => 8,
            Self::R9 | Self::R9d | Self::R9w | Self::R9b | Self::Xmm9 => 9,
            Self::R10 | Self::R10d | Self::R10w | Self::R10b | Self::Xmm10 => 10,
            Self::R11 | Self::R11d | Self::R11w | Self::R11b | Self::Xmm11 => 11,
            Self::R12 | Self::R12d | Self::R12w | Self::R12b | Self::Xmm12 => 12,
            Self::R13 | Self::R13d | Self::R13w | Self::R13b | Self::Xmm13 => 13,
            Self::R14 | Self::R14d | Self::R14w | Self::R14b | Self::Xmm14 => 14,
            Self::R15 | Self::R15d | Self::R15w | Self::R15b | Self::Xmm15 => 15,
            Self::Rip => 0,
        }
    }

    /// Returns the functional class of this register.
    pub fn class(self) -> RegisterClass {
        match self {
            Self::Rax | Self::Rcx | Self::Rdx | Self::Rbx
            | Self::Rsp | Self::Rbp | Self::Rsi | Self::Rdi
            | Self::R8 | Self::R9 | Self::R10 | Self::R11
            | Self::R12 | Self::R13 | Self::R14 | Self::R15
            | Self::Eax | Self::Ecx | Self::Edx | Self::Ebx
            | Self::Esp | Self::Ebp | Self::Esi | Self::Edi
            | Self::R8d | Self::R9d | Self::R10d | Self::R11d
            | Self::R12d | Self::R13d | Self::R14d | Self::R15d
            | Self::Ax | Self::Cx | Self::Dx | Self::Bx
            | Self::Sp | Self::Bp | Self::Si | Self::Di
            | Self::R8w | Self::R9w | Self::R10w | Self::R11w
            | Self::R12w | Self::R13w | Self::R14w | Self::R15w
            | Self::Al | Self::Cl | Self::Dl | Self::Bl
            | Self::Ah | Self::Ch | Self::Dh | Self::Bh
            | Self::Spl | Self::Bpl | Self::Sil | Self::Dil
            | Self::R8b | Self::R9b | Self::R10b | Self::R11b
            | Self::R12b | Self::R13b | Self::R14b | Self::R15b
            | Self::Rip => RegisterClass::Gpr,
            Self::Xmm0 | Self::Xmm1 | Self::Xmm2 | Self::Xmm3
            | Self::Xmm4 | Self::Xmm5 | Self::Xmm6 | Self::Xmm7
            | Self::Xmm8 | Self::Xmm9 | Self::Xmm10 | Self::Xmm11
            | Self::Xmm12 | Self::Xmm13 | Self::Xmm14 | Self::Xmm15 => RegisterClass::Sse,
            Self::Mm0 | Self::Mm1 | Self::Mm2 | Self::Mm3
            | Self::Mm4 | Self::Mm5 | Self::Mm6 | Self::Mm7 => RegisterClass::Mmx,
            Self::St0 | Self::St1 | Self::St2 | Self::St3
            | Self::St4 | Self::St5 | Self::St6 | Self::St7 => RegisterClass::X87,
            Self::Es | Self::Cs | Self::Ss
            | Self::Ds | Self::Fs | Self::Gs => RegisterClass::Segment,
            Self::Cr0 | Self::Cr1 | Self::Cr2 | Self::Cr3
            | Self::Cr4 | Self::Cr5 | Self::Cr6 | Self::Cr7 => RegisterClass::Control,
            Self::Dr0 | Self::Dr1 | Self::Dr2 | Self::Dr3
            | Self::Dr4 | Self::Dr5 | Self::Dr6 | Self::Dr7 => RegisterClass::Debug,
        }
    }

    /// Returns the bit-width of this register.
    pub fn width(self) -> RegisterWidth {
        match self {
            Self::Rax | Self::Rcx | Self::Rdx | Self::Rbx
            | Self::Rsp | Self::Rbp | Self::Rsi | Self::Rdi
            | Self::R8 | Self::R9 | Self::R10 | Self::R11
            | Self::R12 | Self::R13 | Self::R14 | Self::R15
            | Self::Rip => RegisterWidth::Bit64,
            Self::Eax | Self::Ecx | Self::Edx | Self::Ebx
            | Self::Esp | Self::Ebp | Self::Esi | Self::Edi
            | Self::R8d | Self::R9d | Self::R10d | Self::R11d
            | Self::R12d | Self::R13d | Self::R14d | Self::R15d
            | Self::Cr0 | Self::Cr1 | Self::Cr2 | Self::Cr3
            | Self::Cr4 | Self::Cr5 | Self::Cr6 | Self::Cr7
            | Self::Dr0 | Self::Dr1 | Self::Dr2 | Self::Dr3
            | Self::Dr4 | Self::Dr5 | Self::Dr6 | Self::Dr7 => RegisterWidth::Bit32,
            Self::Ax | Self::Cx | Self::Dx | Self::Bx
            | Self::Sp | Self::Bp | Self::Si | Self::Di
            | Self::R8w | Self::R9w | Self::R10w | Self::R11w
            | Self::R12w | Self::R13w | Self::R14w | Self::R15w
            | Self::Es | Self::Cs | Self::Ss
            | Self::Ds | Self::Fs | Self::Gs => RegisterWidth::Bit16,
            Self::Al | Self::Cl | Self::Dl | Self::Bl
            | Self::Ah | Self::Ch | Self::Dh | Self::Bh
            | Self::Spl | Self::Bpl | Self::Sil | Self::Dil
            | Self::R8b | Self::R9b | Self::R10b | Self::R11b
            | Self::R12b | Self::R13b | Self::R14b | Self::R15b => RegisterWidth::Bit8,
            Self::Xmm0 | Self::Xmm1 | Self::Xmm2 | Self::Xmm3
            | Self::Xmm4 | Self::Xmm5 | Self::Xmm6 | Self::Xmm7
            | Self::Xmm8 | Self::Xmm9 | Self::Xmm10 | Self::Xmm11
            | Self::Xmm12 | Self::Xmm13 | Self::Xmm14 | Self::Xmm15 => RegisterWidth::Bit128,
            Self::Mm0 | Self::Mm1 | Self::Mm2 | Self::Mm3
            | Self::Mm4 | Self::Mm5 | Self::Mm6 | Self::Mm7 => RegisterWidth::Bit64,
            Self::St0 | Self::St1 | Self::St2 | Self::St3
            | Self::St4 | Self::St5 | Self::St6 | Self::St7 => RegisterWidth::Bit80,
        }
    }
}

// ---------------------------------------------------------------------------
// X86Instruction — instruction family enum
// ---------------------------------------------------------------------------

/// Representative x86_64 instruction families.
///
/// Each variant represents a mnemonic family (not every encoding variant).
/// The full set of encodings including operand-size suffixes and alternative
/// forms is captured in [`X86_64_ASM_OPS`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum X86Instruction {
    // -- Zero-operand instructions --
    Clc, Cld, Cli, Clts, Cmc, Lahf, Sahf, Pushfq, Popfq,
    Stc, Std, Sti, Nop, Pause, Hlt, Ret, Retf, Int3, Into, Iretq,
    // -- System instructions --
    Syscall, Sysret, Sysenter, Sysexit, Cpuid, Rdtsc, Rdmsr, Wrmsr, Ud2,
    // -- CET --
    Endbr64,
    // -- Data movement --
    Mov, Movabs, Movsx, Movzx, Movsxd, Lea, Push, Pop, Xchg,
    // -- Arithmetic --
    Add, Sub, Adc, Sbb, And, Or, Xor, Cmp, Test,
    Inc, Dec, Not, Neg, Mul, Imul, Div, Idiv,
    // -- Shift / rotate --
    Shl, Shr, Sar, Rol, Ror, Rcl, Rcr, Shld, Shrd,
    // -- Control flow --
    Call, Jmp,
    // -- Conditional jumps (cc conditions) --
    Jo, Jno, Jb, Jae, Je, Jne, Jbe, Ja,
    Js, Jns, Jp, Jnp, Jl, Jge, Jle, Jg,
    // -- Set-condition --
    Seto, Setno, Setb, Setae, Sete, Setne, Setbe, Seta,
    Sets, Setns, Setp, Setnp, Setl, Setge, Setle, Setg,
    // -- Conditional move --
    Cmovo, Cmovno, Cmovb, Cmovae, Cmove, Cmovne, Cmovbe, Cmova,
    Cmovs, Cmovns, Cmovp, Cmovnp, Cmovl, Cmovge, Cmovle, Cmovg,
    // -- Bit operations --
    Bsf, Bsr, Bt, Bts, Btr, Btc, Popcnt, Tzcnt, Lzcnt,
    // -- x87 FPU --
    Fld, Fst, Fstp, Fadd, Fmul, Fsub, Fdiv,
    Fxch, Fucom, Fucomi, Fucomip, Fcomi, Fcomip,
}

impl X86Instruction {
    /// Returns the AT&T-syntax mnemonic string (lowercase).
    pub fn mnemonic(self) -> &'static str {
        match self {
            Self::Clc => "clc", Self::Cld => "cld", Self::Cli => "cli", Self::Clts => "clts",
            Self::Cmc => "cmc", Self::Lahf => "lahf", Self::Sahf => "sahf",
            Self::Pushfq => "pushfq", Self::Popfq => "popfq",
            Self::Stc => "stc", Self::Std => "std", Self::Sti => "sti",
            Self::Nop => "nop", Self::Pause => "pause", Self::Hlt => "hlt",
            Self::Ret => "ret", Self::Retf => "retf",
            Self::Int3 => "int3", Self::Into => "into", Self::Iretq => "iretq",
            Self::Syscall => "syscall", Self::Sysret => "sysret",
            Self::Sysenter => "sysenter", Self::Sysexit => "sysexit",
            Self::Cpuid => "cpuid", Self::Rdtsc => "rdtsc",
            Self::Rdmsr => "rdmsr", Self::Wrmsr => "wrmsr",
            Self::Ud2 => "ud2", Self::Endbr64 => "endbr64",
            Self::Mov => "mov", Self::Movabs => "movabs",
            Self::Movsx => "movsx", Self::Movzx => "movzx",
            Self::Movsxd => "movsxd", Self::Lea => "lea",
            Self::Push => "push", Self::Pop => "pop", Self::Xchg => "xchg",
            Self::Add => "add", Self::Sub => "sub", Self::Adc => "adc", Self::Sbb => "sbb",
            Self::And => "and", Self::Or => "or", Self::Xor => "xor",
            Self::Cmp => "cmp", Self::Test => "test",
            Self::Inc => "inc", Self::Dec => "dec", Self::Not => "not", Self::Neg => "neg",
            Self::Mul => "mul", Self::Imul => "imul", Self::Div => "div", Self::Idiv => "idiv",
            Self::Shl => "shl", Self::Shr => "shr", Self::Sar => "sar",
            Self::Rol => "rol", Self::Ror => "ror", Self::Rcl => "rcl", Self::Rcr => "rcr",
            Self::Shld => "shld", Self::Shrd => "shrd",
            Self::Call => "call", Self::Jmp => "jmp",
            Self::Jo => "jo", Self::Jno => "jno", Self::Jb => "jb", Self::Jae => "jae",
            Self::Je => "je", Self::Jne => "jne", Self::Jbe => "jbe", Self::Ja => "ja",
            Self::Js => "js", Self::Jns => "jns", Self::Jp => "jp", Self::Jnp => "jnp",
            Self::Jl => "jl", Self::Jge => "jge", Self::Jle => "jle", Self::Jg => "jg",
            Self::Seto => "seto", Self::Setno => "setno", Self::Setb => "setb", Self::Setae => "setae",
            Self::Sete => "sete", Self::Setne => "setne", Self::Setbe => "setbe", Self::Seta => "seta",
            Self::Sets => "sets", Self::Setns => "setns", Self::Setp => "setp", Self::Setnp => "setnp",
            Self::Setl => "setl", Self::Setge => "setge", Self::Setle => "setle", Self::Setg => "setg",
            Self::Cmovo => "cmovo", Self::Cmovno => "cmovno",
            Self::Cmovb => "cmovb", Self::Cmovae => "cmovae",
            Self::Cmove => "cmove", Self::Cmovne => "cmovne",
            Self::Cmovbe => "cmovbe", Self::Cmova => "cmova",
            Self::Cmovs => "cmovs", Self::Cmovns => "cmovns",
            Self::Cmovp => "cmovp", Self::Cmovnp => "cmovnp",
            Self::Cmovl => "cmovl", Self::Cmovge => "cmovge",
            Self::Cmovle => "cmovle", Self::Cmovg => "cmovg",
            Self::Bsf => "bsf", Self::Bsr => "bsr",
            Self::Bt => "bt", Self::Bts => "bts", Self::Btr => "btr", Self::Btc => "btc",
            Self::Popcnt => "popcnt", Self::Tzcnt => "tzcnt", Self::Lzcnt => "lzcnt",
            Self::Fld => "fld", Self::Fst => "fst", Self::Fstp => "fstp",
            Self::Fadd => "fadd", Self::Fmul => "fmul", Self::Fsub => "fsub", Self::Fdiv => "fdiv",
            Self::Fxch => "fxch", Self::Fucom => "fucom",
            Self::Fucomi => "fucomi", Self::Fucomip => "fucomip",
            Self::Fcomi => "fcomi", Self::Fcomip => "fcomip",
        }
    }

    /// Returns the zero-based index into the instruction family list.
    /// This is a convenience ordinal matching the enum declaration order.
    pub fn opcode_index(self) -> usize {
        self as usize
    }
}

// ---------------------------------------------------------------------------
// REGISTER_TABLE — complete x86_64 register lookup table
// ---------------------------------------------------------------------------

/// Complete register lookup table for the x86_64 assembler.
///
/// Each entry maps a register name string to its hardware encoding, register
/// class, and bit-width.  The order follows `i386-tok.h` token generation:
/// 8-bit low, 8-bit high, 16-bit, 32-bit, 64-bit, extended, MMX, XMM,
/// control, test, debug, segment, FPU, special.
pub static REGISTER_TABLE: &[RegisterDef] = &[
    // 8-bit low GPRs (legacy encoding 0–3)
    RegisterDef { name: "al",  encoding: 0, class: RegisterClass::Gpr, width: RegisterWidth::Bit8 },
    RegisterDef { name: "cl",  encoding: 1, class: RegisterClass::Gpr, width: RegisterWidth::Bit8 },
    RegisterDef { name: "dl",  encoding: 2, class: RegisterClass::Gpr, width: RegisterWidth::Bit8 },
    RegisterDef { name: "bl",  encoding: 3, class: RegisterClass::Gpr, width: RegisterWidth::Bit8 },
    // 8-bit high GPRs (legacy encoding 4–7)
    RegisterDef { name: "ah",  encoding: 4, class: RegisterClass::Gpr, width: RegisterWidth::Bit8 },
    RegisterDef { name: "ch",  encoding: 5, class: RegisterClass::Gpr, width: RegisterWidth::Bit8 },
    RegisterDef { name: "dh",  encoding: 6, class: RegisterClass::Gpr, width: RegisterWidth::Bit8 },
    RegisterDef { name: "bh",  encoding: 7, class: RegisterClass::Gpr, width: RegisterWidth::Bit8 },
    // 16-bit GPRs (encoding 0–7)
    RegisterDef { name: "ax",  encoding: 0, class: RegisterClass::Gpr, width: RegisterWidth::Bit16 },
    RegisterDef { name: "cx",  encoding: 1, class: RegisterClass::Gpr, width: RegisterWidth::Bit16 },
    RegisterDef { name: "dx",  encoding: 2, class: RegisterClass::Gpr, width: RegisterWidth::Bit16 },
    RegisterDef { name: "bx",  encoding: 3, class: RegisterClass::Gpr, width: RegisterWidth::Bit16 },
    RegisterDef { name: "sp",  encoding: 4, class: RegisterClass::Gpr, width: RegisterWidth::Bit16 },
    RegisterDef { name: "bp",  encoding: 5, class: RegisterClass::Gpr, width: RegisterWidth::Bit16 },
    RegisterDef { name: "si",  encoding: 6, class: RegisterClass::Gpr, width: RegisterWidth::Bit16 },
    RegisterDef { name: "di",  encoding: 7, class: RegisterClass::Gpr, width: RegisterWidth::Bit16 },
    // 32-bit GPRs (encoding 0–7)
    RegisterDef { name: "eax", encoding: 0, class: RegisterClass::Gpr, width: RegisterWidth::Bit32 },
    RegisterDef { name: "ecx", encoding: 1, class: RegisterClass::Gpr, width: RegisterWidth::Bit32 },
    RegisterDef { name: "edx", encoding: 2, class: RegisterClass::Gpr, width: RegisterWidth::Bit32 },
    RegisterDef { name: "ebx", encoding: 3, class: RegisterClass::Gpr, width: RegisterWidth::Bit32 },
    RegisterDef { name: "esp", encoding: 4, class: RegisterClass::Gpr, width: RegisterWidth::Bit32 },
    RegisterDef { name: "ebp", encoding: 5, class: RegisterClass::Gpr, width: RegisterWidth::Bit32 },
    RegisterDef { name: "esi", encoding: 6, class: RegisterClass::Gpr, width: RegisterWidth::Bit32 },
    RegisterDef { name: "edi", encoding: 7, class: RegisterClass::Gpr, width: RegisterWidth::Bit32 },
    // 64-bit GPRs (encoding 0–7)
    RegisterDef { name: "rax", encoding: 0, class: RegisterClass::Gpr, width: RegisterWidth::Bit64 },
    RegisterDef { name: "rcx", encoding: 1, class: RegisterClass::Gpr, width: RegisterWidth::Bit64 },
    RegisterDef { name: "rdx", encoding: 2, class: RegisterClass::Gpr, width: RegisterWidth::Bit64 },
    RegisterDef { name: "rbx", encoding: 3, class: RegisterClass::Gpr, width: RegisterWidth::Bit64 },
    RegisterDef { name: "rsp", encoding: 4, class: RegisterClass::Gpr, width: RegisterWidth::Bit64 },
    RegisterDef { name: "rbp", encoding: 5, class: RegisterClass::Gpr, width: RegisterWidth::Bit64 },
    RegisterDef { name: "rsi", encoding: 6, class: RegisterClass::Gpr, width: RegisterWidth::Bit64 },
    RegisterDef { name: "rdi", encoding: 7, class: RegisterClass::Gpr, width: RegisterWidth::Bit64 },
    // MMX registers (encoding 0–7)
    RegisterDef { name: "mm0", encoding: 0, class: RegisterClass::Mmx, width: RegisterWidth::Bit64 },
    RegisterDef { name: "mm1", encoding: 1, class: RegisterClass::Mmx, width: RegisterWidth::Bit64 },
    RegisterDef { name: "mm2", encoding: 2, class: RegisterClass::Mmx, width: RegisterWidth::Bit64 },
    RegisterDef { name: "mm3", encoding: 3, class: RegisterClass::Mmx, width: RegisterWidth::Bit64 },
    RegisterDef { name: "mm4", encoding: 4, class: RegisterClass::Mmx, width: RegisterWidth::Bit64 },
    RegisterDef { name: "mm5", encoding: 5, class: RegisterClass::Mmx, width: RegisterWidth::Bit64 },
    RegisterDef { name: "mm6", encoding: 6, class: RegisterClass::Mmx, width: RegisterWidth::Bit64 },
    RegisterDef { name: "mm7", encoding: 7, class: RegisterClass::Mmx, width: RegisterWidth::Bit64 },
    // XMM registers (encoding 0–7)
    RegisterDef { name: "xmm0", encoding: 0, class: RegisterClass::Sse, width: RegisterWidth::Bit128 },
    RegisterDef { name: "xmm1", encoding: 1, class: RegisterClass::Sse, width: RegisterWidth::Bit128 },
    RegisterDef { name: "xmm2", encoding: 2, class: RegisterClass::Sse, width: RegisterWidth::Bit128 },
    RegisterDef { name: "xmm3", encoding: 3, class: RegisterClass::Sse, width: RegisterWidth::Bit128 },
    RegisterDef { name: "xmm4", encoding: 4, class: RegisterClass::Sse, width: RegisterWidth::Bit128 },
    RegisterDef { name: "xmm5", encoding: 5, class: RegisterClass::Sse, width: RegisterWidth::Bit128 },
    RegisterDef { name: "xmm6", encoding: 6, class: RegisterClass::Sse, width: RegisterWidth::Bit128 },
    RegisterDef { name: "xmm7", encoding: 7, class: RegisterClass::Sse, width: RegisterWidth::Bit128 },
    // Control registers (encoding 0–7)
    RegisterDef { name: "cr0", encoding: 0, class: RegisterClass::Control, width: RegisterWidth::Bit32 },
    RegisterDef { name: "cr1", encoding: 1, class: RegisterClass::Control, width: RegisterWidth::Bit32 },
    RegisterDef { name: "cr2", encoding: 2, class: RegisterClass::Control, width: RegisterWidth::Bit32 },
    RegisterDef { name: "cr3", encoding: 3, class: RegisterClass::Control, width: RegisterWidth::Bit32 },
    RegisterDef { name: "cr4", encoding: 4, class: RegisterClass::Control, width: RegisterWidth::Bit32 },
    RegisterDef { name: "cr5", encoding: 5, class: RegisterClass::Control, width: RegisterWidth::Bit32 },
    RegisterDef { name: "cr6", encoding: 6, class: RegisterClass::Control, width: RegisterWidth::Bit32 },
    RegisterDef { name: "cr7", encoding: 7, class: RegisterClass::Control, width: RegisterWidth::Bit32 },
    // Debug registers (dr0–dr7, aliased from tr/db tokens in C)
    RegisterDef { name: "dr0", encoding: 0, class: RegisterClass::Debug, width: RegisterWidth::Bit32 },
    RegisterDef { name: "dr1", encoding: 1, class: RegisterClass::Debug, width: RegisterWidth::Bit32 },
    RegisterDef { name: "dr2", encoding: 2, class: RegisterClass::Debug, width: RegisterWidth::Bit32 },
    RegisterDef { name: "dr3", encoding: 3, class: RegisterClass::Debug, width: RegisterWidth::Bit32 },
    RegisterDef { name: "dr4", encoding: 4, class: RegisterClass::Debug, width: RegisterWidth::Bit32 },
    RegisterDef { name: "dr5", encoding: 5, class: RegisterClass::Debug, width: RegisterWidth::Bit32 },
    RegisterDef { name: "dr6", encoding: 6, class: RegisterClass::Debug, width: RegisterWidth::Bit32 },
    RegisterDef { name: "dr7", encoding: 7, class: RegisterClass::Debug, width: RegisterWidth::Bit32 },
    // Segment registers
    RegisterDef { name: "es", encoding: 0, class: RegisterClass::Segment, width: RegisterWidth::Bit16 },
    RegisterDef { name: "cs", encoding: 1, class: RegisterClass::Segment, width: RegisterWidth::Bit16 },
    RegisterDef { name: "ss", encoding: 2, class: RegisterClass::Segment, width: RegisterWidth::Bit16 },
    RegisterDef { name: "ds", encoding: 3, class: RegisterClass::Segment, width: RegisterWidth::Bit16 },
    RegisterDef { name: "fs", encoding: 4, class: RegisterClass::Segment, width: RegisterWidth::Bit16 },
    RegisterDef { name: "gs", encoding: 5, class: RegisterClass::Segment, width: RegisterWidth::Bit16 },
    // x87 FPU registers (st0–st7)
    RegisterDef { name: "st0", encoding: 0, class: RegisterClass::X87, width: RegisterWidth::Bit80 },
    RegisterDef { name: "st1", encoding: 1, class: RegisterClass::X87, width: RegisterWidth::Bit80 },
    RegisterDef { name: "st2", encoding: 2, class: RegisterClass::X87, width: RegisterWidth::Bit80 },
    RegisterDef { name: "st3", encoding: 3, class: RegisterClass::X87, width: RegisterWidth::Bit80 },
    RegisterDef { name: "st4", encoding: 4, class: RegisterClass::X87, width: RegisterWidth::Bit80 },
    RegisterDef { name: "st5", encoding: 5, class: RegisterClass::X87, width: RegisterWidth::Bit80 },
    RegisterDef { name: "st6", encoding: 6, class: RegisterClass::X87, width: RegisterWidth::Bit80 },
    RegisterDef { name: "st7", encoding: 7, class: RegisterClass::X87, width: RegisterWidth::Bit80 },
    // RIP (instruction pointer)
    RegisterDef { name: "rip", encoding: 0, class: RegisterClass::Gpr, width: RegisterWidth::Bit64 },
    // x86_64 REX low-byte registers
    RegisterDef { name: "spl", encoding: 4, class: RegisterClass::Gpr, width: RegisterWidth::Bit8 },
    RegisterDef { name: "bpl", encoding: 5, class: RegisterClass::Gpr, width: RegisterWidth::Bit8 },
    RegisterDef { name: "sil", encoding: 6, class: RegisterClass::Gpr, width: RegisterWidth::Bit8 },
    RegisterDef { name: "dil", encoding: 7, class: RegisterClass::Gpr, width: RegisterWidth::Bit8 },
    // x86_64 extended 64-bit GPRs (r8–r15)
    RegisterDef { name: "r8",  encoding: 8,  class: RegisterClass::Gpr, width: RegisterWidth::Bit64 },
    RegisterDef { name: "r9",  encoding: 9,  class: RegisterClass::Gpr, width: RegisterWidth::Bit64 },
    RegisterDef { name: "r10", encoding: 10, class: RegisterClass::Gpr, width: RegisterWidth::Bit64 },
    RegisterDef { name: "r11", encoding: 11, class: RegisterClass::Gpr, width: RegisterWidth::Bit64 },
    RegisterDef { name: "r12", encoding: 12, class: RegisterClass::Gpr, width: RegisterWidth::Bit64 },
    RegisterDef { name: "r13", encoding: 13, class: RegisterClass::Gpr, width: RegisterWidth::Bit64 },
    RegisterDef { name: "r14", encoding: 14, class: RegisterClass::Gpr, width: RegisterWidth::Bit64 },
    RegisterDef { name: "r15", encoding: 15, class: RegisterClass::Gpr, width: RegisterWidth::Bit64 },
    // x86_64 extended 32-bit GPRs (r8d–r15d)
    RegisterDef { name: "r8d",  encoding: 8,  class: RegisterClass::Gpr, width: RegisterWidth::Bit32 },
    RegisterDef { name: "r9d",  encoding: 9,  class: RegisterClass::Gpr, width: RegisterWidth::Bit32 },
    RegisterDef { name: "r10d", encoding: 10, class: RegisterClass::Gpr, width: RegisterWidth::Bit32 },
    RegisterDef { name: "r11d", encoding: 11, class: RegisterClass::Gpr, width: RegisterWidth::Bit32 },
    RegisterDef { name: "r12d", encoding: 12, class: RegisterClass::Gpr, width: RegisterWidth::Bit32 },
    RegisterDef { name: "r13d", encoding: 13, class: RegisterClass::Gpr, width: RegisterWidth::Bit32 },
    RegisterDef { name: "r14d", encoding: 14, class: RegisterClass::Gpr, width: RegisterWidth::Bit32 },
    RegisterDef { name: "r15d", encoding: 15, class: RegisterClass::Gpr, width: RegisterWidth::Bit32 },
    // x86_64 extended 16-bit GPRs (r8w–r15w)
    RegisterDef { name: "r8w",  encoding: 8,  class: RegisterClass::Gpr, width: RegisterWidth::Bit16 },
    RegisterDef { name: "r9w",  encoding: 9,  class: RegisterClass::Gpr, width: RegisterWidth::Bit16 },
    RegisterDef { name: "r10w", encoding: 10, class: RegisterClass::Gpr, width: RegisterWidth::Bit16 },
    RegisterDef { name: "r11w", encoding: 11, class: RegisterClass::Gpr, width: RegisterWidth::Bit16 },
    RegisterDef { name: "r12w", encoding: 12, class: RegisterClass::Gpr, width: RegisterWidth::Bit16 },
    RegisterDef { name: "r13w", encoding: 13, class: RegisterClass::Gpr, width: RegisterWidth::Bit16 },
    RegisterDef { name: "r14w", encoding: 14, class: RegisterClass::Gpr, width: RegisterWidth::Bit16 },
    RegisterDef { name: "r15w", encoding: 15, class: RegisterClass::Gpr, width: RegisterWidth::Bit16 },
    // x86_64 extended 8-bit GPRs (r8b–r15b)
    RegisterDef { name: "r8b",  encoding: 8,  class: RegisterClass::Gpr, width: RegisterWidth::Bit8 },
    RegisterDef { name: "r9b",  encoding: 9,  class: RegisterClass::Gpr, width: RegisterWidth::Bit8 },
    RegisterDef { name: "r10b", encoding: 10, class: RegisterClass::Gpr, width: RegisterWidth::Bit8 },
    RegisterDef { name: "r11b", encoding: 11, class: RegisterClass::Gpr, width: RegisterWidth::Bit8 },
    RegisterDef { name: "r12b", encoding: 12, class: RegisterClass::Gpr, width: RegisterWidth::Bit8 },
    RegisterDef { name: "r13b", encoding: 13, class: RegisterClass::Gpr, width: RegisterWidth::Bit8 },
    RegisterDef { name: "r14b", encoding: 14, class: RegisterClass::Gpr, width: RegisterWidth::Bit8 },
    RegisterDef { name: "r15b", encoding: 15, class: RegisterClass::Gpr, width: RegisterWidth::Bit8 },
    // x86_64 extended XMM registers (xmm8–xmm15)
    RegisterDef { name: "xmm8",  encoding: 8,  class: RegisterClass::Sse, width: RegisterWidth::Bit128 },
    RegisterDef { name: "xmm9",  encoding: 9,  class: RegisterClass::Sse, width: RegisterWidth::Bit128 },
    RegisterDef { name: "xmm10", encoding: 10, class: RegisterClass::Sse, width: RegisterWidth::Bit128 },
    RegisterDef { name: "xmm11", encoding: 11, class: RegisterClass::Sse, width: RegisterWidth::Bit128 },
    RegisterDef { name: "xmm12", encoding: 12, class: RegisterClass::Sse, width: RegisterWidth::Bit128 },
    RegisterDef { name: "xmm13", encoding: 13, class: RegisterClass::Sse, width: RegisterWidth::Bit128 },
    RegisterDef { name: "xmm14", encoding: 14, class: RegisterClass::Sse, width: RegisterWidth::Bit128 },
    RegisterDef { name: "xmm15", encoding: 15, class: RegisterClass::Sse, width: RegisterWidth::Bit128 },
];

// ---------------------------------------------------------------------------
// AsmOpDef helper constructors (const-compatible)
// ---------------------------------------------------------------------------

/// Compute the stored opcode from a raw opcode value.
/// Mirrors the C macro `O(o)`: strips the `0x0F` byte when it appears in
/// bit positions 8–15, as the `0x0F` prefix is tracked in `flags` instead.
const fn oc(o: u32) -> u32 {
    if (o & 0xff00) == 0x0f00 {
        ((o >> 8) & !0xff) | (o & 0xff)
    } else {
        o
    }
}

/// Compute instruction flags from raw opcode, user flags, and group.
/// Mirrors the C macro `T(o,i,g)`: combines user flags, group shift,
/// and auto-detects `OPC_0F` from the opcode value.
const fn fl(o: u32, i: u32, g: u8) -> u32 {
    let opc_0f = if (o & 0xff00) == 0x0f00 { OPC_0F } else { 0 };
    i | ((g as u32) << OPC_GROUP_SHIFT) | opc_0f
}

/// Construct a zero-operand instruction (DEF_ASM_OP0).
const fn op0(name: &'static str, opcode: u32) -> AsmOpDef {
    AsmOpDef { name, opcode, group: 0, flags: 0, op_count: AsmOpCount::Op0, operands: [0, 0, 0], is_alt: false }
}

/// Construct a zero-operand instruction with extended flags (DEF_ASM_OP0L).
const fn op0l(name: &'static str, o: u32, g: u8, i: u32) -> AsmOpDef {
    AsmOpDef { name, opcode: oc(o), group: g, flags: fl(o, i, g), op_count: AsmOpCount::Op0L, operands: [0, 0, 0], is_alt: false }
}

/// Construct a one-operand instruction (DEF_ASM_OP1).
const fn op1(name: &'static str, o: u32, g: u8, i: u32, a: u32) -> AsmOpDef {
    AsmOpDef { name, opcode: oc(o), group: g, flags: fl(o, i, g), op_count: AsmOpCount::Op1, operands: [a, 0, 0], is_alt: false }
}

/// Construct a two-operand instruction (DEF_ASM_OP2).
const fn op2(name: &'static str, o: u32, g: u8, i: u32, a: u32, b: u32) -> AsmOpDef {
    AsmOpDef { name, opcode: oc(o), group: g, flags: fl(o, i, g), op_count: AsmOpCount::Op2, operands: [a, b, 0], is_alt: false }
}

/// Construct a three-operand instruction (DEF_ASM_OP3).
const fn op3(name: &'static str, o: u32, g: u8, i: u32, a: u32, b: u32, c: u32) -> AsmOpDef {
    AsmOpDef { name, opcode: oc(o), group: g, flags: fl(o, i, g), op_count: AsmOpCount::Op3, operands: [a, b, c], is_alt: false }
}

/// Wrap any AsmOpDef as an alternative encoding (ALT).
const fn alt(mut d: AsmOpDef) -> AsmOpDef {
    d.is_alt = true;
    d
}

// ============================================================================
// X86_64 Assembly Instruction Table
// ============================================================================

/// Complete x86_64 instruction opcode table.
/// Ported from x86_64-asm.h (559 lines). Contains all instruction definitions
/// including zero-operand, single-operand, two-operand, and three-operand forms,
/// as well as alternative encodings for the same mnemonic.
///
/// Total: 452 entries covering the full x86_64 instruction set.
pub static X86_64_ASM_OPS: &[AsmOpDef] = &[
    op0("clc", 0xf8),
    op0("cld", 0xfc),
    op0("cli", 0xfa),
    op0("clts", 0x0f06),
    op0("cmc", 0xf5),
    op0("lahf", 0x9f),
    op0("sahf", 0x9e),
    op0("pushfq", 0x9c),
    op0("popfq", 0x9d),
    op0("pushf", 0x9c),
    op0("popf", 0x9d),
    op0("stc", 0xf9),
    op0("std", 0xfd),
    op0("sti", 0xfb),
    op0("aaa", 0x37),
    op0("aas", 0x3f),
    op0("daa", 0x27),
    op0("das", 0x2f),
    op0("aad", 0xd50a),
    op0("aam", 0xd40a),
    op0("cbw", 0x6698),
    op0("cwd", 0x6699),
    op0("cwde", 0x98),
    op0("cdq", 0x99),
    op0("cbtw", 0x6698),
    op0("cwtl", 0x98),
    op0("cwtd", 0x6699),
    op0("cltd", 0x99),
    op0("cqto", 0x4899),
    op0("int3", 0xcc),
    op0("into", 0xce),
    op0("iret", 0xcf),
    op0("iretw", 0x66cf),
    op0("iretl", 0xcf),
    op0("iretq", 0x48cf),
    op0("rsm", 0x0faa),
    op0("hlt", 0xf4),
    op0("wait", 0x9b),
    op0("nop", 0x90),
    op0("pause", 0xf390),
    op0("xlat", 0xd7),
    op0l("vmcall", 0xc1, 0, OPC_0F01),
    op0l("vmlaunch", 0xc2, 0, OPC_0F01),
    op0l("vmresume", 0xc3, 0, OPC_0F01),
    op0l("vmxoff", 0xc4, 0, OPC_0F01),
    alt(op0l("cmpsb", 0xa6, 0, OPC_BWLX)),
    alt(op0l("scmpb", 0xa6, 0, OPC_BWLX)),
    alt(op0l("insb", 0x6c, 0, OPC_BWL)),
    alt(op0l("outsb", 0x6e, 0, OPC_BWL)),
    alt(op0l("lodsb", 0xac, 0, OPC_BWLX)),
    alt(op0l("slodb", 0xac, 0, OPC_BWLX)),
    alt(op0l("movsb", 0xa4, 0, OPC_BWLX)),
    alt(op0l("smovb", 0xa4, 0, OPC_BWLX)),
    alt(op0l("scasb", 0xae, 0, OPC_BWLX)),
    alt(op0l("sscab", 0xae, 0, OPC_BWLX)),
    alt(op0l("stosb", 0xaa, 0, OPC_BWLX)),
    alt(op0l("sstob", 0xaa, 0, OPC_BWLX)),
    alt(op2("bsfw", 0x0fbc, 0, OPC_MODRM | OPC_WLX, OPT_REGW | OPT_EA, OPT_REGW)),
    alt(op2("bsrw", 0x0fbd, 0, OPC_MODRM | OPC_WLX, OPT_REGW | OPT_EA, OPT_REGW)),
    alt(op2("btw", 0x0fa3, 0, OPC_MODRM | OPC_WLX, OPT_REGW, OPT_REGW | OPT_EA)),
    alt(op2("btw", 0x0fba, 4, OPC_MODRM | OPC_WLX, OPT_IM8, OPT_REGW | OPT_EA)),
    alt(op2("btsw", 0x0fab, 0, OPC_MODRM | OPC_WLX, OPT_REGW, OPT_REGW | OPT_EA)),
    alt(op2("btsw", 0x0fba, 5, OPC_MODRM | OPC_WLX, OPT_IM8, OPT_REGW | OPT_EA)),
    alt(op2("btrw", 0x0fb3, 0, OPC_MODRM | OPC_WLX, OPT_REGW, OPT_REGW | OPT_EA)),
    alt(op2("btrw", 0x0fba, 6, OPC_MODRM | OPC_WLX, OPT_IM8, OPT_REGW | OPT_EA)),
    alt(op2("btcw", 0x0fbb, 0, OPC_MODRM | OPC_WLX, OPT_REGW, OPT_REGW | OPT_EA)),
    alt(op2("btcw", 0x0fba, 7, OPC_MODRM | OPC_WLX, OPT_IM8, OPT_REGW | OPT_EA)),
    alt(op2("popcntw", 0xf30fb8, 0, OPC_MODRM | OPC_WLX, OPT_REGW | OPT_EA, OPT_REGW)),
    alt(op2("tzcntw", 0xf30fbc, 0, OPC_MODRM | OPC_WLX, OPT_REGW | OPT_EA, OPT_REGW)),
    alt(op2("lzcntw", 0xf30fbd, 0, OPC_MODRM | OPC_WLX, OPT_REGW | OPT_EA, OPT_REGW)),
    op0("lock", 0xf0),
    op0("rep", 0xf3),
    op0("repe", 0xf3),
    op0("repz", 0xf3),
    op0("repne", 0xf2),
    op0("repnz", 0xf2),
    op0("invd", 0x0f08),
    op0("wbinvd", 0x0f09),
    op0("cpuid", 0x0fa2),
    op0("wrmsr", 0x0f30),
    op0("rdtsc", 0x0f31),
    op0("rdmsr", 0x0f32),
    op0("rdpmc", 0x0f33),
    op0("syscall", 0x0f05),
    op0("sysret", 0x0f07),
    op0l("sysretq", 0x480f07, 0, 0),
    op0("ud2", 0x0f0b),
    alt(op2("movb", 0xa0, 0, OPC_BWLX, OPT_ADDR, OPT_EAX)),
    alt(op2("movb", 0xa2, 0, OPC_BWLX, OPT_EAX, OPT_ADDR)),
    alt(op2("movb", 0x88, 0, OPC_MODRM | OPC_BWLX, OPT_REG, OPT_EA | OPT_REG)),
    alt(op2("movb", 0x8a, 0, OPC_MODRM | OPC_BWLX, OPT_EA | OPT_REG, OPT_REG)),
    alt(op2("movb", 0xb0, 0, OPC_REG | OPC_BWLX, OPT_IM, OPT_REG)),
    alt(op2("mov", 0xb8, 0, OPC_REG, OPT_IM64, OPT_REG64)),
    alt(op2("movq", 0xb8, 0, OPC_REG, OPT_IM64, OPT_REG64)),
    alt(op2("movb", 0xc6, 0, OPC_MODRM | OPC_BWLX, OPT_IM, OPT_REG | OPT_EA)),
    alt(op2("movw", 0x8c, 0, OPC_MODRM | OPC_WLX, OPT_SEG, OPT_EA | OPT_REG)),
    alt(op2("movw", 0x8e, 0, OPC_MODRM | OPC_WLX, OPT_EA | OPT_REG, OPT_SEG)),
    alt(op2("movw", 0x0f20, 0, OPC_MODRM | OPC_WLX, OPT_CR, OPT_REG64)),
    alt(op2("movw", 0x0f21, 0, OPC_MODRM | OPC_WLX, OPT_DB, OPT_REG64)),
    alt(op2("movw", 0x0f22, 0, OPC_MODRM | OPC_WLX, OPT_REG64, OPT_CR)),
    alt(op2("movw", 0x0f23, 0, OPC_MODRM | OPC_WLX, OPT_REG64, OPT_DB)),
    alt(op2("movsbw", 0x660fbe, 0, OPC_MODRM, OPT_REG8 | OPT_EA, OPT_REG16)),
    alt(op2("movsbl", 0x0fbe, 0, OPC_MODRM, OPT_REG8 | OPT_EA, OPT_REG32)),
    alt(op2("movsbq", 0x0fbe, 0, OPC_MODRM, OPT_REG8 | OPT_EA, OPT_REGW)),
    alt(op2("movswl", 0x0fbf, 0, OPC_MODRM, OPT_REG16 | OPT_EA, OPT_REG32)),
    alt(op2("movswq", 0x0fbf, 0, OPC_MODRM, OPT_REG16 | OPT_EA, OPT_REG)),
    alt(op2("movslq", 0x63, 0, OPC_MODRM, OPT_REG32 | OPT_EA, OPT_REG)),
    alt(op2("movzbw", 0x0fb6, 0, OPC_MODRM | OPC_WLX, OPT_REG8 | OPT_EA, OPT_REGW)),
    alt(op2("movzwl", 0x0fb7, 0, OPC_MODRM, OPT_REG16 | OPT_EA, OPT_REG32)),
    alt(op2("movzwq", 0x0fb7, 0, OPC_MODRM, OPT_REG16 | OPT_EA, OPT_REG)),
    alt(op1("pushq", 0x6a, 0, 0, OPT_IM8S)),
    alt(op1("push", 0x6a, 0, 0, OPT_IM8S)),
    alt(op1("pushw", 0x666a, 0, 0, OPT_IM8S)),
    alt(op1("pushw", 0x50, 0, OPC_REG | OPC_WLX, OPT_REG64)),
    alt(op1("pushw", 0x50, 0, OPC_REG | OPC_WLX, OPT_REG16)),
    alt(op1("pushw", 0xff, 6, OPC_MODRM | OPC_WLX, OPT_REG64 | OPT_EA)),
    alt(op1("pushw", 0x6668, 0, 0, OPT_IM16)),
    alt(op1("pushw", 0x68, 0, OPC_WLX, OPT_IM32)),
    alt(op1("pushw", 0x06, 0, OPC_WLX, OPT_SEG)),
    alt(op1("popw", 0x58, 0, OPC_REG | OPC_WLX, OPT_REG64)),
    alt(op1("popw", 0x58, 0, OPC_REG | OPC_WLX, OPT_REG16)),
    alt(op1("popw", 0x8f, 0, OPC_MODRM | OPC_WLX, OPT_REGW | OPT_EA)),
    alt(op1("popw", 0x07, 0, OPC_WLX, OPT_SEG)),
    alt(op2("xchgw", 0x90, 0, OPC_REG | OPC_WLX, OPT_REGW, OPT_EAX)),
    alt(op2("xchgw", 0x90, 0, OPC_REG | OPC_WLX, OPT_EAX, OPT_REGW)),
    alt(op2("xchgb", 0x86, 0, OPC_MODRM | OPC_BWLX, OPT_REG, OPT_EA | OPT_REG)),
    alt(op2("xchgb", 0x86, 0, OPC_MODRM | OPC_BWLX, OPT_EA | OPT_REG, OPT_REG)),
    alt(op2("inb", 0xe4, 0, OPC_BWL, OPT_IM8, OPT_EAX)),
    alt(op1("inb", 0xe4, 0, OPC_BWL, OPT_IM8)),
    alt(op2("inb", 0xec, 0, OPC_BWL, OPT_DX, OPT_EAX)),
    alt(op1("inb", 0xec, 0, OPC_BWL, OPT_DX)),
    alt(op2("outb", 0xe6, 0, OPC_BWL, OPT_EAX, OPT_IM8)),
    alt(op1("outb", 0xe6, 0, OPC_BWL, OPT_IM8)),
    alt(op2("outb", 0xee, 0, OPC_BWL, OPT_EAX, OPT_DX)),
    alt(op1("outb", 0xee, 0, OPC_BWL, OPT_DX)),
    alt(op2("leaw", 0x8d, 0, OPC_MODRM | OPC_WLX, OPT_EA, OPT_REG)),
    alt(op2("les", 0xc4, 0, OPC_MODRM, OPT_EA, OPT_REG32)),
    alt(op2("lds", 0xc5, 0, OPC_MODRM, OPT_EA, OPT_REG32)),
    alt(op2("lss", 0x0fb2, 0, OPC_MODRM, OPT_EA, OPT_REG32)),
    alt(op2("lfs", 0x0fb4, 0, OPC_MODRM, OPT_EA, OPT_REG32)),
    alt(op2("lgs", 0x0fb5, 0, OPC_MODRM, OPT_EA, OPT_REG32)),
    alt(op2("addb", 0x00, 0, OPC_ARITH | OPC_MODRM | OPC_BWLX, OPT_REG, OPT_EA | OPT_REG)),
    alt(op2("addb", 0x02, 0, OPC_ARITH | OPC_MODRM | OPC_BWLX, OPT_EA | OPT_REG, OPT_REG)),
    alt(op2("addb", 0x04, 0, OPC_ARITH | OPC_BWLX, OPT_IM, OPT_EAX)),
    alt(op2("addw", 0x83, 0, OPC_ARITH | OPC_MODRM | OPC_WLX, OPT_IM8S, OPT_EA | OPT_REGW)),
    alt(op2("addb", 0x80, 0, OPC_ARITH | OPC_MODRM | OPC_BWLX, OPT_IM, OPT_EA | OPT_REG)),
    alt(op2("testb", 0x84, 0, OPC_MODRM | OPC_BWLX, OPT_REG, OPT_EA | OPT_REG)),
    alt(op2("testb", 0x84, 0, OPC_MODRM | OPC_BWLX, OPT_EA | OPT_REG, OPT_REG)),
    alt(op2("testb", 0xa8, 0, OPC_BWLX, OPT_IM, OPT_EAX)),
    alt(op2("testb", 0xf6, 0, OPC_MODRM | OPC_BWLX, OPT_IM, OPT_EA | OPT_REG)),
    alt(op1("incb", 0xfe, 0, OPC_MODRM | OPC_BWLX, OPT_REG | OPT_EA)),
    alt(op1("decb", 0xfe, 1, OPC_MODRM | OPC_BWLX, OPT_REG | OPT_EA)),
    alt(op1("notb", 0xf6, 2, OPC_MODRM | OPC_BWLX, OPT_REG | OPT_EA)),
    alt(op1("negb", 0xf6, 3, OPC_MODRM | OPC_BWLX, OPT_REG | OPT_EA)),
    alt(op1("mulb", 0xf6, 4, OPC_MODRM | OPC_BWLX, OPT_REG | OPT_EA)),
    alt(op1("imulb", 0xf6, 5, OPC_MODRM | OPC_BWLX, OPT_REG | OPT_EA)),
    alt(op2("imulw", 0x0faf, 0, OPC_MODRM | OPC_WLX, OPT_REG | OPT_EA, OPT_REG)),
    alt(op3("imulw", 0x6b, 0, OPC_MODRM | OPC_WLX, OPT_IM8S, OPT_REGW | OPT_EA, OPT_REGW)),
    alt(op2("imulw", 0x6b, 0, OPC_MODRM | OPC_WLX, OPT_IM8S, OPT_REGW)),
    alt(op3("imulw", 0x69, 0, OPC_MODRM | OPC_WLX, OPT_IMW, OPT_REGW | OPT_EA, OPT_REGW)),
    alt(op2("imulw", 0x69, 0, OPC_MODRM | OPC_WLX, OPT_IMW, OPT_REGW)),
    alt(op1("divb", 0xf6, 6, OPC_MODRM | OPC_BWLX, OPT_REG | OPT_EA)),
    alt(op2("divb", 0xf6, 6, OPC_MODRM | OPC_BWLX, OPT_REG | OPT_EA, OPT_EAX)),
    alt(op1("idivb", 0xf6, 7, OPC_MODRM | OPC_BWLX, OPT_REG | OPT_EA)),
    alt(op2("idivb", 0xf6, 7, OPC_MODRM | OPC_BWLX, OPT_REG | OPT_EA, OPT_EAX)),
    alt(op2("rolb", 0xc0, 0, OPC_MODRM | OPC_BWLX | OPC_SHIFT, OPT_IM8, OPT_EA | OPT_REG)),
    alt(op2("rolb", 0xd2, 0, OPC_MODRM | OPC_BWLX | OPC_SHIFT, OPT_CL, OPT_EA | OPT_REG)),
    alt(op1("rolb", 0xd0, 0, OPC_MODRM | OPC_BWLX | OPC_SHIFT, OPT_EA | OPT_REG)),
    alt(op3("shldw", 0x0fa4, 0, OPC_MODRM | OPC_WLX, OPT_IM8, OPT_REGW, OPT_EA | OPT_REGW)),
    alt(op3("shldw", 0x0fa5, 0, OPC_MODRM | OPC_WLX, OPT_CL, OPT_REGW, OPT_EA | OPT_REGW)),
    alt(op2("shldw", 0x0fa5, 0, OPC_MODRM | OPC_WLX, OPT_REGW, OPT_EA | OPT_REGW)),
    alt(op3("shrdw", 0x0fac, 0, OPC_MODRM | OPC_WLX, OPT_IM8, OPT_REGW, OPT_EA | OPT_REGW)),
    alt(op3("shrdw", 0x0fad, 0, OPC_MODRM | OPC_WLX, OPT_CL, OPT_REGW, OPT_EA | OPT_REGW)),
    alt(op2("shrdw", 0x0fad, 0, OPC_MODRM | OPC_WLX, OPT_REGW, OPT_EA | OPT_REGW)),
    alt(op1("call", 0xff, 2, OPC_MODRM, OPT_INDIR)),
    alt(op1("call", 0xe8, 0, 0, OPT_DISP)),
    op1("callq", 0xff, 2, OPC_MODRM, OPT_INDIR),
    alt(op1("callq", 0xe8, 0, 0, OPT_DISP)),
    alt(op1("jmp", 0xff, 4, OPC_MODRM, OPT_INDIR)),
    alt(op1("jmp", 0xeb, 0, 0, OPT_DISP8)),
    alt(op1("lcall", 0xff, 3, OPC_MODRM, OPT_EA)),
    alt(op1("ljmp", 0xff, 5, OPC_MODRM, OPT_EA)),
    op1("ljmpw", 0x66ff, 5, OPC_MODRM, OPT_EA),
    op1("ljmpl", 0xff, 5, OPC_MODRM, OPT_EA),
    alt(op1("int", 0xcd, 0, 0, OPT_IM8)),
    alt(op1("seto", 0x0f90, 0, OPC_MODRM | OPC_TEST, OPT_REG8 | OPT_EA)),
    alt(op1("setob", 0x0f90, 0, OPC_MODRM | OPC_TEST, OPT_REG8 | OPT_EA)),
    op2("enter", 0xc8, 0, 0, OPT_IM16, OPT_IM8),
    op0("leave", 0xc9),
    op0("ret", 0xc3),
    op0("retq", 0xc3),
    alt(op1("retq", 0xc2, 0, 0, OPT_IM16)),
    alt(op1("ret", 0xc2, 0, 0, OPT_IM16)),
    op0("lret", 0xcb),
    alt(op1("lret", 0xca, 0, 0, OPT_IM16)),
    alt(op1("jo", 0x70, 0, OPC_TEST, OPT_DISP8)),
    op1("loopne", 0xe0, 0, 0, OPT_DISP8),
    op1("loopnz", 0xe0, 0, 0, OPT_DISP8),
    op1("loope", 0xe1, 0, 0, OPT_DISP8),
    op1("loopz", 0xe1, 0, 0, OPT_DISP8),
    op1("loop", 0xe2, 0, 0, OPT_DISP8),
    op1("jecxz", 0x67e3, 0, 0, OPT_DISP8),
    alt(op0l("fcomp", 0xd8d9, 0, 0)),
    alt(op1("fadd", 0xd8c0, 0, OPC_FARITH | OPC_REG, OPT_ST)),
    alt(op2("fadd", 0xd8c0, 0, OPC_FARITH | OPC_REG, OPT_ST, OPT_ST0)),
    alt(op2("fadd", 0xdcc0, 0, OPC_FARITH | OPC_REG, OPT_ST0, OPT_ST)),
    alt(op2("fmul", 0xdcc8, 0, OPC_FARITH | OPC_REG, OPT_ST0, OPT_ST)),
    alt(op0l("fadd", 0xdec1, 0, OPC_FARITH)),
    alt(op1("faddp", 0xdec0, 0, OPC_FARITH | OPC_REG, OPT_ST)),
    alt(op2("faddp", 0xdec0, 0, OPC_FARITH | OPC_REG, OPT_ST, OPT_ST0)),
    alt(op2("faddp", 0xdec0, 0, OPC_FARITH | OPC_REG, OPT_ST0, OPT_ST)),
    alt(op0l("faddp", 0xdec1, 0, OPC_FARITH)),
    alt(op1("fadds", 0xd8, 0, OPC_FARITH | OPC_MODRM, OPT_EA)),
    alt(op1("fiaddl", 0xda, 0, OPC_FARITH | OPC_MODRM, OPT_EA)),
    alt(op1("faddl", 0xdc, 0, OPC_FARITH | OPC_MODRM, OPT_EA)),
    alt(op1("fiadds", 0xde, 0, OPC_FARITH | OPC_MODRM, OPT_EA)),
    op0("fucompp", 0xdae9),
    op0("ftst", 0xd9e4),
    op0("fxam", 0xd9e5),
    op0("fld1", 0xd9e8),
    op0("fldl2t", 0xd9e9),
    op0("fldl2e", 0xd9ea),
    op0("fldpi", 0xd9eb),
    op0("fldlg2", 0xd9ec),
    op0("fldln2", 0xd9ed),
    op0("fldz", 0xd9ee),
    op0("f2xm1", 0xd9f0),
    op0("fyl2x", 0xd9f1),
    op0("fptan", 0xd9f2),
    op0("fpatan", 0xd9f3),
    op0("fxtract", 0xd9f4),
    op0("fprem1", 0xd9f5),
    op0("fdecstp", 0xd9f6),
    op0("fincstp", 0xd9f7),
    op0("fprem", 0xd9f8),
    op0("fyl2xp1", 0xd9f9),
    op0("fsqrt", 0xd9fa),
    op0("fsincos", 0xd9fb),
    op0("frndint", 0xd9fc),
    op0("fscale", 0xd9fd),
    op0("fsin", 0xd9fe),
    op0("fcos", 0xd9ff),
    op0("fchs", 0xd9e0),
    op0("fabs", 0xd9e1),
    op0("fninit", 0xdbe3),
    op0("fnclex", 0xdbe2),
    op0("fnop", 0xd9d0),
    op0("fwait", 0x9b),
    op1("fld", 0xd9c0, 0, OPC_REG, OPT_ST),
    op1("fldl", 0xd9c0, 0, OPC_REG, OPT_ST),
    op1("flds", 0xd9, 0, OPC_MODRM, OPT_EA),
    alt(op1("fldl", 0xdd, 0, OPC_MODRM, OPT_EA)),
    op1("fildl", 0xdb, 0, OPC_MODRM, OPT_EA),
    op1("fildq", 0xdf, 5, OPC_MODRM, OPT_EA),
    op1("fildll", 0xdf, 5, OPC_MODRM, OPT_EA),
    op1("fldt", 0xdb, 5, OPC_MODRM, OPT_EA),
    op1("fbld", 0xdf, 4, OPC_MODRM, OPT_EA),
    op1("fst", 0xddd0, 0, OPC_REG, OPT_ST),
    op1("fstl", 0xddd0, 0, OPC_REG, OPT_ST),
    op1("fsts", 0xd9, 2, OPC_MODRM, OPT_EA),
    op1("fstps", 0xd9, 3, OPC_MODRM, OPT_EA),
    alt(op1("fstl", 0xdd, 2, OPC_MODRM, OPT_EA)),
    op1("fstpl", 0xdd, 3, OPC_MODRM, OPT_EA),
    op1("fist", 0xdf, 2, OPC_MODRM, OPT_EA),
    op1("fistp", 0xdf, 3, OPC_MODRM, OPT_EA),
    op1("fistl", 0xdb, 2, OPC_MODRM, OPT_EA),
    op1("fistpl", 0xdb, 3, OPC_MODRM, OPT_EA),
    op1("fstp", 0xddd8, 0, OPC_REG, OPT_ST),
    op1("fistpq", 0xdf, 7, OPC_MODRM, OPT_EA),
    op1("fistpll", 0xdf, 7, OPC_MODRM, OPT_EA),
    op1("fstpt", 0xdb, 7, OPC_MODRM, OPT_EA),
    op1("fbstp", 0xdf, 6, OPC_MODRM, OPT_EA),
    op0("fxch", 0xd9c9),
    alt(op1("fxch", 0xd9c8, 0, OPC_REG, OPT_ST)),
    op1("fucom", 0xdde0, 0, OPC_REG, OPT_ST),
    op1("fucomp", 0xdde8, 0, OPC_REG, OPT_ST),
    op0l("finit", 0xdbe3, 0, OPC_FWAIT),
    op1("fldcw", 0xd9, 5, OPC_MODRM, OPT_EA),
    op1("fnstcw", 0xd9, 7, OPC_MODRM, OPT_EA),
    op1("fstcw", 0xd9, 7, OPC_MODRM | OPC_FWAIT, OPT_EA),
    op0("fnstsw", 0xdfe0),
    alt(op1("fnstsw", 0xdfe0, 0, 0, OPT_EAX)),
    alt(op1("fnstsw", 0xdd, 7, OPC_MODRM, OPT_EA)),
    op1("fstsw", 0xdfe0, 0, OPC_FWAIT, OPT_EAX),
    alt(op0l("fstsw", 0xdfe0, 0, OPC_FWAIT)),
    alt(op1("fstsw", 0xdd, 7, OPC_MODRM | OPC_FWAIT, OPT_EA)),
    op0l("fclex", 0xdbe2, 0, OPC_FWAIT),
    op1("fnstenv", 0xd9, 6, OPC_MODRM, OPT_EA),
    op1("fstenv", 0xd9, 6, OPC_MODRM | OPC_FWAIT, OPT_EA),
    op1("fldenv", 0xd9, 4, OPC_MODRM, OPT_EA),
    op1("fnsave", 0xdd, 6, OPC_MODRM, OPT_EA),
    op1("fsave", 0xdd, 6, OPC_MODRM | OPC_FWAIT, OPT_EA),
    op1("frstor", 0xdd, 4, OPC_MODRM, OPT_EA),
    op1("ffree", 0xddc0, 4, OPC_REG, OPT_ST),
    op1("ffreep", 0xdfc0, 4, OPC_REG, OPT_ST),
    op1("fxsave", 0x0fae, 0, OPC_MODRM, OPT_EA),
    op1("fxrstor", 0x0fae, 1, OPC_MODRM, OPT_EA),
    op1("fxsaveq", 0x0fae, 0, OPC_MODRM | OPC_48, OPT_EA),
    op1("fxrstorq", 0x0fae, 1, OPC_MODRM | OPC_48, OPT_EA),
    op2("arpl", 0x63, 0, OPC_MODRM, OPT_REG16, OPT_REG16 | OPT_EA),
    alt(op2("larw", 0x0f02, 0, OPC_MODRM | OPC_WLX, OPT_REG | OPT_EA, OPT_REG)),
    op1("lgdt", 0x0f01, 2, OPC_MODRM, OPT_EA),
    op1("lgdtq", 0x0f01, 2, OPC_MODRM, OPT_EA),
    op1("lidt", 0x0f01, 3, OPC_MODRM, OPT_EA),
    op1("lidtq", 0x0f01, 3, OPC_MODRM, OPT_EA),
    op1("lldt", 0x0f00, 2, OPC_MODRM, OPT_EA | OPT_REG),
    op1("lmsw", 0x0f01, 6, OPC_MODRM, OPT_EA | OPT_REG),
    alt(op2("lslw", 0x0f03, 0, OPC_MODRM | OPC_WLX, OPT_EA | OPT_REG, OPT_REG)),
    op1("ltr", 0x0f00, 3, OPC_MODRM, OPT_EA | OPT_REG16),
    op1("sgdt", 0x0f01, 0, OPC_MODRM, OPT_EA),
    op1("sgdtq", 0x0f01, 0, OPC_MODRM, OPT_EA),
    op1("sidt", 0x0f01, 1, OPC_MODRM, OPT_EA),
    op1("sidtq", 0x0f01, 1, OPC_MODRM, OPT_EA),
    op1("sldt", 0x0f00, 0, OPC_MODRM, OPT_REG | OPT_EA),
    op1("smsw", 0x0f01, 4, OPC_MODRM, OPT_REG | OPT_EA),
    op1("str", 0x0f00, 1, OPC_MODRM, OPT_REG32 | OPT_EA),
    alt(op1("str", 0x660f00, 1, OPC_MODRM, OPT_REG16)),
    alt(op1("str", 0x0f00, 1, OPC_MODRM | OPC_48, OPT_REG64)),
    op1("verr", 0x0f00, 4, OPC_MODRM, OPT_REG | OPT_EA),
    op1("verw", 0x0f00, 5, OPC_MODRM, OPT_REG | OPT_EA),
    op0l("swapgs", 0x0f01, 7, OPC_MODRM),
    op1("bswap", 0x0fc8, 0, OPC_REG, OPT_REG32),
    op1("bswapl", 0x0fc8, 0, OPC_REG, OPT_REG32),
    op1("bswapq", 0x0fc8, 0, OPC_REG | OPC_48, OPT_REG64),
    alt(op2("xaddb", 0x0fc0, 0, OPC_MODRM | OPC_BWLX, OPT_REG, OPT_REG | OPT_EA)),
    alt(op2("cmpxchgb", 0x0fb0, 0, OPC_MODRM | OPC_BWLX, OPT_REG, OPT_REG | OPT_EA)),
    op1("invlpg", 0x0f01, 7, OPC_MODRM, OPT_EA),
    op1("cmpxchg8b", 0x0fc7, 1, OPC_MODRM, OPT_EA),
    op1("cmpxchg16b", 0x0fc7, 1, OPC_MODRM | OPC_48, OPT_EA),
    alt(op2("cmovo", 0x0f40, 0, OPC_MODRM | OPC_TEST | OPC_WLX, OPT_REGW | OPT_EA, OPT_REGW)),
    op2("fcmovb", 0xdac0, 0, OPC_REG, OPT_ST, OPT_ST0),
    op2("fcmove", 0xdac8, 0, OPC_REG, OPT_ST, OPT_ST0),
    op2("fcmovbe", 0xdad0, 0, OPC_REG, OPT_ST, OPT_ST0),
    op2("fcmovu", 0xdad8, 0, OPC_REG, OPT_ST, OPT_ST0),
    op2("fcmovnb", 0xdbc0, 0, OPC_REG, OPT_ST, OPT_ST0),
    op2("fcmovne", 0xdbc8, 0, OPC_REG, OPT_ST, OPT_ST0),
    op2("fcmovnbe", 0xdbd0, 0, OPC_REG, OPT_ST, OPT_ST0),
    op2("fcmovnu", 0xdbd8, 0, OPC_REG, OPT_ST, OPT_ST0),
    op2("fucomi", 0xdbe8, 0, OPC_REG, OPT_ST, OPT_ST0),
    op2("fcomi", 0xdbf0, 0, OPC_REG, OPT_ST, OPT_ST0),
    op2("fucomip", 0xdfe8, 0, OPC_REG, OPT_ST, OPT_ST0),
    op2("fcomip", 0xdff0, 0, OPC_REG, OPT_ST, OPT_ST0),
    op0("emms", 0x0f77),
    op2("movd", 0x0f6e, 0, OPC_MODRM, OPT_EA | OPT_REG32, OPT_MMXSSE),
    alt(op2("movd", 0x0f6e, 0, OPC_MODRM, OPT_EA | OPT_REG64, OPT_MMXSSE)),
    alt(op2("movq", 0x0f6e, 0, OPC_MODRM | OPC_48, OPT_REG64, OPT_MMXSSE)),
    alt(op2("movq", 0x0f6f, 0, OPC_MODRM, OPT_EA | OPT_MMX, OPT_MMX)),
    alt(op2("movd", 0x0f7e, 0, OPC_MODRM, OPT_MMXSSE, OPT_EA | OPT_REG32)),
    alt(op2("movd", 0x0f7e, 0, OPC_MODRM, OPT_MMXSSE, OPT_EA | OPT_REG64)),
    alt(op2("movq", 0x0f7f, 0, OPC_MODRM, OPT_MMX, OPT_EA | OPT_MMX)),
    alt(op2("movq", 0x660fd6, 0, OPC_MODRM, OPT_SSE, OPT_EA | OPT_SSE)),
    alt(op2("movq", 0xf30f7e, 0, OPC_MODRM, OPT_EA | OPT_SSE, OPT_SSE)),
    alt(op2("movq", 0x0f7e, 0, OPC_MODRM, OPT_MMXSSE, OPT_EA | OPT_REG64)),
    op2("packssdw", 0x0f6b, 0, OPC_MODRM, OPT_EA | OPT_MMXSSE, OPT_MMXSSE),
    op2("packsswb", 0x0f63, 0, OPC_MODRM, OPT_EA | OPT_MMXSSE, OPT_MMXSSE),
    op2("packuswb", 0x0f67, 0, OPC_MODRM, OPT_EA | OPT_MMXSSE, OPT_MMXSSE),
    op2("paddb", 0x0ffc, 0, OPC_MODRM, OPT_EA | OPT_MMXSSE, OPT_MMXSSE),
    op2("paddw", 0x0ffd, 0, OPC_MODRM, OPT_EA | OPT_MMXSSE, OPT_MMXSSE),
    op2("paddd", 0x0ffe, 0, OPC_MODRM, OPT_EA | OPT_MMXSSE, OPT_MMXSSE),
    op2("paddsb", 0x0fec, 0, OPC_MODRM, OPT_EA | OPT_MMXSSE, OPT_MMXSSE),
    op2("paddsw", 0x0fed, 0, OPC_MODRM, OPT_EA | OPT_MMXSSE, OPT_MMXSSE),
    op2("paddusb", 0x0fdc, 0, OPC_MODRM, OPT_EA | OPT_MMXSSE, OPT_MMXSSE),
    op2("paddusw", 0x0fdd, 0, OPC_MODRM, OPT_EA | OPT_MMXSSE, OPT_MMXSSE),
    op2("pand", 0x0fdb, 0, OPC_MODRM, OPT_EA | OPT_MMXSSE, OPT_MMXSSE),
    op2("pandn", 0x0fdf, 0, OPC_MODRM, OPT_EA | OPT_MMXSSE, OPT_MMXSSE),
    op2("pcmpeqb", 0x0f74, 0, OPC_MODRM, OPT_EA | OPT_MMXSSE, OPT_MMXSSE),
    op2("pcmpeqw", 0x0f75, 0, OPC_MODRM, OPT_EA | OPT_MMXSSE, OPT_MMXSSE),
    op2("pcmpeqd", 0x0f76, 0, OPC_MODRM, OPT_EA | OPT_MMXSSE, OPT_MMXSSE),
    op2("pcmpgtb", 0x0f64, 0, OPC_MODRM, OPT_EA | OPT_MMXSSE, OPT_MMXSSE),
    op2("pcmpgtw", 0x0f65, 0, OPC_MODRM, OPT_EA | OPT_MMXSSE, OPT_MMXSSE),
    op2("pcmpgtd", 0x0f66, 0, OPC_MODRM, OPT_EA | OPT_MMXSSE, OPT_MMXSSE),
    op2("pmaddwd", 0x0ff5, 0, OPC_MODRM, OPT_EA | OPT_MMXSSE, OPT_MMXSSE),
    op2("pmulhw", 0x0fe5, 0, OPC_MODRM, OPT_EA | OPT_MMXSSE, OPT_MMXSSE),
    op2("pmullw", 0x0fd5, 0, OPC_MODRM, OPT_EA | OPT_MMXSSE, OPT_MMXSSE),
    op2("por", 0x0feb, 0, OPC_MODRM, OPT_EA | OPT_MMXSSE, OPT_MMXSSE),
    op2("psllw", 0x0ff1, 0, OPC_MODRM, OPT_EA | OPT_MMXSSE, OPT_MMXSSE),
    alt(op2("psllw", 0x0f71, 6, OPC_MODRM, OPT_IM8, OPT_MMXSSE)),
    op2("pslld", 0x0ff2, 0, OPC_MODRM, OPT_EA | OPT_MMXSSE, OPT_MMXSSE),
    alt(op2("pslld", 0x0f72, 6, OPC_MODRM, OPT_IM8, OPT_MMXSSE)),
    op2("psllq", 0x0ff3, 0, OPC_MODRM, OPT_EA | OPT_MMXSSE, OPT_MMXSSE),
    alt(op2("psllq", 0x0f73, 6, OPC_MODRM, OPT_IM8, OPT_MMXSSE)),
    op2("psraw", 0x0fe1, 0, OPC_MODRM, OPT_EA | OPT_MMXSSE, OPT_MMXSSE),
    alt(op2("psraw", 0x0f71, 4, OPC_MODRM, OPT_IM8, OPT_MMXSSE)),
    op2("psrad", 0x0fe2, 0, OPC_MODRM, OPT_EA | OPT_MMXSSE, OPT_MMXSSE),
    alt(op2("psrad", 0x0f72, 4, OPC_MODRM, OPT_IM8, OPT_MMXSSE)),
    op2("psrlw", 0x0fd1, 0, OPC_MODRM, OPT_EA | OPT_MMXSSE, OPT_MMXSSE),
    alt(op2("psrlw", 0x0f71, 2, OPC_MODRM, OPT_IM8, OPT_MMXSSE)),
    op2("psrld", 0x0fd2, 0, OPC_MODRM, OPT_EA | OPT_MMXSSE, OPT_MMXSSE),
    alt(op2("psrld", 0x0f72, 2, OPC_MODRM, OPT_IM8, OPT_MMXSSE)),
    op2("psrlq", 0x0fd3, 0, OPC_MODRM, OPT_EA | OPT_MMXSSE, OPT_MMXSSE),
    alt(op2("psrlq", 0x0f73, 2, OPC_MODRM, OPT_IM8, OPT_MMXSSE)),
    op2("psubb", 0x0ff8, 0, OPC_MODRM, OPT_EA | OPT_MMXSSE, OPT_MMXSSE),
    op2("psubw", 0x0ff9, 0, OPC_MODRM, OPT_EA | OPT_MMXSSE, OPT_MMXSSE),
    op2("psubd", 0x0ffa, 0, OPC_MODRM, OPT_EA | OPT_MMXSSE, OPT_MMXSSE),
    op2("psubsb", 0x0fe8, 0, OPC_MODRM, OPT_EA | OPT_MMXSSE, OPT_MMXSSE),
    op2("psubsw", 0x0fe9, 0, OPC_MODRM, OPT_EA | OPT_MMXSSE, OPT_MMXSSE),
    op2("psubusb", 0x0fd8, 0, OPC_MODRM, OPT_EA | OPT_MMXSSE, OPT_MMXSSE),
    op2("psubusw", 0x0fd9, 0, OPC_MODRM, OPT_EA | OPT_MMXSSE, OPT_MMXSSE),
    op2("punpckhbw", 0x0f68, 0, OPC_MODRM, OPT_EA | OPT_MMXSSE, OPT_MMXSSE),
    op2("punpckhwd", 0x0f69, 0, OPC_MODRM, OPT_EA | OPT_MMXSSE, OPT_MMXSSE),
    op2("punpckhdq", 0x0f6a, 0, OPC_MODRM, OPT_EA | OPT_MMXSSE, OPT_MMXSSE),
    op2("punpcklbw", 0x0f60, 0, OPC_MODRM, OPT_EA | OPT_MMXSSE, OPT_MMXSSE),
    op2("punpcklwd", 0x0f61, 0, OPC_MODRM, OPT_EA | OPT_MMXSSE, OPT_MMXSSE),
    op2("punpckldq", 0x0f62, 0, OPC_MODRM, OPT_EA | OPT_MMXSSE, OPT_MMXSSE),
    op2("pxor", 0x0fef, 0, OPC_MODRM, OPT_EA | OPT_MMXSSE, OPT_MMXSSE),
    op1("ldmxcsr", 0x0fae, 2, OPC_MODRM, OPT_EA),
    op1("stmxcsr", 0x0fae, 3, OPC_MODRM, OPT_EA),
    op2("movups", 0x0f10, 0, OPC_MODRM, OPT_EA | OPT_REG32, OPT_SSE),
    alt(op2("movups", 0x0f11, 0, OPC_MODRM, OPT_SSE, OPT_EA | OPT_REG32)),
    op2("movaps", 0x0f28, 0, OPC_MODRM, OPT_EA | OPT_REG32, OPT_SSE),
    alt(op2("movaps", 0x0f29, 0, OPC_MODRM, OPT_SSE, OPT_EA | OPT_REG32)),
    op2("movhps", 0x0f16, 0, OPC_MODRM, OPT_EA | OPT_REG32, OPT_SSE),
    alt(op2("movhps", 0x0f17, 0, OPC_MODRM, OPT_SSE, OPT_EA | OPT_REG32)),
    op2("addps", 0x0f58, 0, OPC_MODRM, OPT_EA | OPT_SSE, OPT_SSE),
    op2("cvtpi2ps", 0x0f2a, 0, OPC_MODRM, OPT_EA | OPT_MMX, OPT_SSE),
    op2("cvtps2pi", 0x0f2d, 0, OPC_MODRM, OPT_EA | OPT_SSE, OPT_MMX),
    op2("cvtss2si", 0xf30f2d, 0, OPC_MODRM, OPT_EA | OPT_SSE, OPT_REG32),
    alt(op2("cvtss2si", 0xf30f2d, 0, OPC_MODRM | OPC_48, OPT_EA | OPT_SSE, OPT_REG64)),
    op2("cvtsd2si", 0xf20f2d, 0, OPC_MODRM, OPT_EA | OPT_SSE, OPT_REG32),
    alt(op2("cvtsd2si", 0xf20f2d, 0, OPC_MODRM | OPC_48, OPT_EA | OPT_SSE, OPT_REG64)),
    op2("cvttps2pi", 0x0f2c, 0, OPC_MODRM, OPT_EA | OPT_SSE, OPT_MMX),
    op2("andps", 0x0f54, 0, OPC_MODRM, OPT_EA | OPT_SSE, OPT_SSE),
    op2("divps", 0x0f5e, 0, OPC_MODRM, OPT_EA | OPT_SSE, OPT_SSE),
    op2("maxps", 0x0f5f, 0, OPC_MODRM, OPT_EA | OPT_SSE, OPT_SSE),
    op2("minps", 0x0f5d, 0, OPC_MODRM, OPT_EA | OPT_SSE, OPT_SSE),
    op2("mulps", 0x0f59, 0, OPC_MODRM, OPT_EA | OPT_SSE, OPT_SSE),
    op2("pavgb", 0x0fe0, 0, OPC_MODRM, OPT_EA | OPT_SSE, OPT_SSE),
    op2("pavgw", 0x0fe3, 0, OPC_MODRM, OPT_EA | OPT_SSE, OPT_SSE),
    op2("pmaxsw", 0x0fee, 0, OPC_MODRM, OPT_EA | OPT_MMXSSE, OPT_MMXSSE),
    op2("pmaxub", 0x0fde, 0, OPC_MODRM, OPT_EA | OPT_MMXSSE, OPT_MMXSSE),
    op2("pminsw", 0x0fea, 0, OPC_MODRM, OPT_EA | OPT_MMXSSE, OPT_MMXSSE),
    op2("pminub", 0x0fda, 0, OPC_MODRM, OPT_EA | OPT_MMXSSE, OPT_MMXSSE),
    op2("rcpss", 0x0f53, 0, OPC_MODRM, OPT_EA | OPT_SSE, OPT_SSE),
    op2("rsqrtps", 0x0f52, 0, OPC_MODRM, OPT_EA | OPT_SSE, OPT_SSE),
    op2("sqrtps", 0x0f51, 0, OPC_MODRM, OPT_EA | OPT_SSE, OPT_SSE),
    op2("sqrtss", 0xf30f51, 0, OPC_MODRM, OPT_EA | OPT_SSE, OPT_SSE),
    op2("subps", 0x0f5c, 0, OPC_MODRM, OPT_EA | OPT_SSE, OPT_SSE),
    op2("andpd", 0x660f54, 0, OPC_MODRM, OPT_EA | OPT_SSE, OPT_SSE),
    op2("sqrtsd", 0xf20f51, 0, OPC_MODRM, OPT_EA | OPT_SSE, OPT_SSE),
    op2("movnti", 0x0fc3, 0, OPC_MODRM, OPT_REG, OPT_EA),
    op2("movntil", 0x0fc3, 0, OPC_MODRM, OPT_REG32, OPT_EA),
    op2("movntiq", 0x0fc3, 0, OPC_MODRM | OPC_48, OPT_REG64, OPT_EA),
    op1("prefetchnta", 0x0f18, 0, OPC_MODRM, OPT_EA),
    op1("prefetcht0", 0x0f18, 1, OPC_MODRM, OPT_EA),
    op1("prefetcht1", 0x0f18, 2, OPC_MODRM, OPT_EA),
    op1("prefetcht2", 0x0f18, 3, OPC_MODRM, OPT_EA),
    op1("prefetchw", 0x0f0d, 1, OPC_MODRM, OPT_EA),
    op0l("lfence", 0x0fae, 5, OPC_MODRM),
    op0l("mfence", 0x0fae, 6, OPC_MODRM),
    op0l("sfence", 0x0fae, 7, OPC_MODRM),
    op1("clflush", 0x0fae, 7, OPC_MODRM, OPT_EA),
    op0l("endbr64", 0xf30f1e, 7, OPC_MODRM),
];

// ============================================================================
// Token Range Constants
// ============================================================================

/// First token ID for assembly mnemonics (start of the assembler token range).
/// In the original C code, this was derived from the token enum position of
/// the first DEF_ASM entry.
pub const TOK_ASM_FIRST: u32 = 256;

/// Last token ID for assembly mnemonics (non-alternative encodings only).
/// Computed as TOK_ASM_FIRST + number of unique primary mnemonic entries.
pub const TOK_ASM_LAST: u32 = TOK_ASM_FIRST + X86_64_ASM_OPS.len() as u32 - 1;

/// Last token ID including all alternative encodings.
/// Same as TOK_ASM_LAST since alternatives share token IDs with their primary.
pub const TOK_ASM_ALLLAST: u32 = TOK_ASM_LAST;

// ============================================================================
// Lookup Functions
// ============================================================================

/// Look up the first instruction definition matching the given mnemonic name.
///
/// Returns `None` if no instruction with that name exists.
///
/// # Arguments
/// * `name` - The instruction mnemonic to look up (case-sensitive, lowercase expected)
///
/// # Examples
/// ```
/// use tcc_core::arch::x86_64::tokens::lookup_opcode;
/// let op = lookup_opcode("nop");
/// assert!(op.is_some());
/// ```
pub fn lookup_opcode(name: &str) -> Option<&'static AsmOpDef> {
    X86_64_ASM_OPS.iter().find(|op| op.name == name)
}

/// Look up all instruction definitions matching the given mnemonic name.
///
/// Multiple entries may exist for the same mnemonic when alternative encodings
/// are available (e.g., different operand combinations for `mov`).
///
/// # Arguments
/// * `name` - The instruction mnemonic to look up (case-sensitive, lowercase expected)
///
/// # Returns
/// A `Vec` of references to all matching `AsmOpDef` entries.
pub fn lookup_all_opcodes(name: &str) -> Vec<&'static AsmOpDef> {
    X86_64_ASM_OPS.iter().filter(|op| op.name == name).collect()
}

/// Look up a register definition by name.
///
/// Returns `None` if no register with that name exists.
///
/// # Arguments
/// * `name` - The register name to look up (case-sensitive, lowercase expected)
///
/// # Examples
/// ```
/// use tcc_core::arch::x86_64::tokens::register_from_name;
/// let reg = register_from_name("rax");
/// assert!(reg.is_some());
/// assert_eq!(reg.unwrap().encoding, 0);
/// ```
pub fn register_from_name(name: &str) -> Option<&'static RegisterDef> {
    REGISTER_TABLE.iter().find(|r| r.name == name)
}

/// Convert an `X86Instruction` enum variant to its mnemonic name string.
///
/// This delegates to the `mnemonic()` method on the enum.
///
/// # Arguments
/// * `instr` - The instruction variant to name
pub fn instruction_name(instr: X86Instruction) -> &'static str {
    instr.mnemonic()
}

/// Look up an `X86Instruction` variant from a mnemonic name string.
///
/// Returns `None` if the name does not correspond to any known instruction variant.
/// This only matches the base mnemonic names in the `X86Instruction` enum, not
/// suffixed forms (use `strip_suffix` first for suffixed names).
///
/// # Arguments
/// * `name` - The mnemonic name to look up (case-sensitive, lowercase expected)
pub fn instruction_from_name(name: &str) -> Option<X86Instruction> {
    // Linear search through all variants
    let variants = [
        X86Instruction::Clc,
        X86Instruction::Cld,
        X86Instruction::Cli,
        X86Instruction::Clts,
        X86Instruction::Cmc,
        X86Instruction::Lahf,
        X86Instruction::Sahf,
        X86Instruction::Pushfq,
        X86Instruction::Popfq,
        X86Instruction::Stc,
        X86Instruction::Std,
        X86Instruction::Sti,
        X86Instruction::Nop,
        X86Instruction::Pause,
        X86Instruction::Hlt,
        X86Instruction::Ret,
        X86Instruction::Retf,
        X86Instruction::Int3,
        X86Instruction::Into,
        X86Instruction::Iretq,
        X86Instruction::Syscall,
        X86Instruction::Sysret,
        X86Instruction::Sysenter,
        X86Instruction::Sysexit,
        X86Instruction::Cpuid,
        X86Instruction::Rdtsc,
        X86Instruction::Rdmsr,
        X86Instruction::Wrmsr,
        X86Instruction::Ud2,
        X86Instruction::Endbr64,
        X86Instruction::Mov,
        X86Instruction::Movabs,
        X86Instruction::Movsx,
        X86Instruction::Movzx,
        X86Instruction::Movsxd,
        X86Instruction::Lea,
        X86Instruction::Push,
        X86Instruction::Pop,
        X86Instruction::Xchg,
        X86Instruction::Add,
        X86Instruction::Sub,
        X86Instruction::Adc,
        X86Instruction::Sbb,
        X86Instruction::And,
        X86Instruction::Or,
        X86Instruction::Xor,
        X86Instruction::Cmp,
        X86Instruction::Test,
        X86Instruction::Inc,
        X86Instruction::Dec,
        X86Instruction::Not,
        X86Instruction::Neg,
        X86Instruction::Mul,
        X86Instruction::Imul,
        X86Instruction::Div,
        X86Instruction::Idiv,
        X86Instruction::Shl,
        X86Instruction::Shr,
        X86Instruction::Sar,
        X86Instruction::Rol,
        X86Instruction::Ror,
        X86Instruction::Rcl,
        X86Instruction::Rcr,
        X86Instruction::Shld,
        X86Instruction::Shrd,
        X86Instruction::Call,
        X86Instruction::Jmp,
        X86Instruction::Jo,
        X86Instruction::Jno,
        X86Instruction::Jb,
        X86Instruction::Jae,
        X86Instruction::Je,
        X86Instruction::Jne,
        X86Instruction::Jbe,
        X86Instruction::Ja,
        X86Instruction::Js,
        X86Instruction::Jns,
        X86Instruction::Jp,
        X86Instruction::Jnp,
        X86Instruction::Jl,
        X86Instruction::Jge,
        X86Instruction::Jle,
        X86Instruction::Jg,
        X86Instruction::Seto,
        X86Instruction::Setno,
        X86Instruction::Setb,
        X86Instruction::Setae,
        X86Instruction::Sete,
        X86Instruction::Setne,
        X86Instruction::Setbe,
        X86Instruction::Seta,
        X86Instruction::Sets,
        X86Instruction::Setns,
        X86Instruction::Setp,
        X86Instruction::Setnp,
        X86Instruction::Setl,
        X86Instruction::Setge,
        X86Instruction::Setle,
        X86Instruction::Setg,
        X86Instruction::Cmovo,
        X86Instruction::Cmovno,
        X86Instruction::Cmovb,
        X86Instruction::Cmovae,
        X86Instruction::Cmove,
        X86Instruction::Cmovne,
        X86Instruction::Cmovbe,
        X86Instruction::Cmova,
        X86Instruction::Cmovs,
        X86Instruction::Cmovns,
        X86Instruction::Cmovp,
        X86Instruction::Cmovnp,
        X86Instruction::Cmovl,
        X86Instruction::Cmovge,
        X86Instruction::Cmovle,
        X86Instruction::Cmovg,
        X86Instruction::Bsf,
        X86Instruction::Bsr,
        X86Instruction::Bt,
        X86Instruction::Bts,
        X86Instruction::Btr,
        X86Instruction::Btc,
        X86Instruction::Popcnt,
        X86Instruction::Tzcnt,
        X86Instruction::Lzcnt,
        X86Instruction::Fld,
        X86Instruction::Fst,
        X86Instruction::Fstp,
        X86Instruction::Fadd,
        X86Instruction::Fmul,
        X86Instruction::Fsub,
        X86Instruction::Fdiv,
        X86Instruction::Fxch,
        X86Instruction::Fucom,
        X86Instruction::Fucomi,
        X86Instruction::Fucomip,
        X86Instruction::Fcomi,
        X86Instruction::Fcomip,
    ];
    variants.iter().find(|v| v.mnemonic() == name).copied()
}

// ============================================================================
// Suffix Helper Functions
// ============================================================================

/// Append a byte suffix ('b') to the given mnemonic.
///
/// Returns a new `String` with 'b' appended, representing the byte-width
/// variant of the instruction (e.g., "mov" → "movb").
///
/// # Arguments
/// * `mnemonic` - The base instruction mnemonic
pub fn with_byte_suffix(mnemonic: &str) -> String {
    let mut s = String::with_capacity(mnemonic.len() + 1);
    s.push_str(mnemonic);
    s.push('b');
    s
}

/// Append a word suffix ('w') to the given mnemonic.
///
/// Returns a new `String` with 'w' appended, representing the word-width (16-bit)
/// variant of the instruction (e.g., "mov" → "movw").
///
/// # Arguments
/// * `mnemonic` - The base instruction mnemonic
pub fn with_word_suffix(mnemonic: &str) -> String {
    let mut s = String::with_capacity(mnemonic.len() + 1);
    s.push_str(mnemonic);
    s.push('w');
    s
}

/// Append a long suffix ('l') to the given mnemonic.
///
/// Returns a new `String` with 'l' appended, representing the long-width (32-bit)
/// variant of the instruction (e.g., "mov" → "movl").
///
/// # Arguments
/// * `mnemonic` - The base instruction mnemonic
pub fn with_long_suffix(mnemonic: &str) -> String {
    let mut s = String::with_capacity(mnemonic.len() + 1);
    s.push_str(mnemonic);
    s.push('l');
    s
}

/// Append a quad suffix ('q') to the given mnemonic.
///
/// Returns a new `String` with 'q' appended, representing the quad-width (64-bit)
/// variant of the instruction (e.g., "mov" → "movq").
/// This is an x86_64-specific suffix (NBWLX=5).
///
/// # Arguments
/// * `mnemonic` - The base instruction mnemonic
pub fn with_quad_suffix(mnemonic: &str) -> String {
    let mut s = String::with_capacity(mnemonic.len() + 1);
    s.push_str(mnemonic);
    s.push('q');
    s
}

/// Strip any operand-size suffix ('b', 'w', 'l', 'q') from the end of a mnemonic.
///
/// Returns the base mnemonic without the suffix. If the mnemonic does not end
/// with a recognized suffix, returns the original string unchanged.
///
/// # Arguments
/// * `mnemonic` - The potentially-suffixed instruction mnemonic
///
/// # Examples
/// ```
/// use tcc_core::arch::x86_64::tokens::strip_suffix;
/// assert_eq!(strip_suffix("movq"), "mov");
/// assert_eq!(strip_suffix("nop"), "nop");
/// ```
pub fn strip_suffix(mnemonic: &str) -> &str {
    if mnemonic.is_empty() {
        return mnemonic;
    }
    let bytes = mnemonic.as_bytes();
    let last = bytes[bytes.len() - 1];
    if last == b'b' || last == b'w' || last == b'l' || last == b'q' {
        // Verify the base (without suffix) is a known mnemonic or has length > 1
        // to avoid stripping suffixes from very short mnemonics that aren't actually suffixed
        let base = &mnemonic[..mnemonic.len() - 1];
        if !base.is_empty() {
            return base;
        }
    }
    mnemonic
}

/// Determine the operand size in bytes from a mnemonic suffix character.
///
/// Returns the size in bytes corresponding to the suffix:
/// - 'b' → 1 (byte)
/// - 'w' → 2 (word)
/// - 'l' → 4 (long/doubleword)
/// - 'q' → 8 (quad/quadword, x86_64 only)
///
/// Returns `None` if the character is not a recognized operand-size suffix.
///
/// # Arguments
/// * `suffix` - The suffix character to interpret
pub fn suffix_size(suffix: char) -> Option<u32> {
    match suffix {
        'b' => Some(1),
        'w' => Some(2),
        'l' => Some(4),
        'q' => Some(8),
        _ => None,
    }
}
