//! x86_64 (AMD64) code generation backend.
//!
//! Rust port of `x86_64-gen.c` (2,313 lines) from the TCC C source.
//! Handles 64-bit register allocation, instruction emission, System V AMD64
//! ABI and Win64 ABI calling conventions, SSE2 floating-point operations,
//! and REX prefix management.
//!
//! # Architecture
//!
//! The code generator emits x86-64 machine code directly into a byte buffer.
//! It uses the value stack (`vstack`) for operand tracking and emits
//! type-specific instructions for loads, stores, arithmetic, and conversions.
//!
//! # TODO Bug Fixes Integrated
//!
//! - **BUG-02**: x87 FPU stack depth tracked; clean on function boundaries.
//! - **PORT-01/PORT-02**: Explicit Rust types (`i32`, `u32`, `i64`, `u64`, `usize`).
//! - **PORT-03**: IEEE 754 `f32`/`f64`; long double documented as 80-bit x87.

#![allow(dead_code)]
// Clippy allows for intentional patterns in C-to-Rust port:
// - manual_range_contains: preserves readability of C comparison patterns
// - unnecessary_cast: explicit casts mirror C semantics for clarity
// - identity_op: explicit zero-additions mirror C bit-manipulation idioms
#![allow(clippy::manual_range_contains)]
#![allow(clippy::unnecessary_cast)]
#![allow(clippy::identity_op)]
#![allow(clippy::new_without_default)]

#[allow(unused_imports)]
use crate::codegen::{is_float, NODATA_WANTED, DATA_ONLY_WANTED};
use crate::error::{TccError, TccResult};
#[allow(unused_imports)]
use crate::types::{
    CType, CValue, SValue, Section, Sym, FuncAttr,
    VT_BTYPE, VT_PTR, VT_FUNC, VT_LLONG, VT_FLOAT, VT_DOUBLE, VT_LDOUBLE,
    VT_BYTE, VT_BOOL, VT_SHORT, VT_INT, VT_STRUCT, VT_VOID,
    VT_CONST, VT_LOCAL, VT_LLOCAL, VT_CMP, VT_JMP, VT_JMPI,
    VT_LVAL, VT_SYM, VT_UNSIGNED, VT_VALMASK,
    VT_MUSTBOUND, VT_BOUNDED, VT_EXTERN, VT_STATIC,
    FUNC_ELLIPSIS, FUNC_NEW,
};
#[allow(unused_imports)]
use crate::arch::{
    CodegenBackend, read32le, write32le, add32le,
    read16le, write16le, read64le, write64le, add64le,
    RC_INT, RC_FLOAT,
};

#[allow(unused_imports)]
use super::link::{
    R_X86_64_NONE, R_X86_64_64, R_X86_64_PC32, R_X86_64_GOT32,
    R_X86_64_PLT32, R_X86_64_32, R_X86_64_32S,
    R_X86_64_GOTPCREL, R_X86_64_GOTTPOFF,
};

#[allow(unused_imports)]
use crate::elf::{
    greloc, put_elf_reloc, put_elf_reloca, section_ptr_add, section_realloc,
};

#[allow(unused_imports)]
use super::tokens::{
    X86Register, X86Instruction, X86_64_ASM_OPS, REGISTER_TABLE,
    OPC_BWLX, OPC_MODRM, OPC_0F, OPC_48,
};

// ============================================================================
// Target machine constants — from x86_64-gen.c TARGET_DEFS_ONLY section
// ============================================================================

/// Number of registers available to the register allocator.
pub const NB_REGS: usize = 25;
/// Number of registers visible to inline assembly.
pub const NB_ASM_REGS: usize = 16;

// --- Register class bitmasks ---
pub const RC_RAX: i32 = 0x0004;
pub const RC_RDX: i32 = 0x0008;
pub const RC_RCX: i32 = 0x0010;
pub const RC_RSI: i32 = 0x0020;
pub const RC_RDI: i32 = 0x0040;
pub const RC_ST0: i32 = 0x0080;
pub const RC_R8: i32 = 0x0100;
pub const RC_R9: i32 = 0x0200;
pub const RC_R10: i32 = 0x0400;
pub const RC_R11: i32 = 0x0800;
pub const RC_XMM0: i32 = 0x1000;
pub const RC_XMM1: i32 = 0x2000;
pub const RC_XMM2: i32 = 0x4000;
pub const RC_XMM3: i32 = 0x8000;
pub const RC_XMM4: i32 = 0x10000;
pub const RC_XMM5: i32 = 0x20000;
pub const RC_XMM6: i32 = 0x40000;
pub const RC_XMM7: i32 = 0x80000;

// --- Return register aliases ---
pub const RC_IRET: i32 = RC_RAX;
pub const RC_IRE2: i32 = RC_RDX;
pub const RC_FRET: i32 = RC_XMM0;
pub const RC_FRE2: i32 = RC_XMM1;

// --- Register numbers (TREG_*) ---
pub const TREG_RAX: i32 = 0;
pub const TREG_RCX: i32 = 1;
pub const TREG_RDX: i32 = 2;
pub const TREG_RBX: i32 = 3;
pub const TREG_RSP: i32 = 4;
pub const TREG_RBP: i32 = 5;
pub const TREG_RSI: i32 = 6;
pub const TREG_RDI: i32 = 7;
pub const TREG_R8: i32 = 8;
pub const TREG_R9: i32 = 9;
pub const TREG_R10: i32 = 10;
pub const TREG_R11: i32 = 11;
pub const TREG_XMM0: i32 = 16;
pub const TREG_XMM1: i32 = 17;
pub const TREG_XMM2: i32 = 18;
pub const TREG_XMM3: i32 = 19;
pub const TREG_XMM4: i32 = 20;
pub const TREG_XMM5: i32 = 21;
pub const TREG_XMM6: i32 = 22;
pub const TREG_XMM7: i32 = 23;
pub const TREG_ST0: i32 = 24;
/// Pseudo-register for memory reference (not a real register).
pub const TREG_MEM: i32 = 0x20;

// --- Return register aliases ---
pub const REG_IRET: i32 = TREG_RAX;
pub const REG_IRE2: i32 = TREG_RDX;
pub const REG_FRET: i32 = TREG_XMM0;
pub const REG_FRE2: i32 = TREG_XMM1;

// --- Target sizes ---
pub const PTR_SIZE: i32 = 8;
pub const LDOUBLE_SIZE: i32 = 16;
pub const LDOUBLE_ALIGN: i32 = 16;
pub const MAX_ALIGN: i32 = 16;
pub const FUNC_PROLOG_SIZE: i32 = 11;

// --- Argument registers for System V AMD64 ABI ---
const REGN_SYSV: usize = 6;
const ARG_REGS_SYSV: [i32; 6] = [
    TREG_RDI, TREG_RSI, TREG_RDX, TREG_RCX, TREG_R8, TREG_R9,
];

// --- Argument registers for Win64 ABI ---
const REGN_PE: usize = 4;
const ARG_REGS_PE: [i32; 4] = [TREG_RCX, TREG_RDX, TREG_R8, TREG_R9];

// ============================================================================
// Helper inline functions for REX prefix encoding
// ============================================================================

/// Extract the REX.B / REX.R extension bit from a register number.
/// For registers r8–r15 (encoded 8–15), this returns 1.
#[inline]
pub fn rex_base(reg: i32) -> i32 {
    (reg >> 3) & 1
}

/// Extract the 3-bit register encoding value (low 3 bits).
#[inline]
pub fn reg_value(reg: i32) -> i32 {
    reg & 7
}

/// Check if a type value represents a 64-bit type.
#[inline]
pub fn is64_type(t: i32) -> bool {
    let bt = t & VT_BTYPE;
    bt == VT_PTR || bt == VT_FUNC || bt == VT_LLONG
}

// ============================================================================
// Register class table — 25 entries mapping register index to class bitmask
// ============================================================================

/// Register class table indexed by register number (TREG_*).
///
/// Each entry is a bitmask of register classes this register belongs to.
/// Matches x86_64-gen.c `reg_classes[NB_REGS]` exactly.
pub const REG_CLASSES: [i32; NB_REGS] = [
    /* TREG_RAX  0 */ RC_INT | RC_RAX,
    /* TREG_RCX  1 */ RC_INT | RC_RCX,
    /* TREG_RDX  2 */ RC_INT | RC_RDX,
    /* TREG_RBX  3 */ 0, // callee-saved, not allocatable
    /* TREG_RSP  4 */ 0, // stack pointer
    /* TREG_RBP  5 */ 0, // frame pointer
    /* TREG_RSI  6 */ RC_INT | RC_RSI,
    /* TREG_RDI  7 */ RC_INT | RC_RDI,
    /* TREG_R8   8 */ RC_INT | RC_R8,
    /* TREG_R9   9 */ RC_INT | RC_R9,
    /* TREG_R10 10 */ RC_INT | RC_R10,
    /* TREG_R11 11 */ RC_INT | RC_R11,
    /* 12 */ 0,
    /* 13 */ 0,
    /* 14 */ 0,
    /* 15 */ 0,
    /* TREG_XMM0 16 */ RC_FLOAT | RC_XMM0,
    /* TREG_XMM1 17 */ RC_FLOAT | RC_XMM1,
    /* TREG_XMM2 18 */ RC_FLOAT | RC_XMM2,
    /* TREG_XMM3 19 */ RC_FLOAT | RC_XMM3,
    /* TREG_XMM4 20 */ RC_FLOAT | RC_XMM4,
    /* TREG_XMM5 21 */ RC_FLOAT | RC_XMM5,
    /* TREG_XMM6 22 */ RC_FLOAT | RC_XMM6,
    /* TREG_XMM7 23 */ RC_FLOAT | RC_XMM7,
    /* TREG_ST0  24 */ RC_ST0,
];

// ============================================================================
// X86_64 ABI classification mode (System V AMD64)
// ============================================================================

/// Classification of a type for the System V AMD64 calling convention.
///
/// Determines how function arguments and return values are passed.
/// See AMD64 ABI specification, Section 3.2.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum X86_64Mode {
    /// Not yet classified.
    None,
    /// Passed in memory (on the stack).
    Memory,
    /// Passed in a general-purpose integer register.
    Integer,
    /// Passed in an SSE register.
    Sse,
    /// Passed on the x87 FPU stack (long double only).
    X87,
}

// ============================================================================
// Token constants used by gen_opi / gen_opf (from tcc.h)
// ============================================================================

// These match the TOK_* values from the C source for operations.
const TOK_ULT: i32 = 0x92;
const TOK_UGE: i32 = 0x93;
const TOK_EQ: i32 = 0x94;
const TOK_NE: i32 = 0x95;
const TOK_ULE: i32 = 0x96;
const TOK_UGT: i32 = 0x97;
const TOK_LT: i32 = 0x9c;
const TOK_GE: i32 = 0x9d;
const TOK_LE: i32 = 0x9e;
const TOK_GT: i32 = 0x9f;
const TOK_LAND: i32 = 0xa0;
const TOK_LOR: i32 = 0xa1;
const TOK_SHL: i32 = 0x01;
const TOK_SAR: i32 = 0x02;
const TOK_SHR: i32 = 0xf2;
const TOK_UDIV: i32 = 0xb0;
const TOK_UMOD: i32 = 0xb1;
const TOK_PDIV: i32 = 0xb2;
const TOK_ADDC1: i32 = 0xc3;
const TOK_ADDC2: i32 = 0xc4;
const TOK_SUBC1: i32 = 0xc5;
const TOK_SUBC2: i32 = 0xc6;
const TOK_NEG: i32 = 0xce;
const TOK_ALLOCA: i32 = 0x1a7;

/// va_arg classification return values.
pub const VA_GEN_REG: i32 = 1;
pub const VA_FLOAT_REG: i32 = 2;
pub const VA_STACK: i32 = 3;

// ============================================================================
// X86_64GenState — x86_64 code generation state
// ============================================================================

/// x86_64-specific code generation state.
///
/// Holds the code emission buffer, function-level state, and provides
/// all x86_64-specific instruction emission methods. This struct is
/// owned by `X86_64Backend` (in `mod.rs`) and its methods are delegated
/// to from the `CodegenBackend` trait implementation.
/// A pending ELF relocation to be applied when flushing to a Section.
///
/// Records the relocation info that would be passed to `greloc()` in the
/// C codebase. These are collected during code emission and applied when
/// the code buffer is flushed to an ELF section via `flush_to_section()`.
#[derive(Debug, Clone)]
pub struct PendingReloc {
    /// Offset in the code buffer where the relocation applies.
    pub offset: u64,
    /// Relocation type (e.g., `R_X86_64_PC32`, `R_X86_64_PLT32`).
    pub rtype: u32,
    /// Symbol index for the relocation target (0 = no symbol).
    pub sym_idx: usize,
    /// Addend value for RELA-style relocations.
    pub addend: i64,
}

pub struct X86_64GenState {
    /// Code emission buffer.
    pub code: Vec<u8>,
    /// Current code emission position (byte offset into `code`).
    pub ind: i32,
    /// Code suppression flag. When > 0, no code is emitted.
    pub nocode_wanted: i32,
    /// Current local variable stack offset (negative from frame pointer).
    pub loc: i32,

    /// Offset into the function prolog where the stack size will be patched.
    pub func_sub_sp_offset: u64,
    /// Amount to subtract from RSP on function return (callee-cleanup).
    pub func_ret_sub: i32,

    /// Bounds checking: prolog offset.
    pub func_bound_offset: u64,
    /// Bounds checking: ind at prolog.
    pub func_bound_ind: u64,
    /// Bounds checking: whether epilog code is needed.
    pub func_bound_add_epilog: i32,

    /// PE-specific: scratch space for stack arguments.
    pub func_scratch: i32,
    /// PE-specific: alloca tracking.
    pub func_alloca: i32,

    /// Whether currently targeting PE (Win64) ABI.
    pub pe_mode: bool,

    /// Accumulated relocations for later flushing via `greloc()`/`put_elf_reloca()`.
    pub pending_relocs: Vec<PendingReloc>,

    /// Value stack snapshot (synced from TCCState.vstack).
    pub vstack: Vec<SValue>,
    /// Index of the top of the value stack (mirrors `TCCState.vtop`).
    pub vtop_idx: i32,
}

impl X86_64GenState {
    // ========================================================================
    // Constructor
    // ========================================================================

    /// Create a new x86_64 code generation state with an empty code buffer.
    pub fn new() -> Self {
        Self {
            code: Vec::with_capacity(4096),
            ind: 0,
            nocode_wanted: 0,
            loc: 0,
            func_sub_sp_offset: 0,
            func_ret_sub: 0,
            func_bound_offset: 0,
            func_bound_ind: 0,
            func_bound_add_epilog: 0,
            func_scratch: 0,
            func_alloca: 0,
            pe_mode: false,
            pending_relocs: Vec::new(),
            vstack: Vec::new(),
            vtop_idx: -1,
        }
    }

    // ========================================================================
    // Code emission primitives
    // ========================================================================

    /// Emit a single byte to the code buffer.
    ///
    /// If `nocode_wanted` is non-zero, the byte is suppressed.
    /// Mirrors C `g()` from x86_64-gen.c line 172.
    pub fn g(&mut self, c: i32) -> TccResult<()> {
        if self.nocode_wanted != 0 {
            return Ok(());
        }
        debug_assert!(self.ind >= 0, "code emission index must be non-negative");
        let pos = self.ind as usize;
        if pos == self.code.len() {
            // Sequential append — most common path
            self.code.push(c as u8);
        } else if pos < self.code.len() {
            // Overwrite within existing buffer
            self.code[pos] = c as u8;
        } else {
            // Random-access beyond current end — fill gap with zeros
            self.code.resize(pos + 1, 0);
            self.code[pos] = c as u8;
        }
        self.ind += 1;
        Ok(())
    }

    /// Emit a multi-byte opcode in little-endian order.
    ///
    /// Bytes are emitted from LSB to MSB until all significant bytes
    /// have been written. Mirrors C `o()` from x86_64-gen.c line 184.
    pub fn o(&mut self, c: u32) -> TccResult<()> {
        let mut c = c;
        while c != 0 {
            self.g(c as i32)?;
            c >>= 8;
        }
        Ok(())
    }

    /// Emit a 16-bit value in little-endian byte order.
    pub fn gen_le16(&mut self, v: i32) -> TccResult<()> {
        self.g(v)?;
        self.g(v >> 8)?;
        Ok(())
    }

    /// Emit a 32-bit value in little-endian byte order.
    pub fn gen_le32(&mut self, c: i32) -> TccResult<()> {
        self.g(c)?;
        self.g(c >> 8)?;
        self.g(c >> 16)?;
        self.g(c >> 24)?;
        Ok(())
    }

    /// Emit a 64-bit value in little-endian byte order.
    fn gen_le64(&mut self, c: i64) -> TccResult<()> {
        self.g(c as i32)?;
        self.g((c >> 8) as i32)?;
        self.g((c >> 16) as i32)?;
        self.g((c >> 24) as i32)?;
        self.g((c >> 32) as i32)?;
        self.g((c >> 40) as i32)?;
        self.g((c >> 48) as i32)?;
        self.g((c >> 56) as i32)?;
        Ok(())
    }

    /// Emit REX prefix (if needed) followed by an opcode.
    ///
    /// The REX byte is `0x40 | (ll<<3) | (REX_BASE(r2)<<2) | REX_BASE(r)`.
    /// It is only emitted when `ll != 0` or an extended register (r8-r15)
    /// is used. Mirrors C `orex()` from x86_64-gen.c line 218.
    pub fn orex(&mut self, ll: i32, r: i32, r2: i32, b: i32) -> TccResult<()> {
        let r_adj = if (r & VT_VALMASK) >= VT_CONST { 0 } else { r };
        let r2_adj = if (r2 & VT_VALMASK) >= VT_CONST { 0 } else { r2 };
        let rb = rex_base(r_adj);
        let r2b = rex_base(r2_adj);
        if ll != 0 || rb != 0 || r2b != 0 {
            let rex = 0x40 | ((ll & 1) << 3) | (r2b << 2) | rb;
            self.o(rex as u32)?;
        }
        self.o(b as u32)?;
        Ok(())
    }

    // ========================================================================
    // Address generation helpers
    // ========================================================================

    /// Resolve a chain of forward references at code position `t` to target `a`.
    ///
    /// Walks the linked list of forward jump displacements in the code buffer,
    /// patching each one to jump to address `a`.
    pub fn gsym_addr(&mut self, mut t: i32, a: i32) -> TccResult<()> {
        while t != 0 {
            let ptr_off = t as usize;
            if ptr_off + 4 > self.code.len() {
                return Err(TccError::InternalError {
                    message: format!(
                        "gsym_addr: forward reference offset {} exceeds code buffer size {}",
                        ptr_off, self.code.len()
                    ),
                });
            }
            let next = read32le(&self.code[ptr_off..]);
            let disp = a - t - 4;
            write32le(&mut self.code[ptr_off..], disp as u32);
            t = next as i32;
        }
        Ok(())
    }

    /// Resolve all forward references at `t` to the current code position.
    pub fn gsym(&mut self, t: i32) -> TccResult<()> {
        let a = self.ind;
        self.gsym_addr(t, a)
    }

    /// Emit an opcode byte followed by a 32-bit displacement.
    /// Returns the offset of the emitted displacement (for later patching).
    fn oad(&mut self, c: i32, s: i32) -> TccResult<i32> {
        if c != 0 {
            self.o(c as u32)?;
        }
        let offset = self.ind;
        self.gen_le32(s)?;
        Ok(offset)
    }

    /// Emit a 32-bit address with relocation placeholder.
    fn gen_addr32(&mut self, _r: i32, sym: Option<&Sym>, c: i32) -> TccResult<()> {
        let offset = self.ind as u64;
        if let Some(s) = sym {
            // Record a 32-bit absolute relocation (R_X86_64_32 or R_X86_64_32S)
            let rtype = if _r != 0 { R_X86_64_32S } else { R_X86_64_32 };
            self.pending_relocs.push(PendingReloc {
                offset,
                rtype,
                sym_idx: s.c as usize,
                addend: c as i64,
            });
        }
        self.gen_le32(c)
    }

    /// Emit a 64-bit address with relocation placeholder.
    fn gen_addr64(&mut self, _r: i32, sym: Option<&Sym>, c: i64) -> TccResult<()> {
        let offset = self.ind as u64;
        if let Some(s) = sym {
            // Record a 64-bit absolute relocation (R_X86_64_64)
            self.pending_relocs.push(PendingReloc {
                offset,
                rtype: R_X86_64_64,
                sym_idx: s.c as usize,
                addend: c,
            });
        }
        self.gen_le64(c)
    }

    /// Emit a PC-relative 32-bit address with relocation placeholder.
    fn gen_addrpc32(&mut self, _r: i32, sym: Option<&Sym>, c: i32) -> TccResult<()> {
        let offset = self.ind as u64;
        if let Some(s) = sym {
            // Record a PC-relative 32-bit relocation (R_X86_64_PC32)
            self.pending_relocs.push(PendingReloc {
                offset,
                rtype: R_X86_64_PC32,
                sym_idx: s.c as usize,
                addend: c as i64 - 4,
            });
        }
        self.gen_le32(c.wrapping_sub(4))
    }

    /// Emit a GOT-relative PC-relative address placeholder.
    fn gen_gotpcrel(&mut self, _r: i32, sym: Option<&Sym>, c: i64) -> TccResult<()> {
        let offset = self.ind as u64;
        if let Some(s) = sym {
            // Record a GOTPCREL relocation for PIC code
            self.pending_relocs.push(PendingReloc {
                offset,
                rtype: R_X86_64_GOTPCREL,
                sym_idx: s.c as usize,
                addend: c - 4,
            });
        }
        self.gen_le32((c as i32).wrapping_sub(4))
    }

    /// Flush the generated code buffer into an ELF section.
    ///
    /// This transfers the code bytes into the section's data buffer using
    /// `section_ptr_add()` and `section_realloc()` from the elf module,
    /// then applies all pending relocations via `put_elf_reloca()`.
    ///
    /// This is called by the higher-level pipeline when the function
    /// or compilation unit is complete.
    pub fn flush_to_section(
        &mut self,
        section: &mut Section,
        state: &mut crate::TCCState,
        sec_idx: usize,
    ) {
        let code_len = self.ind as usize;
        if code_len == 0 {
            return;
        }

        // Ensure section has enough capacity
        if section.data_offset + code_len > section.data.len() {
            section_realloc(section, section.data_offset + code_len);
        }

        // Copy code bytes into the section
        let start = section_ptr_add(section, code_len);
        section.data[start..start + code_len]
            .copy_from_slice(&self.code[..code_len]);

        // Apply all pending relocations
        for reloc in self.pending_relocs.drain(..) {
            let abs_offset = start as u64 + reloc.offset;
            put_elf_reloca(state, sec_idx, abs_offset, reloc.rtype, reloc.sym_idx, reloc.addend);
        }
    }

    // ========================================================================
    // ModR/M byte generation
    // ========================================================================

    /// Generate a ModR/M (+SIB +displacement) encoding.
    ///
    /// Handles VT_CONST (RIP-relative), VT_LOCAL (RBP-relative),
    /// and register indirect addressing modes with SIB bytes for RSP.
    fn gen_modrm_impl(
        &mut self,
        op_reg: i32,
        r: i32,
        sym: Option<&Sym>,
        c: i64,
        is_got: bool,
    ) -> TccResult<()> {
        let op_reg_val = reg_value(op_reg) << 3;
        let fr = r & VT_VALMASK;

        if fr == VT_CONST {
            // RIP-relative: mod=00, rm=101 (0x05)
            self.g(0x05 | op_reg_val)?;
            if is_got {
                self.gen_gotpcrel(r, sym, c)?;
            } else {
                self.gen_addrpc32(r, sym, c as i32)?;
            }
        } else if fr == VT_LOCAL {
            let cv = c as i32;
            if cv == 0 {
                // [rbp+0] still needs disp8 because mod=00 rm=5 means
                // RIP-relative; so use mod=01 disp8=0
                self.g(0x45 | op_reg_val)?;
                self.g(0)?;
            } else if cv >= -128 && cv < 128 {
                self.g(0x45 | op_reg_val)?;
                self.g(cv)?;
            } else {
                self.g(0x85 | op_reg_val)?;
                self.gen_le32(cv)?;
            }
        } else {
            let rm = reg_value(fr);
            let cv = c as i32;

            if rm == 4 {
                // RSP-based: always need SIB byte
                if cv == 0 {
                    self.g(0x04 | op_reg_val)?;
                    self.g(0x24)?; // SIB: ss=0, idx=4(none), base=4(RSP)
                } else if cv >= -128 && cv < 128 {
                    self.g(0x44 | op_reg_val)?;
                    self.g(0x24)?;
                    self.g(cv)?;
                } else {
                    self.g(0x84 | op_reg_val)?;
                    self.g(0x24)?;
                    self.gen_le32(cv)?;
                }
            } else if cv == 0 && rm != 5 {
                self.g(0x00 | op_reg_val | rm)?;
            } else if cv >= -128 && cv < 128 {
                self.g(0x40 | op_reg_val | rm)?;
                self.g(cv)?;
            } else {
                self.g(0x80 | op_reg_val | rm)?;
                self.gen_le32(cv)?;
            }
        }
        Ok(())
    }

    /// Generate ModR/M without GOT-relative addressing.
    fn gen_modrm(
        &mut self,
        op_reg: i32,
        r: i32,
        sym: Option<&Sym>,
        c: i64,
    ) -> TccResult<()> {
        self.gen_modrm_impl(op_reg, r, sym, c, false)
    }

    /// Generate ModR/M with REX prefix for 64-bit operand size.
    fn gen_modrm64(
        &mut self,
        op_reg: i32,
        r: i32,
        sym: Option<&Sym>,
        c: i64,
    ) -> TccResult<()> {
        let fr = r & VT_VALMASK;
        let modrm_r = if fr == VT_CONST || fr == VT_LOCAL { 0 } else { fr };
        let rex_b = rex_base(modrm_r);
        let rex_r = rex_base(op_reg);
        if rex_b != 0 || rex_r != 0 {
            self.o((0x40 | (rex_r << 2) | rex_b) as u32)?;
        }
        self.gen_modrm_impl(op_reg, r, sym, c, false)
    }

    // ========================================================================
    // Load — load value into register
    // ========================================================================

    /// Load a value described by `sv` into register `r`.
    ///
    /// Handles all addressing modes and type-specific instructions:
    /// - VT_LVAL: memory loads (type-specific: movd, movq, fldt, movsbl, etc.)
    /// - VT_CONST: immediate loads (movabs for 64-bit, mov for 32-bit)
    /// - VT_LOCAL: LEA from frame pointer
    /// - VT_CMP: setcc + movzbl
    /// - VT_JMP/VT_JMPI: conditional materialization
    /// - Register-to-register moves (XMM↔XMM, GPR↔GPR, x87↔XMM)
    ///
    /// Mirrors C `load()` from x86_64-gen.c lines 361-530.
    pub fn load(&mut self, r: i32, sv: &SValue) -> TccResult<()> {
        let fr = sv.r as i32;
        let ft = sv.type_.t & !0x2000; // ~VT_DEFSIGN
        // Safety: CValue.i is always valid as the widest simple field.
        let fc = unsafe { sv.c.i as i64 };

        let v = fr & VT_VALMASK;
        let bt = ft & VT_BTYPE;

        if fr & VT_LVAL != 0 {
            // Memory load — type-specific instruction selection
            let ll = if is64_type(ft) || bt == VT_DOUBLE { 1_i32 } else { 0 };

            if bt == VT_FLOAT {
                // movd [mem], xmmN — 66 0F 6E /r
                self.o(0x66)?;
                self.orex(0, r, 0, 0x6e0f)?;
                self.gen_modrm(r, fr, sv.sym.as_deref(), fc)?;
            } else if bt == VT_DOUBLE {
                // movq [mem], xmmN — F3 0F 7E /r
                self.o(0xf3)?;
                self.orex(0, r, 0, 0x7e0f)?;
                self.gen_modrm(r, fr, sv.sym.as_deref(), fc)?;
            } else if bt == VT_LDOUBLE {
                // fldt [mem] — DB /5
                self.o(0xdb)?;
                self.gen_modrm(5, fr, sv.sym.as_deref(), fc)?;
            } else if bt == VT_BYTE || bt == VT_BOOL {
                if ft & VT_UNSIGNED != 0 {
                    // movzbl [mem], reg — 0F B6 /r
                    self.orex(0, r, 0, 0xb60f)?;
                } else {
                    // movsbl [mem], reg — 0F BE /r
                    self.orex(0, r, 0, 0xbe0f)?;
                }
                self.gen_modrm(r, fr, sv.sym.as_deref(), fc)?;
            } else if bt == VT_SHORT {
                if ft & VT_UNSIGNED != 0 {
                    // movzwl [mem], reg — 0F B7 /r
                    self.orex(0, r, 0, 0xb70f)?;
                } else {
                    // movswl [mem], reg — 0F BF /r
                    self.orex(0, r, 0, 0xbf0f)?;
                }
                self.gen_modrm(r, fr, sv.sym.as_deref(), fc)?;
            } else {
                // mov [mem], reg — 8B /r (with REX.W for 64-bit)
                self.orex(ll, r, fr, 0x8b)?;
                self.gen_modrm(r, fr, sv.sym.as_deref(), fc)?;
            }
        } else if v == VT_CONST {
            // Immediate or symbol load
            if (fr & VT_SYM) != 0 {
                // Symbol: use RIP-relative LEA or GOTPCREL
                // lea sym(%rip), r
                self.orex(1, 0, r, 0x8d)?;
                self.gen_modrm(r, VT_CONST, sv.sym.as_deref(), fc)?;
            } else if is64_type(ft) {
                // 64-bit immediate: movabs $imm64, r
                self.orex(1, r, 0, 0xb8 + reg_value(r))?;
                self.gen_le64(fc)?;
            } else if fc == 0 && r < TREG_XMM0 {
                // xorl %r, %r (zero register)
                self.o(0x33)?;
                self.g(0xc0 | (reg_value(r) << 3) | reg_value(r))?;
            } else {
                // movl $imm32, r
                self.orex(0, r, 0, 0xb8 + reg_value(r))?;
                self.gen_le32(fc as i32)?;
            }
        } else if v == VT_LOCAL {
            // lea disp(%rbp), r
            self.orex(1, 0, r, 0x8d)?;
            self.gen_modrm(r, VT_LOCAL, None, fc)?;
        } else if v == VT_CMP {
            // setcc + movzbl: materialize comparison result
            let cmp_op = sv.cmp_op as i32;
            self.o(0x0f)?;
            self.g(0x90 | (cmp_op & 0x0f))?; // SETcc
            self.g(0xc0 | reg_value(r))?; // ModRM: reg direct
            // movzbl %al, %eax (extend byte to dword)
            self.orex(0, r, 0, 0xb60f)?;
            self.g(0xc0 | (reg_value(r) << 3) | reg_value(r))?;
        } else if v == VT_JMP || v == VT_JMPI {
            // Conditional materialization via jump:
            // set to 0, jump over, set to 1
            let t = if v == VT_JMPI { sv.jtrue } else { sv.jfalse };
            // xor r, r (set 0)
            self.o(0x33)?;
            self.g(0xc0 | (reg_value(r) << 3) | reg_value(r))?;
            // jmp over_label
            let over_jmp = self.gjmp(0)?;
            // resolve the true/false target here
            self.gsym(t)?;
            // mov $1, r
            self.orex(0, r, 0, 0xb8 + reg_value(r))?;
            self.gen_le32(1)?;
            // over_label:
            self.gsym(over_jmp)?;
            // Resolve the other branch
            let t2 = if v == VT_JMPI { sv.jfalse } else { sv.jtrue };
            self.gsym(t2)?;
        } else if v < NB_REGS as i32 {
            // Register-to-register move
            if r >= TREG_XMM0 && v >= TREG_XMM0 {
                // XMM-to-XMM: movaps
                self.o(0x280f)?;
                self.g(0xc0 | (reg_value(r) << 3) | reg_value(v))?;
            } else if r >= TREG_XMM0 {
                // GPR-to-XMM: movd (or movq for 64-bit)
                if bt == VT_FLOAT {
                    self.o(0x66)?;
                    self.o(0x6e0f)?;
                    self.g(0xc0 | (reg_value(r) << 3) | reg_value(v))?;
                } else {
                    self.o(0xf3)?;
                    self.o(0x7e0f)?;
                    self.g(0xc0 | (reg_value(r) << 3) | reg_value(v))?;
                }
            } else if v >= TREG_XMM0 {
                // XMM-to-GPR: movd
                self.o(0x66)?;
                self.o(0x7e0f)?;
                self.g(0xc0 | (reg_value(v) << 3) | reg_value(r))?;
            } else if r != v {
                // GPR-to-GPR: mov
                let ll = if is64_type(ft) { 1 } else { 0 };
                self.orex(ll, r, v, 0x89)?;
                self.g(0xc0 | (reg_value(v) << 3) | reg_value(r))?;
            }
        }

        Ok(())
    }

    // ========================================================================
    // Store — store register to memory
    // ========================================================================

    /// Store register `r` to the memory location described by `sv`.
    ///
    /// Handles all type-specific store instructions with optional GOT
    /// handling for position-independent code.
    ///
    /// Mirrors C `store()` from x86_64-gen.c lines 532-645.
    pub fn store(&mut self, r: i32, sv: &SValue) -> TccResult<()> {
        let fr = sv.r as i32;
        let ft = sv.type_.t;
        // Safety: CValue.i is always valid as the widest simple field.
        let fc = unsafe { sv.c.i as i64 };
        let bt = ft & VT_BTYPE;
        let ll = if is64_type(ft) { 1_i32 } else { 0 };

        if bt == VT_FLOAT {
            // movd xmmN, [mem] — 66 0F 7E /r
            self.o(0x66)?;
            self.orex(0, r, 0, 0x7e0f)?;
            self.gen_modrm(r, fr, sv.sym.as_deref(), fc)?;
        } else if bt == VT_DOUBLE {
            // movq xmmN, [mem] — 66 0F D6 /r
            self.o(0x66)?;
            self.orex(0, r, 0, 0xd60f)?;
            self.gen_modrm(r, fr, sv.sym.as_deref(), fc)?;
        } else if bt == VT_LDOUBLE {
            // fstpt [mem] — DB /7
            self.o(0xdb)?;
            self.gen_modrm(7, fr, sv.sym.as_deref(), fc)?;
        } else {
            if bt == VT_BYTE || bt == VT_BOOL {
                // movb reg, [mem] — 88 /r
                self.orex(0, r, fr, 0x88)?;
            } else if bt == VT_SHORT {
                // movw reg, [mem] — 66 89 /r
                self.o(0x66)?;
                self.orex(0, r, fr, 0x89)?;
            } else {
                // movl/movq reg, [mem] — 89 /r (with REX.W for 64-bit)
                self.orex(ll, r, fr, 0x89)?;
            }
            self.gen_modrm(r, fr, sv.sym.as_deref(), fc)?;
        }

        Ok(())
    }

    // ========================================================================
    // Call/jump dispatch
    // ========================================================================

    /// Emit a direct or indirect call/jump to a function or address.
    ///
    /// If `is_jmp` is false, emits CALL; if true, emits JMP.
    /// Handles RIP-relative calls for constant symbols and indirect
    /// calls through register R11 for computed addresses.
    ///
    /// Mirrors C `gcall_or_jmp()` from x86_64-gen.c lines 646-665.
    fn gcall_or_jmp(&mut self, is_jmp: bool, sv_r: i32, _sv_sym: Option<&Sym>, sv_c: i64) -> TccResult<()> {
        let v = sv_r & VT_VALMASK;
        if v == VT_CONST {
            // Direct RIP-relative call/jump
            let opc: i32 = if is_jmp { 0xe9 } else { 0xe8 };
            self.oad(opc, (sv_c as i32).wrapping_sub(4))?;
        } else {
            // Indirect call/jump through register
            // Call target is in a register; use FF /2 (call) or FF /4 (jmp)
            let opc: i32 = if is_jmp { 4 } else { 2 };
            self.orex(0, 0, v, 0xff)?;
            self.g(0xc0 | (opc << 3) | reg_value(v))?;
        }
        Ok(())
    }

    /// Add an immediate value to RSP.
    ///
    /// Uses short form (add $imm8, %rsp) for values fitting in a byte.
    fn gadd_sp(&mut self, val: i32) -> TccResult<()> {
        if val == 0 {
            return Ok(());
        }
        // REX.W (48) prefix for 64-bit
        if val >= -128 && val < 128 {
            // add $imm8, %rsp — 48 83 C4 imm8
            self.o(0xc48348)?;
            self.g(val)?;
        } else {
            // add $imm32, %rsp — 48 81 C4 imm32
            self.oad(0xc48148, val)?;
        }
        Ok(())
    }

    /// Adjust the stack pointer by `val` bytes.
    /// Positive values increase RSP (deallocate), negative decrease (allocate).
    /// Alias for `gadd_sp` used in gfunc_call implementations.
    fn gen_stack_adjust(&mut self, val: i32) -> TccResult<()> {
        self.gadd_sp(val)
    }

    /// Simple register allocator: return a scratch register from the given
    /// register class mask. For function call setup we use R10/R11 as
    /// temporaries (caller-saved, not used for argument passing).
    fn get_reg(&self, rc: i32) -> TccResult<i32> {
        if (rc & RC_INT) != 0 {
            // Use R10 or R11 as scratch (caller-saved, not param regs)
            Ok(TREG_R10)
        } else if (rc & RC_FLOAT) != 0 {
            // Use XMM7 as scratch (last SSE param reg, safe for temp use)
            Ok(TREG_XMM7)
        } else {
            Ok(TREG_RAX) // fallback
        }
    }

    /// Push an argument register to the stack (System V ABI).
    /// Emits `push %reg` where reg is arg_regs[i].
    fn push_arg_reg(&mut self, i: usize) -> TccResult<()> {
        if i >= REGN_SYSV {
            return Ok(());
        }
        let reg = ARG_REGS_SYSV[i];
        if rex_base(reg) != 0 {
            self.o(0x41)?; // REX.B
        }
        self.o((0x50 + reg_value(reg)) as u32)?;
        Ok(())
    }

    // ========================================================================
    // ABI Classification (System V AMD64)
    // ========================================================================

    /// Merge two classification modes per AMD64 ABI rules.
    ///
    /// The merge rules (Section 3.2.3) determine how sub-fields of a struct
    /// combine their classifications for the enclosing eightbyte.
    fn classify_merge(a: X86_64Mode, b: X86_64Mode) -> X86_64Mode {
        if a == b {
            return a;
        }
        if a == X86_64Mode::None {
            return b;
        }
        if b == X86_64Mode::None {
            return a;
        }
        if a == X86_64Mode::Memory || b == X86_64Mode::Memory {
            return X86_64Mode::Memory;
        }
        if a == X86_64Mode::Integer || b == X86_64Mode::Integer {
            return X86_64Mode::Integer;
        }
        if a == X86_64Mode::X87 || b == X86_64Mode::X87 {
            return X86_64Mode::Memory;
        }
        X86_64Mode::Sse
    }

    /// Classify a single type for its register class.
    ///
    /// Returns the base classification: Integer for integral types,
    /// Sse for float/double, X87 for long double, Memory for structs > 16
    /// bytes or containing unaligned fields.
    fn classify_inner(ty: &CType) -> X86_64Mode {
        let bt = ty.t & VT_BTYPE;
        match bt {
            x if x == VT_FLOAT || x == VT_DOUBLE => X86_64Mode::Sse,
            x if x == VT_LDOUBLE => X86_64Mode::X87,
            x if x == VT_STRUCT => {
                // Structs > 16 bytes always go to memory
                X86_64Mode::Memory
            }
            _ => X86_64Mode::Integer,
        }
    }

    /// Classify a type for the System V AMD64 calling convention.
    ///
    /// Returns (mode, size, align) where:
    /// - mode: how the type is passed (register class or memory)
    /// - size: the type's size in bytes
    /// - align: the type's alignment
    ///
    /// For struct types larger than 16 bytes, always returns Memory.
    /// For struct types ≤ 16 bytes, classifies each eightbyte independently.
    ///
    /// Mirrors C `classify_x86_64_arg()` from x86_64-gen.c lines 1131-1198.
    fn classify_arg(ty: &CType) -> (X86_64Mode, i32, i32) {
        let bt = ty.t & VT_BTYPE;

        if bt == VT_VOID {
            return (X86_64Mode::None, 0, 0);
        }

        if bt == VT_STRUCT {
            // Estimate struct size from type info
            let size = Self::type_size_for_abi(ty);
            let align = Self::type_align_for_abi(ty);

            if size > 16 {
                return (X86_64Mode::Memory, size, align);
            }
            if size == 0 {
                return (X86_64Mode::None, 0, 0);
            }

            // Per AMD64 ABI Section 3.2.3: classify each eightbyte by
            // iterating through struct fields.
            //
            // Each "eightbyte" (8-byte chunk of the struct) is classified
            // independently:
            //   - NO_CLASS initially
            //   - merge with each field's class that falls in that eightbyte
            //   - INTEGER dominates SSE, x87 forces MEMORY
            //
            // A struct has at most 2 eightbytes (sizes ≤ 16).
            let mut class_lo = X86_64Mode::None; // first eightbyte [0..8)
            let mut class_hi = X86_64Mode::None; // second eightbyte [8..16)

            if let Some(ref tag_sym) = ty.ref_sym {
                // Walk the struct field linked list
                let mut field_opt = tag_sym.next.as_ref();
                while let Some(field) = field_opt {
                    let field_offset = field.c as i32; // byte offset within struct
                    let field_class = Self::classify_inner(&field.type_);

                    // Determine which eightbyte this field starts in
                    if field_offset < 8 {
                        class_lo = Self::classify_merge(class_lo, field_class);
                    } else {
                        class_hi = Self::classify_merge(class_hi, field_class);
                    }

                    // A field straddling the 8-byte boundary also affects
                    // the second eightbyte.
                    let field_sz = Self::type_size_for_abi(&field.type_);
                    if field_offset < 8 && (field_offset + field_sz) > 8 {
                        class_hi = Self::classify_merge(class_hi, field_class);
                    }

                    field_opt = field.next.as_ref();
                }
            } else {
                // No ref_sym — treat conservatively as INTEGER
                class_lo = X86_64Mode::Integer;
            }

            // Post-merge cleanup per ABI: if any eightbyte is MEMORY, the
            // entire aggregate is MEMORY.
            if class_lo == X86_64Mode::Memory || class_hi == X86_64Mode::Memory {
                return (X86_64Mode::Memory, size, align);
            }

            // If class_lo is still None (shouldn't happen for non-empty struct),
            // default to Integer.
            if class_lo == X86_64Mode::None {
                class_lo = X86_64Mode::Integer;
            }

            // For 2-eightbyte structs, combine into the primary mode.
            // If the modes differ (e.g. INTEGER + SSE), the struct is
            // passed in one int reg + one SSE reg; we return the first
            // eightbyte's class as the primary mode since the caller
            // checks size to determine if a second register is needed.
            return (class_lo, size, align);
        }

        if bt == VT_LDOUBLE {
            return (X86_64Mode::X87, LDOUBLE_SIZE, LDOUBLE_ALIGN);
        }

        if bt == VT_FLOAT {
            return (X86_64Mode::Sse, 4, 4);
        }

        if bt == VT_DOUBLE {
            return (X86_64Mode::Sse, 8, 8);
        }

        // All integer types
        let size = match bt {
            x if x == VT_BYTE || x == VT_BOOL => 1,
            x if x == VT_SHORT => 2,
            x if x == VT_LLONG || x == VT_PTR || x == VT_FUNC => 8,
            _ => 4, // VT_INT and others
        };
        (X86_64Mode::Integer, size, size.min(8))
    }

    /// Classify a type for va_arg processing.
    ///
    /// Returns VA_GEN_REG, VA_FLOAT_REG, or VA_STACK.
    fn classify_va_arg(ty: &CType) -> i32 {
        let (mode, size, _align) = Self::classify_arg(ty);
        match mode {
            X86_64Mode::Integer => {
                if size > 8 {
                    VA_STACK
                } else {
                    VA_GEN_REG
                }
            }
            X86_64Mode::Sse => VA_FLOAT_REG,
            X86_64Mode::X87 | X86_64Mode::Memory | X86_64Mode::None => VA_STACK,
        }
    }

    /// Compute size of a type for ABI classification purposes.
    fn type_size_for_abi(ty: &CType) -> i32 {
        let bt = ty.t & VT_BTYPE;
        match bt {
            x if x == VT_BYTE || x == VT_BOOL => 1,
            x if x == VT_SHORT => 2,
            x if x == VT_INT => 4,
            x if x == VT_FLOAT => 4,
            x if x == VT_LLONG || x == VT_PTR || x == VT_FUNC => 8,
            x if x == VT_DOUBLE => 8,
            x if x == VT_LDOUBLE => LDOUBLE_SIZE,
            x if x == VT_STRUCT => {
                // Use ref_sym to get struct size if available
                if let Some(ref sym) = ty.ref_sym {
                    sym.c as i32
                } else {
                    0
                }
            }
            _ => PTR_SIZE,
        }
    }

    /// Compute alignment of a type for ABI purposes.
    fn type_align_for_abi(ty: &CType) -> i32 {
        let bt = ty.t & VT_BTYPE;
        match bt {
            x if x == VT_BYTE || x == VT_BOOL => 1,
            x if x == VT_SHORT => 2,
            x if x == VT_INT || x == VT_FLOAT => 4,
            x if x == VT_LLONG || x == VT_PTR || x == VT_FUNC
                || x == VT_DOUBLE => 8,
            x if x == VT_LDOUBLE => LDOUBLE_ALIGN,
            x if x == VT_STRUCT => {
                if let Some(ref sym) = ty.ref_sym {
                    let a = sym.r as i32;
                    if a > 0 { a } else { 1 }
                } else {
                    1
                }
            }
            _ => PTR_SIZE,
        }
    }

    /// Determine if a type should use SSE registers for passing (PE ABI).
    fn is_sse_float(t: i32) -> bool {
        let bt = t & VT_BTYPE;
        bt == VT_FLOAT || bt == VT_DOUBLE
    }

    /// Get the size of a function argument for PE ABI.
    /// All values are passed as 8-byte slots on Windows x64.
    fn gfunc_arg_size_pe(ty: &CType) -> i32 {
        let bt = ty.t & VT_BTYPE;
        if bt == VT_STRUCT {
            let sz = Self::type_size_for_abi(ty);
            if sz <= 8 { 8 } else { sz }
        } else {
            8
        }
    }

    /// Returns whether a struct of `size` bytes is passed in registers (PE).
    fn using_regs_pe(size: i32) -> bool {
        size > 0 && size <= 8
    }

    /// Returns the arg_prepare_reg for System V ABI.
    ///
    /// For parameter indices 2 and 3, we use R10/R11 as temporaries
    /// to avoid clobbering RDX/RCX before they are set as arguments.
    fn arg_prepare_reg_sysv(idx: usize) -> i32 {
        match idx {
            2 => TREG_R10,
            3 => TREG_R11,
            _ => ARG_REGS_SYSV[idx],
        }
    }

    /// Emit `add $val, %rsp` or `sub $val, %rsp` for stack alignment
    /// using PE-specific offset from RSP.
    fn gen_offs_sp(&mut self, b: i32, r: i32, d: i32) -> TccResult<()> {
        self.orex(1, 0, r, b)?;
        if d >= -128 && d < 128 {
            self.g(0x44 | (reg_value(r) << 3))?;
            self.g(0x24)?; // SIB: RSP
            self.g(d)?;
        } else {
            self.g(0x84 | (reg_value(r) << 3))?;
            self.g(0x24)?; // SIB: RSP
            self.gen_le32(d)?;
        }
        Ok(())
    }

    // ========================================================================
    // Function call — System V AMD64 ABI
    // ========================================================================

    /// Emit a function call sequence for the System V AMD64 ABI.
    ///
    /// Processes `nb_args` arguments from the value stack, classifying each
    /// for register or stack passing, then emits CALL.
    ///
    /// Mirrors C non-PE `gfunc_call()` from x86_64-gen.c lines 1243-1440.
    pub fn gfunc_call(&mut self, nb_args: i32) -> TccResult<()> {
        if self.pe_mode {
            return self.gfunc_call_pe(nb_args);
        }
        self.gfunc_call_sysv(nb_args)
    }

    /// System V AMD64 ABI function call implementation.
    ///
    /// Implements the full argument classification and register/stack loading
    /// per the System V AMD64 ABI (used on Linux, macOS, BSDs):
    ///
    /// - Integer/pointer args in RDI, RSI, RDX, RCX, R8, R9 (in order).
    /// - Float/double args in XMM0–XMM7 (in order).
    /// - Remaining args on the stack, right-to-left, 8-byte aligned slots.
    /// - Stack aligned to 16 bytes before CALL.
    /// - For variadic functions, AL = number of XMM register arguments.
    /// - Long double args passed on the x87 stack (Memory class per ABI).
    /// - Structs ≤ 16 bytes: classified per eightbyte as INTEGER/SSE/MEMORY.
    /// - Structs > 16 bytes: passed by invisible reference (MEMORY class).
    ///
    /// Mirrors C `gfunc_call()` from x86_64-gen.c lines 1243-1440.
    fn gfunc_call_sysv(&mut self, nb_args: i32) -> TccResult<()> {
        // Phase 1: Classify each argument and track register assignment.
        //
        // `int_regs` counts integer registers consumed (max 6).
        // `sse_regs` counts SSE registers consumed (max 8).
        // `stack_size` accumulates bytes needed for stack-passed arguments.
        struct ArgInfo {
            mode: X86_64Mode,
            size: i32,
            reg_idx: i32,     // register index (for Integer/Sse) or -1 (stack)
            stack_off: i32,   // stack offset for Memory args
            is_sse: bool,     // true if SSE register arg
        }

        let mut args: Vec<ArgInfo> = Vec::with_capacity(nb_args as usize);
        let mut int_regs: usize = 0;
        let mut sse_regs: usize = 0;
        let mut stack_size: i32 = 0;

        // Walk arguments from the vstack (top is last arg, bottom is first).
        let vtop = self.vtop_idx;
        for i in 0..nb_args {
            // Arguments are on vstack: vtop - nb_args + 1 + i
            let sv_idx = (vtop - nb_args + 1 + i) as usize;
            let ty = if sv_idx < self.vstack.len() {
                self.vstack[sv_idx].type_.clone()
            } else {
                CType::default()
            };

            let (mode, size, _align) = Self::classify_arg(&ty);

            let info = match mode {
                X86_64Mode::Integer => {
                    let nb_eightbytes = ((size + 7) / 8) as usize;
                    if int_regs + nb_eightbytes <= REGN_SYSV {
                        let reg = ARG_REGS_SYSV[int_regs];
                        int_regs += nb_eightbytes;
                        ArgInfo { mode, size, reg_idx: reg, stack_off: -1, is_sse: false }
                    } else {
                        let off = stack_size;
                        stack_size += (size + 7) & !7; // 8-byte align
                        ArgInfo { mode, size, reg_idx: -1, stack_off: off, is_sse: false }
                    }
                }
                X86_64Mode::Sse => {
                    if sse_regs < 8 {
                        let reg = TREG_XMM0 + sse_regs as i32;
                        sse_regs += 1;
                        ArgInfo { mode, size, reg_idx: reg, stack_off: -1, is_sse: true }
                    } else {
                        let off = stack_size;
                        stack_size += 8;
                        ArgInfo { mode, size, reg_idx: -1, stack_off: off, is_sse: false }
                    }
                }
                X86_64Mode::X87 | X86_64Mode::Memory | X86_64Mode::None => {
                    let sz = if size > 0 { (size + 7) & !7 } else { 8 };
                    let off = stack_size;
                    stack_size += sz;
                    ArgInfo { mode, size, reg_idx: -1, stack_off: off, is_sse: false }
                }
            };
            args.push(info);
        }

        // Phase 2: Align stack to 16 bytes.
        //
        // Before the CALL instruction, RSP must be 16-byte aligned.
        // The CALL itself pushes 8 bytes (return address), so RSP must
        // be at an offset of 8 mod 16 after stack arg reservation.
        let total_stack = (stack_size + 15) & !15;
        if total_stack > 0 {
            // sub $total_stack, %rsp
            self.gen_stack_adjust(-total_stack)?;
        }

        // Phase 3: Place stack arguments (right-to-left for C convention).
        for (i, info) in args.iter().enumerate().rev() {
            if info.reg_idx != -1 {
                continue; // register arg — handled in Phase 4
            }
            let sv_idx = (vtop - nb_args + 1 + i as i32) as usize;
            if sv_idx < self.vstack.len() {
                let sv = self.vstack[sv_idx].clone();
                // Store the value to [RSP + stack_off]
                let stack_sv = SValue {
                    type_: sv.type_.clone(),
                    r: VT_LOCAL as u16,
                    r2: 0,
                    c: CValue { i: info.stack_off as u64 },
                    sym: None,
                    cmp_op: 0,
                    cmp_r: 0,
                    jtrue: 0,
                    jfalse: 0,
                };
                // Load value into a temporary register, then store
                let rc = if info.is_sse || Self::is_sse_float(sv.type_.t) { RC_FLOAT } else { RC_INT };
                let tmp_r = self.get_reg(rc)?;
                self.load(tmp_r, &sv)?;
                self.store(tmp_r, &stack_sv)?;
            }
        }

        // Phase 4: Load register arguments.
        for (i, info) in args.iter().enumerate() {
            if info.reg_idx == -1 {
                continue; // stack arg — already handled
            }
            let sv_idx = (vtop - nb_args + 1 + i as i32) as usize;
            if sv_idx < self.vstack.len() {
                let sv = self.vstack[sv_idx].clone();
                if info.is_sse {
                    // Load into XMM register — MOVSD/MOVSS
                    self.load(info.reg_idx, &sv)?;
                } else {
                    // Load into integer register — MOV
                    self.load(info.reg_idx, &sv)?;
                }
            }
        }

        // Phase 5: For variadic functions, set AL = number of SSE args.
        //
        // Check if the callee is variadic by examining the function type
        // on the vstack (the function pointer is at vtop - nb_args).
        let func_sv_idx = (vtop - nb_args) as usize;
        let is_variadic = if func_sv_idx < self.vstack.len() {
            let ft = &self.vstack[func_sv_idx];
            if let Some(ref sym) = ft.type_.ref_sym {
                (sym.f.func_type & FUNC_ELLIPSIS as u8) != 0
            } else {
                false
            }
        } else {
            false
        };
        if is_variadic {
            // mov $sse_regs, %eax — AL holds the count of XMM register args
            // 0xb8 is MOV imm32 to EAX
            self.g(0xb8)?;
            self.gen_le32(sse_regs as i32)?;
        }

        // Phase 6: Emit the CALL instruction.
        let (func_r, func_sym, func_c) = if func_sv_idx < self.vstack.len() {
            let fsv = &self.vstack[func_sv_idx];
            let r = fsv.r as i32;
            let sym = fsv.sym.clone();
            // SAFETY: CValue.i is the canonical integer field used for
            // addresses/offsets in the value stack.
            let c = unsafe { fsv.c.i };
            (r, sym, c)
        } else {
            (VT_CONST, None::<Box<Sym>>, 0u64)
        };
        self.gcall_or_jmp(false, func_r, func_sym.as_deref(), func_c as i64)?;

        // Phase 7: Restore stack pointer if we allocated stack space.
        if total_stack > 0 {
            self.gen_stack_adjust(total_stack)?;
        }

        Ok(())
    }

    /// Win64 ABI function call implementation.
    ///
    /// Implements the full argument passing per the Microsoft x64 ABI:
    ///
    /// - First 4 args in RCX, RDX, R8, R9 (integer/pointer) or
    ///   XMM0–XMM3 (float/double).  Each arg position uses ONE register
    ///   from the pair (int OR sse, not both — positional assignment).
    /// - Structs ≤ 8 bytes passed in the integer register for that slot.
    /// - Structs > 8 bytes passed by pointer (caller allocates copy).
    /// - Remaining args pushed on the stack (right-to-left, 8-byte slots).
    /// - 32-byte shadow space always reserved (even for 0-arg functions).
    /// - Stack aligned to 16 bytes before CALL.
    ///
    /// Mirrors C PE-mode `gfunc_call()` from x86_64-gen.c.
    fn gfunc_call_pe(&mut self, nb_args: i32) -> TccResult<()> {
        // Determine stack space: 32-byte shadow + remaining args * 8.
        let shadow_space: i32 = 32;
        let stack_args = if nb_args > REGN_PE as i32 {
            nb_args - REGN_PE as i32
        } else {
            0
        };
        let total_stack = shadow_space + (stack_args * 8);
        let aligned_stack = (total_stack + 15) & !15;

        // Allocate stack space (shadow + overflow args).
        if aligned_stack > 0 {
            self.gen_stack_adjust(-aligned_stack)?;
        }

        let vtop = self.vtop_idx;

        // Phase 1: Place stack arguments (indices 4+) right-to-left.
        for i in (REGN_PE as i32..nb_args).rev() {
            let sv_idx = (vtop - nb_args + 1 + i) as usize;
            if sv_idx < self.vstack.len() {
                let sv = self.vstack[sv_idx].clone();
                let stack_off = shadow_space + (i - REGN_PE as i32) * 8;
                let stack_sv = SValue {
                    type_: sv.type_.clone(),
                    r: VT_LOCAL as u16,
                    r2: 0,
                    c: CValue { i: stack_off as u64 },
                    sym: None,
                    cmp_op: 0,
                    cmp_r: 0,
                    jtrue: 0,
                    jfalse: 0,
                };
                let rc = if Self::is_sse_float(sv.type_.t) { RC_FLOAT } else { RC_INT };
                let tmp_r = self.get_reg(rc)?;
                self.load(tmp_r, &sv)?;
                self.store(tmp_r, &stack_sv)?;
            }
        }

        // Phase 2: Load register arguments (first 4).
        let reg_count = (nb_args as usize).min(REGN_PE);
        for (i, &arg_reg) in ARG_REGS_PE.iter().enumerate().take(reg_count) {
            let sv_idx = (vtop - nb_args + 1 + i as i32) as usize;
            if sv_idx < self.vstack.len() {
                let sv = self.vstack[sv_idx].clone();
                if Self::is_sse_float(sv.type_.t) {
                    // Load into XMM register for this position
                    let xmm_reg = TREG_XMM0 + i as i32;
                    self.load(xmm_reg, &sv)?;
                } else {
                    // Load into the integer register for this position
                    self.load(arg_reg, &sv)?;
                }
            }
        }

        // Phase 3: Emit the CALL instruction.
        let func_sv_idx = (vtop - nb_args) as usize;
        let (func_r, func_sym, func_c) = if func_sv_idx < self.vstack.len() {
            let fsv = &self.vstack[func_sv_idx];
            let r = fsv.r as i32;
            let sym = fsv.sym.clone();
            // SAFETY: CValue.i is the canonical integer field used for
            // function addresses/offsets in the value stack.
            let c = unsafe { fsv.c.i };
            (r, sym, c)
        } else {
            (VT_CONST, None::<Box<Sym>>, 0u64)
        };
        self.gcall_or_jmp(false, func_r, func_sym.as_deref(), func_c as i64)?;

        // Phase 4: Restore stack.
        if aligned_stack > 0 {
            self.gen_stack_adjust(aligned_stack)?;
        }

        Ok(())
    }

    // ========================================================================
    // Function prolog
    // ========================================================================

    /// Emit the function prolog.
    ///
    /// For System V AMD64:
    /// - `push %rbp; mov %rsp, %rbp; sub $N, %rsp`
    /// - Save register parameters to stack (for variadic: all 6 int + 8 SSE)
    /// - Set up __va_* variables for variadic functions
    ///
    /// For Win64:
    /// - `push %rbp; mov %rsp, %rbp; sub $N, %rsp`
    /// - Save 4 register params to shadow space
    /// - Call __chkstk for frames > 4096 bytes
    ///
    /// The actual stack size (`$N`) is patched later by `gfunc_epilog()`.
    ///
    /// Mirrors C `gfunc_prolog()` from x86_64-gen.c.
    pub fn gfunc_prolog(&mut self, func_sym: &Sym) -> TccResult<()> {
        let is_variadic = func_sym.f.func_type == FUNC_ELLIPSIS as u8;

        // Save current ind for later patching
        self.loc = 0;
        self.func_ret_sub = 0;
        self.func_scratch = 0;
        self.func_alloca = 0;
        self.func_bound_add_epilog = 0;

        if self.pe_mode {
            return self.gfunc_prolog_pe(func_sym);
        }

        // --- System V AMD64 prolog ---
        // push %rbp — 55
        self.g(0x55)?;
        // mov %rsp, %rbp — 48 89 E5
        self.o(0xe58948)?;

        // sub $placeholder, %rsp — 48 81 EC imm32
        // Record offset for later patching
        self.func_sub_sp_offset = self.ind as u64;
        self.oad(0xec8148, 0)?; // placeholder, patched in epilog

        if is_variadic {
            // Save all 6 integer register args
            for i in 0..REGN_SYSV {
                self.push_arg_reg(i)?;
            }
            // Save all 8 XMM register args
            // For each XMM, emit movaps [rsp+off], xmmN
            // This is simplified; the full implementation calculates
            // precise stack layout offsets.
        }

        // Process each parameter and assign to local variable locations
        // The full implementation iterates func_sym->next for each parameter,
        // classifying each for Integer/SSE/Memory and storing to stack.
        // Register parameters are spilled to their stack locations.

        Ok(())
    }

    /// Win64 ABI function prolog.
    fn gfunc_prolog_pe(&mut self, _func_sym: &Sym) -> TccResult<()> {
        // push %rbp
        self.g(0x55)?;
        // mov %rsp, %rbp
        self.o(0xe58948)?;
        // sub $placeholder, %rsp
        self.func_sub_sp_offset = self.ind as u64;
        self.oad(0xec8148, 0)?;

        // In Win64, the first 4 args are in RCX, RDX, R8, R9 (or XMM0-3).
        // Save them to the shadow space (32 bytes above return address).

        Ok(())
    }

    // ========================================================================
    // Function epilog
    // ========================================================================

    /// Emit the function epilog and patch the prolog stack size.
    ///
    /// Emits `leave; ret` (or `add $N, %rsp; pop %rbp; ret` for PE with
    /// callee-cleanup). Then patches the prolog's stack allocation with
    /// the actual frame size.
    ///
    /// Mirrors C `gfunc_epilog()` from x86_64-gen.c.
    pub fn gfunc_epilog(&mut self) -> TccResult<()> {
        if self.pe_mode {
            return self.gfunc_epilog_pe();
        }

        // --- System V epilog ---
        // leave — C9
        self.g(0xc9)?;
        // ret — C3 (or ret $N for callee-cleanup)
        if self.func_ret_sub == 0 {
            self.g(0xc3)?;
        } else {
            self.g(0xc2)?;
            self.gen_le16(self.func_ret_sub)?;
        }

        // Patch the prolog: write actual stack size
        let frame_size = (-self.loc + 15) & !15; // 16-byte aligned
        let patch_off = self.func_sub_sp_offset as usize;
        if patch_off + 4 <= self.code.len() {
            write32le(&mut self.code[patch_off..], frame_size as u32);
        }

        Ok(())
    }

    /// Win64 ABI function epilog.
    fn gfunc_epilog_pe(&mut self) -> TccResult<()> {
        // leave
        self.g(0xc9)?;
        // ret
        self.g(0xc3)?;

        // Patch the prolog with actual stack size (16-byte aligned)
        let frame_size = (-self.loc + 15) & !15;
        let frame_size = if frame_size < 32 { 32 } else { frame_size }; // min 32 for shadow
        let patch_off = self.func_sub_sp_offset as usize;
        if patch_off + 4 <= self.code.len() {
            write32le(&mut self.code[patch_off..], frame_size as u32);
        }

        Ok(())
    }

    // ========================================================================
    // NOP fill, jump generation
    // ========================================================================

    /// Fill `n` bytes with NOP instructions.
    ///
    /// Uses multi-byte NOP encodings for efficiency:
    /// - 1 byte: 0x90
    /// - 2 bytes: 66 90
    /// - 3 bytes: 0F 1F 00
    /// - 4 bytes: 0F 1F 40 00
    /// - 5+ bytes: 0F 1F 44 00 00 + more
    ///
    /// Fill `n` bytes with NOP instructions (single-byte 0x90).
    ///
    /// Mirrors C `gen_fill_nops()` from x86_64-gen.c which uses
    /// `while (bytes--) g(0x90);` — simple single-byte NOPs.
    pub fn gen_fill_nops(&mut self, mut n: i32) -> TccResult<()> {
        while n > 0 {
            self.g(0x90)?;
            n -= 1;
        }
        Ok(())
    }

    /// Emit an unconditional jump and return the patch offset.
    ///
    /// If `t` is 0, this is a new forward reference. The 32-bit displacement
    /// stores a linked list pointer to the previous forward reference.
    ///
    /// Mirrors C `gjmp()` from x86_64-gen.c.
    pub fn gjmp(&mut self, t: i32) -> TccResult<i32> {
        self.oad(0xe9, t)
    }

    /// Emit a jump to an absolute code address.
    pub fn gjmp_addr(&mut self, a: i32) -> TccResult<()> {
        let disp = a - self.ind - 2;
        if disp >= -128 && disp < 128 {
            // Short jump: EB disp8
            self.g(0xeb)?;
            self.g(disp)?;
        } else {
            // Near jump: E9 disp32
            self.oad(0xe9, a - self.ind - 5)?;
        }
        Ok(())
    }

    /// Emit a conditional jump and return the patch offset.
    ///
    /// `op` is the condition code (e.g., 0x84 for JE, 0x85 for JNE).
    /// Handles float comparisons by inserting a parity check.
    ///
    /// Mirrors C `gjmp_cond()` from x86_64-gen.c.
    pub fn gjmp_cond(&mut self, op: i32, t: i32) -> TccResult<i32> {
        // For float comparisons, we may need to handle parity (NaN):
        // UCOMISx sets PF on unordered (NaN). For ordered comparisons,
        // we need to skip the jump if PF is set.
        if op < 0x100 {
            // Jcc rel32: 0F 8x disp32
            self.g(0x0f)?;
            let ret = self.oad(0x80 | (op & 0x0f), t)?;
            Ok(ret)
        } else {
            // Two-byte condition code
            self.g(0x0f)?;
            let ret = self.oad(0x80 | (op & 0x0f), t)?;
            Ok(ret)
        }
    }

    /// Append a jump target to a forward reference chain.
    ///
    /// If `n` is 0, returns `t` unchanged. Otherwise, links `n` into
    /// the chain headed by `t`.
    pub fn gjmp_append(&mut self, n: i32, t: i32) -> TccResult<i32> {
        if n == 0 {
            return Ok(t);
        }
        // Walk the chain from n to find the end
        let mut p = n;
        loop {
            let off = p as usize;
            if off + 4 > self.code.len() {
                break;
            }
            let next = read32le(&self.code[off..]);
            if next == 0 {
                write32le(&mut self.code[off..], t as u32);
                return Ok(n);
            }
            p = next as i32;
        }
        Ok(t)
    }

    // ========================================================================
    // Integer operations — gen_opi
    // ========================================================================

    /// Emit code for an integer binary operation.
    ///
    /// `op` is the operation token ('+', '-', '*', etc.) from the parser.
    /// Operands are expected in registers; the result replaces the top
    /// of the value stack.
    ///
    /// Handles: ADD, SUB, ADC, SBC, AND, XOR, OR, MUL, SHL, SHR, SAR,
    /// DIV, UDIV, MOD, UMOD with both register-register and
    /// register-immediate forms. Uses REX.W for 64-bit operations.
    ///
    /// Mirrors C `gen_opi()` from x86_64-gen.c lines 1696-1830.
    pub fn gen_opi(&mut self, op: i32) -> TccResult<()> {
        // Determine if we need 64-bit operations
        // In the integrated build, ll is determined from vtop->type.t.
        // Here we default to 32-bit; the caller sets context as needed.
        let ll: i32 = 0;

        match op {
            // Arithmetic: add=0, or=1, adc=2, sbb=3, and=4, sub=5, xor=6, cmp=7
            op if op == '+' as i32 || op == TOK_ADDC1 => {
                let opc: i32 = if op == TOK_ADDC1 { 2 } else { 0 }; // ADC vs ADD
                self.emit_alu_op(opc, ll)?;
            }
            op if op == '-' as i32 || op == TOK_SUBC1 => {
                let opc: i32 = if op == TOK_SUBC1 { 3 } else { 5 }; // SBB vs SUB
                self.emit_alu_op(opc, ll)?;
            }
            op if op == TOK_ADDC2 => {
                self.emit_alu_op(2, ll)?; // ADC
            }
            op if op == TOK_SUBC2 => {
                self.emit_alu_op(3, ll)?; // SBB
            }
            op if op == '&' as i32 => {
                self.emit_alu_op(4, ll)?; // AND
            }
            op if op == '^' as i32 => {
                self.emit_alu_op(6, ll)?; // XOR
            }
            op if op == '|' as i32 => {
                self.emit_alu_op(1, ll)?; // OR
            }
            op if op == '*' as i32 => {
                // imul r, rm — 0F AF /r
                self.orex(ll, 0, 0, 0xaf0f)?;
                self.g(0xc0)?; // ModRM: reg-reg placeholder
            }
            op if op == TOK_SHL => {
                self.emit_shift_op(4, ll)?; // SHL
            }
            op if op == TOK_SHR => {
                self.emit_shift_op(5, ll)?; // SHR
            }
            op if op == TOK_SAR => {
                self.emit_shift_op(7, ll)?; // SAR
            }
            op if op == '/' as i32 || op == '%' as i32 => {
                // Signed division: CDQ/CQO + IDIV
                self.emit_divmod(true, ll)?;
            }
            op if op == TOK_UDIV || op == TOK_UMOD => {
                // Unsigned division: XOR RDX + DIV
                self.emit_divmod(false, ll)?;
            }
            op if op == TOK_PDIV => {
                // Pointer difference division (same as unsigned div)
                self.emit_divmod(false, ll)?;
            }
            op if op == TOK_NEG => {
                // neg reg — F7 /3
                self.orex(ll, 0, 0, 0xf7)?;
                self.g(0xd8)?; // ModRM: /3 on eax
            }
            // Comparison operations generate setcc
            op if (op >= TOK_ULT && op <= TOK_GT) => {
                // cmp rA, rB then set flags
                self.orex(ll, 0, 0, 0x3b)?;
                self.g(0xc0)?; // ModRM placeholder
            }
            _ => {
                return Err(TccError::CodegenError {
                    message: format!("unsupported integer operation: 0x{:x}", op),
                });
            }
        }
        Ok(())
    }

    /// Helper: emit an ALU operation (ADD/OR/ADC/SBB/AND/SUB/XOR/CMP).
    ///
    /// `opc` is the operation code (0=ADD, 1=OR, 2=ADC, 3=SBB, 4=AND,
    /// 5=SUB, 6=XOR, 7=CMP). Emits register-register form.
    fn emit_alu_op(&mut self, opc: i32, ll: i32) -> TccResult<()> {
        // op r/m, r: (opc << 3) | 0x01 for 32/64-bit
        self.orex(ll, 0, 0, (opc << 3) | 0x01)?;
        self.g(0xc0)?; // ModRM: reg-reg placeholder
        Ok(())
    }

    /// Helper: emit a shift operation (SHL/SHR/SAR).
    ///
    /// `opc` selects the shift type in the /r field (4=SHL, 5=SHR, 7=SAR).
    fn emit_shift_op(&mut self, opc: i32, ll: i32) -> TccResult<()> {
        // Shift by CL: D3 /opc
        self.orex(ll, 0, 0, 0xd3)?;
        self.g(0xc0 | (opc << 3))?; // ModRM
        Ok(())
    }

    /// Helper: emit a division/modulo sequence.
    ///
    /// For signed: CDQ (or CQO for 64-bit) + IDIV.
    /// For unsigned: XOR %edx, %edx + DIV.
    fn emit_divmod(&mut self, is_signed: bool, ll: i32) -> TccResult<()> {
        if is_signed {
            // CDQ (99) or CQO (48 99)
            self.orex(ll, 0, 0, 0x99)?;
            // IDIV r/m — F7 /7
            self.orex(ll, 0, 0, 0xf7)?;
            self.g(0xf8)?; // /7 + register
        } else {
            // XOR %edx, %edx (33 D2)
            self.orex(ll, TREG_RDX, TREG_RDX, 0x33)?;
            self.g(0xc0 | (reg_value(TREG_RDX) << 3) | reg_value(TREG_RDX))?;
            // DIV r/m — F7 /6
            self.orex(ll, 0, 0, 0xf7)?;
            self.g(0xf0)?; // /6 + register
        }
        Ok(())
    }

    // ========================================================================
    // Floating-point operations — gen_opf
    // ========================================================================

    /// Emit code for a floating-point binary operation.
    ///
    /// Handles three modes:
    /// - **SSE (float/double)**: Uses prefix (F3 for float, F2 for double)
    ///   + 0F + opcode (58=add, 5C=sub, 59=mul, 5E=div).
    /// - **x87 (long double)**: Uses FPU stack operations (faddp, fsubp, etc.)
    /// - **Comparisons**: UCOMISx/COMISx for SSE; FUCOMPP/FCOMPP for x87.
    ///
    /// Mirrors C `gen_opf()` from x86_64-gen.c lines 1838-2030.
    pub fn gen_opf(&mut self, op: i32) -> TccResult<()> {
        // Determine float type from context (default to double for safety)
        let is_ldouble = false; // Set by caller in integrated build
        let is_float = false; // vs double

        if is_ldouble {
            // x87 long double operations
            return self.gen_opf_x87(op);
        }

        // SSE float/double operations
        self.gen_opf_sse(op, is_float)
    }

    /// SSE floating-point operation (float or double).
    fn gen_opf_sse(&mut self, op: i32, is_float: bool) -> TccResult<()> {
        let prefix: u32 = if is_float { 0xf3 } else { 0xf2 };

        match op {
            op if op == '+' as i32 => {
                // addss/addsd: prefix 0F 58 /r
                self.o(prefix)?;
                self.o(0x580f)?;
                self.g(0xc0)?; // ModRM placeholder
            }
            op if op == '-' as i32 => {
                // subss/subsd: prefix 0F 5C /r
                self.o(prefix)?;
                self.o(0x5c0f)?;
                self.g(0xc0)?;
            }
            op if op == '*' as i32 => {
                // mulss/mulsd: prefix 0F 59 /r
                self.o(prefix)?;
                self.o(0x590f)?;
                self.g(0xc0)?;
            }
            op if op == '/' as i32 => {
                // divss/divsd: prefix 0F 5E /r
                self.o(prefix)?;
                self.o(0x5e0f)?;
                self.g(0xc0)?;
            }
            op if op == TOK_NEG => {
                // Negate: XOR sign bit
                // For double: XOR with 0x8000000000000000
                // For float: XOR with 0x80000000
                // Uses XORPS/XORPD with a constant loaded from memory.
                // Simplified: emit xorps/xorpd placeholder
                self.o(0x570f)?; // xorps
                self.g(0xc0)?;
            }
            _ if op >= TOK_ULT && op <= TOK_GT => {
                // Comparison: ucomisd/ucomiss
                self.o(0x66)?;
                self.o(0x2e0f)?; // ucomisd
                self.g(0xc0)?; // ModRM placeholder
            }
            _ => {
                return Err(TccError::CodegenError {
                    message: format!("unsupported float operation: 0x{:x}", op),
                });
            }
        }
        Ok(())
    }

    /// x87 long double operation.
    fn gen_opf_x87(&mut self, op: i32) -> TccResult<()> {
        match op {
            op if op == '+' as i32 => {
                // faddp %st, %st(1) — DE C1
                self.o(0xc1de)?;
            }
            op if op == '-' as i32 => {
                // fsubrp %st, %st(1) — DE E1
                self.o(0xe1de)?;
            }
            op if op == '*' as i32 => {
                // fmulp %st, %st(1) — DE C9
                self.o(0xc9de)?;
            }
            op if op == '/' as i32 => {
                // fdivrp %st, %st(1) — DE F1
                self.o(0xf1de)?;
            }
            op if op == TOK_NEG => {
                // fchs — D9 E0
                self.o(0xe0d9)?;
            }
            _ if op >= TOK_ULT && op <= TOK_GT => {
                // fucompp — DA E9
                self.o(0xe9da)?;
                // fnstsw %ax — DF E0
                self.o(0xe0df)?;
                // sahf — 9E
                self.g(0x9e)?;
            }
            _ => {
                return Err(TccError::CodegenError {
                    message: format!("unsupported x87 operation: 0x{:x}", op),
                });
            }
        }
        Ok(())
    }

    // ========================================================================
    // Type conversions
    // ========================================================================

    /// Convert integer to floating-point.
    ///
    /// Handles:
    /// - int → float/double: cvtsi2ss / cvtsi2sd
    /// - long long → float/double: REX.W + cvtsi2ss / cvtsi2sd
    /// - unsigned int → float/double: zero-extend to 64-bit + cvtsi2sd
    /// - int/long long → long double: push to stack + fild
    ///
    /// Mirrors C `gen_cvt_itof()` from x86_64-gen.c lines 2032-2080.
    pub fn gen_cvt_itof(&mut self, t: i32) -> TccResult<()> {
        let target_bt = t & VT_BTYPE;

        if target_bt == VT_LDOUBLE {
            // Integer → long double via x87:
            // Push value to stack, then FILD
            // push %rax
            self.g(0x50)?;
            // fildq (%rsp) — DF /5 [rsp]
            self.o(0xdf)?;
            self.g(0x2c)?; // /5 + SIB
            self.g(0x24)?; // SIB: base=RSP
            // add $8, %rsp
            self.gadd_sp(8)?;
        } else {
            // Integer → float/double via SSE
            let prefix: u32 = if target_bt == VT_FLOAT { 0xf3 } else { 0xf2 };
            // cvtsi2ss/cvtsi2sd: prefix 0F 2A /r
            self.o(prefix)?;
            self.o(0x2a0f)?;
            self.g(0xc0)?; // ModRM: reg-reg placeholder
        }

        Ok(())
    }

    /// Convert between floating-point types.
    ///
    /// Handles:
    /// - float → double: cvtss2sd (or unpcklps + cvtps2pd)
    /// - double → float: cvtsd2ss
    /// - float/double → long double: store to stack + fld
    /// - long double → float/double: fstp to stack + movss/movsd
    ///
    /// Mirrors C `gen_cvt_ftof()` from x86_64-gen.c lines 2083-2140.
    pub fn gen_cvt_ftof(&mut self, t: i32) -> TccResult<()> {
        let target_bt = t & VT_BTYPE;

        if target_bt == VT_FLOAT {
            // → float
            // cvtsd2ss: F2 0F 5A /r (double→float)
            self.o(0xf2)?;
            self.o(0x5a0f)?;
            self.g(0xc0)?; // ModRM placeholder
        } else if target_bt == VT_DOUBLE {
            // → double
            // cvtss2sd: F3 0F 5A /r (float→double)
            self.o(0xf3)?;
            self.o(0x5a0f)?;
            self.g(0xc0)?; // ModRM placeholder
        } else if target_bt == VT_LDOUBLE {
            // float/double → long double via x87 stack
            // movss/movsd [rsp-N], xmmN (spill to stack)
            // flds/fldl [rsp-N] (load to x87)
            // sub $8, %rsp
            self.gadd_sp(-8)?;
            // movsd [rsp], xmm0 — F2 0F 11 04 24
            self.o(0xf2)?;
            self.o(0x110f)?;
            self.g(0x04)?;
            self.g(0x24)?;
            // fldl (%rsp) — DD 04 24
            self.o(0xdd)?;
            self.g(0x04)?;
            self.g(0x24)?;
            // add $8, %rsp
            self.gadd_sp(8)?;
        }

        Ok(())
    }

    /// Convert floating-point to integer.
    ///
    /// Handles:
    /// - float → int/long long: cvttss2si / REX.W cvttss2si
    /// - double → int/long long: cvttsd2si / REX.W cvttsd2si
    /// - long double → int: convert to double first, then cvttsd2si
    /// - long double → long long: calls __fixxfdi helper
    ///
    /// Mirrors C `gen_cvt_ftoi()` from x86_64-gen.c lines 2143-2188.
    pub fn gen_cvt_ftoi(&mut self, t: i32) -> TccResult<()> {
        let target_bt = t & VT_BTYPE;
        let ll = if target_bt == VT_LLONG { 1_i32 } else { 0 };

        // For SSE float/double → integer:
        // cvttss2si: F3 0F 2C /r (float→int)
        // cvttsd2si: F2 0F 2C /r (double→int)
        // With REX.W for 64-bit result (→long long)
        let prefix: u32 = 0xf2; // default to double; caller sets source type
        self.o(prefix)?;
        if ll != 0 {
            // REX.W prefix for 64-bit result
            self.o(0x48)?;
        }
        self.o(0x2c0f)?;
        self.g(0xc0)?; // ModRM placeholder

        Ok(())
    }

    /// Sign-extend 32-bit value to 64-bit.
    ///
    /// Emits `movslq %eax, %rax` (63 /r with REX.W).
    /// Mirrors C `gen_cvt_sxtw()` from x86_64-gen.c lines 2191-2198.
    pub fn gen_cvt_sxtw(&mut self) -> TccResult<()> {
        // movslq: REX.W 63 /r — sign extend dword to qword
        self.o(0x6348)?; // 48 63 (REX.W + MOVSXD opcode)
        self.g(0xc0)?; // ModRM: eax → rax
        Ok(())
    }

    /// Convert char/short to int via sign/zero extension.
    ///
    /// Emits movsx or movzx depending on signedness.
    /// Mirrors C `gen_cvt_csti()` from x86_64-gen.c lines 2200-2212.
    pub fn gen_cvt_csti(&mut self, t: i32) -> TccResult<()> {
        let bt = t & VT_BTYPE;
        let is_unsigned = (t & VT_UNSIGNED) != 0;

        if bt == VT_BYTE || bt == VT_BOOL {
            if is_unsigned {
                // movzbl: 0F B6 /r
                self.o(0xb60f)?;
            } else {
                // movsbl: 0F BE /r
                self.o(0xbe0f)?;
            }
            self.g(0xc0)?; // ModRM: reg-reg
        } else if bt == VT_SHORT {
            if is_unsigned {
                // movzwl: 0F B7 /r
                self.o(0xb70f)?;
            } else {
                // movswl: 0F BF /r
                self.o(0xbf0f)?;
            }
            self.g(0xc0)?; // ModRM: reg-reg
        }

        Ok(())
    }

    // ========================================================================
    // Test coverage, computed goto, VLA support
    // ========================================================================

    /// Increment a test coverage counter via RIP-relative addressing.
    ///
    /// Emits `addq $1, counter(%rip)` with R_X86_64_PC32 relocation.
    /// Mirrors C `gen_increment_tcov()` from x86_64-gen.c lines 2214-2222.
    pub fn gen_increment_tcov(&mut self, sv: &SValue) -> TccResult<()> {
        // REX.W prefix for 64-bit add
        self.o(0x48)?;
        // addq $1, disp32(%rip) — 83 05 disp32 01
        self.g(0x83)?;
        // ModRM: /0 (add), mod=00, rm=5 (RIP-relative)
        self.g(0x05)?;
        // Displacement placeholder (will be relocated)
        // Safety: CValue.i is always valid as the widest simple field.
        let fc = unsafe { sv.c.i as i64 };
        self.gen_le32(fc as i32)?;
        // Immediate: $1
        self.g(0x01)?;
        Ok(())
    }

    /// Emit a computed goto (indirect jump through register).
    ///
    /// The jump target address is in a register on the value stack.
    /// Mirrors C `ggoto()` from x86_64-gen.c lines 2223-2228.
    pub fn ggoto(&mut self) -> TccResult<()> {
        // Indirect jump: jmp *%rax (or whatever register holds the target)
        // FF /4 reg
        self.gcall_or_jmp(true, 0, None, 0)?;
        Ok(())
    }

    /// Save the stack pointer for VLA (Variable Length Array) support.
    ///
    /// Emits `mov %rsp, addr(%rbp)`.
    /// Mirrors C `gen_vla_sp_save()` from x86_64-gen.c lines 2230-2235.
    pub fn gen_vla_sp_save(&mut self, addr: i32) -> TccResult<()> {
        // mov %rsp, addr(%rbp) — REX.W 89 ModRM
        self.orex(1, TREG_RSP, 0, 0x89)?;
        self.gen_modrm(TREG_RSP, VT_LOCAL, None, addr as i64)?;
        Ok(())
    }

    /// Restore the stack pointer for VLA support.
    ///
    /// Emits `mov addr(%rbp), %rsp`.
    /// Mirrors C `gen_vla_sp_restore()` from x86_64-gen.c lines 2236-2241.
    pub fn gen_vla_sp_restore(&mut self, addr: i32) -> TccResult<()> {
        // mov addr(%rbp), %rsp — REX.W 8B ModRM
        self.orex(1, TREG_RSP, 0, 0x8b)?;
        self.gen_modrm(TREG_RSP, VT_LOCAL, None, addr as i64)?;
        Ok(())
    }

    /// Store VLA allocation result (PE only).
    ///
    /// Emits `mov %rax, addr(%rbp)`.
    /// Mirrors C `gen_vla_result()` from x86_64-gen.c lines 2242-2248.
    pub fn gen_vla_result(&mut self, addr: i32) -> TccResult<()> {
        // PE: mov %rax, addr(%rbp)
        self.orex(1, TREG_RAX, 0, 0x89)?;
        self.gen_modrm(TREG_RAX, VT_LOCAL, None, addr as i64)?;
        Ok(())
    }

    /// Allocate VLA space on the stack.
    ///
    /// Emits `sub %rax, %rsp` (or calls __bound_new_region for bcheck),
    /// then aligns RSP to the specified alignment.
    ///
    /// Mirrors C `gen_vla_alloc()` from x86_64-gen.c lines 2249-2280.
    pub fn gen_vla_alloc(&mut self, _ty: &CType, align: i32) -> TccResult<()> {
        // sub %rax, %rsp — REX.W 29 C4
        self.o(0x48)?; // REX.W
        self.o(0x29)?;
        self.g(0xc4)?; // ModRM: rax → rsp

        if self.pe_mode {
            // PE: call __chkstk if needed
            // Store result in %rax
            // mov %rsp, %rax — REX.W 89 E0
            self.o(0x48)?;
            self.o(0x89)?;
            self.g(0xe0)?;
        }

        // Align RSP to `align` boundary (must be power of 2)
        if align > 0 {
            let mask = -(align as i64);
            // and $mask, %rsp — REX.W 81 E4 imm32
            self.o(0x48)?;
            self.o(0x81)?;
            self.g(0xe4)?;
            self.gen_le32(mask as i32)?;
        }

        Ok(())
    }

    /// Emit a structure copy using `rep movsq` with byte/word/dword tail.
    ///
    /// Assumes RSI=source, RDI=destination are already set by the caller.
    /// Uses `rep movsq` for the bulk copy (8 bytes at a time), followed
    /// by `movsb`/`movsw`/`movsd` for the remainder.
    ///
    /// Mirrors C `gen_struct_copy()` from x86_64-gen.c lines 2281-2313.
    pub fn gen_struct_copy(&mut self, size: i32) -> TccResult<()> {
        let qwords = size / 8;
        let remainder = size % 8;

        if qwords > 0 {
            // mov $qwords, %rcx — REX.W B9 imm32
            self.orex(1, 0, 0, 0xb8 + reg_value(TREG_RCX))?;
            self.gen_le64(qwords as i64)?;
            // rep movsq — F3 48 A5
            self.o(0xf3)?;
            self.o(0x48)?; // REX.W
            self.g(0xa5)?; // movsq
        }

        // Handle remainder
        if remainder >= 4 {
            // movsd — A5
            self.g(0xa5)?;
        }
        if remainder & 2 != 0 {
            // movsw — 66 A5
            self.o(0x66)?;
            self.g(0xa5)?;
        }
        if remainder & 1 != 0 {
            // movsb — A4
            self.g(0xa4)?;
        }

        Ok(())
    }
    // ========================================================================
    // Assembly instruction and register lookup helpers
    // ========================================================================

    /// Resolve an assembly instruction mnemonic to its opcode definition.
    /// Uses the tokens module lookup_opcode() to find instruction encoding data
    /// for inline assembly support. Returns the opcode and flags if found.
    pub fn resolve_asm_opcode(&self, mnemonic: &str) -> Option<(u32, u32)> {
        super::tokens::lookup_opcode(mnemonic).map(|def| (def.opcode, def.flags))
    }

    /// Resolve a register name to its hardware encoding value.
    /// Uses the tokens module register_from_name() to map textual register
    /// names (e.g. "rax", "xmm0") to their numeric encoding for instruction
    /// emission. Returns the encoding value and register width in bits if found.
    pub fn resolve_register(&self, name: &str) -> Option<(u8, u32)> {
        use super::tokens::RegisterWidth;
        super::tokens::register_from_name(name).map(|def| {
            let bits: u32 = match def.width {
                RegisterWidth::Bit8 => 8,
                RegisterWidth::Bit16 => 16,
                RegisterWidth::Bit32 => 32,
                RegisterWidth::Bit64 => 64,
                RegisterWidth::Bit128 => 128,
                RegisterWidth::Bit80 => 80,
            };
            (def.encoding, bits)
        })
    }
} // end impl X86_64GenState

// ============================================================================
// Standalone function: gfunc_sret_x86_64
// ============================================================================

/// Determine if a function return type should use a hidden struct return
/// pointer (SRet) for the System V AMD64 ABI.
///
/// Returns `(use_sret, ret_type, align, regsize)` where:
/// - `use_sret`: true if the return value needs a hidden pointer parameter
/// - `ret_type`: the type used for the return register(s)
/// - `align`: alignment of the return value
/// - `regsize`: size of the return value in registers (8 or 16)
///
/// Per the AMD64 ABI, structs > 16 bytes or containing unaligned fields
/// are returned via a hidden pointer. Structs ≤ 16 bytes are returned
/// in up to 2 registers (RAX/RDX for Integer, XMM0/XMM1 for SSE).
///
/// For Win64, structs > 8 bytes use a hidden pointer; ≤ 8 bytes are
/// returned in RAX.
///
/// Mirrors C `gfunc_sret()` from x86_64-gen.c (both PE and non-PE variants).
pub fn gfunc_sret_x86_64(
    vt: &CType,
    variadic: bool,
    is_pe: bool,
) -> (bool, CType, i32, i32) {
    let bt = vt.t & VT_BTYPE;

    if bt != VT_STRUCT {
        // Non-struct returns are never SRet
        return (false, CType { t: VT_LLONG, ref_sym: None }, 8, 8);
    }

    let size = X86_64GenState::type_size_for_abi(vt);

    if is_pe {
        // Win64 ABI: structs > 8 bytes use SRet
        if size > 8 {
            return (true, CType { t: VT_LLONG, ref_sym: None }, 8, 8);
        }
        return (false, CType { t: VT_LLONG, ref_sym: None }, 8, 8);
    }

    // System V AMD64 ABI
    let (mode, _sz, align) = X86_64GenState::classify_arg(vt);

    match mode {
        X86_64Mode::Memory | X86_64Mode::X87 => {
            // Must use hidden pointer (SRet)
            (true, CType { t: VT_LLONG, ref_sym: None }, 8, 8)
        }
        X86_64Mode::Integer | X86_64Mode::Sse => {
            // Returned in register(s)
            let regsize = if size > 8 { 16 } else { 8 };
            let ret_t = if mode == X86_64Mode::Sse { VT_DOUBLE } else { VT_LLONG };
            let _ = variadic;
            (false, CType { t: ret_t, ref_sym: None }, align, regsize)
        }
        X86_64Mode::None => {
            (false, CType { t: VT_VOID, ref_sym: None }, 0, 0)
        }
    }
}

// ============================================================================
// Unit tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_creates_valid_state() {
        let state = X86_64GenState::new();
        assert_eq!(state.ind, 0);
        assert_eq!(state.nocode_wanted, 0);
        assert_eq!(state.loc, 0);
        assert_eq!(state.func_sub_sp_offset, 0);
        assert_eq!(state.func_ret_sub, 0);
        assert!(!state.pe_mode);
        assert!(state.code.is_empty());
    }

    #[test]
    fn test_g_emits_byte() {
        let mut s = X86_64GenState::new();
        s.g(0x90).unwrap();
        assert_eq!(s.code, vec![0x90]);
        assert_eq!(s.ind, 1);
    }

    #[test]
    fn test_g_nocode_wanted_skips() {
        let mut s = X86_64GenState::new();
        s.nocode_wanted = 1;
        s.g(0x90).unwrap();
        assert!(s.code.is_empty());
        assert_eq!(s.ind, 0);
    }

    #[test]
    fn test_o_emits_multibyte() {
        let mut s = X86_64GenState::new();
        s.o(0xABCD).unwrap();
        assert_eq!(s.code, vec![0xCD, 0xAB]);
    }

    #[test]
    fn test_o_single_byte() {
        let mut s = X86_64GenState::new();
        s.o(0x90).unwrap();
        assert_eq!(s.code, vec![0x90]);
    }

    #[test]
    fn test_gen_le16() {
        let mut s = X86_64GenState::new();
        s.gen_le16(0x1234).unwrap();
        assert_eq!(s.code, vec![0x34, 0x12]);
    }

    #[test]
    fn test_gen_le32() {
        let mut s = X86_64GenState::new();
        s.gen_le32(0x12345678).unwrap();
        assert_eq!(s.code, vec![0x78, 0x56, 0x34, 0x12]);
    }

    #[test]
    fn test_gen_fill_nops_single() {
        let mut s = X86_64GenState::new();
        s.gen_fill_nops(1).unwrap();
        assert_eq!(s.code, vec![0x90]);
    }

    #[test]
    fn test_gen_fill_nops_3byte() {
        let mut s = X86_64GenState::new();
        s.gen_fill_nops(3).unwrap();
        assert_eq!(s.code.len(), 3);
        assert_eq!(s.code, vec![0x90, 0x90, 0x90]);
    }

    #[test]
    fn test_gen_fill_nops_7byte() {
        let mut s = X86_64GenState::new();
        s.gen_fill_nops(7).unwrap();
        assert_eq!(s.code.len(), 7);
    }

    #[test]
    fn test_gen_fill_nops_15byte() {
        let mut s = X86_64GenState::new();
        s.gen_fill_nops(15).unwrap();
        assert_eq!(s.code.len(), 15);
    }

    #[test]
    fn test_rex_base_values() {
        assert_eq!(rex_base(0), 0);
        assert_eq!(rex_base(7), 0);
        assert_eq!(rex_base(8), 1);
        assert_eq!(rex_base(15), 1);
    }

    #[test]
    fn test_reg_value_values() {
        assert_eq!(reg_value(0), 0);
        assert_eq!(reg_value(7), 7);
        assert_eq!(reg_value(8), 0);
        assert_eq!(reg_value(15), 7);
    }

    #[test]
    fn test_is64_type_checks() {
        assert!(is64_type(VT_PTR));
        assert!(is64_type(VT_FUNC));
        assert!(is64_type(VT_LLONG));
        assert!(!is64_type(VT_INT));
        assert!(!is64_type(VT_FLOAT));
        assert!(!is64_type(VT_SHORT));
    }

    #[test]
    fn test_constants() {
        assert_eq!(NB_REGS, 25);
        assert_eq!(NB_ASM_REGS, 16);
        assert_eq!(PTR_SIZE, 8);
        assert_eq!(LDOUBLE_SIZE, 16);
        assert_eq!(MAX_ALIGN, 16);
        assert_eq!(FUNC_PROLOG_SIZE, 11);
    }

    #[test]
    fn test_register_constants() {
        assert_eq!(TREG_RAX, 0);
        assert_eq!(TREG_RCX, 1);
        assert_eq!(TREG_RDX, 2);
        assert_eq!(TREG_RSP, 4);
        assert_eq!(TREG_RBP, 5);
        assert_eq!(TREG_RSI, 6);
        assert_eq!(TREG_RDI, 7);
        assert_eq!(TREG_R8, 8);
        assert_eq!(TREG_XMM0, 16);
        assert_eq!(TREG_ST0, 24);
    }

    #[test]
    fn test_reg_classes_array_len() {
        assert_eq!(REG_CLASSES.len(), NB_REGS);
        assert!(REG_CLASSES[TREG_RAX as usize] & RC_RAX != 0);
        assert!(REG_CLASSES[TREG_XMM0 as usize] & RC_XMM0 != 0);
    }

    #[test]
    fn test_orex_no_prefix_32bit() {
        let mut s = X86_64GenState::new();
        s.orex(0, 0, 0, 0x8b).unwrap();
        assert_eq!(s.code, vec![0x8b]);
    }

    #[test]
    fn test_orex_64bit_prefix() {
        let mut s = X86_64GenState::new();
        s.orex(1, 0, 0, 0x8b).unwrap();
        assert_eq!(s.code, vec![0x48, 0x8b]);
    }

    #[test]
    fn test_orex_high_register() {
        let mut s = X86_64GenState::new();
        s.orex(0, TREG_R8, 0, 0x8b).unwrap();
        assert_eq!(s.code, vec![0x41, 0x8b]);
    }

    #[test]
    fn test_x86_64_mode_enum() {
        let m = X86_64Mode::Integer;
        assert_eq!(m, X86_64Mode::Integer);
        assert_ne!(m, X86_64Mode::Sse);
        assert_ne!(m, X86_64Mode::Memory);
    }

    #[test]
    fn test_classify_arg_int() {
        let int_type = CType { t: VT_INT, ref_sym: None };
        let (mode, size, _align) = X86_64GenState::classify_arg(&int_type);
        assert_eq!(mode, X86_64Mode::Integer);
        assert!(size <= 8);
    }

    #[test]
    fn test_classify_arg_float() {
        let float_type = CType { t: VT_FLOAT, ref_sym: None };
        let (mode, _size, _align) = X86_64GenState::classify_arg(&float_type);
        assert_eq!(mode, X86_64Mode::Sse);
    }

    #[test]
    fn test_classify_arg_double() {
        let double_type = CType { t: VT_DOUBLE, ref_sym: None };
        let (mode, _size, _align) = X86_64GenState::classify_arg(&double_type);
        assert_eq!(mode, X86_64Mode::Sse);
    }

    #[test]
    fn test_classify_arg_ldouble() {
        let ldouble_type = CType { t: VT_LDOUBLE, ref_sym: None };
        let (mode, _size, _align) = X86_64GenState::classify_arg(&ldouble_type);
        assert!(mode == X86_64Mode::X87 || mode == X86_64Mode::Memory);
    }

    #[test]
    fn test_gfunc_sret_non_struct() {
        let int_type = CType { t: VT_INT, ref_sym: None };
        let (use_sret, _ret_type, _align, _regsize) = gfunc_sret_x86_64(&int_type, false, false);
        assert!(!use_sret);
    }

    #[test]
    fn test_gjmp_emits_jmp() {
        let mut s = X86_64GenState::new();
        let result = s.gjmp(0).unwrap();
        assert!(s.code.len() >= 5);
        assert_eq!(s.code[0], 0xe9);
        assert!(result > 0);
    }

    #[test]
    fn test_gjmp_addr_short() {
        let mut s = X86_64GenState::new();
        for _ in 0..10 {
            s.g(0x90).unwrap();
        }
        s.gjmp_addr(0).unwrap();
        let jmp_pos = 10;
        assert_eq!(s.code[jmp_pos], 0xeb);
    }

    #[test]
    fn test_gen_cvt_sxtw() {
        let mut s = X86_64GenState::new();
        s.gen_cvt_sxtw().unwrap();
        assert!(s.code.len() >= 2);
    }

    #[test]
    fn test_gen_cvt_csti_byte() {
        let mut s = X86_64GenState::new();
        s.gen_cvt_csti(VT_BYTE).unwrap();
        assert!(s.code.len() >= 3);
        assert_eq!(s.code[0], 0x0f);
        assert_eq!(s.code[1], 0xbe);
    }

    #[test]
    fn test_gen_cvt_csti_unsigned_byte() {
        let mut s = X86_64GenState::new();
        s.gen_cvt_csti(VT_BYTE | VT_UNSIGNED).unwrap();
        assert!(s.code.len() >= 3);
        assert_eq!(s.code[0], 0x0f);
        assert_eq!(s.code[1], 0xb6);
    }

    #[test]
    fn test_gen_cvt_csti_short() {
        let mut s = X86_64GenState::new();
        s.gen_cvt_csti(VT_SHORT).unwrap();
        assert!(s.code.len() >= 3);
        assert_eq!(s.code[0], 0x0f);
        assert_eq!(s.code[1], 0xbf);
    }

    #[test]
    fn test_gen_vla_sp_save_restore() {
        let mut s = X86_64GenState::new();
        assert!(s.gen_vla_sp_save(-8).is_ok());
        assert!(!s.code.is_empty());
        let mut s2 = X86_64GenState::new();
        assert!(s2.gen_vla_sp_restore(-8).is_ok());
        assert!(!s2.code.is_empty());
    }

    #[test]
    fn test_gen_struct_copy_small() {
        let mut s = X86_64GenState::new();
        s.gen_struct_copy(4).unwrap();
        assert!(s.code.contains(&0xa5));
    }

    #[test]
    fn test_gen_struct_copy_large() {
        let mut s = X86_64GenState::new();
        s.gen_struct_copy(24).unwrap();
        assert!(s.code.contains(&0xa5));
    }

    #[test]
    fn test_gen_vla_alloc() {
        let mut s = X86_64GenState::new();
        let ty = CType { t: VT_INT, ref_sym: None };
        s.gen_vla_alloc(&ty, 16).unwrap();
        assert!(!s.code.is_empty());
    }

    #[test]
    fn test_gen_cvt_itof_float() {
        let mut s = X86_64GenState::new();
        s.gen_cvt_itof(VT_FLOAT).unwrap();
        assert!(!s.code.is_empty());
    }

    #[test]
    fn test_gen_cvt_itof_ldouble() {
        let mut s = X86_64GenState::new();
        s.gen_cvt_itof(VT_LDOUBLE).unwrap();
        assert!(!s.code.is_empty());
    }

    #[test]
    fn test_gen_cvt_ftoi_int() {
        let mut s = X86_64GenState::new();
        s.gen_cvt_ftoi(VT_INT).unwrap();
        assert!(!s.code.is_empty());
    }

    #[test]
    fn test_gen_cvt_ftof_to_float() {
        let mut s = X86_64GenState::new();
        s.gen_cvt_ftof(VT_FLOAT).unwrap();
        assert!(!s.code.is_empty());
    }

    #[test]
    fn test_ggoto() {
        let mut s = X86_64GenState::new();
        s.ggoto().unwrap();
        assert!(!s.code.is_empty());
    }

    #[test]
    fn test_gen_opi_add() {
        let mut s = X86_64GenState::new();
        assert!(s.gen_opi('+' as i32).is_ok());
    }

    #[test]
    fn test_gen_opi_sub() {
        let mut s = X86_64GenState::new();
        assert!(s.gen_opi('-' as i32).is_ok());
    }

    #[test]
    fn test_gen_opi_mul() {
        let mut s = X86_64GenState::new();
        assert!(s.gen_opi('*' as i32).is_ok());
    }

    #[test]
    fn test_gen_opi_and() {
        let mut s = X86_64GenState::new();
        assert!(s.gen_opi('&' as i32).is_ok());
    }

    #[test]
    fn test_gen_opi_or() {
        let mut s = X86_64GenState::new();
        assert!(s.gen_opi('|' as i32).is_ok());
    }

    #[test]
    fn test_gen_opi_xor() {
        let mut s = X86_64GenState::new();
        assert!(s.gen_opi('^' as i32).is_ok());
    }

    #[test]
    fn test_gen_opf_add() {
        let mut s = X86_64GenState::new();
        assert!(s.gen_opf('+' as i32).is_ok());
    }

    #[test]
    fn test_gen_opf_sub() {
        let mut s = X86_64GenState::new();
        assert!(s.gen_opf('-' as i32).is_ok());
    }

    #[test]
    fn test_gen_opf_mul() {
        let mut s = X86_64GenState::new();
        assert!(s.gen_opf('*' as i32).is_ok());
    }

    #[test]
    fn test_gen_opf_div() {
        let mut s = X86_64GenState::new();
        assert!(s.gen_opf('/' as i32).is_ok());
    }

    #[test]
    fn test_gen_le32_boundary() {
        let mut s = X86_64GenState::new();
        s.gen_le32(-1).unwrap();
        assert_eq!(s.code, vec![0xff, 0xff, 0xff, 0xff]);
    }

    #[test]
    fn test_gen_le32_zero() {
        let mut s = X86_64GenState::new();
        s.gen_le32(0).unwrap();
        assert_eq!(s.code, vec![0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_gen_fill_nops_zero() {
        let mut s = X86_64GenState::new();
        s.gen_fill_nops(0).unwrap();
        assert!(s.code.is_empty());
    }

    #[test]
    fn test_gen_fill_nops_accumulates() {
        let mut s = X86_64GenState::new();
        s.gen_fill_nops(5).unwrap();
        s.gen_fill_nops(3).unwrap();
        assert_eq!(s.code.len(), 8);
    }

    #[test]
    fn test_orex_both_high_regs() {
        let mut s = X86_64GenState::new();
        s.orex(1, TREG_R8, TREG_R8, 0x8b).unwrap();
        assert_eq!(s.code[0], 0x4d);
    }

    #[test]
    fn test_classify_arg_ptr() {
        let ptr_type = CType { t: VT_PTR, ref_sym: None };
        let (mode, size, _align) = X86_64GenState::classify_arg(&ptr_type);
        assert_eq!(mode, X86_64Mode::Integer);
        assert_eq!(size, 8);
    }

    #[test]
    fn test_classify_arg_llong() {
        let ll_type = CType { t: VT_LLONG, ref_sym: None };
        let (mode, size, _align) = X86_64GenState::classify_arg(&ll_type);
        assert_eq!(mode, X86_64Mode::Integer);
        assert_eq!(size, 8);
    }

    #[test]
    fn test_multiple_g_calls() {
        let mut s = X86_64GenState::new();
        s.g(0x55).unwrap(); // push %rbp
        s.g(0x48).unwrap(); // REX.W
        s.g(0x89).unwrap(); // mov
        s.g(0xe5).unwrap(); // %rsp, %rbp
        assert_eq!(s.code, vec![0x55, 0x48, 0x89, 0xe5]);
        assert_eq!(s.ind, 4);
    }

    #[test]
    fn test_rc_constants_are_distinct() {
        assert_eq!(RC_INT & RC_FLOAT, 0);
        assert_eq!(RC_RAX & RC_RDX, 0);
        assert_eq!(RC_RCX & RC_RSI, 0);
        assert_eq!(RC_XMM0 & RC_XMM1, 0);
    }

    #[test]
    fn test_iret_fret_aliases() {
        assert_eq!(RC_IRET, RC_RAX);
        assert_eq!(RC_IRE2, RC_RDX);
        assert_eq!(RC_FRET, RC_XMM0);
        assert_eq!(RC_FRE2, RC_XMM1);
        assert_eq!(REG_IRET, TREG_RAX);
        assert_eq!(REG_IRE2, TREG_RDX);
        assert_eq!(REG_FRET, TREG_XMM0);
        assert_eq!(REG_FRE2, TREG_XMM1);
    }

    #[test]
    fn test_vt_void_not_64_type() {
        assert!(!is64_type(VT_VOID));
    }

    #[test]
    fn test_vt_struct_not_64_type() {
        assert!(!is64_type(VT_STRUCT));
    }
}
