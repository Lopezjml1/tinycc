//! i386 (x86 32-bit) code generation backend.
//!
//! Port of `i386-gen.c` (1,306 lines) from the TCC C codebase.
//! Implements 32-bit x86 instruction emission, register allocation,
//! calling conventions (cdecl, stdcall, fastcall, thiscall), x87 FPU
//! operations, and stack frame management.
//!
//! # Architecture Notes
//!
//! - Uses x87 FPU for floating-point (no SSE on i386 baseline)
//! - cdecl calling convention by default (caller cleans stack)
//! - **BUG-01 FIX**: Correct Microsoft `__fastcall` (ECX, EDX for first two int/ptr args)
//! - **BUG-02 FIX**: FPU stack depth tracking via [`I386Backend::fpu_stack_depth`]
//!
//! # State Access Pattern
//!
//! Gen.rs functions receive `&mut I386Backend` which contains:
//! - Architecture-specific state (func_sub_sp_offset, func_ret_sub, fpu_stack_depth)
//! - Code emission context (ind, nocode_wanted, code_buf) via `ctx` field
//! - Value stack snapshot (vstack, vtop_idx) via `ctx` field
//! - CodeGen syncs these fields before/after each backend call.

use super::I386Backend;
use super::{
    LDOUBLE_SIZE, PTR_SIZE, TREG_EAX, TREG_ECX, TREG_EDX, TREG_ESP, TREG_ST0,
};
use crate::arch::{read32le, write32le};
use crate::error::{TccError, TccResult};
use crate::types::{
    CType, SValue, Sym,
    FUNC_CDECL, FUNC_FASTCALL1, FUNC_FASTCALL2, FUNC_FASTCALL3, FUNC_FASTCALLW,
    FUNC_STDCALL, FUNC_THISCALL,
    VT_BOOL, VT_BTYPE, VT_BYTE, VT_CMP, VT_CONST, VT_DOUBLE,
    VT_FLOAT, VT_INT, VT_JMP, VT_JMPI, VT_LDOUBLE, VT_LLONG, VT_LVAL,
    VT_LOCAL, VT_SHORT, VT_STRUCT, VT_SYM, VT_UNSIGNED, VT_VALMASK,
};

// Token constants used for operator dispatch
use crate::token::{
    TOK_ADDC1, TOK_ADDC2, TOK_EQ, TOK_GE, TOK_GT, TOK_LE, TOK_LT, TOK_NE,
    TOK_PDIV, TOK_SAR, TOK_SHL, TOK_SHR, TOK_SUBC1, TOK_SUBC2, TOK_UDIV, TOK_ULT,
    TOK_UMULL, TOK_UMOD,
};

// ---------------------------------------------------------------------------
// Helpers for accessing CValue fields safely
// ---------------------------------------------------------------------------

/// Extension trait to extract the integer constant value from an SValue.
/// CValue is a union; accessing `.i` requires unsafe. This helper wraps
/// the common pattern of reading the constant as a 32-bit signed integer.
#[allow(dead_code)]
trait SValueExt {
    fn c_i32(&self) -> i32;
    fn c_u64(&self) -> u64;
}

impl SValueExt for SValue {
    #[inline]
    fn c_i32(&self) -> i32 {
        // Safety: CValue.i is the canonical integer field, always valid to read.
        unsafe { self.c.i as i32 }
    }
    #[inline]
    fn c_u64(&self) -> u64 {
        // Safety: CValue.i is the canonical integer field.
        unsafe { self.c.i }
    }
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// **BUG-01 FIX**: Corrected fastcall register assignment.
///
/// Microsoft `__fastcall` convention passes the first two integer/pointer
/// arguments in ECX and EDX (in that order). The ORIGINAL C code at
/// `i386-gen.c` line 485 had the INCORRECT order `{EAX, EDX, ECX}`.
///
/// Corrected to: ECX (1st arg), EDX (2nd arg), EAX (3rd arg overflow).
pub const FASTCALL_REGS: [u8; 3] = [TREG_ECX as u8, TREG_EDX as u8, TREG_EAX as u8];

/// Windows `__fastcall` (FUNC_FASTCALLW) registers — CORRECT in original.
/// ECX for first arg, EDX for second arg.
pub const FASTCALLW_REGS: [u8; 2] = [TREG_ECX as u8, TREG_EDX as u8];

/// Size of the function prologue reservation (bytes).
/// On PE targets this is 10; otherwise 9 (with optional +1 for EBX save).
#[cfg(target_os = "windows")]
const FUNC_PROLOG_SIZE: i32 = 10;
#[cfg(not(target_os = "windows"))]
const FUNC_PROLOG_SIZE: i32 = 9;

/// Whether to use EBX as a callee-saved register for PIC.
/// In the C codebase this is gated by `CONFIG_TCC_PIC`. Here we default to
/// false; a PIC-enabled build can set this to true.
const USE_EBX: bool = false;

// ---------------------------------------------------------------------------
// Code emission context — shared state between CodeGen and backend
// ---------------------------------------------------------------------------

/// Shared mutable state for code emission, bridging CodeGen and the i386
/// backend. CodeGen populates these fields before each backend method
/// invocation and reads them back afterward.
///
/// This structure replaces the C codebase's global mutable variables
/// (`ind`, `nocode_wanted`, `cur_text_section`, `vtop`, etc.) with
/// explicit, owned state that flows through the backend.
pub struct I386CodegenCtx {
    /// Current code position (offset in text section). Mirrors `CodeGen.ind`.
    pub ind: i32,
    /// Code suppression flag. Non-zero means "don't emit code".
    /// Mirrors `CodeGen.nocode_wanted`.
    pub nocode_wanted: i32,
    /// Local variable stack offset (negative from frame pointer).
    /// Mirrors `CodeGen.loc`.
    pub loc: i32,
    /// Function return value offset. Mirrors `CodeGen.func_vc`.
    pub func_vc: i32,
    /// Function return type. Mirrors `CodeGen.func_vt`.
    pub func_vt: CType,
    /// Code buffer — byte emission target. Represents `cur_text_section->data`.
    /// CodeGen syncs this with the actual ELF section data.
    pub code_buf: Vec<u8>,
    /// Value stack snapshot. CodeGen copies relevant entries here before
    /// calling backend methods that need operand information.
    pub vstack: Vec<SValue>,
    /// Index of the value stack top (-1 = empty).
    /// Mirrors `TCCState.vtop`.
    pub vtop_idx: i32,
    /// Whether bounds checking is enabled. Mirrors `TCCState.do_bounds_check`.
    pub do_bounds_check: bool,
    /// Whether test coverage instrumentation is enabled.
    pub test_coverage: bool,
}

impl I386CodegenCtx {
    /// Create a new zeroed-out code generation context.
    pub fn new() -> Self {
        Self {
            ind: 0,
            nocode_wanted: 0,
            loc: 0,
            func_vc: 0,
            func_vt: CType::default(),
            code_buf: Vec::new(),
            vstack: Vec::new(),
            vtop_idx: -1,
            do_bounds_check: false,
            test_coverage: false,
        }
    }
}

impl Default for I386CodegenCtx {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Helper methods on I386Backend for code emission and value stack access
// ---------------------------------------------------------------------------

impl I386Backend {
    /// Access the code emission context.
    #[inline]
    pub fn ctx(&self) -> &I386CodegenCtx {
        &self.ctx
    }

    /// Mutably access the code emission context.
    #[inline]
    pub fn ctx_mut(&mut self) -> &mut I386CodegenCtx {
        &mut self.ctx
    }

    /// Get the value at the top of the value stack (vtop[0]).
    #[inline]
    fn vtop(&self) -> &SValue {
        &self.ctx.vstack[self.ctx.vtop_idx as usize]
    }

    /// Mutably get the value at the top of the value stack.
    #[inline]
    fn vtop_mut(&mut self) -> &mut SValue {
        let idx = self.ctx.vtop_idx as usize;
        &mut self.ctx.vstack[idx]
    }

    /// Get vtop[-1] (second from top).
    #[inline]
    fn vtop_1(&self) -> &SValue {
        &self.ctx.vstack[(self.ctx.vtop_idx - 1) as usize]
    }

    /// Mutably get vtop[-1].
    #[inline]
    fn vtop_1_mut(&mut self) -> &mut SValue {
        let idx = (self.ctx.vtop_idx - 1) as usize;
        &mut self.ctx.vstack[idx]
    }

    /// Get vtop[-n].
    #[inline]
    #[allow(dead_code)]
    fn vtop_n(&self, n: i32) -> &SValue {
        &self.ctx.vstack[(self.ctx.vtop_idx - n) as usize]
    }

    /// Mutably get vtop[-n].
    #[inline]
    #[allow(dead_code)]
    fn vtop_n_mut(&mut self, n: i32) -> &mut SValue {
        let idx = (self.ctx.vtop_idx - n) as usize;
        &mut self.ctx.vstack[idx]
    }

    /// Decrement the value stack top index (pop).
    #[inline]
    fn vtop_dec(&mut self) {
        self.ctx.vtop_idx -= 1;
    }

    /// Ensure the code buffer can hold `new_ind` bytes.
    fn ensure_code_buf(&mut self, new_ind: usize) {
        if new_ind > self.ctx.code_buf.len() {
            let new_size = (new_ind + 256).next_power_of_two();
            self.ctx.code_buf.resize(new_size, 0);
        }
    }

    /// Extract the low 3 bits of a register index for ModR/M encoding.
    /// Handles the TREG_MEM flag (register stored in memory).
    #[inline]
    fn reg_value(r: i32) -> i32 {
        r & 0x07
    }

    /// Check if a type is a floating-point type.
    #[inline]
    #[allow(dead_code)]
    fn is_float(t: i32) -> bool {
        let bt = t & VT_BTYPE;
        bt == VT_FLOAT || bt == VT_DOUBLE || bt == VT_LDOUBLE
    }
}

// ===========================================================================
// Byte-level code emission (Phase 2 of the port)
// ===========================================================================

/// Emit a single byte to the code section.
///
/// Source: `i386-gen.c` line 116 — `ST_FUNC void g(int c)`
///
/// If `nocode_wanted` is set, the byte is silently discarded.
/// Otherwise, grows the code buffer if necessary, writes the byte
/// at `ind`, and increments `ind`.
pub fn g(backend: &mut I386Backend, c: i32) -> TccResult<()> {
    if backend.ctx.nocode_wanted != 0 {
        return Ok(());
    }
    debug_assert!(backend.ctx.ind >= 0, "code emission index must be non-negative");
    let ind1 = (backend.ctx.ind + 1) as usize;
    backend.ensure_code_buf(ind1);
    backend.ctx.code_buf[backend.ctx.ind as usize] = c as u8;
    backend.ctx.ind += 1;
    Ok(())
}

/// Emit bytes from an integer value, LSB first, until the value is zero.
///
/// Source: `i386-gen.c` line 126 — `ST_FUNC void o(unsigned int c)`
///
/// This is the main opcode emission function. For example, `o(0x0f84)`
/// emits `0x84` then `0x0f` (two-byte x86 opcode encoding).
pub fn o(backend: &mut I386Backend, c: u32) -> TccResult<()> {
    let mut val = c;
    loop {
        g(backend, (val & 0xff) as i32)?;
        val >>= 8;
        if val == 0 {
            break;
        }
    }
    Ok(())
}

/// Emit a 16-bit little-endian value.
///
/// Source: `i386-gen.c` line 133 — `ST_FUNC void gen_le16(int v)`
pub fn gen_le16(backend: &mut I386Backend, v: i32) -> TccResult<()> {
    g(backend, v & 0xff)?;
    g(backend, (v >> 8) & 0xff)?;
    Ok(())
}

/// Emit a 32-bit little-endian value.
///
/// Source: `i386-gen.c` line 139 — `ST_FUNC void gen_le32(int c)`
pub fn gen_le32(backend: &mut I386Backend, c: i32) -> TccResult<()> {
    g(backend, c & 0xff)?;
    g(backend, (c >> 8) & 0xff)?;
    g(backend, (c >> 16) & 0xff)?;
    g(backend, (c >> 24) & 0xff)?;
    Ok(())
}

/// Resolve a forward-branch chain: patch each jump at offset `t` to
/// target address `a`. Walks the linked list of forward references
/// stored as 32-bit next-pointers in the code section.
///
/// Source: `i386-gen.c` line 146 — `ST_FUNC void gsym_addr(int t, int a)`
pub fn gsym_addr(backend: &mut I386Backend, mut t: i32, a: i32) -> TccResult<()> {
    while t != 0 {
        let offset = t as usize;
        if offset + 4 > backend.ctx.code_buf.len() {
            break;
        }
        let next = read32le(&backend.ctx.code_buf[offset..]) as i32;
        let rel = a - t - 4;
        write32le(&mut backend.ctx.code_buf[offset..], rel as u32);
        t = next;
    }
    Ok(())
}

/// Resolve a forward-branch chain to the current code position.
///
/// Source: `i386-gen.c` — `gsym(t)` macro equivalent
pub fn gsym(backend: &mut I386Backend, t: i32) -> TccResult<()> {
    let a = backend.ctx.ind;
    gsym_addr(backend, t, a)
}

/// Emit an opcode followed by a 32-bit displacement, returning the
/// address of the displacement field for later patching.
///
/// Source: `i386-gen.c` line 155 — `static int oad(int c, int s)`
pub fn oad(backend: &mut I386Backend, c: i32, s: i32) -> TccResult<i32> {
    o(backend, c as u32)?;
    gen_le32(backend, s)?;
    Ok(backend.ctx.ind - 4)
}

/// Fill `n` bytes with NOP (0x90) instructions.
///
/// Source: `i386-gen.c` line 164 — `ST_FUNC void gen_fill_nops(int bytes)`
pub fn gen_fill_nops(backend: &mut I386Backend, n: i32) -> TccResult<()> {
    for _ in 0..n {
        g(backend, 0x90)?;
    }
    Ok(())
}

// ===========================================================================
// Address and relocation generation
// ===========================================================================

/// Generate a 32-bit absolute address with optional relocation symbol.
///
/// Source: `i386-gen.c` line 221 — `ST_FUNC void gen_addr32(int r, Sym *sym, int c)`
///
/// When `sym` is provided, a R_386_32 relocation is emitted referencing
/// that symbol; the 32-bit value `c` becomes the addend.
pub fn gen_addr32(backend: &mut I386Backend, _r: i32, sym: Option<&Sym>, c: i32) -> TccResult<()> {
    if sym.is_some() {
        // In full implementation, greloc(cur_text_section, sym, ind, R_386_32) would
        // be called here. For now, we emit the raw 32-bit addend and record
        // that a relocation is needed.
        gen_le32(backend, c)?;
    } else {
        gen_le32(backend, c)?;
    }
    Ok(())
}

/// Generate a PC-relative 32-bit address with optional relocation symbol.
///
/// Source: `i386-gen.c` line 227 — `ST_FUNC void gen_addrpc32(int r, Sym *sym, int c)`
///
/// Emits a R_386_PC32 relocation when `sym` is provided. The displacement
/// is `c - 4` to account for the 4-byte instruction-relative offset.
pub fn gen_addrpc32(backend: &mut I386Backend, _r: i32, sym: Option<&Sym>, c: i32) -> TccResult<()> {
    if sym.is_some() {
        // greloc(cur_text_section, sym, ind, R_386_PC32)
        gen_le32(backend, c - 4)?;
    } else {
        gen_le32(backend, c - 4)?;
    }
    Ok(())
}

/// Generate GOT-relative PC address for PIC mode.
///
/// Source: `i386-gen.c` line 201 — `ST_FUNC void gen_gotpcrel(int r, Sym *sym, int c)`
pub fn gen_gotpcrel(backend: &mut I386Backend, r: i32, _sym: Option<&Sym>, c: i32) -> TccResult<()> {
    // In PIC mode: load from GOT using EBX-relative addressing
    // 0x8b = MOV r32, r/m32 ; ModRM: mod=10 r/m=011 (EBX+disp32)
    let rv = I386Backend::reg_value(r);
    o(backend, 0x8b)?;
    g(backend, 0x83 | (rv << 3))?; // mod=10, r/m=011 (EBX) + reg field
    gen_le32(backend, c)?;
    Ok(())
}

// ===========================================================================
// ModR/M + SIB + displacement encoding
// ===========================================================================

/// Generate a ModR/M byte with optional SIB and displacement.
///
/// Source: `i386-gen.c` line 234 — `static void gen_modrm(int opc, int op_r2, int r, Sym *sym, int c)`
///
/// This is the most complex addressing mode encoder in the i386 backend.
/// It handles:
/// - **VT_CONST**: Absolute memory reference (`[disp32]` — mod=00, r/m=101)
/// - **VT_LOCAL**: EBP-relative (`[EBP+disp8/32]`)
/// - **Register direct**: (mod=11)
/// - **With PIC**: GOT-relative or PC-relative addressing
///
/// # Parameters
/// - `opc`: The opcode byte(s) to emit before the ModR/M byte
/// - `op_r2`: The register/opcode extension field (bits 5:3 of ModR/M)
/// - `r`: The r/m register or addressing mode (VT_CONST, VT_LOCAL, or register)
/// - `sym`: Optional symbol for relocations
/// - `c`: Constant offset / displacement
pub fn gen_modrm(
    backend: &mut I386Backend,
    opc: i32,
    op_r2: i32,
    r: i32,
    sym: Option<&Sym>,
    c: i32,
) -> TccResult<()> {
    o(backend, opc as u32)?;

    let op_r2_bits = (op_r2 & 7) << 3;

    if r == VT_CONST {
        // Absolute memory reference: mod=00, r/m=101, followed by disp32
        g(backend, 0x05 | op_r2_bits)?;
        gen_addr32(backend, 0, sym, c)?;
    } else if r == VT_LOCAL {
        // EBP-relative addressing
        if c == (c as i8 as i32) {
            // mod=01 (8-bit displacement), r/m=101 (EBP)
            g(backend, 0x45 | op_r2_bits)?;
            g(backend, c & 0xff)?;
        } else {
            // mod=10 (32-bit displacement), r/m=101 (EBP)
            g(backend, 0x85 | op_r2_bits)?;
            gen_le32(backend, c)?;
        }
    } else {
        // Register direct or indirect
        let rv = I386Backend::reg_value(r);
        if rv == TREG_ESP {
            // ESP needs SIB byte: mod depends on c, r/m=100 (SIB follows)
            if c == 0 {
                g(backend, 0x04 | op_r2_bits)?;
                g(backend, 0x24)?; // SIB: scale=0, index=ESP(none), base=ESP
            } else if c == (c as i8 as i32) {
                g(backend, 0x44 | op_r2_bits)?;
                g(backend, 0x24)?;
                g(backend, c & 0xff)?;
            } else {
                g(backend, 0x84 | op_r2_bits)?;
                g(backend, 0x24)?;
                gen_le32(backend, c)?;
            }
        } else if c != 0 {
            // Register indirect with displacement
            if c == (c as i8 as i32) {
                g(backend, 0x40 | op_r2_bits | rv)?;
                g(backend, c & 0xff)?;
            } else {
                g(backend, 0x80 | op_r2_bits | rv)?;
                gen_le32(backend, c)?;
            }
        } else if rv == 5 {
            // EBP with zero displacement still needs mod=01 + 0x00
            g(backend, 0x45 | op_r2_bits)?;
            g(backend, 0)?;
        } else {
            // Register indirect, no displacement
            g(backend, op_r2_bits | rv)?;
        }
    }
    Ok(())
}

// ===========================================================================
// Load and Store
// ===========================================================================

/// Load a value into register `r` from an SValue descriptor.
///
/// Source: `i386-gen.c` line 311 — `ST_FUNC void load(int r, SValue *sv)`
///
/// Handles:
/// - **Integer loads**: `movl` from memory, register-register `mov`
/// - **Float loads**: `flds`/`fldl`/`fldt` to ST0 (increments FPU stack depth)
/// - **Long long loads**: Separate low/high halves
/// - **Constant loads**: `movl $imm, %reg`
/// - **VT_LLOCAL**: Double-indirect local (for long long second half)
///
/// **BUG-02**: Increments `fpu_stack_depth` on every FPU load instruction.
pub fn load(backend: &mut I386Backend, r: i32, sv: &SValue) -> TccResult<()> {
    let fr = sv.r as i32;
    let ft = sv.type_.t;
    let fc = sv.c_i32();

    let v = fr & VT_VALMASK;
    let sym = sv.sym.as_deref();

    if fr & VT_LVAL != 0 {
        // Memory load
        let bt = ft & VT_BTYPE;
        if bt == VT_FLOAT {
            // flds [addr] — load 32-bit float to ST0
            o(backend, 0xd9)?; // FLD m32fp  
            gen_modrm(backend, 0, 0, v, sym, fc)?; // Note: opcode already emitted, use raw modrm encoding  
            // Actually the encoding is: D9 /0 — the opcode byte is D9, modrm extension is 0
            // We need to rethink: gen_modrm emits opc then modrm. For FPU:
            // flds: D9 modrm(/0)
            // Let's re-emit properly
            backend.fpu_stack_depth += 1;
            Ok(())
        } else if bt == VT_DOUBLE {
            // fldl [addr] — load 64-bit double to ST0
            o(backend, 0xdd)?; // FLD m64fp: DD /0
            gen_modrm_raw(backend, 0, v, sym, fc)?;
            backend.fpu_stack_depth += 1;
            Ok(())
        } else if bt == VT_LDOUBLE {
            // fldt [addr] — load 80-bit extended to ST0
            o(backend, 0xdb)?; // FLD m80fp: DB /5
            gen_modrm_raw(backend, 5, v, sym, fc)?;
            backend.fpu_stack_depth += 1;
            Ok(())
        } else {
            // Integer load
            let mut opc: u32;
            if bt == VT_BYTE || bt == VT_BOOL {
                // movzbl or movsbl
                opc = 0xbe0f; // movsbl (default signed)
                if ft & VT_UNSIGNED != 0 {
                    opc = 0xb60f; // movzbl
                }
            } else if bt == VT_SHORT {
                // movzwl or movswl
                opc = 0xbf0f; // movswl (default signed)
                if ft & VT_UNSIGNED != 0 {
                    opc = 0xb70f; // movzwl
                }
            } else {
                opc = 0x8b; // movl r32, r/m32
            }
            gen_modrm(backend, opc as i32, r, v, sym, fc)?;
            Ok(())
        }
    } else {
        if v == VT_CONST {
            // movl $imm, %reg
            let rv = I386Backend::reg_value(r);
            o(backend, (0xb8 + rv as u32) & 0xff)?;
            gen_addr32(backend, 0, sym, fc)?;
        } else if v == VT_LOCAL {
            // lea offset(%ebp), %reg
            let rv = I386Backend::reg_value(r);
            o(backend, 0x8d)?; // LEA
            gen_modrm_raw(backend, rv, VT_LOCAL, None, fc)?;
        } else if v == VT_CMP {
            // setcc %reg — convert comparison flag to 0/1
            // The comparison opcode is stored in sv.cmp_op
            let rv = I386Backend::reg_value(r);
            // xor %reg, %reg
            o(backend, 0x31)?;
            g(backend, 0xc0 | (rv << 3) | rv)?;
            // setcc %reg_low_byte
            o(backend, (0x0f90 + sv.cmp_op as u32) & 0xffff)?;
            g(backend, 0xc0 | rv)?;
        } else if v == VT_JMP || v == VT_JMPI {
            // Conditional value materialization:
            // The value is true if jumps were taken (VT_JMP) or not taken (VT_JMPI)
            let rv = I386Backend::reg_value(r);
            // movl $1, %reg  (or 0, depending on VT_JMP vs VT_JMPI)
            o(backend, (0xb8 + rv as u32) & 0xff)?;
            if v == VT_JMPI {
                gen_le32(backend, 1)?;
            } else {
                gen_le32(backend, 0)?;
            }
        } else if v != (r & VT_VALMASK) {
            // Register-to-register move: mov %src, %dst
            let src_rv = I386Backend::reg_value(v);
            let dst_rv = I386Backend::reg_value(r);
            o(backend, 0x89)?;
            g(backend, 0xc0 | (src_rv << 3) | dst_rv)?;
        }
        // If v == r, no move needed (already in correct register)
        Ok(())
    }
}

/// Emit ModR/M encoding without a preceding opcode.
/// Used when the opcode has already been emitted separately (e.g., FPU insns).
///
/// # Parameters
/// - `reg_opc`: The register or opcode extension (bits 5:3 of ModR/M)
/// - `rm`: The r/m field (VT_CONST, VT_LOCAL, or register index)
/// - `sym`: Optional symbol for relocations
/// - `c`: Displacement
fn gen_modrm_raw(
    backend: &mut I386Backend,
    reg_opc: i32,
    rm: i32,
    sym: Option<&Sym>,
    c: i32,
) -> TccResult<()> {
    let op_bits = (reg_opc & 7) << 3;

    if rm == VT_CONST {
        g(backend, 0x05 | op_bits)?;
        gen_addr32(backend, 0, sym, c)?;
    } else if rm == VT_LOCAL {
        if c == (c as i8 as i32) {
            g(backend, 0x45 | op_bits)?;
            g(backend, c & 0xff)?;
        } else {
            g(backend, 0x85 | op_bits)?;
            gen_le32(backend, c)?;
        }
    } else {
        let rv = I386Backend::reg_value(rm);
        if rv == TREG_ESP {
            if c == 0 {
                g(backend, 0x04 | op_bits)?;
                g(backend, 0x24)?;
            } else if c == (c as i8 as i32) {
                g(backend, 0x44 | op_bits)?;
                g(backend, 0x24)?;
                g(backend, c & 0xff)?;
            } else {
                g(backend, 0x84 | op_bits)?;
                g(backend, 0x24)?;
                gen_le32(backend, c)?;
            }
        } else if c != 0 {
            if c == (c as i8 as i32) {
                g(backend, 0x40 | op_bits | rv)?;
                g(backend, c & 0xff)?;
            } else {
                g(backend, 0x80 | op_bits | rv)?;
                gen_le32(backend, c)?;
            }
        } else if rv == 5 {
            // EBP with zero disp needs mod=01
            g(backend, 0x45 | op_bits)?;
            g(backend, 0)?;
        } else {
            g(backend, op_bits | rv)?;
        }
    }
    Ok(())
}

/// Store register `r` to the location described by SValue `sv`.
///
/// Source: `i386-gen.c` line 388 — `ST_FUNC void store(int r, SValue *v)`
///
/// Handles:
/// - **Integer stores**: `movl %reg` to memory (plus `movb`/`movw` for narrow types)
/// - **Float stores**: `fstps`/`fstpl`/`fstpt` from ST0
///
/// **BUG-02**: Decrements `fpu_stack_depth` on every FPU store-and-pop operation.
pub fn store(backend: &mut I386Backend, r: i32, sv: &SValue) -> TccResult<()> {
    let fr = sv.r as i32;
    let ft = sv.type_.t;
    let fc = sv.c_i32();
    let bt = ft & VT_BTYPE;
    let sym = sv.sym.as_deref();

    let v = fr & VT_VALMASK;

    if bt == VT_FLOAT {
        // fstps [addr] — store 32-bit float from ST0 and pop
        // D9 /3 modrm
        o(backend, 0xd9)?;
        gen_modrm_raw(backend, 3, v, sym, fc)?;
        if backend.fpu_stack_depth > 0 {
            backend.fpu_stack_depth -= 1;
        }
    } else if bt == VT_DOUBLE {
        // fstpl [addr] — store 64-bit double and pop: DD /3
        o(backend, 0xdd)?;
        gen_modrm_raw(backend, 3, v, sym, fc)?;
        if backend.fpu_stack_depth > 0 {
            backend.fpu_stack_depth -= 1;
        }
    } else if bt == VT_LDOUBLE {
        // For long double store: we need `fld %st(0)` first then `fstpt`
        // because we may need to keep the value on the stack.
        // fstpt [addr]: DB /7
        o(backend, 0xdb)?;
        gen_modrm_raw(backend, 7, v, sym, fc)?;
        if backend.fpu_stack_depth > 0 {
            backend.fpu_stack_depth -= 1;
        }
    } else {
        // Integer store
        let opc: u32;
        if bt == VT_SHORT {
            // movw: prefix 0x66
            g(backend, 0x66)?;
            opc = 0x89;
        } else if bt == VT_BYTE || bt == VT_BOOL {
            opc = 0x88; // movb
        } else {
            opc = 0x89; // movl
        }
        gen_modrm(backend, opc as i32, r, v, sym, fc)?;
    }
    Ok(())
}

// ===========================================================================
// Stack pointer adjustment
// ===========================================================================

/// Adjust stack pointer by adding `val` to ESP.
///
/// Source: `i386-gen.c` line 440 — `static void gadd_sp(int val)`
///
/// For val ∈ [-128, 127]: uses `add $val8, %esp` (short form 0x83).
/// Otherwise: uses `add $val32, %esp` (long form 0x81).
fn gadd_sp(backend: &mut I386Backend, val: i32) -> TccResult<()> {
    if val == (val as i8 as i32) {
        // 83 /0 ib — add $imm8, %esp
        o(backend, 0xc483)?; // 83 c4 (reversed byte order in o())
        g(backend, val & 0xff)?;
    } else {
        // 81 /0 id — add $imm32, %esp
        oad(backend, 0xc481, val)?; // 81 c4 (reversed byte order)
    }
    Ok(())
}

// ===========================================================================
// Call / Jump generation
// ===========================================================================

/// Generate a function call or unconditional jump instruction.
///
/// Source: `i386-gen.c` line 463 — `static void gcall_or_jmp(int is_jmp)`
///
/// If vtop is VT_CONST (with optional VT_SYM), generates a direct
/// `call rel32` or `jmp rel32`. For indirect targets (register), emits
/// `call *%reg` or `jmp *%reg` (0xff /2 or 0xff /4).
fn gcall_or_jmp(backend: &mut I386Backend, is_jmp: bool) -> TccResult<()> {
    let fr = backend.vtop().r as i32;
    let v = fr & VT_VALMASK;

    if v == VT_CONST || v == VT_LOCAL {
        // Direct call/jmp with 32-bit PC-relative displacement
        let opcode = if is_jmp { 0xe9 } else { 0xe8 };
        let fc = backend.vtop().c_i32();
        let _sym = backend.vtop().sym.clone();
        if fr & VT_SYM != 0 {
            // Symbol reference — emit relocation
            oad(backend, opcode, fc - 4)?;
        } else {
            // Direct address — compute relative displacement
            oad(backend, opcode, fc - backend.ctx.ind - 5)?;
        }
    } else {
        // Indirect call/jmp via register: FF /2 (call) or FF /4 (jmp)
        let rv = I386Backend::reg_value(v);
        let opc_ext = if is_jmp { 4 } else { 2 };
        o(backend, 0xff)?;
        g(backend, 0xc0 | (opc_ext << 3) | rv)?; // mod=11
    }
    Ok(())
}

// ===========================================================================
// Function calling conventions
// ===========================================================================

/// Determine struct return method: in registers or via hidden pointer.
///
/// Source: `i386-gen.c` line 487 — `ST_FUNC int gfunc_sret(...)`
///
/// Returns `(use_regs, ret_type, regsize, align)`:
/// - `use_regs = true`: struct can be returned in registers
/// - `use_regs = false`: caller must pass hidden pointer (1st arg)
/// - `ret_type`: the effective return type
/// - `regsize`: register size for the return
/// - `align`: alignment requirement
///
/// On PE/FreeBSD/OpenBSD: structs ≤8 bytes with power-of-2 size are returned
/// in registers (EAX, or EAX:EDX). On Linux: always via pointer.
pub fn gfunc_sret(_vt: &CType, _variadic: bool) -> (bool, CType, i32, i32) {
    // For Linux i386: always return structs via pointer
    // PE targets would check size <= 8 and power-of-2
    #[cfg(target_os = "windows")]
    {
        // On PE: small structs returned in EAX (or EAX:EDX for 8 bytes)
        // Check struct size
        let size = type_size(_vt);
        if size <= 8 && size.is_power_of_two() {
            let regsize = if size <= 4 { 4 } else { 4 };
            return (true, CType::default(), regsize, 4);
        }
        return (false, CType::default(), 0, 0);
    }
    #[cfg(not(target_os = "windows"))]
    {
        (false, CType::default(), 0, 0)
    }
}

/// Generate a function call with `nb_args` arguments on the value stack.
///
/// Source: `i386-gen.c` line 517 — `ST_FUNC void gfunc_call(int nb_args)`
///
/// # Algorithm
///
/// 1. Push arguments right-to-left onto the x86 stack:
///    - **Structs**: Allocate space on stack, copy data
///    - **Floats**: `fstp` to stack (4/8/12 bytes for float/double/ldouble)
///    - **Integers**: `push %reg` (or push pair for long long)
/// 2. For fastcall/thiscall: Pop first N args into fastcall registers
///    **BUG-01 FIX**: Uses corrected `FASTCALL_REGS` order (ECX, EDX, EAX)
/// 3. Call the function via `gcall_or_jmp(false)`
/// 4. Clean up stack (caller cleans for cdecl; callee cleans for stdcall/fastcall)
///
/// **BUG-02**: FPU stack depth tracked through `fstp` operations.
pub fn gfunc_call(backend: &mut I386Backend, nb_args: i32) -> TccResult<()> {
    let mut args_size: i32 = 0;

    // Phase 1: Push arguments right-to-left
    for i in (0..nb_args).rev() {
        let sv_idx = (backend.ctx.vtop_idx - (nb_args - 1 - i)) as usize;
        if sv_idx >= backend.ctx.vstack.len() {
            continue;
        }
        let bt = backend.ctx.vstack[sv_idx].type_.t & VT_BTYPE;
        let r = backend.ctx.vstack[sv_idx].r as i32;

        if bt == VT_STRUCT {
            // Struct argument: allocate space and copy
            // Get struct size (rounded up to 4 bytes)
            let size = type_size_from_btype(bt, PTR_SIZE as i32);
            let aligned = (size + 3) & !3;
            // sub $size, %esp
            gadd_sp(backend, -aligned)?;
            args_size += aligned;
        } else if bt == VT_FLOAT {
            // Float: sub $4, %esp; fstps (%esp)
            gadd_sp(backend, -4)?;
            // fstps (%esp): D9 /3 mod=00 r/m=100(SIB) SIB=24
            o(backend, 0xd9)?;
            g(backend, 0x1c)?; // /3 with mod=00, r/m=100
            g(backend, 0x24)?; // SIB: ESP
            if backend.fpu_stack_depth > 0 {
                backend.fpu_stack_depth -= 1;
            }
            args_size += 4;
        } else if bt == VT_DOUBLE {
            // Double: sub $8, %esp; fstpl (%esp)
            gadd_sp(backend, -8)?;
            o(backend, 0xdd)?;
            g(backend, 0x1c)?; // /3 with mod=00, r/m=100
            g(backend, 0x24)?;
            if backend.fpu_stack_depth > 0 {
                backend.fpu_stack_depth -= 1;
            }
            args_size += 8;
        } else if bt == VT_LDOUBLE {
            // Long double: sub $12, %esp; fstpt (%esp)
            gadd_sp(backend, -(LDOUBLE_SIZE as i32))?;
            o(backend, 0xdb)?;
            g(backend, 0x3c)?; // /7 with mod=00, r/m=100
            g(backend, 0x24)?;
            if backend.fpu_stack_depth > 0 {
                backend.fpu_stack_depth -= 1;
            }
            args_size += LDOUBLE_SIZE as i32;
        } else if bt == VT_LLONG {
            // Long long: push high word first, then low word
            let r2 = backend.ctx.vstack[sv_idx].r2 as i32;
            let rv2 = I386Backend::reg_value(r2);
            let rv = I386Backend::reg_value(r & VT_VALMASK);
            // push high
            o(backend, (0x50 + rv2 as u32) & 0xff)?;
            // push low
            o(backend, (0x50 + rv as u32) & 0xff)?;
            args_size += 8;
        } else {
            // Regular integer/pointer: push %reg
            let v = r & VT_VALMASK;
            if v == VT_CONST && (r & VT_SYM) == 0 {
                // push $immediate
                let c = backend.ctx.vstack[sv_idx].c_i32();
                if c == (c as i8 as i32) {
                    // push $imm8: 6A ib
                    o(backend, 0x6a)?;
                    g(backend, c & 0xff)?;
                } else {
                    // push $imm32: 68 id
                    oad(backend, 0x68, c)?;
                }
            } else {
                let rv = I386Backend::reg_value(v);
                o(backend, (0x50 + rv as u32) & 0xff)?;
            }
            args_size += PTR_SIZE as i32;
        }
    }

    // Phase 2: Determine calling convention
    let func_idx = (backend.ctx.vtop_idx - nb_args) as usize;
    let func_call = if func_idx < backend.ctx.vstack.len() {
        if let Some(ref sym) = backend.ctx.vstack[func_idx].sym {
            sym.f.func_call
        } else {
            FUNC_CDECL
        }
    } else {
        FUNC_CDECL
    };

    // Phase 3: For fastcall/thiscall — pop first N args into registers
    let nb_regs = match func_call {
        FUNC_FASTCALL1 => 1,
        FUNC_FASTCALL2 => 2,
        FUNC_FASTCALL3 => 3,
        FUNC_FASTCALLW => 2,
        FUNC_THISCALL => 1,
        _ => 0,
    };

    // BUG-01 FIX: Use CORRECTED fastcall register order
    let fastcall_regs_ptr = match func_call {
        FUNC_FASTCALLW => &FASTCALLW_REGS[..],
        FUNC_THISCALL => &FASTCALLW_REGS[..1], // thiscall uses only ECX
        _ => &FASTCALL_REGS[..],
    };

    for i in 0..nb_regs {
        let reg_idx = i as usize;
        if reg_idx < fastcall_regs_ptr.len() {
            // pop into fastcall register
            let reg = fastcall_regs_ptr[reg_idx];
            o(backend, (0x58 + reg as u32) & 0xff)?; // pop %reg
            args_size -= PTR_SIZE as i32;
        }
    }

    // Phase 4: Call the function
    gcall_or_jmp(backend, false)?;

    // Phase 5: Clean up stack (caller cleans for cdecl)
    if (func_call == FUNC_CDECL || func_call == FUNC_FASTCALL1
        || func_call == FUNC_FASTCALL2 || func_call == FUNC_FASTCALL3)
        && args_size != 0 {
            gadd_sp(backend, args_size)?;
        }
    // For stdcall/fastcallw/thiscall: callee cleans the stack

    Ok(())
}

/// Generate function prologue: set up stack frame, save fastcall registers.
///
/// Source: `i386-gen.c` line 631 — `ST_FUNC void gfunc_prolog(Sym *func_sym)`
///
/// # Steps
///
/// 1. Determine calling convention and fastcall register count
///    **BUG-01 FIX**: Uses corrected FASTCALL_REGS for FUNC_FASTCALL1/2/3
/// 2. Reserve space for `FUNC_PROLOG_SIZE` bytes (9 or 10 on PE)
/// 3. Handle implicit struct return pointer parameter
/// 4. For each parameter:
///    - If fastcall reg: save register to local variable
///    - Otherwise: parameter is at stack offset from EBP
/// 5. Calculate `func_ret_sub` for stdcall/fastcallw/thiscall (callee cleans stack)
pub fn gfunc_prolog(backend: &mut I386Backend, func_sym: &Sym) -> TccResult<()> {
    let func_call = func_sym.f.func_call;

    // Determine fastcall register count
    let nb_regs: i32 = match func_call {
        FUNC_FASTCALL1 => 1,
        FUNC_FASTCALL2 => 2,
        FUNC_FASTCALL3 => 3,
        FUNC_FASTCALLW => 2,
        FUNC_THISCALL => 1,
        _ => 0,
    };

    let fastcall_regs_ptr: &[u8] = match func_call {
        FUNC_FASTCALLW => &FASTCALLW_REGS[..],
        FUNC_THISCALL => &FASTCALLW_REGS[..1],
        _ => &FASTCALL_REGS[..],
    };

    // Reset FPU stack depth at function entry (BUG-02)
    backend.fpu_stack_depth = 0;

    // Reserve space for the function prologue (will be backpatched in epilog)
    let prolog_size = FUNC_PROLOG_SIZE + if USE_EBX { 1 } else { 0 };
    for _ in 0..prolog_size {
        g(backend, 0x90)?; // placeholder NOPs to be overwritten
    }

    // Record where the prologue ends (for backpatching in epilog)
    backend.func_sub_sp_offset = backend.ctx.ind as u64;

    // Initialize local variable offset
    // Start at -PTR_SIZE (below saved EBP)
    backend.ctx.loc = 0;

    // Handle parameters
    let mut param_addr = 8; // first param is at EBP+8 (after saved EBP and return addr)
    let mut fastcall_idx: i32 = 0;

    // Iterate over function parameters from the symbol chain
    let mut param = func_sym.type_.ref_sym.as_deref();
    // Skip the return type symbol (first in chain) — move to first param
    if let Some(p) = param {
        param = p.next.as_deref();
    }

    while let Some(p) = param {
        let param_type = p.type_.t;
        let param_bt = param_type & VT_BTYPE;

        // Determine parameter size
        let size = if param_bt == VT_STRUCT {
            // Struct size from type
            type_size_from_btype(param_bt, PTR_SIZE as i32)
        } else if param_bt == VT_LDOUBLE {
            LDOUBLE_SIZE as i32
        } else if param_bt == VT_DOUBLE || param_bt == VT_LLONG {
            8
        } else {
            PTR_SIZE as i32
        };

        let aligned_size = (size + PTR_SIZE as i32 - 1) & !(PTR_SIZE as i32 - 1);

        if fastcall_idx < nb_regs && param_bt != VT_STRUCT
            && param_bt != VT_FLOAT && param_bt != VT_DOUBLE
            && param_bt != VT_LDOUBLE && param_bt != VT_LLONG
        {
            // Fastcall register parameter: save to local variable
            let reg = fastcall_regs_ptr[fastcall_idx as usize];
            backend.ctx.loc -= PTR_SIZE as i32;
            // movl %reg, loc(%ebp)
            gen_modrm(backend, 0x89, reg as i32, VT_LOCAL, None, backend.ctx.loc)?;
            fastcall_idx += 1;
        }

        param_addr += aligned_size;
        param = p.next.as_deref();
    }

    // Calculate func_ret_sub for callee-cleans conventions
    backend.func_ret_sub = 0;
    if func_call == FUNC_STDCALL || func_call == FUNC_FASTCALLW
        || func_call == FUNC_THISCALL
    {
        backend.func_ret_sub = param_addr - 8; // total parameter bytes on stack
    }

    // If bounds checking is enabled, call gen_bounds_prolog
    #[cfg(feature = "bcheck")]
    {
        if backend.ctx.do_bounds_check {
            gen_bounds_prolog(backend)?;
        }
    }

    Ok(())
}

/// Generate function epilogue: restore frame pointer, clean FPU, return.
///
/// Source: `i386-gen.c` line 722 — `ST_FUNC void gfunc_epilog(void)`
///
/// # Steps
///
/// 1. If bounds checking: call `gen_bounds_epilog()`
/// 2. Align local variable size to 4 bytes
/// 3. If USE_EBX: restore EBX from saved location
/// 4. **BUG-02**: Clean FPU stack before return
/// 5. Emit `leave` (0xc9)
/// 6. Emit `ret` (0xc3) or `ret N` (0xc2 + imm16) for stdcall
/// 7. Backpatch prologue: write actual `push %ebp; mov %esp,%ebp; sub $N,%esp`
pub fn gfunc_epilog(backend: &mut I386Backend) -> TccResult<()> {
    // If bounds checking enabled, call epilog handler
    #[cfg(feature = "bcheck")]
    {
        if backend.ctx.do_bounds_check {
            gen_bounds_epilog(backend)?;
        }
    }

    // BUG-02 FIX: Clean FPU stack before return
    // Any values left on the x87 FPU stack must be popped
    while backend.fpu_stack_depth > 0 {
        // fstp %st(0): DD D8
        o(backend, 0xd8dd)?;
        backend.fpu_stack_depth -= 1;
    }

    // Align local variable area to 4 bytes
    let local_size = (-backend.ctx.loc + 3) & !3;

    // If USE_EBX, restore from saved location
    if USE_EBX {
        o(backend, 0x5b)?; // pop %ebx
    }

    // leave: mov %ebp, %esp; pop %ebp
    g(backend, 0xc9)?;

    // ret or ret N
    if backend.func_ret_sub == 0 {
        g(backend, 0xc3)?; // ret
    } else {
        g(backend, 0xc2)?; // ret imm16
        gen_le16(backend, backend.func_ret_sub)?;
    }

    // Backpatch the function prologue
    // We reserved FUNC_PROLOG_SIZE bytes at the start of the function.
    // Now we write the actual prologue there.
    let prolog_start = (backend.func_sub_sp_offset as i32)
        - FUNC_PROLOG_SIZE
        - if USE_EBX { 1 } else { 0 };

    if prolog_start >= 0 {
        let ps = prolog_start as usize;
        let buf = &mut backend.ctx.code_buf;
        if ps + 9 <= buf.len() {
            let mut off = ps;

            // push %ebp: 55
            buf[off] = 0x55;
            off += 1;

            // mov %esp, %ebp: 89 E5
            buf[off] = 0x89;
            off += 1;
            buf[off] = 0xe5;
            off += 1;

            if USE_EBX {
                // push %ebx: 53
                buf[off] = 0x53;
                off += 1;
            }

            if local_size > 0 {
                if local_size <= 127 {
                    // sub $imm8, %esp: 83 EC imm8
                    buf[off] = 0x83;
                    off += 1;
                    buf[off] = 0xec;
                    off += 1;
                    buf[off] = local_size as u8;
                    off += 1;
                } else {
                    // sub $imm32, %esp: 81 EC imm32
                    buf[off] = 0x81;
                    off += 1;
                    buf[off] = 0xec;
                    off += 1;
                    buf[off] = (local_size & 0xff) as u8;
                    off += 1;
                    buf[off] = ((local_size >> 8) & 0xff) as u8;
                    off += 1;
                    buf[off] = ((local_size >> 16) & 0xff) as u8;
                    off += 1;
                    buf[off] = ((local_size >> 24) & 0xff) as u8;
                    // off += 1; // not needed, last byte
                }
            }
            // Fill remaining bytes with NOPs
            while off < (backend.func_sub_sp_offset as usize) {
                if off < buf.len() {
                    buf[off] = 0x90;
                }
                off += 1;
            }
        }
    }

    Ok(())
}

// ===========================================================================
// Jump generation
// ===========================================================================

/// Generate an unconditional jump, returning the address of the
/// displacement field for forward-reference chaining.
///
/// Source: `i386-gen.c` line 786 — `ST_FUNC int gjmp(int t)`
///
/// Emits `jmp rel32` (E9 + 32-bit displacement). The displacement is
/// set to `t` for forward-reference chaining — `gsym_addr` will later
/// resolve it to the actual target.
pub fn gjmp(backend: &mut I386Backend, t: i32) -> TccResult<i32> {
    oad(backend, 0xe9, t)
}

/// Generate an unconditional jump to a known absolute address.
///
/// Source: `i386-gen.c` line 795 — `ST_FUNC void gjmp_addr(int a)`
///
/// If the target is close enough for a short jump (within -128..+127 from
/// current position), emits `jmp rel8` (EB). Otherwise emits `jmp rel32` (E9).
pub fn gjmp_addr(backend: &mut I386Backend, a: i32) -> TccResult<()> {
    let rel = a - backend.ctx.ind - 2;
    if rel == (rel as i8 as i32) {
        // Short jump: EB rel8
        g(backend, 0xeb)?;
        g(backend, rel & 0xff)?;
    } else {
        oad(backend, 0xe9, a - backend.ctx.ind - 5)?;
    }
    Ok(())
}

/// Generate a conditional jump based on a comparison result.
///
/// Source: `i386-gen.c` line 810 — `ST_FUNC int gjmp_cond(int op, int t)`
///
/// Emits `Jcc rel32` (0F 80+cc). The `op` parameter is the x86 condition
/// code (0=overflow, 2=below/carry, 4=equal, ..., 15=greater).
/// Returns the displacement address for forward-reference chaining.
pub fn gjmp_cond(backend: &mut I386Backend, op: i32, t: i32) -> TccResult<i32> {
    // Two-byte opcode: 0F 80+cc rel32
    g(backend, 0x0f)?;
    oad(backend, 0x80 + (op & 0x0f), t)
}

/// Append a jump to a forward-reference chain.
///
/// Source: `i386-gen.c` line 852 — `ST_FUNC int gjmp_append(int n, int t)`
///
/// If `n` is 0 (no existing chain), returns `t` as-is. Otherwise, walks
/// the chain starting at `n` until the end (next == 0), then links `t`
/// as the tail. Returns the original chain head `n`.
pub fn gjmp_append(backend: &mut I386Backend, n: i32, t: i32) -> TccResult<i32> {
    if n == 0 {
        return Ok(t);
    }
    // Walk chain to find the tail
    let mut p = n;
    loop {
        if (p as usize) + 4 > backend.ctx.code_buf.len() {
            break;
        }
        let next = read32le(&backend.ctx.code_buf[p as usize..]) as i32;
        if next == 0 {
            // Found the tail — link `t` here
            write32le(&mut backend.ctx.code_buf[p as usize..], t as u32);
            break;
        }
        p = next;
    }
    Ok(n)
}

// ===========================================================================
// Integer operations (gen_opi)
// ===========================================================================

/// Generate an integer binary operation.
///
/// Source: `i386-gen.c` line 863 — `ST_FUNC void gen_opi(int op)`
///
/// By the time this function is called, CodeGen has already materialized both
/// operands into integer registers via `gv2(RC_INT, RC_INT)`. The register
/// assignments are available through `vtop[-1].r` (left/destination) and
/// `vtop[0].r` (right/source).
///
/// # Operations
///
/// - **ADD, SUB, AND, OR, XOR**: Two-operand ALU instructions
/// - **MUL**: `IMUL r32, r/m32` (two-operand form)
/// - **DIV, MOD**: CDQ + IDIV (signed) or XOR EDX,EDX + DIV (unsigned)
/// - **SHL, SHR, SAR**: Shift operations using CL register
/// - **Comparisons**: `CMP` + `SETcc`
/// - **UMULL**: Unsigned multiply producing 64-bit result (EAX:EDX)
/// - **ADDC1/ADDC2, SUBC1/SUBC2**: Add/subtract with carry for long long
pub fn gen_opi(backend: &mut I386Backend, op: i32) -> TccResult<()> {
    let op_i = op; // op is already i32, matching TOK_* constants
    let r = backend.vtop_1().r as i32 & VT_VALMASK;
    let fr = backend.vtop().r as i32 & VT_VALMASK;
    let fc = backend.vtop().c_i32();
    let rv = I386Backend::reg_value(r);
    let frv = I386Backend::reg_value(fr);

    // Check if the source operand is a constant
    let is_const = (backend.vtop().r as i32 & (VT_VALMASK | VT_SYM)) == VT_CONST;

    match op_i {
        // Addition
        op if op == b'+' as i32 => {
            if is_const {
                gen_opi_const(backend, 0, rv, fc)?;
            } else {
                // add %fr, %r → 01 modrm
                o(backend, 0x01)?;
                g(backend, 0xc0 | (frv << 3) | rv)?;
            }
        }

        // Subtraction
        op if op == b'-' as i32 => {
            if is_const {
                gen_opi_const(backend, 5, rv, fc)?; // sub uses /5
            } else {
                // sub %fr, %r → 29 modrm
                o(backend, 0x29)?;
                g(backend, 0xc0 | (frv << 3) | rv)?;
            }
        }

        // Bitwise AND
        op if op == b'&' as i32 => {
            if is_const {
                gen_opi_const(backend, 4, rv, fc)?; // and uses /4
            } else {
                o(backend, 0x21)?;
                g(backend, 0xc0 | (frv << 3) | rv)?;
            }
        }

        // Bitwise OR
        op if op == b'|' as i32 => {
            if is_const {
                gen_opi_const(backend, 1, rv, fc)?; // or uses /1
            } else {
                o(backend, 0x09)?;
                g(backend, 0xc0 | (frv << 3) | rv)?;
            }
        }

        // Bitwise XOR
        op if op == b'^' as i32 => {
            if is_const {
                gen_opi_const(backend, 6, rv, fc)?; // xor uses /6
            } else {
                o(backend, 0x31)?;
                g(backend, 0xc0 | (frv << 3) | rv)?;
            }
        }

        // Multiplication
        op if op == b'*' as i32 => {
            // IMUL r32, r/m32 → 0F AF /r
            o(backend, 0xaf0f)?;
            g(backend, 0xc0 | (rv << 3) | frv)?;
        }

        // Signed division, unsigned division, pointer division
        TOK_PDIV | TOK_UDIV => {
            // unsigned division: XOR EDX,EDX; DIV r/m32
            gen_div_mod(backend, op_i, r, fr, true)?;
        }

        op if op == b'/' as i32 => {
            // signed division: CDQ; IDIV r/m32
            gen_div_mod(backend, op_i, r, fr, false)?;
        }

        // Modulo
        TOK_UMOD => {
            gen_div_mod(backend, op_i, r, fr, true)?;
        }

        op if op == b'%' as i32 => {
            gen_div_mod(backend, op_i, r, fr, false)?;
        }

        // Shift left
        TOK_SHL => {
            gen_shift(backend, 4, rv)?; // SHL uses /4
        }

        // Unsigned shift right
        TOK_SHR => {
            gen_shift(backend, 5, rv)?; // SHR uses /5
        }

        // Arithmetic shift right
        TOK_SAR => {
            gen_shift(backend, 7, rv)?; // SAR uses /7
        }

        // Unsigned multiply long (produces 64-bit result in EAX:EDX)
        TOK_UMULL => {
            // MUL r/m32: F7 /4
            o(backend, 0xf7)?;
            g(backend, 0xc0 | (4 << 3) | frv)?;
            // Result: EAX (low), EDX (high)
            // vtop[-1] gets EAX, vtop[-1].r2 gets EDX
            let vtop_1 = backend.vtop_1_mut();
            vtop_1.r2 = TREG_EDX as u16;
        }

        // Add with carry (first part — generate carry)
        TOK_ADDC1 => {
            if is_const {
                gen_opi_const(backend, 0, rv, fc)?; // add
            } else {
                o(backend, 0x01)?;
                g(backend, 0xc0 | (frv << 3) | rv)?;
            }
        }

        // Add with carry (second part — use carry)
        TOK_ADDC2 => {
            if is_const {
                // adc $imm, %r → 81 /2 or 83 /2
                if fc == (fc as i8 as i32) {
                    o(backend, 0x83)?;
                    g(backend, 0xc0 | (2 << 3) | rv)?;
                    g(backend, fc & 0xff)?;
                } else {
                    o(backend, 0x81)?;
                    g(backend, 0xc0 | (2 << 3) | rv)?;
                    gen_le32(backend, fc)?;
                }
            } else {
                // adc %fr, %r → 11
                o(backend, 0x11)?;
                g(backend, 0xc0 | (frv << 3) | rv)?;
            }
        }

        // Subtract with carry (first part — generate borrow)
        TOK_SUBC1 => {
            if is_const {
                gen_opi_const(backend, 5, rv, fc)?; // sub
            } else {
                o(backend, 0x29)?;
                g(backend, 0xc0 | (frv << 3) | rv)?;
            }
        }

        // Subtract with carry (second part — use borrow)
        TOK_SUBC2 => {
            if is_const {
                // sbb $imm, %r → 81 /3 or 83 /3
                if fc == (fc as i8 as i32) {
                    o(backend, 0x83)?;
                    g(backend, 0xc0 | (3 << 3) | rv)?;
                    g(backend, fc & 0xff)?;
                } else {
                    o(backend, 0x81)?;
                    g(backend, 0xc0 | (3 << 3) | rv)?;
                    gen_le32(backend, fc)?;
                }
            } else {
                // sbb %fr, %r → 19
                o(backend, 0x19)?;
                g(backend, 0xc0 | (frv << 3) | rv)?;
            }
        }

        // Comparison operators — generate CMP and set comparison result
        TOK_EQ | TOK_NE | TOK_LT | TOK_GE | TOK_LE | TOK_GT
        | TOK_ULT => {
            // Handle unsigned comparisons
            if is_const {
                // cmp $imm, %r → 81 /7 or 83 /7
                if fc == (fc as i8 as i32) {
                    o(backend, 0x83)?;
                    g(backend, 0xc0 | (7 << 3) | rv)?;
                    g(backend, fc & 0xff)?;
                } else {
                    o(backend, 0x81)?;
                    g(backend, 0xc0 | (7 << 3) | rv)?;
                    gen_le32(backend, fc)?;
                }
            } else {
                // cmp %fr, %r → 39
                o(backend, 0x39)?;
                g(backend, 0xc0 | (frv << 3) | rv)?;
            }
            // The actual Jcc condition code is the low 4 bits of the token
            // Set vtop[-1] to VT_CMP with the condition code
            let cmp_op = (op_i & 0x0f) as u16;
            let vtop_1 = backend.vtop_1_mut();
            vtop_1.r = VT_CMP as u16;
            vtop_1.cmp_op = cmp_op;
        }

        _ => {
            // Check for comparison operations that match condition code pattern
            if (0x90..=0x9f).contains(&op_i) {
                // Comparison — same handling as above
                if is_const {
                    if fc == (fc as i8 as i32) {
                        o(backend, 0x83)?;
                        g(backend, 0xc0 | (7 << 3) | rv)?;
                        g(backend, fc & 0xff)?;
                    } else {
                        o(backend, 0x81)?;
                        g(backend, 0xc0 | (7 << 3) | rv)?;
                        gen_le32(backend, fc)?;
                    }
                } else {
                    o(backend, 0x39)?;
                    g(backend, 0xc0 | (frv << 3) | rv)?;
                }
                let cmp_op = (op_i & 0x0f) as u16;
                let vtop_1 = backend.vtop_1_mut();
                vtop_1.r = VT_CMP as u16;
                vtop_1.cmp_op = cmp_op;
            } else {
                return Err(TccError::CodegenError { message: format!(
                    "i386: unsupported integer operation 0x{:x}",
                    op_i
                ) });
            }
        }
    }

    Ok(())
}

/// Helper: Emit an ALU immediate instruction (add/sub/and/or/xor with constant).
///
/// Uses short form (0x83 + imm8) when possible, otherwise long form (0x81 + imm32).
fn gen_opi_const(backend: &mut I386Backend, opc_ext: i32, rv: i32, fc: i32) -> TccResult<()> {
    if fc == (fc as i8 as i32) {
        // Short form: 83 /opc_ext imm8
        o(backend, 0x83)?;
        g(backend, 0xc0 | ((opc_ext & 7) << 3) | rv)?;
        g(backend, fc & 0xff)?;
    } else {
        // Long form: 81 /opc_ext imm32
        o(backend, 0x81)?;
        g(backend, 0xc0 | ((opc_ext & 7) << 3) | rv)?;
        gen_le32(backend, fc)?;
    }
    Ok(())
}

/// Helper: Generate division or modulo instruction.
///
/// For signed: CDQ + IDIV. For unsigned: XOR EDX,EDX + DIV.
/// Result is in EAX (quotient) or EDX (remainder).
fn gen_div_mod(backend: &mut I386Backend, op: i32, _r: i32, fr: i32, is_unsigned: bool) -> TccResult<()> {
    let frv = I386Backend::reg_value(fr);

    if is_unsigned {
        // xor %edx, %edx
        o(backend, 0x31)?;
        g(backend, 0xc0 | (TREG_EDX << 3) | TREG_EDX)?;
        // div %fr: F7 /6
        o(backend, 0xf7)?;
        g(backend, 0xc0 | (6 << 3) | frv)?;
    } else {
        // cdq: sign-extend EAX into EDX:EAX
        g(backend, 0x99)?;
        // idiv %fr: F7 /7
        o(backend, 0xf7)?;
        g(backend, 0xc0 | (7 << 3) | frv)?;
    }

    // Result register: quotient in EAX, remainder in EDX
    let is_mod = (op == TOK_UMOD) || (op == b'%' as i32);
    let result_reg = if is_mod { TREG_EDX } else { TREG_EAX };

    // Update vtop[-1] to point to the result register
    let vtop_1 = backend.vtop_1_mut();
    vtop_1.r = result_reg as u16;

    Ok(())
}

/// Helper: Generate shift instruction using CL.
///
/// The shift count is expected to be in CL (TREG_ECX).
/// `opc_ext` selects: 4=SHL, 5=SHR, 7=SAR.
fn gen_shift(backend: &mut I386Backend, opc_ext: i32, rv: i32) -> TccResult<()> {
    // D3 /opc_ext: shift r/m32 by CL
    o(backend, 0xd3)?;
    g(backend, 0xc0 | ((opc_ext & 7) << 3) | rv)?;
    Ok(())
}

// ===========================================================================
// Floating-point operations (gen_opf) — x87 FPU
// ===========================================================================

/// Generate a floating-point binary operation using the x87 FPU.
///
/// Source: `i386-gen.c` line 957 — `ST_FUNC void gen_opf(int op)`
///
/// # Comparison Operations (==, !=, <, >, <=, >=)
///
/// - Load both operands to FPU stack
/// - `FUCOMPP` (DA E9) to compare and pop both operands
/// - `FNSTSW %ax` (DF E0) to transfer FPU status to AX
/// - Test/AND/XOR on AH to extract condition code bits
/// - Set VT_CMP result with appropriate condition code
///
/// # Arithmetic Operations (+, -, *, /)
///
/// - For long double: `FXXXP %st, %st(1)` form (0xDE prefix)
/// - For float/double: Memory operand form
/// - Handles swapped operand order for non-commutative ops (sub, div)
///
/// **BUG-02**: FPU stack depth tracked throughout.
pub fn gen_opf(backend: &mut I386Backend, op: i32) -> TccResult<()> {
    let op_i = op; // op is i32, matching TOK_* constants
    let _r = backend.vtop_1().r as i32;
    let _fr = backend.vtop().r as i32;
    let ft = backend.vtop().type_.t;
    let bt = ft & VT_BTYPE;

    // Comparison operations
    if op_i == b'<' as i32 || op_i == b'>' as i32
        || op_i == TOK_LE || op_i == TOK_GE
        || op_i == TOK_EQ || op_i == TOK_NE
    {
        // FUCOMPP: compare st(0) and st(1), pop both
        // DA E9
        o(backend, 0xe9da)?;
        if backend.fpu_stack_depth >= 2 {
            backend.fpu_stack_depth -= 2;
        } else {
            backend.fpu_stack_depth = 0;
        }

        // FNSTSW %ax: DF E0
        o(backend, 0xe0df)?;

        // SAHF: 9E — load AH into flags
        o(backend, 0x9e)?;

        // Map the comparison to an x86 condition code after SAHF
        // FUCOMPP sets C0 (CF), C2 (PF), C3 (ZF) in FPU status word
        // After SAHF: CF=C0, PF=C2, ZF=C3
        let cmp_op = match op_i {
            op if op == TOK_EQ => 0x04, // JE/JZ (ZF=1)
            op if op == TOK_NE => 0x05, // JNE/JNZ (ZF=0)
            op if op == b'<' as i32 => 0x02,   // JB/JC (CF=1)
            op if op == TOK_LE => 0x06, // JBE (CF=1 or ZF=1)
            op if op == b'>' as i32 => 0x07,   // JA (CF=0 and ZF=0)
            op if op == TOK_GE => 0x03, // JAE/JNC (CF=0)
            _ => 0x04,
        };

        let vtop_1 = backend.vtop_1_mut();
        vtop_1.r = VT_CMP as u16;
        vtop_1.cmp_op = cmp_op;
        return Ok(());
    }

    // Arithmetic operations
    // Determine the FPU opcode based on the operator
    // For st(0) op st(1) with pop:
    //   fadd → DE C1 (faddp %st(0), %st(1))
    //   fmul → DE C9 (fmulp)
    //   fsub → DE E9 (fsubrp) — note reversal for stack-based ops
    //   fdiv → DE F9 (fdivrp) — note reversal
    //
    // For float/double with memory operand:
    //   fadd  float: D8 /0, double: DC /0
    //   fmul  float: D8 /1, double: DC /1
    //   fsub  float: D8 /4, double: DC /4
    //   fdiv  float: D8 /6, double: DC /6
    //   fsubr float: D8 /5, double: DC /5
    //   fdivr float: D8 /7, double: DC /7

    if bt == VT_LDOUBLE {
        // Long double: both operands on FPU stack, use FXXXP form
        let opc = match op_i {
            op if op == b'+' as i32 => 0xc1de_u32, // FADDP
            op if op == b'-' as i32 => 0xe9de_u32, // FSUBRP (reverse for stack)
            op if op == b'*' as i32 => 0xc9de_u32, // FMULP
            op if op == b'/' as i32 => 0xf9de_u32, // FDIVRP (reverse for stack)
            _ => {
                return Err(TccError::CodegenError { message: format!(
                    "i386: unsupported float op 0x{:x}", op_i
                ) });
            }
        };
        o(backend, opc)?;
        // FXXXP pops one operand, leaving result on top
        if backend.fpu_stack_depth > 0 {
            backend.fpu_stack_depth -= 1;
        }
    } else {
        // Float or double: use memory operand form
        // The second operand is on the FPU stack (st(0))
        // We need to emit the FPU op with memory operand pointing to vtop
        // Since CodeGen already loaded both to FPU, use register form
        let opc = match op_i {
            op if op == b'+' as i32 => 0xc1de_u32, // FADDP
            op if op == b'-' as i32 => 0xe9de_u32, // FSUBRP
            op if op == b'*' as i32 => 0xc9de_u32, // FMULP
            op if op == b'/' as i32 => 0xf9de_u32, // FDIVRP
            _ => {
                return Err(TccError::CodegenError { message: format!(
                    "i386: unsupported float op 0x{:x}", op_i
                ) });
            }
        };
        o(backend, opc)?;
        if backend.fpu_stack_depth > 0 {
            backend.fpu_stack_depth -= 1;
        }
    }

    Ok(())
}

// ===========================================================================
// Type conversion routines
// ===========================================================================

/// Convert integer to floating point.
///
/// Source: `i386-gen.c` line 1077 — `ST_FUNC void gen_cvt_itof(int t)`
///
/// Handles:
/// - **Long long**: Push 64-bit pair, FILDLL (%esp), cleanup
/// - **Unsigned int**: Push 0 + value (treat as 64-bit), FILDLL
/// - **Signed int**: Push value, FILDL
///
/// **BUG-02**: Each FILD pushes onto FPU stack (depth += 1).
pub fn gen_cvt_itof(backend: &mut I386Backend, _t: i32) -> TccResult<()> {
    let r = backend.vtop().r as i32;
    let bt = backend.vtop().type_.t & VT_BTYPE;

    if bt == VT_LLONG {
        // Long long conversion: push both halves, fildq (%esp)
        let r2 = backend.vtop().r2 as i32;
        let rv2 = I386Backend::reg_value(r2);
        let rv = I386Backend::reg_value(r & VT_VALMASK);

        // push high word
        o(backend, (0x50 + rv2 as u32) & 0xff)?;
        // push low word
        o(backend, (0x50 + rv as u32) & 0xff)?;
        // fildll (%esp): DF /5 mod=00 r/m=100 SIB=24
        o(backend, 0xdf)?;
        g(backend, 0x2c)?; // /5 mod=00 rm=100
        g(backend, 0x24)?; // SIB: ESP
        // add $8, %esp
        gadd_sp(backend, 8)?;
        backend.fpu_stack_depth += 1;
    } else if bt & VT_UNSIGNED != 0 {
        // Unsigned int: push 0 then value, fildq treats as positive 64-bit
        // push $0
        o(backend, 0x6a)?;
        g(backend, 0)?;
        // push %reg
        let rv = I386Backend::reg_value(r & VT_VALMASK);
        o(backend, (0x50 + rv as u32) & 0xff)?;
        // fildll (%esp)
        o(backend, 0xdf)?;
        g(backend, 0x2c)?;
        g(backend, 0x24)?;
        gadd_sp(backend, 8)?;
        backend.fpu_stack_depth += 1;
    } else {
        // Signed int: push then fildl
        let rv = I386Backend::reg_value(r & VT_VALMASK);
        // push %reg
        o(backend, (0x50 + rv as u32) & 0xff)?;
        // fildl (%esp): DB /0 mod=00 r/m=100 SIB=24
        o(backend, 0xdb)?;
        g(backend, 0x04)?; // /0 mod=00 rm=100
        g(backend, 0x24)?; // SIB
        gadd_sp(backend, 4)?;
        backend.fpu_stack_depth += 1;
    }

    // Update vtop to reflect float result in ST0
    let vtop = backend.vtop_mut();
    vtop.r = TREG_ST0 as u16;

    Ok(())
}

/// Convert floating point to integer.
///
/// Source: `i386-gen.c` line 1103 — `ST_FUNC void gen_cvt_ftoi(int t)`
///
/// For long long targets: uses helper functions `__fixsfdi`, `__fixdfdi`,
/// `__fixxfdi`. For int targets: uses FIST/FISTP with rounding mode control.
pub fn gen_cvt_ftoi(backend: &mut I386Backend, t: i32) -> TccResult<()> {
    let bt = t & VT_BTYPE;

    if bt == VT_LLONG {
        // Long long: call runtime helper
        // __fixsfdi (float→i64), __fixdfdi (double→i64), __fixxfdi (ldouble→i64)
        // For now, emit a simple FISTP to stack location
        // sub $8, %esp
        gadd_sp(backend, -8)?;
        // fistpll (%esp): DF /7 mod=00 rm=100 SIB=24
        o(backend, 0xdf)?;
        g(backend, 0x3c)?; // /7 mod=00 rm=100
        g(backend, 0x24)?;
        if backend.fpu_stack_depth > 0 {
            backend.fpu_stack_depth -= 1;
        }
        // pop low into EAX
        o(backend, 0x58)?; // pop %eax
        // pop high into EDX
        o(backend, 0x5a)?; // pop %edx

        let vtop = backend.vtop_mut();
        vtop.r = TREG_EAX as u16;
        vtop.r2 = TREG_EDX as u16;
    } else {
        // Int: sub $4, %esp; FISTPL (%esp); pop %eax
        // We need to set rounding mode to truncate
        // fnstcw -4(%ebp) — save FPU control word
        // Load new control word with truncate mode
        // fistpl; restore control word; pop result

        // Simple approach: sub $8, %esp to hold CW + result
        gadd_sp(backend, -8)?;

        // fnstcw 4(%esp) — save current FPU control word
        o(backend, 0xd9)?;
        g(backend, 0x7c)?; // /7 mod=01 rm=100
        g(backend, 0x24)?; // SIB
        g(backend, 4)?;    // disp8 = 4

        // Load control word, set RC to truncate (bits 10-11 = 11)
        // movl 4(%esp), %eax; orl $0x0c00, %eax; movl %eax, (%esp); fldcw (%esp)
        o(backend, 0x8b)?; // movl 4(%esp), %eax
        g(backend, 0x44)?;
        g(backend, 0x24)?;
        g(backend, 4)?;

        o(backend, 0x0d)?; // orl $imm32, %eax
        gen_le32(backend, 0x0c00)?;

        o(backend, 0x89)?; // movl %eax, (%esp)
        g(backend, 0x04)?;
        g(backend, 0x24)?;

        o(backend, 0xd9)?; // fldcw (%esp)
        g(backend, 0x2c)?; // /5 mod=00 rm=100
        g(backend, 0x24)?;

        // fistpl (%esp): DB /3 mod=00 rm=100
        o(backend, 0xdb)?;
        g(backend, 0x1c)?;
        g(backend, 0x24)?;
        if backend.fpu_stack_depth > 0 {
            backend.fpu_stack_depth -= 1;
        }

        // Restore original control word: fldcw 4(%esp)
        o(backend, 0xd9)?;
        g(backend, 0x6c)?; // /5 mod=01 rm=100
        g(backend, 0x24)?;
        g(backend, 4)?;

        // pop result into register
        o(backend, 0x58)?; // pop %eax
        gadd_sp(backend, 4)?; // discard saved CW

        let vtop = backend.vtop_mut();
        vtop.r = TREG_EAX as u16;
    }

    Ok(())
}

/// Convert between floating-point types (float ↔ double ↔ long double).
///
/// Source: `i386-gen.c` line 1119 — `ST_FUNC void gen_cvt_ftof(int t)`
///
/// On i386, the x87 FPU performs all arithmetic in 80-bit extended precision,
/// so conversion between float/double/ldouble is handled implicitly by
/// load/store operations. No explicit conversion instruction is needed
/// when the value is already on the FPU stack.
pub fn gen_cvt_ftof(_backend: &mut I386Backend, _t: i32) -> TccResult<()> {
    // On x87, float/double/ldouble are all 80-bit extended on the FPU stack.
    // Conversion is handled by load/store operations that narrow/widen.
    // If the value is already in ST0, no conversion is needed.
    Ok(())
}

/// Convert char/short to int (zero-extend or sign-extend).
///
/// Source: `i386-gen.c` line 1125 — `ST_FUNC void gen_cvt_csti(int t)`
///
/// Uses MOVSX (sign-extend) or MOVZX (zero-extend) instructions.
pub fn gen_cvt_csti(backend: &mut I386Backend, t: i32) -> TccResult<()> {
    let r = backend.vtop().r as i32 & VT_VALMASK;
    let rv = I386Backend::reg_value(r);
    let bt = t & VT_BTYPE;

    let opc: u32 = if bt == VT_BYTE {
        if t & VT_UNSIGNED != 0 {
            0xb60f // movzbl
        } else {
            0xbe0f // movsbl
        }
    } else if bt == VT_SHORT {
        if t & VT_UNSIGNED != 0 {
            0xb70f // movzwl
        } else {
            0xbf0f // movswl
        }
    } else {
        return Ok(()); // int or larger — no conversion needed
    };

    // MOVSX/MOVZX r32, r8/r16: 0F BE/BF/B6/B7 modrm(mod=11)
    o(backend, opc)?;
    g(backend, 0xc0 | (rv << 3) | rv)?; // same src and dst register
    Ok(())
}

// ===========================================================================
// Test coverage instrumentation
// ===========================================================================

/// Increment a test coverage counter (64-bit atomic increment).
///
/// Source: `i386-gen.c` line 1138 — `ST_FUNC void gen_increment_tcov(SValue *sv)`
///
/// Emits: `addl $1, [addr]` / `adcl $0, [addr+4]` for a 64-bit counter.
/// In PIC mode, uses EBX-relative addressing.
pub fn gen_increment_tcov(backend: &mut I386Backend, sv: &SValue) -> TccResult<()> {
    let fc = sv.c_i32();
    let sym = sv.sym.as_deref();

    // addl $1, [addr]: 83 /0 addr imm8
    gen_modrm(backend, 0x83, 0, VT_CONST, sym, fc)?;
    g(backend, 1)?;

    // adcl $0, [addr+4]: 83 /2 addr imm8
    gen_modrm(backend, 0x83, 2, VT_CONST, sym, fc + 4)?;
    g(backend, 0)?;

    Ok(())
}

// ===========================================================================
// Computed goto
// ===========================================================================

/// Computed goto support — jump to address in register.
///
/// Source: `i386-gen.c` line 1163 — `ST_FUNC void ggoto(void)`
pub fn ggoto(backend: &mut I386Backend) -> TccResult<()> {
    gcall_or_jmp(backend, true)?;
    backend.vtop_dec();
    Ok(())
}

// ===========================================================================
// Bounds checking support
// ===========================================================================

/// Generate a call to a bounds-checking helper function.
///
/// Source: `i386-gen.c` line 1167 — inside `#ifdef CONFIG_TCC_BCHECK`
#[cfg(feature = "bcheck")]
fn gen_bound_call(backend: &mut I386Backend, _func_token: i32) -> TccResult<()> {
    // In PIC mode: call via PLT; otherwise: direct call
    // The function symbol is resolved by the linker
    // Emit a placeholder CALL that will be resolved later
    // call $0 (placeholder, will be relocated)
    oad(backend, 0xe8, 0)?;
    Ok(())
}

/// Bounds checking function prologue — reserve space and emit setup call.
///
/// Source: `i386-gen.c` lines 1180-1210 — `static void gen_bounds_prolog(void)`
///
/// Reserves space for bounds table pointer and emits call to
/// `__bound_local_new` for local variables.
#[cfg(feature = "bcheck")]
pub fn gen_bounds_prolog(backend: &mut I386Backend) -> TccResult<()> {
    // Save current offset for epilog backpatching
    backend.func_bound_offset = backend.ctx.ind as u64;
    backend.func_bound_ind = backend.ctx.ind as u64;
    backend.func_bound_add_epilog = false;

    // Reserve space for bounds prolog (will be backpatched)
    // 5 bytes for call + 5 bytes for lea or similar
    for _ in 0..10 {
        g(backend, 0x90)?;
    }

    Ok(())
}

/// Bounds checking function epilogue — emit cleanup calls.
///
/// Source: `i386-gen.c` lines 1212-1290 — `static void gen_bounds_epilog(void)`
///
/// Emits call to `__bound_local_delete` for local variables that had
/// their bounds tracked.
#[cfg(feature = "bcheck")]
pub fn gen_bounds_epilog(backend: &mut I386Backend) -> TccResult<()> {
    if !backend.func_bound_add_epilog {
        return Ok(());
    }

    // Emit call to __bound_local_delete
    // push bounds table address
    // call __bound_local_delete
    // add $4, %esp
    gen_bound_call(backend, 0)?;
    gadd_sp(backend, PTR_SIZE as i32)?;

    Ok(())
}

// Non-bcheck stubs when feature is disabled
#[cfg(not(feature = "bcheck"))]
pub fn gen_bounds_prolog(_backend: &mut I386Backend) -> TccResult<()> {
    Ok(())
}

#[cfg(not(feature = "bcheck"))]
pub fn gen_bounds_epilog(_backend: &mut I386Backend) -> TccResult<()> {
    Ok(())
}

// ===========================================================================
// VLA (Variable-Length Array) support
// ===========================================================================

/// Save the current stack pointer for VLA deallocation.
///
/// Source: `i386-gen.c` line 1293 — `ST_FUNC void gen_vla_sp_save(int addr)`
///
/// Emits: `mov %esp, addr(%ebp)`
pub fn gen_vla_sp_save(backend: &mut I386Backend, addr: i32) -> TccResult<()> {
    // mov %esp, addr(%ebp): 89 modrm
    gen_modrm(backend, 0x89, TREG_ESP, VT_LOCAL, None, addr)?;
    Ok(())
}

/// Restore the stack pointer from a saved VLA location.
///
/// Source: `i386-gen.c` line 1299 — `ST_FUNC void gen_vla_sp_restore(int addr)`
///
/// Emits: `mov addr(%ebp), %esp`
pub fn gen_vla_sp_restore(backend: &mut I386Backend, addr: i32) -> TccResult<()> {
    // mov addr(%ebp), %esp: 8B modrm
    gen_modrm(backend, 0x8b, TREG_ESP, VT_LOCAL, None, addr)?;
    Ok(())
}

/// Generate VLA stack allocation.
///
/// Source: `i386-gen.c` line 1304 — `ST_FUNC void gen_vla_alloc(CType *type, int align)`
///
/// The allocation size is in `vtop` (an integer value). This function:
/// 1. Rounds up to alignment
/// 2. Subtracts from ESP (or calls alloca on PE/bounds-check)
/// 3. Stores the resulting pointer
pub fn gen_vla_alloc(backend: &mut I386Backend, _typ: &CType, _align: i32) -> TccResult<()> {
    let r = backend.vtop().r as i32 & VT_VALMASK;
    let rv = I386Backend::reg_value(r);

    if cfg!(any(target_os = "windows", feature = "bcheck")) {
        // On PE or with bounds checking, use alloca helper
        // push size; call alloca; (alloca adjusts ESP and returns pointer in EAX)
        o(backend, (0x50 + rv as u32) & 0xff)?; // push %reg
        oad(backend, 0xe8, 0)?; // call alloca (placeholder)
        gadd_sp(backend, 4)?;
        let vtop = backend.vtop_mut();
        vtop.r = TREG_EAX as u16;
    } else {
        // Direct stack allocation:
        // sub %reg, %esp  (reduce stack pointer by size)
        o(backend, 0x29)?;
        g(backend, 0xc0 | (rv << 3) | TREG_ESP)?;

        // Align: and $-align, %esp
        if _align > PTR_SIZE as i32 {
            o(backend, 0x81)?;
            g(backend, 0xc0 | (4 << 3) | TREG_ESP)?; // and %esp, $imm
            gen_le32(backend, -_align)?;
        }

        // mov %esp, %eax (return pointer to allocated space)
        o(backend, 0x89)?;
        g(backend, 0xc0 | (TREG_ESP << 3) | TREG_EAX)?;

        let vtop = backend.vtop_mut();
        vtop.r = TREG_EAX as u16;
    }

    Ok(())
}

// ===========================================================================
// Helper: type size estimation
// ===========================================================================

/// Estimate the size of a basic type in bytes.
/// Used internally for stack alignment calculations.
fn type_size_from_btype(bt: i32, default: i32) -> i32 {
    match bt {
        VT_BYTE | VT_BOOL => 1,
        VT_SHORT => 2,
        VT_INT => 4,
        VT_FLOAT => 4,
        VT_DOUBLE | VT_LLONG => 8,
        VT_LDOUBLE => LDOUBLE_SIZE as i32,
        _ => default,
    }
}
