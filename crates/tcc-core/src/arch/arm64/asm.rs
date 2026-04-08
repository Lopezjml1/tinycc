#![allow(unused_imports, unused_variables, dead_code)]
//! AArch64 dummy assembler
//!
//! Port of `arm64-asm.c` (94 lines) from the TCC C codebase.
//! This is a STUB assembler — AArch64 inline assembly is **not** fully
//! implemented in TCC. Most functions return an error or are no-ops.
//! Only the low-level byte emission functions ([`g`], [`gen_le16`],
//! [`gen_le32`], [`gen_expr32`]) have real implementations.
//!
//! # Architecture note
//!
//! In the original C codebase, the ARM64 assembler was the smallest of all
//! architecture backends — only 94 lines. The few real functions handle
//! emitting raw bytes into the code buffer; everything else (opcode
//! encoding, operand substitution, register variable parsing, clobber
//! tracking) returns "ARM64 asm not implemented." errors or is an
//! intentional no-op, because upstream TCC never completed this backend.
//!
//! # Byte emission
//!
//! The byte emission functions ([`g`], [`gen_le16`], [`gen_le32`]) write
//! into `Arm64Backend::ctx.code_buf` at the position tracked by
//! `Arm64Backend::ctx.ind`. The [`CodegenBackend`](crate::arch::CodegenBackend)
//! trait implementation in `arm64/mod.rs` delegates `g()`, `gen_le16()`,
//! and `gen_le32()` trait methods to these functions, passing `&mut self`
//! (the backend) and the value as `i32`.
//!
//! # Feature gate
//!
//! This entire module is conditionally compiled behind
//! `#[cfg(feature = "arm64")]` at the parent module level.

use crate::error::{TccError, TccResult};
use crate::TCCState;
use crate::types::{SValue, CString as TccCString};
use crate::assembler::{ExprValue, AsmOperand};
use super::Arm64Backend;

// ===================================================================
// Constants (from arm64-asm.c lines 9-10)
// ===================================================================

/// Assembly is configured for ARM64.
///
/// Mirrors `#define CONFIG_TCC_ASM` from the C source, signalling that
/// the architecture has an assembler module (even though most functions
/// are stubs).
pub const CONFIG_TCC_ASM: bool = true;

/// Number of ASM registers available for the inline-assembly constraint
/// allocator.
///
/// Set to 16 to match the C source (`NB_ASM_REGS 16`). This covers the
/// general-purpose register file x0-x15 that TCC's assembler constraint
/// solver could theoretically allocate from.
pub const NB_ASM_REGS: usize = 16;

// ===================================================================
// Error Helper (from arm64-asm.c lines 22-25)
// ===================================================================

/// Return a [`TccError`] indicating ARM64 assembly is not implemented.
///
/// This is the Rust equivalent of the C helper:
/// ```c
/// static void asm_error(void)
/// {
///     tcc_error("ARM asm not implemented.");
/// }
/// ```
/// Every stub function below delegates to this helper so that the error
/// message is consistent and defined in exactly one place.
#[inline]
fn asm_error() -> TccError {
    TccError::asm("", 0, "ARM64 asm not implemented.")
}

// ===================================================================
// Byte Emission Functions (from arm64-asm.c lines 28-55)
//
// These are the ONLY functions with real implementations.
// They write into `backend.ctx.code_buf` at position `backend.ctx.ind`.
// The CodegenBackend trait impl in mod.rs delegates g(), gen_le16(),
// gen_le32() to these functions.
// ===================================================================

/// Emit a single byte into the code buffer.
///
/// Ported from `arm64-asm.c` lines 28-38:
/// ```c
/// ST_FUNC void g(int c)
/// {
///     int ind1;
///     if (nocode_wanted)
///         return;
///     ind1 = ind + 1;
///     if (ind1 > cur_text_section->data_allocated)
///         section_realloc(cur_text_section, ind1);
///     cur_text_section->data[ind] = c;
///     ind = ind1;
/// }
/// ```
///
/// # Behaviour
///
/// 1. If `ctx.nocode_wanted` is non-zero the call is a silent no-op
///    (we are in a dead-code region the parser decided to skip).
/// 2. Ensures the code buffer is large enough to hold one more byte.
/// 3. Writes `c` (masked to `u8`) at the current position and advances
///    `ctx.ind` by 1.
///
/// # Parameters
///
/// * `backend` — The ARM64 backend, whose `ctx` field provides
///   `code_buf`, `ind`, and `nocode_wanted`.
/// * `c` — The byte value to emit (only the low 8 bits are used,
///   matching the C prototype `void g(int c)`).
pub fn g(backend: &mut Arm64Backend, c: i32) -> TccResult<()> {
    // Dead-code elision: skip emission when the parser says so.
    if backend.ctx.nocode_wanted != 0 {
        return Ok(());
    }

    let ind = backend.ctx.ind as usize;
    let ind1 = ind + 1;

    // Ensure the backing buffer can hold at least one more byte.
    if ind1 > backend.ctx.code_buf.len() {
        backend.ctx.code_buf.resize(ind1, 0);
    }

    // Write the byte and advance the position.
    backend.ctx.code_buf[ind] = (c & 0xFF) as u8;
    backend.ctx.ind = ind1 as i32;

    Ok(())
}

/// Emit a 16-bit little-endian value (two bytes, low byte first).
///
/// Ported from `arm64-asm.c` lines 40-44:
/// ```c
/// ST_FUNC void gen_le16(int v)
/// {
///     g(v);
///     g(v >> 8);
/// }
/// ```
pub fn gen_le16(backend: &mut Arm64Backend, v: i32) -> TccResult<()> {
    g(backend, v & 0xFF)?;
    g(backend, (v >> 8) & 0xFF)?;
    Ok(())
}

/// Emit a 32-bit little-endian value (four bytes, low half first).
///
/// Ported from `arm64-asm.c` lines 46-50:
/// ```c
/// ST_FUNC void gen_le32(int v)
/// {
///     gen_le16(v);
///     gen_le16(v >> 16);
/// }
/// ```
///
/// This is the primary instruction emission primitive for AArch64 since
/// all A64 instructions are exactly 32 bits wide.
pub fn gen_le32(backend: &mut Arm64Backend, v: i32) -> TccResult<()> {
    gen_le16(backend, v & 0xFFFF)?;
    gen_le16(backend, (v >> 16) & 0xFFFF)?;
    Ok(())
}

/// Emit a 32-bit expression value.
///
/// Ported from `arm64-asm.c` lines 52-55:
/// ```c
/// ST_FUNC void gen_expr32(ExprValue *pe)
/// {
///     gen_le32(pe->v);
/// }
/// ```
///
/// Extracts the integer value from the [`ExprValue`] and emits it as a
/// 32-bit little-endian quantity. Unlike the ARM backend, the ARM64 C
/// source does *not* handle symbol relocations in this function — it
/// is a direct passthrough to [`gen_le32`].
pub fn gen_expr32(backend: &mut Arm64Backend, pe: &ExprValue) -> TccResult<()> {
    gen_le32(backend, pe.v as i32)
}

// ===================================================================
// Stub Functions (from arm64-asm.c lines 57-91)
//
// ALL of the following are stubs. They either return an error via
// asm_error() or are intentional no-ops (empty bodies matching the
// C originals). This matches the upstream TCC codebase where AArch64
// inline assembly was never fully implemented.
// ===================================================================

/// Assembly opcode handler — **NOT IMPLEMENTED** for ARM64.
///
/// Ported from `arm64-asm.c` lines 57-60:
/// ```c
/// ST_FUNC void asm_opcode(TCCState *s1, int opcode)
/// {
///     asm_error();
/// }
/// ```
///
/// Any attempt to use inline assembly opcodes on AArch64 will produce a
/// descriptive error rather than silent misbehaviour.
pub fn asm_opcode(s1: &mut TCCState, token: i32) -> TccResult<()> {
    Err(asm_error())
}

/// Substitute an inline-assembly operand — **NOT IMPLEMENTED** for ARM64.
///
/// Ported from `arm64-asm.c` lines 62-65:
/// ```c
/// ST_FUNC void subst_asm_operand(CString *add_str, SValue *sv, int modifier)
/// {
///     asm_error();
/// }
/// ```
pub fn subst_asm_operand(
    add_str: &mut TccCString,
    sv: &SValue,
    modifier: char,
) -> TccResult<()> {
    Err(asm_error())
}

/// Generate prologue and epilogue code for an asm statement — **NO-OP**
/// for ARM64.
///
/// Ported from `arm64-asm.c` lines 68-73:
/// ```c
/// ST_FUNC void asm_gen_code(ASMOperand *operands, int nb_operands,
///                           int nb_outputs, int is_output,
///                           uint8_t *clobber_regs, int out_reg)
/// {
/// }
/// ```
///
/// The function body in the C source is **completely empty** — this is
/// intentional, not an oversight. The function exists solely to satisfy
/// the assembler interface contract. The Rust version preserves this
/// contract by returning `Ok(())`.
pub fn asm_gen_code(
    s1: &mut TCCState,
    operands: &mut [AsmOperand],
    nb_operands: usize,
    nb_outputs: usize,
    is_output: bool,
    clobber_regs: &[u8],
    out_reg: i32,
) -> TccResult<()> {
    // Intentionally empty — ARM64 asm_gen_code is a no-op in the C source.
    Ok(())
}

/// Compute constraints for inline-assembly operands — **NO-OP** for ARM64.
///
/// Ported from `arm64-asm.c` lines 75-80:
/// ```c
/// ST_FUNC void asm_compute_constraints(ASMOperand *operands,
///                                       int nb_operands,
///                                       int nb_outputs,
///                                       const uint8_t *clobber_regs,
///                                       int *pout_reg)
/// {
/// }
/// ```
///
/// As with [`asm_gen_code`], the C body is empty. The Rust version returns
/// `Ok(())` to indicate success (no-op is the correct behaviour).
pub fn asm_compute_constraints(
    operands: &mut [AsmOperand],
    nb_operands: usize,
    nb_outputs: usize,
    clobber_regs: &[u8],
    pout_reg: &mut i32,
) -> TccResult<()> {
    // Intentionally empty — ARM64 asm_compute_constraints is a no-op in
    // the C source.
    Ok(())
}

/// Mark clobber registers — **NOT IMPLEMENTED** for ARM64.
///
/// Ported from `arm64-asm.c` lines 82-85:
/// ```c
/// ST_FUNC void asm_clobber(uint8_t *clobber_regs, const char *str)
/// {
///     asm_error();
/// }
/// ```
pub fn asm_clobber(
    clobber_regs: &mut [u8],
    name: &str,
) -> TccResult<()> {
    Err(asm_error())
}

/// Parse a register variable token — **NOT IMPLEMENTED** for ARM64.
///
/// Ported from `arm64-asm.c` lines 87-91:
/// ```c
/// ST_FUNC int asm_parse_regvar(int t)
/// {
///     asm_error();
///     return -1;
/// }
/// ```
///
/// Returns `-1` to indicate "not a recognised register" per the TCC
/// convention. The original C code also calls `asm_error()` first, but
/// since that would abort via `tcc_error`, the return value was never
/// actually reached in practice. In the Rust port we simply return the
/// sentinel directly; callers checking for `-1` will know that ARM64
/// register variables are unsupported.
pub fn asm_parse_regvar(token: i32) -> i32 {
    // ARM64 does not support register variable parsing.
    // Return -1 to indicate "not a register" per TCC convention.
    -1
}

// ===================================================================
// Unit Tests
// ===================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to create an `Arm64Backend` with a zeroed context ready
    /// for byte emission tests.
    fn make_backend() -> Arm64Backend {
        let mut b = Arm64Backend::new();
        b.ctx.nocode_wanted = 0;
        b.ctx.ind = 0;
        b.ctx.code_buf.clear();
        b
    }

    // --- Constant tests ---

    #[test]
    fn test_config_tcc_asm_is_true() {
        assert!(CONFIG_TCC_ASM);
    }

    #[test]
    fn test_nb_asm_regs_is_16() {
        assert_eq!(NB_ASM_REGS, 16);
    }

    // --- asm_error helper ---

    #[test]
    fn test_asm_error_message() {
        let err = asm_error();
        let msg = format!("{}", err);
        assert!(
            msg.contains("ARM64 asm not implemented"),
            "Expected 'ARM64 asm not implemented' in error message, got: {}",
            msg
        );
    }

    // --- Byte emission: g() ---

    #[test]
    fn test_g_emits_byte() {
        let mut b = make_backend();
        g(&mut b, 0xAB).unwrap();

        assert_eq!(b.ctx.code_buf.len(), 1);
        assert_eq!(b.ctx.code_buf[0], 0xAB);
        assert_eq!(b.ctx.ind, 1);
    }

    #[test]
    fn test_g_emits_multiple_bytes() {
        let mut b = make_backend();
        g(&mut b, 0x11).unwrap();
        g(&mut b, 0x22).unwrap();
        g(&mut b, 0x33).unwrap();

        assert_eq!(b.ctx.code_buf, vec![0x11, 0x22, 0x33]);
        assert_eq!(b.ctx.ind, 3);
    }

    #[test]
    fn test_g_masks_to_low_byte() {
        let mut b = make_backend();
        // 0x1AB → only 0xAB should be written
        g(&mut b, 0x1AB).unwrap();

        assert_eq!(b.ctx.code_buf[0], 0xAB);
    }

    #[test]
    fn test_g_skips_when_nocode_wanted() {
        let mut b = make_backend();
        b.ctx.nocode_wanted = 1; // Dead-code region

        g(&mut b, 0xFF).unwrap();

        // Nothing should have been written.
        assert!(b.ctx.code_buf.is_empty());
        assert_eq!(b.ctx.ind, 0);
    }

    #[test]
    fn test_g_resizes_buffer_when_full() {
        let mut b = make_backend();
        // Start with an empty buffer — g() must resize it.
        assert!(b.ctx.code_buf.is_empty());

        g(&mut b, 0x42).unwrap();

        assert_eq!(b.ctx.code_buf.len(), 1);
        assert_eq!(b.ctx.code_buf[0], 0x42);
        assert_eq!(b.ctx.ind, 1);
    }

    // --- gen_le16 ---

    #[test]
    fn test_gen_le16_little_endian() {
        let mut b = make_backend();
        gen_le16(&mut b, 0xBEEFu16 as i32).unwrap();

        assert_eq!(b.ctx.code_buf.len(), 2);
        assert_eq!(b.ctx.code_buf[0], 0xEF); // low byte first
        assert_eq!(b.ctx.code_buf[1], 0xBE); // high byte second
        assert_eq!(b.ctx.ind, 2);
    }

    #[test]
    fn test_gen_le16_zero() {
        let mut b = make_backend();
        gen_le16(&mut b, 0).unwrap();

        assert_eq!(b.ctx.code_buf, vec![0x00, 0x00]);
    }

    // --- gen_le32 ---

    #[test]
    fn test_gen_le32_little_endian() {
        let mut b = make_backend();
        gen_le32(&mut b, 0xDEADBEEFu32 as i32).unwrap();

        assert_eq!(b.ctx.code_buf.len(), 4);
        assert_eq!(b.ctx.code_buf[0], 0xEF);
        assert_eq!(b.ctx.code_buf[1], 0xBE);
        assert_eq!(b.ctx.code_buf[2], 0xAD);
        assert_eq!(b.ctx.code_buf[3], 0xDE);
        assert_eq!(b.ctx.ind, 4);
    }

    #[test]
    fn test_gen_le32_known_instruction() {
        let mut b = make_backend();
        // ARM64 NOP = 0xD503201F
        gen_le32(&mut b, 0xD503201Fu32 as i32).unwrap();

        assert_eq!(b.ctx.code_buf[0], 0x1F);
        assert_eq!(b.ctx.code_buf[1], 0x20);
        assert_eq!(b.ctx.code_buf[2], 0x03);
        assert_eq!(b.ctx.code_buf[3], 0xD5);
    }

    // --- gen_expr32 ---

    #[test]
    fn test_gen_expr32_emits_value() {
        let mut b = make_backend();

        let pe = ExprValue {
            v: 0x1234_5678,
            sym: None,
            pcrel: false,
        };

        gen_expr32(&mut b, &pe).unwrap();

        assert_eq!(b.ctx.code_buf[0], 0x78);
        assert_eq!(b.ctx.code_buf[1], 0x56);
        assert_eq!(b.ctx.code_buf[2], 0x34);
        assert_eq!(b.ctx.code_buf[3], 0x12);
        assert_eq!(b.ctx.ind, 4);
    }

    #[test]
    fn test_gen_expr32_truncates_u64_to_u32() {
        let mut b = make_backend();

        let pe = ExprValue {
            v: 0xFFFF_FFFF_0000_00FF,
            sym: None,
            pcrel: false,
        };

        gen_expr32(&mut b, &pe).unwrap();

        // Only the low 32 bits should be emitted.
        assert_eq!(b.ctx.code_buf[0], 0xFF);
        assert_eq!(b.ctx.code_buf[1], 0x00);
        assert_eq!(b.ctx.code_buf[2], 0x00);
        assert_eq!(b.ctx.code_buf[3], 0x00);
    }

    // --- Stub function tests ---

    #[test]
    fn test_asm_opcode_returns_error() {
        let mut s1 = TCCState::default();
        let result = asm_opcode(&mut s1, 42);
        assert!(result.is_err());
    }

    #[test]
    fn test_subst_asm_operand_returns_error() {
        let mut add_str = TccCString { data: Vec::new() };
        let sv = SValue::default();
        let result = subst_asm_operand(&mut add_str, &sv, 'c');
        assert!(result.is_err());
    }

    #[test]
    fn test_asm_gen_code_is_noop() {
        let mut s1 = TCCState::default();
        let mut operands: Vec<AsmOperand> = Vec::new();
        let clobber_regs = [0u8; NB_ASM_REGS];
        let result = asm_gen_code(
            &mut s1,
            &mut operands,
            0, // nb_operands
            0, // nb_outputs
            false,
            &clobber_regs,
            -1,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_asm_compute_constraints_is_noop() {
        let mut operands: Vec<AsmOperand> = Vec::new();
        let clobber_regs = [0u8; NB_ASM_REGS];
        let mut pout_reg: i32 = -1;
        let result = asm_compute_constraints(
            &mut operands,
            0,
            0,
            &clobber_regs,
            &mut pout_reg,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_asm_clobber_returns_error() {
        let mut clobber_regs = [0u8; NB_ASM_REGS];
        let result = asm_clobber(&mut clobber_regs, "r0");
        assert!(result.is_err());
    }

    #[test]
    fn test_asm_parse_regvar_returns_negative_one() {
        assert_eq!(asm_parse_regvar(0), -1);
        assert_eq!(asm_parse_regvar(100), -1);
        assert_eq!(asm_parse_regvar(-5), -1);
    }

    // --- Integration: sequential emission ---

    #[test]
    fn test_sequential_le32_emissions() {
        let mut b = make_backend();

        // Emit two 32-bit values back-to-back.
        gen_le32(&mut b, 0x11223344u32 as i32).unwrap();
        gen_le32(&mut b, 0x55667788u32 as i32).unwrap();

        assert_eq!(b.ctx.code_buf.len(), 8);
        assert_eq!(b.ctx.ind, 8);

        // First word
        assert_eq!(b.ctx.code_buf[0], 0x44);
        assert_eq!(b.ctx.code_buf[1], 0x33);
        assert_eq!(b.ctx.code_buf[2], 0x22);
        assert_eq!(b.ctx.code_buf[3], 0x11);

        // Second word
        assert_eq!(b.ctx.code_buf[4], 0x88);
        assert_eq!(b.ctx.code_buf[5], 0x77);
        assert_eq!(b.ctx.code_buf[6], 0x66);
        assert_eq!(b.ctx.code_buf[7], 0x55);
    }

    #[test]
    fn test_nocode_wanted_prevents_all_emission() {
        let mut b = make_backend();
        b.ctx.nocode_wanted = 1;

        gen_le32(&mut b, 0xDEAD_BEEFu32 as i32).unwrap();
        gen_le16(&mut b, 0xCAFE_u16 as i32).unwrap();
        g(&mut b, 0x42).unwrap();

        assert!(b.ctx.code_buf.is_empty());
        assert_eq!(b.ctx.ind, 0);
    }
}
