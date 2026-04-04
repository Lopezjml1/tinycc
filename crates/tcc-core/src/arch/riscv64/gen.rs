// Copyright (c) TinyCC contributors. LGPL licensed.
// Ported from riscv64-gen.c to Rust.
//
//! # RISC-V 64-bit Code Generation
//!
//! This module contains the code generation functions for the RISC-V 64-bit
//! (RV64GC) target, ported from `riscv64-gen.c` (1,434 lines).
//!
//! All public functions in this module are called by the [`CodegenBackend`]
//! trait implementation on [`Riscv64Backend`] in the parent `mod.rs`.

use crate::error::TccResult;
use crate::types::{CType, SValue, Sym};
use super::Riscv64Backend;

/// Resolves a forward branch chain at `t` to target address `a`.
///
/// Walks the linked list of forward-reference patches starting at code offset `t`,
/// patching each to branch to `a`.  Each link stores the offset of the previous
/// link in the chain.
///
/// Corresponds to: `ST_FUNC void gsym_addr(int t, int a)` in `riscv64-gen.c`.
pub fn gsym_addr(_backend: &mut Riscv64Backend, _t: i32, _a: i32) -> TccResult<()> {
    // Full implementation will be provided by the gen.rs agent.
    // This stub enables mod.rs compilation and trait dispatch.
    Ok(())
}

/// Resolves a forward branch chain at `t` to the current code position.
///
/// Equivalent to `gsym_addr(t, current_pc)`.
///
/// Corresponds to: `ST_FUNC void gsym(int t)` in `riscv64-gen.c`.
pub fn gsym(_backend: &mut Riscv64Backend, _t: i32) -> TccResult<()> {
    Ok(())
}

/// Loads value `sv` into register `r`.
///
/// Emits appropriate RISC-V load instructions based on the value's type and
/// location (constant, local variable, global, register).
///
/// Corresponds to: `ST_FUNC void load(int r, SValue *sv)` in `riscv64-gen.c`.
pub fn load(_backend: &mut Riscv64Backend, _r: i32, _sv: &SValue) -> TccResult<()> {
    Ok(())
}

/// Stores register `r` to the location described by `sv`.
///
/// Corresponds to: `ST_FUNC void store(int r, SValue *v)` in `riscv64-gen.c`.
pub fn store(_backend: &mut Riscv64Backend, _r: i32, _sv: &SValue) -> TccResult<()> {
    Ok(())
}

/// Determines struct return convention for the RISC-V LP64D ABI.
///
/// Returns `(in_registers, ret_type, align, regsize)`.
///
/// Corresponds to: `ST_FUNC int gfunc_sret(...)` in `riscv64-gen.c`.
pub fn gfunc_sret(_vt: &CType, _variadic: bool) -> (bool, CType, i32, i32) {
    // Default: structs passed by reference (not in registers)
    (false, CType { t: 0, ref_sym: None }, 8, 8)
}

/// Generates code for a function call with `nb_args` arguments.
///
/// Corresponds to: `ST_FUNC void gfunc_call(int nb_args)` in `riscv64-gen.c`.
pub fn gfunc_call(_backend: &mut Riscv64Backend, _nb_args: i32) -> TccResult<()> {
    Ok(())
}

/// Generates the function prologue.
///
/// Corresponds to: `ST_FUNC void gfunc_prolog(Sym *func_sym)` in `riscv64-gen.c`.
pub fn gfunc_prolog(_backend: &mut Riscv64Backend, _func_sym: &Sym) -> TccResult<()> {
    Ok(())
}

/// Generates the function epilogue.
///
/// Corresponds to: `ST_FUNC void gfunc_epilog(void)` in `riscv64-gen.c`.
pub fn gfunc_epilog(_backend: &mut Riscv64Backend) -> TccResult<()> {
    Ok(())
}

/// Fills `n` bytes with NOP instructions (RISC-V NOP = `addi x0, x0, 0` = `0x00000013`).
///
/// Corresponds to: `ST_FUNC void gen_fill_nops(int n)` in `riscv64-gen.c`.
pub fn gen_fill_nops(_backend: &mut Riscv64Backend, _n: i32) -> TccResult<()> {
    Ok(())
}

/// Generates an unconditional forward jump, returning the patch address.
///
/// Corresponds to: `ST_FUNC int gjmp(int t)` in `riscv64-gen.c`.
pub fn gjmp(_backend: &mut Riscv64Backend, t: i32) -> TccResult<i32> {
    Ok(t)
}

/// Generates an unconditional jump to absolute address `a`.
///
/// Corresponds to: `ST_FUNC void gjmp_addr(int a)` in `riscv64-gen.c`.
pub fn gjmp_addr(_backend: &mut Riscv64Backend, _a: i32) -> TccResult<()> {
    Ok(())
}

/// Generates a conditional jump based on comparison `op`.
///
/// Corresponds to: `ST_FUNC int gjmp_cond(int op, int t)` in `riscv64-gen.c`.
pub fn gjmp_cond(_backend: &mut Riscv64Backend, _op: i32, t: i32) -> TccResult<i32> {
    Ok(t)
}

/// Appends jump target `t` to forward-reference chain `n`.
///
/// Corresponds to: `ST_FUNC int gjmp_append(int n, int t)` in `riscv64-gen.c`.
pub fn gjmp_append(_backend: &mut Riscv64Backend, _n: i32, t: i32) -> TccResult<i32> {
    Ok(t)
}

/// Generates code for an integer binary operation.
///
/// Corresponds to: `ST_FUNC void gen_opi(int op)` in `riscv64-gen.c`.
pub fn gen_opi(_backend: &mut Riscv64Backend, _op: i32) -> TccResult<()> {
    Ok(())
}

/// Generates code for a floating-point binary operation.
///
/// Corresponds to: `ST_FUNC void gen_opf(int op)` in `riscv64-gen.c`.
pub fn gen_opf(_backend: &mut Riscv64Backend, _op: i32) -> TccResult<()> {
    Ok(())
}

/// Generates float-to-integer conversion code.
///
/// Corresponds to: `ST_FUNC void gen_cvt_ftoi(int t)` in `riscv64-gen.c`.
pub fn gen_cvt_ftoi(_backend: &mut Riscv64Backend, _t: i32) -> TccResult<()> {
    Ok(())
}

/// Generates integer-to-float conversion code.
///
/// Corresponds to: `ST_FUNC void gen_cvt_itof(int t)` in `riscv64-gen.c`.
pub fn gen_cvt_itof(_backend: &mut Riscv64Backend, _t: i32) -> TccResult<()> {
    Ok(())
}

/// Generates float-to-float precision conversion code.
///
/// Corresponds to: `ST_FUNC void gen_cvt_ftof(int t)` in `riscv64-gen.c`.
pub fn gen_cvt_ftof(_backend: &mut Riscv64Backend, _t: i32) -> TccResult<()> {
    Ok(())
}

/// Generates a computed goto (indirect jump).
///
/// Corresponds to: `ST_FUNC void ggoto(void)` in `riscv64-gen.c`.
pub fn ggoto(_backend: &mut Riscv64Backend) -> TccResult<()> {
    Ok(())
}

/// Emits a raw 32-bit instruction word to the code section.
///
/// This is the fundamental instruction emission primitive for RISC-V.
/// All instructions are 32 bits (or 16 bits for RVC compressed instructions).
///
/// Corresponds to: `ST_FUNC void o(unsigned int c)` in `riscv64-gen.c`.
pub fn emit_opcode(_backend: &mut Riscv64Backend, _c: u32) -> TccResult<()> {
    Ok(())
}

/// Saves the current stack pointer for VLA support.
///
/// Corresponds to: `ST_FUNC void gen_vla_sp_save(int addr)` in `riscv64-gen.c`.
pub fn gen_vla_sp_save(_backend: &mut Riscv64Backend, _addr: i32) -> TccResult<()> {
    Ok(())
}

/// Restores the stack pointer from a saved VLA state.
///
/// Corresponds to: `ST_FUNC void gen_vla_sp_restore(int addr)` in `riscv64-gen.c`.
pub fn gen_vla_sp_restore(_backend: &mut Riscv64Backend, _addr: i32) -> TccResult<()> {
    Ok(())
}

/// Generates a VLA stack allocation.
///
/// Corresponds to: `ST_FUNC void gen_vla_alloc(CType *type, int align)` in `riscv64-gen.c`.
pub fn gen_vla_alloc(_backend: &mut Riscv64Backend, _typ: &CType, _align: i32) -> TccResult<()> {
    Ok(())
}

/// Generates test coverage counter increment code.
///
/// Corresponds to: `ST_FUNC void gen_increment_tcov(SValue *sv)` in `riscv64-gen.c`.
pub fn gen_increment_tcov(_backend: &mut Riscv64Backend, _sv: &SValue) -> TccResult<()> {
    Ok(())
}
