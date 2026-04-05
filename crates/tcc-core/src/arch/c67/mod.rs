//! TMS320C67xx DSP code generation backend.
//!
//! This module implements the code generation and linker support for the
//! Texas Instruments TMS320C67xx Digital Signal Processor family.
//!
//! This is a port of `c67-gen.c` (2,543 lines) and `c67-link.c` (125 lines).

pub mod gen;
pub mod link;

use crate::arch::CodegenBackend;
use crate::error::TccResult;
use crate::types::{CType, SValue, Sym};

use gen::{C67CodegenCtx, C67GenState, PendingReloc};

/// TI TMS320C67xx DSP code generation backend.
///
/// Implements the `CodegenBackend` trait for the C67 DSP family.
/// Port of `c67-gen.c` (2,543 lines) and `c67-link.c` (125 lines).
pub struct C67Backend {
    /// Internal code generation state (function params, compare regs, etc.).
    pub gen_state: C67GenState,
    /// Codegen context (ind, code_buf, vstack, nocode_wanted, loc, etc.).
    pub ctx: C67CodegenCtx,
    /// Pending relocations generated during code emission.
    pub pending_relocs: Vec<PendingReloc>,
}

impl C67Backend {
    /// Creates a new C67 backend instance.
    pub fn new() -> Self {
        C67Backend {
            gen_state: C67GenState::new(),
            ctx: C67CodegenCtx::new(),
            pending_relocs: Vec::new(),
        }
    }
}

impl Default for C67Backend {
    fn default() -> Self {
        Self::new()
    }
}

/// Register classes for the 24 TCC-visible registers.
///
/// Each entry maps a TCC register index to its register class bitmask.
/// Registers 0-3 (TREG_EAX..TREG_ST0) map to base classes.
/// Registers 4-23 (TREG_C67_A4..TREG_C67_B13) use computed RC_C67_* bitmasks.
///
/// Format: RC_INT | RC_FLOAT | RC_C67_Xn for each register.
/// Register classes for the 24 TCC-visible registers.
/// Uses crate::arch constants for RC_INT/RC_FLOAT and gen module constants for RC_C67_*.
const C67_REG_CLASSES: [i32; gen::NB_REGS] = {
    // In a const context, we cannot use `use` statements, so we
    // define local constants that mirror the parent module values.
    const RI: i32 = 0x0001; // RC_INT
    const RF: i32 = 0x0002; // RC_FLOAT
    [
        // TREG_EAX (A2) — general purpose integer
        RI,
        // TREG_ECX (A3) — general purpose integer
        RI,
        // TREG_EDX (B0) — general purpose integer (B-side)
        RI,
        // TREG_ST0 (B1) — general purpose / float scratch
        RF,
        // TREG_C67_A4
        RI | RF | gen::RC_C67_A4,
        // TREG_C67_A5
        RI | RF | gen::RC_C67_A5,
        // TREG_C67_B4
        RI | RF | gen::RC_C67_B4,
        // TREG_C67_B5
        RI | RF | gen::RC_C67_B5,
        // TREG_C67_A6
        RI | RF | gen::RC_C67_A6,
        // TREG_C67_A7
        RI | RF | gen::RC_C67_A7,
        // TREG_C67_B6
        RI | RF | gen::RC_C67_B6,
        // TREG_C67_B7
        RI | RF | gen::RC_C67_B7,
        // TREG_C67_A8
        RI | RF | gen::RC_C67_A8,
        // TREG_C67_A9
        RI | RF | gen::RC_C67_A9,
        // TREG_C67_B8
        RI | RF | gen::RC_C67_B8,
        // TREG_C67_B9
        RI | RF | gen::RC_C67_B9,
        // TREG_C67_A10
        RI | RF | gen::RC_C67_A10,
        // TREG_C67_A11
        RI | RF | gen::RC_C67_A11,
        // TREG_C67_B10
        RI | RF | gen::RC_C67_B10,
        // TREG_C67_B11
        RI | RF | gen::RC_C67_B11,
        // TREG_C67_A12
        RI | RF | gen::RC_C67_A12,
        // TREG_C67_A13
        RI | RF | gen::RC_C67_A13,
        // TREG_C67_B12
        RI | RF | gen::RC_C67_B12,
        // TREG_C67_B13
        RI | RF | gen::RC_C67_B13,
    ]
};

impl CodegenBackend for C67Backend {
    fn target_machine_defs(&self) -> &'static str {
        "__C67__\0"
    }

    fn reg_classes(&self) -> &[i32] {
        &C67_REG_CLASSES
    }

    fn nb_regs(&self) -> usize {
        gen::NB_REGS
    }

    fn ptr_size(&self) -> usize {
        4
    }

    // --- Code generation dispatch to gen.rs ---

    fn gsym_addr(&mut self, t: i32, a: i32) -> TccResult<()> {
        gen::gsym_addr(self, t, a)
    }

    fn gsym(&mut self, t: i32) -> TccResult<()> {
        let a = self.ctx.ind;
        gen::gsym_addr(self, t, a)
    }

    fn load(&mut self, r: i32, sv: &SValue) -> TccResult<()> {
        gen::load(self, r, sv)
    }

    fn store(&mut self, r: i32, sv: &SValue) -> TccResult<()> {
        gen::store(self, r, sv)
    }

    fn gfunc_sret(&self, vt: &CType, variadic: bool) -> (bool, CType, i32, i32) {
        gen::gfunc_sret(self, vt, variadic)
    }

    fn gfunc_call(&mut self, nb_args: i32) -> TccResult<()> {
        gen::gfunc_call(self, nb_args)
    }

    fn gfunc_prolog(&mut self, func_sym: &Sym) -> TccResult<()> {
        gen::gfunc_prolog(self, func_sym)
    }

    fn gfunc_epilog(&mut self) -> TccResult<()> {
        gen::gfunc_epilog(self)
    }

    fn gen_fill_nops(&mut self, n: i32) -> TccResult<()> {
        gen::gen_fill_nops(self, n)
    }

    fn gjmp(&mut self, t: i32) -> TccResult<i32> {
        gen::gjmp(self, t)
    }

    fn gjmp_addr(&mut self, a: i32) -> TccResult<()> {
        gen::gjmp_addr(self, a)
    }

    fn gjmp_cond(&mut self, op: i32, t: i32) -> TccResult<i32> {
        gen::gjmp_cond(self, op, t)
    }

    fn gjmp_append(&mut self, n: i32, t: i32) -> TccResult<i32> {
        gen::gjmp_append(self, n, t)
    }

    fn gen_opi(&mut self, op: i32) -> TccResult<()> {
        gen::gen_opi(self, op)
    }

    fn gen_opf(&mut self, op: i32) -> TccResult<()> {
        gen::gen_opf(self, op)
    }

    fn gen_cvt_ftoi(&mut self, t: i32) -> TccResult<()> {
        gen::gen_cvt_ftoi(self, t)
    }

    fn gen_cvt_itof(&mut self, t: i32) -> TccResult<()> {
        gen::gen_cvt_itof(self, t)
    }

    fn gen_cvt_ftof(&mut self, t: i32) -> TccResult<()> {
        gen::gen_cvt_ftof(self, t)
    }

    fn ggoto(&mut self) -> TccResult<()> {
        gen::ggoto(self)
    }

    /// C67 does not use the generic `o()` opcode emission.
    /// C67-specific instruction emission goes through `c67_g()` in gen.rs.
    fn emit_opcode(&mut self, _c: u32) -> TccResult<()> {
        Ok(())
    }

    fn gen_vla_sp_save(&mut self, addr: i32) -> TccResult<()> {
        gen::gen_vla_sp_save(self, addr)
    }

    fn gen_vla_sp_restore(&mut self, addr: i32) -> TccResult<()> {
        gen::gen_vla_sp_restore(self, addr)
    }

    fn gen_vla_alloc(&mut self, typ: &CType, align: i32) -> TccResult<()> {
        gen::gen_vla_alloc(self, typ, align)
    }

    // --- Linker / Relocation support ---

    fn code_reloc(&self, _reloc_type: i32) -> i32 {
        -1
    }

    fn gotplt_entry_type(&self, _reloc_type: i32) -> i32 {
        0
    }

    fn relocate(
        &mut self,
        rel_type: i32,
        ptr: &mut [u8],
        addr: u64,
        val: u64,
    ) -> TccResult<()> {
        link::relocate(rel_type, ptr, addr, val)
    }

    // --- ELF / Output format constants ---

    fn elf_machine(&self) -> u16 {
        140 // EM_TI_C6000
    }

    fn elf_start_addr(&self) -> u64 {
        0x0000_0000
    }

    fn elf_page_size(&self) -> u64 {
        0x1000
    }

    fn pcrelative_dllplt(&self) -> bool {
        false
    }

    fn relocate_dllplt(&self) -> bool {
        false
    }
}

// ===========================================================================
// Unit tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_c67_backend_new() {
        let backend = C67Backend::new();
        assert_eq!(backend.gen_state.c67_compare_reg, -1);
        assert_eq!(backend.gen_state.no_of_cur_func_args, 0);
        assert_eq!(backend.ctx.ind, 0);
    }

    #[test]
    fn test_c67_backend_default() {
        let backend = C67Backend::default();
        assert_eq!(backend.pending_relocs.len(), 0);
    }

    #[test]
    fn test_c67_backend_nb_regs() {
        let backend = C67Backend::new();
        assert_eq!(backend.nb_regs(), 24);
    }

    #[test]
    fn test_c67_backend_ptr_size() {
        let backend = C67Backend::new();
        assert_eq!(backend.ptr_size(), 4);
    }

    #[test]
    fn test_c67_backend_target_defs() {
        let backend = C67Backend::new();
        assert!(backend.target_machine_defs().contains("__C67__"));
    }

    #[test]
    fn test_c67_backend_reg_classes() {
        let backend = C67Backend::new();
        assert_eq!(backend.reg_classes().len(), 24);
    }

    #[test]
    fn test_c67_backend_elf_machine() {
        let backend = C67Backend::new();
        assert_eq!(backend.elf_machine(), 140);
    }

    #[test]
    fn test_c67_backend_elf_start_addr() {
        let backend = C67Backend::new();
        assert_eq!(backend.elf_start_addr(), 0x0000_0000);
    }

    #[test]
    fn test_c67_backend_elf_page_size() {
        let backend = C67Backend::new();
        assert_eq!(backend.elf_page_size(), 0x1000);
    }

    #[test]
    fn test_c67_backend_vla_unsupported() {
        let mut backend = C67Backend::new();
        assert!(backend.gen_vla_sp_save(0).is_err());
        assert!(backend.gen_vla_sp_restore(0).is_err());
        let ct = CType { t: 0, ref_sym: None };
        assert!(backend.gen_vla_alloc(&ct, 4).is_err());
    }

    #[test]
    fn test_c67_backend_reloc_defaults() {
        let backend = C67Backend::new();
        assert_eq!(backend.code_reloc(0), -1);
        assert_eq!(backend.gotplt_entry_type(0), 0);
        assert!(!backend.pcrelative_dllplt());
        assert!(!backend.relocate_dllplt());
    }

    #[test]
    fn test_c67_backend_gfunc_sret() {
        let backend = C67Backend::new();
        let ct = CType { t: 0, ref_sym: None };
        let (use_ptr, _sret_ty, align, size) = backend.gfunc_sret(&ct, false);
        assert!(!use_ptr);
        assert_eq!(align, 4);
        assert_eq!(size, 4);
    }
}
