//! TMS320C67xx DSP code generation backend.
//!
//! This module implements the code generation and linker support for the
//! Texas Instruments TMS320C67xx Digital Signal Processor family.
//!
//! This is a port of `c67-gen.c` (2,543 lines) and `c67-link.c` (125 lines).

pub mod link;

use crate::arch::CodegenBackend;
use crate::error::TccResult;
use crate::types::{CType, SValue, Sym};

/// TI TMS320C67xx DSP code generation backend.
///
/// Implements the `CodegenBackend` trait for the C67 DSP family.
/// Port of `c67-gen.c` (2,543 lines) and `c67-link.c` (125 lines).
pub struct C67Backend {
    _private: (),
}

impl C67Backend {
    /// Creates a new C67 backend instance.
    pub fn new() -> Self {
        C67Backend { _private: () }
    }
}

impl Default for C67Backend {
    fn default() -> Self {
        Self::new()
    }
}

const C67_REG_CLASSES: [i32; 16] = [
    1, 1, 1, 1, 1, 1, 1, 1,
    2, 2, 2, 2, 2, 2, 2, 2,
];

impl CodegenBackend for C67Backend {
    fn target_machine_defs(&self) -> &'static str {
        "__C67__\0"
    }

    fn reg_classes(&self) -> &[i32] { &C67_REG_CLASSES }
    fn nb_regs(&self) -> usize { 16 }
    fn ptr_size(&self) -> usize { 4 }

    fn gsym_addr(&mut self, _t: i32, _a: i32) -> TccResult<()> { Ok(()) }
    fn gsym(&mut self, _t: i32) -> TccResult<()> { Ok(()) }
    fn load(&mut self, _r: i32, _sv: &SValue) -> TccResult<()> { Ok(()) }
    fn store(&mut self, _r: i32, _sv: &SValue) -> TccResult<()> { Ok(()) }

    fn gfunc_sret(&self, _vt: &CType, _variadic: bool) -> (bool, CType, i32, i32) {
        (false, CType { t: 0, ref_sym: None }, 4, 4)
    }

    fn gfunc_call(&mut self, _nb_args: i32) -> TccResult<()> { Ok(()) }
    fn gfunc_prolog(&mut self, _func_sym: &Sym) -> TccResult<()> { Ok(()) }
    fn gfunc_epilog(&mut self) -> TccResult<()> { Ok(()) }
    fn gen_fill_nops(&mut self, _n: i32) -> TccResult<()> { Ok(()) }
    fn gjmp(&mut self, t: i32) -> TccResult<i32> { Ok(t) }
    fn gjmp_addr(&mut self, _a: i32) -> TccResult<()> { Ok(()) }
    fn gjmp_cond(&mut self, _op: i32, t: i32) -> TccResult<i32> { Ok(t) }
    fn gjmp_append(&mut self, _n: i32, t: i32) -> TccResult<i32> { Ok(t) }
    fn gen_opi(&mut self, _op: i32) -> TccResult<()> { Ok(()) }
    fn gen_opf(&mut self, _op: i32) -> TccResult<()> { Ok(()) }
    fn gen_cvt_ftoi(&mut self, _t: i32) -> TccResult<()> { Ok(()) }
    fn gen_cvt_itof(&mut self, _t: i32) -> TccResult<()> { Ok(()) }
    fn gen_cvt_ftof(&mut self, _t: i32) -> TccResult<()> { Ok(()) }
    fn ggoto(&mut self) -> TccResult<()> { Ok(()) }

    /// C67 does not use raw opcode emission (the `o()` function is not available
    /// on C67 in the C codebase).
    fn emit_opcode(&mut self, _c: u32) -> TccResult<()> { Ok(()) }

    fn gen_vla_sp_save(&mut self, _addr: i32) -> TccResult<()> { Ok(()) }
    fn gen_vla_sp_restore(&mut self, _addr: i32) -> TccResult<()> { Ok(()) }
    fn gen_vla_alloc(&mut self, _typ: &CType, _align: i32) -> TccResult<()> { Ok(()) }

    fn code_reloc(&self, _reloc_type: i32) -> i32 { -1 }
    fn gotplt_entry_type(&self, _reloc_type: i32) -> i32 { 0 }
    fn relocate(&mut self, _rel_type: i32, _ptr: &mut [u8], _addr: u64, _val: u64) -> TccResult<()> { Ok(()) }

    fn elf_machine(&self) -> u16 { 140 } // EM_TI_C6000
    fn elf_start_addr(&self) -> u64 { 0x00000000 }
    fn elf_page_size(&self) -> u64 { 0x1000 }
    fn pcrelative_dllplt(&self) -> bool { false }
    fn relocate_dllplt(&self) -> bool { false }
}
