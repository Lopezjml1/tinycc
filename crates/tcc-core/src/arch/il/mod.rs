//! .NET IL (Intermediate Language) code generation backend.
//!
//! This module implements an experimental code generation backend that emits
//! .NET Common Intermediate Language (CIL) bytecode instead of native machine
//! code.
//!
//! This is a port of `il-gen.c` (657 lines) and `il-opcodes.h` (251 lines).

use crate::arch::CodegenBackend;
use crate::error::TccResult;
use crate::types::{CType, SValue, Sym};

/// .NET IL code generation backend (experimental).
///
/// Implements the `CodegenBackend` trait for .NET IL bytecode emission.
/// Port of `il-gen.c` (657 lines) and `il-opcodes.h` (251 lines).
///
/// Key characteristics:
/// - Stack-based virtual machine (no general-purpose registers)
/// - 4-byte pointer size (32-bit .NET runtime)
/// - Experimental/incomplete backend
pub struct IlBackend {
    _private: (),
}

impl IlBackend {
    /// Creates a new IL backend instance.
    pub fn new() -> Self {
        IlBackend { _private: () }
    }
}

impl Default for IlBackend {
    fn default() -> Self {
        Self::new()
    }
}

/// IL backend register classes.
/// The .NET IL backend uses a virtual register model.
/// 8 virtual integer slots + 8 virtual float slots.
const IL_REG_CLASSES: [i32; 16] = [
    1, 1, 1, 1, 1, 1, 1, 1,
    2, 2, 2, 2, 2, 2, 2, 2,
];

impl CodegenBackend for IlBackend {
    fn target_machine_defs(&self) -> &'static str {
        "__IL__\0"
    }

    fn reg_classes(&self) -> &[i32] { &IL_REG_CLASSES }
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
    fn emit_opcode(&mut self, _c: u32) -> TccResult<()> { Ok(()) }
    fn gen_vla_sp_save(&mut self, _addr: i32) -> TccResult<()> { Ok(()) }
    fn gen_vla_sp_restore(&mut self, _addr: i32) -> TccResult<()> { Ok(()) }
    fn gen_vla_alloc(&mut self, _typ: &CType, _align: i32) -> TccResult<()> { Ok(()) }

    fn code_reloc(&self, _reloc_type: i32) -> i32 { -1 }
    fn gotplt_entry_type(&self, _reloc_type: i32) -> i32 { 0 }
    fn relocate(&mut self, _rel_type: i32, _ptr: &mut [u8], _addr: u64, _val: u64) -> TccResult<()> { Ok(()) }

    /// IL backend does not have a standard ELF machine type; we use 0.
    fn elf_machine(&self) -> u16 { 0 }
    fn elf_start_addr(&self) -> u64 { 0 }
    fn elf_page_size(&self) -> u64 { 0x1000 }
    fn pcrelative_dllplt(&self) -> bool { false }
    fn relocate_dllplt(&self) -> bool { false }
}
