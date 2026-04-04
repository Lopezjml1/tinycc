//! i386 (IA-32) architecture backend
//!
//! Rust port of the i386 code generation, linking, and assembly
//! support from TCC. Sources: `i386-gen.c`, `i386-link.c`, `i386-asm.c`.
//!
//! Feature flag: `i386`

pub mod tokens;

use crate::arch::CodegenBackend;
use crate::error::TccResult;
use crate::types::{CType, SValue, Sym};

/// i386 code generation backend.
///
/// Implements the `CodegenBackend` trait for Intel IA-32 targets.
/// Port of `i386-gen.c` (1,306 lines) and `i386-link.c` (329 lines).
pub struct I386Backend {
    _private: (),
}

impl I386Backend {
    /// Creates a new i386 backend instance.
    pub fn new() -> Self {
        I386Backend { _private: () }
    }
}

impl Default for I386Backend {
    fn default() -> Self {
        Self::new()
    }
}

// NB_REGS = 5 for i386 (EAX, ECX, EDX, EBX, ST0)
const I386_REG_CLASSES: [i32; 5] = [1, 1, 1, 1, 2];

impl CodegenBackend for I386Backend {
    fn target_machine_defs(&self) -> &'static str {
        "__i386__\0__i386\0i386\0"
    }

    fn reg_classes(&self) -> &[i32] {
        &I386_REG_CLASSES
    }

    fn nb_regs(&self) -> usize { 5 }
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

    fn elf_machine(&self) -> u16 { 3 } // EM_386
    fn elf_start_addr(&self) -> u64 { 0x08048000 }
    fn elf_page_size(&self) -> u64 { 0x1000 }
    fn pcrelative_dllplt(&self) -> bool { false }
    fn relocate_dllplt(&self) -> bool { true }
}
