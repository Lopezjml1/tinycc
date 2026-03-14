//! x86-64 code generation and linker backend.
//!
//! This module implements the [`CodegenBackend`] trait for the x86-64
//! architecture.  Full implementation is provided by the dedicated
//! x86_64 backend agent.
//!
//! C equivalent: `x86_64-gen.c`, `x86_64-link.c`, `x86_64-asm.h`.

use crate::context::TccState;
use crate::error::{TccError, TccResult};
use crate::targets::{CodegenBackend, GotPltEntry, LinkerBackend};
use crate::types::{CType, SValue, Symbol};

// ---------------------------------------------------------------------------
// Target machine definitions
// ---------------------------------------------------------------------------

/// Preprocessor macros defined when targeting x86-64.
static TARGET_MACHINE_DEFS: &[&str] = &[
    "__x86_64__",
    "__amd64__",
    "__LP64__",
];

/// Register class bitmasks for x86-64 registers.
///
/// x86-64 has 16 general-purpose registers + 8 XMM registers = 24 total.
/// Indices: RAX=0, RCX=1, RDX=2, ..., R15=15, XMM0..XMM7=16..23.
/// Class bits: 0x1 = integer, 0x2 = float/SSE.
static REG_CLASSES: &[u32] = &[
    0x01, 0x01, 0x01, 0x01, // RAX, RCX, RDX, RBX
    0x00, 0x00, 0x00, 0x00, // RSP, RBP, RSI, RDI (RSP/RBP not allocatable)
    0x01, 0x01, 0x01, 0x01, // R8-R11
    0x01, 0x01, 0x01, 0x01, // R12-R15
    0x02, 0x02, 0x02, 0x02, // XMM0-XMM3
    0x02, 0x02, 0x02, 0x02, // XMM4-XMM7
];

// ---------------------------------------------------------------------------
// X86_64Backend
// ---------------------------------------------------------------------------

/// x86-64 code generation backend.
///
/// Implements `CodegenBackend` for generating x86-64 machine code.
///
/// C equivalent: Functions in `x86_64-gen.c`.
pub(crate) struct X86_64Backend {
    _private: (),
}

impl X86_64Backend {
    /// Create a new x86-64 backend instance.
    pub(crate) fn new() -> Self {
        Self { _private: () }
    }
}

#[allow(unused_variables)]
impl CodegenBackend for X86_64Backend {
    fn target_machine_defs(&self) -> &[&str] {
        TARGET_MACHINE_DEFS
    }

    fn reg_classes(&self) -> &[u32] {
        REG_CLASSES
    }

    fn gsym_addr(&mut self, state: &mut TccState, t: i32, a: i32) -> TccResult<()> {
        Err(TccError::UnsupportedTarget(
            "x86_64 backend: gsym_addr not yet fully implemented".to_string(),
        ))
    }

    fn gsym(&mut self, state: &mut TccState, t: i32) -> TccResult<()> {
        Err(TccError::UnsupportedTarget(
            "x86_64 backend: gsym not yet fully implemented".to_string(),
        ))
    }

    fn load(&mut self, state: &mut TccState, r: i32, sv: &SValue) -> TccResult<()> {
        Err(TccError::UnsupportedTarget(
            "x86_64 backend: load not yet fully implemented".to_string(),
        ))
    }

    fn store(&mut self, state: &mut TccState, r: i32, v: &SValue) -> TccResult<()> {
        Err(TccError::UnsupportedTarget(
            "x86_64 backend: store not yet fully implemented".to_string(),
        ))
    }

    fn gfunc_sret(
        &self,
        vt: &CType,
        variadic: bool,
        ret: &mut CType,
        align: &mut i32,
        regsize: &mut i32,
    ) -> i32 {
        0
    }

    fn gfunc_call(&mut self, state: &mut TccState, nb_args: i32) -> TccResult<()> {
        Err(TccError::UnsupportedTarget(
            "x86_64 backend: gfunc_call not yet fully implemented".to_string(),
        ))
    }

    fn gfunc_prolog(&mut self, state: &mut TccState, func_sym: &Symbol) -> TccResult<()> {
        Err(TccError::UnsupportedTarget(
            "x86_64 backend: gfunc_prolog not yet fully implemented".to_string(),
        ))
    }

    fn gfunc_epilog(&mut self, state: &mut TccState) -> TccResult<()> {
        Err(TccError::UnsupportedTarget(
            "x86_64 backend: gfunc_epilog not yet fully implemented".to_string(),
        ))
    }

    fn gen_fill_nops(&mut self, state: &mut TccState, bytes: i32) -> TccResult<()> {
        Err(TccError::UnsupportedTarget(
            "x86_64 backend: gen_fill_nops not yet fully implemented".to_string(),
        ))
    }

    fn gjmp(&mut self, state: &mut TccState, t: i32) -> TccResult<i32> {
        Err(TccError::UnsupportedTarget(
            "x86_64 backend: gjmp not yet fully implemented".to_string(),
        ))
    }

    fn gjmp_addr(&mut self, state: &mut TccState, a: i32) -> TccResult<()> {
        Err(TccError::UnsupportedTarget(
            "x86_64 backend: gjmp_addr not yet fully implemented".to_string(),
        ))
    }

    fn gjmp_cond(&mut self, state: &mut TccState, op: i32, t: i32) -> TccResult<i32> {
        Err(TccError::UnsupportedTarget(
            "x86_64 backend: gjmp_cond not yet fully implemented".to_string(),
        ))
    }

    fn gjmp_append(&mut self, state: &mut TccState, n: i32, t: i32) -> TccResult<i32> {
        Err(TccError::UnsupportedTarget(
            "x86_64 backend: gjmp_append not yet fully implemented".to_string(),
        ))
    }

    fn gen_opi(&mut self, state: &mut TccState, op: i32) -> TccResult<()> {
        Err(TccError::UnsupportedTarget(
            "x86_64 backend: gen_opi not yet fully implemented".to_string(),
        ))
    }

    fn gen_opf(&mut self, state: &mut TccState, op: i32) -> TccResult<()> {
        Err(TccError::UnsupportedTarget(
            "x86_64 backend: gen_opf not yet fully implemented".to_string(),
        ))
    }

    fn gen_cvt_ftoi(&mut self, state: &mut TccState, t: i32) -> TccResult<()> {
        Err(TccError::UnsupportedTarget(
            "x86_64 backend: gen_cvt_ftoi not yet fully implemented".to_string(),
        ))
    }

    fn gen_cvt_itof(&mut self, state: &mut TccState, t: i32) -> TccResult<()> {
        Err(TccError::UnsupportedTarget(
            "x86_64 backend: gen_cvt_itof not yet fully implemented".to_string(),
        ))
    }

    fn gen_cvt_ftof(&mut self, state: &mut TccState, t: i32) -> TccResult<()> {
        Err(TccError::UnsupportedTarget(
            "x86_64 backend: gen_cvt_ftof not yet fully implemented".to_string(),
        ))
    }

    fn ggoto(&mut self, state: &mut TccState) -> TccResult<()> {
        Err(TccError::UnsupportedTarget(
            "x86_64 backend: ggoto not yet fully implemented".to_string(),
        ))
    }

    fn o(&mut self, state: &mut TccState, c: u32) -> TccResult<()> {
        Err(TccError::UnsupportedTarget(
            "x86_64 backend: o not yet fully implemented".to_string(),
        ))
    }

    fn gen_vla_sp_save(&mut self, state: &mut TccState, addr: i32) -> TccResult<()> {
        Err(TccError::UnsupportedTarget(
            "x86_64 backend: gen_vla_sp_save not yet fully implemented".to_string(),
        ))
    }

    fn gen_vla_sp_restore(&mut self, state: &mut TccState, addr: i32) -> TccResult<()> {
        Err(TccError::UnsupportedTarget(
            "x86_64 backend: gen_vla_sp_restore not yet fully implemented".to_string(),
        ))
    }

    fn gen_vla_alloc(
        &mut self,
        state: &mut TccState,
        type_: &CType,
        align: i32,
    ) -> TccResult<()> {
        Err(TccError::UnsupportedTarget(
            "x86_64 backend: gen_vla_alloc not yet fully implemented".to_string(),
        ))
    }
}

// ---------------------------------------------------------------------------
// X86_64LinkerBackend
// ---------------------------------------------------------------------------

/// x86-64 linker backend — relocation processing, GOT/PLT.
///
/// C equivalent: Functions in `x86_64-link.c`.
pub(crate) struct X86_64LinkerBackend {
    _private: (),
}

impl X86_64LinkerBackend {
    /// Create a new x86-64 linker backend instance.
    pub(crate) fn new() -> Self {
        Self { _private: () }
    }
}

#[allow(unused_variables)]
impl LinkerBackend for X86_64LinkerBackend {
    fn code_reloc(&self, reloc_type: i32) -> i32 {
        -1
    }

    fn gotplt_entry_type(&self, reloc_type: i32) -> GotPltEntry {
        GotPltEntry::NoEntry
    }

    fn relocate(
        &self,
        state: &mut TccState,
        rel_type: i32,
        ptr: &mut [u8],
        addr: u64,
        val: u64,
    ) -> TccResult<()> {
        Err(TccError::UnsupportedTarget(
            "x86_64 linker backend: relocate not yet fully implemented".to_string(),
        ))
    }

    fn create_plt_entry(
        &mut self,
        state: &mut TccState,
        got_offset: u32,
    ) -> TccResult<u32> {
        Err(TccError::UnsupportedTarget(
            "x86_64 linker backend: create_plt_entry not yet fully implemented".to_string(),
        ))
    }

    fn relocate_plt(&mut self, state: &mut TccState) -> TccResult<()> {
        Err(TccError::UnsupportedTarget(
            "x86_64 linker backend: relocate_plt not yet fully implemented".to_string(),
        ))
    }
}
