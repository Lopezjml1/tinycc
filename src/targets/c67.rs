//! TMS320C67 DSP code generation and linker backend.
//!
//! This module implements the [`CodegenBackend`] trait for the TMS320C67
//! DSP processor.  Full implementation is provided by the dedicated
//! C67 backend agent.
//!
//! C equivalent: `c67-gen.c`, `c67-link.c`.

use crate::context::TccState;
use crate::error::{TccError, TccResult};
use crate::targets::{CodegenBackend, GotPltEntry, LinkerBackend};
use crate::types::{CType, SValue, Symbol};

// ---------------------------------------------------------------------------
// Target machine definitions
// ---------------------------------------------------------------------------

/// Preprocessor macros defined when targeting TMS320C67.
static TARGET_MACHINE_DEFS: &[&str] = &["__C67__"];

/// Register class bitmasks for TMS320C67 registers.
///
/// C67 has two register files (A and B) with 16 registers each.
/// 0x01 = integer, 0x02 = float.
static REG_CLASSES: &[u32] = &[
    0x01, 0x01, 0x01, 0x01, // A0-A3
    0x01, 0x01, 0x01, 0x01, // A4-A7
    0x01, 0x01, 0x03, 0x03, // A8-A11 (A10-A11 also float)
    0x03, 0x03, 0x03, 0x03, // A12-A15 (also float)
    0x01, 0x01, 0x01, 0x01, // B0-B3
    0x01, 0x01, 0x01, 0x01, // B4-B7
    0x01, 0x01, 0x03, 0x03, // B8-B11 (B10-B11 also float)
    0x03, 0x03, 0x03, 0x03, // B12-B15 (also float)
];

// ---------------------------------------------------------------------------
// C67Backend
// ---------------------------------------------------------------------------

/// TMS320C67 DSP code generation backend.
///
/// Implements `CodegenBackend` for generating TMS320C67 machine code.
/// Note: the `o()` method is not available on C67 (per tcc.h:1642).
///
/// C equivalent: Functions in `c67-gen.c`.
pub(crate) struct C67Backend {
    _private: (),
}

impl C67Backend {
    /// Create a new C67 backend instance.
    pub(crate) fn new() -> Self {
        Self { _private: () }
    }
}

#[allow(unused_variables)]
impl CodegenBackend for C67Backend {
    fn target_machine_defs(&self) -> &[&str] {
        TARGET_MACHINE_DEFS
    }

    fn reg_classes(&self) -> &[u32] {
        REG_CLASSES
    }

    fn gsym_addr(&mut self, state: &mut TccState, t: i32, a: i32) -> TccResult<()> {
        Err(TccError::UnsupportedTarget(
            "c67 backend: gsym_addr not yet fully implemented".to_string(),
        ))
    }

    fn gsym(&mut self, state: &mut TccState, t: i32) -> TccResult<()> {
        Err(TccError::UnsupportedTarget(
            "c67 backend: gsym not yet fully implemented".to_string(),
        ))
    }

    fn load(&mut self, state: &mut TccState, r: i32, sv: &SValue) -> TccResult<()> {
        Err(TccError::UnsupportedTarget(
            "c67 backend: load not yet fully implemented".to_string(),
        ))
    }

    fn store(&mut self, state: &mut TccState, r: i32, v: &SValue) -> TccResult<()> {
        Err(TccError::UnsupportedTarget(
            "c67 backend: store not yet fully implemented".to_string(),
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
            "c67 backend: gfunc_call not yet fully implemented".to_string(),
        ))
    }

    fn gfunc_prolog(&mut self, state: &mut TccState, func_sym: &Symbol) -> TccResult<()> {
        Err(TccError::UnsupportedTarget(
            "c67 backend: gfunc_prolog not yet fully implemented".to_string(),
        ))
    }

    fn gfunc_epilog(&mut self, state: &mut TccState) -> TccResult<()> {
        Err(TccError::UnsupportedTarget(
            "c67 backend: gfunc_epilog not yet fully implemented".to_string(),
        ))
    }

    fn gen_fill_nops(&mut self, state: &mut TccState, bytes: i32) -> TccResult<()> {
        Err(TccError::UnsupportedTarget(
            "c67 backend: gen_fill_nops not yet fully implemented".to_string(),
        ))
    }

    fn gjmp(&mut self, state: &mut TccState, t: i32) -> TccResult<i32> {
        Err(TccError::UnsupportedTarget(
            "c67 backend: gjmp not yet fully implemented".to_string(),
        ))
    }

    fn gjmp_addr(&mut self, state: &mut TccState, a: i32) -> TccResult<()> {
        Err(TccError::UnsupportedTarget(
            "c67 backend: gjmp_addr not yet fully implemented".to_string(),
        ))
    }

    fn gjmp_cond(&mut self, state: &mut TccState, op: i32, t: i32) -> TccResult<i32> {
        Err(TccError::UnsupportedTarget(
            "c67 backend: gjmp_cond not yet fully implemented".to_string(),
        ))
    }

    fn gjmp_append(&mut self, state: &mut TccState, n: i32, t: i32) -> TccResult<i32> {
        Err(TccError::UnsupportedTarget(
            "c67 backend: gjmp_append not yet fully implemented".to_string(),
        ))
    }

    fn gen_opi(&mut self, state: &mut TccState, op: i32) -> TccResult<()> {
        Err(TccError::UnsupportedTarget(
            "c67 backend: gen_opi not yet fully implemented".to_string(),
        ))
    }

    fn gen_opf(&mut self, state: &mut TccState, op: i32) -> TccResult<()> {
        Err(TccError::UnsupportedTarget(
            "c67 backend: gen_opf not yet fully implemented".to_string(),
        ))
    }

    fn gen_cvt_ftoi(&mut self, state: &mut TccState, t: i32) -> TccResult<()> {
        Err(TccError::UnsupportedTarget(
            "c67 backend: gen_cvt_ftoi not yet fully implemented".to_string(),
        ))
    }

    fn gen_cvt_itof(&mut self, state: &mut TccState, t: i32) -> TccResult<()> {
        Err(TccError::UnsupportedTarget(
            "c67 backend: gen_cvt_itof not yet fully implemented".to_string(),
        ))
    }

    fn gen_cvt_ftof(&mut self, state: &mut TccState, t: i32) -> TccResult<()> {
        Err(TccError::UnsupportedTarget(
            "c67 backend: gen_cvt_ftof not yet fully implemented".to_string(),
        ))
    }

    fn ggoto(&mut self, state: &mut TccState) -> TccResult<()> {
        Err(TccError::UnsupportedTarget(
            "c67 backend: ggoto not yet fully implemented".to_string(),
        ))
    }

    /// Note: `o()` is not available on C67 target per `tcc.h:1642`.
    /// This implementation returns an error indicating the operation
    /// is unsupported for this architecture.
    fn o(&mut self, state: &mut TccState, c: u32) -> TccResult<()> {
        Err(TccError::UnsupportedTarget(
            "c67 backend: o() is not available on TMS320C67".to_string(),
        ))
    }

    fn gen_vla_sp_save(&mut self, state: &mut TccState, addr: i32) -> TccResult<()> {
        Err(TccError::UnsupportedTarget(
            "c67 backend: gen_vla_sp_save not yet fully implemented".to_string(),
        ))
    }

    fn gen_vla_sp_restore(&mut self, state: &mut TccState, addr: i32) -> TccResult<()> {
        Err(TccError::UnsupportedTarget(
            "c67 backend: gen_vla_sp_restore not yet fully implemented".to_string(),
        ))
    }

    fn gen_vla_alloc(
        &mut self,
        state: &mut TccState,
        type_: &CType,
        align: i32,
    ) -> TccResult<()> {
        Err(TccError::UnsupportedTarget(
            "c67 backend: gen_vla_alloc not yet fully implemented".to_string(),
        ))
    }
}

// ---------------------------------------------------------------------------
// C67LinkerBackend
// ---------------------------------------------------------------------------

/// C67 linker backend — relocation processing.
///
/// C equivalent: Functions in `c67-link.c`.
pub(crate) struct C67LinkerBackend {
    _private: (),
}

impl C67LinkerBackend {
    /// Create a new C67 linker backend instance.
    pub(crate) fn new() -> Self {
        Self { _private: () }
    }
}

#[allow(unused_variables)]
impl LinkerBackend for C67LinkerBackend {
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
            "c67 linker backend: relocate not yet fully implemented".to_string(),
        ))
    }

    fn create_plt_entry(
        &mut self,
        state: &mut TccState,
        got_offset: u32,
    ) -> TccResult<u32> {
        Err(TccError::UnsupportedTarget(
            "c67 linker backend: create_plt_entry not yet fully implemented".to_string(),
        ))
    }

    fn relocate_plt(&mut self, state: &mut TccState) -> TccResult<()> {
        Err(TccError::UnsupportedTarget(
            "c67 linker backend: relocate_plt not yet fully implemented".to_string(),
        ))
    }
}
