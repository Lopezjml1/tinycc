//! TMS320C67xx DSP code generation backend.
//!
//! This module implements the [`CodegenBackend`] trait for the Texas Instruments
//! TMS320C67xx Digital Signal Processor family. The C67 is a VLIW architecture
//! with dual data paths (A and B sides), 8 functional units, and deep pipelines.
//!
//! This is a port of `c67-gen.c` (2,543 lines) and `c67-link.c` (125 lines).
//!
//! # Architecture Notes
//!
//! - VLIW (Very Long Instruction Word) architecture
//! - Uses COFF output format (not standard ELF)
//! - 24 registers (12 on A side, 12 on B side)
//! - No VLA support
//! - No long double hardware support (uses 12-byte software emulation)
//! - No bounds checking support (`CONFIG_TCC_BCHECK` is undefined)
//! - First 10 function parameters passed in register pairs (A4:A5 through B12:B13)
//! - Pipeline scheduling with explicit NOP delays for loads, branches, and multiplies

pub mod gen;
pub mod link;

// ===========================================================================
// Re-exports from gen.rs — register count, class table, pointer size
// These constants are the authoritative definitions used by the code generator.
// ===========================================================================

/// Number of available registers for the C67 backend (24).
/// Re-exported from `gen.rs`; originally from c67-gen.c line 26.
pub use gen::NB_REGS;

/// Register class table — maps register number to class bitmask.
/// Re-exported from `gen.rs`; originally from c67-gen.c lines 123-150.
pub use gen::REG_CLASSES;

/// Pointer size in bytes for the C67 target (32-bit architecture).
/// Re-exported from `gen.rs`; originally from c67-gen.c line 103.
pub use gen::PTR_SIZE;

// ===========================================================================
// Re-exports from gen.rs — register class bitmask constants
// ===========================================================================

pub use gen::{
    RC_EAX, RC_ST0, RC_ECX, RC_EDX, RC_INT_BSIDE,
    RC_C67_A4, RC_C67_A5, RC_C67_B4, RC_C67_B5,
    RC_C67_A6, RC_C67_A7, RC_C67_B6, RC_C67_B7,
    RC_C67_A8, RC_C67_A9, RC_C67_B8, RC_C67_B9,
    RC_C67_A10, RC_C67_A11, RC_C67_B10, RC_C67_B11,
    RC_C67_A12, RC_C67_A13, RC_C67_B12, RC_C67_B13,
};

// ===========================================================================
// Re-exports from gen.rs — TCC register number constants (TREG_*)
// ===========================================================================

pub use gen::{
    TREG_EAX, TREG_ECX, TREG_EDX, TREG_ST0,
    TREG_C67_A4, TREG_C67_A5, TREG_C67_B4, TREG_C67_B5,
    TREG_C67_A6, TREG_C67_A7, TREG_C67_B6, TREG_C67_B7,
    TREG_C67_A8, TREG_C67_A9, TREG_C67_B8, TREG_C67_B9,
    TREG_C67_A10, TREG_C67_A11, TREG_C67_B10, TREG_C67_B11,
    TREG_C67_A12, TREG_C67_A13, TREG_C67_B12, TREG_C67_B13,
};

// ===========================================================================
// Re-exports from gen.rs — return register number aliases
// ===========================================================================

/// Single-word integer return register number (A4).
/// Re-exported from `gen.rs`; originally from c67-gen.c line 91.
pub use gen::REG_IRET;

/// Second-word integer return register number (A5, for long long).
/// Re-exported from `gen.rs`; originally from c67-gen.c line 92.
pub use gen::REG_IRE2;

/// Floating-point return register number (A4, same physical register as REG_IRET).
/// Re-exported from `gen.rs`; originally from c67-gen.c line 93.
pub use gen::REG_FRET;

// ===========================================================================
// Re-exports from parent arch module — shared register class constants
// These are defined in `crate::arch` and shared across all backends.
// ===========================================================================

/// Generic integer register class bitmask (0x0001).
pub use crate::arch::RC_INT;

/// Generic floating-point register class bitmask (0x0002).
pub use crate::arch::RC_FLOAT;

// ===========================================================================
// Constants defined at module level (not present in gen.rs or link.rs)
// ===========================================================================

/// Target machine predefined macros string.
///
/// When compiling for C67, the preprocessor defines `__C67__` automatically.
/// The null terminator is included for compatibility with C string handling.
///
/// From c67-gen.c lines 119-121.
pub const TARGET_MACHINE_DEFS: &str = "__C67__\0";

/// Long double size in bytes.
///
/// The C67 DSP does not have hardware long double support. TCC uses a 12-byte
/// software emulation format consistent with x87 extended precision layout.
///
/// From c67-gen.c line 106: `#define LDOUBLE_SIZE 12`
pub const LDOUBLE_SIZE: usize = 12;

/// Long double alignment in bytes.
///
/// From c67-gen.c line 107: `#define LDOUBLE_ALIGN 4`
pub const LDOUBLE_ALIGN: usize = 4;

/// Maximum alignment for this target (for `__attribute__((aligned(N)))` support).
///
/// From c67-gen.c line 109: `#define MAX_ALIGN 8`
pub const MAX_ALIGN: usize = 8;

// ===========================================================================
// Return register CLASS aliases
// These map to register class bitmasks (not register numbers).
// From c67-gen.c lines 58-60.
// ===========================================================================

/// Register class for integer return values (maps to the A4 register class bitmask).
///
/// From c67-gen.c line 58: `#define RC_IRET RC_C67_A4`
pub const RC_IRET: i32 = gen::RC_C67_A4;

/// Register class for second integer return value (maps to A5 register class bitmask).
///
/// Used for the high word of `long long` return values.
///
/// From c67-gen.c line 59: `#define RC_IRE2 RC_C67_A5`
pub const RC_IRE2: i32 = gen::RC_C67_A5;

/// Register class for floating-point return values (maps to A4 register class bitmask).
///
/// On C67, float and integer returns use the same physical register (A4).
///
/// From c67-gen.c line 60: `#define RC_FRET RC_C67_A4`
pub const RC_FRET: i32 = gen::RC_C67_A4;

// ===========================================================================
// Imports for struct definition and trait implementation
// ===========================================================================

use crate::arch::CodegenBackend;
use crate::error::{TccError, TccResult};
use crate::types::{CType, SValue, Sym};

use gen::{C67CodegenCtx, C67GenState, PendingReloc};

// ===========================================================================
// C67Backend struct
// ===========================================================================

/// TMS320C67xx DSP code generation backend.
///
/// Implements the [`CodegenBackend`] trait for TI C67xx DSP processors.
/// This struct encapsulates all mutable state needed for code generation,
/// replacing the global variables from the original C implementation.
///
/// # Fields
///
/// - `gen_state` — C67-specific code generation state (function parameter tracking,
///   comparison register state, stack layout). Corresponds to global variables in
///   c67-gen.c lines 152-187.
/// - `ctx` — Code emission context shared with the generic codegen layer (current
///   code position, code buffer, value stack snapshot). Synced before/after each
///   trait method call.
/// - `pending_relocs` — Relocation entries queued during code emission for later
///   processing by the generic codegen layer.
///
/// # Architecture Notes
///
/// - VLIW architecture with A-side and B-side data paths
/// - Uses COFF output format (via `crate::coff` module)
/// - 24 registers: A2-A13 (A side) and B0-B1, B4-B13 (B side)
/// - First 10 function parameters passed in register pairs (A4:A5 through B12:B13)
/// - No VLA support, no bounds checking
/// - Pipeline scheduling with explicit NOP delays for loads, branches, and multiplies
pub struct C67Backend {
    /// Internal code generation state (function params, compare regs, stack layout).
    ///
    /// This is public so that callers (e.g., the generic codegen layer) can inspect
    /// or save/restore C67-specific state when needed.
    pub gen_state: C67GenState,

    /// Code emission context (ind, code_buf, vstack, nocode_wanted, loc, func_vt).
    ///
    /// Synced by the generic `CodeGen` before and after each backend trait method
    /// call, mirroring the pattern used by other architecture backends.
    pub(crate) ctx: C67CodegenCtx,

    /// Pending relocations generated during code emission.
    ///
    /// Since the backend cannot directly call ELF/COFF relocation functions (they
    /// require `&mut TCCState`), relocations are queued here and processed by the
    /// generic codegen layer after the trait method returns.
    pub(crate) pending_relocs: Vec<PendingReloc>,
}

impl C67Backend {
    /// Creates a new C67 backend instance with all state initialized to defaults.
    ///
    /// The comparison register is initialized to `C67_CREG_ZERO` (-1), indicating
    /// no active condition register. The value stack index starts at -1 (empty).
    /// All other fields are zero-initialized.
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

// ===========================================================================
// CodegenBackend trait implementation
// ===========================================================================

impl CodegenBackend for C67Backend {
    // -----------------------------------------------------------------------
    // Target information queries
    // -----------------------------------------------------------------------

    /// Returns the predefined macro string for the C67 target.
    ///
    /// The preprocessor defines `__C67__` when targeting this architecture.
    fn target_machine_defs(&self) -> &'static str {
        TARGET_MACHINE_DEFS
    }

    /// Returns the register class table for all 24 C67 registers.
    ///
    /// Each entry maps a TCC register index (TREG_*) to a bitmask of register
    /// classes that the register belongs to. The generic register allocator uses
    /// this table to select appropriate registers for each operation.
    fn reg_classes(&self) -> &[i32] {
        &gen::REG_CLASSES
    }

    /// Returns the number of registers available to TCC's allocator (24).
    fn nb_regs(&self) -> usize {
        gen::NB_REGS
    }

    /// Returns the pointer size for the C67 target (4 bytes, 32-bit).
    fn ptr_size(&self) -> usize {
        gen::PTR_SIZE
    }

    // -----------------------------------------------------------------------
    // Symbol resolution
    // -----------------------------------------------------------------------

    /// Resolve a forward reference chain at a specific address.
    ///
    /// Patches all instructions in the forward reference chain starting at
    /// offset `t` to jump to address `a`.
    ///
    /// Delegates to [`gen::gsym_addr`].
    fn gsym_addr(&mut self, t: i32, a: i32) -> TccResult<()> {
        gen::gsym_addr(self, t, a)
    }

    /// Resolve a forward reference chain at the current code position.
    ///
    /// Equivalent to `gsym_addr(t, ind)` where `ind` is the current code offset.
    /// In the C source this is implemented as `gsym(t) { gsym_addr(t, ind); }`.
    fn gsym(&mut self, t: i32) -> TccResult<()> {
        let a = self.ctx.ind;
        gen::gsym_addr(self, t, a)
    }

    // -----------------------------------------------------------------------
    // Value loading and storing
    // -----------------------------------------------------------------------

    /// Load a value described by `sv` into hardware register `r`.
    ///
    /// Handles constants (VT_CONST), local variables (VT_LOCAL), lvalues
    /// (VT_LVAL), comparison results (VT_CMP), and jump conditions (VT_JMP/JMPI).
    /// Emits appropriate C67 load instructions with pipeline delay NOPs.
    ///
    /// Delegates to [`gen::load`].
    fn load(&mut self, r: i32, sv: &SValue) -> TccResult<()> {
        gen::load(self, r, sv)
    }

    /// Store the value in hardware register `r` to the location described by `sv`.
    ///
    /// Handles stores to local variables, global variables, and pointer
    /// dereferences. Emits STB/STH/STW instructions based on data size.
    ///
    /// Delegates to [`gen::store`].
    fn store(&mut self, r: i32, sv: &SValue) -> TccResult<()> {
        gen::store(self, r, sv)
    }

    // -----------------------------------------------------------------------
    // Function call interface
    // -----------------------------------------------------------------------

    /// Determine if a struct return type should use a hidden pointer parameter.
    ///
    /// On C67, struct returns always use a hidden pointer parameter (the function
    /// never returns structs directly in registers). Returns `(false, ...)` to
    /// indicate no special struct-return register convention is used.
    ///
    /// Delegates to [`gen::gfunc_sret`].
    fn gfunc_sret(&self, vt: &CType, variadic: bool) -> (bool, CType, i32, i32) {
        gen::gfunc_sret(self, vt, variadic)
    }

    /// Generate a function call with `nb_args` arguments on the value stack.
    ///
    /// Arguments are assigned to register pairs A4:A5 through B12:B13 (up to
    /// 10 arguments). Emits MVKL/MVKH for the function address, a branch
    /// instruction, and appropriate pipeline delay NOPs.
    ///
    /// Delegates to [`gen::gfunc_call`].
    fn gfunc_call(&mut self, nb_args: i32) -> TccResult<()> {
        gen::gfunc_call(self, nb_args)
    }

    /// Generate a function prologue.
    ///
    /// Sets up the stack frame: pushes return address (B3), frame pointer (A15),
    /// and allocates space for local variables. Maps function parameters from
    /// their stack locations to assigned registers.
    ///
    /// Delegates to [`gen::gfunc_prolog`].
    fn gfunc_prolog(&mut self, func_sym: &Sym) -> TccResult<()> {
        gen::gfunc_prolog(self, func_sym)
    }

    /// Generate a function epilogue.
    ///
    /// Tears down the stack frame: restores frame pointer and return address,
    /// deallocates local variable space, and emits a return branch (B B3) with
    /// pipeline delay NOPs.
    ///
    /// Delegates to [`gen::gfunc_epilog`].
    fn gfunc_epilog(&mut self) -> TccResult<()> {
        gen::gfunc_epilog(self)
    }

    // -----------------------------------------------------------------------
    // NOP generation
    // -----------------------------------------------------------------------

    /// Fill `n` bytes with NOP instructions.
    ///
    /// Each C67 NOP is a 4-byte instruction word. Used for alignment padding
    /// and pipeline delay slot filling.
    ///
    /// Delegates to [`gen::gen_fill_nops`].
    fn gen_fill_nops(&mut self, n: i32) -> TccResult<()> {
        gen::gen_fill_nops(self, n)
    }

    // -----------------------------------------------------------------------
    // Jump generation
    // -----------------------------------------------------------------------

    /// Generate an unconditional jump, returning the forward reference offset.
    ///
    /// The parameter `t` is a forward reference chain that the new jump is
    /// appended to. Returns the offset of the new jump instruction for later
    /// patching via `gsym_addr`.
    ///
    /// Delegates to [`gen::gjmp`].
    fn gjmp(&mut self, t: i32) -> TccResult<i32> {
        gen::gjmp(self, t)
    }

    /// Generate an unconditional jump to a known absolute address `a`.
    ///
    /// Delegates to [`gen::gjmp_addr`].
    fn gjmp_addr(&mut self, a: i32) -> TccResult<()> {
        gen::gjmp_addr(self, a)
    }

    /// Generate a conditional jump based on comparison operator `op`.
    ///
    /// Uses the C67 comparison register state (`c67_compare_reg`,
    /// `c67_invert_test`) to determine the condition. Returns a forward
    /// reference chain offset.
    ///
    /// Delegates to [`gen::gjmp_cond`].
    fn gjmp_cond(&mut self, op: i32, t: i32) -> TccResult<i32> {
        gen::gjmp_cond(self, op, t)
    }

    /// Append a forward reference to an existing chain.
    ///
    /// Links jump target `t` into the chain starting at `n`. Used to build
    /// linked lists of forward references that are later resolved by `gsym`.
    ///
    /// Delegates to [`gen::gjmp_append`].
    fn gjmp_append(&mut self, n: i32, t: i32) -> TccResult<i32> {
        gen::gjmp_append(self, n, t)
    }

    // -----------------------------------------------------------------------
    // Integer arithmetic operations
    // -----------------------------------------------------------------------

    /// Generate an integer arithmetic operation.
    ///
    /// Supports ADD, SUB, MUL, DIV, MOD, AND, OR, XOR, SHL, SHR, SAR, and
    /// comparison operators. Uses the C67 .L, .S, and .M functional units
    /// as appropriate.
    ///
    /// Delegates to [`gen::gen_opi`].
    fn gen_opi(&mut self, op: i32) -> TccResult<()> {
        gen::gen_opi(self, op)
    }

    // -----------------------------------------------------------------------
    // Floating-point arithmetic operations
    // -----------------------------------------------------------------------

    /// Generate a floating-point arithmetic operation.
    ///
    /// Supports ADDDP, SUBDP, MPYDP (double precision) and ADDSP, SUBSP,
    /// MPYSP (single precision) operations on the C67's floating-point units.
    ///
    /// Delegates to [`gen::gen_opf`].
    fn gen_opf(&mut self, op: i32) -> TccResult<()> {
        gen::gen_opf(self, op)
    }

    // -----------------------------------------------------------------------
    // Type conversion operations
    // -----------------------------------------------------------------------

    /// Generate float-to-integer conversion.
    ///
    /// Emits SPTRUNC.L or DPTRUNC.L instructions depending on the source
    /// floating-point type.
    ///
    /// Delegates to [`gen::gen_cvt_ftoi`].
    fn gen_cvt_ftoi(&mut self, t: i32) -> TccResult<()> {
        gen::gen_cvt_ftoi(self, t)
    }

    /// Generate integer-to-float conversion.
    ///
    /// Emits INTSP.L, INTSPU.L, INTDP.L, or INTDPU.L instructions depending
    /// on signedness and target floating-point type.
    ///
    /// Delegates to [`gen::gen_cvt_itof`].
    fn gen_cvt_itof(&mut self, t: i32) -> TccResult<()> {
        gen::gen_cvt_itof(self, t)
    }

    /// Generate float-to-float conversion (e.g., float ↔ double).
    ///
    /// Emits SPDP.L (float→double) or DPSP.L (double→float) instructions.
    ///
    /// Delegates to [`gen::gen_cvt_ftof`].
    fn gen_cvt_ftof(&mut self, t: i32) -> TccResult<()> {
        gen::gen_cvt_ftof(self, t)
    }

    // -----------------------------------------------------------------------
    // Indirect jump (computed goto)
    // -----------------------------------------------------------------------

    /// Generate a computed goto (indirect jump to address on value stack top).
    ///
    /// Delegates to [`gen::ggoto`].
    fn ggoto(&mut self) -> TccResult<()> {
        gen::ggoto(self)
    }

    // -----------------------------------------------------------------------
    // Generic opcode emission — NOT available for C67
    // -----------------------------------------------------------------------

    /// Generic opcode emission is not available for the C67 target.
    ///
    /// The C67 uses its own VLIW instruction format and does not support the
    /// generic byte-level `o()` emission function. In the original C source,
    /// this is excluded by `#ifndef TCC_TARGET_C67` in `tcc.h`.
    ///
    /// C67-specific instruction emission goes through `c67_g()` in `gen.rs`.
    fn emit_opcode(&mut self, _c: u32) -> TccResult<()> {
        Err(TccError::codegen(
            "C67: generic opcode emission (o()) is not available for this target",
        ))
    }

    // -----------------------------------------------------------------------
    // Variable-length array support — NOT available for C67
    // -----------------------------------------------------------------------

    /// VLA stack pointer save — not supported on C67.
    ///
    /// The C67 target does not support variable-length arrays.
    /// `CONFIG_TCC_BCHECK` is explicitly undefined for C67 (c67-gen.c line 111).
    ///
    /// Delegates to [`gen::gen_vla_sp_save`] which returns an error.
    fn gen_vla_sp_save(&mut self, addr: i32) -> TccResult<()> {
        gen::gen_vla_sp_save(self, addr)
    }

    /// VLA stack pointer restore — not supported on C67.
    ///
    /// Delegates to [`gen::gen_vla_sp_restore`] which returns an error.
    fn gen_vla_sp_restore(&mut self, addr: i32) -> TccResult<()> {
        gen::gen_vla_sp_restore(self, addr)
    }

    /// VLA memory allocation — not supported on C67.
    ///
    /// Delegates to [`gen::gen_vla_alloc`] which returns an error.
    fn gen_vla_alloc(&mut self, typ: &CType, align: i32) -> TccResult<()> {
        gen::gen_vla_alloc(self, typ, align)
    }

    // -----------------------------------------------------------------------
    // Linker / Relocation support (delegating to link.rs)
    // -----------------------------------------------------------------------

    /// Classify a C67 relocation type as code (1), data (0), or unknown (-1).
    ///
    /// Used by the linker to determine whether a relocation references code or
    /// data, affecting PLT entry generation decisions.
    ///
    /// Delegates to [`link::code_reloc`].
    fn code_reloc(&self, reloc_type: i32) -> i32 {
        link::code_reloc(reloc_type)
    }

    /// Determine whether a C67 relocation type requires GOT and/or PLT entries.
    ///
    /// Returns `NO_GOTPLT_ENTRY` (0), `BUILD_GOT_ONLY` (1), or
    /// `ALWAYS_GOTPLT_ENTRY` (3) for known types, -1 for unknown.
    ///
    /// Delegates to [`link::gotplt_entry_type`].
    fn gotplt_entry_type(&self, reloc_type: i32) -> i32 {
        link::gotplt_entry_type(reloc_type)
    }

    /// Apply a C67 relocation to a memory location.
    ///
    /// Handles R_C60_32 (absolute 32-bit), R_C60LO16 (low 16 bits), and
    /// R_C60HI16 (high 16 bits) relocation types.
    ///
    /// Delegates to [`link::relocate`].
    fn relocate(
        &mut self,
        rel_type: i32,
        ptr: &mut [u8],
        addr: u64,
        val: u64,
    ) -> TccResult<()> {
        link::relocate(rel_type, ptr, addr, val)
    }

    // -----------------------------------------------------------------------
    // ELF / Output format constants (from link.rs)
    // -----------------------------------------------------------------------

    /// Returns the ELF machine type identifier for the C67 target.
    ///
    /// Uses `link::EM_TCC_TARGET` which corresponds to the TCC-specific
    /// machine identifier for the TMS320C60 family.
    fn elf_machine(&self) -> u16 {
        link::EM_TCC_TARGET
    }

    /// Returns the default start address for C67 executables.
    ///
    /// From c67-link.c: `#define ELF_START_ADDR 0x00000400`
    fn elf_start_addr(&self) -> u64 {
        link::ELF_START_ADDR
    }

    /// Returns the page size for C67 target memory layout.
    ///
    /// From c67-link.c: `#define ELF_PAGE_SIZE 0x1000`
    fn elf_page_size(&self) -> u64 {
        link::ELF_PAGE_SIZE
    }

    /// C67 does not use PC-relative DLL PLT entries.
    fn pcrelative_dllplt(&self) -> bool {
        link::PCRELATIVE_DLLPLT
    }

    /// C67 does not perform DLL PLT relocation.
    fn relocate_dllplt(&self) -> bool {
        link::RELOCATE_DLLPLT
    }
}

// ===========================================================================
// Unit tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Construction and initialization tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_c67_backend_new() {
        let backend = C67Backend::new();
        // C67_CREG_ZERO is -1 (no active condition register)
        assert_eq!(backend.gen_state.c67_compare_reg, -1);
        assert_eq!(backend.gen_state.no_of_cur_func_args, 0);
        assert_eq!(backend.gen_state.func_sub_sp_offset, 0);
        assert_eq!(backend.gen_state.func_ret_sub, 0);
        assert!(!backend.gen_state.c67_invert_test);
        assert_eq!(backend.gen_state.total_bytes_pushed_on_stack, 0);
        assert_eq!(backend.ctx.ind, 0);
        assert_eq!(backend.ctx.nocode_wanted, 0);
        assert_eq!(backend.ctx.vtop_idx, -1);
        assert_eq!(backend.pending_relocs.len(), 0);
    }

    #[test]
    fn test_c67_backend_default() {
        let backend = C67Backend::default();
        assert_eq!(backend.pending_relocs.len(), 0);
        assert_eq!(backend.ctx.vtop_idx, -1);
        assert_eq!(backend.ctx.code_buf.len(), 0);
    }

    // -----------------------------------------------------------------------
    // Constant value tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_target_constants() {
        assert_eq!(NB_REGS, 24);
        assert_eq!(PTR_SIZE, 4);
        assert_eq!(LDOUBLE_SIZE, 12);
        assert_eq!(LDOUBLE_ALIGN, 4);
        assert_eq!(MAX_ALIGN, 8);
        assert!(TARGET_MACHINE_DEFS.starts_with("__C67__"));
        assert!(TARGET_MACHINE_DEFS.ends_with('\0'));
    }

    #[test]
    fn test_register_number_constants() {
        // TREG numbers are sequential 0-23
        assert_eq!(TREG_EAX, 0);
        assert_eq!(TREG_ECX, 1);
        assert_eq!(TREG_EDX, 2);
        assert_eq!(TREG_ST0, 3);
        assert_eq!(TREG_C67_A4, 4);
        assert_eq!(TREG_C67_A5, 5);
        assert_eq!(TREG_C67_B4, 6);
        assert_eq!(TREG_C67_B5, 7);
        assert_eq!(TREG_C67_A6, 8);
        assert_eq!(TREG_C67_A7, 9);
        assert_eq!(TREG_C67_B6, 10);
        assert_eq!(TREG_C67_B7, 11);
        assert_eq!(TREG_C67_A8, 12);
        assert_eq!(TREG_C67_A9, 13);
        assert_eq!(TREG_C67_B8, 14);
        assert_eq!(TREG_C67_B9, 15);
        assert_eq!(TREG_C67_A10, 16);
        assert_eq!(TREG_C67_A11, 17);
        assert_eq!(TREG_C67_B10, 18);
        assert_eq!(TREG_C67_B11, 19);
        assert_eq!(TREG_C67_A12, 20);
        assert_eq!(TREG_C67_A13, 21);
        assert_eq!(TREG_C67_B12, 22);
        assert_eq!(TREG_C67_B13, 23);
    }

    #[test]
    fn test_return_register_number_aliases() {
        assert_eq!(REG_IRET, TREG_C67_A4);
        assert_eq!(REG_IRE2, TREG_C67_A5);
        assert_eq!(REG_FRET, TREG_C67_A4);
    }

    #[test]
    fn test_return_register_class_aliases() {
        assert_eq!(RC_IRET, RC_C67_A4);
        assert_eq!(RC_IRE2, RC_C67_A5);
        assert_eq!(RC_FRET, RC_C67_A4);
    }

    #[test]
    fn test_shared_register_class_constants() {
        // RC_INT and RC_FLOAT are shared across all backends
        assert_eq!(RC_INT, 0x0001);
        assert_eq!(RC_FLOAT, 0x0002);
    }

    #[test]
    fn test_register_classes_array_length() {
        assert_eq!(REG_CLASSES.len(), NB_REGS);
    }

    #[test]
    fn test_register_classes_first_four() {
        // Registers 0-3 have RC_INT
        assert_ne!(REG_CLASSES[0] & RC_INT, 0, "TREG_EAX should have RC_INT");
        assert_ne!(REG_CLASSES[1] & RC_INT, 0, "TREG_ECX should have RC_INT");
        assert_ne!(REG_CLASSES[2] & RC_INT, 0, "TREG_EDX should have RC_INT");
    }

    #[test]
    fn test_register_classes_a_side() {
        // A-side registers (4, 5, 8, 9, 12, 13, 16, 17, 20, 21) have RC_INT | RC_FLOAT
        for &idx in &[4, 5, 8, 9, 12, 13, 16, 17, 20, 21] {
            assert_ne!(
                REG_CLASSES[idx] & RC_INT,
                0,
                "Register {} should have RC_INT",
                idx
            );
            assert_ne!(
                REG_CLASSES[idx] & RC_FLOAT,
                0,
                "Register {} should have RC_FLOAT",
                idx
            );
        }
    }

    #[test]
    fn test_register_classes_b_side() {
        // B-side registers (6, 7, 10, 11, 14, 15, 18, 19, 22, 23) have RC_INT | RC_FLOAT
        for &idx in &[6, 7, 10, 11, 14, 15, 18, 19, 22, 23] {
            assert_ne!(
                REG_CLASSES[idx] & RC_INT,
                0,
                "Register {} should have RC_INT",
                idx
            );
            assert_ne!(
                REG_CLASSES[idx] & RC_FLOAT,
                0,
                "Register {} should have RC_FLOAT",
                idx
            );
        }
    }

    // -----------------------------------------------------------------------
    // CodegenBackend trait method tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_trait_nb_regs() {
        let backend = C67Backend::new();
        assert_eq!(backend.nb_regs(), 24);
    }

    #[test]
    fn test_trait_ptr_size() {
        let backend = C67Backend::new();
        assert_eq!(backend.ptr_size(), 4);
    }

    #[test]
    fn test_trait_target_defs() {
        let backend = C67Backend::new();
        let defs = backend.target_machine_defs();
        assert!(defs.contains("__C67__"));
        assert!(defs.ends_with('\0'));
    }

    #[test]
    fn test_trait_reg_classes() {
        let backend = C67Backend::new();
        let classes = backend.reg_classes();
        assert_eq!(classes.len(), 24);
        // Verify it returns the same array as gen::REG_CLASSES
        for i in 0..NB_REGS {
            assert_eq!(classes[i], gen::REG_CLASSES[i]);
        }
    }

    #[test]
    fn test_trait_elf_machine() {
        let backend = C67Backend::new();
        assert_eq!(backend.elf_machine(), link::EM_TCC_TARGET);
    }

    #[test]
    fn test_trait_elf_start_addr() {
        let backend = C67Backend::new();
        assert_eq!(backend.elf_start_addr(), link::ELF_START_ADDR);
        assert_eq!(backend.elf_start_addr(), 0x0000_0400);
    }

    #[test]
    fn test_trait_elf_page_size() {
        let backend = C67Backend::new();
        assert_eq!(backend.elf_page_size(), link::ELF_PAGE_SIZE);
        assert_eq!(backend.elf_page_size(), 0x1000);
    }

    #[test]
    fn test_trait_pcrelative_dllplt() {
        let backend = C67Backend::new();
        assert!(!backend.pcrelative_dllplt());
    }

    #[test]
    fn test_trait_relocate_dllplt() {
        let backend = C67Backend::new();
        assert!(!backend.relocate_dllplt());
    }

    #[test]
    fn test_trait_vla_unsupported() {
        let mut backend = C67Backend::new();
        assert!(backend.gen_vla_sp_save(0).is_err());
        assert!(backend.gen_vla_sp_restore(0).is_err());
        let ct = CType::default();
        assert!(backend.gen_vla_alloc(&ct, 4).is_err());
    }

    #[test]
    fn test_trait_emit_opcode_unsupported() {
        let mut backend = C67Backend::new();
        let result = backend.emit_opcode(0x90);
        assert!(result.is_err());
    }

    #[test]
    fn test_trait_code_reloc_delegates_to_link() {
        let backend = C67Backend::new();
        // R_C60_32 = 1 is a data relocation -> returns 0
        assert_eq!(backend.code_reloc(1), 0);
        // R_C60_PLT32 = 4 is a code relocation -> returns 1
        assert_eq!(backend.code_reloc(4), 1);
        // Unknown relocation -> returns -1
        assert_eq!(backend.code_reloc(999), -1);
    }

    #[test]
    fn test_trait_gotplt_entry_type_delegates_to_link() {
        let backend = C67Backend::new();
        // R_C60_32 = 1 needs no GOT/PLT entry -> returns 0
        assert_eq!(backend.gotplt_entry_type(1), 0);
        // Unknown relocation -> returns -1
        assert_eq!(backend.gotplt_entry_type(999), -1);
    }

    #[test]
    fn test_trait_gfunc_sret() {
        let backend = C67Backend::new();
        let ct = CType::default();
        let (use_ptr, _sret_ty, regsize, align) = backend.gfunc_sret(&ct, false);
        // C67 never returns structs in registers
        assert!(!use_ptr);
        assert_eq!(regsize, 4);
        assert_eq!(align, 4);
    }

    #[test]
    fn test_trait_gfunc_sret_variadic() {
        let backend = C67Backend::new();
        let ct = CType::default();
        let (use_ptr, _, regsize, align) = backend.gfunc_sret(&ct, true);
        // Same behavior for variadic functions
        assert!(!use_ptr);
        assert_eq!(regsize, 4);
        assert_eq!(align, 4);
    }

    // -----------------------------------------------------------------------
    // Relocation tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_relocate_r_c60_32() {
        let mut backend = C67Backend::new();
        let mut buf = [0u8; 4];
        // R_C60_32 = 1, applies absolute 32-bit relocation
        let result = backend.relocate(1, &mut buf, 0, 0x12345678);
        assert!(result.is_ok());
    }
}
