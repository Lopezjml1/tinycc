//! x86_64 (AMD64) architecture backend
//!
//! Rust port of the x86-64 code generation, linking, and assembly
//! support from TCC. Sources: `x86_64-gen.c` (2,313 lines),
//! `x86_64-link.c` (410 lines), `x86_64-asm.h` (559 lines).
//!
//! This is the DEFAULT target architecture for the Rust TCC port
//! (Linux-first, x86_64 primary target).
//!
//! Feature flag: `x86_64`

// ---------------------------------------------------------------------------
// Submodule declarations
// ---------------------------------------------------------------------------

pub mod gen;
pub mod link;
pub mod tokens;

// ---------------------------------------------------------------------------
// Imports from sibling crate modules
// ---------------------------------------------------------------------------

use crate::arch::CodegenBackend;
use crate::error::TccResult;
use crate::types::{CType, SValue, Sym};

// ---------------------------------------------------------------------------
// Re-exports from gen module — register constants, helper functions, types
// These make all x86_64-specific constants available as `x86_64::CONSTANT`
// in addition to `x86_64::gen::CONSTANT`.
// ---------------------------------------------------------------------------

// Number of registers
pub use gen::NB_REGS;
pub use gen::NB_ASM_REGS;

// Register class bitmasks (from x86_64-gen.c lines 33-52)
// Sorted from general to precise per gv2() requirements
pub use gen::RC_RAX;
pub use gen::RC_RDX;
pub use gen::RC_RCX;
pub use gen::RC_RSI;
pub use gen::RC_RDI;
pub use gen::RC_ST0;
pub use gen::RC_R8;
pub use gen::RC_R9;
pub use gen::RC_R10;
pub use gen::RC_R11;
pub use gen::RC_XMM0;
pub use gen::RC_XMM1;
pub use gen::RC_XMM2;
pub use gen::RC_XMM3;
pub use gen::RC_XMM4;
pub use gen::RC_XMM5;
pub use gen::RC_XMM6;
pub use gen::RC_XMM7;

// Return register class aliases (from x86_64-gen.c lines 53-56)
pub use gen::RC_IRET;
pub use gen::RC_IRE2;
pub use gen::RC_FRET;
pub use gen::RC_FRE2;

// Register indices / "pretty names" (from x86_64-gen.c lines 59-84)
pub use gen::TREG_RAX;
pub use gen::TREG_RCX;
pub use gen::TREG_RDX;
pub use gen::TREG_RSP;
pub use gen::TREG_RSI;
pub use gen::TREG_RDI;
pub use gen::TREG_R8;
pub use gen::TREG_R9;
pub use gen::TREG_R10;
pub use gen::TREG_R11;
pub use gen::TREG_XMM0;
pub use gen::TREG_XMM1;
pub use gen::TREG_XMM2;
pub use gen::TREG_XMM3;
pub use gen::TREG_XMM4;
pub use gen::TREG_XMM5;
pub use gen::TREG_XMM6;
pub use gen::TREG_XMM7;
pub use gen::TREG_ST0;
pub use gen::TREG_MEM;

// Return register mappings (from x86_64-gen.c lines 89-93)
pub use gen::REG_IRET;
pub use gen::REG_IRE2;
pub use gen::REG_FRET;
pub use gen::REG_FRE2;

// Target configuration constants (from x86_64-gen.c lines 95-112)
pub use gen::PTR_SIZE;
pub use gen::LDOUBLE_SIZE;
pub use gen::LDOUBLE_ALIGN;
pub use gen::MAX_ALIGN;
pub use gen::FUNC_PROLOG_SIZE;

// Register class table (from x86_64-gen.c lines 128-157)
pub use gen::REG_CLASSES;

// REX prefix helpers (from x86_64-gen.c lines 86-87)
pub use gen::rex_base;
pub use gen::reg_value;

// Re-export generic register classes from parent arch module so callers
// can access them as `x86_64::RC_INT` / `x86_64::RC_FLOAT`.
pub use crate::arch::RC_INT;
pub use crate::arch::RC_FLOAT;

// ---------------------------------------------------------------------------
// Re-exports from link module — ELF linker constants and relocation aliases
// These mirror the TARGET_DEFS_ONLY section of x86_64-link.c lines 1-26.
// ---------------------------------------------------------------------------

pub use link::EM_TCC_TARGET;
pub use link::ELF_START_ADDR;
pub use link::ELF_PAGE_SIZE;
pub use link::PCRELATIVE_DLLPLT;
pub use link::RELOCATE_DLLPLT;
pub use link::R_DATA_32;
pub use link::R_DATA_PTR;
pub use link::R_JMP_SLOT;
pub use link::R_GLOB_DAT;
pub use link::R_COPY;
pub use link::R_RELATIVE;
pub use link::R_NUM;

// ---------------------------------------------------------------------------
// Target-specific constants defined in mod.rs
// These are NOT present in gen.rs or link.rs — they come from the
// TARGET_DEFS_ONLY section of x86_64-gen.c lines 95-115.
// ---------------------------------------------------------------------------

/// Function parameters evaluated in reverse order on stack.
/// Required for the System V AMD64 ABI where the first argument is pushed last.
///
/// From `x86_64-gen.c` line 96: `#define INVERT_FUNC_PARAMS`
pub const INVERT_FUNC_PARAMS: bool = true;

/// Return values promoted to full register width at caller side.
/// Required for interfacing with non-TCC compiled code (GCC, Clang).
/// The caller sign- or zero-extends narrow return values to 64 bits.
///
/// From `x86_64-gen.c` lines 107-109:
/// ```c
/// /* define if return values need to be extended at caller side (1) */
/// /*  - currentass. of small structs in regs needs that */
/// #define PROMOTE_RET
/// ```
pub const PROMOTE_RET: bool = true;

/// Native struct copy support — `gen_struct_copy()` is available.
/// When set, the codegen layer calls `gen_struct_copy()` for struct
/// assignments instead of falling back to a generic `memcpy` call.
///
/// From `x86_64-gen.c` line 111:
/// ```c
/// #define TCC_TARGET_NATIVE_STRUCT_COPY
/// ```
pub const TCC_TARGET_NATIVE_STRUCT_COPY: bool = true;

/// Assembler support is available for this architecture.
/// When true, inline assembly and standalone `.S` file compilation
/// are supported.
///
/// From `x86_64-gen.c` line 28: `#define CONFIG_TCC_ASM`
pub const CONFIG_TCC_ASM: bool = true;

/// Predefined macros for x86_64 target.
/// Injected into the preprocessor when targeting x86_64.
/// Null-separated list of macro names that the preprocessor should
/// define as `1` for programs compiled for this target.
///
/// From `x86_64-gen.c` lines 123-126:
/// ```c
/// ST_DATA const char *target_machine_defs =
///     "__x86_64__\0"
///     "__x86_64\0"
///     "__amd64__\0";
/// ```
pub const TARGET_MACHINE_DEFS: &str = "__x86_64__\0__x86_64\0__amd64__\0";

// ===========================================================================
// X86_64Backend — backend struct implementing CodegenBackend
// ===========================================================================

/// x86_64 (AMD64) code generation backend.
///
/// Implements the [`CodegenBackend`] trait for the x86-64 architecture.
/// Supports both System V AMD64 ABI (Linux, macOS, BSD) and Win64 ABI
/// (Windows PE targets).
///
/// This is the primary/default backend for the Rust TCC port
/// ("Linux-first target, x86_64 Linux is the primary target" — AAP §0.1.1).
///
/// # Architecture
///
/// The backend owns an [`gen::X86_64GenState`] instance that holds all mutable
/// code generation state (code buffer, function-level context, pending
/// relocations). The [`CodegenBackend`] trait methods delegate to
/// `gen_state` methods for code generation and to the `link` module for
/// linker operations.
///
/// # Register allocation
///
/// x86_64 has 25 allocatable registers ([`NB_REGS`]):
/// - 12 general-purpose integer registers: RAX, RCX, RDX, RSI, RDI, R8-R11
///   (RBX, RBP, RSP, R12-R15 are reserved/callee-saved)
/// - 8 SSE registers: XMM0-XMM7 (XMM8-XMM15 are callee-saved on Win64)
/// - 1 x87 FPU register: ST0 (for `long double` support)
///
/// See [`REG_CLASSES`] for the full register class table.
pub struct X86_64Backend {
    /// Code generation state — holds code buffer, function-level context,
    /// pending relocations, and all mutable codegen state.
    pub gen_state: gen::X86_64GenState,
}

impl X86_64Backend {
    /// Creates a new x86_64 backend instance with fresh code generation state.
    ///
    /// The code buffer starts empty with 4 KiB pre-allocated capacity.
    /// No function context is active after construction.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use tcc_core::arch::x86_64::X86_64Backend;
    ///
    /// let backend = X86_64Backend::new();
    /// assert_eq!(backend.gen_state.ind, 0);
    /// ```
    pub fn new() -> Self {
        Self {
            gen_state: gen::X86_64GenState::new(),
        }
    }
}

impl Default for X86_64Backend {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// CodegenBackend trait implementation
// ===========================================================================
//
// All methods delegate to either:
// - self.gen_state.method() — for code generation operations
// - link::function() — for linker operations
// - Constant returns — for target property queries
//
// This matches the C architecture where x86_64-gen.c functions access
// global state and x86_64-link.c functions are called with explicit params.
// ===========================================================================

impl CodegenBackend for X86_64Backend {
    // -----------------------------------------------------------------------
    // Target property queries — constant returns
    // -----------------------------------------------------------------------

    /// Returns the predefined macros for x86_64: `__x86_64__`, `__x86_64`,
    /// `__amd64__` as a null-separated string.
    fn target_machine_defs(&self) -> &'static str {
        TARGET_MACHINE_DEFS
    }

    /// Returns the register class table (25 entries, one per allocatable register).
    /// See [`REG_CLASSES`] for the full table with class bitmask documentation.
    fn reg_classes(&self) -> &[i32] {
        &REG_CLASSES
    }

    /// Returns the number of allocatable registers: 25 for x86_64.
    fn nb_regs(&self) -> usize {
        NB_REGS
    }

    /// Returns the pointer size: 8 bytes for x86_64.
    fn ptr_size(&self) -> usize {
        PTR_SIZE as usize
    }

    /// Returns the ELF machine type: `EM_X86_64` = 62.
    fn elf_machine(&self) -> u16 {
        link::EM_TCC_TARGET
    }

    /// Returns the default ELF entry point address: `0x400000`.
    fn elf_start_addr(&self) -> u64 {
        link::ELF_START_ADDR
    }

    /// Returns the ELF page size for segment alignment: `0x200000` (2 MiB).
    /// This large page size allows the kernel to use huge pages for the
    /// text segment on x86_64.
    fn elf_page_size(&self) -> u64 {
        link::ELF_PAGE_SIZE
    }

    /// Returns `true` — x86_64 uses PC-relative addressing in PLT entries.
    fn pcrelative_dllplt(&self) -> bool {
        link::PCRELATIVE_DLLPLT
    }

    /// Returns `true` — x86_64 requires DLL PLT entry relocation.
    fn relocate_dllplt(&self) -> bool {
        link::RELOCATE_DLLPLT
    }

    // -----------------------------------------------------------------------
    // Code generation — delegate to gen_state (X86_64GenState)
    // -----------------------------------------------------------------------

    /// Resolves a chain of forward references at code position `t` to target `a`.
    /// Walks the linked list of 32-bit displacements, patching each to jump
    /// to address `a`.
    fn gsym_addr(&mut self, t: i32, a: i32) -> TccResult<()> {
        self.gen_state.gsym_addr(t, a)
    }

    /// Resolves all forward references at `t` to the current code position.
    fn gsym(&mut self, t: i32) -> TccResult<()> {
        self.gen_state.gsym(t)
    }

    /// Loads a value described by `sv` into register `r`.
    /// Handles all addressing modes: VT_LVAL (memory), VT_CONST (immediate),
    /// VT_LOCAL (frame-relative), VT_CMP (condition code), VT_JMP/JMPI
    /// (conditional materialization), and register-to-register moves.
    fn load(&mut self, r: i32, sv: &SValue) -> TccResult<()> {
        self.gen_state.load(r, sv)
    }

    /// Stores register `r` to the memory location described by `sv`.
    /// Handles type-specific store instructions (movd for float, movq for
    /// double, fstpt for long double, mov/movb/movw for integers).
    fn store(&mut self, r: i32, sv: &SValue) -> TccResult<()> {
        self.gen_state.store(r, sv)
    }

    /// Determines the struct return convention for x86_64.
    ///
    /// Implements the System V AMD64 ABI struct classification:
    /// - Structs <= 16 bytes with INTEGER/SSE fields: returned in registers
    /// - Structs > 16 bytes or with x87 fields: returned via hidden pointer (SRet)
    ///
    /// On Win64 (pe_mode), structs > 8 bytes use SRet unconditionally.
    ///
    /// # Returns
    /// `(uses_sret, return_type, alignment, register_size)`
    fn gfunc_sret(&self, vt: &CType, variadic: bool) -> (bool, CType, i32, i32) {
        gen::gfunc_sret_x86_64(vt, variadic, self.gen_state.pe_mode)
    }

    /// Generates a function call with `nb_args` arguments on the stack/registers.
    /// Implements the System V AMD64 or Win64 calling convention depending
    /// on `pe_mode`.
    fn gfunc_call(&mut self, nb_args: i32) -> TccResult<()> {
        self.gen_state.gfunc_call(nb_args)
    }

    /// Generates a function prologue: push RBP, mov RSP→RBP, sub RSP for
    /// locals, save callee-saved registers, handle argument passing from
    /// registers to stack slots.
    fn gfunc_prolog(&mut self, func_sym: &Sym) -> TccResult<()> {
        self.gen_state.gfunc_prolog(func_sym)
    }

    /// Generates a function epilogue: restore callee-saved registers,
    /// restore RSP from RBP, pop RBP, ret. Patches the prologue's
    /// stack size placeholder with the actual local frame size.
    fn gfunc_epilog(&mut self) -> TccResult<()> {
        self.gen_state.gfunc_epilog()
    }

    /// Fills `n` bytes with NOP instructions (0x90).
    /// Used for function alignment padding.
    fn gen_fill_nops(&mut self, n: i32) -> TccResult<()> {
        self.gen_state.gen_fill_nops(n)
    }

    /// Generates an unconditional jump. Returns the offset of the
    /// displacement for forward reference patching. The `t` parameter
    /// forms a linked list of forward references.
    fn gjmp(&mut self, t: i32) -> TccResult<i32> {
        self.gen_state.gjmp(t)
    }

    /// Generates an unconditional jump to absolute address `a`.
    fn gjmp_addr(&mut self, a: i32) -> TccResult<()> {
        self.gen_state.gjmp_addr(a)
    }

    /// Generates a conditional jump based on comparison operator `op`.
    /// Returns the updated forward reference chain.
    fn gjmp_cond(&mut self, op: i32, t: i32) -> TccResult<i32> {
        self.gen_state.gjmp_cond(op, t)
    }

    /// Appends a forward reference at position `n` into the chain `t`.
    /// Returns the new chain head.
    fn gjmp_append(&mut self, n: i32, t: i32) -> TccResult<i32> {
        self.gen_state.gjmp_append(n, t)
    }

    /// Generates an integer ALU operation (add, sub, mul, div, mod,
    /// shift, and, or, xor, comparison) on the top two values of the
    /// value stack.
    fn gen_opi(&mut self, op: i32) -> TccResult<()> {
        self.gen_state.gen_opi(op)
    }

    /// Generates a floating-point operation (add, sub, mul, div,
    /// comparison) on the top two values of the value stack.
    /// Handles float, double, and long double via SSE2 and x87.
    fn gen_opf(&mut self, op: i32) -> TccResult<()> {
        self.gen_state.gen_opf(op)
    }

    /// Converts a floating-point value to an integer type.
    /// Uses `cvttsd2si` / `cvttss2si` for SSE, or `fistp` for x87.
    fn gen_cvt_ftoi(&mut self, t: i32) -> TccResult<()> {
        self.gen_state.gen_cvt_ftoi(t)
    }

    /// Converts an integer value to a floating-point type.
    /// Uses `cvtsi2sd` / `cvtsi2ss` for SSE, or `fild` for x87.
    fn gen_cvt_itof(&mut self, t: i32) -> TccResult<()> {
        self.gen_state.gen_cvt_itof(t)
    }

    /// Converts between floating-point types (float ↔ double ↔ long double).
    /// Handles SSE ↔ SSE (`cvtsd2ss` / `cvtss2sd`) and SSE ↔ x87 transfers.
    fn gen_cvt_ftof(&mut self, t: i32) -> TccResult<()> {
        self.gen_state.gen_cvt_ftof(t)
    }

    /// Generates an indirect jump (computed goto) through the value on
    /// the top of the value stack.
    fn ggoto(&mut self) -> TccResult<()> {
        self.gen_state.ggoto()
    }

    /// Emits a multi-byte opcode in little-endian order.
    /// Bytes are emitted from LSB to MSB until all significant bytes
    /// have been written. Delegates to `X86_64GenState::o()`.
    fn emit_opcode(&mut self, c: u32) -> TccResult<()> {
        self.gen_state.o(c)
    }

    /// Saves the current stack pointer to a VLA tracking slot at frame
    /// offset `addr`. Used before VLA allocation to enable later restore.
    fn gen_vla_sp_save(&mut self, addr: i32) -> TccResult<()> {
        self.gen_state.gen_vla_sp_save(addr)
    }

    /// Restores the stack pointer from a VLA tracking slot at frame
    /// offset `addr`. Used when leaving a VLA scope to reclaim stack.
    fn gen_vla_sp_restore(&mut self, addr: i32) -> TccResult<()> {
        self.gen_state.gen_vla_sp_restore(addr)
    }

    /// Adjusts the stack pointer to allocate space for a VLA.
    /// Subtracts the computed size from RSP and aligns to `align`.
    fn gen_vla_alloc(&mut self, typ: &CType, align: i32) -> TccResult<()> {
        self.gen_state.gen_vla_alloc(typ, align)
    }

    /// Emits a single byte to the code section.
    /// If `nocode_wanted` is non-zero, the byte is suppressed.
    fn g(&mut self, c: i32) -> TccResult<()> {
        self.gen_state.g(c)
    }

    /// Emits a 16-bit little-endian value to the code section.
    fn gen_le16(&mut self, c: i32) -> TccResult<()> {
        self.gen_state.gen_le16(c)
    }

    /// Emits a 32-bit little-endian value to the code section.
    fn gen_le32(&mut self, c: i32) -> TccResult<()> {
        self.gen_state.gen_le32(c)
    }

    /// Generates test coverage counter instrumentation.
    /// Emits code to increment a 64-bit counter at the location described
    /// by `sv` using `lock addq [mem], 1`.
    fn gen_increment_tcov(&mut self, sv: &SValue) -> TccResult<()> {
        self.gen_state.gen_increment_tcov(sv)
    }

    // -----------------------------------------------------------------------
    // Linker operations — delegate to link module functions
    // -----------------------------------------------------------------------

    /// Classifies a relocation type as code (1), data (0), or unknown (-1).
    fn code_reloc(&self, reloc_type: i32) -> i32 {
        link::code_reloc(reloc_type)
    }

    /// Determines what kind of GOT/PLT entry is needed for a relocation type.
    /// Returns `NO_GOTPLT_ENTRY`, `BUILD_GOT_ONLY`, `AUTO_GOTPLT_ENTRY`,
    /// or `ALWAYS_GOTPLT_ENTRY`.
    fn gotplt_entry_type(&self, reloc_type: i32) -> i32 {
        link::gotplt_entry_type(reloc_type)
    }

    /// Applies a relocation to a code/data buffer.
    /// Handles all x86_64 ELF relocation types: R_X86_64_64, R_X86_64_32,
    /// R_X86_64_32S, R_X86_64_PC32, R_X86_64_PLT32, R_X86_64_GOTPCREL, etc.
    fn relocate(&mut self, rel_type: i32, ptr: &mut [u8], addr: u64, val: u64) -> TccResult<()> {
        link::relocate(rel_type, ptr, addr, val)
    }
}

// ===========================================================================
// x86_64-specific methods — not part of the generic CodegenBackend trait
// ===========================================================================

impl X86_64Backend {
    /// Sign-extends a 32-bit value to 64-bit (`movslq` / `cdqe`).
    ///
    /// Used when a 32-bit computation result needs to be used as a 64-bit
    /// value (e.g., array indexing with a signed 32-bit index).
    ///
    /// From `x86_64-gen.c` lines 2191-2198.
    pub fn gen_cvt_sxtw(&mut self) -> TccResult<()> {
        self.gen_state.gen_cvt_sxtw()
    }

    /// Converts a char or short value to int with proper sign/zero extension.
    ///
    /// Emits `movsx` or `movzx` depending on the signedness of the source type.
    /// The `t` parameter carries the source type flags.
    ///
    /// From `x86_64-gen.c` lines 2200-2212.
    pub fn gen_cvt_csti(&mut self, t: i32) -> TccResult<()> {
        self.gen_state.gen_cvt_csti(t)
    }

    /// Copies a struct using `rep movsq` / `rep movsb`.
    ///
    /// Generates inline code to copy `size` bytes from RSI to RDI using
    /// REP MOVSQ for the bulk (8-byte chunks) followed by REP MOVSB for
    /// the remainder. This is the native struct copy that is enabled by
    /// [`TCC_TARGET_NATIVE_STRUCT_COPY`].
    ///
    /// From `x86_64-gen.c` lines 2281-2313.
    pub fn gen_struct_copy(&mut self, size: i32) -> TccResult<()> {
        self.gen_state.gen_struct_copy(size)
    }

    /// Saves the VLA allocation result (PE/Win64 only).
    ///
    /// On Windows, VLA allocation goes through `__chkstk` which returns the
    /// new stack pointer in RAX. This method saves it to the frame slot at
    /// `addr`.
    ///
    /// From `x86_64-gen.c` lines 2242-2248.
    pub fn gen_vla_result(&mut self, addr: i32) -> TccResult<()> {
        self.gen_state.gen_vla_result(addr)
    }
}

// ===========================================================================
// Unit tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Construction tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_x86_64_backend_new() {
        let backend = X86_64Backend::new();
        assert_eq!(backend.gen_state.ind, 0);
        assert_eq!(backend.gen_state.nocode_wanted, 0);
        assert_eq!(backend.gen_state.loc, 0);
    }

    #[test]
    fn test_x86_64_backend_default() {
        let backend = X86_64Backend::default();
        assert_eq!(backend.gen_state.ind, 0);
    }

    // -----------------------------------------------------------------------
    // Target property query tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_target_machine_defs() {
        let backend = X86_64Backend::new();
        let defs = backend.target_machine_defs();
        assert!(defs.contains("__x86_64__"));
        assert!(defs.contains("__x86_64"));
        assert!(defs.contains("__amd64__"));
    }

    #[test]
    fn test_nb_regs() {
        let backend = X86_64Backend::new();
        assert_eq!(backend.nb_regs(), 25);
    }

    #[test]
    fn test_ptr_size() {
        let backend = X86_64Backend::new();
        assert_eq!(backend.ptr_size(), 8);
    }

    #[test]
    fn test_reg_classes_length() {
        let backend = X86_64Backend::new();
        assert_eq!(backend.reg_classes().len(), 25);
    }

    #[test]
    fn test_reg_classes_rax() {
        let backend = X86_64Backend::new();
        let classes = backend.reg_classes();
        // RAX (index 0) should have RC_INT | RC_RAX
        assert_ne!(classes[TREG_RAX as usize] & RC_INT, 0);
        assert_ne!(classes[TREG_RAX as usize] & RC_RAX, 0);
    }

    #[test]
    fn test_reg_classes_xmm0() {
        let backend = X86_64Backend::new();
        let classes = backend.reg_classes();
        // XMM0 (index 16) should have RC_FLOAT | RC_XMM0
        assert_ne!(classes[TREG_XMM0 as usize] & RC_FLOAT, 0);
        assert_ne!(classes[TREG_XMM0 as usize] & RC_XMM0, 0);
    }

    #[test]
    fn test_reg_classes_callee_saved_not_allocatable() {
        let backend = X86_64Backend::new();
        let classes = backend.reg_classes();
        // RBX (3), RSP (4), RBP (5), R12-R15 (12-15) should be 0
        assert_eq!(classes[3], 0, "RBX should not be allocatable");
        assert_eq!(classes[4], 0, "RSP should not be allocatable");
        assert_eq!(classes[5], 0, "RBP should not be allocatable");
        assert_eq!(classes[12], 0, "R12 should not be allocatable");
        assert_eq!(classes[13], 0, "R13 should not be allocatable");
        assert_eq!(classes[14], 0, "R14 should not be allocatable");
        assert_eq!(classes[15], 0, "R15 should not be allocatable");
    }

    #[test]
    fn test_reg_classes_st0() {
        let backend = X86_64Backend::new();
        let classes = backend.reg_classes();
        // ST0 (index 24) should have RC_ST0
        assert_ne!(classes[TREG_ST0 as usize] & RC_ST0, 0);
    }

    // -----------------------------------------------------------------------
    // ELF constant tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_elf_machine() {
        let backend = X86_64Backend::new();
        assert_eq!(backend.elf_machine(), 62, "EM_X86_64 = 62");
    }

    #[test]
    fn test_elf_start_addr() {
        let backend = X86_64Backend::new();
        assert_eq!(backend.elf_start_addr(), 0x400000);
    }

    #[test]
    fn test_elf_page_size() {
        let backend = X86_64Backend::new();
        assert_eq!(backend.elf_page_size(), 0x200000, "x86_64 uses 2 MiB pages");
    }

    #[test]
    fn test_pcrelative_dllplt() {
        let backend = X86_64Backend::new();
        assert!(backend.pcrelative_dllplt());
    }

    #[test]
    fn test_relocate_dllplt() {
        let backend = X86_64Backend::new();
        assert!(backend.relocate_dllplt());
    }

    // -----------------------------------------------------------------------
    // Constant value tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_register_constants() {
        // Verify register index values match x86_64 encoding
        assert_eq!(TREG_RAX, 0);
        assert_eq!(TREG_RCX, 1);
        assert_eq!(TREG_RDX, 2);
        assert_eq!(TREG_RSP, 4);
        assert_eq!(TREG_RSI, 6);
        assert_eq!(TREG_RDI, 7);
        assert_eq!(TREG_R8, 8);
        assert_eq!(TREG_R9, 9);
        assert_eq!(TREG_R10, 10);
        assert_eq!(TREG_R11, 11);
        assert_eq!(TREG_XMM0, 16);
        assert_eq!(TREG_XMM7, 23);
        assert_eq!(TREG_ST0, 24);
        assert_eq!(TREG_MEM, 0x20);
    }

    #[test]
    fn test_return_register_aliases() {
        assert_eq!(RC_IRET, RC_RAX);
        assert_eq!(RC_IRE2, RC_RDX);
        assert_eq!(RC_FRET, RC_XMM0);
        assert_eq!(RC_FRE2, RC_XMM1);
        assert_eq!(REG_IRET, TREG_RAX);
        assert_eq!(REG_IRE2, TREG_RDX);
        assert_eq!(REG_FRET, TREG_XMM0);
        assert_eq!(REG_FRE2, TREG_XMM1);
    }

    #[test]
    fn test_target_config_constants() {
        assert!(INVERT_FUNC_PARAMS);
        assert_eq!(PTR_SIZE, 8);
        assert_eq!(LDOUBLE_SIZE, 16);
        assert_eq!(LDOUBLE_ALIGN, 16);
        assert_eq!(MAX_ALIGN, 16);
        assert!(PROMOTE_RET);
        assert!(TCC_TARGET_NATIVE_STRUCT_COPY);
        assert!(CONFIG_TCC_ASM);
        assert_eq!(FUNC_PROLOG_SIZE, 11);
    }

    #[test]
    fn test_elf_link_constants() {
        assert_eq!(EM_TCC_TARGET, 62);
        assert_eq!(ELF_START_ADDR, 0x400000);
        assert_eq!(ELF_PAGE_SIZE, 0x200000);
        assert!(PCRELATIVE_DLLPLT);
        assert!(RELOCATE_DLLPLT);
    }

    #[test]
    fn test_rc_bitmask_uniqueness() {
        // Each register class should have a unique bit
        let rc_values = [
            RC_RAX, RC_RDX, RC_RCX, RC_RSI, RC_RDI, RC_ST0,
            RC_R8, RC_R9, RC_R10, RC_R11,
            RC_XMM0, RC_XMM1, RC_XMM2, RC_XMM3,
            RC_XMM4, RC_XMM5, RC_XMM6, RC_XMM7,
        ];
        for (i, &a) in rc_values.iter().enumerate() {
            for (j, &b) in rc_values.iter().enumerate() {
                if i != j {
                    assert_eq!(a & b, 0, "RC bitmasks at indices {i} and {j} overlap");
                }
            }
        }
    }

    #[test]
    fn test_nb_regs_constant() {
        assert_eq!(NB_REGS, 25);
        assert_eq!(NB_ASM_REGS, 16);
    }

    // -----------------------------------------------------------------------
    // REX prefix helper tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_rex_base() {
        // Low registers (0-7): REX.B = 0
        assert_eq!(rex_base(0), 0); // RAX
        assert_eq!(rex_base(7), 0); // RDI
        // High registers (8-15): REX.B = 1
        assert_eq!(rex_base(8), 1);  // R8
        assert_eq!(rex_base(15), 1); // R15
        // XMM registers (16-23): also uses bit 3
        assert_eq!(rex_base(16), 0); // XMM0 — bit 3 = 0
        assert_eq!(rex_base(24), 1); // ST0 — bit 3 = 1
    }

    #[test]
    fn test_reg_value() {
        // Should extract lower 3 bits
        assert_eq!(reg_value(0), 0); // RAX
        assert_eq!(reg_value(1), 1); // RCX
        assert_eq!(reg_value(7), 7); // RDI
        assert_eq!(reg_value(8), 0); // R8 — same encoding as RAX with REX.B
        assert_eq!(reg_value(15), 7); // R15
    }

    // -----------------------------------------------------------------------
    // Code generation delegation tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_gsym_addr_delegation() {
        let mut backend = X86_64Backend::new();
        // Empty chain (t=0) should be a no-op
        assert!(backend.gsym_addr(0, 0).is_ok());
    }

    #[test]
    fn test_gsym_delegation() {
        let mut backend = X86_64Backend::new();
        // Empty chain (t=0) should be a no-op
        assert!(backend.gsym(0).is_ok());
    }

    #[test]
    fn test_g_byte_emission() {
        let mut backend = X86_64Backend::new();
        assert!(backend.g(0x90).is_ok()); // NOP
        assert_eq!(backend.gen_state.ind, 1);
        assert_eq!(backend.gen_state.code[0], 0x90);
    }

    #[test]
    fn test_gen_le16_emission() {
        let mut backend = X86_64Backend::new();
        assert!(backend.gen_le16(0x1234).is_ok());
        assert_eq!(backend.gen_state.ind, 2);
        assert_eq!(backend.gen_state.code[0], 0x34);
        assert_eq!(backend.gen_state.code[1], 0x12);
    }

    #[test]
    fn test_gen_le32_emission() {
        let mut backend = X86_64Backend::new();
        assert!(backend.gen_le32(0x12345678).is_ok());
        assert_eq!(backend.gen_state.ind, 4);
        assert_eq!(backend.gen_state.code[0], 0x78);
        assert_eq!(backend.gen_state.code[1], 0x56);
        assert_eq!(backend.gen_state.code[2], 0x34);
        assert_eq!(backend.gen_state.code[3], 0x12);
    }

    #[test]
    fn test_emit_opcode_delegation() {
        let mut backend = X86_64Backend::new();
        // Emit a 2-byte opcode (e.g., 0F 90 = seto)
        assert!(backend.emit_opcode(0x900f).is_ok());
        assert_eq!(backend.gen_state.ind, 2);
        // Bytes emitted in LE order: 0x0f first, then 0x90
        assert_eq!(backend.gen_state.code[0], 0x0f);
        assert_eq!(backend.gen_state.code[1], 0x90);
    }

    #[test]
    fn test_gen_fill_nops_delegation() {
        let mut backend = X86_64Backend::new();
        assert!(backend.gen_fill_nops(4).is_ok());
        assert_eq!(backend.gen_state.ind, 4);
        for i in 0..4 {
            assert_eq!(backend.gen_state.code[i], 0x90, "byte {i} should be NOP");
        }
    }

    #[test]
    fn test_gjmp_delegation() {
        let mut backend = X86_64Backend::new();
        let result = backend.gjmp(0);
        assert!(result.is_ok());
    }

    #[test]
    fn test_nocode_wanted_suppresses_emission() {
        let mut backend = X86_64Backend::new();
        backend.gen_state.nocode_wanted = 1;
        assert!(backend.g(0x90).is_ok());
        assert_eq!(backend.gen_state.ind, 0, "no byte should be emitted");
        assert!(backend.gen_state.code.is_empty());
    }

    // -----------------------------------------------------------------------
    // Linker delegation tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_code_reloc_delegation() {
        let backend = X86_64Backend::new();
        // R_X86_64_PC32 (=2) is a code relocation
        assert_eq!(backend.code_reloc(2), 1);
        // R_X86_64_64 (=1) is a data relocation
        assert_eq!(backend.code_reloc(1), 0);
        // Unknown type returns -1
        assert_eq!(backend.code_reloc(9999), -1);
    }

    #[test]
    fn test_gotplt_entry_type_delegation() {
        let backend = X86_64Backend::new();
        // R_X86_64_GLOB_DAT (=6) needs no GOT/PLT
        assert_eq!(backend.gotplt_entry_type(6), 0);
        // R_X86_64_32 (=10) is AUTO
        assert_eq!(backend.gotplt_entry_type(10), 2);
    }

    #[test]
    fn test_relocate_none() {
        let mut backend = X86_64Backend::new();
        let mut buf = [0u8; 8];
        // R_X86_64_NONE (=0) should be a no-op
        assert!(backend.relocate(0, &mut buf, 0, 0).is_ok());
        assert_eq!(buf, [0u8; 8]);
    }

    // -----------------------------------------------------------------------
    // gfunc_sret delegation test
    // -----------------------------------------------------------------------

    #[test]
    fn test_gfunc_sret_non_struct() {
        let backend = X86_64Backend::new();
        let int_type = CType { t: 0, ref_sym: None }; // VT_VOID/int-like
        let (sret, _ret_type, _align, _size) = backend.gfunc_sret(&int_type, false);
        assert!(!sret, "non-struct types should not use SRet");
    }

    // -----------------------------------------------------------------------
    // x86_64-specific method tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_gen_cvt_sxtw() {
        let mut backend = X86_64Backend::new();
        let result = backend.gen_cvt_sxtw();
        assert!(result.is_ok());
    }

    #[test]
    fn test_gen_cvt_csti() {
        let mut backend = X86_64Backend::new();
        let result = backend.gen_cvt_csti(0);
        assert!(result.is_ok());
    }

    #[test]
    fn test_gen_struct_copy() {
        let mut backend = X86_64Backend::new();
        let result = backend.gen_struct_copy(16);
        assert!(result.is_ok());
    }

    #[test]
    fn test_gen_vla_result() {
        let mut backend = X86_64Backend::new();
        let result = backend.gen_vla_result(-8);
        assert!(result.is_ok());
    }
}
