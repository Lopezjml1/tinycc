//! i386 (x86 32-bit) code generation backend.
//!
//! This module implements the [`CodegenBackend`] trait for the Intel i386 (IA-32)
//! architecture. It serves as the module root for the i386 backend, declaring
//! submodules and providing the main backend struct with all i386-specific
//! constants, register definitions, and trait implementation that delegates to
//! functions in `gen.rs`, `link.rs`, `asm.rs`, and `tokens.rs`.
//!
//! # Source Files
//!
//! Port of:
//! - `i386-gen.c` (1,306 lines) — code generation, register allocation, calling conventions
//! - `i386-link.c` (329 lines) — relocation types, PLT/GOT generation, symbol binding
//! - `i386-asm.c` (1,757 lines) — x86 instruction encoding, operand parsing
//! - `i386-tok.h` (332 lines) + `i386-asm.h` (490 lines) — register/instruction definitions
//!
//! Total: ~4,214 lines of C → Rust.
//!
//! # Feature Gate
//!
//! This module is only compiled when the `i386` Cargo feature is enabled.
//! The parent `arch/mod.rs` gates inclusion with `#[cfg(feature = "i386")]`.
//!
//! # Bug Fixes
//!
//! - **BUG-01**: i386 fastcall calling convention correctly implements Microsoft
//!   `__fastcall` (ECX, EDX for first two integer/pointer args, rest on stack).
//! - **BUG-02**: FPU stack depth tracking via [`I386Backend::fpu_stack_depth`] ensures
//!   the x87 FPU stack is clean before function returns and external calls.

// ---------------------------------------------------------------------------
// Submodule declarations
// ---------------------------------------------------------------------------

/// i386 code generation — instruction emission, register allocation, calling
/// conventions, expression-to-machine-code translation.
/// Port of `i386-gen.c` (1,306 lines).
pub mod gen;

/// i386 relocation and linking — relocation type classification, PLT/GOT
/// generation, relocation application.
/// Port of `i386-link.c` (329 lines).
pub mod link;

/// i386 assembly encoding — x86 instruction encoding, operand parsing,
/// opcode tables for inline and standalone assembler.
/// Port of `i386-asm.c` (1,757 lines).
pub mod asm;

/// x86 register names and instruction mnemonics — register name tokens,
/// assembly instruction mnemonic tokens, opcode lookup tables.
/// Port of `i386-tok.h` (332 lines) + `i386-asm.h` (490 lines).
pub mod tokens;

// ---------------------------------------------------------------------------
// Imports from within tcc-core (verified against depends_on_files whitelist)
// ---------------------------------------------------------------------------

use crate::arch::CodegenBackend;
use crate::error::TccResult;
use crate::types::{CType, SValue, Sym};

// ===========================================================================
// Register and Architecture Constants
// Source: i386-gen.c lines 22-85 (TARGET_DEFS_ONLY section)
// ===========================================================================

// --- Number of registers ---

/// Number of available registers for the register allocator.
///
/// The i386 backend uses 5 registers:
/// - 4 general-purpose integer: EAX (0), ECX (1), EDX (2), EBX (3)
/// - 1 floating-point: ST0 (4) — top of x87 FPU stack
///
/// Note: EBX (index 3) may be unavailable depending on USE_EBX configuration.
/// ESP and EBP are reserved for stack/frame pointer and are never allocatable.
///
/// Source: `i386-gen.c` line 24 — `#define NB_REGS 5`
pub const NB_REGS: usize = 5;

/// Number of assembly registers (full x86 register set for inline asm).
///
/// Includes all 8 general-purpose registers: EAX, ECX, EDX, EBX, ESP, EBP,
/// ESI, EDI. Used by the inline assembler for register constraint resolution.
///
/// Source: `i386-gen.c` line 25 — `#define NB_ASM_REGS 8`
pub const NB_ASM_REGS: usize = 8;

// --- Register class bitmasks ---
// These form a hierarchy from general to specific (required by gv2()).
// More specific classes have higher bit values.

/// Generic integer register class.
///
/// Any register that can hold an integer value. Used by the register allocator
/// when any integer register will suffice.
///
/// Source: `i386-gen.c` line 31 — `#define RC_INT 0x0001`
pub const RC_INT: i32 = 0x0001;

/// Generic floating-point register class.
///
/// On i386, this maps to the x87 FPU stack (specifically ST0).
///
/// Source: `i386-gen.c` line 32 — `#define RC_FLOAT 0x0002`
pub const RC_FLOAT: i32 = 0x0002;

/// EAX register class.
///
/// Source: `i386-gen.c` line 33 — `#define RC_EAX 0x0004`
pub const RC_EAX: i32 = 0x0004;

/// EDX register class.
///
/// Source: `i386-gen.c` line 34 — `#define RC_EDX 0x0008`
pub const RC_EDX: i32 = 0x0008;

/// ECX register class.
///
/// Source: `i386-gen.c` line 35 — `#define RC_ECX 0x0010`
pub const RC_ECX: i32 = 0x0010;

/// EBX register class.
///
/// Source: `i386-gen.c` line 36 — `#define RC_EBX 0x0020`
pub const RC_EBX: i32 = 0x0020;

/// x87 FPU stack top (ST0) register class.
///
/// Source: `i386-gen.c` line 37 — `#define RC_ST0 0x0040`
pub const RC_ST0: i32 = 0x0040;

// --- Return register class aliases ---

/// Function return: integer register class (EAX).
///
/// Source: `i386-gen.c` line 39 — `#define RC_IRET RC_EAX`
pub const RC_IRET: i32 = RC_EAX;

/// Function return: second integer register class (EDX, for 64-bit returns).
///
/// When returning `long long`, the low 32 bits are in EAX and the high 32
/// bits are in EDX.
///
/// Source: `i386-gen.c` line 40 — `#define RC_IRE2 RC_EDX`
pub const RC_IRE2: i32 = RC_EDX;

/// Function return: floating-point register class (ST0).
///
/// Source: `i386-gen.c` line 41 — `#define RC_FRET RC_ST0`
pub const RC_FRET: i32 = RC_ST0;

// --- Register enumeration ---
// The register numbering matches x86 encoding (low 3 bits = ModR/M encoding).

/// Register index for EAX (accumulator). x86 encoding: 000.
///
/// Source: `i386-gen.c` line 43 — `TREG_EAX = 0`
pub const TREG_EAX: i32 = 0;

/// Register index for ECX (counter). x86 encoding: 001.
///
/// Source: `i386-gen.c` line 44 — `TREG_ECX = 1`
pub const TREG_ECX: i32 = 1;

/// Register index for EDX (data). x86 encoding: 010.
///
/// Source: `i386-gen.c` line 45 — `TREG_EDX = 2`
pub const TREG_EDX: i32 = 2;

/// Register index for EBX (base). x86 encoding: 011.
///
/// May be reserved for GOT pointer in PIC mode.
///
/// Source: `i386-gen.c` line 46 — `TREG_EBX = 3`
pub const TREG_EBX: i32 = 3;

/// Register index for ST0 (x87 FPU stack top).
///
/// Note: This index (4) is also used as `TREG_ESP` in different contexts
/// (the inline assembler uses the full 8-register numbering).
///
/// Source: `i386-gen.c` line 47 — `TREG_ST0 = 4`
pub const TREG_ST0: i32 = 4;

/// Register alias for ESP in the assembler context.
///
/// In the register allocator, index 4 is ST0. In the assembler's full
/// 8-register view, index 4 maps to ESP. These never conflict because
/// the allocator and assembler use separate numbering contexts.
///
/// Source: `i386-gen.c` line 48 — `TREG_ESP = 4`
pub const TREG_ESP: i32 = 4;

/// Marker for a memory operand (not a physical register).
///
/// Used in the code generator to indicate that a value is accessed via
/// memory rather than residing in a register. The high bit distinguishes
/// it from physical register numbers.
///
/// Source: `i386-gen.c` line 50 — `#define TREG_MEM 0x20`
pub const TREG_MEM: i32 = 0x20;

/// Extracts the low 3 bits of a register value for x86 instruction encoding.
///
/// On i386, the low 3 bits of a register number directly correspond to the
/// register field in ModR/M and SIB bytes.
///
/// Source: `i386-gen.c` line 54 — `#define REG_VALUE(reg) ((reg) & 7)`
///
/// # Examples
///
/// ```ignore
/// assert_eq!(reg_value(TREG_EAX), 0); // EAX encoding = 000
/// assert_eq!(reg_value(TREG_ECX), 1); // ECX encoding = 001
/// assert_eq!(reg_value(TREG_EDX), 2); // EDX encoding = 010
/// assert_eq!(reg_value(TREG_EBX), 3); // EBX encoding = 011
/// ```
#[inline]
pub const fn reg_value(reg: i32) -> i32 {
    reg & 7
}

// --- Return register aliases ---

/// Function return: integer result register (EAX).
///
/// Source: `i386-gen.c` line 57 — `#define REG_IRET TREG_EAX`
pub const REG_IRET: i32 = TREG_EAX;

/// Function return: second word of 64-bit result (EDX).
///
/// Source: `i386-gen.c` line 58 — `#define REG_IRE2 TREG_EDX`
pub const REG_IRE2: i32 = TREG_EDX;

/// Function return: floating-point result register (ST0).
///
/// Source: `i386-gen.c` line 59 — `#define REG_FRET TREG_ST0`
pub const REG_FRET: i32 = TREG_ST0;

// --- Architecture characteristics ---

/// Function parameters are evaluated right-to-left (x86 cdecl/stdcall convention).
///
/// The C calling conventions on x86 push arguments onto the stack from right
/// to left. TCC's code generator uses this flag to determine argument
/// evaluation order.
///
/// Source: `i386-gen.c` line 64 — `#define INVERT_FUNC_PARAMS`
pub const INVERT_FUNC_PARAMS: bool = true;

/// Pointer size in bytes (4 for 32-bit i386).
///
/// Source: `i386-gen.c` line 71 — `#define PTR_SIZE 4`
pub const PTR_SIZE: usize = 4;

/// Long double size in bytes.
///
/// On i386, `long double` is 80-bit extended precision stored in 12 bytes
/// (10 bytes of data + 2 bytes padding for alignment).
///
/// Source: `i386-gen.c` line 74 — `#define LDOUBLE_SIZE 12`
pub const LDOUBLE_SIZE: usize = 12;

/// Long double alignment in bytes.
///
/// Source: `i386-gen.c` line 75 — `#define LDOUBLE_ALIGN 4`
pub const LDOUBLE_ALIGN: usize = 4;

/// Maximum alignment for any type in bytes.
///
/// On i386, the maximum useful alignment is 8 bytes (for `double` and
/// `long long`).
///
/// Source: `i386-gen.c` line 77 — `#define MAX_ALIGN 8`
pub const MAX_ALIGN: usize = 8;

/// Return values are zero/sign-extended to full register width.
///
/// When returning `char` or `short`, the value is extended to fill the full
/// 32-bit EAX register. This matches the behavior expected by callers.
///
/// Source: `i386-gen.c` line 81 — `#define PROMOTE_RET`
pub const PROMOTE_RET: bool = true;

// ===========================================================================
// ELF/Linker Constants
// Source: i386-link.c lines 3-24 (TARGET_DEFS_ONLY section)
// ===========================================================================

/// ELF machine type for i386 (`EM_386 = 3`).
///
/// Written into the ELF header's `e_machine` field to identify the target
/// architecture of the generated object/executable.
///
/// Source: `i386-link.c` line 3 — `#define EM_TCC_TARGET EM_386`
pub const EM_TCC_TARGET: u16 = 3;

/// Default executable load address for i386 ELF binaries.
///
/// This is the traditional Linux default for i386 executables.
///
/// Source: `i386-link.c` line 17 — `#define ELF_START_ADDR 0x08048000`
pub const ELF_START_ADDR: u64 = 0x08048000;

/// Default ELF page size (4 KiB).
///
/// Used for segment alignment in the output ELF file.
///
/// Source: `i386-link.c` line 18 — `#define ELF_PAGE_SIZE 0x1000`
pub const ELF_PAGE_SIZE: u64 = 0x1000;

// --- Relocation type aliases ---
// Map architecture-neutral names to i386-specific ELF relocation constants.

/// Absolute 32-bit data relocation (`R_386_32 = 1`).
///
/// Source: `i386-link.c` line 5 — `#define R_DATA_32 R_386_32`
pub const R_DATA_32: i32 = 1;

/// Pointer-sized data relocation (same as `R_DATA_32` on 32-bit).
///
/// Source: `i386-link.c` line 6 — `#define R_DATA_PTR R_386_32`
pub const R_DATA_PTR: i32 = 1;

/// PLT jump slot relocation (`R_386_JMP_SLOT = 7`).
///
/// Source: `i386-link.c` line 7 — `#define R_JMP_SLOT R_386_JMP_SLOT`
pub const R_JMP_SLOT: i32 = 7;

/// GOT global data relocation (`R_386_GLOB_DAT = 6`).
///
/// Source: `i386-link.c` line 8 — `#define R_GLOB_DAT R_386_GLOB_DAT`
pub const R_GLOB_DAT: i32 = 6;

/// Copy relocation for dynamic linking (`R_386_COPY = 5`).
///
/// Source: `i386-link.c` line 9 — `#define R_COPY R_386_COPY`
pub const R_COPY: i32 = 5;

/// Relative relocation (`R_386_RELATIVE = 8`).
///
/// Source: `i386-link.c` line 10 — `#define R_RELATIVE R_386_RELATIVE`
pub const R_RELATIVE: i32 = 8;

/// Whether PLT entries use PC-relative addressing in DLLs.
///
/// On i386, PLT entries use absolute addressing by default (non-PIC mode).
/// PIC mode would require PC-relative PLT, but the `pic` feature is not
/// currently configured, so this defaults to `false`.
///
/// Source: `i386-link.c` lines 13-16 — conditional on `__PIC__`
pub const PCRELATIVE_DLLPLT: bool = false;

/// Whether DLL PLT entries need relocation.
///
/// Always `true` for i386 — PLT stubs in shared libraries require relocation
/// at load time.
///
/// Source: `i386-link.c` line 23 — `#define RELOCATE_DLLPLT 1`
pub const RELOCATE_DLLPLT: bool = true;

// ===========================================================================
// Register Class Table
// Source: i386-gen.c lines 94-105
// ===========================================================================

/// USE_EBX configuration: whether EBX is available as a general register.
///
/// - 0: EBX is not available as a general register (default, non-PIC)
/// - 1: EBX is an additional (4th) general integer register
/// - 2: EBX is reserved for GOT pointer (PIC mode)
///
/// Currently hardcoded to 0 (standard non-PIC mode). The `pic` feature flag
/// is not defined in Cargo.toml, so PIC mode (USE_EBX=2) is not available.
///
/// Source: `i386-gen.c` lines 94-98
const USE_EBX: i32 = 0;

/// Register class table — maps register number to class bitmask.
///
/// Each entry is a bitwise OR of register class flags indicating which
/// classes the register belongs to. The register allocator uses this
/// table to find a register matching the required class.
///
/// | Index | Register | Classes |
/// |-------|----------|---------|
/// | 0 | EAX | `RC_INT \| RC_EAX` |
/// | 1 | ECX | `RC_INT \| RC_ECX` |
/// | 2 | EDX | `RC_INT \| RC_EDX` |
/// | 3 | EBX | 0 (unavailable when USE_EBX ≠ 1) |
/// | 4 | ST0 | `RC_FLOAT \| RC_ST0` |
///
/// Source: `i386-gen.c` lines 100-105
pub const REG_CLASSES: [i32; NB_REGS] = [
    RC_INT | RC_EAX,   // index 0: EAX — general integer + specific EAX class
    RC_INT | RC_ECX,   // index 1: ECX — general integer + specific ECX class
    RC_INT | RC_EDX,   // index 2: EDX — general integer + specific EDX class
    // index 3: EBX — only available as integer register when USE_EBX == 1.
    // When USE_EBX == 0 (default) or USE_EBX == 2 (PIC), EBX is not allocatable.
    if USE_EBX == 1 { RC_INT | RC_EBX } else { 0 },
    RC_FLOAT | RC_ST0, // index 4: ST0 — x87 FPU stack top
];

// ===========================================================================
// Target Machine Predefined Macros
// Source: i386-gen.c line 91
// ===========================================================================

/// Target machine predefined macro string for i386.
///
/// Null-separated list of macros that the preprocessor defines automatically
/// when compiling for the i386 target. Contains:
/// - `__i386__` (ISO C standard predefined macro)
/// - `__i386` (common extension)
/// - `i386` (legacy, pre-ANSI)
///
/// Source: `i386-gen.c` line 91 — `"__i386__\0__i386\0i386\0"`
pub const TARGET_MACHINE_DEFS: &str = "__i386__\0__i386\0i386\0";

// ===========================================================================
// I386Backend — Architecture Backend State
// ===========================================================================

/// i386 code generation backend.
///
/// Contains all mutable state for i386 code generation that was previously
/// held in global/static variables in `i386-gen.c`. This struct implements
/// the [`CodegenBackend`] trait, providing all architecture-specific code
/// generation, linking, and relocation functionality.
///
/// # State Fields
///
/// - [`func_sub_sp_offset`](Self::func_sub_sp_offset): Tracks where to
///   backpatch the prologue's stack adjustment instruction.
/// - [`func_ret_sub`](Self::func_ret_sub): Callee-cleaned stack size for
///   `stdcall`/`fastcall`/`thiscall` conventions.
/// - [`fpu_stack_depth`](Self::fpu_stack_depth): **BUG-02 fix** — Tracks
///   the x87 FPU stack depth to prevent leaving stale values on the FPU
///   stack, which would cause incompatibility with gcc/msvc compiled code.
///
/// # Thread Safety
///
/// `I386Backend` is not `Send` or `Sync` by default. Each compilation
/// instance should have its own backend, which is guaranteed by the
/// `TCCState` ownership model (BUG-13 fix — full reentrancy).
pub struct I386Backend {
    /// Offset in the code section where the function prologue's stack
    /// adjustment instruction (`sub esp, N`) was emitted. Used during
    /// `gfunc_epilog` to backpatch the actual local variable size once
    /// the function body has been fully compiled.
    ///
    /// Source: `i386-gen.c` line 107 — `static unsigned long func_sub_sp_offset;`
    pub func_sub_sp_offset: u64,

    /// Callee-cleaned stack size in bytes.
    ///
    /// Non-zero for calling conventions where the callee pops arguments
    /// from the stack (`stdcall`, `fastcall`, `thiscall`). The epilogue
    /// emits `ret N` where N is this value. Zero for `cdecl` (default).
    ///
    /// Source: `i386-gen.c` line 108 — `static int func_ret_sub;`
    pub func_ret_sub: i32,

    /// x87 FPU stack depth counter.
    ///
    /// **BUG-02 FIX**: Tracks the current depth of the x87 FPU stack.
    /// Incremented on every FPU push operation (`fld`, `fild`, `fldz`,
    /// `fld1`, etc.) and decremented on every FPU pop operation (`fstp`,
    /// `ffree+fincstp`, `fucompp`).
    ///
    /// Must be 0 before:
    /// - Function return (to avoid corrupting the caller's FPU state)
    /// - Calling external functions (to maintain ABI compatibility)
    ///
    /// If non-zero when these conditions are reached, the codegen must
    /// emit `fstp`/`ffree` instructions to clean the FPU stack.
    pub fpu_stack_depth: u8,

    /// Code emission context — holds mutable state shared between
    /// `gen.rs` functions and the `CodeGen` driver. CodeGen syncs this
    /// context before/after each backend method call.
    pub ctx: gen::I386CodegenCtx,

    /// Bounds checking: code section offset saved at function entry.
    ///
    /// Used to compute the function body range for bounds-checking
    /// instrumentation during the function epilogue.
    ///
    /// Source: `i386-gen.c` line 110 — `static unsigned long func_bound_offset;`
    #[cfg(feature = "bcheck")]
    pub func_bound_offset: u64,

    /// Bounds checking: code index at function entry.
    ///
    /// Source: `i386-gen.c` line 111 — `static unsigned long func_bound_ind;`
    #[cfg(feature = "bcheck")]
    pub func_bound_ind: u64,

    /// Bounds checking: whether epilogue instrumentation is needed.
    ///
    /// Set to `true` when bounds-checked memory accesses are emitted
    /// within the function body, indicating that the epilogue must
    /// call the bounds-checking cleanup function.
    ///
    /// Source: `i386-gen.c` line 112 — `static int func_bound_add_epilog;`
    #[cfg(feature = "bcheck")]
    pub func_bound_add_epilog: bool,
}

impl I386Backend {
    /// Creates a new i386 backend with default (zero-initialized) state.
    ///
    /// All state fields start at zero/false, which is the correct initial
    /// state before any function compilation begins. Each function's
    /// prologue resets the relevant fields.
    pub fn new() -> Self {
        Self {
            func_sub_sp_offset: 0,
            func_ret_sub: 0,
            fpu_stack_depth: 0,
            ctx: gen::I386CodegenCtx::new(),
            #[cfg(feature = "bcheck")]
            func_bound_offset: 0,
            #[cfg(feature = "bcheck")]
            func_bound_ind: 0,
            #[cfg(feature = "bcheck")]
            func_bound_add_epilog: false,
        }
    }
}

impl Default for I386Backend {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// CodegenBackend Trait Implementation
// Delegates code emission to gen.rs and linker operations to link.rs
// ===========================================================================

impl CodegenBackend for I386Backend {
    // =======================================================================
    // Target information — direct constant returns
    // =======================================================================

    fn target_machine_defs(&self) -> &'static str {
        TARGET_MACHINE_DEFS
    }

    fn reg_classes(&self) -> &[i32] {
        &REG_CLASSES
    }

    fn nb_regs(&self) -> usize {
        NB_REGS
    }

    fn ptr_size(&self) -> usize {
        PTR_SIZE
    }

    // =======================================================================
    // Code emission — delegated to gen.rs
    // =======================================================================

    fn gsym_addr(&mut self, t: i32, a: i32) -> TccResult<()> {
        gen::gsym_addr(self, t, a)
    }

    fn gsym(&mut self, t: i32) -> TccResult<()> {
        gen::gsym(self, t)
    }

    fn load(&mut self, r: i32, sv: &SValue) -> TccResult<()> {
        gen::load(self, r, sv)
    }

    fn store(&mut self, r: i32, sv: &SValue) -> TccResult<()> {
        gen::store(self, r, sv)
    }

    fn gfunc_sret(&self, vt: &CType, variadic: bool) -> (bool, CType, i32, i32) {
        gen::gfunc_sret(vt, variadic)
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

    fn emit_opcode(&mut self, c: u32) -> TccResult<()> {
        gen::o(self, c)
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

    // =======================================================================
    // Optional methods — overridden with i386 implementations from gen.rs
    // =======================================================================

    fn g(&mut self, c: i32) -> TccResult<()> {
        gen::g(self, c)
    }

    fn gen_le16(&mut self, c: i32) -> TccResult<()> {
        gen::gen_le16(self, c)
    }

    fn gen_le32(&mut self, c: i32) -> TccResult<()> {
        gen::gen_le32(self, c)
    }

    fn gen_increment_tcov(&mut self, sv: &SValue) -> TccResult<()> {
        gen::gen_increment_tcov(self, sv)
    }

    // =======================================================================
    // Linker interface — delegated to link.rs
    // =======================================================================

    fn code_reloc(&self, reloc_type: i32) -> i32 {
        link::code_reloc(reloc_type)
    }

    fn gotplt_entry_type(&self, reloc_type: i32) -> i32 {
        link::gotplt_entry_type(reloc_type)
    }

    fn relocate(&mut self, rel_type: i32, ptr: &mut [u8], addr: u64, val: u64) -> TccResult<()> {
        link::relocate(rel_type, ptr, addr, val)
    }

    // =======================================================================
    // ELF constants — direct constant returns
    // =======================================================================

    fn elf_machine(&self) -> u16 {
        EM_TCC_TARGET
    }

    fn elf_start_addr(&self) -> u64 {
        ELF_START_ADDR
    }

    fn elf_page_size(&self) -> u64 {
        ELF_PAGE_SIZE
    }

    fn pcrelative_dllplt(&self) -> bool {
        PCRELATIVE_DLLPLT
    }

    fn relocate_dllplt(&self) -> bool {
        RELOCATE_DLLPLT
    }
}

// ===========================================================================
// Unit tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_count_constants() {
        assert_eq!(NB_REGS, 5);
        assert_eq!(NB_ASM_REGS, 8);
    }

    #[test]
    fn test_register_class_bitmasks() {
        assert_eq!(RC_INT, 0x0001);
        assert_eq!(RC_FLOAT, 0x0002);
        assert_eq!(RC_EAX, 0x0004);
        assert_eq!(RC_EDX, 0x0008);
        assert_eq!(RC_ECX, 0x0010);
        assert_eq!(RC_EBX, 0x0020);
        assert_eq!(RC_ST0, 0x0040);
        // Verify no overlapping bits between specific classes
        assert_eq!(RC_EAX & RC_EDX, 0);
        assert_eq!(RC_EAX & RC_ECX, 0);
        assert_eq!(RC_EAX & RC_EBX, 0);
        assert_eq!(RC_EAX & RC_ST0, 0);
        assert_eq!(RC_INT & RC_FLOAT, 0);
    }

    #[test]
    fn test_return_register_classes() {
        assert_eq!(RC_IRET, RC_EAX);
        assert_eq!(RC_IRE2, RC_EDX);
        assert_eq!(RC_FRET, RC_ST0);
    }

    #[test]
    fn test_register_indices() {
        assert_eq!(TREG_EAX, 0);
        assert_eq!(TREG_ECX, 1);
        assert_eq!(TREG_EDX, 2);
        assert_eq!(TREG_EBX, 3);
        assert_eq!(TREG_ST0, 4);
        assert_eq!(TREG_ESP, 4); // overlaps ST0 in different contexts
        assert_eq!(TREG_MEM, 0x20);
    }

    #[test]
    fn test_reg_value_function() {
        // Register encoding: low 3 bits
        assert_eq!(reg_value(0), 0);
        assert_eq!(reg_value(1), 1);
        assert_eq!(reg_value(2), 2);
        assert_eq!(reg_value(3), 3);
        assert_eq!(reg_value(4), 4);
        assert_eq!(reg_value(5), 5);
        assert_eq!(reg_value(6), 6);
        assert_eq!(reg_value(7), 7);
        // Wraps at 8
        assert_eq!(reg_value(8), 0);
        assert_eq!(reg_value(9), 1);
        // TREG_MEM (0x20) wraps to 0
        assert_eq!(reg_value(TREG_MEM), 0);
        // Standard register values
        assert_eq!(reg_value(TREG_EAX), 0);
        assert_eq!(reg_value(TREG_ECX), 1);
        assert_eq!(reg_value(TREG_EDX), 2);
        assert_eq!(reg_value(TREG_EBX), 3);
    }

    #[test]
    fn test_return_registers() {
        assert_eq!(REG_IRET, TREG_EAX);
        assert_eq!(REG_IRE2, TREG_EDX);
        assert_eq!(REG_FRET, TREG_ST0);
    }

    #[test]
    fn test_architecture_constants() {
        assert_eq!(PTR_SIZE, 4);
        assert_eq!(LDOUBLE_SIZE, 12);
        assert_eq!(LDOUBLE_ALIGN, 4);
        assert_eq!(MAX_ALIGN, 8);
        assert!(INVERT_FUNC_PARAMS);
        assert!(PROMOTE_RET);
    }

    #[test]
    fn test_elf_constants() {
        assert_eq!(EM_TCC_TARGET, 3); // EM_386
        assert_eq!(ELF_START_ADDR, 0x08048000);
        assert_eq!(ELF_PAGE_SIZE, 0x1000);
    }

    #[test]
    fn test_relocation_constants() {
        assert_eq!(R_DATA_32, 1);
        assert_eq!(R_DATA_PTR, 1);
        assert_eq!(R_JMP_SLOT, 7);
        assert_eq!(R_GLOB_DAT, 6);
        assert_eq!(R_COPY, 5);
        assert_eq!(R_RELATIVE, 8);
        assert!(!PCRELATIVE_DLLPLT);
        assert!(RELOCATE_DLLPLT);
    }

    #[test]
    fn test_reg_classes_table() {
        assert_eq!(REG_CLASSES.len(), NB_REGS);
        assert_eq!(REG_CLASSES[0], RC_INT | RC_EAX);
        assert_eq!(REG_CLASSES[1], RC_INT | RC_ECX);
        assert_eq!(REG_CLASSES[2], RC_INT | RC_EDX);
        // USE_EBX = 0, so EBX is not available
        assert_eq!(REG_CLASSES[3], 0);
        assert_eq!(REG_CLASSES[4], RC_FLOAT | RC_ST0);
    }

    #[test]
    fn test_reg_classes_int_membership() {
        // All integer registers should have RC_INT bit set
        assert_ne!(REG_CLASSES[0] & RC_INT, 0); // EAX
        assert_ne!(REG_CLASSES[1] & RC_INT, 0); // ECX
        assert_ne!(REG_CLASSES[2] & RC_INT, 0); // EDX
        // EBX not available (USE_EBX=0)
        assert_eq!(REG_CLASSES[3] & RC_INT, 0);
        // ST0 is float, not int
        assert_eq!(REG_CLASSES[4] & RC_INT, 0);
    }

    #[test]
    fn test_reg_classes_float_membership() {
        // Only ST0 should have RC_FLOAT bit set
        assert_eq!(REG_CLASSES[0] & RC_FLOAT, 0);
        assert_eq!(REG_CLASSES[1] & RC_FLOAT, 0);
        assert_eq!(REG_CLASSES[2] & RC_FLOAT, 0);
        assert_eq!(REG_CLASSES[3] & RC_FLOAT, 0);
        assert_ne!(REG_CLASSES[4] & RC_FLOAT, 0);
    }

    #[test]
    fn test_backend_new() {
        let backend = I386Backend::new();
        assert_eq!(backend.func_sub_sp_offset, 0);
        assert_eq!(backend.func_ret_sub, 0);
        assert_eq!(backend.fpu_stack_depth, 0);
    }

    #[test]
    fn test_backend_default() {
        let backend = I386Backend::default();
        assert_eq!(backend.func_sub_sp_offset, 0);
        assert_eq!(backend.func_ret_sub, 0);
        assert_eq!(backend.fpu_stack_depth, 0);
    }

    #[test]
    fn test_backend_field_mutation() {
        let mut backend = I386Backend::new();
        backend.func_sub_sp_offset = 42;
        backend.func_ret_sub = 8;
        backend.fpu_stack_depth = 2;
        assert_eq!(backend.func_sub_sp_offset, 42);
        assert_eq!(backend.func_ret_sub, 8);
        assert_eq!(backend.fpu_stack_depth, 2);
    }

    #[test]
    fn test_backend_target_info() {
        let backend = I386Backend::new();
        assert_eq!(backend.target_machine_defs(), TARGET_MACHINE_DEFS);
        assert_eq!(backend.reg_classes(), &REG_CLASSES);
        assert_eq!(backend.nb_regs(), NB_REGS);
        assert_eq!(backend.ptr_size(), PTR_SIZE);
    }

    #[test]
    fn test_backend_elf_constants() {
        let backend = I386Backend::new();
        assert_eq!(backend.elf_machine(), EM_TCC_TARGET);
        assert_eq!(backend.elf_start_addr(), ELF_START_ADDR);
        assert_eq!(backend.elf_page_size(), ELF_PAGE_SIZE);
        assert!(!backend.pcrelative_dllplt());
        assert!(backend.relocate_dllplt());
    }

    #[test]
    fn test_target_machine_defs_content() {
        let defs = TARGET_MACHINE_DEFS;
        // Should contain null-separated macro definitions
        assert!(defs.contains("__i386__"));
        assert!(defs.contains("__i386"));
        assert!(defs.contains("i386"));
        // Verify null separation
        let parts: Vec<&str> = defs.split('\0').filter(|s| !s.is_empty()).collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[0], "__i386__");
        assert_eq!(parts[1], "__i386");
        assert_eq!(parts[2], "i386");
    }

    #[test]
    fn test_use_ebx_default() {
        // Verify USE_EBX is 0 (default, non-PIC)
        assert_eq!(USE_EBX, 0);
    }
}
