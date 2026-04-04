// Copyright (c) TinyCC contributors. LGPL licensed.
// Ported from tcc.h architecture dispatch and function declarations to Rust.
//
//! # Architecture Backend Module — CodegenBackend Trait and Dispatch
//!
//! This module is the root for all architecture-specific backends. It defines:
//!
//! - [`CodegenBackend`] — The trait that every architecture implements, collecting
//!   all target-specific code generation, linking, and relocation functions.
//! - [`TargetArch`] — An enum of all supported target architectures.
//! - [`create_backend()`] — A factory function that instantiates the appropriate
//!   backend based on Cargo feature flags.
//! - [`native_target()`] — Compile-time detection of the host architecture.
//! - Register class constants ([`RC_INT`], [`RC_FLOAT`]).
//! - Little-endian byte manipulation utilities ([`read16le`], [`write16le`],
//!   [`read32le`], [`write32le`], [`read64le`], [`write64le`], [`add32le`],
//!   [`add64le`]).
//!
//! ## C-to-Rust Mapping
//!
//! | C Pattern | Rust Equivalent |
//! |-----------|-----------------|
//! | `#ifdef TCC_TARGET_I386` / `#include "i386-gen.c"` | `#[cfg(feature = "i386")] pub mod i386;` |
//! | `ST_FUNC void gsym_addr(int t, int a);` | `fn gsym_addr(&mut self, t: i32, a: i32) -> TccResult<()>;` |
//! | `#define RC_INT 0x0001` | `pub const RC_INT: i32 = 0x0001;` |
//! | `static inline uint32_t read32le(unsigned char *p)` | `pub fn read32le(p: &[u8]) -> u32` |
//! | Compile-time `#ifdef` target selection | Runtime `match` on `TargetArch` with feature-gated arms |
//!
//! ## Architecture Backends
//!
//! Each backend is a submodule gated by a Cargo feature flag:
//!
//! | Feature | Module | C Source | Target |
//! |---------|--------|----------|--------|
//! | `i386` | [`i386`] | `i386-gen.c`, `i386-link.c`, `i386-asm.c` | Intel 32-bit |
//! | `x86_64` | [`x86_64`] | `x86_64-gen.c`, `x86_64-link.c` | AMD/Intel 64-bit |
//! | `arm` | [`arm`] | `arm-gen.c`, `arm-link.c`, `arm-asm.c` | ARM 32-bit |
//! | `arm64` | [`arm64`] | `arm64-gen.c`, `arm64-link.c`, `arm64-asm.c` | ARM 64-bit / AArch64 |
//! | `riscv64` | [`riscv64`] | `riscv64-gen.c`, `riscv64-link.c`, `riscv64-asm.c` | RISC-V 64-bit |
//! | `c67` | [`c67`] | `c67-gen.c`, `c67-link.c` | TI TMS320C67xx DSP |
//! | `il` | [`il`] | `il-gen.c`, `il-opcodes.h` | .NET IL/CIL |

// ---------------------------------------------------------------------------
// Conditional submodule declarations — feature-gated architecture backends
// Replaces: tcc.h lines 374-401 (#ifdef TCC_TARGET_* ... #include "{arch}-gen.c" ...)
// ---------------------------------------------------------------------------

/// Intel i386 (IA-32) backend — 32-bit x86 code generation, linking, and assembly.
#[cfg(feature = "i386")]
pub mod i386;

/// AMD/Intel x86_64 (AMD64) backend — 64-bit x86 code generation and linking.
#[cfg(feature = "x86_64")]
pub mod x86_64;

/// ARM (ARMv4+) backend — 32-bit ARM code generation, linking, and assembly.
#[cfg(feature = "arm")]
pub mod arm;

/// ARM64 / AArch64 (ARMv8) backend — 64-bit ARM code generation and linking.
#[cfg(feature = "arm64")]
pub mod arm64;

/// RISC-V 64-bit (RV64GC) backend — code generation, linking, and assembly.
#[cfg(feature = "riscv64")]
pub mod riscv64;

/// TI TMS320C67xx DSP backend — code generation and linking.
#[cfg(feature = "c67")]
pub mod c67;

/// .NET IL/CIL (experimental) backend — IL bytecode generation.
#[cfg(feature = "il")]
pub mod il;

// ---------------------------------------------------------------------------
// Imports from within tcc-core (verified against depends_on_files whitelist)
// ---------------------------------------------------------------------------

use crate::error::{TccError, TccResult};
use crate::types::{CType, SValue, Sym};

// ---------------------------------------------------------------------------
// Register class constants — shared across all architecture backends
// From tcc.h / i386-gen.c / x86_64-gen.c / arm-gen.c / etc. TARGET_DEFS_ONLY
// ---------------------------------------------------------------------------

/// Generic integer register class bit flag.
///
/// Every architecture backend defines this with value `0x0001`. Register
/// classes are bitwise OR'd to form composite classes (e.g., `RC_INT | RC_EAX`
/// means "EAX register, which is an integer register").
///
/// Used by the register allocator in `codegen.rs` to find a register of the
/// correct class when `gv()` / `gv2()` need to materialize a value.
pub const RC_INT: i32 = 0x0001;

/// Generic floating-point register class bit flag.
///
/// Every architecture backend defines this with value `0x0002`. On x87-based
/// backends (i386), this maps to the FPU stack; on SSE/NEON/VFP backends
/// (x86_64, ARM, ARM64), this maps to SIMD/FP register files.
pub const RC_FLOAT: i32 = 0x0002;

// ---------------------------------------------------------------------------
// GOT/PLT entry type constants — from tcc.h lines 1600-1607
// Used by the linker interface methods code_reloc() and gotplt_entry_type()
// ---------------------------------------------------------------------------

/// Never generate a GOT/PLT entry (e.g., `GLOB_DAT` and `JMP_SLOT` relocations).
pub const NO_GOTPLT_ENTRY: i32 = 0;

/// Only build a GOT entry, no PLT (e.g., `TPOFF` relocations).
pub const BUILD_GOT_ONLY: i32 = 1;

/// Generate GOT/PLT entry only if the symbol is undefined (auto-detect).
pub const AUTO_GOTPLT_ENTRY: i32 = 2;

/// Always generate a GOT/PLT entry (e.g., `PLTOFF` relocations).
pub const ALWAYS_GOTPLT_ENTRY: i32 = 3;

// ---------------------------------------------------------------------------
// TargetArch — Supported target architectures
// Replaces TCC_TARGET_* preprocessor defines from tcc.h lines 146-151
// ---------------------------------------------------------------------------

/// Enumerates all target architectures supported by TCC.
///
/// Each variant corresponds to a `TCC_TARGET_*` preprocessor define in the
/// original C codebase. The associated Cargo feature flag must be enabled
/// at compile time for the backend to be available.
///
/// # Examples
///
/// ```
/// use tcc_core::arch::TargetArch;
///
/// let target = TargetArch::X86_64;
/// assert_eq!(format!("{:?}", target), "X86_64");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TargetArch {
    /// Intel 32-bit (IA-32) — from `TCC_TARGET_I386`.
    ///
    /// Generates i386 machine code with x87 FPU support.
    /// Pointer size: 4 bytes. ELF machine: `EM_386` (3).
    I386,

    /// AMD/Intel 64-bit (AMD64 / x86-64) — from `TCC_TARGET_X86_64`.
    ///
    /// Generates x86_64 machine code with SSE2 FP support.
    /// Pointer size: 8 bytes. ELF machine: `EM_X86_64` (62).
    X86_64,

    /// ARM 32-bit (ARMv4+) — from `TCC_TARGET_ARM`.
    ///
    /// Generates ARM machine code with optional VFP/NEON support.
    /// Pointer size: 4 bytes. ELF machine: `EM_ARM` (40).
    Arm,

    /// ARM 64-bit / AArch64 (ARMv8) — from `TCC_TARGET_ARM64`.
    ///
    /// Generates AArch64 machine code with AAPCS64 calling convention.
    /// Pointer size: 8 bytes. ELF machine: `EM_AARCH64` (183).
    Arm64,

    /// RISC-V 64-bit (RV64GC) — from `TCC_TARGET_RISCV64`.
    ///
    /// Generates RISC-V 64-bit machine code with G (IMAFD) + C extensions.
    /// Pointer size: 8 bytes. ELF machine: `EM_RISCV` (243).
    Riscv64,

    /// TI TMS320C67xx DSP — from `TCC_TARGET_C67`.
    ///
    /// Generates TMS320C67xx VLIW instructions. Uses COFF output format.
    /// Pointer size: 4 bytes.
    C67,

    /// .NET IL/CIL (experimental) — generates MSIL bytecode.
    ///
    /// Experimental backend for .NET Common Language Infrastructure.
    Il,
}

impl std::fmt::Display for TargetArch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TargetArch::I386 => write!(f, "i386"),
            TargetArch::X86_64 => write!(f, "x86_64"),
            TargetArch::Arm => write!(f, "arm"),
            TargetArch::Arm64 => write!(f, "arm64"),
            TargetArch::Riscv64 => write!(f, "riscv64"),
            TargetArch::C67 => write!(f, "c67"),
            TargetArch::Il => write!(f, "il"),
        }
    }
}

// ---------------------------------------------------------------------------
// CodegenBackend — Architecture-specific code generation trait
// Collects all functions from tcc.h lines 1619-1684 and {arch}-link.c
// ---------------------------------------------------------------------------

/// Architecture-specific code generation backend trait.
///
/// Each architecture (i386, x86_64, ARM, ARM64, RISC-V64, C67, IL) implements
/// this trait with its specific instruction encoding, register allocation,
/// calling conventions, relocation handling, and ELF configuration.
///
/// This trait replaces the pattern in `tcc.h` where architecture-specific functions
/// (`gsym_addr`, `load`, `store`, `gfunc_call`, etc.) are declared as `ST_FUNC`
/// and one of the `{arch}-gen.c` files is `#include`d to provide the implementation,
/// selected by `#ifdef TCC_TARGET_*`.
///
/// All fallible methods return [`TccResult<T>`] instead of the C pattern of
/// `void` return with `longjmp`-based error recovery (see BUG-16).
///
/// # Method Categories
///
/// 1. **Target info** — `target_machine_defs`, `reg_classes`, `nb_regs`, `ptr_size`
/// 2. **Code emission** — `gsym_addr`, `gsym`, `load`, `store`, `gfunc_*`, `gjmp_*`,
///    `gen_opi`, `gen_opf`, `gen_cvt_*`, `ggoto`, `emit_opcode`, `gen_vla_*`
/// 3. **Optional emission** — `g`, `gen_le16`, `gen_le32`, `gen_increment_tcov`
///    (with default no-op implementations)
/// 4. **Linker interface** — `code_reloc`, `gotplt_entry_type`, `relocate`
/// 5. **ELF constants** — `elf_machine`, `elf_start_addr`, `elf_page_size`,
///    `pcrelative_dllplt`, `relocate_dllplt`
pub trait CodegenBackend {
    // ===================================================================
    // Target machine definitions
    // From each {arch}-gen.c TARGET_DEFS_ONLY section
    // ===================================================================

    /// Returns the target machine predefined macro string.
    ///
    /// Each architecture provides a null-separated list of predefined macros
    /// that the preprocessor defines automatically when targeting that architecture.
    ///
    /// # Examples
    ///
    /// - i386: `"__i386__\0__i386\0i386\0"`
    /// - x86_64: `"__x86_64__\0__x86_64\0"`
    /// - ARM: `"__arm__\0__arm\0"`
    fn target_machine_defs(&self) -> &'static str;

    /// Returns the register class table for this architecture.
    ///
    /// Maps register number (index) to a bitmask of register classes the
    /// register belongs to. The table has `nb_regs()` entries.
    ///
    /// Register classes are bitwise OR'd combinations of [`RC_INT`], [`RC_FLOAT`],
    /// and architecture-specific class flags (e.g., `RC_EAX`, `RC_XMM0`).
    ///
    /// Corresponds to: `ST_DATA const int reg_classes[NB_REGS];`
    fn reg_classes(&self) -> &[i32];

    /// Returns the number of registers available for the register allocator.
    ///
    /// This is `NB_REGS` from each `{arch}-gen.c` `TARGET_DEFS_ONLY` section.
    ///
    /// # Architecture Values
    ///
    /// - i386: 5 (EAX, ECX, EDX, EBX, ST0)
    /// - x86_64: 25 (RAX..R11, XMM0..XMM7, ST0)
    /// - ARM: varies (typically 16)
    /// - ARM64: varies (typically 32)
    /// - RISC-V64: varies
    fn nb_regs(&self) -> usize;

    /// Returns the pointer size in bytes for this target architecture.
    ///
    /// Corresponds to `PTR_SIZE` from each `{arch}-gen.c` `TARGET_DEFS_ONLY` section.
    ///
    /// - 4 for 32-bit targets (i386, ARM, C67)
    /// - 8 for 64-bit targets (x86_64, ARM64, RISC-V64)
    fn ptr_size(&self) -> usize;

    // ===================================================================
    // Code emission — from tcc.h lines 1623-1647
    // ===================================================================

    /// Resolves a forward branch target: patches the jump instruction at code
    /// offset `t` to branch to absolute address `a`.
    ///
    /// Used during code generation to back-patch forward jumps once the target
    /// address is known. The implementation walks the forward-reference chain
    /// starting at `t` (each link contains the offset of the previous link)
    /// and patches each to jump to `a`.
    ///
    /// Corresponds to: `ST_FUNC void gsym_addr(int t, int a);`
    fn gsym_addr(&mut self, t: i32, a: i32) -> TccResult<()>;

    /// Resolves a forward branch target to the current code position.
    ///
    /// Equivalent to `gsym_addr(t, current_pc)` — patches the jump chain
    /// starting at `t` to branch to wherever the code pointer currently is.
    ///
    /// Corresponds to: `ST_FUNC void gsym(int t);`
    fn gsym(&mut self, t: i32) -> TccResult<()>;

    /// Loads the value described by `sv` into register `r`.
    ///
    /// This is one of the core code generation primitives. Based on the value
    /// location in `sv.r` (constant, local variable, global, register), it
    /// emits the appropriate load instruction(s) for the target architecture.
    ///
    /// # Arguments
    /// * `r` — Destination register number
    /// * `sv` — Source value descriptor (type, location, constant value, symbol)
    ///
    /// Corresponds to: `ST_FUNC void load(int r, SValue *sv);`
    fn load(&mut self, r: i32, sv: &SValue) -> TccResult<()>;

    /// Stores the value in register `r` to the location described by `sv`.
    ///
    /// The inverse of [`load()`](Self::load). Emits store instruction(s) based
    /// on the value's type and destination location.
    ///
    /// # Arguments
    /// * `r` — Source register number
    /// * `sv` — Destination value descriptor
    ///
    /// Corresponds to: `ST_FUNC void store(int r, SValue *v);`
    fn store(&mut self, r: i32, sv: &SValue) -> TccResult<()>;

    /// Determines if a struct/union should be returned via registers or memory.
    ///
    /// Each architecture has different rules for struct return:
    /// - i386: Structs are returned via a hidden pointer parameter (always memory)
    /// - x86_64 (System V): Structs ≤ 16 bytes may be returned in registers
    /// - ARM/ARM64: Architecture-specific rules based on size and composition
    ///
    /// # Arguments
    /// * `vt` — The type of the value being returned
    /// * `variadic` — Whether the function is variadic
    ///
    /// # Returns
    /// A tuple of `(in_registers, ret_type, align, regsize)`:
    /// - `in_registers` — `true` if returned in registers, `false` if via memory pointer
    /// - `ret_type` — The register type used for return (modified `CType`)
    /// - `align` — Alignment requirement
    /// - `regsize` — Size per register used for return
    ///
    /// Corresponds to: `ST_FUNC int gfunc_sret(CType *vt, int variadic, CType *ret, int *align, int *regsize);`
    fn gfunc_sret(&self, vt: &CType, variadic: bool) -> (bool, CType, i32, i32);

    /// Generates code for a function call with `nb_args` arguments on the value stack.
    ///
    /// Handles the complete calling sequence:
    /// 1. Argument evaluation and placement (registers or stack per ABI)
    /// 2. Stack alignment (if required by ABI)
    /// 3. The actual call instruction emission
    /// 4. Stack cleanup after return
    /// 5. Return value retrieval
    ///
    /// Corresponds to: `ST_FUNC void gfunc_call(int nb_args);`
    fn gfunc_call(&mut self, nb_args: i32) -> TccResult<()>;

    /// Generates the function prologue (entry code).
    ///
    /// Emits instructions to:
    /// 1. Save the frame pointer and establish a new stack frame
    /// 2. Allocate space for local variables
    /// 3. Save callee-saved registers
    /// 4. Copy register-passed arguments to their stack slots
    ///
    /// The `func_sym` parameter provides function attributes (calling convention,
    /// parameter types, variadic flag) needed to generate correct prologue code.
    ///
    /// Corresponds to: `ST_FUNC void gfunc_prolog(Sym *func_sym);`
    fn gfunc_prolog(&mut self, func_sym: &Sym) -> TccResult<()>;

    /// Generates the function epilogue (exit code).
    ///
    /// Emits instructions to:
    /// 1. Restore callee-saved registers
    /// 2. Tear down the stack frame
    /// 3. Return to the caller
    ///
    /// Corresponds to: `ST_FUNC void gfunc_epilog(void);`
    fn gfunc_epilog(&mut self) -> TccResult<()>;

    /// Fills `n` bytes with NOP instructions for alignment padding.
    ///
    /// The implementation must use the optimal NOP encoding for the target.
    /// For x86, this uses multi-byte NOP forms (e.g., `0x0F 0x1F 0x44 0x00 0x00`
    /// for 5-byte NOP) rather than `n` individual single-byte NOPs.
    ///
    /// Corresponds to: `ST_FUNC void gen_fill_nops(int);`
    fn gen_fill_nops(&mut self, n: i32) -> TccResult<()>;

    /// Generates an unconditional forward jump and returns a patch address.
    ///
    /// The returned value is used later with [`gsym()`](Self::gsym) or
    /// [`gsym_addr()`](Self::gsym_addr) to back-patch the jump target once
    /// the destination address is known. If `t` is non-zero, the jump is
    /// appended to the existing forward-reference chain starting at `t`.
    ///
    /// Corresponds to: `ST_FUNC int gjmp(int t);`
    fn gjmp(&mut self, t: i32) -> TccResult<i32>;

    /// Generates an unconditional jump to the absolute address `a`.
    ///
    /// Unlike [`gjmp()`](Self::gjmp), the target address is known immediately.
    /// Used for backward jumps (e.g., loop back-edges).
    ///
    /// Corresponds to: `ST_FUNC void gjmp_addr(int a);`
    fn gjmp_addr(&mut self, a: i32) -> TccResult<()>;

    /// Generates a conditional jump based on the comparison `op`.
    ///
    /// The condition code in `op` determines which branch is taken. Returns
    /// a patch address for the forward jump, which is chained to `t` if
    /// `t` is non-zero.
    ///
    /// Corresponds to: `ST_FUNC int gjmp_cond(int op, int t);`
    fn gjmp_cond(&mut self, op: i32, t: i32) -> TccResult<i32>;

    /// Appends a jump target to the forward-reference chain.
    ///
    /// Links jump `t` into the chain starting at `n`. Returns the new chain head.
    /// Used to merge multiple forward jumps that target the same destination.
    ///
    /// Corresponds to: `ST_FUNC int gjmp_append(int n, int t);`
    fn gjmp_append(&mut self, n: i32, t: i32) -> TccResult<i32>;

    /// Generates code for an integer binary operation.
    ///
    /// Handles: addition, subtraction, multiplication, division, modulo,
    /// left/right shifts, bitwise AND/OR/XOR, and comparison operations.
    /// The operation `op` is a token value (e.g., `'+'`, `'-'`, `TOK_SHL`).
    ///
    /// Corresponds to: `ST_FUNC void gen_opi(int op);`
    fn gen_opi(&mut self, op: i32) -> TccResult<()>;

    /// Generates code for a floating-point binary operation.
    ///
    /// Handles: floating-point addition, subtraction, multiplication, division,
    /// and comparison operations. The `op` parameter is a token value.
    ///
    /// Corresponds to: `ST_FUNC void gen_opf(int op);`
    fn gen_opf(&mut self, op: i32) -> TccResult<()>;

    /// Generates float-to-integer conversion code.
    ///
    /// Converts the top-of-stack floating-point value to an integer of type `t`
    /// (one of `VT_INT`, `VT_LLONG`, etc.).
    ///
    /// Corresponds to: `ST_FUNC void gen_cvt_ftoi(int t);`
    fn gen_cvt_ftoi(&mut self, t: i32) -> TccResult<()>;

    /// Generates integer-to-float conversion code.
    ///
    /// Converts the top-of-stack integer value to a floating-point type `t`
    /// (one of `VT_FLOAT`, `VT_DOUBLE`, `VT_LDOUBLE`).
    ///
    /// Corresponds to: `ST_FUNC void gen_cvt_itof(int t);`
    fn gen_cvt_itof(&mut self, t: i32) -> TccResult<()>;

    /// Generates float-to-float conversion code.
    ///
    /// Converts between floating-point precisions (e.g., `float` → `double`,
    /// `double` → `long double`). The target type is `t`.
    ///
    /// Corresponds to: `ST_FUNC void gen_cvt_ftof(int t);`
    fn gen_cvt_ftof(&mut self, t: i32) -> TccResult<()>;

    /// Generates a computed goto (indirect jump through a function pointer or label address).
    ///
    /// Used for GCC computed goto extension (`goto *ptr;`) and indirect function calls
    /// via function pointers.
    ///
    /// Corresponds to: `ST_FUNC void ggoto(void);`
    fn ggoto(&mut self) -> TccResult<()>;

    /// Emits a raw opcode word to the code section.
    ///
    /// This is the lowest-level instruction emission primitive. On x86, `c` is
    /// typically 1-4 bytes of opcode. On ARM, it's a full 32-bit instruction word.
    ///
    /// Note: Not available on C67 target (which uses a different emission model).
    ///
    /// Corresponds to: `ST_FUNC void o(unsigned int c);`
    fn emit_opcode(&mut self, c: u32) -> TccResult<()>;

    /// Saves the current stack pointer for VLA (Variable Length Array) support.
    ///
    /// Before a VLA allocation, the current stack pointer is saved at the local
    /// variable offset `addr` so it can be restored when the VLA goes out of scope.
    ///
    /// Corresponds to: `ST_FUNC void gen_vla_sp_save(int addr);`
    fn gen_vla_sp_save(&mut self, addr: i32) -> TccResult<()>;

    /// Restores the stack pointer from a saved VLA state.
    ///
    /// Restores the stack pointer from the local variable at offset `addr`,
    /// effectively deallocating VLA storage.
    ///
    /// Corresponds to: `ST_FUNC void gen_vla_sp_restore(int addr);`
    fn gen_vla_sp_restore(&mut self, addr: i32) -> TccResult<()>;

    /// Generates a VLA stack allocation.
    ///
    /// Adjusts the stack pointer to allocate space for a VLA. The `typ` parameter
    /// carries the element type (used to compute element size), and `align` specifies
    /// the required alignment.
    ///
    /// Note (NC-08): VLA stack allocation is not signal-safe. This is an inherent
    /// limitation of the stack-pointer-manipulation approach and is documented in
    /// `docs/compatibility_report.md`.
    ///
    /// Corresponds to: `ST_FUNC void gen_vla_alloc(CType *type, int align);`
    fn gen_vla_alloc(&mut self, typ: &CType, align: i32) -> TccResult<()>;

    // ===================================================================
    // Architecture-specific optional methods with default no-op implementations
    // From tcc.h lines 1673-1684 — only available for some architectures
    // ===================================================================

    /// Emits a single byte to the code section.
    ///
    /// Used by x86 (i386, x86_64) and ARM backends for byte-level instruction
    /// encoding. Backends that use word-level emission (C67, IL) do not override this.
    ///
    /// Corresponds to: `ST_FUNC void g(int c);` (i386/x86_64/ARM only)
    fn g(&mut self, _c: i32) -> TccResult<()> {
        // Default no-op — overridden by architectures that use byte-level emission
        Ok(())
    }

    /// Emits a 16-bit little-endian value to the code section.
    ///
    /// Used by x86 and ARM backends for immediate value encoding in instructions.
    ///
    /// Corresponds to: `ST_FUNC void gen_le16(int c);` (i386/x86_64/ARM only)
    fn gen_le16(&mut self, _c: i32) -> TccResult<()> {
        // Default no-op — overridden by architectures that emit 16-bit values
        Ok(())
    }

    /// Emits a 32-bit little-endian value to the code section.
    ///
    /// Used by x86 and ARM backends for address and immediate encoding.
    ///
    /// Corresponds to: `ST_FUNC void gen_le32(int c);` (i386/x86_64/ARM only)
    fn gen_le32(&mut self, _c: i32) -> TccResult<()> {
        // Default no-op — overridden by architectures that emit 32-bit values
        Ok(())
    }

    /// Generates test coverage counter instrumentation.
    ///
    /// Emits code to increment a coverage counter at the location described by
    /// `sv`. Only implemented for i386, x86_64, ARM, ARM64, and RISC-V64 backends.
    ///
    /// Corresponds to: `ST_FUNC void gen_increment_tcov(SValue *sv);`
    fn gen_increment_tcov(&mut self, _sv: &SValue) -> TccResult<()> {
        // Default no-op — overridden by architectures that support test coverage
        Ok(())
    }

    // ===================================================================
    // Linker interface — from {arch}-link.c files
    // From tcc.h lines 1597-1617
    // ===================================================================

    /// Checks whether a relocation type refers to code or data.
    ///
    /// # Returns
    /// - `1` if the relocation is for code (e.g., branch relocations)
    /// - `0` if the relocation is for data (e.g., absolute address relocations)
    /// - `-1` if the relocation type is unknown
    ///
    /// Used during linking to classify relocations for section placement.
    ///
    /// Corresponds to: `ST_FUNC int code_reloc(int reloc_type);`
    fn code_reloc(&self, reloc_type: i32) -> i32;

    /// Determines what kind of GOT/PLT entry is needed for a relocation type.
    ///
    /// # Returns
    /// One of the `*_GOTPLT_ENTRY` constants:
    /// - [`NO_GOTPLT_ENTRY`] (0) — Never generate (e.g., `GLOB_DAT`, `JMP_SLOT`)
    /// - [`BUILD_GOT_ONLY`] (1) — Only build GOT entry (e.g., `TPOFF`)
    /// - [`AUTO_GOTPLT_ENTRY`] (2) — Generate if symbol is undefined
    /// - [`ALWAYS_GOTPLT_ENTRY`] (3) — Always generate (e.g., `PLTOFF`)
    ///
    /// Corresponds to: `ST_FUNC int gotplt_entry_type(int reloc_type);`
    fn gotplt_entry_type(&self, reloc_type: i32) -> i32;

    /// Applies a relocation to a code/data buffer.
    ///
    /// Computes the final relocated value and patches it into the byte buffer
    /// at the appropriate location. This is the core relocation engine for each
    /// architecture.
    ///
    /// # Arguments
    /// * `rel_type` — Architecture-specific relocation type (e.g., `R_386_32`, `R_X86_64_PC32`)
    /// * `ptr` — Mutable byte slice at the relocation site
    /// * `addr` — The address of the relocation site in the output
    /// * `val` — The resolved symbol value (target address)
    ///
    /// Corresponds to: `ST_FUNC void relocate(TCCState *s1, ElfW_Rel *rel, int type, unsigned char *ptr, addr_t addr, addr_t val);`
    fn relocate(&mut self, rel_type: i32, ptr: &mut [u8], addr: u64, val: u64) -> TccResult<()>;

    // ===================================================================
    // ELF constants for this target — used by elf.rs and linker
    // ===================================================================

    /// Returns the ELF machine type constant for this architecture.
    ///
    /// # Standard Values
    /// - i386: `EM_386` = 3
    /// - x86_64: `EM_X86_64` = 62
    /// - ARM: `EM_ARM` = 40
    /// - ARM64: `EM_AARCH64` = 183
    /// - RISC-V: `EM_RISCV` = 243
    /// - C67: `EM_C60` = 140 (TMS320C6000)
    fn elf_machine(&self) -> u16;

    /// Returns the default ELF program entry point address for executables.
    ///
    /// # Architecture Values
    /// - i386: `0x08048000`
    /// - x86_64: `0x400000`
    /// - ARM: `0x10000`
    /// - ARM64: `0x400000`
    /// - RISC-V64: `0x10000`
    fn elf_start_addr(&self) -> u64;

    /// Returns the default ELF page size for this target.
    ///
    /// Used for segment alignment in the ELF output.
    ///
    /// # Architecture Values
    /// - Most targets: `0x1000` (4 KiB)
    /// - Some ARM configurations: `0x10000` (64 KiB)
    fn elf_page_size(&self) -> u64;

    /// Returns whether this target uses PC-relative DLL PLT entries.
    ///
    /// On some architectures (e.g., x86_64), PLT entries use PC-relative
    /// addressing. On others (e.g., i386), they use absolute addresses.
    fn pcrelative_dllplt(&self) -> bool;

    /// Returns whether this target requires DLL PLT entry relocation.
    ///
    /// Some targets need to relocate PLT stubs when loading shared libraries.
    fn relocate_dllplt(&self) -> bool;
}

// ---------------------------------------------------------------------------
// create_backend — Architecture backend factory function
// Replaces the compile-time #ifdef selection in tcc.h lines 374-401
// ---------------------------------------------------------------------------

/// Creates a new [`CodegenBackend`] for the specified target architecture.
///
/// Uses Cargo feature flags to determine which backends are available at compile
/// time. If the requested architecture's feature is not enabled, returns
/// [`TccError::ConfigError`].
///
/// This function replaces the compile-time `#ifdef TCC_TARGET_*` selection
/// in `tcc.h` lines 374-401, enabling runtime target selection when multiple
/// backend features are compiled in.
///
/// # Arguments
/// * `target` — The desired target architecture
///
/// # Returns
/// * `Ok(Box<dyn CodegenBackend>)` — A boxed trait object for the requested backend
/// * `Err(TccError::ConfigError)` — If the architecture feature is not compiled in
///
/// # Examples
///
/// ```ignore
/// use tcc_core::arch::{create_backend, TargetArch};
///
/// let backend = create_backend(TargetArch::X86_64)?;
/// assert_eq!(backend.ptr_size(), 8);
/// ```
#[allow(unreachable_patterns)]
pub fn create_backend(target: TargetArch) -> TccResult<Box<dyn CodegenBackend>> {
    match target {
        #[cfg(feature = "i386")]
        TargetArch::I386 => Ok(Box::new(i386::I386Backend::new())),

        #[cfg(feature = "x86_64")]
        TargetArch::X86_64 => Ok(Box::new(x86_64::X86_64Backend::new())),

        #[cfg(feature = "arm")]
        TargetArch::Arm => Ok(Box::new(arm::ArmBackend::new())),

        #[cfg(feature = "arm64")]
        TargetArch::Arm64 => Ok(Box::new(arm64::Arm64Backend::new())),

        #[cfg(feature = "riscv64")]
        TargetArch::Riscv64 => Ok(Box::new(riscv64::Riscv64Backend::new())),

        #[cfg(feature = "c67")]
        TargetArch::C67 => Ok(Box::new(c67::C67Backend::new())),

        #[cfg(feature = "il")]
        TargetArch::Il => Ok(Box::new(il::IlBackend::new())),

        // Catch-all for architectures not compiled in (feature disabled).
        // With #[allow(unreachable_patterns)], this compiles without warnings
        // even when all features are enabled.
        _ => Err(TccError::ConfigError {
            message: format!(
                "Target architecture {:?} not compiled in. \
                 Enable the corresponding Cargo feature flag (e.g., --features {}).",
                target, target
            ),
        }),
    }
}

// ---------------------------------------------------------------------------
// native_target — Compile-time host architecture detection
// Replaces tcc.h lines 180-193 (#ifdef __i386__ / __x86_64__ / __arm__ / etc.)
// ---------------------------------------------------------------------------

/// Detects the native host architecture at compile time.
///
/// Returns `Some(TargetArch)` if the host architecture is one of TCC's supported
/// targets, or `None` for unsupported host architectures (e.g., PowerPC, MIPS).
///
/// This replaces the `TCC_IS_NATIVE` detection chain in `tcc.h` lines 180-193.
/// The native target is required for the `-run` mode (compile and execute in memory),
/// which is only supported when the target matches the host.
///
/// # Examples
///
/// ```
/// use tcc_core::arch::native_target;
///
/// // On an x86_64 Linux host:
/// if let Some(target) = native_target() {
///     println!("Native target: {:?}", target);
/// }
/// ```
pub fn native_target() -> Option<TargetArch> {
    // Each cfg block returns immediately if the host matches.
    // The #[allow(unreachable_code)] at the end handles the case where
    // one of the earlier blocks has already returned.

    #[cfg(target_arch = "x86")]
    {
        return Some(TargetArch::I386);
    }

    #[cfg(target_arch = "x86_64")]
    {
        return Some(TargetArch::X86_64);
    }

    #[cfg(target_arch = "arm")]
    {
        return Some(TargetArch::Arm);
    }

    #[cfg(target_arch = "aarch64")]
    {
        return Some(TargetArch::Arm64);
    }

    #[cfg(all(target_arch = "riscv64", target_pointer_width = "64"))]
    {
        return Some(TargetArch::Riscv64);
    }

    // If none of the above cfg conditions matched, the host architecture
    // is not supported as a TCC native target.
    #[allow(unreachable_code)]
    None
}

// ---------------------------------------------------------------------------
// Little-endian byte manipulation utilities
// Ported from tcc.h lines 1649-1672 (static inline functions)
// ---------------------------------------------------------------------------

/// Reads a 16-bit unsigned value from a byte slice in little-endian order.
///
/// # Panics
/// Panics if `p.len() < 2`.
///
/// # Examples
///
/// ```
/// use tcc_core::arch::read16le;
///
/// let data = [0x34u8, 0x12];
/// assert_eq!(read16le(&data), 0x1234);
/// ```
///
/// Replaces: `static inline uint16_t read16le(unsigned char *p)`
#[inline]
pub fn read16le(p: &[u8]) -> u16 {
    debug_assert!(p.len() >= 2, "read16le: buffer must be at least 2 bytes");
    u16::from(p[0]) | (u16::from(p[1]) << 8)
}

/// Writes a 16-bit unsigned value to a byte slice in little-endian order.
///
/// # Panics
/// Panics if `p.len() < 2`.
///
/// # Examples
///
/// ```
/// use tcc_core::arch::write16le;
///
/// let mut data = [0u8; 2];
/// write16le(&mut data, 0x1234);
/// assert_eq!(data, [0x34, 0x12]);
/// ```
///
/// Replaces: `static inline void write16le(unsigned char *p, uint16_t x)`
#[inline]
pub fn write16le(p: &mut [u8], x: u16) {
    debug_assert!(p.len() >= 2, "write16le: buffer must be at least 2 bytes");
    p[0] = (x & 0xFF) as u8;
    p[1] = ((x >> 8) & 0xFF) as u8;
}

/// Reads a 32-bit unsigned value from a byte slice in little-endian order.
///
/// # Panics
/// Panics if `p.len() < 4`.
///
/// # Examples
///
/// ```
/// use tcc_core::arch::read32le;
///
/// let data = [0x78u8, 0x56, 0x34, 0x12];
/// assert_eq!(read32le(&data), 0x12345678);
/// ```
///
/// Replaces: `static inline uint32_t read32le(unsigned char *p)`
#[inline]
pub fn read32le(p: &[u8]) -> u32 {
    debug_assert!(p.len() >= 4, "read32le: buffer must be at least 4 bytes");
    u32::from(read16le(p)) | (u32::from(read16le(&p[2..])) << 16)
}

/// Writes a 32-bit unsigned value to a byte slice in little-endian order.
///
/// # Panics
/// Panics if `p.len() < 4`.
///
/// # Examples
///
/// ```
/// use tcc_core::arch::write32le;
///
/// let mut data = [0u8; 4];
/// write32le(&mut data, 0x12345678);
/// assert_eq!(data, [0x78, 0x56, 0x34, 0x12]);
/// ```
///
/// Replaces: `static inline void write32le(unsigned char *p, uint32_t x)`
#[inline]
pub fn write32le(p: &mut [u8], x: u32) {
    debug_assert!(p.len() >= 4, "write32le: buffer must be at least 4 bytes");
    write16le(p, x as u16);
    write16le(&mut p[2..], (x >> 16) as u16);
}

/// Adds a signed 32-bit value to a 32-bit little-endian value in place.
///
/// Reads the current value at `p`, adds `x`, and writes the result back.
///
/// # Panics
/// Panics if `p.len() < 4`.
///
/// # Examples
///
/// ```
/// use tcc_core::arch::add32le;
///
/// let mut data = [0x78u8, 0x56, 0x34, 0x12]; // 0x12345678
/// add32le(&mut data, 1);
/// assert_eq!(data, [0x79, 0x56, 0x34, 0x12]); // 0x12345679
/// ```
///
/// Replaces: `static inline void add32le(unsigned char *p, int32_t x)`
#[inline]
pub fn add32le(p: &mut [u8], x: i32) {
    debug_assert!(p.len() >= 4, "add32le: buffer must be at least 4 bytes");
    write32le(p, (read32le(p) as i32).wrapping_add(x) as u32);
}

/// Reads a 64-bit unsigned value from a byte slice in little-endian order.
///
/// # Panics
/// Panics if `p.len() < 8`.
///
/// # Examples
///
/// ```
/// use tcc_core::arch::read64le;
///
/// let data = [0xEF, 0xCD, 0xAB, 0x90, 0x78, 0x56, 0x34, 0x12];
/// assert_eq!(read64le(&data), 0x1234567890ABCDEF);
/// ```
///
/// Replaces: `static inline uint64_t read64le(unsigned char *p)`
#[inline]
pub fn read64le(p: &[u8]) -> u64 {
    debug_assert!(p.len() >= 8, "read64le: buffer must be at least 8 bytes");
    u64::from(read32le(p)) | (u64::from(read32le(&p[4..])) << 32)
}

/// Writes a 64-bit unsigned value to a byte slice in little-endian order.
///
/// # Panics
/// Panics if `p.len() < 8`.
///
/// # Examples
///
/// ```
/// use tcc_core::arch::write64le;
///
/// let mut data = [0u8; 8];
/// write64le(&mut data, 0x1234567890ABCDEF);
/// assert_eq!(data, [0xEF, 0xCD, 0xAB, 0x90, 0x78, 0x56, 0x34, 0x12]);
/// ```
///
/// Replaces: `static inline void write64le(unsigned char *p, uint64_t x)`
#[inline]
pub fn write64le(p: &mut [u8], x: u64) {
    debug_assert!(p.len() >= 8, "write64le: buffer must be at least 8 bytes");
    write32le(p, x as u32);
    write32le(&mut p[4..], (x >> 32) as u32);
}

/// Adds a signed 64-bit value to a 64-bit little-endian value in place.
///
/// Reads the current value at `p`, adds `x`, and writes the result back.
///
/// # Panics
/// Panics if `p.len() < 8`.
///
/// # Examples
///
/// ```
/// use tcc_core::arch::add64le;
///
/// let mut data = [0xEF, 0xCD, 0xAB, 0x90, 0x78, 0x56, 0x34, 0x12];
/// add64le(&mut data, 1);
/// assert_eq!(data, [0xF0, 0xCD, 0xAB, 0x90, 0x78, 0x56, 0x34, 0x12]);
/// ```
///
/// Replaces: `static inline void add64le(unsigned char *p, int64_t x)`
#[inline]
pub fn add64le(p: &mut [u8], x: i64) {
    debug_assert!(p.len() >= 8, "add64le: buffer must be at least 8 bytes");
    write64le(p, (read64le(p) as i64).wrapping_add(x) as u64);
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- TargetArch tests ---

    #[test]
    fn test_target_arch_debug_display() {
        assert_eq!(format!("{:?}", TargetArch::I386), "I386");
        assert_eq!(format!("{:?}", TargetArch::X86_64), "X86_64");
        assert_eq!(format!("{:?}", TargetArch::Arm), "Arm");
        assert_eq!(format!("{:?}", TargetArch::Arm64), "Arm64");
        assert_eq!(format!("{:?}", TargetArch::Riscv64), "Riscv64");
        assert_eq!(format!("{:?}", TargetArch::C67), "C67");
        assert_eq!(format!("{:?}", TargetArch::Il), "Il");
    }

    #[test]
    fn test_target_arch_display() {
        assert_eq!(format!("{}", TargetArch::I386), "i386");
        assert_eq!(format!("{}", TargetArch::X86_64), "x86_64");
        assert_eq!(format!("{}", TargetArch::Arm), "arm");
        assert_eq!(format!("{}", TargetArch::Arm64), "arm64");
        assert_eq!(format!("{}", TargetArch::Riscv64), "riscv64");
        assert_eq!(format!("{}", TargetArch::C67), "c67");
        assert_eq!(format!("{}", TargetArch::Il), "il");
    }

    #[test]
    fn test_target_arch_equality() {
        assert_eq!(TargetArch::X86_64, TargetArch::X86_64);
        assert_ne!(TargetArch::X86_64, TargetArch::I386);
    }

    #[test]
    fn test_target_arch_clone_copy() {
        let a = TargetArch::Arm64;
        let b = a; // Copy
        let c = a.clone(); // Clone
        assert_eq!(a, b);
        assert_eq!(a, c);
    }

    #[test]
    fn test_target_arch_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(TargetArch::I386);
        set.insert(TargetArch::X86_64);
        set.insert(TargetArch::I386); // duplicate
        assert_eq!(set.len(), 2);
    }

    // --- Register class constant tests ---

    #[test]
    fn test_register_class_constants() {
        assert_eq!(RC_INT, 0x0001);
        assert_eq!(RC_FLOAT, 0x0002);
        // They should be distinct
        assert_eq!(RC_INT & RC_FLOAT, 0);
    }

    // --- GOT/PLT entry constant tests ---

    #[test]
    fn test_gotplt_constants() {
        assert_eq!(NO_GOTPLT_ENTRY, 0);
        assert_eq!(BUILD_GOT_ONLY, 1);
        assert_eq!(AUTO_GOTPLT_ENTRY, 2);
        assert_eq!(ALWAYS_GOTPLT_ENTRY, 3);
    }

    // --- native_target tests ---

    #[test]
    fn test_native_target_returns_some_on_supported_arch() {
        // This test passes on any of the supported host architectures.
        // On unsupported hosts (e.g., MIPS, PowerPC), it returns None.
        let target = native_target();
        #[cfg(target_arch = "x86_64")]
        assert_eq!(target, Some(TargetArch::X86_64));
        #[cfg(target_arch = "x86")]
        assert_eq!(target, Some(TargetArch::I386));
        #[cfg(target_arch = "arm")]
        assert_eq!(target, Some(TargetArch::Arm));
        #[cfg(target_arch = "aarch64")]
        assert_eq!(target, Some(TargetArch::Arm64));
        #[cfg(all(target_arch = "riscv64", target_pointer_width = "64"))]
        assert_eq!(target, Some(TargetArch::Riscv64));
        // Ensure it's at least Some on common CI architectures
        #[cfg(any(target_arch = "x86_64", target_arch = "x86", target_arch = "aarch64"))]
        assert!(target.is_some());
    }

    // --- create_backend tests ---

    #[test]
    fn test_create_backend_unsupported_arch_returns_error() {
        // Test with architectures that might not be compiled in.
        // We use C67 and IL which are typically not in default features.
        #[cfg(not(feature = "c67"))]
        {
            let result = create_backend(TargetArch::C67);
            assert!(result.is_err());
            if let Err(err) = result {
                let msg = format!("{}", err);
                assert!(msg.contains("not compiled in"), "Error message: {}", msg);
            }
        }

        #[cfg(not(feature = "il"))]
        {
            let result = create_backend(TargetArch::Il);
            assert!(result.is_err());
        }
    }

    // --- Little-endian utility function tests ---

    #[test]
    fn test_read16le() {
        assert_eq!(read16le(&[0x00, 0x00]), 0x0000);
        assert_eq!(read16le(&[0xFF, 0xFF]), 0xFFFF);
        assert_eq!(read16le(&[0x34, 0x12]), 0x1234);
        assert_eq!(read16le(&[0x01, 0x00]), 0x0001);
        assert_eq!(read16le(&[0x00, 0x80]), 0x8000);
    }

    #[test]
    fn test_write16le() {
        let mut buf = [0u8; 2];
        write16le(&mut buf, 0x1234);
        assert_eq!(buf, [0x34, 0x12]);

        write16le(&mut buf, 0x0000);
        assert_eq!(buf, [0x00, 0x00]);

        write16le(&mut buf, 0xFFFF);
        assert_eq!(buf, [0xFF, 0xFF]);
    }

    #[test]
    fn test_read16le_write16le_roundtrip() {
        for val in [0u16, 1, 0x1234, 0x8000, 0xFFFF, 0x00FF, 0xFF00] {
            let mut buf = [0u8; 2];
            write16le(&mut buf, val);
            assert_eq!(read16le(&buf), val, "roundtrip failed for {:#06x}", val);
        }
    }

    #[test]
    fn test_read32le() {
        assert_eq!(read32le(&[0x78, 0x56, 0x34, 0x12]), 0x12345678);
        assert_eq!(read32le(&[0x00, 0x00, 0x00, 0x00]), 0x00000000);
        assert_eq!(read32le(&[0xFF, 0xFF, 0xFF, 0xFF]), 0xFFFFFFFF);
        assert_eq!(read32le(&[0x01, 0x00, 0x00, 0x00]), 0x00000001);
    }

    #[test]
    fn test_write32le() {
        let mut buf = [0u8; 4];
        write32le(&mut buf, 0x12345678);
        assert_eq!(buf, [0x78, 0x56, 0x34, 0x12]);

        write32le(&mut buf, 0xDEADBEEF);
        assert_eq!(buf, [0xEF, 0xBE, 0xAD, 0xDE]);
    }

    #[test]
    fn test_read32le_write32le_roundtrip() {
        for val in [0u32, 1, 0x12345678, 0x80000000, 0xFFFFFFFF, 0xDEADBEEF] {
            let mut buf = [0u8; 4];
            write32le(&mut buf, val);
            assert_eq!(read32le(&buf), val, "roundtrip failed for {:#010x}", val);
        }
    }

    #[test]
    fn test_add32le() {
        let mut buf = [0x78, 0x56, 0x34, 0x12]; // 0x12345678
        add32le(&mut buf, 1);
        assert_eq!(read32le(&buf), 0x12345679);

        add32le(&mut buf, -1);
        assert_eq!(read32le(&buf), 0x12345678);

        // Test wrapping behavior (overflow)
        let mut buf2 = [0xFF, 0xFF, 0xFF, 0xFF]; // 0xFFFFFFFF
        add32le(&mut buf2, 1);
        assert_eq!(read32le(&buf2), 0x00000000);

        // Test negative addition
        let mut buf3 = [0x00, 0x00, 0x00, 0x00]; // 0
        add32le(&mut buf3, -1);
        assert_eq!(read32le(&buf3), 0xFFFFFFFF);
    }

    #[test]
    fn test_read64le() {
        assert_eq!(
            read64le(&[0xEF, 0xCD, 0xAB, 0x90, 0x78, 0x56, 0x34, 0x12]),
            0x1234567890ABCDEF
        );
        assert_eq!(
            read64le(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
            0
        );
        assert_eq!(
            read64le(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]),
            0xFFFFFFFFFFFFFFFF
        );
    }

    #[test]
    fn test_write64le() {
        let mut buf = [0u8; 8];
        write64le(&mut buf, 0x1234567890ABCDEF);
        assert_eq!(buf, [0xEF, 0xCD, 0xAB, 0x90, 0x78, 0x56, 0x34, 0x12]);
    }

    #[test]
    fn test_read64le_write64le_roundtrip() {
        for val in [
            0u64,
            1,
            0x1234567890ABCDEF,
            0x8000000000000000,
            0xFFFFFFFFFFFFFFFF,
            0xDEADBEEFCAFEBABE,
        ] {
            let mut buf = [0u8; 8];
            write64le(&mut buf, val);
            assert_eq!(read64le(&buf), val, "roundtrip failed for {:#018x}", val);
        }
    }

    #[test]
    fn test_add64le() {
        let mut buf = [0xEF, 0xCD, 0xAB, 0x90, 0x78, 0x56, 0x34, 0x12];
        add64le(&mut buf, 1);
        assert_eq!(read64le(&buf), 0x1234567890ABCDF0);

        add64le(&mut buf, -1);
        assert_eq!(read64le(&buf), 0x1234567890ABCDEF);

        // Wrapping
        let mut buf2 = [0xFF; 8];
        add64le(&mut buf2, 1);
        assert_eq!(read64le(&buf2), 0);

        let mut buf3 = [0x00; 8];
        add64le(&mut buf3, -1);
        assert_eq!(read64le(&buf3), 0xFFFFFFFFFFFFFFFF);
    }

    #[test]
    fn test_read_write_with_extra_bytes() {
        // Ensure functions work when the slice is larger than minimum
        let data = [0x34u8, 0x12, 0xFF, 0xFF];
        assert_eq!(read16le(&data), 0x1234);

        let data = [0x78, 0x56, 0x34, 0x12, 0xAA, 0xBB];
        assert_eq!(read32le(&data), 0x12345678);

        let mut buf = [0u8; 16];
        write64le(&mut buf, 0xCAFEBABE);
        assert_eq!(read64le(&buf), 0xCAFEBABE);
        // Extra bytes should be untouched
        assert_eq!(buf[8..], [0u8; 8]);
    }

    #[test]
    fn test_add32le_large_values() {
        let mut buf = [0x00, 0x00, 0x00, 0x80]; // 0x80000000 (INT_MIN as u32)
        add32le(&mut buf, i32::MIN); // -2147483648
        assert_eq!(read32le(&buf), 0x00000000);
    }

    #[test]
    fn test_add64le_large_values() {
        let mut buf = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80]; // 0x8000000000000000
        add64le(&mut buf, i64::MIN);
        assert_eq!(read64le(&buf), 0);
    }
}
