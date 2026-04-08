//! AArch64 (ARM64) code generation backend for TCC.
//!
//! This module is the root of the ARM64 backend, which implements the
//! [`CodegenBackend`] trait for the AArch64 (ARMv8-A) architecture.
//! It declares submodules, defines the [`Arm64Backend`] struct, exports all
//! AArch64-specific constants (register definitions, register class bitmasks,
//! ELF/linker constants, architecture characteristics), and delegates trait
//! method implementations to the appropriate submodule functions.
//!
//! # Source Files
//!
//! Port of three C source files:
//! - `arm64-gen.c` (2,209 lines) — Code generator: instruction emission,
//!   register allocation, AAPCS64 calling convention, HFA support
//! - `arm64-link.c` (322 lines) — ELF linker / relocation handler: all
//!   AArch64 relocation types, PLT/GOT generation
//! - `arm64-asm.c` (94 lines) — Minimal inline assembler stub: byte/word
//!   emission helpers and error-reporting stubs for unsupported operations
//!
//! Total: ~2,625 lines of C → Rust.
//!
//! # Feature Gate
//!
//! This module is only compiled when the `arm64` Cargo feature is enabled.
//! The parent `arch/mod.rs` gates inclusion with `#[cfg(feature = "arm64")]`.
//!
//! # Architecture Notes
//!
//! - ARMv8-A A64 instruction set (fixed 32-bit instruction width)
//! - AAPCS64 calling convention with HFA (Homogeneous Floating-point
//!   Aggregate) support for efficient struct passing
//! - 19 allocatable integer registers (x0-x18), x30 as special temp/link
//! - 8 allocatable SIMD/FP registers (v0-v7)
//! - 8-byte pointer size, 16-byte long double, unsigned char by default
//! - PC-relative PLT entries, 64 KiB page size
//!
//! # Submodule Organization
//!
//! Unlike i386/ARM/RISC-V backends, there is **no** `tokens` submodule —
//! the original TCC source has no `arm64-tok.h` or `arm64-asm.h` header.

// ---------------------------------------------------------------------------
// Submodule declarations
// ---------------------------------------------------------------------------

/// AArch64 code generation — instruction emission, register allocation,
/// AAPCS64 calling convention, HFA detection, expression-to-machine-code
/// translation.
/// Port of `arm64-gen.c` (2,209 lines).
pub mod gen;

/// AArch64 relocation and linking — ELF relocation type classification,
/// PLT/GOT generation, relocation application for all AArch64 reloc types.
/// Port of `arm64-link.c` (322 lines).
pub mod link;

/// AArch64 minimal assembly support — byte/word emission helpers for code
/// section output, and error-reporting stubs for unsupported inline asm.
/// Port of `arm64-asm.c` (94 lines).
pub mod asm;

// NOTE: No `tokens` submodule — arm64 has no separate token/register
// definition header in the original TCC source.

// ---------------------------------------------------------------------------
// Imports from within tcc-core (verified against depends_on_files whitelist)
// ---------------------------------------------------------------------------

use crate::arch::CodegenBackend;
use crate::error::TccResult;
use crate::types::{CType, SValue, Sym};

// ===========================================================================
// Register Constants
// Source: arm64-gen.c lines 14-19 (TARGET_DEFS_ONLY section)
// ===========================================================================

/// Number of registers available to the register allocator.
///
/// The ARM64 backend uses 28 registers:
/// - 19 general-purpose integer: x0-x18 (indices 0-18)
/// - 1 special link register: x30 (index 19, NOT in RC_INT)
/// - 8 SIMD/floating-point: v0-v7 (indices 20-27)
///
/// Note: x19-x28 are callee-saved and not used by the allocator.
/// x29 (FP) and SP are reserved. x30 (LR) is a special temp register.
///
/// Source: `arm64-gen.c` line 15 — `#define NB_REGS 28`
pub const NB_REGS: usize = 28;

/// Integer register index mapping: `TREG_R(x)` = x for x in 0..=18.
///
/// Maps logical register number to TCC register index. For AArch64,
/// the mapping is identity: x0 = index 0, x1 = index 1, ..., x18 = index 18.
///
/// Source: `arm64-gen.c` line 17 — `#define TREG_R(x) (x)`
///
/// # Examples
/// ```ignore
/// assert_eq!(TREG_R(0), 0);  // x0
/// assert_eq!(TREG_R(18), 18); // x18
/// ```
#[allow(non_snake_case)]
#[inline]
pub const fn TREG_R(x: i32) -> i32 {
    x
}

/// x30 (link register) gets special index 19.
///
/// x30 is used as a temporary register during code generation but is
/// NOT included in the RC_INT register class — it has its own dedicated
/// class `RC_R30` to prevent the register allocator from treating it as
/// a general-purpose register.
///
/// Source: `arm64-gen.c` line 18 — `#define TREG_R30 19`
pub const TREG_R30: i32 = 19;

/// Float/SIMD register index mapping: `TREG_F(x)` = x + 20 for x in 0..=7.
///
/// Maps SIMD/FP register number to TCC register index. v0 = index 20,
/// v1 = index 21, ..., v7 = index 27.
///
/// Source: `arm64-gen.c` line 19 — `#define TREG_F(x) ((x) + 20)`
///
/// # Examples
/// ```ignore
/// assert_eq!(TREG_F(0), 20); // v0
/// assert_eq!(TREG_F(7), 27); // v7
/// ```
#[allow(non_snake_case)]
#[inline]
pub const fn TREG_F(x: i32) -> i32 {
    x + 20
}

// ===========================================================================
// Register Class Constants (bitmask-based allocation framework)
// Source: arm64-gen.c lines 21-32 (TARGET_DEFS_ONLY section)
// ===========================================================================
//
// Register classes are bitmasks used by the register allocator. Each register
// belongs to one or more classes, and the allocator selects a register from
// the requested class. The hierarchy is:
//   - RC_INT / RC_FLOAT: Generic classes (any integer or float register)
//   - RC_R(n) / RC_F(n): Per-register specific classes
//   - RC_R30: Special class for x30 (not in RC_INT)

/// Generic integer register class — any of x0-x18.
///
/// Does NOT include x30 (which has special class `RC_R30`).
///
/// Source: `arm64-gen.c` line 22 — `#define RC_INT 0x0001`
pub const RC_INT: i32 = 0x0001;

/// Generic floating-point/SIMD register class — any of v0-v7.
///
/// Source: `arm64-gen.c` line 23 — `#define RC_FLOAT 0x0002`
pub const RC_FLOAT: i32 = 0x0002;

/// Per-register class for integer registers: `RC_R(x)` = 1 << (2 + x).
///
/// Each integer register x0-x18 has a unique bit in the class bitmask,
/// allowing the allocator to request a specific register when needed
/// (e.g., for ABI-mandated register usage in function calls).
///
/// Source: `arm64-gen.c` line 24 — `#define RC_R(x) (1 << (2 + (x)))`
///
/// # Examples
/// ```ignore
/// assert_eq!(RC_R(0), 1 << 2);  // x0-specific class = 0x0004
/// assert_eq!(RC_R(18), 1 << 20); // x18-specific class
/// ```
#[allow(non_snake_case)]
#[inline]
pub const fn RC_R(x: i32) -> i32 {
    1 << (2 + x)
}

/// Special register class for x30 (link register): bit 21.
///
/// x30 is NOT in `RC_INT` — it has special use as a temporary register
/// for address computation and is the hardware link register for branch-
/// with-link instructions. It gets its own dedicated class so the
/// register allocator never accidentally uses it as a general integer
/// register.
///
/// Source: `arm64-gen.c` line 25 — `#define RC_R30 (1 << 21)`
pub const RC_R30: i32 = 1 << 21;

/// Per-register class for float/SIMD registers: `RC_F(x)` = 1 << (22 + x).
///
/// Each SIMD/FP register v0-v7 has a unique bit, allowing the allocator
/// to request specific float registers when required by the ABI.
///
/// Source: `arm64-gen.c` line 26 — `#define RC_F(x) (1 << (22 + (x)))`
///
/// # Examples
/// ```ignore
/// assert_eq!(RC_F(0), 1 << 22); // v0-specific class
/// assert_eq!(RC_F(7), 1 << 29); // v7-specific class
/// ```
#[allow(non_snake_case)]
#[inline]
pub const fn RC_F(x: i32) -> i32 {
    1 << (22 + x)
}

/// Integer return register class (x0).
///
/// Function return values of integer type are placed in x0.
///
/// Source: `arm64-gen.c` line 28 — `#define RC_IRET RC_R(0)`
pub const RC_IRET: i32 = RC_R(0);

/// Float return register class (v0).
///
/// Function return values of floating-point type are placed in v0.
///
/// Source: `arm64-gen.c` line 29 — `#define RC_FRET RC_F(0)`
pub const RC_FRET: i32 = RC_F(0);

/// Integer return register number (x0 = index 0).
///
/// Source: `arm64-gen.c` line 31 — `#define REG_IRET TREG_R(0)`
pub const REG_IRET: i32 = TREG_R(0);

/// Float return register number (v0 = index 20).
///
/// Source: `arm64-gen.c` line 32 — `#define REG_FRET TREG_F(0)`
pub const REG_FRET: i32 = TREG_F(0);

// ===========================================================================
// Architecture Size Constants
// Source: arm64-gen.c lines 34-39 (TARGET_DEFS_ONLY section)
// ===========================================================================

/// Pointer size in bytes (AArch64 is a 64-bit architecture).
///
/// Source: `arm64-gen.c` line 34 — `#define PTR_SIZE 8`
pub const PTR_SIZE: usize = 8;

/// Long double size in bytes (128-bit IEEE quad precision on AArch64 Linux).
///
/// Note: On macOS with `TCC_USING_DOUBLE_FOR_LDOUBLE`, this would be 8.
/// For the primary Linux target, the hardware supports 128-bit quad
/// precision floating-point.
///
/// Source: `arm64-gen.c` line 36 — `#define LDOUBLE_SIZE 16`
pub const LDOUBLE_SIZE: usize = 16;

/// Long double alignment in bytes.
///
/// Must match the ABI requirement for `long double` alignment on AArch64.
///
/// Source: `arm64-gen.c` line 37 — `#define LDOUBLE_ALIGN 16`
pub const LDOUBLE_ALIGN: usize = 16;

/// Maximum alignment supported for any type.
///
/// AArch64 supports up to 16-byte natural alignment for SIMD types
/// and `long double`.
///
/// Source: `arm64-gen.c` line 39 — `#define MAX_ALIGN 16`
pub const MAX_ALIGN: usize = 16;

// ===========================================================================
// Character Signedness and Return Value Promotion
// Source: arm64-gen.c lines 41-47 (TARGET_DEFS_ONLY section)
// ===========================================================================

/// Whether `char` type is unsigned on this target.
///
/// On AArch64 Linux, `char` is unsigned by default (unlike x86 where it
/// is signed). This matches the ARM ABI specification.
///
/// On AArch64 macOS, `char` would be signed — but for the primary Linux
/// target, this is `true`.
///
/// Source: `arm64-gen.c` lines 41-43 — `#define CHAR_IS_UNSIGNED`
pub const CHAR_IS_UNSIGNED: bool = true;

/// Whether return values need explicit extension at the caller side.
///
/// When `true`, values smaller than register width (e.g., `char`, `short`)
/// are zero/sign-extended to full 64-bit register width on return. This is
/// required for correct interoperability with non-TCC-compiled code.
///
/// Source: `arm64-gen.c` lines 45-47 — `#define PROMOTE_RET`
pub const PROMOTE_RET: bool = true;

// ===========================================================================
// ELF / Linker Constants
// Source: arm64-link.c lines 1-19 (TARGET_DEFS_ONLY section)
// ===========================================================================

/// ELF machine type for AArch64 (`EM_AARCH64` = 183).
///
/// Written into the ELF header's `e_machine` field to identify the target
/// architecture of the generated object/executable.
///
/// Source: `arm64-link.c` line 5 — `#define EM_TCC_TARGET EM_AARCH64`
pub const EM_TCC_TARGET: u16 = 183;

/// Default executable load address for AArch64 ELF binaries.
///
/// Source: `arm64-link.c` line 17 — `#define ELF_START_ADDR 0x00400000`
pub const ELF_START_ADDR: u64 = 0x00400000;

/// Default ELF page size (64 KiB for AArch64).
///
/// AArch64 commonly uses 64 KiB pages (the kernel can also use 4 KiB or
/// 16 KiB, but TCC uses 64 KiB as the standard alignment).
///
/// Source: `arm64-link.c` line 18 — `#define ELF_PAGE_SIZE 0x10000`
pub const ELF_PAGE_SIZE: u64 = 0x10000;

// --- Relocation type aliases ---
// Map architecture-neutral names to AArch64-specific ELF relocation constants.

/// Absolute 32-bit data relocation (`R_AARCH64_ABS32` = 258).
///
/// Source: `arm64-link.c` line 7 — `#define R_DATA_32 R_AARCH64_ABS32`
pub const R_DATA_32: i32 = 258;

/// Pointer-sized data relocation (`R_AARCH64_ABS64` = 257).
///
/// On AArch64, pointers are 64-bit, so this maps to R_AARCH64_ABS64.
///
/// Source: `arm64-link.c` line 8 — `#define R_DATA_PTR R_AARCH64_ABS64`
pub const R_DATA_PTR: i32 = 257;

/// PLT jump slot relocation (`R_AARCH64_JUMP_SLOT` = 1026).
///
/// Source: `arm64-link.c` line 9 — `#define R_JMP_SLOT R_AARCH64_JUMP_SLOT`
pub const R_JMP_SLOT: i32 = 1026;

/// GOT global data relocation (`R_AARCH64_GLOB_DAT` = 1025).
///
/// Source: `arm64-link.c` line 10 — `#define R_GLOB_DAT R_AARCH64_GLOB_DAT`
pub const R_GLOB_DAT: i32 = 1025;

/// Copy relocation for dynamic linking (`R_AARCH64_COPY` = 1024).
///
/// Source: `arm64-link.c` line 11 — `#define R_COPY R_AARCH64_COPY`
pub const R_COPY: i32 = 1024;

/// Relative relocation (`R_AARCH64_RELATIVE` = 1027).
///
/// Source: `arm64-link.c` line 12 — `#define R_RELATIVE R_AARCH64_RELATIVE`
pub const R_RELATIVE: i32 = 1027;

/// Number of AArch64 relocation types (`R_AARCH64_NUM` = 1028).
///
/// One past the highest relocation type value; used for bounds checking.
///
/// Source: `arm64-link.c` line 13 — `#define R_NUM R_AARCH64_NUM`
pub const R_NUM: i32 = 1028;

/// Whether PLT entries use PC-relative addressing in DLLs.
///
/// On AArch64, PLT entries use ADRP+ADD+BR sequences which are inherently
/// PC-relative, so this is `true`.
///
/// Source: `arm64-link.c` line 15 — `#define PCRELATIVE_DLLPLT 1`
pub const PCRELATIVE_DLLPLT: bool = true;

/// Whether DLL PLT entries need relocation.
///
/// On AArch64, PLT stubs in shared libraries require runtime relocation
/// of the GOT entries they reference.
///
/// Source: `arm64-link.c` line 16 — `#define RELOCATE_DLLPLT 1`
pub const RELOCATE_DLLPLT: bool = true;

// ===========================================================================
// Assembly Constants
// Source: arm64-asm.c lines 4-5 (TARGET_DEFS_ONLY section)
// ===========================================================================

/// Number of assembly registers recognized by the inline assembler.
///
/// For AArch64, this covers the primary general-purpose registers used
/// in constraint resolution.
///
/// Source: `arm64-asm.c` line 5 — `#define NB_ASM_REGS 16`
pub const NB_ASM_REGS: usize = 16;

// ===========================================================================
// Target Machine Predefined Macros
// Source: arm64-gen.c lines 55-61
// ===========================================================================

/// Target machine predefined macro string for AArch64.
///
/// Null-separated list of macros that the preprocessor defines automatically
/// when compiling for the AArch64 target. Contains:
/// - `__aarch64__` (standard AArch64 predefined macro)
/// - `__AARCH64EL__` (little-endian AArch64)
///
/// Note: On macOS (`TCC_TARGET_MACHO`), `__arm64__` would also be included.
/// For the primary Linux target, only the two shown macros are defined.
///
/// Source: `arm64-gen.c` lines 55-61 —
///   `"__aarch64__\0" ... "__AARCH64EL__\0"`
pub const TARGET_MACHINE_DEFS: &str = "__aarch64__\0__AARCH64EL__\0";

// ===========================================================================
// Register Class Table
// Source: arm64-gen.c lines 63-92
// ===========================================================================

/// Register class lookup table, indexed by TCC register number (0..27).
///
/// Each entry is a bitwise OR of register class flags indicating which
/// classes the register belongs to. The register allocator uses this
/// table to find a register matching the required class.
///
/// Layout:
///
/// | Index | HW Reg | Classes                |
/// |-------|--------|------------------------|
/// | 0     | x0     | `RC_INT \| RC_R(0)`    |
/// | 1     | x1     | `RC_INT \| RC_R(1)`    |
/// | ...   | ...    | ...                    |
/// | 18    | x18    | `RC_INT \| RC_R(18)`   |
/// | 19    | x30    | `RC_R30` only (NOT RC_INT!) |
/// | 20    | v0     | `RC_FLOAT \| RC_F(0)`  |
/// | 21    | v1     | `RC_FLOAT \| RC_F(1)`  |
/// | ...   | ...    | ...                    |
/// | 27    | v7     | `RC_FLOAT \| RC_F(7)`  |
///
/// **Important**: x30 (index 19) is intentionally NOT in `RC_INT`. It serves
/// as a dedicated temporary register for address computations and must not be
/// allocated as a general-purpose integer register by the register allocator.
///
/// Source: `arm64-gen.c` lines 63-92
pub const REG_CLASSES: [i32; NB_REGS] = [
    // x0-x18: general-purpose integer registers
    RC_INT | RC_R(0),   // index 0:  x0
    RC_INT | RC_R(1),   // index 1:  x1
    RC_INT | RC_R(2),   // index 2:  x2
    RC_INT | RC_R(3),   // index 3:  x3
    RC_INT | RC_R(4),   // index 4:  x4
    RC_INT | RC_R(5),   // index 5:  x5
    RC_INT | RC_R(6),   // index 6:  x6
    RC_INT | RC_R(7),   // index 7:  x7
    RC_INT | RC_R(8),   // index 8:  x8
    RC_INT | RC_R(9),   // index 9:  x9
    RC_INT | RC_R(10),  // index 10: x10
    RC_INT | RC_R(11),  // index 11: x11
    RC_INT | RC_R(12),  // index 12: x12
    RC_INT | RC_R(13),  // index 13: x13
    RC_INT | RC_R(14),  // index 14: x14
    RC_INT | RC_R(15),  // index 15: x15
    RC_INT | RC_R(16),  // index 16: x16
    RC_INT | RC_R(17),  // index 17: x17
    RC_INT | RC_R(18),  // index 18: x18
    // x30: link register — NOT in RC_INT (special temp use)
    RC_R30,              // index 19: x30
    // v0-v7: SIMD/floating-point registers
    RC_FLOAT | RC_F(0), // index 20: v0
    RC_FLOAT | RC_F(1), // index 21: v1
    RC_FLOAT | RC_F(2), // index 22: v2
    RC_FLOAT | RC_F(3), // index 23: v3
    RC_FLOAT | RC_F(4), // index 24: v4
    RC_FLOAT | RC_F(5), // index 25: v5
    RC_FLOAT | RC_F(6), // index 26: v6
    RC_FLOAT | RC_F(7), // index 27: v7
];

// ===========================================================================
// Arm64Backend — Architecture Backend State
// ===========================================================================

/// AArch64 code generation backend.
///
/// Contains all mutable state for AArch64 code generation that was previously
/// held in global/static variables in `arm64-gen.c`. This struct implements
/// the [`CodegenBackend`] trait, providing all architecture-specific code
/// generation, linking, and relocation functionality.
///
/// # State Fields
///
/// - [`func_sub_sp_offset`](Self::func_sub_sp_offset): Code section offset where
///   a NOP placeholder was emitted in the function prologue, to be backpatched
///   in the epilogue with `sub sp, sp, #N` once the total local variable size
///   is known.
/// - [`func_vc`](Self::func_vc): Whether the current function uses variadic
///   arguments (affects saving of q0-q7 in the prologue for va_arg access).
/// - Bounds-checking fields (`func_bound_*`): Only present when the `bcheck`
///   feature is enabled; track state needed for bounds-checking instrumentation
///   in function prologues and epilogues.
///
/// # Thread Safety
///
/// `Arm64Backend` is not `Send` or `Sync` by default. Each compilation
/// instance should have its own backend, which is guaranteed by the
/// `TCCState` ownership model (BUG-13 fix — full reentrancy). All
/// compilation state is encapsulated within this struct with no
/// module-level mutable statics.
pub struct Arm64Backend {
    /// Bounds checking: saved offset in bounds section for function prolog
    /// backpatching.
    ///
    /// Source: `arm64-gen.c` line 95 — `static addr_t func_bound_offset;`
    #[cfg(feature = "bcheck")]
    pub func_bound_offset: u64,

    /// Bounds checking: saved code position for function prolog backpatching.
    ///
    /// Source: `arm64-gen.c` line 96 — `static unsigned long func_bound_ind;`
    #[cfg(feature = "bcheck")]
    pub func_bound_ind: u64,

    /// Bounds checking: whether epilogue cleanup code is needed.
    ///
    /// Set to `true` when bounds-checked memory accesses are emitted within
    /// the function body, indicating that the epilogue must call the
    /// bounds-checking cleanup function.
    ///
    /// Source: `arm64-gen.c` line 97 — `ST_DATA int func_bound_add_epilog;`
    #[cfg(feature = "bcheck")]
    pub func_bound_add_epilog: bool,

    /// Saved position of NOP placeholder in function prologue.
    ///
    /// During `gfunc_prolog`, a NOP instruction is emitted as a placeholder
    /// for the `sub sp, sp, #N` stack allocation. During `gfunc_epilog`,
    /// this position is used to backpatch the NOP with the actual stack
    /// adjustment once the total local variable size is known.
    ///
    /// Source: `arm64-gen.c` line 99 — `static int func_sub_sp_offset;`
    pub func_sub_sp_offset: u64,

    /// Whether the current function uses variadic arguments.
    ///
    /// When `true`, the function prologue saves the SIMD/FP registers
    /// q0-q7 to the stack (in addition to x0-x7) so that `va_arg` can
    /// access floating-point variadic arguments. Set during `gfunc_prolog`
    /// based on the function type's variadic flag.
    ///
    /// Source: `arm64-gen.c` line 100 — `static int func_vc;`
    pub func_vc: bool,

    /// Code generation context — holds instruction buffer, value stack,
    /// pending relocations, and per-function state for the ARM64 backend.
    /// This is the primary working state used by `gen.rs` during code
    /// emission. Every `Arm64Backend` method that emits instructions
    /// accesses this context.
    pub ctx: gen::Arm64CodegenCtx,
}

impl Arm64Backend {
    /// Creates a new ARM64 backend with default (zero-initialized) state.
    ///
    /// All state fields start at zero/false, which is the correct initial
    /// state before any function compilation begins. Each function's
    /// prologue resets the relevant fields.
    pub fn new() -> Self {
        Self {
            #[cfg(feature = "bcheck")]
            func_bound_offset: 0,
            #[cfg(feature = "bcheck")]
            func_bound_ind: 0,
            #[cfg(feature = "bcheck")]
            func_bound_add_epilog: false,
            func_sub_sp_offset: 0,
            func_vc: false,
            ctx: gen::Arm64CodegenCtx::new(),
        }
    }
}

impl Default for Arm64Backend {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// CodegenBackend Trait Implementation
// Delegates code emission to gen.rs, linker operations to link.rs, and
// byte-level emission to asm.rs.
// ===========================================================================

impl CodegenBackend for Arm64Backend {
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
        gen::emit_opcode(self, c)
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
    // Optional methods — overridden with arm64 implementations
    // =======================================================================

    /// Emits a single byte to the code section.
    ///
    /// Delegates to `asm::g()` which writes to the current text section.
    fn g(&mut self, c: i32) -> TccResult<()> {
        asm::g(self, c)
    }

    /// Emits a 16-bit little-endian value to the code section.
    ///
    /// Delegates to `asm::gen_le16()`.
    fn gen_le16(&mut self, c: i32) -> TccResult<()> {
        asm::gen_le16(self, c)
    }

    /// Emits a 32-bit little-endian value to the code section.
    ///
    /// Used extensively by the ARM64 code generator since all A64 instructions
    /// are fixed 32-bit width. The `o()` function in gen.rs calls this to emit
    /// each instruction word.
    fn gen_le32(&mut self, c: i32) -> TccResult<()> {
        asm::gen_le32(self, c)
    }

    /// Generates test coverage counter instrumentation.
    ///
    /// Emits AArch64 instructions to increment a coverage counter at the
    /// location described by `sv`.
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
        link::relocate(rel_type, ptr, addr, val, 0)
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

    // --- Register count tests ---

    #[test]
    fn test_register_count() {
        assert_eq!(NB_REGS, 28);
        assert_eq!(NB_ASM_REGS, 16);
    }

    // --- TREG mapping tests ---

    #[test]
    fn test_treg_r_mapping() {
        // TREG_R(x) = x for x in 0..=18
        assert_eq!(TREG_R(0), 0);
        assert_eq!(TREG_R(1), 1);
        assert_eq!(TREG_R(8), 8);
        assert_eq!(TREG_R(18), 18);
    }

    #[test]
    fn test_treg_r30() {
        assert_eq!(TREG_R30, 19);
    }

    #[test]
    fn test_treg_f_mapping() {
        // TREG_F(x) = x + 20 for x in 0..=7
        assert_eq!(TREG_F(0), 20);
        assert_eq!(TREG_F(1), 21);
        assert_eq!(TREG_F(7), 27);
    }

    #[test]
    fn test_treg_no_overlap() {
        // Integer register indices 0-18 must not overlap with float indices 20-27
        // and the special x30 index 19 must be distinct
        let mut used = [false; NB_REGS];
        for i in 0..=18 {
            let idx = TREG_R(i) as usize;
            assert!(!used[idx], "TREG_R({}) overlaps at index {}", i, idx);
            used[idx] = true;
        }
        assert!(!used[TREG_R30 as usize], "TREG_R30 overlaps");
        used[TREG_R30 as usize] = true;
        for i in 0..=7 {
            let idx = TREG_F(i) as usize;
            assert!(!used[idx], "TREG_F({}) overlaps at index {}", i, idx);
            used[idx] = true;
        }
        // All 28 slots should be used
        assert!(used.iter().all(|&b| b));
    }

    // --- Register class bitmask tests ---

    #[test]
    fn test_rc_int_float_no_overlap() {
        assert_eq!(RC_INT, 0x0001);
        assert_eq!(RC_FLOAT, 0x0002);
        assert_eq!(RC_INT & RC_FLOAT, 0, "RC_INT and RC_FLOAT must not overlap");
    }

    #[test]
    fn test_rc_r_values() {
        assert_eq!(RC_R(0), 1 << 2);     // 0x0004
        assert_eq!(RC_R(1), 1 << 3);     // 0x0008
        assert_eq!(RC_R(18), 1 << 20);   // 0x00100000
    }

    #[test]
    fn test_rc_r30() {
        assert_eq!(RC_R30, 1 << 21);
        // RC_R30 must not overlap with any RC_R(n) for n in 0..=18
        for n in 0..=18 {
            assert_eq!(
                RC_R30 & RC_R(n),
                0,
                "RC_R30 overlaps with RC_R({})",
                n
            );
        }
    }

    #[test]
    fn test_rc_f_values() {
        assert_eq!(RC_F(0), 1 << 22);
        assert_eq!(RC_F(1), 1 << 23);
        assert_eq!(RC_F(7), 1 << 29);
    }

    #[test]
    fn test_rc_f_no_overlap_with_r() {
        // RC_F(n) must not overlap with any RC_R(n) or RC_R30
        for f in 0..=7 {
            for r in 0..=18 {
                assert_eq!(
                    RC_F(f) & RC_R(r),
                    0,
                    "RC_F({}) overlaps with RC_R({})",
                    f,
                    r
                );
            }
            assert_eq!(
                RC_F(f) & RC_R30,
                0,
                "RC_F({}) overlaps with RC_R30",
                f
            );
        }
    }

    #[test]
    fn test_return_register_classes() {
        assert_eq!(RC_IRET, RC_R(0));
        assert_eq!(RC_FRET, RC_F(0));
    }

    #[test]
    fn test_return_register_indices() {
        assert_eq!(REG_IRET, TREG_R(0));
        assert_eq!(REG_IRET, 0);
        assert_eq!(REG_FRET, TREG_F(0));
        assert_eq!(REG_FRET, 20);
    }

    // --- REG_CLASSES array tests ---

    #[test]
    fn test_reg_classes_length() {
        assert_eq!(REG_CLASSES.len(), NB_REGS);
        assert_eq!(REG_CLASSES.len(), 28);
    }

    #[test]
    fn test_reg_classes_integer_regs() {
        // x0-x18 (indices 0-18) must have RC_INT set
        for i in 0..=18 {
            assert_ne!(
                REG_CLASSES[i as usize] & RC_INT,
                0,
                "x{} (index {}) missing RC_INT",
                i,
                i
            );
            // Each must also have its specific RC_R(i) class
            assert_ne!(
                REG_CLASSES[i as usize] & RC_R(i),
                0,
                "x{} (index {}) missing RC_R({})",
                i,
                i,
                i
            );
        }
    }

    #[test]
    fn test_reg_classes_x30_not_rc_int() {
        // x30 (index 19) must NOT have RC_INT set
        assert_eq!(
            REG_CLASSES[19] & RC_INT,
            0,
            "x30 (index 19) must NOT be in RC_INT"
        );
        // x30 must have RC_R30 set
        assert_ne!(
            REG_CLASSES[19] & RC_R30,
            0,
            "x30 (index 19) must have RC_R30"
        );
    }

    #[test]
    fn test_reg_classes_float_regs() {
        // v0-v7 (indices 20-27) must have RC_FLOAT set
        for i in 0..=7 {
            let idx = (i + 20) as usize;
            assert_ne!(
                REG_CLASSES[idx] & RC_FLOAT,
                0,
                "v{} (index {}) missing RC_FLOAT",
                i,
                idx
            );
            // Each must also have its specific RC_F(i) class
            assert_ne!(
                REG_CLASSES[idx] & RC_F(i),
                0,
                "v{} (index {}) missing RC_F({})",
                i,
                idx,
                i
            );
        }
    }

    #[test]
    fn test_reg_classes_int_not_float() {
        // Integer registers must not have RC_FLOAT
        for i in 0..=18 {
            assert_eq!(
                REG_CLASSES[i as usize] & RC_FLOAT,
                0,
                "x{} should not have RC_FLOAT",
                i
            );
        }
    }

    #[test]
    fn test_reg_classes_float_not_int() {
        // Float registers must not have RC_INT
        for i in 0..=7 {
            let idx = (i + 20) as usize;
            assert_eq!(
                REG_CLASSES[idx] & RC_INT,
                0,
                "v{} should not have RC_INT",
                i
            );
        }
    }

    // --- Architecture constants tests ---

    #[test]
    fn test_ptr_size() {
        assert_eq!(PTR_SIZE, 8, "AArch64 is 64-bit");
    }

    #[test]
    fn test_ldouble_constants() {
        assert_eq!(LDOUBLE_SIZE, 16, "AArch64 long double is 128-bit");
        assert_eq!(LDOUBLE_ALIGN, 16);
    }

    #[test]
    fn test_max_align() {
        assert_eq!(MAX_ALIGN, 16);
    }

    #[test]
    fn test_char_is_unsigned() {
        assert!(CHAR_IS_UNSIGNED, "AArch64 Linux char is unsigned");
    }

    #[test]
    fn test_promote_ret() {
        assert!(PROMOTE_RET);
    }

    // --- ELF constants tests ---

    #[test]
    fn test_elf_machine() {
        assert_eq!(EM_TCC_TARGET, 183, "EM_AARCH64 = 183");
    }

    #[test]
    fn test_elf_start_addr() {
        assert_eq!(ELF_START_ADDR, 0x0040_0000);
    }

    #[test]
    fn test_elf_page_size() {
        assert_eq!(ELF_PAGE_SIZE, 0x10000, "64 KiB pages for AArch64");
    }

    #[test]
    fn test_relocation_constants() {
        assert_eq!(R_DATA_32, 258, "R_AARCH64_ABS32");
        assert_eq!(R_DATA_PTR, 257, "R_AARCH64_ABS64");
        assert_eq!(R_JMP_SLOT, 1026, "R_AARCH64_JUMP_SLOT");
        assert_eq!(R_GLOB_DAT, 1025, "R_AARCH64_GLOB_DAT");
        assert_eq!(R_COPY, 1024, "R_AARCH64_COPY");
        assert_eq!(R_RELATIVE, 1027, "R_AARCH64_RELATIVE");
        assert_eq!(R_NUM, 1028, "R_AARCH64_NUM");
    }

    #[test]
    fn test_plt_flags() {
        assert!(PCRELATIVE_DLLPLT);
        assert!(RELOCATE_DLLPLT);
    }

    // --- Target machine defs tests ---

    #[test]
    fn test_target_machine_defs() {
        let parts: Vec<&str> = TARGET_MACHINE_DEFS
            .split('\0')
            .filter(|s| !s.is_empty())
            .collect();
        assert!(parts.contains(&"__aarch64__"));
        assert!(parts.contains(&"__AARCH64EL__"));
        assert_eq!(parts.len(), 2);
    }

    // --- Arm64Backend struct tests ---

    #[test]
    fn test_backend_new() {
        let backend = Arm64Backend::new();
        assert_eq!(backend.func_sub_sp_offset, 0);
        assert!(!backend.func_vc);
    }

    #[test]
    fn test_backend_default() {
        let backend = Arm64Backend::default();
        assert_eq!(backend.func_sub_sp_offset, 0);
        assert!(!backend.func_vc);
    }

    #[cfg(feature = "bcheck")]
    #[test]
    fn test_backend_bcheck_fields() {
        let backend = Arm64Backend::new();
        assert_eq!(backend.func_bound_offset, 0);
        assert_eq!(backend.func_bound_ind, 0);
        assert!(!backend.func_bound_add_epilog);
    }

    // --- CodegenBackend trait accessor tests ---

    #[test]
    fn test_trait_accessors() {
        let backend = Arm64Backend::new();
        assert_eq!(backend.target_machine_defs(), TARGET_MACHINE_DEFS);
        assert_eq!(backend.reg_classes().len(), NB_REGS);
        assert_eq!(backend.nb_regs(), NB_REGS);
        assert_eq!(backend.ptr_size(), PTR_SIZE);
        assert_eq!(backend.elf_machine(), EM_TCC_TARGET);
        assert_eq!(backend.elf_start_addr(), ELF_START_ADDR);
        assert_eq!(backend.elf_page_size(), ELF_PAGE_SIZE);
        assert!(backend.pcrelative_dllplt());
        assert!(backend.relocate_dllplt());
    }
}
