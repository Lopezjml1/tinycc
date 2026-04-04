//! ARM (ARMv4+) architecture backend for TCC.
//!
//! Rust port of the ARM backend from the TCC C codebase:
//! - `arm-gen.c` (2,385 lines) — code generation, register allocation, calling conventions
//! - `arm-link.c` (445 lines) — ELF relocation handling, PLT/GOT generation
//! - `arm-asm.c` (3,092 lines) — ARM/Thumb assembly instruction encoding
//! - `arm-tok.h` (406 lines) — register names, condition codes, instruction tokens
//!
//! Total: 6,328 lines — the largest architecture backend in TCC.
//!
//! # Architecture Support
//!
//! - ARM (ARMv4+) and Thumb instruction sets
//! - VFP/NEON floating-point (optional, controlled by [`ArmBackend::vfp_enabled`])
//! - Soft-float and hard-float ABIs (selected via [`FloatAbi`])
//! - EABI calling convention (default, controlled by [`ArmBackend::eabi_enabled`])
//!
//! # Module Organization
//!
//! - [`gen`] — Code generation: register allocation, instruction emission,
//!   function prologue/epilogue, integer/float operations, VLA support
//! - [`link`] — ELF linking: relocation application, PLT/GOT entry creation,
//!   symbol resolution for ARM-specific relocation types
//! - [`asm`] — Assembly: ARM/Thumb instruction encoding, operand parsing,
//!   inline assembly constraint handling
//! - [`tokens`] — Token definitions: register names (r0-r15, aliases),
//!   condition codes, coprocessor registers, VFP/NEON register names,
//!   instruction mnemonics

pub mod gen;
pub mod link;
pub mod asm;
pub mod tokens;

use crate::arch::{CodegenBackend, RC_INT, RC_FLOAT};
use crate::error::{TccError, TccResult};
use crate::types::{CType, SValue, Sym, VT_FLOAT, VT_BTYPE};

// ===========================================================================
// Register count constants
// From arm-gen.c TARGET_DEFS_ONLY section, lines 26-44
// ===========================================================================

/// Number of available registers with VFP support enabled.
///
/// Includes: r0-r3, r12 (5 integer) + f0-f7 (8 VFP float) = 13 total.
/// These are the registers managed by TCC's register allocator.
/// SP (r13) and LR (r14) are special-purpose and not allocated.
pub const NB_REGS_VFP: usize = 13;

/// Number of available registers without VFP support.
///
/// Includes: r0-r3, r12 (5 integer) + f0-f3 (4 FPA float) = 9 total.
/// When VFP is disabled, only the basic FPA register set is available
/// for floating-point operations (software emulation path).
pub const NB_REGS_NO_VFP: usize = 9;

/// Default CPU version: ARMv5.
///
/// ARMv5 is chosen as the default because it supports the BLX instruction
/// (Branch with Link and eXchange) needed for ARM/Thumb interworking.
/// Can be overridden by `-mcpu=` option. Values: 4=ARMv4, 5=ARMv5,
/// 6=ARMv6, 7=ARMv7.
pub const DEFAULT_CONFIG_TCC_CPUVER: u32 = 5;

// ===========================================================================
// Register class bitmask constants
// From arm-gen.c TARGET_DEFS_ONLY section, lines 46-73
//
// Each register gets a unique bit in the register class bitmask.
// RC_INT and RC_FLOAT are generic class markers from arch/mod.rs.
// The register allocator finds registers by ANDing the desired class
// mask with each register's class bits.
// ===========================================================================

/// Register class: r0 — first argument, integer return value
pub const RC_R0: i32 = 0x0004;
/// Register class: r1 — second argument, high word of 64-bit return
pub const RC_R1: i32 = 0x0008;
/// Register class: r2 — third argument
pub const RC_R2: i32 = 0x0010;
/// Register class: r3 — fourth argument
pub const RC_R3: i32 = 0x0020;
/// Register class: r12 — intra-procedure-call scratch register (IP)
pub const RC_R12: i32 = 0x0040;
/// Register class: f0/d0/s0 — first float argument, float return value
pub const RC_F0: i32 = 0x0080;
/// Register class: f1/d1/s2 — second float argument
pub const RC_F1: i32 = 0x0100;
/// Register class: f2/d2/s4 — third float argument
pub const RC_F2: i32 = 0x0200;
/// Register class: f3/d3/s6 — fourth float argument
pub const RC_F3: i32 = 0x0400;
/// Register class: f4/d4/s8 (VFP-only, not available without VFP)
pub const RC_F4: i32 = 0x0800;
/// Register class: f5/d5/s10 (VFP-only)
pub const RC_F5: i32 = 0x1000;
/// Register class: f6/d6/s12 (VFP-only)
pub const RC_F6: i32 = 0x2000;
/// Register class: f7/d7/s14 (VFP-only)
pub const RC_F7: i32 = 0x4000;

/// Integer return register class (r0)
pub const RC_IRET: i32 = RC_R0;
/// Second integer return register class (r1) — high word of `long long`
pub const RC_IRE2: i32 = RC_R1;
/// Floating-point return register class (f0/d0)
pub const RC_FRET: i32 = RC_F0;

// ===========================================================================
// TCC register indices (TREG_*)
// From arm-gen.c lines 55-73
//
// These are indices into the register allocator's arrays and the
// reg_classes arrays. They are NOT ARM hardware register numbers
// (ARM r12 is TREG index 4, not 12).
// ===========================================================================

/// TCC register index for r0
pub const TREG_R0: usize = 0;
/// TCC register index for r1
pub const TREG_R1: usize = 1;
/// TCC register index for r2
pub const TREG_R2: usize = 2;
/// TCC register index for r3
pub const TREG_R3: usize = 3;
/// TCC register index for r12 (IP — intra-procedure-call scratch)
pub const TREG_R12: usize = 4;
/// TCC register index for VFP d0 (first float register)
pub const TREG_F0: usize = 5;
/// TCC register index for VFP d1
pub const TREG_F1: usize = 6;
/// TCC register index for VFP d2
pub const TREG_F2: usize = 7;
/// TCC register index for VFP d3
pub const TREG_F3: usize = 8;
/// TCC register index for VFP d4 (VFP-only, beyond basic FPA set)
pub const TREG_F4: usize = 9;
/// TCC register index for VFP d5 (VFP-only)
pub const TREG_F5: usize = 10;
/// TCC register index for VFP d6 (VFP-only)
pub const TREG_F6: usize = 11;
/// TCC register index for VFP d7 (VFP-only)
pub const TREG_F7: usize = 12;
/// TCC special index for SP (r13) — not allocatable, used in address calculations
pub const TREG_SP: usize = 13;
/// TCC special index for LR (r14) — link register, not allocatable
pub const TREG_LR: usize = 14;

/// Integer return register index — maps to r0
pub const REG_IRET: usize = TREG_R0;
/// Second integer return register index — maps to r1
pub const REG_IRE2: usize = TREG_R1;
/// Floating-point return register index — maps to d0
pub const REG_FRET: usize = TREG_F0;

// ===========================================================================
// Architecture size constants
// From arm-gen.c lines 75-90 and tcc.h
// ===========================================================================

/// Pointer size in bytes for ARM (32-bit architecture).
pub const PTR_SIZE: usize = 4;

/// Long double size in bytes on ARM.
///
/// ARM treats `long double` the same as `double` (8 bytes, IEEE 754
/// binary64). Unlike x86 where `long double` is 80-bit extended
/// precision, ARM has no native extended precision format.
pub const LDOUBLE_SIZE: usize = 8;

/// Long double alignment under EABI (8-byte aligned).
///
/// EABI requires 8-byte alignment for 64-bit types including `double`
/// and `long double`, matching the natural alignment of doubleword
/// load/store instructions (LDRD/STRD).
pub const LDOUBLE_ALIGN_EABI: usize = 8;

/// Long double alignment without EABI (4-byte aligned).
///
/// Legacy (non-EABI) ARM calling conventions only require 4-byte
/// alignment for all types.
pub const LDOUBLE_ALIGN_NO_EABI: usize = 4;

/// Maximum alignment supported by `__attribute__((aligned(N)))` on ARM.
pub const MAX_ALIGN: usize = 8;

/// ARM uses unsigned `char` by default (unlike x86 which uses signed `char`).
///
/// This matches the ARM ABI specification and GCC's default behavior
/// on ARM targets. Affects how character literals and `char` variables
/// are sign-extended.
pub const CHAR_IS_UNSIGNED: bool = true;

/// ARM evaluates function parameters in reverse order.
///
/// When `true`, function arguments are pushed right-to-left onto the
/// stack/registers. This affects how TCC's `gfunc_call()` processes
/// the argument value stack.
pub const INVERT_FUNC_PARAMS: bool = true;

// ===========================================================================
// ELF constants
// From arm-link.c lines 1-14
// ===========================================================================

/// ARM ELF machine type constant (EM_ARM = 40).
///
/// Used in the ELF header `e_machine` field to identify ARM object files.
pub const EM_TCC_TARGET: u16 = 40;

/// Default ELF program entry virtual address for ARM executables.
///
/// ARM Linux executables conventionally start at 0x10000 (64KB), leaving
/// the first 64KB unmapped as a guard for null pointer dereferences.
pub const ELF_START_ADDR: u64 = 0x0001_0000;

/// ELF page size for ARM segment alignment (64KB).
///
/// ARM Linux uses 64KB page alignment for ELF segments. This is larger
/// than the typical 4KB hardware page size to accommodate transparent
/// huge pages and various ARM SoC configurations.
pub const ELF_PAGE_SIZE: u64 = 0x0001_0000;

/// ARM uses PC-relative PLT entries for position-independent dynamic linking.
pub const PCRELATIVE_DLLPLT: bool = true;

/// ARM requires PLT entry relocation during dynamic linking.
pub const RELOCATE_DLLPLT: bool = true;

// ===========================================================================
// Target machine preprocessor definitions
// From arm-gen.c lines 144-157
//
// Null-separated string of predefined macros that the preprocessor
// defines automatically when targeting ARM. The trait method
// target_machine_defs() returns this string.
// ===========================================================================

/// Target machine predefined macros for ARM with EABI.
///
/// Null-character separated list of macro names. The preprocessor defines
/// each as `1` when targeting ARM. Includes `__ARM_EABI__` for EABI mode.
pub const TARGET_MACHINE_DEFS: &str = concat!(
    "__arm__\0",
    "__arm\0",
    "arm\0",
    "__arm_elf__\0",
    "__arm_elf\0",
    "arm_elf\0",
    "__ARM_ARCH_4__\0",
    "__ARMEL__\0",
    "__APCS_32__\0",
    "__ARM_EABI__\0",
);

/// Target machine predefined macros for ARM without EABI.
///
/// Same as [`TARGET_MACHINE_DEFS`] but excludes the `__ARM_EABI__` macro.
const TARGET_MACHINE_DEFS_NO_EABI: &str = concat!(
    "__arm__\0",
    "__arm\0",
    "arm\0",
    "__arm_elf__\0",
    "__arm_elf\0",
    "arm_elf\0",
    "__ARM_ARCH_4__\0",
    "__ARMEL__\0",
    "__APCS_32__\0",
);

// ===========================================================================
// FloatAbi — ARM floating-point ABI selection
// From arm-link.c lines 16-19 and arm-gen.c line 159
// ===========================================================================

/// ARM floating-point ABI selection.
///
/// Controls how floating-point arguments are passed in function calls:
/// - [`SoftFp`](FloatAbi::SoftFp): FP values passed in integer registers (r0-r3)
///   and on the stack, compatible with non-VFP ARM cores.
/// - [`HardFloat`](FloatAbi::HardFloat): FP values passed in VFP registers
///   (s0-s15, d0-d7), more efficient but requires VFP hardware.
///
/// The float ABI also affects the ELF interpreter path: hard-float uses
/// `/lib/ld-linux-armhf.so.3`, soft-float uses `/lib/ld-linux.so.3`.
///
/// Ported from `enum float_abi { ARM_SOFTFP_FLOAT, ARM_HARD_FLOAT }` in
/// `arm-link.c` lines 16-19.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FloatAbi {
    /// Soft-float ABI: FP arguments passed in integer registers (r0-r3).
    ///
    /// Compatible with all ARM cores. This is the default ABI for most
    /// ARM Linux distributions (armel). Corresponds to `-mfloat-abi=softfp`
    /// in GCC terminology.
    SoftFp,

    /// Hard-float ABI: FP arguments passed in VFP registers (s0-s15, d0-d7).
    ///
    /// Requires VFP hardware support. Used by armhf Linux distributions.
    /// More efficient for floating-point intensive code. Corresponds to
    /// `-mfloat-abi=hard` in GCC terminology.
    HardFloat,
}

impl Default for FloatAbi {
    /// Returns [`FloatAbi::SoftFp`] as the default, matching TCC's default
    /// behavior when `TCC_ARM_HARDFLOAT` is not defined at build time.
    #[inline]
    fn default() -> Self {
        FloatAbi::SoftFp
    }
}

// ===========================================================================
// EABI helper function remappings
// From arm-gen.c lines 95-100
//
// Under the ARM EABI, 64-bit integer division and modulo operations use
// different runtime helper functions than the standard GCC names. TCC
// remaps these at the token level to call the correct EABI helpers.
// ===========================================================================

/// EABI 64-bit arithmetic helper function name remappings.
///
/// Under ARM EABI, the standard GCC runtime helper function names for
/// 64-bit division/modulo are replaced with ARM-specific EABI names:
///
/// | Standard Name | EABI Replacement    |
/// |--------------|---------------------|
/// | `__divdi3`   | `__aeabi_ldivmod`   |
/// | `__moddi3`   | `__aeabi_ldivmod`   |
/// | `__udivdi3`  | `__aeabi_uldivmod`  |
/// | `__umoddi3`  | `__aeabi_uldivmod`  |
///
/// Note: The signed and unsigned helpers share the same EABI function name
/// because the EABI ldivmod/uldivmod functions return both quotient and
/// remainder via registers (r0:r1 = quotient, r2:r3 = remainder).
///
/// Ported from token remapping in `arm-gen.c` lines 95-100.
pub struct EabiRemappings;

impl EabiRemappings {
    /// Returns the EABI name for signed 64-bit division
    /// (`__divdi3` → `__aeabi_ldivmod`).
    #[inline]
    pub fn divdi3_name() -> &'static str {
        "__aeabi_ldivmod"
    }

    /// Returns the EABI name for signed 64-bit modulo
    /// (`__moddi3` → `__aeabi_ldivmod`).
    ///
    /// Same function as divdi3 — the EABI ldivmod returns both
    /// quotient (r0:r1) and remainder (r2:r3).
    #[inline]
    pub fn moddi3_name() -> &'static str {
        "__aeabi_ldivmod"
    }

    /// Returns the EABI name for unsigned 64-bit division
    /// (`__udivdi3` → `__aeabi_uldivmod`).
    #[inline]
    pub fn udivdi3_name() -> &'static str {
        "__aeabi_uldivmod"
    }

    /// Returns the EABI name for unsigned 64-bit modulo
    /// (`__umoddi3` → `__aeabi_uldivmod`).
    ///
    /// Same function as udivdi3 — the EABI uldivmod returns both
    /// quotient (r0:r1) and remainder (r2:r3).
    #[inline]
    pub fn umoddi3_name() -> &'static str {
        "__aeabi_uldivmod"
    }
}

// ===========================================================================
// VFP coprocessor selection helper
// From arm-gen.c line 92: #define T2CPR(t) (((t) & VT_BTYPE) != VT_FLOAT ? 0x100 : 0)
// ===========================================================================

/// Determines the VFP coprocessor register field for a given type.
///
/// Returns `0x100` for double-precision operations (VT_DOUBLE, VT_LDOUBLE)
/// and `0` for single-precision operations (VT_FLOAT). This value is OR'd
/// into VFP instruction encodings to select between the single-precision
/// (cp10) and double-precision (cp11) coprocessor.
///
/// # Arguments
/// * `t` — The full type value (will be masked with [`VT_BTYPE`])
///
/// # Returns
/// * `0x100` — Double-precision (64-bit): set bit 8 to select cp11 (D-register)
/// * `0` — Single-precision (32-bit): cp10 (S-register)
///
/// Ported from `T2CPR(t)` macro in `arm-gen.c` line 92.
#[inline]
pub fn t2cpr(t: i32) -> i32 {
    if (t & VT_BTYPE) != VT_FLOAT {
        0x100
    } else {
        0
    }
}

// ===========================================================================
// Default ELF interpreter path
// From arm-gen.c lines 231-242 (default_elfinterp function)
// ===========================================================================

/// Returns the default ELF dynamic linker/interpreter path for ARM Linux.
///
/// The interpreter path depends on both the EABI mode and the float ABI:
/// - EABI + hard-float: `/lib/ld-linux-armhf.so.3` (armhf distributions)
/// - EABI + soft-float: `/lib/ld-linux.so.3` (armel distributions)
/// - Non-EABI: `/lib/ld-linux.so.2` (legacy ARM Linux)
///
/// This path is written into the ELF `.interp` section of executables.
///
/// Ported from `default_elfinterp()` in `arm-gen.c` lines 231-242.
///
/// # Arguments
/// * `eabi` — Whether EABI calling convention is enabled
/// * `float_abi` — The floating-point ABI selection
#[inline]
pub fn default_elfinterp(eabi: bool, float_abi: FloatAbi) -> &'static str {
    if eabi {
        match float_abi {
            FloatAbi::HardFloat => "/lib/ld-linux-armhf.so.3",
            FloatAbi::SoftFp => "/lib/ld-linux.so.3",
        }
    } else {
        "/lib/ld-linux.so.2"
    }
}

// ===========================================================================
// Register class arrays
// From arm-gen.c lines 161-177
//
// Each entry maps a TREG_* register index to a bitmask of register classes.
// The register allocator uses these to find a register belonging to a
// requested class. The arrays have NB_REGS entries (13 or 9).
// ===========================================================================

/// Register class assignments with VFP enabled (13 registers).
///
/// Maps TREG_* index → bitmask of (generic class | specific register class):
/// - Indices 0-4: Integer registers r0, r1, r2, r3, r12
/// - Indices 5-12: VFP double-precision registers d0-d7
///
/// Each integer register is in [`RC_INT`] plus its specific class.
/// Each float register is in [`RC_FLOAT`] plus its specific class.
pub const REG_CLASSES_VFP: [i32; NB_REGS_VFP] = [
    RC_INT | RC_R0,      // [0] r0  — integer, first argument, return value
    RC_INT | RC_R1,      // [1] r1  — integer, second argument, 64-bit return high
    RC_INT | RC_R2,      // [2] r2  — integer, third argument
    RC_INT | RC_R3,      // [3] r3  — integer, fourth argument
    RC_INT | RC_R12,     // [4] r12 — integer, intra-procedure scratch (IP)
    RC_FLOAT | RC_F0,    // [5] d0  — float, first float arg, float return
    RC_FLOAT | RC_F1,    // [6] d1  — float, second float arg
    RC_FLOAT | RC_F2,    // [7] d2  — float, third float arg
    RC_FLOAT | RC_F3,    // [8] d3  — float, fourth float arg
    RC_FLOAT | RC_F4,    // [9] d4  — float (VFP-only)
    RC_FLOAT | RC_F5,    // [10] d5 — float (VFP-only)
    RC_FLOAT | RC_F6,    // [11] d6 — float (VFP-only)
    RC_FLOAT | RC_F7,    // [12] d7 — float (VFP-only)
];

/// Register class assignments without VFP (9 registers).
///
/// Same layout as [`REG_CLASSES_VFP`] but only includes f0-f3 (legacy FPA
/// registers), not the extended VFP register set d4-d7.
pub const REG_CLASSES_NO_VFP: [i32; NB_REGS_NO_VFP] = [
    RC_INT | RC_R0,      // [0] r0
    RC_INT | RC_R1,      // [1] r1
    RC_INT | RC_R2,      // [2] r2
    RC_INT | RC_R3,      // [3] r3
    RC_INT | RC_R12,     // [4] r12
    RC_FLOAT | RC_F0,    // [5] f0
    RC_FLOAT | RC_F1,    // [6] f1
    RC_FLOAT | RC_F2,    // [7] f2
    RC_FLOAT | RC_F3,    // [8] f3
];

// ===========================================================================
// ArmBackend struct — ARM architecture backend state
// From arm-gen.c lines 179-180 (static variables) and init function
//
// Encapsulates all mutable state that was previously stored in global/static
// variables in the C codebase. Each compilation context gets its own
// ArmBackend instance, making the compiler reentrant (fixing TODO BUG-13).
// ===========================================================================

/// ARM architecture backend — implements [`CodegenBackend`] for ARM targets.
///
/// Encapsulates all mutable compilation state that was previously stored in
/// global/static variables in `arm-gen.c`. This includes:
/// - Configuration: CPU version, float ABI, VFP/EABI/Thumb mode flags
/// - Compilation state: function prolog offset, leaf-function detection,
///   itod magic tracking, bounds checking state
///
/// # Usage
///
/// ```ignore
/// use tcc_core::arch::arm::ArmBackend;
///
/// let mut backend = ArmBackend::new();
/// // Configure for ARMv7 hard-float
/// backend.cpu_version = 7;
/// backend.float_abi = FloatAbi::HardFloat;
/// ```
///
/// # Thread Safety
///
/// Each `ArmBackend` instance is independent. Multiple compilation
/// contexts can run concurrently with separate backend instances,
/// resolving TCC TODO item BUG-13 (make libtcc fully reentrant).
pub struct ArmBackend {
    /// CPU version: 4=ARMv4, 5=ARMv5 (default), 6=ARMv6, 7=ARMv7.
    ///
    /// Affects instruction selection:
    /// - v4: No BLX (uses BX for interworking)
    /// - v5+: BLX available (ARM/Thumb interworking)
    /// - v6+: REV/REV16, MOVW/MOVT
    /// - v7+: Thumb-2, IT blocks, DMB/DSB/ISB
    pub cpu_version: u32,

    /// Floating-point ABI selection.
    ///
    /// Determines how floating-point values are passed in function calls
    /// and affects ELF interpreter path selection.
    pub float_abi: FloatAbi,

    /// Whether VFP (Vector Floating-Point) coprocessor instructions are enabled.
    ///
    /// When `true`, floating-point operations use VFP instructions (VADD,
    /// VMUL, etc.) and the d0-d7 register set. When `false`, floating-point
    /// operations are emulated via runtime library calls.
    pub vfp_enabled: bool,

    /// Whether EABI (Embedded Application Binary Interface) is enabled.
    ///
    /// EABI affects:
    /// - 64-bit helper function names (div/mod → aeabi_ldivmod/uldivmod)
    /// - Struct alignment rules (8-byte for doublewords)
    /// - Target machine preprocessor definitions
    /// - ELF interpreter path
    pub eabi_enabled: bool,

    /// Whether Thumb instruction set mode is selected.
    ///
    /// Thumb mode uses 16-bit instructions for improved code density.
    /// When enabled, function prologues and epilogues use Thumb encoding.
    /// Note: Thumb-2 (ARMv7+) allows mixing 16-bit and 32-bit instructions.
    pub thumb_mode: bool,

    /// Offset in the code section where the function prolog's stack adjustment
    /// instruction was emitted. This location is backpatched in the epilogue
    /// once the total stack frame size is known.
    ///
    /// Ported from `static int func_sub_sp_offset` in `arm-gen.c` line 179.
    pub func_sub_sp_offset: i32,

    /// Magic value tracking the last integer-to-double conversion.
    ///
    /// Used as an optimization hint to avoid redundant VMOV instructions
    /// when the same integer value is converted to double multiple times
    /// in sequence.
    ///
    /// Ported from `static int last_itod_magic` in `arm-gen.c` line 179.
    pub last_itod_magic: i32,

    /// Whether the current function is a leaf function (makes no calls).
    ///
    /// Leaf functions can skip saving/restoring the link register (LR)
    /// and may use a simplified function prologue/epilogue.
    ///
    /// Ported from `static int leaffunc` in `arm-gen.c` line 179.
    pub leaffunc: bool,

    /// Whether bounds checking is enabled for the current compilation.
    ///
    /// When enabled, additional instrumentation code is emitted around
    /// memory accesses to detect buffer overflows at runtime.
    pub bounds_enabled: bool,

    /// Saved bounds pointer register value.
    ///
    /// During bounds-checked code generation, this stores the register
    /// holding the pointer to the bounds-checking shadow data structure.
    pub bounds_ptr: i32,
}

impl ArmBackend {
    /// Creates a new ARM backend with default settings.
    ///
    /// Defaults:
    /// - CPU version: ARMv5 (supports BLX)
    /// - Float ABI: SoftFp (compatible with all ARM cores)
    /// - VFP: enabled
    /// - EABI: enabled
    /// - Thumb mode: disabled
    /// - All compilation state zeroed
    pub fn new() -> Self {
        ArmBackend {
            cpu_version: DEFAULT_CONFIG_TCC_CPUVER,
            float_abi: FloatAbi::default(),
            vfp_enabled: true,
            eabi_enabled: true,
            thumb_mode: false,
            func_sub_sp_offset: 0,
            last_itod_magic: 0,
            leaffunc: false,
            bounds_enabled: false,
            bounds_ptr: 0,
        }
    }

    /// Returns the number of available registers based on VFP state.
    ///
    /// - VFP enabled: 13 registers (r0-r3, r12, d0-d7)
    /// - VFP disabled: 9 registers (r0-r3, r12, f0-f3)
    #[inline]
    pub fn nb_regs(&self) -> usize {
        if self.vfp_enabled {
            NB_REGS_VFP
        } else {
            NB_REGS_NO_VFP
        }
    }

    /// Returns the register class array based on VFP state.
    ///
    /// Each entry maps a register index to its class bitmask, used by
    /// the register allocator to find registers of a specific class.
    #[inline]
    pub fn reg_classes(&self) -> &[i32] {
        if self.vfp_enabled {
            &REG_CLASSES_VFP
        } else {
            &REG_CLASSES_NO_VFP
        }
    }

    /// Returns long double alignment based on EABI setting.
    ///
    /// EABI requires 8-byte alignment for doubleword types;
    /// legacy ABI uses 4-byte alignment.
    #[inline]
    pub fn ldouble_align(&self) -> usize {
        if self.eabi_enabled {
            LDOUBLE_ALIGN_EABI
        } else {
            LDOUBLE_ALIGN_NO_EABI
        }
    }

    /// Initializes the ARM backend for a compilation session.
    ///
    /// Validates configuration constraints (EABI requires VFP) and
    /// resets per-function state.
    ///
    /// Ported from `arm_init()` in `arm-gen.c` lines 182-200.
    ///
    /// # Errors
    ///
    /// Returns [`TccError::CodegenError`] if EABI is enabled but VFP
    /// is disabled, since TCC's ARM EABI implementation requires VFP
    /// instructions for floating-point computation.
    pub fn init(&mut self) -> TccResult<()> {
        // EABI requires VFP — this matches the compile-time constraint
        // in the C codebase: #if defined(TCC_ARM_EABI) && !defined(TCC_ARM_VFP)
        //   #error "Currently TinyCC only supports float computation with VFP instructions"
        // #endif
        if self.eabi_enabled && !self.vfp_enabled {
            return Err(TccError::CodegenError {
                message: "Currently TinyCC only supports float computation \
                          with VFP instructions"
                    .into(),
            });
        }

        // Reset per-function compilation state
        self.func_sub_sp_offset = 0;
        self.last_itod_magic = 0;
        self.leaffunc = false;

        Ok(())
    }
}

impl Default for ArmBackend {
    /// Creates a default ARM backend (delegates to [`ArmBackend::new()`]).
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// CodegenBackend trait implementation
// Implements all 39 trait methods from crate::arch::CodegenBackend
//
// Methods are organized by category:
// 1. Configuration/query methods (return constants or computed values)
// 2. Code generation methods (delegate to gen module)
// 3. Linker methods (delegate to link module)
// 4. Assembly methods — not in CodegenBackend trait; handled separately
//
// The delegation pattern allows each submodule (gen, link, asm) to be
// developed and tested independently while presenting a unified interface
// through the trait.
// ===========================================================================

impl CodegenBackend for ArmBackend {
    // -----------------------------------------------------------------------
    // Configuration and query methods
    // -----------------------------------------------------------------------

    /// Returns the target machine preprocessor definitions.
    ///
    /// Returns different macro sets depending on whether EABI is enabled,
    /// since EABI mode defines `__ARM_EABI__` as an additional predefined macro.
    fn target_machine_defs(&self) -> &'static str {
        if self.eabi_enabled {
            TARGET_MACHINE_DEFS
        } else {
            TARGET_MACHINE_DEFS_NO_EABI
        }
    }

    /// Returns the register class array for the register allocator.
    ///
    /// With VFP: 13 entries (r0-r3, r12, d0-d7).
    /// Without VFP: 9 entries (r0-r3, r12, f0-f3).
    fn reg_classes(&self) -> &[i32] {
        self.reg_classes()
    }

    /// Returns the number of allocatable registers.
    fn nb_regs(&self) -> usize {
        self.nb_regs()
    }

    /// Returns pointer size for ARM (4 bytes, 32-bit architecture).
    fn ptr_size(&self) -> usize {
        PTR_SIZE
    }

    /// Returns the ARM ELF machine type (EM_ARM = 40).
    fn elf_machine(&self) -> u16 {
        EM_TCC_TARGET
    }

    /// Returns the default ELF entry address for ARM executables.
    fn elf_start_addr(&self) -> u64 {
        ELF_START_ADDR
    }

    /// Returns the ELF page size for ARM segment alignment.
    fn elf_page_size(&self) -> u64 {
        ELF_PAGE_SIZE
    }

    /// Returns whether ARM uses PC-relative DLL PLT entries.
    fn pcrelative_dllplt(&self) -> bool {
        PCRELATIVE_DLLPLT
    }

    /// Returns whether ARM needs DLL PLT relocation.
    fn relocate_dllplt(&self) -> bool {
        RELOCATE_DLLPLT
    }

    // -----------------------------------------------------------------------
    // Code generation methods — delegate to gen module
    // -----------------------------------------------------------------------

    /// Patches a symbol address into a previously emitted jump/branch.
    ///
    /// Walks the chain of forward references starting at offset `t`,
    /// patching each to point to address `a`.
    fn gsym_addr(&mut self, t: i32, a: i32) -> TccResult<()> {
        gen::gsym_addr(self, t, a)
    }

    /// Patches a symbol to point to the current code position.
    fn gsym(&mut self, t: i32) -> TccResult<()> {
        gen::gsym(self, t)
    }

    /// Loads a value into a register.
    ///
    /// Handles all SValue types: constants, local variables, global
    /// symbols, register values, and indirect references. Selects
    /// appropriate ARM/VFP load instructions based on the value type.
    fn load(&mut self, r: i32, sv: &SValue) -> TccResult<()> {
        gen::load(self, r, sv)
    }

    /// Stores a register value to a memory location.
    ///
    /// The inverse of `load()`. Selects appropriate ARM/VFP store
    /// instructions based on the destination type.
    fn store(&mut self, r: i32, sv: &SValue) -> TccResult<()> {
        gen::store(self, r, sv)
    }

    /// Determines the struct return convention for a given type.
    ///
    /// Returns a tuple of `(uses_sret, ret_type, ret_align, reg_size)`:
    /// - `uses_sret`: `true` if the struct must be returned via pointer
    /// - `ret_type`: The type used for the return value register
    /// - `ret_align`: Alignment of the return value
    /// - `reg_size`: Size in registers
    ///
    /// ARM EABI rules:
    /// - Size ≤ 4 bytes: returned in r0
    /// - Homogeneous float aggregate (HFA): returned in VFP registers
    /// - Larger structs: returned via hidden pointer parameter
    fn gfunc_sret(&self, vt: &CType, variadic: bool) -> (bool, CType, i32, i32) {
        gen::gfunc_sret(self, vt, variadic)
    }

    /// Generates a function call with the given number of arguments.
    ///
    /// Handles ARM/EABI calling convention:
    /// - Integer args: r0-r3, then stack
    /// - Float args (hard-float): s0-s15/d0-d7, then stack
    /// - Float args (soft-float): r0-r3, then stack
    /// - 64-bit args: aligned to even register pair
    /// - Return value in r0 (integer) or d0 (float, hard-float ABI)
    fn gfunc_call(&mut self, nb_args: i32) -> TccResult<()> {
        gen::gfunc_call(self, nb_args)
    }

    /// Generates a function prologue.
    ///
    /// Emits: push {regs, lr}, sub sp for locals, save callee-saved regs.
    /// The stack adjustment is initially a placeholder; it's backpatched
    /// in `gfunc_epilog()` once the total frame size is known.
    fn gfunc_prolog(&mut self, func_sym: &Sym) -> TccResult<()> {
        gen::gfunc_prolog(self, func_sym)
    }

    /// Generates a function epilogue.
    ///
    /// Emits: restore callee-saved regs, add sp for locals, pop {regs, pc}.
    /// Backpatches the prolog's stack adjustment with the actual frame size.
    fn gfunc_epilog(&mut self) -> TccResult<()> {
        gen::gfunc_epilog(self)
    }

    /// Fills a code region with NOP instructions.
    ///
    /// Uses ARM NOP (0xE1A00000 = MOV r0, r0) or Thumb NOP (0xBF00)
    /// depending on the current instruction set mode.
    fn gen_fill_nops(&mut self, n: i32) -> TccResult<()> {
        gen::gen_fill_nops(self, n)
    }

    /// Generates an unconditional jump, returning the patch address.
    ///
    /// Emits an ARM B (branch) instruction. The target is encoded as
    /// a forward reference chain; `t` is the previous chain head.
    fn gjmp(&mut self, t: i32) -> TccResult<i32> {
        gen::gjmp(self, t)
    }

    /// Generates an unconditional jump to an absolute address.
    fn gjmp_addr(&mut self, a: i32) -> TccResult<()> {
        gen::gjmp_addr(self, a)
    }

    /// Generates a conditional jump based on a comparison operator.
    ///
    /// The condition is derived from the comparison operator `op` and
    /// the current flags state. Returns the forward reference chain head.
    fn gjmp_cond(&mut self, op: i32, t: i32) -> TccResult<i32> {
        gen::gjmp_cond(self, op, t)
    }

    /// Appends a jump target to the forward reference chain.
    fn gjmp_append(&mut self, n: i32, t: i32) -> TccResult<i32> {
        gen::gjmp_append(self, n, t)
    }

    /// Generates an integer operation (add, sub, mul, div, shift, etc.).
    ///
    /// Handles ARM-specific instruction selection including barrel shifter
    /// operations, multiply, and software division via runtime helpers.
    fn gen_opi(&mut self, op: i32) -> TccResult<()> {
        gen::gen_opi(self, op)
    }

    /// Generates a floating-point operation (add, sub, mul, div, compare).
    ///
    /// Uses VFP instructions (VADD, VSUB, VMUL, VDIV, VCMP) when VFP
    /// is enabled, or calls runtime library functions for soft-float.
    fn gen_opf(&mut self, op: i32) -> TccResult<()> {
        gen::gen_opf(self, op)
    }

    /// Generates float-to-integer conversion.
    ///
    /// Uses VCVT (VFP) or calls runtime library for conversion.
    /// Handles both float→int and double→int conversions.
    fn gen_cvt_ftoi(&mut self, t: i32) -> TccResult<()> {
        gen::gen_cvt_ftoi(self, t)
    }

    /// Generates integer-to-float conversion.
    ///
    /// Uses VCVT (VFP) or calls runtime library for conversion.
    /// Handles both int→float and int→double conversions.
    fn gen_cvt_itof(&mut self, t: i32) -> TccResult<()> {
        gen::gen_cvt_itof(self, t)
    }

    /// Generates float-to-float conversion (float↔double).
    ///
    /// Uses VCVT.F32.F64 or VCVT.F64.F32 (VFP) for precision conversion.
    fn gen_cvt_ftof(&mut self, t: i32) -> TccResult<()> {
        gen::gen_cvt_ftof(self, t)
    }

    /// Generates a computed goto (indirect jump through register).
    fn ggoto(&mut self) -> TccResult<()> {
        gen::ggoto(self)
    }

    /// Emits a raw opcode word into the code section.
    fn emit_opcode(&mut self, c: u32) -> TccResult<()> {
        gen::emit_opcode(self, c)
    }

    /// Saves the current stack pointer for VLA (variable-length array) support.
    fn gen_vla_sp_save(&mut self, addr: i32) -> TccResult<()> {
        gen::gen_vla_sp_save(self, addr)
    }

    /// Restores a previously saved stack pointer for VLA support.
    fn gen_vla_sp_restore(&mut self, addr: i32) -> TccResult<()> {
        gen::gen_vla_sp_restore(self, addr)
    }

    /// Allocates stack space for a variable-length array.
    fn gen_vla_alloc(&mut self, typ: &CType, align: i32) -> TccResult<()> {
        gen::gen_vla_alloc(self, typ, align)
    }

    /// Emits a single byte into the code section.
    fn g(&mut self, c: i32) -> TccResult<()> {
        gen::g(self, c)
    }

    /// Emits a 16-bit little-endian value into the code section.
    fn gen_le16(&mut self, c: i32) -> TccResult<()> {
        gen::gen_le16(self, c)
    }

    /// Emits a 32-bit little-endian value into the code section.
    fn gen_le32(&mut self, c: i32) -> TccResult<()> {
        gen::gen_le32(self, c)
    }

    /// Increments a test coverage counter.
    fn gen_increment_tcov(&mut self, sv: &SValue) -> TccResult<()> {
        gen::gen_increment_tcov(self, sv)
    }

    // -----------------------------------------------------------------------
    // Linker methods — delegate to link module
    // -----------------------------------------------------------------------

    /// Classifies a relocation type for the linker.
    ///
    /// Returns a code indicating how the relocation should be processed:
    /// negative for errors, 0 for absolute, positive for GOT/PLT.
    fn code_reloc(&self, reloc_type: i32) -> i32 {
        link::code_reloc(reloc_type)
    }

    /// Determines the GOT/PLT entry type for a given relocation.
    fn gotplt_entry_type(&self, reloc_type: i32) -> i32 {
        link::gotplt_entry_type(reloc_type)
    }

    /// Applies a relocation to the output binary.
    ///
    /// Handles all ARM relocation types: R_ARM_PC24, R_ARM_ABS32,
    /// R_ARM_GOTPC, R_ARM_GOT32, R_ARM_PLT32, R_ARM_COPY,
    /// R_ARM_GLOB_DAT, R_ARM_JMP_SLOT, R_ARM_RELATIVE, R_ARM_PREL31,
    /// R_ARM_V4BX, R_ARM_TARGET1, R_ARM_TARGET2, R_ARM_REL32,
    /// R_ARM_CALL, R_ARM_JUMP24, R_ARM_MOVW_ABS_NC, R_ARM_MOVT_ABS,
    /// R_ARM_THM_JUMP24, R_ARM_THM_MOVW_ABS_NC, R_ARM_THM_MOVT_ABS,
    /// R_ARM_GOT_PREL.
    fn relocate(&mut self, rel_type: i32, ptr: &mut [u8], addr: u64, val: u64) -> TccResult<()> {
        link::relocate(self, rel_type, ptr, addr, val)
    }
}

// ===========================================================================
// Unit tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_arm_backend_new_defaults() {
        let backend = ArmBackend::new();
        assert_eq!(backend.cpu_version, DEFAULT_CONFIG_TCC_CPUVER);
        assert_eq!(backend.cpu_version, 5);
        assert_eq!(backend.float_abi, FloatAbi::SoftFp);
        assert!(backend.vfp_enabled);
        assert!(backend.eabi_enabled);
        assert!(!backend.thumb_mode);
        assert_eq!(backend.func_sub_sp_offset, 0);
        assert_eq!(backend.last_itod_magic, 0);
        assert!(!backend.leaffunc);
        assert!(!backend.bounds_enabled);
        assert_eq!(backend.bounds_ptr, 0);
    }

    #[test]
    fn test_arm_backend_default_trait() {
        let backend = ArmBackend::default();
        assert_eq!(backend.cpu_version, 5);
        assert!(backend.vfp_enabled);
    }

    #[test]
    fn test_nb_regs_vfp_enabled() {
        let backend = ArmBackend::new();
        assert_eq!(backend.nb_regs(), NB_REGS_VFP);
        assert_eq!(backend.nb_regs(), 13);
    }

    #[test]
    fn test_nb_regs_vfp_disabled() {
        let mut backend = ArmBackend::new();
        backend.vfp_enabled = false;
        assert_eq!(backend.nb_regs(), NB_REGS_NO_VFP);
        assert_eq!(backend.nb_regs(), 9);
    }

    #[test]
    fn test_reg_classes_vfp_enabled() {
        let backend = ArmBackend::new();
        let classes = backend.reg_classes();
        assert_eq!(classes.len(), NB_REGS_VFP);
        // r0 should be in RC_INT | RC_R0
        assert_eq!(classes[TREG_R0], RC_INT | RC_R0);
        // d0 should be in RC_FLOAT | RC_F0
        assert_eq!(classes[TREG_F0], RC_FLOAT | RC_F0);
        // d7 should be in RC_FLOAT | RC_F7
        assert_eq!(classes[TREG_F7], RC_FLOAT | RC_F7);
    }

    #[test]
    fn test_reg_classes_vfp_disabled() {
        let mut backend = ArmBackend::new();
        backend.vfp_enabled = false;
        let classes = backend.reg_classes();
        assert_eq!(classes.len(), NB_REGS_NO_VFP);
        assert_eq!(classes[TREG_R0], RC_INT | RC_R0);
        assert_eq!(classes[TREG_F3], RC_FLOAT | RC_F3);
    }

    #[test]
    fn test_ldouble_align_eabi() {
        let backend = ArmBackend::new();
        assert_eq!(backend.ldouble_align(), LDOUBLE_ALIGN_EABI);
        assert_eq!(backend.ldouble_align(), 8);
    }

    #[test]
    fn test_ldouble_align_no_eabi() {
        let mut backend = ArmBackend::new();
        backend.eabi_enabled = false;
        assert_eq!(backend.ldouble_align(), LDOUBLE_ALIGN_NO_EABI);
        assert_eq!(backend.ldouble_align(), 4);
    }

    #[test]
    fn test_init_ok() {
        let mut backend = ArmBackend::new();
        // Default: eabi=true, vfp=true → should succeed
        assert!(backend.init().is_ok());
    }

    #[test]
    fn test_init_eabi_without_vfp_fails() {
        let mut backend = ArmBackend::new();
        backend.eabi_enabled = true;
        backend.vfp_enabled = false;
        let result = backend.init();
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("VFP"));
    }

    #[test]
    fn test_init_no_eabi_no_vfp_ok() {
        let mut backend = ArmBackend::new();
        backend.eabi_enabled = false;
        backend.vfp_enabled = false;
        assert!(backend.init().is_ok());
    }

    #[test]
    fn test_init_resets_state() {
        let mut backend = ArmBackend::new();
        backend.func_sub_sp_offset = 42;
        backend.last_itod_magic = 99;
        backend.leaffunc = true;
        backend.init().unwrap();
        assert_eq!(backend.func_sub_sp_offset, 0);
        assert_eq!(backend.last_itod_magic, 0);
        assert!(!backend.leaffunc);
    }

    #[test]
    fn test_float_abi_default() {
        assert_eq!(FloatAbi::default(), FloatAbi::SoftFp);
    }

    #[test]
    fn test_float_abi_equality() {
        assert_eq!(FloatAbi::SoftFp, FloatAbi::SoftFp);
        assert_eq!(FloatAbi::HardFloat, FloatAbi::HardFloat);
        assert_ne!(FloatAbi::SoftFp, FloatAbi::HardFloat);
    }

    #[test]
    fn test_eabi_remappings() {
        assert_eq!(EabiRemappings::divdi3_name(), "__aeabi_ldivmod");
        assert_eq!(EabiRemappings::moddi3_name(), "__aeabi_ldivmod");
        assert_eq!(EabiRemappings::udivdi3_name(), "__aeabi_uldivmod");
        assert_eq!(EabiRemappings::umoddi3_name(), "__aeabi_uldivmod");
        // Signed div and mod share the same EABI function
        assert_eq!(EabiRemappings::divdi3_name(), EabiRemappings::moddi3_name());
        // Unsigned div and mod share the same EABI function
        assert_eq!(
            EabiRemappings::udivdi3_name(),
            EabiRemappings::umoddi3_name()
        );
    }

    #[test]
    fn test_t2cpr_float() {
        // VT_FLOAT (type value 8 with only VT_FLOAT in btype) should return 0
        assert_eq!(t2cpr(VT_FLOAT as i32), 0);
    }

    #[test]
    fn test_t2cpr_non_float() {
        // Any non-VT_FLOAT btype should return 0x100 (double-precision)
        assert_eq!(t2cpr(0), 0x100); // VT_INT
        assert_eq!(t2cpr(9), 0x100); // VT_DOUBLE (btype 9)
    }

    #[test]
    fn test_default_elfinterp_eabi_softfp() {
        assert_eq!(
            default_elfinterp(true, FloatAbi::SoftFp),
            "/lib/ld-linux.so.3"
        );
    }

    #[test]
    fn test_default_elfinterp_eabi_hardfloat() {
        assert_eq!(
            default_elfinterp(true, FloatAbi::HardFloat),
            "/lib/ld-linux-armhf.so.3"
        );
    }

    #[test]
    fn test_default_elfinterp_no_eabi() {
        assert_eq!(
            default_elfinterp(false, FloatAbi::SoftFp),
            "/lib/ld-linux.so.2"
        );
        assert_eq!(
            default_elfinterp(false, FloatAbi::HardFloat),
            "/lib/ld-linux.so.2"
        );
    }

    #[test]
    fn test_constants_match_c_source() {
        // Verify all constants match arm-gen.c and arm-link.c exactly
        assert_eq!(NB_REGS_VFP, 13);
        assert_eq!(NB_REGS_NO_VFP, 9);
        assert_eq!(DEFAULT_CONFIG_TCC_CPUVER, 5);

        // Register classes
        assert_eq!(RC_R0, 0x0004);
        assert_eq!(RC_R1, 0x0008);
        assert_eq!(RC_R2, 0x0010);
        assert_eq!(RC_R3, 0x0020);
        assert_eq!(RC_R12, 0x0040);
        assert_eq!(RC_F0, 0x0080);
        assert_eq!(RC_F1, 0x0100);
        assert_eq!(RC_F2, 0x0200);
        assert_eq!(RC_F3, 0x0400);
        assert_eq!(RC_F4, 0x0800);
        assert_eq!(RC_F5, 0x1000);
        assert_eq!(RC_F6, 0x2000);
        assert_eq!(RC_F7, 0x4000);

        // Return register classes
        assert_eq!(RC_IRET, RC_R0);
        assert_eq!(RC_IRE2, RC_R1);
        assert_eq!(RC_FRET, RC_F0);

        // Register indices
        assert_eq!(TREG_R0, 0);
        assert_eq!(TREG_R1, 1);
        assert_eq!(TREG_R2, 2);
        assert_eq!(TREG_R3, 3);
        assert_eq!(TREG_R12, 4);
        assert_eq!(TREG_F0, 5);
        assert_eq!(TREG_F1, 6);
        assert_eq!(TREG_F2, 7);
        assert_eq!(TREG_F3, 8);
        assert_eq!(TREG_F4, 9);
        assert_eq!(TREG_F5, 10);
        assert_eq!(TREG_F6, 11);
        assert_eq!(TREG_F7, 12);
        assert_eq!(TREG_SP, 13);
        assert_eq!(TREG_LR, 14);

        // Return register indices
        assert_eq!(REG_IRET, TREG_R0);
        assert_eq!(REG_IRE2, TREG_R1);
        assert_eq!(REG_FRET, TREG_F0);

        // Architecture sizes
        assert_eq!(PTR_SIZE, 4);
        assert_eq!(LDOUBLE_SIZE, 8);
        assert_eq!(LDOUBLE_ALIGN_EABI, 8);
        assert_eq!(LDOUBLE_ALIGN_NO_EABI, 4);
        assert_eq!(MAX_ALIGN, 8);
        assert!(CHAR_IS_UNSIGNED);
        assert!(INVERT_FUNC_PARAMS);

        // ELF constants
        assert_eq!(EM_TCC_TARGET, 40);
        assert_eq!(ELF_START_ADDR, 0x0001_0000);
        assert_eq!(ELF_PAGE_SIZE, 0x0001_0000);
        assert!(PCRELATIVE_DLLPLT);
        assert!(RELOCATE_DLLPLT);
    }

    #[test]
    fn test_reg_classes_array_sizes() {
        assert_eq!(REG_CLASSES_VFP.len(), NB_REGS_VFP);
        assert_eq!(REG_CLASSES_NO_VFP.len(), NB_REGS_NO_VFP);
    }

    #[test]
    fn test_reg_classes_vfp_all_classified() {
        // Every register in the VFP array should have at least one class
        for (i, &class) in REG_CLASSES_VFP.iter().enumerate() {
            assert!(
                class != 0,
                "Register {} has no class assignment",
                i
            );
            // Each register should be either INT or FLOAT (not both)
            let is_int = (class & RC_INT) != 0;
            let is_float = (class & RC_FLOAT) != 0;
            assert!(
                is_int ^ is_float,
                "Register {} should be exactly one of INT or FLOAT",
                i
            );
        }
    }

    #[test]
    fn test_reg_classes_no_vfp_all_classified() {
        for (i, &class) in REG_CLASSES_NO_VFP.iter().enumerate() {
            assert!(class != 0, "Register {} has no class assignment", i);
            let is_int = (class & RC_INT) != 0;
            let is_float = (class & RC_FLOAT) != 0;
            assert!(
                is_int ^ is_float,
                "Register {} should be exactly one of INT or FLOAT",
                i
            );
        }
    }

    #[test]
    fn test_target_machine_defs_contains_required_macros() {
        // Verify key macros are present in the EABI definition string
        assert!(TARGET_MACHINE_DEFS.contains("__arm__"));
        assert!(TARGET_MACHINE_DEFS.contains("__ARM_ARCH_4__"));
        assert!(TARGET_MACHINE_DEFS.contains("__ARMEL__"));
        assert!(TARGET_MACHINE_DEFS.contains("__ARM_EABI__"));
    }

    #[test]
    fn test_target_machine_defs_no_eabi_excludes_eabi() {
        assert!(!TARGET_MACHINE_DEFS_NO_EABI.contains("__ARM_EABI__"));
        // But should still have the base ARM macros
        assert!(TARGET_MACHINE_DEFS_NO_EABI.contains("__arm__"));
        assert!(TARGET_MACHINE_DEFS_NO_EABI.contains("__ARMEL__"));
    }
}
