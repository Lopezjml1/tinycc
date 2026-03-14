// Copyright (c) 2024 tinycc-rs contributors
// SPDX-License-Identifier: MIT OR LGPL-2.1-or-later

//! Architecture backend trait and module aggregation.
//!
//! Each architecture implements the [`CodegenBackend`] trait which defines
//! the interface between the target-independent compiler core and
//! architecture-specific code generation, assembly, and linking.
//!
//! The [`LinkerBackend`] trait defines the interface for architecture-specific
//! relocation processing, GOT/PLT entry generation, and PLT patching.
//!
//! The [`create_backend`] function provides runtime or compile-time dispatch
//! to the appropriate backend based on a target architecture name string.
//!
//! Byte-order utility functions ([`read16le`], [`write16le`], [`read32le`],
//! [`write32le`], [`add32le`], [`read64le`], [`write64le`], [`add64le`]) are
//! used by all backends and the linker for in-place little-endian value
//! manipulation in ELF/PE/Mach-O section data buffers.
//!
//! C equivalent: The backend interface defined in `tcc.h` lines 1596–1672.

// ===========================================================================
//  Submodule Declarations — Feature-Gated Architecture Backends
// ===========================================================================
//
// Each architecture backend is compiled only when the corresponding Cargo
// feature is enabled.  The C67 (TMS320C67 DSP) backend has no feature gate
// because it has negligible code size and no platform-specific dependencies.
//
// C equivalent: `#ifdef TCC_TARGET_*` conditional compilation in tcc.h.

/// x86 32-bit code generation, assembler, and linker backend.
/// C equivalent: `i386-gen.c`, `i386-asm.c`, `i386-link.c`.
#[cfg(feature = "i386")]
pub(crate) mod i386;

/// x86-64 code generation and linker backend.
/// C equivalent: `x86_64-gen.c`, `x86_64-link.c`.
#[cfg(feature = "x86_64")]
pub(crate) mod x86_64;

/// ARM 32-bit code generation, assembler, and linker backend.
/// C equivalent: `arm-gen.c`, `arm-asm.c`, `arm-link.c`.
#[cfg(feature = "arm")]
pub(crate) mod arm;

/// AArch64 (ARM64) code generation, assembler, and linker backend.
/// C equivalent: `arm64-gen.c`, `arm64-asm.c`, `arm64-link.c`.
#[cfg(feature = "arm64")]
pub(crate) mod arm64;

/// RISC-V 64-bit code generation, assembler, and linker backend.
/// C equivalent: `riscv64-gen.c`, `riscv64-asm.c`, `riscv64-link.c`.
#[cfg(feature = "riscv64")]
pub(crate) mod riscv64;

/// TMS320C67 DSP code generation and linker backend.
/// C equivalent: `c67-gen.c`, `c67-link.c`.
pub(crate) mod c67;

// ===========================================================================
//  Imports
// ===========================================================================

use crate::context::TccState;
use crate::error::{TccError, TccResult};
use crate::types::{CType, SValue, Symbol};

// ===========================================================================
//  CodegenBackend Trait (tcc.h:1619–1648)
// ===========================================================================

/// Architecture-specific code generation backend.
///
/// This trait defines the interface between the target-independent compiler
/// core (parser, codegen) and architecture-specific code generation, assembly
/// instruction encoding, and linker relocation handling.
///
/// Every architecture module (`i386`, `x86_64`, `arm`, `arm64`, `riscv64`,
/// `c67`) provides a struct that implements this trait, replacing the C
/// pattern where each `xxx-gen.c` file provides `ST_FUNC` implementations
/// of the same function signatures.
///
/// The `&mut TccState` parameter on most methods replaces the C pattern of
/// accessing the global `TCCState *s1` pointer.  Per AAP §0.4.4, all compiler
/// state is owned by the [`TccState`] struct with owned Rust types.
///
/// C equivalent: `ST_FUNC` declarations in `tcc.h` lines 1619–1648.
pub(crate) trait CodegenBackend {
    // -------------------------------------------------------------------
    // Static data queries — infallible, no state mutation
    // -------------------------------------------------------------------

    /// Target machine preprocessor definitions.
    ///
    /// Returns a slice of preprocessor macro definitions (e.g.
    /// `"__x86_64__"`, `"__LP64__"`) that the preprocessor adds when
    /// targeting this architecture.  Each string is either a bare macro name
    /// (implicitly defined as `1`) or a `"NAME=VALUE"` pair.
    ///
    /// C equivalent: `target_machine_defs` (`tcc.h:1620`).
    fn target_machine_defs(&self) -> &[&str];

    /// Register class definitions for the register allocator.
    ///
    /// Returns a fixed-size slice (length `NB_REGS` for the target) where
    /// each element is a bitmask of register-class flags used by the
    /// register allocator to determine which registers can hold which value
    /// types.
    ///
    /// C equivalent: `reg_classes[NB_REGS]` (`tcc.h:1621`).
    fn reg_classes(&self) -> &[u32];

    // -------------------------------------------------------------------
    // Forward-reference resolution
    // -------------------------------------------------------------------

    /// Resolve forward reference at position `t` to point to address `a`.
    ///
    /// Walks the forward-jump chain starting at code offset `t` and patches
    /// each jump instruction to target absolute address `a`.
    ///
    /// C equivalent: `gsym_addr()` (`tcc.h:1623`).
    fn gsym_addr(&mut self, state: &mut TccState, t: i32, a: i32) -> TccResult<()>;

    /// Resolve forward reference to current code position.
    ///
    /// Equivalent to `gsym_addr(t, state.ind)` — patches the jump chain at
    /// `t` to land at the current instruction pointer.
    ///
    /// C equivalent: `gsym()` (`tcc.h:1624`).
    fn gsym(&mut self, state: &mut TccState, t: i32) -> TccResult<()>;

    // -------------------------------------------------------------------
    // Register ↔ Value transfers
    // -------------------------------------------------------------------

    /// Load value `sv` into register `r`.
    ///
    /// Generates machine instructions to move the value described by [`SValue`]
    /// `sv` (which may be a constant, a local variable, a global symbol, or
    /// already in another register) into hardware register `r`.
    ///
    /// The `sv.ctype`, `sv.r`, and `sv.r2` fields determine the load strategy.
    ///
    /// C equivalent: `load()` (`tcc.h:1625`).
    fn load(&mut self, state: &mut TccState, r: i32, sv: &SValue) -> TccResult<()>;

    /// Store register `r` into location described by `v`.
    ///
    /// Generates machine instructions to move the value in hardware register
    /// `r` to the memory location described by [`SValue`] `v`.
    ///
    /// The `v.ctype`, `v.r`, and `v.r2` fields determine the store strategy.
    ///
    /// C equivalent: `store()` (`tcc.h:1626`).
    fn store(&mut self, state: &mut TccState, r: i32, v: &SValue) -> TccResult<()>;

    // -------------------------------------------------------------------
    // Function calling convention
    // -------------------------------------------------------------------

    /// Determine structure return convention.
    ///
    /// Inspects the function return type `vt` and the `variadic` flag to
    /// decide whether the struct/union return value should be returned in
    /// registers or via a hidden pointer parameter.
    ///
    /// On output:
    /// - `ret` receives the adjusted return type (e.g. `int` for small structs).
    /// - `align` receives the required alignment.
    /// - `regsize` receives the register size used for the return.
    ///
    /// Returns `1` if the struct is returned in registers, `0` if via
    /// hidden pointer.
    ///
    /// The `vt.t` and `vt.ref_sym` fields are used to inspect the type.
    ///
    /// C equivalent: `gfunc_sret()` (`tcc.h:1627`).
    fn gfunc_sret(
        &self,
        vt: &CType,
        variadic: bool,
        ret: &mut CType,
        align: &mut i32,
        regsize: &mut i32,
    ) -> i32;

    /// Generate function call with `nb_args` arguments on value stack.
    ///
    /// Emits the machine code to perform a function call.  The top
    /// `nb_args` entries on the value stack are the arguments (in
    /// left-to-right order), and the entry below them is the function
    /// address.
    ///
    /// C equivalent: `gfunc_call()` (`tcc.h:1628`).
    fn gfunc_call(&mut self, state: &mut TccState, nb_args: i32) -> TccResult<()>;

    /// Generate function prologue for `func_sym`.
    ///
    /// Emits the function entry sequence (stack frame setup, register saves,
    /// parameter copying) based on the function's [`Symbol`] attributes
    /// including `func_sym.func_attr` for calling convention and
    /// `func_sym.ctype` for the return type.
    ///
    /// C equivalent: `gfunc_prolog()` (`tcc.h:1629`).
    fn gfunc_prolog(&mut self, state: &mut TccState, func_sym: &Symbol) -> TccResult<()>;

    /// Generate function epilogue.
    ///
    /// Emits the function exit sequence (register restores, stack frame
    /// teardown, return instruction).
    ///
    /// C equivalent: `gfunc_epilog()` (`tcc.h:1630`).
    fn gfunc_epilog(&mut self, state: &mut TccState) -> TccResult<()>;

    // -------------------------------------------------------------------
    // Alignment and NOP fill
    // -------------------------------------------------------------------

    /// Fill `bytes` bytes with NOP instructions for alignment.
    ///
    /// Writes architecture-appropriate NOP instructions (single-byte or
    /// multi-byte NOPs for x86, NOP for ARM, etc.) to pad the code section
    /// to the required alignment boundary.
    ///
    /// C equivalent: `gen_fill_nops()` (`tcc.h:1631`).
    fn gen_fill_nops(&mut self, state: &mut TccState, bytes: i32) -> TccResult<()>;

    // -------------------------------------------------------------------
    // Jumps and control flow
    // -------------------------------------------------------------------

    /// Generate unconditional jump, returns jump list head.
    ///
    /// Emits an unconditional jump instruction.  If `t != 0`, the new jump
    /// is linked into the forward-reference chain starting at `t`.
    /// Returns the offset of the new jump for later patching via
    /// [`gsym_addr`](CodegenBackend::gsym_addr).
    ///
    /// C equivalent: `gjmp()` (`tcc.h:1632`).
    fn gjmp(&mut self, state: &mut TccState, t: i32) -> TccResult<i32>;

    /// Generate unconditional jump to absolute address `a`.
    ///
    /// Unlike [`gjmp`](CodegenBackend::gjmp), the target address is known
    /// at emission time, so no forward-reference patching is needed.
    ///
    /// C equivalent: `gjmp_addr()` (`tcc.h:1633`).
    fn gjmp_addr(&mut self, state: &mut TccState, a: i32) -> TccResult<()>;

    /// Generate conditional jump based on `op`, returns jump list head.
    ///
    /// Emits a conditional jump instruction for comparison operator `op`.
    /// If `t != 0`, the new jump is linked into the chain at `t`.
    /// Returns the chain head for later patching.
    ///
    /// C equivalent: `gjmp_cond()` (`tcc.h:1634`).
    fn gjmp_cond(&mut self, state: &mut TccState, op: i32, t: i32) -> TccResult<i32>;

    /// Append jump at `t` to jump chain `n`, returns new chain head.
    ///
    /// Links two forward-reference chains together.  Used when merging
    /// branch targets from `if`/`else` or `||`/`&&` expressions.
    ///
    /// C equivalent: `gjmp_append()` (`tcc.h:1635`).
    fn gjmp_append(&mut self, state: &mut TccState, n: i32, t: i32) -> TccResult<i32>;

    // -------------------------------------------------------------------
    // Arithmetic and conversion operations
    // -------------------------------------------------------------------

    /// Generate integer binary operation.
    ///
    /// Emits machine code for the integer operation `op` (addition,
    /// subtraction, multiplication, division, shift, bitwise, comparison)
    /// operating on the top two value-stack entries.
    ///
    /// C equivalent: `gen_opi()` (`tcc.h:1636`).
    fn gen_opi(&mut self, state: &mut TccState, op: i32) -> TccResult<()>;

    /// Generate floating-point binary operation.
    ///
    /// Emits machine code for the floating-point operation `op` (addition,
    /// subtraction, multiplication, division, comparison) operating on the
    /// top two value-stack entries.
    ///
    /// C equivalent: `gen_opf()` (`tcc.h:1637`).
    fn gen_opf(&mut self, state: &mut TccState, op: i32) -> TccResult<()>;

    /// Generate float-to-integer conversion.
    ///
    /// Converts the value-stack top from a floating-point type to the
    /// integer type indicated by `t` (a `VT_*` type constant).
    ///
    /// C equivalent: `gen_cvt_ftoi()` (`tcc.h:1638`).
    fn gen_cvt_ftoi(&mut self, state: &mut TccState, t: i32) -> TccResult<()>;

    /// Generate integer-to-float conversion.
    ///
    /// Converts the value-stack top from an integer type to the
    /// floating-point type indicated by `t` (a `VT_*` type constant).
    ///
    /// C equivalent: `gen_cvt_itof()` (`tcc.h:1639`).
    fn gen_cvt_itof(&mut self, state: &mut TccState, t: i32) -> TccResult<()>;

    /// Generate float-to-float conversion (e.g., double ↔ float).
    ///
    /// Converts the value-stack top between floating-point types as
    /// indicated by `t` (a `VT_*` type constant).
    ///
    /// C equivalent: `gen_cvt_ftof()` (`tcc.h:1640`).
    fn gen_cvt_ftof(&mut self, state: &mut TccState, t: i32) -> TccResult<()>;

    // -------------------------------------------------------------------
    // Computed goto
    // -------------------------------------------------------------------

    /// Generate computed goto (indirect jump through value stack top).
    ///
    /// Emits an indirect jump to the address on top of the value stack.
    /// Used for GCC-style computed `goto *ptr` and `switch` dispatch tables.
    ///
    /// C equivalent: `ggoto()` (`tcc.h:1641`).
    fn ggoto(&mut self, state: &mut TccState) -> TccResult<()>;

    // -------------------------------------------------------------------
    // Raw opcode emission
    // -------------------------------------------------------------------

    /// Emit opcode byte(s) to code section.
    ///
    /// Writes the raw opcode value `c` to the current text section.  For
    /// x86/x86-64 this writes one to four bytes; for ARM it writes a 32-bit
    /// instruction word.  Not available on the C67 target where instruction
    /// encoding uses a different mechanism.
    ///
    /// C equivalent: `o()` (`tcc.h:1643`) — `#ifndef TCC_TARGET_C67`.
    fn o(&mut self, state: &mut TccState, c: u32) -> TccResult<()>;

    // -------------------------------------------------------------------
    // Variable-Length Array (VLA) support
    // -------------------------------------------------------------------

    /// Save stack pointer for VLA (variable-length array) scope.
    ///
    /// Stores the current stack pointer to the local variable at stack
    /// offset `addr` so it can be restored when leaving the VLA scope.
    ///
    /// C equivalent: `gen_vla_sp_save()` (`tcc.h:1645`).
    fn gen_vla_sp_save(&mut self, state: &mut TccState, addr: i32) -> TccResult<()>;

    /// Restore stack pointer from VLA scope.
    ///
    /// Loads the saved stack pointer from the local variable at stack
    /// offset `addr`, undoing VLA allocations made since the save.
    ///
    /// C equivalent: `gen_vla_sp_restore()` (`tcc.h:1646`).
    fn gen_vla_sp_restore(&mut self, state: &mut TccState, addr: i32) -> TccResult<()>;

    /// Allocate VLA on stack with given type and alignment.
    ///
    /// Emits code to subtract the allocation size (from the value stack top)
    /// from the stack pointer, aligned to `align` bytes, for a VLA of
    /// C type `type_`.
    ///
    /// The `type_.t` field determines the element type for computing the
    /// total allocation size.
    ///
    /// C equivalent: `gen_vla_alloc()` (`tcc.h:1647`).
    fn gen_vla_alloc(&mut self, state: &mut TccState, type_: &CType, align: i32) -> TccResult<()>;
}

// ===========================================================================
//  GotPltEntry Enum (tcc.h:1602–1607)
// ===========================================================================

/// GOT/PLT entry type classification for linker relocation processing.
///
/// Determines whether and when a GOT (Global Offset Table) or PLT
/// (Procedure Linkage Table) entry should be generated for a given
/// relocation type.  The linker backend's
/// [`gotplt_entry_type`](LinkerBackend::gotplt_entry_type) method returns
/// one of these variants for each relocation.
///
/// The variants are ordered so that `NoEntry` is first, ensuring that
/// unknown/unrecognised relocation types default to not generating any
/// GOT/PLT entry.
///
/// C equivalent: `enum gotplt_entry` in `tcc.h:1602–1607`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum GotPltEntry {
    /// Never generate a GOT/PLT entry.
    ///
    /// Used for relocation types like `GLOB_DAT` and `JMP_SLOT` that are
    /// filled in by the dynamic linker at load time.
    NoEntry = 0,

    /// Only build a GOT entry (no PLT trampoline).
    ///
    /// Used for relocation types like `TPOFF` (thread-local storage offset)
    /// that require a GOT slot but not an executable PLT stub.
    BuildGotOnly = 1,

    /// Generate a GOT/PLT entry only if the symbol is undefined.
    ///
    /// This is the most common classification: the linker generates a PLT
    /// entry only for symbols that cannot be resolved statically (i.e.
    /// symbols imported from shared libraries).
    AutoEntry = 2,

    /// Always generate a GOT/PLT entry regardless of symbol definition.
    ///
    /// Used for relocation types like `PLTOFF` that always require an
    /// indirection through the PLT even for locally-defined symbols.
    AlwaysEntry = 3,
}

// ===========================================================================
//  LinkerBackend Trait (tcc.h:1596–1617)
// ===========================================================================

/// Architecture-specific linker backend interface.
///
/// This trait defines the relocation processing, GOT/PLT generation, and
/// PLT patching operations that each architecture must implement in its
/// `xxx-link.c` equivalent module.
///
/// The methods here are called by the format-independent linker in
/// `src/linker/elf.rs` during the final link step after all relocations
/// have been collected.
///
/// C equivalent: Functions in `xxx-link.c` files and relocation dispatch
/// in `tccelf.c`.
pub(crate) trait LinkerBackend {
    /// Classify relocation as code (1) or data (0).
    ///
    /// Returns `1` if `reloc_type` represents a code relocation (e.g.
    /// branch, call, PLT-relative), `0` if it represents a data relocation
    /// (e.g. absolute address, GOT offset), or `-1` if the relocation type
    /// is unrecognised.
    ///
    /// C equivalent: `code_reloc()` (`tcc.h:1598`).
    fn code_reloc(&self, reloc_type: i32) -> i32;

    /// Determine GOT/PLT entry type for a relocation.
    ///
    /// Returns a [`GotPltEntry`] variant indicating whether and when a
    /// GOT or PLT entry should be generated for `reloc_type`.
    ///
    /// C equivalent: `gotplt_entry_type()` (`tcc.h:1599`).
    fn gotplt_entry_type(&self, reloc_type: i32) -> GotPltEntry;

    /// Apply a relocation to the given location.
    ///
    /// Patches the byte slice `ptr` (a view into section data) with the
    /// resolved value `val` at address `addr`, according to the
    /// architecture-specific relocation formula for `rel_type`.
    ///
    /// - `state` — compiler state (for section access).
    /// - `rel_type` — architecture-specific relocation type constant.
    /// - `ptr` — mutable slice into the section data at the relocation offset.
    /// - `addr` — virtual address of the relocation site.
    /// - `val` — resolved symbol value (address + addend).
    ///
    /// C equivalent: `relocate()` (`tcc.h:1617`).
    fn relocate(
        &self,
        state: &mut TccState,
        rel_type: i32,
        ptr: &mut [u8],
        addr: u64,
        val: u64,
    ) -> TccResult<()>;

    /// Create a PLT entry at the given GOT offset.
    ///
    /// Writes a PLT trampoline that loads the target address from
    /// `got_offset` in the GOT section and jumps to it.  Returns the
    /// offset of the created PLT entry within the PLT section.
    ///
    /// C equivalent: `create_plt_entry()` (`tcc.h:1610`).
    fn create_plt_entry(
        &mut self,
        state: &mut TccState,
        got_offset: u32,
    ) -> TccResult<u32>;

    /// Relocate PLT entries after final addresses are known.
    ///
    /// Called after all section addresses have been assigned, this method
    /// patches the PLT stub instructions that depend on absolute addresses
    /// (e.g. the GOT base address used in PLT0).
    ///
    /// C equivalent: `relocate_plt()` (`tcc.h:1611`).
    fn relocate_plt(&mut self, state: &mut TccState) -> TccResult<()>;
}

// ===========================================================================
//  Target Dispatch — create_backend()
// ===========================================================================

/// Create the appropriate code generation backend based on target architecture.
///
/// This function implements the runtime target dispatch described in
/// AAP §0.4.1.  Cargo feature gates control which backends are compiled
/// in; requesting a backend that is not compiled returns
/// [`TccError::UnsupportedTarget`].
///
/// # Target name aliases
///
/// Each backend accepts multiple name variants for convenience:
///
/// | Feature    | Accepted names                       |
/// |------------|--------------------------------------|
/// | `x86_64`   | `"x86_64"`, `"x86-64"`, `"amd64"`   |
/// | `i386`     | `"i386"`, `"x86"`, `"i686"`          |
/// | `arm`      | `"arm"`, `"armv4"`                   |
/// | `arm64`    | `"arm64"`, `"aarch64"`               |
/// | `riscv64`  | `"riscv64"`                          |
/// | *(always)* | `"c67"`, `"tms320c67"`               |
///
/// # Errors
///
/// Returns [`TccError::UnsupportedTarget`] if:
/// - The target name is not recognised, or
/// - The target's Cargo feature is not enabled.
///
/// C equivalent: Compile-time `#ifdef TCC_TARGET_*` selection in `tcc.h`.
pub(crate) fn create_backend(target: &str) -> TccResult<Box<dyn CodegenBackend>> {
    match target {
        #[cfg(feature = "x86_64")]
        "x86_64" | "x86-64" | "amd64" => Ok(Box::new(x86_64::X86_64Backend::new())),

        #[cfg(feature = "i386")]
        "i386" | "x86" | "i686" => Ok(Box::new(i386::I386Backend::new())),

        #[cfg(feature = "arm")]
        "arm" | "armv4" => Ok(Box::new(arm::ArmBackend::new())),

        #[cfg(feature = "arm64")]
        "arm64" | "aarch64" => Ok(Box::new(arm64::Arm64Backend::new())),

        #[cfg(feature = "riscv64")]
        "riscv64" => Ok(Box::new(riscv64::Riscv64Backend::new())),

        "c67" | "tms320c67" => Ok(Box::new(c67::C67Backend::new())),

        _ => Err(TccError::UnsupportedTarget(target.to_string())),
    }
}

// ===========================================================================
//  Byte-Order Utility Functions (tcc.h:1649–1672)
// ===========================================================================
//
// These inline helpers read, write, and add little-endian integer values
// in byte slices.  They are used throughout the linker and code-generation
// backends for in-place patching of relocations, instruction immediates,
// and section data.
//
// The Rust implementations use `from_le_bytes()` / `to_le_bytes()` and
// `copy_from_slice()` for zero-cast, clippy-clean byte manipulation.
//
// # Panics
//
// All functions panic if the provided slice has fewer bytes than the
// integer width (2, 4, or 8 bytes).  This is a deliberate safety
// improvement over the C originals, which silently produced undefined
// behaviour on short buffers.

/// Read a little-endian 16-bit unsigned value from `p`.
///
/// # Panics
///
/// Panics if `p.len() < 2`.
///
/// C equivalent: `read16le()` (`tcc.h:1649–1651`).
#[inline]
pub(crate) fn read16le(p: &[u8]) -> u16 {
    u16::from_le_bytes([p[0], p[1]])
}

/// Write a little-endian 16-bit unsigned value to `p`.
///
/// # Panics
///
/// Panics if `p.len() < 2`.
///
/// C equivalent: `write16le()` (`tcc.h:1652–1654`).
#[inline]
pub(crate) fn write16le(p: &mut [u8], x: u16) {
    let bytes = x.to_le_bytes();
    p[0] = bytes[0];
    p[1] = bytes[1];
}

/// Read a little-endian 32-bit unsigned value from `p`.
///
/// # Panics
///
/// Panics if `p.len() < 4`.
///
/// C equivalent: `read32le()` (`tcc.h:1655–1657`).
#[inline]
pub(crate) fn read32le(p: &[u8]) -> u32 {
    u32::from_le_bytes([p[0], p[1], p[2], p[3]])
}

/// Write a little-endian 32-bit unsigned value to `p`.
///
/// # Panics
///
/// Panics if `p.len() < 4`.
///
/// C equivalent: `write32le()` (`tcc.h:1658–1660`).
#[inline]
pub(crate) fn write32le(p: &mut [u8], x: u32) {
    let bytes = x.to_le_bytes();
    p[..4].copy_from_slice(&bytes);
}

/// Add a signed 32-bit value to a little-endian 32-bit value in-place.
///
/// Reads the current little-endian `u32` from `p`, performs a wrapping
/// addition with signed `x`, and writes the result back.  Wrapping
/// semantics match the C original which uses unsigned arithmetic.
///
/// # Panics
///
/// Panics if `p.len() < 4`.
///
/// C equivalent: `add32le()` (`tcc.h:1661–1663`).
#[inline]
pub(crate) fn add32le(p: &mut [u8], x: i32) {
    let current = read32le(p);
    write32le(p, current.wrapping_add_signed(x));
}

/// Read a little-endian 64-bit unsigned value from `p`.
///
/// # Panics
///
/// Panics if `p.len() < 8`.
///
/// C equivalent: `read64le()` (`tcc.h:1664–1666`).
#[inline]
pub(crate) fn read64le(p: &[u8]) -> u64 {
    u64::from_le_bytes([p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7]])
}

/// Write a little-endian 64-bit unsigned value to `p`.
///
/// # Panics
///
/// Panics if `p.len() < 8`.
///
/// C equivalent: `write64le()` (`tcc.h:1667–1669`).
#[inline]
pub(crate) fn write64le(p: &mut [u8], x: u64) {
    let bytes = x.to_le_bytes();
    p[..8].copy_from_slice(&bytes);
}

/// Add a signed 64-bit value to a little-endian 64-bit value in-place.
///
/// Reads the current little-endian `u64` from `p`, performs a wrapping
/// addition with signed `x`, and writes the result back.  Wrapping
/// semantics match the C original which uses unsigned arithmetic.
///
/// # Panics
///
/// Panics if `p.len() < 8`.
///
/// C equivalent: `add64le()` (`tcc.h:1670–1672`).
#[inline]
pub(crate) fn add64le(p: &mut [u8], x: i64) {
    let current = read64le(p);
    write64le(p, current.wrapping_add_signed(x));
}

// ===========================================================================
//  Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -------------------------------------------------------------------
    // Byte-order utility function tests
    // -------------------------------------------------------------------

    #[test]
    fn test_read_write_16le() {
        let mut buf = [0u8; 4];
        write16le(&mut buf, 0x1234);
        assert_eq!(buf[0], 0x34);
        assert_eq!(buf[1], 0x12);
        assert_eq!(read16le(&buf), 0x1234);
    }

    #[test]
    fn test_read_write_16le_boundary() {
        // Verify zero and max values
        let mut buf = [0xFFu8; 2];
        write16le(&mut buf, 0);
        assert_eq!(read16le(&buf), 0);

        write16le(&mut buf, u16::MAX);
        assert_eq!(read16le(&buf), u16::MAX);
    }

    #[test]
    fn test_read_write_32le() {
        let mut buf = [0u8; 8];
        write32le(&mut buf, 0xDEAD_BEEF);
        assert_eq!(buf[0], 0xEF);
        assert_eq!(buf[1], 0xBE);
        assert_eq!(buf[2], 0xAD);
        assert_eq!(buf[3], 0xDE);
        assert_eq!(read32le(&buf), 0xDEAD_BEEF);
    }

    #[test]
    fn test_read_write_32le_boundary() {
        let mut buf = [0u8; 4];
        write32le(&mut buf, 0);
        assert_eq!(read32le(&buf), 0);

        write32le(&mut buf, u32::MAX);
        assert_eq!(read32le(&buf), u32::MAX);
    }

    #[test]
    fn test_add32le_positive() {
        let mut buf = [0u8; 4];
        write32le(&mut buf, 100);
        add32le(&mut buf, 50);
        assert_eq!(read32le(&buf), 150);
    }

    #[test]
    fn test_add32le_negative() {
        let mut buf = [0u8; 4];
        write32le(&mut buf, 100);
        add32le(&mut buf, -30);
        assert_eq!(read32le(&buf), 70);
    }

    #[test]
    fn test_add32le_wrapping() {
        let mut buf = [0u8; 4];
        write32le(&mut buf, 0);
        add32le(&mut buf, -1);
        assert_eq!(read32le(&buf), u32::MAX);
    }

    #[test]
    fn test_read_write_64le() {
        let mut buf = [0u8; 16];
        write64le(&mut buf, 0x0102_0304_0506_0708);
        assert_eq!(buf[0], 0x08);
        assert_eq!(buf[1], 0x07);
        assert_eq!(buf[2], 0x06);
        assert_eq!(buf[3], 0x05);
        assert_eq!(buf[4], 0x04);
        assert_eq!(buf[5], 0x03);
        assert_eq!(buf[6], 0x02);
        assert_eq!(buf[7], 0x01);
        assert_eq!(read64le(&buf), 0x0102_0304_0506_0708);
    }

    #[test]
    fn test_read_write_64le_boundary() {
        let mut buf = [0u8; 8];
        write64le(&mut buf, 0);
        assert_eq!(read64le(&buf), 0);

        write64le(&mut buf, u64::MAX);
        assert_eq!(read64le(&buf), u64::MAX);
    }

    #[test]
    fn test_add64le_positive() {
        let mut buf = [0u8; 8];
        write64le(&mut buf, 1000);
        add64le(&mut buf, 2000);
        assert_eq!(read64le(&buf), 3000);
    }

    #[test]
    fn test_add64le_negative() {
        let mut buf = [0u8; 8];
        write64le(&mut buf, 1000);
        add64le(&mut buf, -500);
        assert_eq!(read64le(&buf), 500);
    }

    #[test]
    fn test_add64le_wrapping() {
        let mut buf = [0u8; 8];
        write64le(&mut buf, 0);
        add64le(&mut buf, -1);
        assert_eq!(read64le(&buf), u64::MAX);
    }

    // -------------------------------------------------------------------
    // GotPltEntry enum tests
    // -------------------------------------------------------------------

    #[test]
    fn test_gotplt_entry_discriminants() {
        assert_eq!(GotPltEntry::NoEntry as i32, 0);
        assert_eq!(GotPltEntry::BuildGotOnly as i32, 1);
        assert_eq!(GotPltEntry::AutoEntry as i32, 2);
        assert_eq!(GotPltEntry::AlwaysEntry as i32, 3);
    }

    #[test]
    fn test_gotplt_entry_equality() {
        assert_eq!(GotPltEntry::NoEntry, GotPltEntry::NoEntry);
        assert_ne!(GotPltEntry::NoEntry, GotPltEntry::AlwaysEntry);
    }

    #[test]
    fn test_gotplt_entry_clone() {
        let entry = GotPltEntry::AutoEntry;
        let cloned = entry;
        assert_eq!(entry, cloned);
    }

    // -------------------------------------------------------------------
    // create_backend dispatch tests
    // -------------------------------------------------------------------

    #[test]
    fn test_create_backend_unknown_target() {
        let result = create_backend("nonexistent_arch");
        assert!(result.is_err());
        match result {
            Err(TccError::UnsupportedTarget(name)) => {
                assert_eq!(name, "nonexistent_arch");
            }
            _ => panic!("Expected UnsupportedTarget error"),
        }
    }

    #[test]
    fn test_create_backend_empty_target() {
        let result = create_backend("");
        assert!(result.is_err());
    }
}
