//! Binary format structure definitions for the TinyCC compiler.
//!
//! This module provides Rust translations of the binary format headers used
//! throughout the TinyCC compiler for generating object files, executables,
//! and debug information.
//!
//! # Submodules
//!
//! - [`elf`] — ELF (Executable and Linkable Format) structs and constants from `elf.h`
//! - [`dwarf`] — DWARF debug format constants from `dwarf.h`
//! - [`coff`] — COFF (Common Object File Format) structs and constants from `coff.h`
//! - [`stab`] — STABS debug symbol definitions from `stab.h` / `stab.def`
//!
//! All structs use `#[repr(C)]` for binary compatibility with their respective
//! format specifications. Integer types match exact C sizes (u8, u16, u32, u64).
//! No raw pointers are used — these are pure data definitions.

pub(crate) mod elf;
pub(crate) mod dwarf;
pub(crate) mod coff;
pub(crate) mod stab;
