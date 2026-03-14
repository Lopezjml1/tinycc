//! Linker backends — ELF, PE/COFF, Mach-O, and COFF output.
//!
//! This module aggregates all linker format backends:
//! - `elf` — ELF object/executable/shared library (primary Unix backend)
//! - `pe` — PE/COFF DLL and EXE (Windows backend, future)
//! - `macho` — Mach-O executable/dylib (macOS backend, future)
//! - `coff` — COFF output for C67 target (future)

pub mod elf;
