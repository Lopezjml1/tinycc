//! Output format linker backends for the TinyCC compiler.
//!
//! This module provides backends for generating executables, shared libraries,
//! and object files in various binary formats:
//!
//! - [`elf`] — ELF (Executable and Linkable Format) for Linux/Unix/BSD targets
//! - [`pe`] — PE/COFF (Portable Executable) for Windows targets
//! - [`macho`] — Mach-O for macOS/iOS targets
//! - [`coff`] — COFF for TMS320C67 DSP target
//!
//! The ELF backend is the primary linker, handling section management, symbol
//! tables, relocations, GOT/PLT, and dynamic linking for most platforms.
//! The PE and Mach-O backends generate platform-specific executable formats
//! for Windows and macOS respectively. The COFF backend is specific to the
//! legacy C67 DSP target.
//!
//! ## Architecture
//!
//! Each backend translates the compiler's internal representation (sections
//! with `Vec<u8>` data buffers, typed symbol entries, and relocation records)
//! into the target binary format. The dispatch from compiler core to specific
//! backend is handled by `TccContext` based on the configured output type.
//!
//! ## Convenience Re-exports
//!
//! Commonly used ELF functions (section management, symbol table operations,
//! relocation helpers, GOT/PLT building, and runtime additions) are re-exported
//! at this module level for ergonomic access by other crate modules such as
//! `context`, `debug`, `runtime`, and target backends.
//!
//! C equivalents:
//! - `tccelf.c` (4,116 lines) → [`elf`] module
//! - `tccpe.c` (2,114 lines) → [`pe`] module
//! - `tccmacho.c` (2,476 lines) → [`macho`] module
//! - `tcccoff.c` (951 lines) → [`coff`] module

// =============================================================================
// Submodule Declarations
// =============================================================================
//
// All four linker backend submodules are declared with `pub(crate)` visibility —
// accessible within the crate but not part of the public API surface.
// This matches the C pattern where all linker functions are internal to the
// compiler and only exposed through the top-level libtcc API.

/// ELF (Executable and Linkable Format) output backend.
///
/// Primary linker for Linux, Unix, and BSD targets. Handles section creation,
/// symbol table management, relocations, GOT/PLT generation, dynamic linking,
/// and ELF object/executable/shared library output.
///
/// C equivalent: `tccelf.c` (4,116 lines)
pub(crate) mod elf;

/// PE/COFF (Portable Executable) output backend.
///
/// Generates Windows DLL and EXE files with import tables, export tables,
/// base relocations, unwind data, and resource sections. Available on all
/// host platforms to support cross-compilation workflows.
///
/// C equivalent: `tccpe.c` (2,114 lines)
pub(crate) mod pe;

/// Mach-O output backend.
///
/// Generates macOS 64-bit executables and dynamic libraries with segment
/// hierarchy, symbol tables, bind/rebase opcodes, export tries, and
/// TBD stub file parsing. Available on all host platforms for cross-compilation.
///
/// C equivalent: `tccmacho.c` (2,476 lines)
pub(crate) mod macho;

/// COFF output backend for TMS320C67 DSP target.
///
/// Generates COFF object files and executables for the legacy C67 DSP
/// architecture. Converts ELF internal representation to COFF format
/// with appropriate section headers, symbol tables, and debug info.
///
/// C equivalent: `tcccoff.c` (951 lines)
pub(crate) mod coff;

// =============================================================================
// Convenience Re-exports — ELF Functions
// =============================================================================
//
// The ELF backend provides the core infrastructure used by the entire compiler:
// section management, symbol tables, relocations, and output file generation.
// These functions are re-exported here so that consumers (context.rs, debug.rs,
// runtime.rs, target backends) can import them via `crate::linker::*` without
// reaching into the `elf` submodule directly.

// ---------------------------------------------------------------------------
// Primary output functions
// ---------------------------------------------------------------------------

// ELF helper functions — re-exported for future consumer modules.
// These are currently unused as the full compilation pipeline is not yet wired,
// but are preserved as the intended public(crate) interface for ELF operations.
// When the pipeline connects context.rs → codegen.rs → linker, these will be
// consumed.
#[allow(unused_imports)]
pub(crate) use elf::tcc_output_file;
#[allow(unused_imports)]
pub(crate) use elf::elf_output_obj;
#[allow(unused_imports)]
pub(crate) use elf::tccelf_new;
#[allow(unused_imports)]
pub(crate) use elf::tccelf_delete;
#[allow(unused_imports)]
pub(crate) use elf::tccelf_begin_file;
#[allow(unused_imports)]
pub(crate) use elf::tccelf_end_file;
#[allow(unused_imports)]
pub(crate) use elf::new_section;
#[allow(unused_imports)]
pub(crate) use elf::section_add;
#[allow(unused_imports)]
pub(crate) use elf::section_ptr_add;
#[allow(unused_imports)]
pub(crate) use elf::put_elf_sym;
#[allow(unused_imports)]
pub(crate) use elf::find_elf_sym;
#[allow(unused_imports)]
pub(crate) use elf::set_elf_sym;
#[allow(unused_imports)]
pub(crate) use elf::put_elf_str;
#[allow(unused_imports)]
pub(crate) use elf::put_elf_reloca;
#[allow(unused_imports)]
pub(crate) use elf::put_elf_reloc;
#[allow(unused_imports)]
pub(crate) use elf::get_sym_attr;
#[allow(unused_imports)]
pub(crate) use elf::build_got;
#[allow(unused_imports)]
pub(crate) use elf::build_got_entries;
#[allow(unused_imports)]
pub(crate) use elf::tcc_add_runtime;
#[allow(unused_imports)]
pub(crate) use elf::tcc_add_bcheck;
