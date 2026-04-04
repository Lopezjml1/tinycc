// Copyright (c) TinyCC contributors. LGPL licensed.
// Ported from il-gen.c (657 lines) and il-opcodes.h (251 lines) to Rust.

//! .NET IL/CIL bytecode generation backend (EXPERIMENTAL)
//!
//! This module implements the [`CodegenBackend`] trait for .NET Common Intermediate
//! Language (CIL) bytecode output. Ported from `il-gen.c` (657 lines) +
//! `il-opcodes.h` (251 lines).
//!
//! # Warning — Experimental / Historical
//!
//! This backend is **experimental** and has been non-functional since 2003 in the
//! original C codebase (`#error this code has bit-rotted since 2003`). It is
//! included for completeness and historical reference per the AAP scope
//! requirements. It is **only compiled** when the `il` Cargo feature flag is
//! enabled (gated in the parent [`crate::arch`] module).
//!
//! # Architecture Overview
//!
//! The IL backend uses a fundamentally different execution model from the native
//! code backends (i386, x86_64, ARM, etc.):
//!
//! - **Stack-based virtual machine** — not register-based. The .NET CLR
//!   evaluates expressions using an operand evaluation stack.
//! - **Only 3 virtual "registers"** (evaluation stack positions): `ST0`, `ST1`,
//!   `ST2`. These map to TCC's register allocator slots but represent CIL
//!   evaluation stack depth, not hardware registers.
//! - **Output is CIL assembly text** — not binary machine code. The backend
//!   writes `.method` headers, CIL mnemonics, and labels into a text buffer
//!   (`il_output`) rather than emitting raw bytes into an ELF section.
//! - **Targets the 32-bit .NET CLR runtime** — pointer size is 4 bytes, long
//!   double maps to `float64` (no 80-bit extended precision).
//!
//! # Submodules
//!
//! - [`gen`] — CIL opcode definitions, byte emission helpers, and all code
//!   generation functions (load, store, function prologue/epilogue, jumps,
//!   arithmetic/comparison operations, type conversions).

pub mod gen;

// ---------------------------------------------------------------------------
// Imports (whitelist-verified from depends_on_files)
// ---------------------------------------------------------------------------

use crate::arch::CodegenBackend;
use crate::error::{TccError, TccResult};
use crate::types::{CType, SValue, Sym};

// ===========================================================================
// IL Architecture Constants — Port of il-gen.c lines 23-69 (TARGET_DEFS_ONLY)
// ===========================================================================

// --- Number of registers ------------------------------------------------

/// Number of available registers (evaluation stack positions) for the allocator.
///
/// Unlike native backends with actual hardware registers, the IL backend uses
/// evaluation stack positions as "registers". This is a stack-based VM with
/// only 3 usable slots.
///
/// Source: `il-gen.c` line 24 — `#define NB_REGS 3`
pub const NB_REGS: usize = 3;

// --- Register class bitmasks -------------------------------------------
// Classes are sorted from most general to most precise. The `gv2()` code
// in the common codegen layer depends on this ordering.

/// Any stack entry — most general register class.
///
/// Source: `il-gen.c` line 29 — `#define RC_ST 0x0001`
pub const RC_ST: i32 = 0x0001;

/// Top of evaluation stack (stack position 0).
///
/// Source: `il-gen.c` line 30 — `#define RC_ST0 0x0002`
pub const RC_ST0: i32 = 0x0002;

/// Second from top of evaluation stack (stack position 1).
///
/// Source: `il-gen.c` line 31 — `#define RC_ST1 0x0004`
pub const RC_ST1: i32 = 0x0004;

// --- Aliased register classes ------------------------------------------
// In the IL backend the evaluation stack is unified — the same stack is
// used for integers and floats. So RC_INT == RC_FLOAT == RC_ST.

/// Integer register class = any stack entry (IL uses a unified stack).
///
/// Source: `il-gen.c` line 33 — `#define RC_INT RC_ST`
///
/// Note: This intentionally shadows [`crate::arch::RC_INT`] (which is 0x0001
/// for the generic case). The IL backend redefines it because the stack-based
/// model conflates integer and float "registers".
pub const RC_INT: i32 = RC_ST;

/// Float register class = any stack entry (IL uses a unified stack).
///
/// Source: `il-gen.c` line 34 — `#define RC_FLOAT RC_ST`
///
/// Note: This intentionally differs from [`crate::arch::RC_FLOAT`] (0x0002).
/// In the IL backend, float and integer values share the same evaluation stack.
pub const RC_FLOAT: i32 = RC_ST;

/// Function integer return: top of evaluation stack.
///
/// Source: `il-gen.c` line 35 — `#define RC_IRET RC_ST0`
pub const RC_IRET: i32 = RC_ST0;

/// Function long long return: also top of stack (IL uses 64-bit stack slots).
///
/// Source: `il-gen.c` line 36 — `#define RC_LRET RC_ST0`
pub const RC_LRET: i32 = RC_ST0;

/// Function float return: top of evaluation stack.
///
/// Source: `il-gen.c` line 37 — `#define RC_FRET RC_ST0`
pub const RC_FRET: i32 = RC_ST0;

// --- Register enumeration -----------------------------------------------
// These correspond to CIL evaluation stack depth positions.

/// Stack position 0 — top of the evaluation stack.
///
/// Source: `il-gen.c` line 41 — `REG_ST0 = 0,`
pub const REG_ST0: i32 = 0;

/// Stack position 1 — second from top of the evaluation stack.
///
/// Source: `il-gen.c` line 42 — `REG_ST1,`
pub const REG_ST1: i32 = 1;

/// Stack position 2 — third from top of the evaluation stack.
///
/// Source: `il-gen.c` line 43 — `REG_ST2,`
pub const REG_ST2: i32 = 2;

// --- Return register aliases -------------------------------------------

/// Single-word integer return register = top of stack.
///
/// Source: `il-gen.c` line 53 — `#define REG_IRET REG_ST0`
pub const REG_IRET: i32 = REG_ST0;

/// Second-word return register (for `long long`) = top of stack.
///
/// Source: `il-gen.c` line 54 — `#define REG_LRET REG_ST0`
pub const REG_LRET: i32 = REG_ST0;

/// Float return register = top of stack.
///
/// Source: `il-gen.c` line 55 — `#define REG_FRET REG_ST0`
pub const REG_FRET: i32 = REG_ST0;

// --- Architecture characteristics --------------------------------------

/// Pointer size in bytes — IL targets 32-bit .NET CLR.
///
/// Source: `il-gen.c` line 65 — `#define PTR_SIZE 4`
pub const PTR_SIZE: usize = 4;

/// Long double size in bytes — mapped to `float64` in CIL (no 80-bit extended).
///
/// Source: `il-gen.c` line 68 — `#define LDOUBLE_SIZE 8`
pub const LDOUBLE_SIZE: usize = 8;

/// Long double alignment in bytes.
///
/// Source: `il-gen.c` line 69 — `#define LDOUBLE_ALIGN 8`
pub const LDOUBLE_ALIGN: usize = 8;

/// Argument variable numbers start from this base value.
///
/// Used to distinguish function arguments from local variables in the IL
/// backend. Local variable indices are `0`-based; argument indices are
/// `ARG_BASE + n`.
///
/// Source: `il-gen.c` line 96 — `#define ARG_BASE 0x70000000`
pub const ARG_BASE: i32 = 0x7000_0000;

/// Function parameters are **not** evaluated in reverse order for IL.
///
/// Source: `il-gen.c` line 58 (commented out) — `/* #define INVERT_FUNC_PARAMS */`
pub const INVERT_FUNC_PARAMS: bool = false;

/// Structures are **not** passed as pointers by default for IL.
///
/// Source: `il-gen.c` line 62 (commented out) — `/* #define FUNC_STRUCT_PARAM_AS_PTR */`
pub const FUNC_STRUCT_PARAM_AS_PTR: bool = false;

// ===========================================================================
// Register Class Table
// ===========================================================================

/// Register class table — maps register number (stack position) to class bitmask.
///
/// The table has exactly [`NB_REGS`] (3) entries, one per evaluation stack slot:
///
/// | Index | Position | Class Mask                       |
/// |-------|----------|----------------------------------|
/// | 0     | ST0      | `RC_ST \| RC_ST0` (0x0003)       |
/// | 1     | ST1      | `RC_ST \| RC_ST1` (0x0005)       |
/// | 2     | ST2      | `RC_ST`           (0x0001)       |
///
/// Source: `il-gen.c` lines 46-50
pub const REG_CLASSES: [i32; NB_REGS] = [
    RC_ST | RC_ST0, // ST0 — top of evaluation stack
    RC_ST | RC_ST1, // ST1 — second position
    RC_ST,          // ST2 — third position (general class only)
];

// ===========================================================================
// IlBackend — Backend State
// ===========================================================================

/// .NET IL/CIL code generation backend state.
///
/// Unlike native code backends that emit machine instructions to binary
/// sections, the IL backend generates CIL assembly text. The "code buffer"
/// is primarily the textual IL output in [`il_output`](Self::il_output).
///
/// This backend is **EXPERIMENTAL** — ported from C code that was
/// non-functional since 2003. It is only available when the `il` Cargo
/// feature is enabled.
///
/// All compilation state is encapsulated within this struct — there is no
/// global mutable state.
pub struct IlBackend {
    /// Whether the output file has been initialized with the `mscorlib`
    /// assembly reference header.
    ///
    /// Source: `il-gen.c` line 98 — `static FILE *il_outfile` (lazily
    /// initialized via [`gen::init_outfile`]).
    pub outfile_initialized: bool,

    /// IL text output buffer (replaces `fprintf` to `il_outfile` in the C code).
    ///
    /// Accumulates the complete CIL assembly listing: `.assembly extern`,
    /// `.method` headers, opcode mnemonics, labels, and closing braces.
    pub il_output: String,

    /// Current code emission index — tracks the byte offset within the
    /// binary code buffer for label resolution and jump patching.
    pub ind: usize,

    /// Binary code buffer for IL bytecode emission.
    ///
    /// Stores the raw CIL opcode bytes emitted by [`gen::out_byte`],
    /// [`gen::out_op1`], etc. This parallels the native backends'
    /// `cur_text_section->data` buffer.
    pub code: Vec<u8>,
}

impl IlBackend {
    /// Creates a new IL backend instance with default (empty) state.
    ///
    /// The output file is not yet initialized; call
    /// [`gen::init_outfile`] to emit the `mscorlib` assembly reference
    /// before any code generation.
    pub fn new() -> Self {
        Self {
            outfile_initialized: false,
            il_output: String::new(),
            ind: 0,
            code: Vec::new(),
        }
    }
}

impl Default for IlBackend {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// CodegenBackend Trait Implementation
// ===========================================================================

impl CodegenBackend for IlBackend {
    // -------------------------------------------------------------------
    // Target identification and register metadata
    // -------------------------------------------------------------------

    /// Returns the predefined macro string identifying the IL target.
    ///
    /// This causes `-D__IL__` to be defined when compiling for the IL target.
    fn target_machine_defs(&self) -> &'static str {
        "__IL__\0"
    }

    /// Returns the register class table for the IL backend.
    ///
    /// See [`REG_CLASSES`] — 3 entries mapping evaluation stack positions to
    /// class bitmasks.
    fn reg_classes(&self) -> &[i32] {
        &REG_CLASSES
    }

    /// Returns the number of available registers (evaluation stack slots).
    ///
    /// Always 3 for the IL backend.
    fn nb_regs(&self) -> usize {
        NB_REGS
    }

    /// Returns the pointer size in bytes.
    ///
    /// Always 4 for the 32-bit .NET CLR target.
    fn ptr_size(&self) -> usize {
        PTR_SIZE
    }

    // -------------------------------------------------------------------
    // Symbol and label resolution
    // -------------------------------------------------------------------

    /// Patch a symbol address — **no-op** in the IL backend.
    ///
    /// The IL backend does not use native-style address patching; symbol
    /// resolution is handled by the .NET CLR at load time.
    ///
    /// Source: `il-gen.c` lines 236-238 — empty function body.
    fn gsym_addr(&mut self, _t: i32, _a: i32) -> TccResult<()> {
        // Intentionally empty — IL backend does not patch addresses.
        Ok(())
    }

    /// Emit a label at the current code position.
    ///
    /// Delegates to [`gen::gsym`] which writes `L<t>:` to the IL output.
    ///
    /// Source: `il-gen.c` lines 252-255.
    fn gsym(&mut self, t: i32) -> TccResult<()> {
        gen::gsym(self, t);
        Ok(())
    }

    // -------------------------------------------------------------------
    // Load / Store operations
    // -------------------------------------------------------------------

    /// Load a value described by `sv` into register `r` (stack position).
    ///
    /// Delegates to [`gen::load`] which emits the appropriate CIL `ldarg`,
    /// `ldloc`, `ldind`, or `ldc` opcode depending on the value's storage
    /// class and type.
    ///
    /// Source: `il-gen.c` lines 258-334.
    fn load(&mut self, r: i32, sv: &SValue) -> TccResult<()> {
        gen::load(self, r, sv)
    }

    /// Store register `r` (top of stack) into the location described by `sv`.
    ///
    /// Delegates to [`gen::store`] which emits the appropriate CIL `starg`,
    /// `stloc`, or `stind` opcode.
    ///
    /// Source: `il-gen.c` lines 337-379.
    fn store(&mut self, r: i32, sv: &SValue) -> TccResult<()> {
        gen::store(self, r, sv)
    }

    // -------------------------------------------------------------------
    // Function call / return interface
    // -------------------------------------------------------------------

    /// Determine whether structures are returned via a hidden pointer parameter.
    ///
    /// The IL backend always returns via the evaluation stack — structures
    /// are never returned in registers. Returns `(false, CType::default(), 0, 0)`.
    fn gfunc_sret(&self, _vt: &CType, _variadic: bool) -> (bool, CType, i32, i32) {
        // IL always returns via stack; no struct-in-register return.
        (false, CType::default(), 0, 0)
    }

    /// Generate a function call instruction.
    ///
    /// Delegates to [`gen::gfunc_call`] which emits either a CIL `call`
    /// (direct) or `calli` (indirect) instruction with the appropriate type
    /// signature.
    ///
    /// Source: `il-gen.c` lines 402-417.
    fn gfunc_call(&mut self, nb_args: i32) -> TccResult<()> {
        gen::gfunc_call(self, nb_args)
    }

    /// Generate function prologue.
    ///
    /// Delegates to [`gen::gfunc_prolog`] which emits the `.method` header,
    /// `.maxstack`, `.locals`, and optional `.entrypoint` directive.
    ///
    /// Source: `il-gen.c` lines 420-458.
    fn gfunc_prolog(&mut self, func_sym: &Sym) -> TccResult<()> {
        gen::gfunc_prolog(self, func_sym)
    }

    /// Generate function epilogue.
    ///
    /// Delegates to [`gen::gfunc_epilog`] which emits the CIL `ret` opcode
    /// and the closing `}` brace.
    ///
    /// Source: `il-gen.c` lines 461-465.
    fn gfunc_epilog(&mut self) -> TccResult<()> {
        gen::gfunc_epilog(self)
    }

    // -------------------------------------------------------------------
    // NOP fill for alignment
    // -------------------------------------------------------------------

    /// Emit `n` CIL `nop` opcodes for alignment padding.
    ///
    /// IL does not need NOP padding for alignment in the same way native
    /// backends do, but we emit valid CIL `nop` (0x00) instructions to
    /// satisfy the interface contract.
    fn gen_fill_nops(&mut self, n: i32) -> TccResult<()> {
        for _ in 0..n {
            gen::out_op(self, gen::IlOpcode::Nop);
        }
        Ok(())
    }

    // -------------------------------------------------------------------
    // Jump generation
    // -------------------------------------------------------------------

    /// Generate an unconditional jump and return a label identifier for
    /// later patching.
    ///
    /// Delegates to [`gen::gjmp`] which emits `IL_OP_BR` with a forward
    /// reference label.
    ///
    /// Source: `il-gen.c` lines 468-471.
    fn gjmp(&mut self, t: i32) -> TccResult<i32> {
        Ok(gen::gjmp(self, t))
    }

    /// Generate an unconditional jump to a fixed address.
    ///
    /// Source: `il-gen.c` lines 474-478.
    fn gjmp_addr(&mut self, a: i32) -> TccResult<()> {
        gen::gjmp_addr(self, a);
        Ok(())
    }

    /// Generate a conditional branch based on comparison operator `op`.
    ///
    /// Delegates to [`gen::gtst`] which maps TCC comparison tokens
    /// (TOK_EQ, TOK_NE, TOK_LT, etc.) to the appropriate CIL branch
    /// opcodes (BEQ, BNE_UN, BLT, etc.).
    ///
    /// Source: `il-gen.c` lines 481-537.
    fn gjmp_cond(&mut self, op: i32, t: i32) -> TccResult<i32> {
        gen::gtst(self, op, t)
    }

    /// Append a jump target `t` to an existing jump chain `n`.
    ///
    /// Simple chain logic: if `n` is non-zero (existing chain), keep it;
    /// otherwise use `t` as the new chain head.
    fn gjmp_append(&mut self, n: i32, t: i32) -> TccResult<i32> {
        if n != 0 {
            Ok(n)
        } else {
            Ok(t)
        }
    }

    // -------------------------------------------------------------------
    // Integer and floating-point operations
    // -------------------------------------------------------------------

    /// Generate an integer binary operation.
    ///
    /// Delegates to [`gen::gen_opi`] which maps C operators (+, -, *, /,
    /// %, &, |, ^, <<, >>, comparisons) to CIL opcodes (ADD, SUB, MUL,
    /// DIV, REM, AND, OR, XOR, SHL, SHR, CEQ, etc.).
    ///
    /// Source: `il-gen.c` lines 540-602.
    fn gen_opi(&mut self, op: i32) -> TccResult<()> {
        gen::gen_opi(self, op)
    }

    /// Generate a floating-point binary operation.
    ///
    /// In the IL backend, the CIL evaluation stack uses the same opcodes
    /// for both integer and floating-point arithmetic. This simply
    /// delegates to [`gen::gen_opf`] (which in turn calls [`gen::gen_opi`]).
    ///
    /// Source: `il-gen.c` lines 606-610.
    fn gen_opf(&mut self, op: i32) -> TccResult<()> {
        gen::gen_opf(self, op)
    }

    // -------------------------------------------------------------------
    // Type conversion operations
    // -------------------------------------------------------------------

    /// Convert a floating-point value to an integer.
    ///
    /// Delegates to [`gen::gen_cvt_ftoi`] which emits `conv.u4`, `conv.i8`,
    /// `conv.u8`, or `conv.i4` depending on the target integer type.
    ///
    /// Source: `il-gen.c` lines 625-642.
    fn gen_cvt_ftoi(&mut self, t: i32) -> TccResult<()> {
        gen::gen_cvt_ftoi(self, t)
    }

    /// Convert an integer value to floating-point.
    ///
    /// Delegates to [`gen::gen_cvt_itof`] which emits `conv.r4` for
    /// `float` or `conv.r8` for `double`/`long double`.
    ///
    /// Source: `il-gen.c` lines 614-621.
    fn gen_cvt_itof(&mut self, t: i32) -> TccResult<()> {
        gen::gen_cvt_itof(self, t)
    }

    /// Convert between floating-point types (`float` ↔ `double`).
    ///
    /// Delegates to [`gen::gen_cvt_ftof`] which emits `conv.r4` for
    /// narrowing to `float` or `conv.r8` for widening to `double`.
    ///
    /// Source: `il-gen.c` lines 645-653.
    fn gen_cvt_ftof(&mut self, t: i32) -> TccResult<()> {
        gen::gen_cvt_ftof(self, t)
    }

    // -------------------------------------------------------------------
    // Unsupported operations — return errors
    // -------------------------------------------------------------------

    /// Computed goto — **not supported** in the IL/.NET backend.
    ///
    /// The .NET CLR does not support computed gotos (indirect jumps to
    /// arbitrary code addresses). Returns [`TccError::CodegenError`].
    fn ggoto(&mut self) -> TccResult<()> {
        Err(TccError::CodegenError {
            message: "Computed goto not supported in IL/.NET backend".to_string(),
        })
    }

    /// Emit a raw opcode byte.
    ///
    /// Delegates to [`gen::out_byte`] for single-byte emission into the
    /// code buffer.
    fn emit_opcode(&mut self, c: u32) -> TccResult<()> {
        gen::out_byte(self, c as u8);
        Ok(())
    }

    /// VLA stack pointer save — **not supported** in the IL/.NET backend.
    ///
    /// Variable-length arrays require direct stack pointer manipulation
    /// which is not available in the CIL instruction set. Returns
    /// [`TccError::CodegenError`].
    fn gen_vla_sp_save(&mut self, _addr: i32) -> TccResult<()> {
        Err(TccError::CodegenError {
            message: "Variable-length arrays not supported in IL/.NET backend"
                .to_string(),
        })
    }

    /// VLA stack pointer restore — **not supported** in the IL/.NET backend.
    ///
    /// See [`gen_vla_sp_save`](Self::gen_vla_sp_save) for rationale.
    fn gen_vla_sp_restore(&mut self, _addr: i32) -> TccResult<()> {
        Err(TccError::CodegenError {
            message: "Variable-length arrays not supported in IL/.NET backend"
                .to_string(),
        })
    }

    /// VLA allocation — **not supported** in the IL/.NET backend.
    ///
    /// See [`gen_vla_sp_save`](Self::gen_vla_sp_save) for rationale.
    fn gen_vla_alloc(&mut self, _typ: &CType, _align: i32) -> TccResult<()> {
        Err(TccError::CodegenError {
            message: "Variable-length arrays not supported in IL/.NET backend"
                .to_string(),
        })
    }

    // -------------------------------------------------------------------
    // Linker interface — stubs (IL does not produce native object files)
    // -------------------------------------------------------------------

    /// Determine if a relocation type requires code-level handling.
    ///
    /// Returns `-1` (unknown/unsupported) because the IL backend does not
    /// use native relocations — relocation is handled by the CLR.
    fn code_reloc(&self, _reloc_type: i32) -> i32 {
        -1
    }

    /// Determine GOT/PLT entry type for a relocation.
    ///
    /// Returns `0` (NO_GOTPLT_ENTRY) because the IL backend does not use
    /// GOT or PLT structures.
    fn gotplt_entry_type(&self, _reloc_type: i32) -> i32 {
        0
    }

    /// Apply a relocation — **no-op** for the IL backend.
    ///
    /// The IL backend does not produce native object files with ELF/PE
    /// relocations. Symbol resolution is deferred to the .NET CLR loader.
    fn relocate(
        &mut self,
        _rel_type: i32,
        _ptr: &mut [u8],
        _addr: u64,
        _val: u64,
    ) -> TccResult<()> {
        Ok(())
    }

    // -------------------------------------------------------------------
    // ELF constants — stubs (IL does not target ELF)
    // -------------------------------------------------------------------

    /// ELF machine type — `0` (not applicable for IL targets).
    fn elf_machine(&self) -> u16 {
        0
    }

    /// ELF default start address — `0` (not applicable for IL targets).
    fn elf_start_addr(&self) -> u64 {
        0
    }

    /// ELF page size — default `0x1000` (not used by the IL backend).
    fn elf_page_size(&self) -> u64 {
        0x1000
    }

    /// Whether PLT entries use PC-relative addressing — `false` for IL.
    fn pcrelative_dllplt(&self) -> bool {
        false
    }

    /// Whether DLL PLT entries need relocation — `false` for IL.
    fn relocate_dllplt(&self) -> bool {
        false
    }
}
