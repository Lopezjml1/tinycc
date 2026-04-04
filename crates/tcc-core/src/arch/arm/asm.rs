//! ARM assembly encoding — ARM/Thumb instruction encoding, operand
//! parsing, opcode tables for inline and standalone assembler.
//!
//! Port of `arm-asm.c` (3,092 lines).
//!
//! This module provides the ARM assembly encoding functions for the ARM
//! backend. It handles:
//! - GAS-syntax inline assembly parsing and encoding
//! - Standalone assembler mode for `.s` / `.S` files
//! - ARM (A32) and Thumb (T16/T32) instruction encoding
//! - Data processing, branch, load/store, VFP/NEON instruction forms
//! - Operand constraint resolution for inline asm
//! - ARM-specific register allocation for asm operands
//!
//! # Instruction Encoding
//!
//! ARM A32 instructions are fixed 32-bit with condition field:
//! `[cond:4][opcode fields:28]`
//!
//! Thumb T16 instructions are 16-bit:
//! `[opcode fields:16]`
//!
//! Thumb T32 (Thumb-2) instructions are 32-bit (two 16-bit halfwords):
//! `[hw1:16][hw2:16]`
//!
//! This module builds on the token definitions in [`super::tokens`].

// The full assembly encoding implementation will be provided by the
// asm.rs implementation agent. This module placeholder ensures that
// `pub mod asm;` in mod.rs compiles successfully.

// Note: The CodegenBackend trait does NOT delegate any assembly methods
// directly. Assembly operations are invoked through the assembler module
// (crate::assembler) which calls into architecture-specific assembly
// functions when processing inline asm or standalone .S files.
//
// The assembler module will import from this module directly, not through
// the CodegenBackend trait dispatch.
