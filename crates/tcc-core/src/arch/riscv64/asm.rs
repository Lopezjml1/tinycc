// Copyright (c) TinyCC contributors. LGPL licensed.
// Ported from riscv64-asm.c to Rust.
//
//! # RISC-V 64-bit Assembler
//!
//! Instruction encoding, operand parsing, and directive handling for RISC-V 64-bit
//! assembly.  Ported from `riscv64-asm.c` (2,628 lines).
//!
//! All public functions in this module are called by the [`CodegenBackend`]
//! trait implementation on [`Riscv64Backend`] or by the assembler framework.

// Imports will be used when the full implementation is provided.
// The assembler module requires TccResult and Riscv64Backend for all
// assembly encoding and operand parsing functions.
