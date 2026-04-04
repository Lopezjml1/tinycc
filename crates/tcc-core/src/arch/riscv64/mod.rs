//! RISC-V 64-bit architecture backend
//!
//! Rust port of the RISC-V 64-bit code generation, linking, and assembly
//! support from TCC. Sources: `riscv64-gen.c`, `riscv64-link.c`,
//! `riscv64-asm.c`, `riscv64-tok.h`.
//!
//! Feature flag: `riscv64`

pub mod tokens;
