//! x86_64 (AMD64) architecture backend
//!
//! Rust port of the x86-64 code generation, linking, and assembly
//! support from TCC. Sources: `x86_64-gen.c`, `x86_64-link.c`, `x86_64-asm.h`.
//!
//! Feature flag: `x86_64`

pub mod tokens;
