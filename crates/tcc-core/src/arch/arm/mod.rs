//! ARM (ARMv4+) architecture backend
//!
//! Rust port of the ARM code generation, linking, and assembly
//! support from TCC. Sources: `arm-gen.c`, `arm-link.c`,
//! `arm-asm.c`, `arm-tok.h`.
//!
//! Feature flag: `arm`

pub mod tokens;
