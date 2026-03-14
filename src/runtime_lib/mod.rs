//! Runtime library components for the TCC compiler.
//!
//! This module aggregates all runtime library components that provide support
//! for programs compiled with tinycc-rs. These components are linked into
//! compiled executables as needed (equivalent to `libtcc1.a` in the C version).
//!
//! ## Module Organization
//!
//! The runtime library translates TinyCC's `lib/` directory (18 files, 8,319 lines
//! of C and assembly) into safe Rust:
//!
//! | Rust Module       | C Source(s)                           | Purpose                          |
//! |-------------------|---------------------------------------|----------------------------------|
//! | `bcheck`          | `lib/bcheck.c` (2,261 lines)         | Bounds-checking runtime          |
//! | `libtcc1`         | `lib/libtcc1.c` (635 lines)          | 64-bit arithmetic helpers        |
//! | `tcov`            | `lib/tcov.c` (428 lines)             | Code coverage runtime            |
//! | `backtrace`       | `lib/bt-{exe,log,dll}.c` (201 lines) | Backtrace infrastructure         |
//! | `builtin`         | `lib/builtin.c` (164 lines)          | Compiler builtins (ffs/clz/ctz)  |
//! | `runmain`         | `lib/runmain.c` (86 lines)           | Constructor/destructor handling   |
//! | `armeabi`         | `lib/armeabi.c` (642 lines)          | ARM EABI helpers                 |
//! | `arm64_math`      | `lib/lib-arm64.c` (693 lines)        | ARM64 soft-float long double     |
//! | `armflush`        | `lib/armflush.c` (51 lines)          | ARM instruction cache flush      |
//! | `alloca`          | `lib/alloca.S` + `alloca-bt.S`       | Stack allocation helpers         |
//! | `atomic`          | `lib/atomic.S` (2,669 lines)         | Atomic operation implementations |
//! | `stdatomic`       | `lib/stdatomic.c` (105 lines)        | C11 atomic wrappers              |
//! | `pic86`           | `lib/pic86.S` (39 lines)             | x86 PIC thunk helpers            |
//! | `dsohandle`       | `lib/dsohandle.c` (1 line)           | DSO handle symbol                |

// Bounds-checking runtime — splay tree replaced by BTreeMap
pub(crate) mod bcheck;

// 64-bit arithmetic helpers — division, modulo, shift, float conversion
pub(crate) mod libtcc1;

// Code coverage runtime — gcov-compatible output
pub(crate) mod tcov;

// Backtrace infrastructure — initialization, logging, DLL helpers
pub(crate) mod backtrace;

// Compiler builtins — ffs, clz, ctz, popcount, parity via De Bruijn tables
pub(crate) mod builtin;

// Constructor/destructor handling — atexit/on_exit tables
pub(crate) mod runmain;

// ARM EABI helper functions — float-to-int, shifts, division
pub(crate) mod armeabi;

// ARM64 soft-float quad-precision (long double) arithmetic
pub(crate) mod arm64_math;

// ARM instruction cache flush — __clear_cache syscall wrapper
pub(crate) mod armflush;

// Stack allocation helpers — architecture-specific alloca support
pub(crate) mod alloca;

// Atomic operation implementations — leveraging std::sync::atomic
pub(crate) mod atomic;

// C11 atomic wrappers — exchange, fetch_add, etc. for 1/2/4/8-byte types
pub(crate) mod stdatomic;

// x86 PIC thunk helpers — __x86.get_pc_thunk.{ax,bx,cx,dx}
pub(crate) mod pic86;

// DSO handle symbol — __dso_handle with hidden visibility
pub(crate) mod dsohandle;
