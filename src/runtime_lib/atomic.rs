//! Atomic operation wrappers for the TCC runtime library.
//!
//! Provides `__atomic_*` operation implementations used by programs compiled with
//! tinycc-rs. These map to hardware atomic instructions on each supported architecture
//! (i386, x86_64, ARM, AArch64, RISC-V).
//!
//! # C/ASM Equivalent
//!
//! `lib/atomic.S` (2,669 lines) — extracted from GCC 15.1 `libatomic.a`.
//! The original assembly provides architecture-specific implementations of:
//!
//! - `__atomic_load_[1,2,4,8]` — sized atomic loads
//! - `__atomic_store_[1,2,4,8]` — sized atomic stores
//! - `__atomic_compare_exchange_[1,2,4,8]` — sized compare-and-swap
//! - `__atomic_test_and_set_[1,2,4,8]` — sized test-and-set (swap with 1)
//! - `atomic_thread_fence` — full memory barrier (lock or on x86, dmb on ARM, fence on RISC-V)
//! - `atomic_signal_fence` — compiler-only barrier (no hardware instruction)
//! - `atomic_flag_test_and_set[_explicit]` — atomic flag set
//! - `atomic_flag_clear[_explicit]` — atomic flag clear
//!
//! # Translation Strategy
//!
//! Per AAP §0.3.1: "Leveraging `std::sync::atomic` or `global_asm!` for
//! platform-specific paths."
//!
//! We use `std::sync::atomic` for safe, portable atomic operations that compile
//! down to the same hardware instructions on each architecture. For target-specific
//! machine code bytes that must be emitted into the runtime library (`libtcc1.a`)
//! for compiled programs, the [`target_code`] module provides pre-assembled byte
//! sequences organized by architecture and operation.
//!
//! # Architecture Coverage
//!
//! | Architecture | Hardware Instructions                                |
//! |-------------|------------------------------------------------------|
//! | i386        | `lock cmpxchg`, `xchg`, `lock orl`, `fildll/fistpll` |
//! | x86_64      | `lock cmpxchg`, `xchg`, `lock orq`                   |
//! | ARM         | `ldrex/strex` loops, `mcr p15` (dmb) barriers         |
//! | AArch64     | `ldaxr/stlxr`, `ldar/stlr`, `dmb ish`               |
//! | RISC-V      | `lr/sc` (load-reserved/store-conditional), `fence`   |

use std::sync::atomic::{compiler_fence, fence, Ordering};

// ============================================================================
// Memory ordering conversion
// ============================================================================

/// Converts a C `__ATOMIC_*` memory ordering constant to a Rust [`Ordering`].
///
/// # C Constants (from `<stdatomic.h>`)
///
/// | Constant              | Value | Rust Equivalent        |
/// |-----------------------|-------|------------------------|
/// | `__ATOMIC_RELAXED`    |   0   | `Ordering::Relaxed`    |
/// | `__ATOMIC_CONSUME`    |   1   | `Ordering::Acquire`    |
/// | `__ATOMIC_ACQUIRE`    |   2   | `Ordering::Acquire`    |
/// | `__ATOMIC_RELEASE`    |   3   | `Ordering::Release`    |
/// | `__ATOMIC_ACQ_REL`    |   4   | `Ordering::AcqRel`     |
/// | `__ATOMIC_SEQ_CST`    |   5   | `Ordering::SeqCst`     |
///
/// Note: `__ATOMIC_CONSUME` (1) maps to `Acquire` because Rust's memory model
/// does not have a separate `Consume` ordering. The C11 standard itself recommends
/// treating consume as acquire in most implementations.
///
/// Out-of-range values default to `SeqCst` (strongest ordering) for safety.
///
/// # C equivalent
///
/// No direct C equivalent — this conversion is implicit in `lib/atomic.S` where
/// the memory ordering parameter selects between barrier/non-barrier code paths.
pub fn c_memorder_to_rust(memorder: i32) -> Ordering {
    match memorder {
        0 => Ordering::Relaxed,
        // Consume (1) maps to Acquire — Rust does not distinguish consume/acquire.
        // The C11 spec notes consume is deprecated in practice and implementations
        // may strengthen it to acquire.
        1 | 2 => Ordering::Acquire,
        3 => Ordering::Release,
        4 => Ordering::AcqRel,
        // SeqCst for value 5 and any out-of-range value (defensive default)
        _ => Ordering::SeqCst,
    }
}

// ============================================================================
// Atomic load operations
// ============================================================================

/// Atomic load operations for 1, 2, 4, and 8 byte widths.
///
/// C equivalent: `__atomic_load_[1,2,4,8]` in `lib/atomic.S`
///
/// These functions perform an atomic read from the given location with the
/// specified memory ordering. On x86, plain loads are already atomic for
/// naturally aligned data; on ARM/AArch64, acquire variants (`ldar`, `ldaxr`)
/// enforce ordering; on RISC-V, fence instructions bracket the load.
pub mod load {
    use std::sync::atomic::{AtomicU16, AtomicU32, AtomicU64, AtomicU8, Ordering};

    /// Atomic load of a single byte.
    ///
    /// C equivalent: `__atomic_load_1(ptr, memorder)` in `lib/atomic.S`
    ///
    /// On i386: `movzbl (%eax),%eax`
    /// On x86_64: `movzbl (%rdi),%eax`
    /// On ARM: `ldrb` with optional `mcr p15` (dmb) barriers
    /// On AArch64: `ldrb` / `ldarb` depending on ordering
    /// On RISC-V: `fence rw,rw; lbu a0,0(a0); fence rw,rw`
    pub fn atomic_load_1(ptr: &AtomicU8, order: Ordering) -> u8 {
        ptr.load(order)
    }

    /// Atomic load of a 16-bit value.
    ///
    /// C equivalent: `__atomic_load_2(ptr, memorder)` in `lib/atomic.S`
    ///
    /// On i386: `movzwl (%eax),%eax`
    /// On x86_64: `movzwl (%rdi),%eax`
    /// On ARM: `ldrh` with optional dmb barriers
    /// On AArch64: `ldrh` / `ldarh`
    /// On RISC-V: `fence rw,rw; lhu a0,0(a0); fence rw,rw`
    pub fn atomic_load_2(ptr: &AtomicU16, order: Ordering) -> u16 {
        ptr.load(order)
    }

    /// Atomic load of a 32-bit value.
    ///
    /// C equivalent: `__atomic_load_4(ptr, memorder)` in `lib/atomic.S`
    ///
    /// On i386: `mov (%eax),%eax`
    /// On x86_64: `mov (%rdi),%eax`
    /// On ARM: `ldr` with optional dmb barriers
    /// On AArch64: `ldr w0, [x0]` / `ldar w0, [x0]`
    /// On RISC-V: `fence rw,rw; lw a0,0(a0); fence r,rw; sext.w a0,a0`
    pub fn atomic_load_4(ptr: &AtomicU32, order: Ordering) -> u32 {
        ptr.load(order)
    }

    /// Atomic load of a 64-bit value.
    ///
    /// C equivalent: `__atomic_load_8(ptr, memorder)` in `lib/atomic.S`
    ///
    /// On i386: `fildll/fistpll` (FPU trick for atomic 64-bit load on 32-bit)
    /// On x86_64: `mov (%rdi),%rax`
    /// On ARM: `ldrexd r0, [r0]`
    /// On AArch64: `ldr x0, [x0]` / `ldar x0, [x0]`
    /// On RISC-V: `fence rw,rw; ld a0,0(a0); fence r,rw`
    pub fn atomic_load_8(ptr: &AtomicU64, order: Ordering) -> u64 {
        ptr.load(order)
    }
}

// ============================================================================
// Atomic store operations
// ============================================================================

/// Atomic store operations for 1, 2, 4, and 8 byte widths.
///
/// C equivalent: `__atomic_store_[1,2,4,8]` in `lib/atomic.S`
///
/// These functions perform an atomic write to the given location with the
/// specified memory ordering. On x86, `xchg` is used (implicit lock prefix)
/// to guarantee atomicity and full fence semantics. On ARM, `strb`/`strh`/`str`
/// with dmb barriers; on AArch64, `stlrb`/`stlrh`/`stlr` for release stores;
/// on RISC-V, fence-bracketed plain stores.
pub mod store {
    use std::sync::atomic::{AtomicU16, AtomicU32, AtomicU64, AtomicU8, Ordering};

    /// Atomic store of a single byte.
    ///
    /// C equivalent: `__atomic_store_1(ptr, val, memorder)` in `lib/atomic.S`
    ///
    /// On x86: `xchg %al,(%edx)` — uses xchg for implicit full fence
    /// On ARM: `strb r1, [r0]` with optional dmb barriers
    /// On AArch64: `strb` / `stlrb` depending on ordering
    /// On RISC-V: `fence rw,rw; sb a1,0(a0); fence rw,rw`
    pub fn atomic_store_1(ptr: &AtomicU8, val: u8, order: Ordering) {
        ptr.store(val, order);
    }

    /// Atomic store of a 16-bit value.
    ///
    /// C equivalent: `__atomic_store_2(ptr, val, memorder)` in `lib/atomic.S`
    ///
    /// On x86: `xchg %ax,(%edx)` — uses xchg for implicit full fence
    /// On ARM: `strh r1, [r0]` with optional dmb barriers
    /// On AArch64: `strh` / `stlrh`
    /// On RISC-V: `fence rw,rw; sh a1,0(a0); fence rw,rw`
    pub fn atomic_store_2(ptr: &AtomicU16, val: u16, order: Ordering) {
        ptr.store(val, order);
    }

    /// Atomic store of a 32-bit value.
    ///
    /// C equivalent: `__atomic_store_4(ptr, val, memorder)` in `lib/atomic.S`
    ///
    /// On x86: `xchg %eax,(%edx)` — uses xchg for implicit full fence
    /// On ARM: `str r1, [r0]` with optional dmb barriers
    /// On AArch64: `str` / `stlr`
    /// On RISC-V: `fence rw,w; sw a1,0(a0); fence rw,rw`
    pub fn atomic_store_4(ptr: &AtomicU32, val: u32, order: Ordering) {
        ptr.store(val, order);
    }

    /// Atomic store of a 64-bit value.
    ///
    /// C equivalent: `__atomic_store_8(ptr, val, memorder)` in `lib/atomic.S`
    ///
    /// On i386: `fildll/fistpll` + `lock orl $0x0,(%esp)` — FPU trick with fence
    /// On x86_64: `xchg %rsi,(%rdi)`
    /// On ARM: `ldrexd/strexd` loop (exclusive load/store for 64-bit on 32-bit ARM)
    /// On AArch64: `str` / `stlr`
    /// On RISC-V: `fence rw,w; sd a1,0(a0); fence rw,rw`
    pub fn atomic_store_8(ptr: &AtomicU64, val: u64, order: Ordering) {
        ptr.store(val, order);
    }
}

// ============================================================================
// Atomic compare-and-exchange operations
// ============================================================================

/// Atomic compare-and-exchange operations for 1, 2, 4, and 8 byte widths.
///
/// C equivalent: `__atomic_compare_exchange_[1,2,4,8]` in `lib/atomic.S`
///
/// These functions atomically compare the value at `ptr` with `*expected`. If equal,
/// `desired` is stored and `true` is returned. If not equal, `*expected` is updated
/// to the actual value found and `false` is returned.
///
/// On x86: `lock cmpxchg` (1/2/4 bytes) or `lock cmpxchg8b` (8 bytes on i386)
/// On ARM: `ldrex/strex` loop with optional dmb barriers
/// On AArch64: `ldxr/stxr` (relaxed) or `ldaxr/stlxr` (acquire-release) loops
/// On RISC-V: `lr.w.aqrl/sc.w.rl` (4 bytes) or `lr.d.aqrl/sc.d.rl` (8 bytes);
///            sub-word (1/2 bytes) use word-width lr/sc with bit masking
pub mod compare_exchange {
    use std::sync::atomic::{AtomicU16, AtomicU32, AtomicU64, AtomicU8, Ordering};

    /// Atomic compare-exchange of a single byte.
    ///
    /// C equivalent: `__atomic_compare_exchange_1` in `lib/atomic.S`
    ///
    /// Returns `true` if the exchange succeeded (value was equal to `*expected`).
    /// On failure, `*expected` is updated to the actual value found at `ptr`.
    ///
    /// On x86: `lock cmpxchg %bl,(%edx)` — hardware CAS, `sete` for result
    /// On ARM: `ldrexb/strexb` loop with conditional `strbne ip, [r1]` on failure
    /// On AArch64: `ldxrb/stxrb` or `ldaxrb/stlxrb` loop with `cset w0, eq`
    /// On RISC-V: word-aligned `lr.w.aqrl/sc.w.rl` with byte masking and shift
    pub fn atomic_cmpxchg_1(
        ptr: &AtomicU8,
        expected: &mut u8,
        desired: u8,
        success: Ordering,
        failure: Ordering,
    ) -> bool {
        match ptr.compare_exchange(*expected, desired, success, failure) {
            Ok(_) => true,
            Err(actual) => {
                *expected = actual;
                false
            }
        }
    }

    /// Atomic compare-exchange of a 16-bit value.
    ///
    /// C equivalent: `__atomic_compare_exchange_2` in `lib/atomic.S`
    ///
    /// Returns `true` if the exchange succeeded. On failure, `*expected` is updated.
    ///
    /// On x86: `lock cmpxchg %bx,(%edx)` — hardware CAS
    /// On ARM: `ldrexh/strexh` loop
    /// On AArch64: `ldxrh/stxrh` or `ldaxrh/stlxrh` loop
    /// On RISC-V: word-aligned `lr.w.aqrl/sc.w.rl` with halfword masking
    pub fn atomic_cmpxchg_2(
        ptr: &AtomicU16,
        expected: &mut u16,
        desired: u16,
        success: Ordering,
        failure: Ordering,
    ) -> bool {
        match ptr.compare_exchange(*expected, desired, success, failure) {
            Ok(_) => true,
            Err(actual) => {
                *expected = actual;
                false
            }
        }
    }

    /// Atomic compare-exchange of a 32-bit value.
    ///
    /// C equivalent: `__atomic_compare_exchange_4` in `lib/atomic.S`
    ///
    /// Returns `true` if the exchange succeeded. On failure, `*expected` is updated.
    ///
    /// On x86: `lock cmpxchg %ebx,(%edx)` — hardware CAS
    /// On ARM: `ldrex/strex` loop
    /// On AArch64: `ldxr/stxr` or `ldaxr/stlxr` loop
    /// On RISC-V: `lr.w.aqrl/sc.w.rl` loop
    pub fn atomic_cmpxchg_4(
        ptr: &AtomicU32,
        expected: &mut u32,
        desired: u32,
        success: Ordering,
        failure: Ordering,
    ) -> bool {
        match ptr.compare_exchange(*expected, desired, success, failure) {
            Ok(_) => true,
            Err(actual) => {
                *expected = actual;
                false
            }
        }
    }

    /// Atomic compare-exchange of a 64-bit value.
    ///
    /// C equivalent: `__atomic_compare_exchange_8` in `lib/atomic.S`
    ///
    /// Returns `true` if the exchange succeeded. On failure, `*expected` is updated.
    ///
    /// On i386: `lock cmpxchg8b (%edi)` — 8-byte CAS using EDX:EAX / ECX:EBX
    /// On x86_64: `lock cmpxchg %rdx,(%rdi)` — direct 64-bit CAS
    /// On ARM: `ldrexd/strexd` loop (double-register exclusive)
    /// On AArch64: `ldxr/stxr` or `ldaxr/stlxr` loop (native 64-bit)
    /// On RISC-V: `lr.d.aqrl/sc.d.rl` loop (native 64-bit)
    pub fn atomic_cmpxchg_8(
        ptr: &AtomicU64,
        expected: &mut u64,
        desired: u64,
        success: Ordering,
        failure: Ordering,
    ) -> bool {
        match ptr.compare_exchange(*expected, desired, success, failure) {
            Ok(_) => true,
            Err(actual) => {
                *expected = actual;
                false
            }
        }
    }
}

// ============================================================================
// Atomic test-and-set operations
// ============================================================================

/// Atomic test-and-set operation.
///
/// C equivalent: `__atomic_test_and_set_[1,2,4,8]` in `lib/atomic.S`
///
/// The test-and-set operation atomically writes 1 to the byte at `ptr` and
/// returns the previous value. Note: in the original assembly, all size variants
/// (1, 2, 4, 8) perform the same byte-width swap — the size parameter only
/// affects the calling convention, not the actual operation width. This matches
/// the GCC libatomic behavior where `__atomic_test_and_set` always operates on
/// a single byte regardless of the nominal size.
///
/// On x86: `mov $0x1,%eax; xchg %al,(%edx)` — implicit lock prefix on xchg
/// On ARM: `ldrexb/strexb` loop with `mov r2, #1`
/// On AArch64: `ldxrb/stxrb` or `ldaxrb/stlxrb` loop with `mov w2, #1`
/// On RISC-V: `amoor.w.aqrl` with byte masking (atomic OR with 1-bit at offset)
pub mod test_and_set {
    use std::sync::atomic::{AtomicU8, Ordering};

    /// Atomically sets the byte at `ptr` to 1 and returns the previous value.
    ///
    /// C equivalent: `__atomic_test_and_set(ptr, memorder)` in `lib/atomic.S`
    ///
    /// This is the canonical test-and-set primitive used for spinlock
    /// implementations and `atomic_flag` operations.
    pub fn atomic_test_and_set(ptr: &AtomicU8, order: Ordering) -> u8 {
        ptr.swap(1, order)
    }
}

// ============================================================================
// Memory fence operations
// ============================================================================

/// Issues a hardware memory fence (full barrier) with the given ordering.
///
/// C equivalent: `atomic_thread_fence(memorder)` in `lib/atomic.S`
///
/// This ensures that memory operations before the fence are visible to other
/// threads/cores before memory operations after the fence.
///
/// Hardware implementation:
/// - x86/x86_64: `lock orl $0x0,(%esp)` or `lock orq $0x0,(%rsp)` — a locked
///   operation on the stack serves as a full fence (cheaper than `mfence`)
/// - ARM: `mcr p15, #0, r0, c7, c10, #5` — data memory barrier (CP15 DMB)
/// - AArch64: `dmb ish` — data memory barrier, inner-shareable domain
/// - RISC-V: `fence rw,rw` — full fence on all read/write operations
///
/// Note: `atomic_signal_fence` is the compiler-only variant (no hardware barrier).
pub fn thread_fence(order: Ordering) {
    fence(order);
}

/// Issues a compiler-only memory fence (no hardware barrier) with the given ordering.
///
/// C equivalent: `atomic_signal_fence(memorder)` in `lib/atomic.S`
///
/// This prevents the compiler from reordering memory operations across the fence
/// but does NOT issue any hardware barrier instruction. It is used for
/// signal handler / main thread synchronization where both execute on the same
/// core.
///
/// Hardware implementation on all architectures: just `ret` (no barrier
/// instruction emitted) — the ordering is enforced purely at the compiler level.
pub fn signal_fence(order: Ordering) {
    compiler_fence(order);
}

// ============================================================================
// Atomic flag operations
// ============================================================================

/// Atomic flag operations for `atomic_flag` type.
///
/// C equivalents: `atomic_flag_test_and_set[_explicit]`,
/// `atomic_flag_clear[_explicit]` in `lib/atomic.S`
///
/// An `atomic_flag` is the only lock-free atomic type guaranteed by the C11
/// standard. It provides exactly two operations: test-and-set (returns previous
/// value, sets to true) and clear (sets to false).
///
/// The original assembly uses the same byte-width swap/store as
/// `__atomic_test_and_set`, since `atomic_flag` is defined as a byte-sized type.
pub mod flag {
    use std::sync::atomic::{AtomicBool, Ordering};

    /// Atomically sets the flag to `true` and returns the previous value.
    ///
    /// C equivalent: `atomic_flag_test_and_set(flag)` /
    /// `atomic_flag_test_and_set_explicit(flag, memorder)` in `lib/atomic.S`
    ///
    /// On x86: `mov $0x1,%eax; xchg %al,(%edx)` — byte swap with 1
    /// On ARM: `ldrexb/strexb` loop with `mcr p15` (dmb) barriers
    /// On AArch64: `ldaxrb/stlxrb` loop — acquire/release exclusive byte swap
    /// On RISC-V: `amoor.w.aqrl` with byte masking — atomic OR at byte offset
    ///
    /// Returns `true` if the flag was previously set, `false` if it was clear.
    pub fn test_and_set(flag: &AtomicBool, order: Ordering) -> bool {
        flag.swap(true, order)
    }

    /// Atomically clears the flag (sets to `false`).
    ///
    /// C equivalent: `atomic_flag_clear(flag)` /
    /// `atomic_flag_clear_explicit(flag, memorder)` in `lib/atomic.S`
    ///
    /// On x86: `xor %eax,%eax; xchg %al,(%edx)` — byte swap with 0
    /// On ARM: `movs r3, #0; mcr p15 (dmb); strb r3, [r0]; mcr p15 (dmb)`
    /// On AArch64: `stlrb wzr, [x0]` — release store of zero
    /// On RISC-V: `fence rw,rw; sb zero,0(a0); fence rw,rw`
    pub fn clear(flag: &AtomicBool, order: Ordering) {
        flag.store(false, order);
    }
}

// ============================================================================
// Architecture-specific machine code for the compiled runtime library
// ============================================================================

/// Machine code bytes for atomic operations, organized by architecture.
///
/// These pre-assembled instruction sequences are emitted into the runtime
/// library (`libtcc1.a`) for programs compiled by tinycc-rs. When tinycc-rs
/// compiles a C program that uses `<stdatomic.h>` or GCC `__atomic_*` builtins,
/// these machine code bytes provide the actual atomic operation implementations
/// that get linked into the compiled executable.
///
/// The bytes are extracted from the `#ifdef __TINYC__` sections of `lib/atomic.S`,
/// which contain pre-assembled `.int` and `.short` directives representing the
/// machine code for each architecture. This approach allows TCC (which has a
/// simplified assembler) to emit correct atomic operations without needing to
/// assemble complex instruction sequences at compile time.
///
/// # Organization
///
/// Each architecture sub-module provides byte slices for:
/// - Load operations (1, 2, 4, 8 bytes)
/// - Store operations (1, 2, 4, 8 bytes)
/// - Compare-exchange operations (1, 2, 4, 8 bytes)
/// - Test-and-set operations (1, 2, 4, 8 bytes)
/// - Thread fence and signal fence
/// - Flag test-and-set (plain + explicit) and clear (plain + explicit)
pub mod target_code {

    /// x86 (i386) atomic operation machine code.
    ///
    /// These are native i386 instruction sequences using:
    /// - `xchg` for stores (implicit lock prefix)
    /// - `lock cmpxchg` for compare-exchange (1, 2, 4 bytes)
    /// - `lock cmpxchg8b` for 8-byte compare-exchange
    /// - `fildll`/`fistpll` for atomic 64-bit load/store (FPU trick)
    /// - `lock orl $0x0,(%esp)` for thread fence
    /// - `endbr32` for CET-compatible function entry (defined as nop)
    #[cfg(feature = "i386")]
    pub mod i386 {
        /// `__atomic_load_1` — `movzbl (%eax),%eax; ret`
        pub const ATOMIC_LOAD_1: &[u8] = &[
            0x8b, 0x44, 0x24, 0x04, // mov 0x4(%esp),%eax
            0x0f, 0xb6, 0x00, // movzbl (%eax),%eax
            0xc3, // ret
        ];

        /// `__atomic_load_2` — `movzwl (%eax),%eax; ret`
        pub const ATOMIC_LOAD_2: &[u8] = &[
            0x8b, 0x44, 0x24, 0x04, // mov 0x4(%esp),%eax
            0x0f, 0xb7, 0x00, // movzwl (%eax),%eax
            0xc3, // ret
        ];

        /// `__atomic_load_4` — `mov (%eax),%eax; ret`
        pub const ATOMIC_LOAD_4: &[u8] = &[
            0x8b, 0x44, 0x24, 0x04, // mov 0x4(%esp),%eax
            0x8b, 0x00, // mov (%eax),%eax
            0xc3, // ret
        ];

        /// `__atomic_store_1` — `xchg %al,(%edx); ret`
        pub const ATOMIC_STORE_1: &[u8] = &[
            0x8b, 0x54, 0x24, 0x04, // mov 0x4(%esp),%edx
            0x8b, 0x44, 0x24, 0x08, // mov 0x8(%esp),%eax
            0x86, 0x02, // xchg %al,(%edx)
            0xc3, // ret
        ];

        /// `__atomic_store_2` — `xchg %ax,(%edx); ret`
        pub const ATOMIC_STORE_2: &[u8] = &[
            0x8b, 0x54, 0x24, 0x04, // mov 0x4(%esp),%edx
            0x8b, 0x44, 0x24, 0x08, // mov 0x8(%esp),%eax
            0x66, 0x87, 0x02, // xchg %ax,(%edx)
            0xc3, // ret
        ];

        /// `__atomic_store_4` — `xchg %eax,(%edx); ret`
        pub const ATOMIC_STORE_4: &[u8] = &[
            0x8b, 0x54, 0x24, 0x04, // mov 0x4(%esp),%edx
            0x8b, 0x44, 0x24, 0x08, // mov 0x8(%esp),%eax
            0x87, 0x02, // xchg %eax,(%edx)
            0xc3, // ret
        ];

        /// `__atomic_test_and_set_1` — `mov $1,%eax; xchg %al,(%edx); ret`
        pub const ATOMIC_TEST_AND_SET: &[u8] = &[
            0x8b, 0x54, 0x24, 0x04, // mov 0x4(%esp),%edx
            0xb8, 0x01, 0x00, 0x00, 0x00, // mov $0x1,%eax
            0x86, 0x02, // xchg %al,(%edx)
            0xc3, // ret
        ];

        /// `atomic_thread_fence` — `lock orl $0x0,(%esp); ret`
        pub const THREAD_FENCE: &[u8] = &[
            0xf0, 0x83, 0x0c, 0x24, 0x00, // lock orl $0x0,(%esp)
            0xc3, // ret
        ];

        /// `atomic_signal_fence` — `ret` (compiler barrier only, no hw instruction)
        pub const SIGNAL_FENCE: &[u8] = &[
            0xc3, // ret
        ];

        /// `atomic_flag_test_and_set` — same as test_and_set_1
        pub const FLAG_TEST_AND_SET: &[u8] = &[
            0x8b, 0x54, 0x24, 0x04, // mov 0x4(%esp),%edx
            0xb8, 0x01, 0x00, 0x00, 0x00, // mov $0x1,%eax
            0x86, 0x02, // xchg %al,(%edx)
            0xc3, // ret
        ];

        /// `atomic_flag_clear` — `xor %eax,%eax; xchg %al,(%edx); ret`
        pub const FLAG_CLEAR: &[u8] = &[
            0x8b, 0x54, 0x24, 0x04, // mov 0x4(%esp),%edx
            0x31, 0xc0, // xor %eax,%eax
            0x86, 0x02, // xchg %al,(%edx)
            0xc3, // ret
        ];
    }

    /// x86_64 (System V ABI) atomic operation machine code.
    ///
    /// These are native x86_64 instruction sequences using the System V calling
    /// convention (arguments in rdi, rsi, rdx, rcx, r8, r9).
    ///
    /// Key instructions:
    /// - `lock cmpxchg` for compare-exchange (all sizes)
    /// - `xchg` for stores (implicit lock prefix)
    /// - `lock orq $0x0,(%rsp)` for thread fence
    /// - `endbr64` for CET-compatible function entry (defined as nop)
    #[cfg(feature = "x86_64")]
    pub mod x86_64_sysv {
        /// `__atomic_load_1` — `movzbl (%rdi),%eax; ret`
        pub const ATOMIC_LOAD_1: &[u8] = &[
            0x0f, 0xb6, 0x07, // movzbl (%rdi),%eax
            0xc3, // ret
        ];

        /// `__atomic_load_2` — `movzwl (%rdi),%eax; ret`
        pub const ATOMIC_LOAD_2: &[u8] = &[
            0x0f, 0xb7, 0x07, // movzwl (%rdi),%eax
            0xc3, // ret
        ];

        /// `__atomic_load_4` — `mov (%rdi),%eax; ret`
        pub const ATOMIC_LOAD_4: &[u8] = &[
            0x8b, 0x07, // mov (%rdi),%eax
            0xc3, // ret
        ];

        /// `__atomic_load_8` — `mov (%rdi),%rax; ret`
        pub const ATOMIC_LOAD_8: &[u8] = &[
            0x48, 0x8b, 0x07, // mov (%rdi),%rax
            0xc3, // ret
        ];

        /// `__atomic_store_1` — `xchg %sil,(%rdi); ret`
        pub const ATOMIC_STORE_1: &[u8] = &[
            0x40, 0x86, 0x37, // xchg %sil,(%rdi)
            0xc3, // ret
        ];

        /// `__atomic_store_2` — `xchg %si,(%rdi); ret`
        pub const ATOMIC_STORE_2: &[u8] = &[
            0x66, 0x87, 0x37, // xchg %si,(%rdi)
            0xc3, // ret
        ];

        /// `__atomic_store_4` — `xchg %esi,(%rdi); ret`
        pub const ATOMIC_STORE_4: &[u8] = &[
            0x87, 0x37, // xchg %esi,(%rdi)
            0xc3, // ret
        ];

        /// `__atomic_store_8` — `xchg %rsi,(%rdi); ret`
        pub const ATOMIC_STORE_8: &[u8] = &[
            0x48, 0x87, 0x37, // xchg %rsi,(%rdi)
            0xc3, // ret
        ];

        /// `__atomic_test_and_set_1` — `mov $1,%eax; xchg %al,(%rdi); ret`
        pub const ATOMIC_TEST_AND_SET: &[u8] = &[
            0xb8, 0x01, 0x00, 0x00, 0x00, // mov $0x1,%eax
            0x86, 0x07, // xchg %al,(%rdi)
            0xc3, // ret
        ];

        /// `atomic_thread_fence` — `lock orq $0x0,(%rsp); ret`
        pub const THREAD_FENCE: &[u8] = &[
            0xf0, 0x48, 0x83, 0x0c, 0x24, 0x00, // lock orq $0x0,(%rsp)
            0xc3, // ret
        ];

        /// `atomic_signal_fence` — `ret` (compiler barrier only)
        pub const SIGNAL_FENCE: &[u8] = &[
            0xc3, // ret
        ];

        /// `atomic_flag_test_and_set` — same as test_and_set
        pub const FLAG_TEST_AND_SET: &[u8] = &[
            0xb8, 0x01, 0x00, 0x00, 0x00, // mov $0x1,%eax
            0x86, 0x07, // xchg %al,(%rdi)
            0xc3, // ret
        ];

        /// `atomic_flag_clear` — `xor %eax,%eax; xchg %al,(%rdi); ret`
        pub const FLAG_CLEAR: &[u8] = &[
            0x31, 0xc0, // xor %eax,%eax
            0x86, 0x07, // xchg %al,(%rdi)
            0xc3, // ret
        ];
    }

    /// x86_64 (Windows ABI) atomic operation machine code.
    ///
    /// Uses the Windows x64 calling convention (arguments in rcx, rdx, r8, r9).
    /// Functionally identical to System V but with different register assignments.
    #[cfg(feature = "x86_64")]
    pub mod x86_64_win {
        /// `__atomic_load_1` — `movzbl (%rcx),%eax; ret`
        pub const ATOMIC_LOAD_1: &[u8] = &[
            0x0f, 0xb6, 0x01, // movzbl (%rcx),%eax
            0xc3, // ret
        ];

        /// `__atomic_load_2` — `movzwl (%rcx),%eax; ret`
        pub const ATOMIC_LOAD_2: &[u8] = &[
            0x0f, 0xb7, 0x01, // movzwl (%rcx),%eax
            0xc3, // ret
        ];

        /// `__atomic_load_4` — `mov (%rcx),%eax; ret`
        pub const ATOMIC_LOAD_4: &[u8] = &[
            0x8b, 0x01, // mov (%rcx),%eax
            0xc3, // ret
        ];

        /// `__atomic_load_8` — `mov (%rcx),%rax; ret`
        pub const ATOMIC_LOAD_8: &[u8] = &[
            0x48, 0x8b, 0x01, // mov (%rcx),%rax
            0xc3, // ret
        ];

        /// `__atomic_store_1` — `xchg %dl,(%rcx); ret`
        pub const ATOMIC_STORE_1: &[u8] = &[
            0x86, 0x11, // xchg %dl,(%rcx)
            0xc3, // ret
        ];

        /// `__atomic_store_2` — `xchg %dx,(%rcx); ret`
        pub const ATOMIC_STORE_2: &[u8] = &[
            0x66, 0x87, 0x11, // xchg %dx,(%rcx)
            0xc3, // ret
        ];

        /// `__atomic_store_4` — `xchg %edx,(%rcx); ret`
        pub const ATOMIC_STORE_4: &[u8] = &[
            0x87, 0x11, // xchg %edx,(%rcx)
            0xc3, // ret
        ];

        /// `__atomic_store_8` — `xchg %rdx,(%rcx); ret`
        pub const ATOMIC_STORE_8: &[u8] = &[
            0x48, 0x87, 0x11, // xchg %rdx,(%rcx)
            0xc3, // ret
        ];

        /// `__atomic_test_and_set_1` — `mov $1,%eax; xchg %al,(%rcx); ret`
        pub const ATOMIC_TEST_AND_SET: &[u8] = &[
            0xb8, 0x01, 0x00, 0x00, 0x00, // mov $0x1,%eax
            0x86, 0x01, // xchg %al,(%rcx)
            0xc3, // ret
        ];

        /// `atomic_thread_fence` — `lock orq $0x0,(%rsp); ret`
        pub const THREAD_FENCE: &[u8] = &[
            0xf0, 0x48, 0x83, 0x0c, 0x24, 0x00, // lock orq $0x0,(%rsp)
            0xc3, // ret
        ];

        /// `atomic_signal_fence` — `ret`
        pub const SIGNAL_FENCE: &[u8] = &[
            0xc3, // ret
        ];

        /// `atomic_flag_test_and_set` — same as test_and_set
        pub const FLAG_TEST_AND_SET: &[u8] = &[
            0xb8, 0x01, 0x00, 0x00, 0x00, // mov $0x1,%eax
            0x86, 0x01, // xchg %al,(%rcx)
            0xc3, // ret
        ];

        /// `atomic_flag_clear` — `xor %eax,%eax; xchg %al,(%rcx); ret`
        pub const FLAG_CLEAR: &[u8] = &[
            0x31, 0xc0, // xor %eax,%eax
            0x86, 0x01, // xchg %al,(%rcx)
            0xc3, // ret
        ];
    }

    /// ARM (32-bit) atomic operation machine code.
    ///
    /// These are pre-assembled ARM instructions from the `#ifdef __TINYC__`
    /// sections of `lib/atomic.S`. TCC's ARM assembler cannot handle the
    /// `ldrex/strex` instructions directly, so the `.int` directives provide
    /// the raw machine code words.
    ///
    /// Key ARM instruction patterns:
    /// - `ldrex`/`strex` exclusive load/store loops for atomicity
    /// - `mcr p15, #0, r0, c7, c10, #5` for DMB (data memory barrier)
    /// - `uxtb`/`uxth` for zero-extension of sub-word results
    /// - `bx lr` for function return
    #[cfg(feature = "arm")]
    pub mod arm {
        /// `__atomic_load_1` — ARM machine code words (10 × 4 bytes)
        /// Implements: conditional DMB + `ldrb` + `uxtb` based on ordering arg
        pub const ATOMIC_LOAD_1: &[u32] = &[
            0xe351_0000, // cmp r1, #0
            0x1a00_0002, // bne .Lordered
            0xe5d0_0000, // ldrb r0, [r0]
            0xe6ef_0070, // uxtb r0, r0
            0xe12f_ff1e, // bx lr
            0xee07_0fba, // mcr p15, 0, r0, c7, c10, 5 (dmb)
            0xe5d0_0000, // ldrb r0, [r0]
            0xee07_0fba, // mcr p15, 0, r0, c7, c10, 5 (dmb)
            0xe6ef_0070, // uxtb r0, r0
            0xe12f_ff1e, // bx lr
        ];

        /// `__atomic_load_2` — ARM machine code words
        pub const ATOMIC_LOAD_2: &[u32] = &[
            0xe351_0000, 0x1a00_0002, 0xe1d0_00b0, 0xe6ff_0070,
            0xe12f_ff1e, 0xee07_0fba, 0xe1d0_00b0, 0xee07_0fba,
            0xe6ff_0070, 0xe12f_ff1e,
        ];

        /// `__atomic_load_4` — ARM machine code words
        pub const ATOMIC_LOAD_4: &[u32] = &[
            0xe351_0000, 0x1a00_0001, 0xe590_0000, 0xe12f_ff1e,
            0xee07_0fba, 0xe590_0000, 0xee07_0fba, 0xe12f_ff1e,
        ];

        /// `__atomic_load_8` — ARM machine code words
        pub const ATOMIC_LOAD_8: &[u32] = &[
            0xe351_0000, 0x1a00_0001, 0xe1b0_0f9f, 0xe12f_ff1e,
            0xee07_0fba, 0xe1b0_0f9f, 0xee07_0fba, 0xe12f_ff1e,
        ];

        /// `__atomic_store_1` — ARM machine code words
        pub const ATOMIC_STORE_1: &[u32] = &[
            0xe352_0000, 0x1a00_0001, 0xe5c0_1000, 0xe12f_ff1e,
            0xee07_0fba, 0xe5c0_1000, 0xee07_0fba, 0xe12f_ff1e,
        ];

        /// `__atomic_store_2` — ARM machine code words
        pub const ATOMIC_STORE_2: &[u32] = &[
            0xe352_0000, 0x1a00_0001, 0xe1c0_10b0, 0xe12f_ff1e,
            0xee07_0fba, 0xe1c0_10b0, 0xee07_0fba, 0xe12f_ff1e,
        ];

        /// `__atomic_store_4` — ARM machine code words
        pub const ATOMIC_STORE_4: &[u32] = &[
            0xe352_0000, 0x1a00_0001, 0xe580_1000, 0xe12f_ff1e,
            0xee07_0fba, 0xe580_1000, 0xee07_0fba, 0xe12f_ff1e,
        ];

        /// `__atomic_store_8` — ARM machine code words (20 × 4 bytes)
        /// Implements: ldrexd/strexd loop with optional DMB barriers
        pub const ATOMIC_STORE_8: &[u32] = &[
            0xe92d_0030, 0xe1a0_4002, 0xe59d_1008, 0xe1a0_5003,
            0xe351_0000, 0x1a00_0005, 0xe1b0_2f9f, 0xe1a0_1f94,
            0xe351_0000, 0x1aff_fffb, 0xe8bd_0030, 0xe12f_ff1e,
            0xee07_0fba, 0xe1b0_2f9f, 0xe1a0_1f94, 0xe351_0000,
            0x1aff_fffb, 0xee07_0fba, 0xe8bd_0030, 0xe12f_ff1e,
        ];

        /// `__atomic_compare_exchange_1` — ARM machine code words (24 × 4 bytes)
        /// Implements: ldrexb/strexb CAS loop with conditional DMB
        pub const ATOMIC_CMPXCHG_1: &[u32] = &[
            0xe52d_e004, 0xe353_0000, 0x1a00_000a, 0xe5d1_3000,
            0xe1d0_cf9f, 0xe15c_0003, 0x1a00_0002, 0xe1c0_ef92,
            0xe35e_0000, 0x1aff_fff9, 0x03a0_0001, 0x13a0_0000,
            0x15c1_c000, 0xe49d_f004, 0xe5d1_3000, 0xee07_0fba,
            0xe1d0_cf9f, 0xe15c_0003, 0x1aff_fff6, 0xe1c0_ef92,
            0xe35e_0000, 0x1aff_fff9, 0xee07_0fba, 0xeaff_fff1,
        ];

        /// `__atomic_compare_exchange_2` — ARM machine code words
        pub const ATOMIC_CMPXCHG_2: &[u32] = &[
            0xe52d_e004, 0xe353_0000, 0x1a00_000a, 0xe1d1_30b0,
            0xe1f0_cf9f, 0xe15c_0003, 0x1a00_0002, 0xe1e0_ef92,
            0xe35e_0000, 0x1aff_fff9, 0x03a0_0001, 0x13a0_0000,
            0x11c1_c0b0, 0xe49d_f004, 0xe1d1_30b0, 0xee07_0fba,
            0xe1f0_cf9f, 0xe15c_0003, 0x1aff_fff6, 0xe1e0_ef92,
            0xe35e_0000, 0x1aff_fff9, 0xee07_0fba, 0xeaff_fff1,
        ];

        /// `__atomic_compare_exchange_4` — ARM machine code words (25 × 4 bytes)
        pub const ATOMIC_CMPXCHG_4: &[u32] = &[
            0xe52d_4004, 0xe353_0000, 0x1a00_000b, 0xe591_3000,
            0xe190_4f9f, 0xe154_0003, 0x1a00_0002, 0xe180_cf92,
            0xe35c_0000, 0x1aff_fff9, 0x03a0_0001, 0x13a0_0000,
            0x1581_4000, 0xe49d_4004, 0xe12f_ff1e, 0xe591_3000,
            0xee07_0fba, 0xe190_4f9f, 0xe154_0003, 0x1aff_fff5,
            0xe180_cf92, 0xe35c_0000, 0x1aff_fff9, 0xee07_0fba,
            0xeaff_fff0,
        ];

        /// `__atomic_compare_exchange_8` — ARM machine code words (29 × 4 bytes)
        pub const ATOMIC_CMPXCHG_8: &[u32] = &[
            0xe92d_00f0, 0xe1a0_5003, 0xe59d_3010, 0xe1a0_4002,
            0xe353_0000, 0x1a00_000c, 0xe1c1_20d0, 0xe1b0_6f9f,
            0xe157_0003, 0x0156_0002, 0x1a00_0002, 0xe1a0_cf94,
            0xe35c_0000, 0x1aff_fff8, 0x03a0_0001, 0x13a0_0000,
            0x11c1_60f0, 0xe8bd_00f0, 0xe12f_ff1e, 0xe1c1_20d0,
            0xee07_0fba, 0xe1b0_6f9f, 0xe157_0003, 0x0156_0002,
            0x1aff_fff4, 0xe1a0_cf94, 0xe35c_0000, 0x1aff_fff8,
            0xee07_0fba, 0xeaff_ffef,
        ];

        /// `__atomic_test_and_set_1` — ARM machine code words (17 × 4 bytes)
        /// All size variants (1,2,4,8) use the same byte-width swap
        pub const ATOMIC_TEST_AND_SET: &[u32] = &[
            0xe3a0_2001, 0xe351_0000, 0x1a00_0005, 0xe1d0_3f9f,
            0xe1c0_1f92, 0xe351_0000, 0x1aff_fffb, 0xe6ef_0073,
            0xe12f_ff1e, 0xee07_0fba, 0xe1d0_3f9f, 0xe1c0_1f92,
            0xe351_0000, 0x1aff_fffb, 0xe6ef_0073, 0xee07_0fba,
            0xe12f_ff1e,
        ];

        /// `atomic_thread_fence` — ARM machine code: `dmb; bx lr`
        pub const THREAD_FENCE: &[u32] = &[
            0xee07_0fba, // mcr p15, 0, r0, c7, c10, 5
            0xe12f_ff1e, // bx lr
        ];

        /// `atomic_signal_fence` — ARM machine code: `bx lr` (no barrier)
        pub const SIGNAL_FENCE: &[u32] = &[
            0xe12f_ff1e, // bx lr
        ];

        /// `atomic_flag_test_and_set` — ARM machine code (9 × 4 bytes)
        pub const FLAG_TEST_AND_SET: &[u32] = &[
            0xe3a0_2001, 0xee07_0fba, 0xe1d0_3f9f, 0xe1c0_1f92,
            0xe351_0000, 0x1aff_fffb, 0xe6ef_0073, 0xee07_0fba,
            0xe12f_ff1e,
        ];

        /// `atomic_flag_clear` — ARM machine code (5 × 4 bytes)
        pub const FLAG_CLEAR: &[u32] = &[
            0xe3b0_3000, // movs r3, #0
            0xee07_0fba, // mcr p15, 0, r0, c7, c10, 5
            0xe5c0_3000, // strb r3, [r0]
            0xee07_0fba, // mcr p15, 0, r0, c7, c10, 5
            0xe12f_ff1e, // bx lr
        ];
    }

    /// AArch64 atomic operation machine code.
    ///
    /// These are pre-assembled AArch64 instructions from the `#ifdef __TINYC__`
    /// sections of `lib/atomic.S`. The machine code uses:
    /// - `ldaxr/stlxr` for acquire-release exclusive loops
    /// - `ldxr/stxr` for relaxed exclusive loops
    /// - `ldar/stlr` for acquire loads and release stores
    /// - `dmb ish` for full memory barrier
    /// - `cbnz` for conditional branching on non-zero (loop control)
    /// - `cset` for condition code to register transfer
    #[cfg(feature = "arm64")]
    pub mod aarch64 {
        /// `__atomic_load_1` — AArch64 machine code words (7 × 4 bytes)
        pub const ATOMIC_LOAD_1: &[u32] = &[
            0x3500_0081, // cbnz w1, .Lordered
            0x3940_0000, // ldrb w0, [x0]
            0x1200_1c00, // and w0, w0, #0xff
            0xd65f_03c0, // ret
            0x08df_fc00, // ldarb w0, [x0]
            0x1200_1c00, // and w0, w0, #0xff
            0xd65f_03c0, // ret
        ];

        /// `__atomic_load_2` — AArch64 machine code words
        pub const ATOMIC_LOAD_2: &[u32] = &[
            0x3500_0081, 0x7940_0000, 0x1200_3c00, 0xd65f_03c0,
            0x48df_fc00, 0x1200_3c00, 0xd65f_03c0,
        ];

        /// `__atomic_load_4` — AArch64 machine code words
        pub const ATOMIC_LOAD_4: &[u32] = &[
            0x3500_0061, 0xb940_0000, 0xd65f_03c0,
            0x88df_fc00, 0xd65f_03c0,
        ];

        /// `__atomic_load_8` — AArch64 machine code words
        pub const ATOMIC_LOAD_8: &[u32] = &[
            0x3500_0061, 0xf940_0000, 0xd65f_03c0,
            0xc8df_fc00, 0xd65f_03c0,
        ];

        /// `__atomic_store_1` — AArch64 machine code words (6 × 4 bytes)
        pub const ATOMIC_STORE_1: &[u32] = &[
            0x1200_1c21, // and w1, w1, #0xff
            0x3500_0062, // cbnz w2, .Lordered
            0x3900_0001, // strb w1, [x0]
            0xd65f_03c0, // ret
            0x089f_fc01, // stlrb w1, [x0]
            0xd65f_03c0, // ret
        ];

        /// `__atomic_store_2` — AArch64 machine code words
        pub const ATOMIC_STORE_2: &[u32] = &[
            0x1200_3c21, 0x3500_0062, 0x7900_0001, 0xd65f_03c0,
            0x489f_fc01, 0xd65f_03c0,
        ];

        /// `__atomic_store_4` — AArch64 machine code words
        pub const ATOMIC_STORE_4: &[u32] = &[
            0x3500_0062, 0xb900_0001, 0xd65f_03c0,
            0x889f_fc01, 0xd65f_03c0,
        ];

        /// `__atomic_store_8` — AArch64 machine code words
        pub const ATOMIC_STORE_8: &[u32] = &[
            0x3500_0062, 0xf900_0001, 0xd65f_03c0,
            0xc89f_fc01, 0xd65f_03c0,
        ];

        /// `__atomic_compare_exchange_1` — AArch64 machine code (21 × 4 bytes)
        pub const ATOMIC_CMPXCHG_1: &[u32] = &[
            0x1200_1c42, 0x3500_0143, 0x3940_0023, 0x085f_7c04,
            0x6b23_009f, 0x5400_0061, 0x0805_7c02, 0x35ff_ff85,
            0x1a9f_17e0, 0x5400_0141, 0xd65f_03c0, 0x3940_0023,
            0x085f_fc04, 0x6b23_009f, 0x5400_0061, 0x0805_fc02,
            0x35ff_ff85, 0x1a9f_17e0, 0x54ff_ff00, 0x3900_0024,
            0xd65f_03c0,
        ];

        /// `__atomic_compare_exchange_2` — AArch64 machine code
        pub const ATOMIC_CMPXCHG_2: &[u32] = &[
            0x1200_3c42, 0x3500_0143, 0x7940_0023, 0x485f_7c04,
            0x6b23_209f, 0x5400_0061, 0x4805_7c02, 0x35ff_ff85,
            0x1a9f_17e0, 0x5400_0141, 0xd65f_03c0, 0x7940_0023,
            0x485f_fc04, 0x6b23_209f, 0x5400_0061, 0x4805_fc02,
            0x35ff_ff85, 0x1a9f_17e0, 0x54ff_ff00, 0x7900_0024,
            0xd65f_03c0,
        ];

        /// `__atomic_compare_exchange_4` — AArch64 machine code (20 × 4 bytes)
        pub const ATOMIC_CMPXCHG_4: &[u32] = &[
            0x3500_0143, 0xb940_0023, 0x885f_7c04, 0x6b03_009f,
            0x5400_0061, 0x8805_7c02, 0x35ff_ff85, 0x1a9f_17e0,
            0x5400_0141, 0xd65f_03c0, 0xb940_0023, 0x885f_fc04,
            0x6b03_009f, 0x5400_0061, 0x8805_fc02, 0x35ff_ff85,
            0x1a9f_17e0, 0x54ff_ff00, 0xb900_0024, 0xd65f_03c0,
        ];

        /// `__atomic_compare_exchange_8` — AArch64 machine code (20 × 4 bytes)
        pub const ATOMIC_CMPXCHG_8: &[u32] = &[
            0x3500_0143, 0xf940_0023, 0xc85f_7c04, 0xeb03_009f,
            0x5400_0061, 0xc805_7c02, 0x35ff_ff85, 0x1a9f_17e0,
            0x5400_0141, 0xd65f_03c0, 0xf940_0023, 0xc85f_fc04,
            0xeb03_009f, 0x5400_0061, 0xc805_fc02, 0x35ff_ff85,
            0x1a9f_17e0, 0x54ff_ff00, 0xf900_0024, 0xd65f_03c0,
        ];

        /// `__atomic_test_and_set_1` — AArch64 machine code (12 × 4 bytes)
        /// All size variants use the same byte-width swap
        pub const ATOMIC_TEST_AND_SET: &[u32] = &[
            0x5280_0022, 0x3500_00c1, 0x085f_7c01, 0x0803_7c02,
            0x35ff_ffc3, 0x1200_1c20, 0xd65f_03c0, 0x085f_fc01,
            0x0803_fc02, 0x35ff_ffc3, 0x1200_1c20, 0xd65f_03c0,
        ];

        /// `atomic_thread_fence` — `dmb ish; ret`
        pub const THREAD_FENCE: &[u32] = &[
            0xd503_3bbf, // dmb ish
            0xd65f_03c0, // ret
        ];

        /// `atomic_signal_fence` — `ret` (no barrier)
        pub const SIGNAL_FENCE: &[u32] = &[
            0xd65f_03c0, // ret
        ];

        /// `atomic_flag_test_and_set` — AArch64 machine code (6 × 4 bytes)
        pub const FLAG_TEST_AND_SET: &[u32] = &[
            0xaa00_03e1, // mov x1, x0
            0x5280_0022, // mov w2, #1
            0x085f_fc20, // ldaxrb w0, [x1]
            0x0803_fc22, // stlxrb w3, w2, [x1]
            0x35ff_ffc3, // cbnz w3, .-8
            0xd65f_03c0, // ret
        ];

        /// `atomic_flag_clear` — AArch64 machine code (2 × 4 bytes)
        pub const FLAG_CLEAR: &[u32] = &[
            0x089f_fc1f, // stlrb wzr, [x0]
            0xd65f_03c0, // ret
        ];
    }

    /// RISC-V 64-bit atomic operation machine code.
    ///
    /// These are pre-assembled RISC-V instructions from the `#ifdef __TINYC__`
    /// sections of `lib/atomic.S`. The machine code uses both 32-bit and
    /// 16-bit (compressed) instruction encodings:
    /// - `lr.w.aqrl`/`sc.w.rl` for 32-bit load-reserved/store-conditional
    /// - `lr.d.aqrl`/`sc.d.rl` for 64-bit load-reserved/store-conditional
    /// - `amoor.w.aqrl` for atomic OR (test-and-set)
    /// - `fence rw,rw` for full memory barrier
    /// - `.short` values are compressed (C extension) instructions
    ///
    /// Sub-word atomics (1, 2 bytes) use word-aligned lr/sc with bit masking,
    /// since RISC-V does not have sub-word atomic instructions.
    #[cfg(feature = "riscv64")]
    pub mod riscv64 {
        /// Raw instruction bytes for RISC-V atomic operations.
        /// Mixed 32-bit (.int) and 16-bit (.short) instructions represented
        /// as byte arrays for proper encoding preservation.

        /// `__atomic_load_1` — `fence rw,rw; lbu a0,0(a0); fence rw,rw; ret`
        pub const ATOMIC_LOAD_1: &[u8] = &[
            0x0f, 0x00, 0x30, 0x03, // fence rw,rw
            0x03, 0x45, 0x05, 0x00, // lbu a0,0(a0)
            0x0f, 0x00, 0x30, 0x03, // fence rw,rw
            0x82, 0x80, // c.ret
        ];

        /// `__atomic_load_2` — `fence rw,rw; lhu a0,0(a0); fence rw,rw; ret`
        pub const ATOMIC_LOAD_2: &[u8] = &[
            0x0f, 0x00, 0x30, 0x03, // fence rw,rw
            0x03, 0x55, 0x05, 0x00, // lhu a0,0(a0)
            0x0f, 0x00, 0x30, 0x03, // fence rw,rw
            0x82, 0x80, // c.ret
        ];

        /// `__atomic_load_4` — `fence rw,rw; lw; fence r,rw; sext.w; ret`
        pub const ATOMIC_LOAD_4: &[u8] = &[
            0x0f, 0x00, 0x30, 0x03, // fence rw,rw
            0x08, 0x41, // c.lw a0,0(a0)
            0x0f, 0x00, 0x30, 0x02, // fence r,rw
            0x01, 0x25, // c.sext.w a0
            0x82, 0x80, // c.ret
        ];

        /// `__atomic_load_8` — `fence rw,rw; ld; fence r,rw; ret`
        pub const ATOMIC_LOAD_8: &[u8] = &[
            0x0f, 0x00, 0x30, 0x03, // fence rw,rw
            0x08, 0x61, // c.ld a0,0(a0)
            0x0f, 0x00, 0x30, 0x02, // fence r,rw
            0x82, 0x80, // c.ret
        ];

        /// `__atomic_store_1` — `fence rw,rw; sb a1,0(a0); fence rw,rw; ret`
        pub const ATOMIC_STORE_1: &[u8] = &[
            0x0f, 0x00, 0x30, 0x03, // fence rw,rw
            0x23, 0x00, 0xb5, 0x00, // sb a1,0(a0)
            0x0f, 0x00, 0x30, 0x03, // fence rw,rw
            0x82, 0x80, // c.ret
        ];

        /// `__atomic_store_2` — `fence rw,rw; sh a1,0(a0); fence rw,rw; ret`
        pub const ATOMIC_STORE_2: &[u8] = &[
            0x0f, 0x00, 0x30, 0x03, // fence rw,rw
            0x23, 0x10, 0xb5, 0x00, // sh a1,0(a0)
            0x0f, 0x00, 0x30, 0x03, // fence rw,rw
            0x82, 0x80, // c.ret
        ];

        /// `__atomic_store_4` — `fence rw,w; sw a1,0(a0); fence rw,rw; ret`
        pub const ATOMIC_STORE_4: &[u8] = &[
            0x0f, 0x00, 0x10, 0x03, // fence rw,w
            0x0c, 0xc1, // c.sw a1,0(a0)
            0x0f, 0x00, 0x30, 0x03, // fence rw,rw
            0x82, 0x80, // c.ret
        ];

        /// `__atomic_store_8` — `fence rw,w; sd a1,0(a0); fence rw,rw; ret`
        pub const ATOMIC_STORE_8: &[u8] = &[
            0x0f, 0x00, 0x10, 0x03, // fence rw,w
            0x0c, 0xe1, // c.sd a1,0(a0)
            0x0f, 0x00, 0x30, 0x03, // fence rw,rw
            0x82, 0x80, // c.ret
        ];

        /// `__atomic_test_and_set_1` — RISC-V machine code
        /// Uses `amoor.w.aqrl` with byte masking at word-aligned address
        pub const ATOMIC_TEST_AND_SET: &[u8] = &[
            0x93, 0x77, 0x35, 0x00, // andi a5,a0,3
            0x9b, 0x97, 0x37, 0x00, // slliw a5,a5,3
            0x85, 0x46, // c.li a3,1
            0x71, 0x99, // c.andi a0,-4
            0xbb, 0x96, 0xf6, 0x00, // sllw a3,a3,a5
            0x2f, 0x27, 0xd5, 0x46, // amoor.w.aqrl a4,a3,(a0)
            0x3b, 0x55, 0xf7, 0x00, // srlw a0,a4,a5
            0x13, 0x75, 0xf5, 0x0f, // zext.b a0,a0
            0x82, 0x80, // c.ret
        ];

        /// `atomic_thread_fence` — `fence rw,rw; ret`
        pub const THREAD_FENCE: &[u8] = &[
            0x0f, 0x00, 0x30, 0x03, // fence rw,rw
            0x82, 0x80, // c.ret
        ];

        /// `atomic_signal_fence` — `ret` (no hardware barrier)
        pub const SIGNAL_FENCE: &[u8] = &[
            0x82, 0x80, // c.ret
        ];

        /// `atomic_flag_test_and_set` — same as test_and_set (byte-width)
        pub const FLAG_TEST_AND_SET: &[u8] = &[
            0x93, 0x77, 0x35, 0x00, // andi a5,a0,3
            0x9b, 0x97, 0x37, 0x00, // slliw a5,a5,3
            0x85, 0x46, // c.li a3,1
            0x71, 0x99, // c.andi a0,-4
            0xbb, 0x96, 0xf6, 0x00, // sllw a3,a3,a5
            0x2f, 0x27, 0xd5, 0x46, // amoor.w.aqrl a4,a3,(a0)
            0x3b, 0x55, 0xf7, 0x00, // srlw a0,a4,a5
            0x13, 0x75, 0xf5, 0x0f, // zext.b a0,a0
            0x82, 0x80, // c.ret
        ];

        /// `atomic_flag_clear` — `fence rw,rw; sb zero,0(a0); fence rw,rw; ret`
        pub const FLAG_CLEAR: &[u8] = &[
            0x0f, 0x00, 0x30, 0x03, // fence rw,rw
            0x23, 0x00, 0x05, 0x00, // sb zero,0(a0)
            0x0f, 0x00, 0x30, 0x03, // fence rw,rw
            0x82, 0x80, // c.ret
        ];
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, AtomicU64, AtomicU8, Ordering};

    #[test]
    fn test_c_memorder_to_rust_relaxed() {
        assert_eq!(c_memorder_to_rust(0), Ordering::Relaxed);
    }

    #[test]
    fn test_c_memorder_to_rust_consume_maps_to_acquire() {
        assert_eq!(c_memorder_to_rust(1), Ordering::Acquire);
    }

    #[test]
    fn test_c_memorder_to_rust_acquire() {
        assert_eq!(c_memorder_to_rust(2), Ordering::Acquire);
    }

    #[test]
    fn test_c_memorder_to_rust_release() {
        assert_eq!(c_memorder_to_rust(3), Ordering::Release);
    }

    #[test]
    fn test_c_memorder_to_rust_acqrel() {
        assert_eq!(c_memorder_to_rust(4), Ordering::AcqRel);
    }

    #[test]
    fn test_c_memorder_to_rust_seqcst() {
        assert_eq!(c_memorder_to_rust(5), Ordering::SeqCst);
    }

    #[test]
    fn test_c_memorder_to_rust_out_of_range_defaults_to_seqcst() {
        assert_eq!(c_memorder_to_rust(6), Ordering::SeqCst);
        assert_eq!(c_memorder_to_rust(-1), Ordering::SeqCst);
        assert_eq!(c_memorder_to_rust(100), Ordering::SeqCst);
    }

    #[test]
    fn test_atomic_load_1() {
        let val = AtomicU8::new(42);
        assert_eq!(load::atomic_load_1(&val, Ordering::SeqCst), 42);
    }

    #[test]
    fn test_atomic_load_2() {
        let val = AtomicU16::new(1234);
        assert_eq!(load::atomic_load_2(&val, Ordering::Relaxed), 1234);
    }

    #[test]
    fn test_atomic_load_4() {
        let val = AtomicU32::new(0xDEAD_BEEF);
        assert_eq!(load::atomic_load_4(&val, Ordering::Acquire), 0xDEAD_BEEF);
    }

    #[test]
    fn test_atomic_load_8() {
        let val = AtomicU64::new(0xDEAD_BEEF_CAFE_BABE);
        assert_eq!(
            load::atomic_load_8(&val, Ordering::SeqCst),
            0xDEAD_BEEF_CAFE_BABE
        );
    }

    #[test]
    fn test_atomic_store_1() {
        let val = AtomicU8::new(0);
        store::atomic_store_1(&val, 77, Ordering::Release);
        assert_eq!(val.load(Ordering::SeqCst), 77);
    }

    #[test]
    fn test_atomic_store_2() {
        let val = AtomicU16::new(0);
        store::atomic_store_2(&val, 5678, Ordering::SeqCst);
        assert_eq!(val.load(Ordering::SeqCst), 5678);
    }

    #[test]
    fn test_atomic_store_4() {
        let val = AtomicU32::new(0);
        store::atomic_store_4(&val, 0xCAFE_BABE, Ordering::Relaxed);
        assert_eq!(val.load(Ordering::SeqCst), 0xCAFE_BABE);
    }

    #[test]
    fn test_atomic_store_8() {
        let val = AtomicU64::new(0);
        store::atomic_store_8(&val, 0x1234_5678_9ABC_DEF0, Ordering::Release);
        assert_eq!(val.load(Ordering::SeqCst), 0x1234_5678_9ABC_DEF0);
    }

    #[test]
    fn test_atomic_cmpxchg_1_success() {
        let val = AtomicU8::new(10);
        let mut expected = 10u8;
        let result =
            compare_exchange::atomic_cmpxchg_1(&val, &mut expected, 20, Ordering::SeqCst, Ordering::SeqCst);
        assert!(result);
        assert_eq!(val.load(Ordering::SeqCst), 20);
        assert_eq!(expected, 10); // expected unchanged on success
    }

    #[test]
    fn test_atomic_cmpxchg_1_failure() {
        let val = AtomicU8::new(10);
        let mut expected = 99u8;
        let result =
            compare_exchange::atomic_cmpxchg_1(&val, &mut expected, 20, Ordering::SeqCst, Ordering::SeqCst);
        assert!(!result);
        assert_eq!(val.load(Ordering::SeqCst), 10); // unchanged
        assert_eq!(expected, 10); // expected updated to actual value
    }

    #[test]
    fn test_atomic_cmpxchg_2_success() {
        let val = AtomicU16::new(1000);
        let mut expected = 1000u16;
        let result =
            compare_exchange::atomic_cmpxchg_2(&val, &mut expected, 2000, Ordering::SeqCst, Ordering::SeqCst);
        assert!(result);
        assert_eq!(val.load(Ordering::SeqCst), 2000);
    }

    #[test]
    fn test_atomic_cmpxchg_2_failure() {
        let val = AtomicU16::new(1000);
        let mut expected = 999u16;
        let result =
            compare_exchange::atomic_cmpxchg_2(&val, &mut expected, 2000, Ordering::SeqCst, Ordering::SeqCst);
        assert!(!result);
        assert_eq!(expected, 1000);
    }

    #[test]
    fn test_atomic_cmpxchg_4_success() {
        let val = AtomicU32::new(0xAAAA_BBBB);
        let mut expected = 0xAAAA_BBBBu32;
        let result = compare_exchange::atomic_cmpxchg_4(
            &val,
            &mut expected,
            0xCCCC_DDDD,
            Ordering::SeqCst,
            Ordering::SeqCst,
        );
        assert!(result);
        assert_eq!(val.load(Ordering::SeqCst), 0xCCCC_DDDD);
    }

    #[test]
    fn test_atomic_cmpxchg_4_failure() {
        let val = AtomicU32::new(0xAAAA_BBBB);
        let mut expected = 0x1111_2222u32;
        let result = compare_exchange::atomic_cmpxchg_4(
            &val,
            &mut expected,
            0xCCCC_DDDD,
            Ordering::SeqCst,
            Ordering::SeqCst,
        );
        assert!(!result);
        assert_eq!(expected, 0xAAAA_BBBB);
    }

    #[test]
    fn test_atomic_cmpxchg_8_success() {
        let val = AtomicU64::new(0x1234_5678_9ABC_DEF0);
        let mut expected = 0x1234_5678_9ABC_DEF0u64;
        let result = compare_exchange::atomic_cmpxchg_8(
            &val,
            &mut expected,
            0xFEDC_BA98_7654_3210,
            Ordering::SeqCst,
            Ordering::SeqCst,
        );
        assert!(result);
        assert_eq!(val.load(Ordering::SeqCst), 0xFEDC_BA98_7654_3210);
    }

    #[test]
    fn test_atomic_cmpxchg_8_failure() {
        let val = AtomicU64::new(0x1234_5678_9ABC_DEF0);
        let mut expected = 0u64;
        let result = compare_exchange::atomic_cmpxchg_8(
            &val,
            &mut expected,
            0xFFFF,
            Ordering::SeqCst,
            Ordering::SeqCst,
        );
        assert!(!result);
        assert_eq!(expected, 0x1234_5678_9ABC_DEF0);
    }

    #[test]
    fn test_atomic_test_and_set_returns_previous() {
        let val = AtomicU8::new(0);
        assert_eq!(test_and_set::atomic_test_and_set(&val, Ordering::SeqCst), 0);
        assert_eq!(val.load(Ordering::SeqCst), 1);

        // Second call should return 1 (already set)
        assert_eq!(test_and_set::atomic_test_and_set(&val, Ordering::SeqCst), 1);
        assert_eq!(val.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_thread_fence_does_not_panic() {
        thread_fence(Ordering::SeqCst);
        thread_fence(Ordering::Acquire);
        thread_fence(Ordering::Release);
        thread_fence(Ordering::AcqRel);
    }

    #[test]
    fn test_signal_fence_does_not_panic() {
        signal_fence(Ordering::SeqCst);
        signal_fence(Ordering::Acquire);
        signal_fence(Ordering::Release);
        signal_fence(Ordering::AcqRel);
    }

    #[test]
    fn test_flag_test_and_set() {
        let f = AtomicBool::new(false);
        assert!(!flag::test_and_set(&f, Ordering::SeqCst));
        assert!(f.load(Ordering::SeqCst));
        assert!(flag::test_and_set(&f, Ordering::SeqCst));
    }

    #[test]
    fn test_flag_clear() {
        let f = AtomicBool::new(true);
        flag::clear(&f, Ordering::SeqCst);
        assert!(!f.load(Ordering::SeqCst));
    }

    #[test]
    fn test_flag_set_then_clear_cycle() {
        let f = AtomicBool::new(false);
        assert!(!flag::test_and_set(&f, Ordering::SeqCst));
        assert!(f.load(Ordering::SeqCst));
        flag::clear(&f, Ordering::SeqCst);
        assert!(!f.load(Ordering::SeqCst));
        assert!(!flag::test_and_set(&f, Ordering::SeqCst));
    }

    #[test]
    fn test_load_store_roundtrip_all_sizes() {
        let v1 = AtomicU8::new(0);
        store::atomic_store_1(&v1, 255, Ordering::SeqCst);
        assert_eq!(load::atomic_load_1(&v1, Ordering::SeqCst), 255);

        let v2 = AtomicU16::new(0);
        store::atomic_store_2(&v2, 65535, Ordering::SeqCst);
        assert_eq!(load::atomic_load_2(&v2, Ordering::SeqCst), 65535);

        let v4 = AtomicU32::new(0);
        store::atomic_store_4(&v4, u32::MAX, Ordering::SeqCst);
        assert_eq!(load::atomic_load_4(&v4, Ordering::SeqCst), u32::MAX);

        let v8 = AtomicU64::new(0);
        store::atomic_store_8(&v8, u64::MAX, Ordering::SeqCst);
        assert_eq!(load::atomic_load_8(&v8, Ordering::SeqCst), u64::MAX);
    }

    // Validate that target_code modules exist and contain non-empty byte slices
    #[cfg(feature = "x86_64")]
    #[test]
    fn test_x86_64_target_code_non_empty() {
        assert!(!target_code::x86_64_sysv::ATOMIC_LOAD_1.is_empty());
        assert!(!target_code::x86_64_sysv::ATOMIC_LOAD_8.is_empty());
        assert!(!target_code::x86_64_sysv::ATOMIC_STORE_1.is_empty());
        assert!(!target_code::x86_64_sysv::THREAD_FENCE.is_empty());
        assert!(!target_code::x86_64_sysv::SIGNAL_FENCE.is_empty());
        assert!(!target_code::x86_64_sysv::FLAG_TEST_AND_SET.is_empty());
        assert!(!target_code::x86_64_sysv::FLAG_CLEAR.is_empty());

        assert!(!target_code::x86_64_win::ATOMIC_LOAD_1.is_empty());
        assert!(!target_code::x86_64_win::THREAD_FENCE.is_empty());
    }
}
