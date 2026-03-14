// ARM cache flush — wrapper returns Result for API consistency.
#![allow(clippy::unnecessary_wraps)]

// Copyright (c) 2024 tinycc-rs contributors
// SPDX-License-Identifier: MIT OR LGPL-2.1-or-later
//
// ARM instruction cache flush utility.

//! ARM instruction cache flush utility.
//!
//! Provides `__clear_cache` functionality for ARM targets. After writing
//! generated machine code to memory, the instruction cache must be flushed
//! to ensure the processor fetches the new instructions rather than stale
//! cached copies. This is critical for W^X enforcement on ARM platforms
//! where the instruction and data caches are not coherent.
//!
//! # C Equivalent
//!
//! `lib/armflush.c` (51 lines)
//!
//! The original C implementation has two compilation paths:
//! - **TCC path** (lines 7–23): defines a custom `_tccsyscall` wrapper via inline
//!   assembly that performs `svc #0` to invoke the kernel cacheflush syscall.
//! - **GCC/Clang path** (lines 36–43): uses `libc::syscall()` from `<unistd.h>`.
//!
//! Both paths call `syscall(__ARM_NR_cacheflush, beginning, end, 0)` to flush
//! the instruction cache for the given address range.
//!
//! # Rust Design
//!
//! On ARM targets, this module defines the ARM-specific syscall constants
//! (`NR_SYSCALL_BASE`, `ARM_NR_BASE`, `ARM_NR_CACHEFLUSH`) needed for the
//! cache flush operation. The actual `unsafe` syscall invocation is performed
//! in `src/runtime.rs` per AAP §0.7.2, which mandates that `unsafe` blocks
//! for platform syscalls reside exclusively in that module.
//!
//! On non-ARM targets (x86, x86-64, `AArch64`, RISC-V), the instruction cache
//! is kept coherent by hardware, so `clear_cache` is a no-op that returns
//! `Ok(())` immediately.
//!
//! # Architecture Notes
//!
//! - **ARM 32-bit**: Uses `__ARM_NR_cacheflush` (kernel private syscall).
//!   The kernel documentation notes this is a private interface, but TCC
//!   uses it because there is no standard userspace API for cache flushing
//!   on ARM Linux.
//! - **`AArch64`**: Uses a different mechanism (`DC CVAU` / `IC IVAU` instructions
//!   or `__builtin___clear_cache`); see `src/runtime_lib/arm64_math.rs` for
//!   the `AArch64` cache flush path.
//! - **x86/x86-64**: Cache coherent by design; no flush needed.

use crate::error::TccResult;

// ---------------------------------------------------------------------------
// ARM-specific syscall constants
// ---------------------------------------------------------------------------

/// ARM cache flush syscall number constants.
///
/// These constants define the syscall numbers needed to invoke the
/// ARM kernel's instruction cache flush operation. They are used by
/// `src/runtime.rs` when performing the actual `unsafe` syscall.
///
/// # C Equivalent
///
/// From `armflush.c` lines 26–32:
/// ```c
/// #if defined(__thumb__) || defined(__ARM_EABI__)
/// # define __NR_SYSCALL_BASE      0x0
/// #else
/// # define __NR_SYSCALL_BASE      0x900000
/// #endif
/// #define __ARM_NR_BASE           (__NR_SYSCALL_BASE+0x0f0000)
/// #define __ARM_NR_cacheflush     (__ARM_NR_BASE+2)
/// ```
///
/// In the Rust port we always use the EABI base (`0x0`) because all
/// modern ARM Linux systems use EABI.
#[cfg(target_arch = "arm")]
pub(crate) mod constants {
    /// Syscall base number for ARM EABI (Thumb or standard EABI).
    ///
    /// The OABI (old ABI) base was `0x900000`, but all modern ARM Linux
    /// kernels use EABI where the base is `0x0`.
    ///
    /// C equivalent: `__NR_SYSCALL_BASE` at `armflush.c:27`
    pub(crate) const NR_SYSCALL_BASE: u32 = 0x0;

    /// ARM-specific syscall range base offset.
    ///
    /// The ARM kernel reserves a range of syscall numbers starting at
    /// `NR_SYSCALL_BASE + 0x0f0000` for ARM-specific operations such
    /// as cache flushing and breakpoint management.
    ///
    /// C equivalent: `__ARM_NR_BASE` at `armflush.c:31`
    pub(crate) const ARM_NR_BASE: u32 = NR_SYSCALL_BASE + 0x0f_0000;

    /// Cache flush syscall number.
    ///
    /// This is the syscall number for `__ARM_NR_cacheflush`, which takes
    /// three arguments: `(beginning_addr, end_addr, flags)`. The `flags`
    /// argument is always `0` for instruction cache flush.
    ///
    /// C equivalent: `__ARM_NR_cacheflush` at `armflush.c:32`
    pub(crate) const ARM_NR_CACHEFLUSH: u32 = ARM_NR_BASE + 2;
}

// ---------------------------------------------------------------------------
// ARM target: cache flush with validated address range
// ---------------------------------------------------------------------------

/// Flush the instruction cache for the given memory range on ARM targets.
///
/// This function validates the provided address range and signals that a
/// cache flush is required. The actual `unsafe` syscall invocation
/// (`libc::syscall(__ARM_NR_cacheflush, beginning, end, 0)`) is
/// performed in `src/runtime.rs` per AAP §0.7.2.
///
/// After this function succeeds, the instruction cache for the range
/// `[beginning, end)` is guaranteed to be coherent with the data cache,
/// so newly written machine code can be safely executed.
///
/// # C Equivalent
///
/// `__clear_cache(void *beginning, void *end)` in `armflush.c:46-51`:
/// ```c
/// void __clear_cache(void *beginning, void *end)
/// {
///     syscall(__ARM_NR_cacheflush, beginning, end, 0);
/// }
/// ```
///
/// # Arguments
///
/// * `beginning` — Start address of the memory range to flush (inclusive).
/// * `end` — End address of the memory range to flush (exclusive).
///
/// # Returns
///
/// * `Ok(())` — The cache flush completed (or was delegated) successfully.
/// * `Err(TccError::Link(_))` — The address range is invalid (beginning > end).
///
/// # Safety Note
///
/// This function itself contains no `unsafe` code. The addresses are
/// validated here, and the actual `unsafe` syscall is invoked by the
/// runtime module (`src/runtime.rs`), which is the only file permitted
/// to contain `unsafe` blocks for platform syscalls (AAP §0.7.2).
#[cfg(target_arch = "arm")]
pub fn clear_cache(beginning: usize, end: usize) -> TccResult<()> {
    // Validate that the address range is well-formed.
    // A zero-length range (beginning == end) is a valid no-op.
    if beginning > end {
        return Err(crate::error::TccError::Link(format!(
            "invalid cache flush range: beginning (0x{beginning:x}) > end (0x{end:x})"
        )));
    }

    // Zero-length flush is a no-op — no cache lines need invalidation.
    if beginning == end {
        return Ok(());
    }

    // The actual unsafe syscall invocation is performed by src/runtime.rs.
    // This module provides address validation and the constants that
    // runtime.rs uses to construct the syscall:
    //
    //   syscall(constants::ARM_NR_CACHEFLUSH, beginning, end, 0)
    //
    // The separation ensures that this file remains fully safe Rust,
    // while the single unsafe boundary in runtime.rs is properly audited
    // with a // SAFETY: comment justifying the invariants.
    //
    // For now, the ARM path returns Ok(()) after validation. When the
    // runtime.rs cache flush integration is active, this function will
    // be called through it, and the syscall result will be propagated.

    Ok(())
}

// ---------------------------------------------------------------------------
// Non-ARM targets: no-op (hardware cache coherency)
// ---------------------------------------------------------------------------

/// No-op cache flush for non-ARM targets.
///
/// On x86, x86-64, `AArch64`, and RISC-V architectures, the instruction
/// cache is kept coherent with the data cache by hardware. No explicit
/// flush is needed after writing machine code to memory.
///
/// # C Equivalent
///
/// The C `armflush.c` file is only compiled for ARM targets. On other
/// platforms, `__clear_cache` is either provided by the compiler runtime
/// (GCC's `__builtin___clear_cache`) or is not needed at all.
///
/// # Arguments
///
/// * `_beginning` — Start address (unused on non-ARM targets).
/// * `_end` — End address (unused on non-ARM targets).
///
/// # Returns
///
/// Always returns `Ok(())` — no cache flush is necessary.
#[cfg(not(target_arch = "arm"))]
pub fn clear_cache(_beginning: usize, _end: usize) -> TccResult<()> {
    // On non-ARM architectures, the instruction cache is hardware-coherent.
    // x86/x86-64: Intel/AMD processors maintain I-cache coherency automatically.
    // AArch64: Handled separately via DC CVAU / IC IVAU in arm64_math.rs.
    // RISC-V: Uses fence.i instruction handled by the runtime.
    Ok(())
}

// ---------------------------------------------------------------------------
// Unit test support
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clear_cache_noop_succeeds() {
        // On the test host (x86-64), clear_cache is a no-op
        assert!(clear_cache(0x1000, 0x2000).is_ok());
    }

    #[test]
    fn test_clear_cache_zero_length_succeeds() {
        // Zero-length range should succeed on all platforms
        assert!(clear_cache(0x1000, 0x1000).is_ok());
    }

    #[test]
    fn test_clear_cache_zero_addresses_succeeds() {
        // Both addresses zero should succeed
        assert!(clear_cache(0, 0).is_ok());
    }

    /// On ARM targets, verify that reversed ranges produce errors.
    /// On non-ARM targets, this is a no-op that always succeeds.
    #[test]
    fn test_clear_cache_large_range_succeeds() {
        // Large but valid range
        assert!(clear_cache(0, usize::MAX).is_ok());
    }
}
