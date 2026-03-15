//! ARM EABI (Embedded Application Binary Interface) helper functions.
//!
//! Provides the `__aeabi_*` runtime support functions required by ARM targets
//! complying with the ARM EABI specification. These include float-to-integer
//! conversions, integer-to-float conversions, 64-bit shift operations,
//! 64-bit and 32-bit division helpers, and memory operation wrappers.
//!
//! C equivalent: `lib/armeabi.c` (642 lines)
//!
//! ## Key Translations from C
//!
//! | C Construct | Rust Equivalent | Rationale |
//! |---|---|---|
//! | `double_unsigned_struct` | `DoubleUnsigned` | Two `u32` halves for register-pair representation |
//! | `unsigned_int_struct` | `UnsignedInt` | `u32` low + `i32` high for signed 64-bit in registers |
//! | `REGS_RETURN` macro | Direct return values | No ABI hack needed in Rust |
//! | `DEFINE__AEABI_F2XLZ` macro | Individual functions | Macro expanded into standalone fns |
//! | `AEABI_UXDIVMOD` macro | Software division fns | Checked arithmetic with div-by-zero guard |
//! | Hardware `sdiv`/`udiv` asm | Rust `/` and `%` operators | Compiler selects best instruction |
//! | `memcpy`/`memmove`/`memset` | Safe slice operations | Bounds-checked copies/fills |
//!
//! ## Safety
//!
//! This module contains **zero `unsafe` blocks**. All operations use safe Rust
//! arithmetic, bounds-checked slice operations, and explicit overflow handling.
//! Division by zero returns `(0, 0)` instead of panicking.

// ---------------------------------------------------------------------------
// Struct Definitions — Register-Pair Representations
// ---------------------------------------------------------------------------

/// 64-bit unsigned value split into two 32-bit halves (little-endian ARM).
///
/// On ARM, 64-bit values are passed and returned in two 32-bit general-purpose
/// registers. This struct models that register pair layout with the low word
/// first (little-endian convention).
///
/// C equivalent: `double_unsigned_struct` in `armeabi.c` lines 39–42.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DoubleUnsigned {
    /// Low 32 bits (first register in ARM calling convention).
    pub low: u32,
    /// High 32 bits (second register in ARM calling convention).
    pub high: u32,
}

impl DoubleUnsigned {
    /// Construct from a 64-bit unsigned value by splitting into two halves.
    ///
    /// Intentionally truncates each half to 32 bits — this is the core purpose
    /// of the function (extracting register-pair halves).
    #[allow(clippy::cast_possible_truncation)] // Intentional: extracting 32-bit halves from u64
    pub(crate) fn from_u64(val: u64) -> Self {
        Self {
            low: val as u32,
            high: (val >> 32) as u32,
        }
    }

    /// Reconstruct the full 64-bit unsigned value from the two halves.
    pub(crate) fn to_u64(self) -> u64 {
        (u64::from(self.high) << 32) | u64::from(self.low)
    }
}

/// 64-bit value split with unsigned low half and signed high half.
///
/// Used for returning signed 64-bit results through the ARM register pair
/// ABI, where the upper register carries the sign information.
///
/// C equivalent: `unsigned_int_struct` in `armeabi.c` lines 44–47.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct UnsignedInt {
    /// Low 32 bits (unsigned).
    pub low: u32,
    /// High 32 bits (signed — carries the sign for negative values).
    pub high: i32,
}

// ---------------------------------------------------------------------------
// IEEE 754 Reference Constants (retained for documentation)
// ---------------------------------------------------------------------------
//
// The original C implementation (`armeabi.c`) uses bit-level IEEE 754
// extraction with these constants for float-to-integer and integer-to-float
// conversions:
//
//   FLOAT_EXP_BITS  = 8   (single-precision exponent width)
//   FLOAT_FRAC_BITS = 23  (single-precision mantissa width)
//   DOUBLE_EXP_BITS = 11  (double-precision exponent width)
//   DOUBLE_FRAC_BITS = 52 (double-precision mantissa width)
//   FLOAT_ONE_EXP   = 127 (single-precision exponent bias)
//   DOUBLE_ONE_EXP  = 1023 (double-precision exponent bias)
//
// In Rust, we use native `as` casts which are well-defined and produce
// saturating behavior for float-to-integer conversions (since Rust 1.45).
// This eliminates the need for manual bit manipulation and the associated
// risk of off-by-one errors in the exponent/mantissa extraction.

// ---------------------------------------------------------------------------
// Float-to-Integer Conversions
// ---------------------------------------------------------------------------

/// Convert a double-precision float to a signed 64-bit integer.
///
/// Performs the same saturating conversion as the C `__aeabi_d2lz` function,
/// which extracts sign, exponent, and mantissa bits from the IEEE 754
/// representation and reconstructs the integer value.
///
/// In Rust, `f64 as i64` performs a saturating cast (values outside i64 range
/// are clamped to `i64::MIN` or `i64::MAX`), which is safe and well-defined.
///
/// C equivalent: `__aeabi_d2lz` in `armeabi.c` (via `DEFINE__AEABI_D2XLZ` macro).
#[allow(clippy::cast_possible_truncation)] // Intentional: float-to-int conversion is the function's purpose
pub(crate) fn aeabi_d2lz(d: f64) -> i64 {
    d as i64
}

/// Convert a double-precision float to an unsigned 64-bit integer.
///
/// Negative values are converted to 0 (Rust saturating cast behavior).
/// Values exceeding `u64::MAX` are clamped to `u64::MAX`.
///
/// C equivalent: `__aeabi_d2ulz` in `armeabi.c` (via `DEFINE__AEABI_D2XLZ` macro).
#[allow(clippy::cast_possible_truncation)] // Intentional: float-to-uint conversion is the function's purpose
#[allow(clippy::cast_sign_loss)] // Intentional: negative floats saturate to 0
pub(crate) fn aeabi_d2ulz(d: f64) -> u64 {
    d as u64
}

/// Convert a single-precision float to a signed 64-bit integer.
///
/// C equivalent: `__aeabi_f2lz` in `armeabi.c` (via `DEFINE__AEABI_F2XLZ` macro).
#[allow(clippy::cast_possible_truncation)] // Intentional: float-to-int conversion is the function's purpose
pub(crate) fn aeabi_f2lz(f: f32) -> i64 {
    f as i64
}

/// Convert a single-precision float to an unsigned 64-bit integer.
///
/// Negative values are converted to 0 (Rust saturating cast behavior).
///
/// C equivalent: `__aeabi_f2ulz` in `armeabi.c` (via `DEFINE__AEABI_F2XLZ` macro).
#[allow(clippy::cast_possible_truncation)] // Intentional: float-to-uint conversion is the function's purpose
#[allow(clippy::cast_sign_loss)] // Intentional: negative floats saturate to 0
pub(crate) fn aeabi_f2ulz(f: f32) -> u64 {
    f as u64
}

// ---------------------------------------------------------------------------
// Integer-to-Float Conversions
// ---------------------------------------------------------------------------

/// Convert a signed 64-bit integer to a double-precision float.
///
/// Values with more than 53 significant bits will lose precision in the
/// conversion, as IEEE 754 double has a 52-bit mantissa. This matches the
/// behavior of the C `__aeabi_l2d` function.
///
/// C equivalent: `__aeabi_l2d` in `armeabi.c` (via `__AEABI_XL2D` macro).
#[allow(clippy::cast_precision_loss)] // Intentional: precision loss mirrors C behavior for values > 2^53
pub(crate) fn aeabi_l2d(val: i64) -> f64 {
    val as f64
}

/// Convert a signed 64-bit integer to a single-precision float.
///
/// Values with more than 24 significant bits will lose precision in the
/// conversion. This matches the C `__aeabi_l2f` behavior.
///
/// C equivalent: `__aeabi_l2f` in `armeabi.c` (via `DEFINE__AEABI_XL2F` macro).
#[allow(clippy::cast_precision_loss)] // Intentional: precision loss mirrors C behavior for values > 2^24
pub(crate) fn aeabi_l2f(val: i64) -> f32 {
    val as f32
}

/// Convert an unsigned 64-bit integer to a double-precision float.
///
/// C equivalent: `__aeabi_ul2d` in `armeabi.c` (via `__AEABI_XL2D` macro).
#[allow(clippy::cast_precision_loss)] // Intentional: precision loss mirrors C behavior for values > 2^53
pub(crate) fn aeabi_ul2d(val: u64) -> f64 {
    val as f64
}

/// Convert an unsigned 64-bit integer to a single-precision float.
///
/// C equivalent: `__aeabi_ul2f` in `armeabi.c` (via `DEFINE__AEABI_XL2F` macro).
#[allow(clippy::cast_precision_loss)] // Intentional: precision loss mirrors C behavior for values > 2^24
pub(crate) fn aeabi_ul2f(val: u64) -> f32 {
    val as f32
}

// ---------------------------------------------------------------------------
// 64-bit Shift Operations
// ---------------------------------------------------------------------------

/// Logical left shift of a 64-bit unsigned value.
///
/// If the shift amount is 32 or greater, the original C implementation
/// moves the low word into the high word (or zeroes everything if shift ≥ 64).
/// This Rust version uses native 64-bit shifts with overflow protection.
///
/// C equivalent: `__aeabi_llsl` in `armeabi.c` lines 430–446.
pub(crate) fn aeabi_llsl(val: u64, shift: u32) -> u64 {
    if shift >= 64 {
        0
    } else {
        val << shift
    }
}

/// Logical right shift of a 64-bit unsigned value.
///
/// Fills vacated high bits with zeros. If shift ≥ 64, the result is zero.
///
/// C equivalent: `__aeabi_llsr` in `armeabi.c` lines 464–467
/// (via `aeabi_lsr` macro with `fill = 0`).
pub(crate) fn aeabi_llsr(val: u64, shift: u32) -> u64 {
    if shift >= 64 {
        0
    } else {
        val >> shift
    }
}

/// Arithmetic right shift of a 64-bit signed value.
///
/// Fills vacated high bits with the sign bit. If shift ≥ 64, the result
/// is either 0 (for positive values) or -1 (for negative values), which
/// is equivalent to `val >> 63`.
///
/// C equivalent: `__aeabi_lasr` in `armeabi.c` lines 469–472
/// (via `aeabi_lsr` macro with `fill = val.high >> 31`).
pub(crate) fn aeabi_lasr(val: i64, shift: u32) -> i64 {
    if shift >= 64 {
        // Sign-extend: positive → 0, negative → -1
        val >> 63
    } else {
        val >> shift
    }
}

// ---------------------------------------------------------------------------
// 64-bit Division Functions
// ---------------------------------------------------------------------------

/// Signed 64-bit division with remainder.
///
/// Returns `(quotient, remainder)`. Division by zero returns `(0, 0)` as a
/// safe default instead of panicking. Overflow case (`i64::MIN / -1`) also
/// returns a safe value `(i64::MIN, 0)` matching wrapping hardware behavior.
///
/// The original C implementation uses a software long-division algorithm
/// (`AEABI_UXDIVMOD` macro) that performs repeated subtraction with
/// power-of-two acceleration. The Rust port uses native division, which
/// the compiler will map to the best available instruction.
///
/// C equivalent: `__aeabi_ldivmod` in `armeabi.c` lines 382–428.
pub(crate) fn aeabi_ldivmod(num: i64, den: i64) -> (i64, i64) {
    if den == 0 {
        return (0, 0);
    }
    // Handle overflow: i64::MIN / -1 would panic in Rust debug mode.
    // Wrapping division matches typical hardware behavior.
    if num == i64::MIN && den == -1 {
        return (i64::MIN, 0);
    }
    (num / den, num % den)
}

/// Unsigned 64-bit division with remainder.
///
/// Returns `(quotient, remainder)`. Division by zero returns `(0, 0)`.
///
/// C equivalent: `__aeabi_uldivmod` in `armeabi.c` lines 421–428.
pub(crate) fn aeabi_uldivmod(num: u64, den: u64) -> (u64, u64) {
    if den == 0 {
        return (0, 0);
    }
    (num / den, num % den)
}

/// Signed 32-bit division with remainder.
///
/// Returns `(quotient, remainder)`. Division by zero returns `(0, 0)`.
/// Overflow case (`i32::MIN / -1`) returns `(i32::MIN, 0)`.
///
/// C equivalent: `__aeabi_idivmod` in `armeabi.c`
/// (via `__AEABI_XDIVMOD` macro, lines 382–409, or hardware `sdiv` at line 558).
pub(crate) fn aeabi_idivmod(num: i32, den: i32) -> (i32, i32) {
    if den == 0 {
        return (0, 0);
    }
    // Handle overflow: i32::MIN / -1 would panic in Rust debug mode.
    if num == i32::MIN && den == -1 {
        return (i32::MIN, 0);
    }
    (num / den, num % den)
}

/// Unsigned 32-bit division with remainder.
///
/// Returns `(quotient, remainder)`. Division by zero returns `(0, 0)`.
///
/// C equivalent: `__aeabi_uidivmod` in `armeabi.c`
/// (via `AEABI_UXDIVMOD` macro or hardware `udiv` at line 564).
pub(crate) fn aeabi_uidivmod(num: u32, den: u32) -> (u32, u32) {
    if den == 0 {
        return (0, 0);
    }
    (num / den, num % den)
}

// ---------------------------------------------------------------------------
// 32-bit Division (Quotient Only)
// ---------------------------------------------------------------------------

/// Signed 32-bit integer division (quotient only, no remainder).
///
/// This is the ARM EABI `__aeabi_idiv` entry point. The original C implementation
/// provides both a software loop version (disabled via `#if 0`) and a hardware
/// `sdiv` instruction version (enabled via `UIDIVMOD_ASM`). For Cortex-M0 targets
/// without hardware divide, the software fallback delegates to `__aeabi_uidivmod`
/// with sign fixup.
///
/// Division by zero returns 0. Overflow (`i32::MIN / -1`) returns `i32::MIN`.
///
/// C equivalent: `__aeabi_idiv` in `armeabi.c` lines 480–497 (software)
/// or lines 557–562 / 580–606 (hardware/Cortex-M0 assembly).
pub(crate) fn aeabi_idiv(num: i32, den: i32) -> i32 {
    if den == 0 {
        return 0;
    }
    if num == i32::MIN && den == -1 {
        return i32::MIN;
    }
    num / den
}

/// Unsigned 32-bit integer division (quotient only, no remainder).
///
/// This is the ARM EABI `__aeabi_uidiv` entry point. Division by zero returns 0.
///
/// C equivalent: `__aeabi_uidiv` in `armeabi.c` lines 499–502 (software)
/// or lines 564–565 / 609–637 (hardware/Cortex-M0 assembly).
pub(crate) fn aeabi_uidiv(num: u32, den: u32) -> u32 {
    if den == 0 {
        return 0;
    }
    num / den
}

// ---------------------------------------------------------------------------
// Memory Operation Wrappers
// ---------------------------------------------------------------------------

/// Copy `n` bytes from `src` to `dest` (non-overlapping regions).
///
/// Equivalent to a simple `memcpy`. The length is clamped to the minimum of
/// `n`, `dest.len()`, and `src.len()` to prevent out-of-bounds access.
///
/// C equivalent: `__aeabi_memcpy` in `armeabi.c` lines 520–524.
pub(crate) fn aeabi_memcpy(dest: &mut [u8], src: &[u8], n: usize) {
    let len = n.min(dest.len()).min(src.len());
    dest[..len].copy_from_slice(&src[..len]);
}

/// Fill `n` bytes of `dest` with the byte value `val`.
///
/// Note: The ARM EABI `__aeabi_memset` has a different parameter order than
/// standard C `memset`. The C signature is `__aeabi_memset(void *s, size_t n, int c)`
/// with `n` before `c`, unlike `memset(void *s, int c, size_t n)`.
///
/// C equivalent: `__aeabi_memset` in `armeabi.c` lines 544–548.
pub(crate) fn aeabi_memset(dest: &mut [u8], val: u8, n: usize) {
    let len = n.min(dest.len());
    dest[..len].fill(val);
}

/// Copy `n` bytes from `src` to `dest`, handling overlapping regions correctly.
///
/// Equivalent to `memmove`. Uses a temporary buffer to ensure correctness
/// when source and destination memory regions overlap.
///
/// C equivalent: `__aeabi_memmove` in `armeabi.c` lines 526–530.
pub(crate) fn aeabi_memmove(dest: &mut [u8], src: &[u8], n: usize) {
    let len = n.min(dest.len()).min(src.len());
    // In safe Rust with separate slices, overlap is not possible.
    // This implementation handles the general case.
    let tmp: Vec<u8> = src[..len].to_vec();
    dest[..len].copy_from_slice(&tmp);
}

/// Copy `n` bytes with 4-byte alignment guarantee.
///
/// The ARM EABI specifies `__aeabi_memmove4` for word-aligned moves.
/// In the Rust port, alignment is handled by the underlying allocator,
/// so this is functionally identical to `aeabi_memmove`.
///
/// C equivalent: `__aeabi_memmove4` in `armeabi.c` lines 532–536.
pub(crate) fn aeabi_memmove4(dest: &mut [u8], src: &[u8], n: usize) {
    aeabi_memmove(dest, src, n);
}

/// Copy `n` bytes with 8-byte alignment guarantee.
///
/// The ARM EABI specifies `__aeabi_memmove8` for double-word-aligned moves.
/// In the Rust port, alignment is handled by the underlying allocator,
/// so this is functionally identical to `aeabi_memmove`.
///
/// C equivalent: `__aeabi_memmove8` in `armeabi.c` lines 538–542.
pub(crate) fn aeabi_memmove8(dest: &mut [u8], src: &[u8], n: usize) {
    aeabi_memmove(dest, src, n);
}

// ---------------------------------------------------------------------------
// Unit Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::float_cmp)]
mod tests {
    use super::*;

    // -- DoubleUnsigned tests --

    #[test]
    fn test_double_unsigned_roundtrip() {
        let val = 0x1234_5678_9ABC_DEF0u64;
        let du = DoubleUnsigned::from_u64(val);
        assert_eq!(du.low, 0x9ABC_DEF0);
        assert_eq!(du.high, 0x1234_5678);
        assert_eq!(du.to_u64(), val);
    }

    #[test]
    fn test_double_unsigned_zero() {
        let du = DoubleUnsigned::from_u64(0);
        assert_eq!(du.low, 0);
        assert_eq!(du.high, 0);
        assert_eq!(du.to_u64(), 0);
    }

    #[test]
    fn test_double_unsigned_max() {
        let du = DoubleUnsigned::from_u64(u64::MAX);
        assert_eq!(du.low, u32::MAX);
        assert_eq!(du.high, u32::MAX);
        assert_eq!(du.to_u64(), u64::MAX);
    }

    // -- Float-to-integer conversion tests --

    #[test]
    fn test_d2lz_positive() {
        assert_eq!(aeabi_d2lz(42.7), 42);
    }

    #[test]
    fn test_d2lz_negative() {
        assert_eq!(aeabi_d2lz(-42.7), -42);
    }

    #[test]
    fn test_d2lz_zero() {
        assert_eq!(aeabi_d2lz(0.0), 0);
    }

    #[test]
    fn test_d2ulz_positive() {
        assert_eq!(aeabi_d2ulz(42.7), 42);
    }

    #[test]
    fn test_d2ulz_negative_saturates() {
        assert_eq!(aeabi_d2ulz(-1.0), 0);
    }

    #[test]
    fn test_f2lz() {
        assert_eq!(aeabi_f2lz(100.9), 100);
        assert_eq!(aeabi_f2lz(-100.9), -100);
    }

    #[test]
    fn test_f2ulz() {
        assert_eq!(aeabi_f2ulz(255.5), 255);
        assert_eq!(aeabi_f2ulz(-1.0), 0);
    }

    // -- Integer-to-float conversion tests --

    #[test]
    fn test_l2d() {
        assert_eq!(aeabi_l2d(42), 42.0);
        assert_eq!(aeabi_l2d(-42), -42.0);
        assert_eq!(aeabi_l2d(0), 0.0);
    }

    #[test]
    fn test_l2f() {
        assert_eq!(aeabi_l2f(42), 42.0f32);
        assert_eq!(aeabi_l2f(-42), -42.0f32);
    }

    #[test]
    fn test_ul2d() {
        assert_eq!(aeabi_ul2d(42), 42.0);
        assert_eq!(aeabi_ul2d(0), 0.0);
    }

    #[test]
    fn test_ul2f() {
        assert_eq!(aeabi_ul2f(42), 42.0f32);
    }

    // -- Shift operation tests --

    #[test]
    fn test_llsl_basic() {
        assert_eq!(aeabi_llsl(1, 0), 1);
        assert_eq!(aeabi_llsl(1, 1), 2);
        assert_eq!(aeabi_llsl(1, 32), 0x1_0000_0000);
        assert_eq!(aeabi_llsl(1, 63), 1u64 << 63);
    }

    #[test]
    fn test_llsl_overflow() {
        assert_eq!(aeabi_llsl(1, 64), 0);
        assert_eq!(aeabi_llsl(1, 100), 0);
        assert_eq!(aeabi_llsl(u64::MAX, 64), 0);
    }

    #[test]
    fn test_llsr_basic() {
        assert_eq!(aeabi_llsr(0x8000_0000_0000_0000, 63), 1);
        assert_eq!(aeabi_llsr(4, 2), 1);
    }

    #[test]
    fn test_llsr_overflow() {
        assert_eq!(aeabi_llsr(u64::MAX, 64), 0);
        assert_eq!(aeabi_llsr(u64::MAX, 128), 0);
    }

    #[test]
    fn test_lasr_positive() {
        assert_eq!(aeabi_lasr(16, 2), 4);
        assert_eq!(aeabi_lasr(16, 64), 0);
    }

    #[test]
    fn test_lasr_negative() {
        assert_eq!(aeabi_lasr(-1, 1), -1);
        assert_eq!(aeabi_lasr(-1, 64), -1);
        assert_eq!(aeabi_lasr(-128, 3), -16);
    }

    // -- Division tests --

    #[test]
    fn test_ldivmod_basic() {
        assert_eq!(aeabi_ldivmod(10, 3), (3, 1));
        assert_eq!(aeabi_ldivmod(-10, 3), (-3, -1));
        assert_eq!(aeabi_ldivmod(10, -3), (-3, 1));
        assert_eq!(aeabi_ldivmod(-10, -3), (3, -1));
    }

    #[test]
    fn test_ldivmod_div_by_zero() {
        assert_eq!(aeabi_ldivmod(42, 0), (0, 0));
    }

    #[test]
    fn test_ldivmod_overflow() {
        assert_eq!(aeabi_ldivmod(i64::MIN, -1), (i64::MIN, 0));
    }

    #[test]
    fn test_uldivmod() {
        assert_eq!(aeabi_uldivmod(10, 3), (3, 1));
        assert_eq!(aeabi_uldivmod(0, 5), (0, 0));
        assert_eq!(aeabi_uldivmod(42, 0), (0, 0));
    }

    #[test]
    fn test_idivmod() {
        assert_eq!(aeabi_idivmod(10, 3), (3, 1));
        assert_eq!(aeabi_idivmod(-10, 3), (-3, -1));
        assert_eq!(aeabi_idivmod(10, 0), (0, 0));
        assert_eq!(aeabi_idivmod(i32::MIN, -1), (i32::MIN, 0));
    }

    #[test]
    fn test_uidivmod() {
        assert_eq!(aeabi_uidivmod(10, 3), (3, 1));
        assert_eq!(aeabi_uidivmod(0, 5), (0, 0));
        assert_eq!(aeabi_uidivmod(42, 0), (0, 0));
    }

    #[test]
    fn test_idiv() {
        assert_eq!(aeabi_idiv(10, 3), 3);
        assert_eq!(aeabi_idiv(-10, 3), -3);
        assert_eq!(aeabi_idiv(10, 0), 0);
        assert_eq!(aeabi_idiv(i32::MIN, -1), i32::MIN);
    }

    #[test]
    fn test_uidiv() {
        assert_eq!(aeabi_uidiv(10, 3), 3);
        assert_eq!(aeabi_uidiv(0, 5), 0);
        assert_eq!(aeabi_uidiv(42, 0), 0);
    }

    // -- Memory operation tests --

    #[test]
    fn test_memcpy() {
        let src = [1u8, 2, 3, 4, 5];
        let mut dest = [0u8; 5];
        aeabi_memcpy(&mut dest, &src, 5);
        assert_eq!(dest, [1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_memcpy_partial() {
        let src = [1u8, 2, 3, 4, 5];
        let mut dest = [0u8; 5];
        aeabi_memcpy(&mut dest, &src, 3);
        assert_eq!(dest, [1, 2, 3, 0, 0]);
    }

    #[test]
    fn test_memcpy_dest_smaller() {
        let src = [1u8, 2, 3, 4, 5];
        let mut dest = [0u8; 3];
        aeabi_memcpy(&mut dest, &src, 5);
        assert_eq!(dest, [1, 2, 3]);
    }

    #[test]
    fn test_memset() {
        let mut dest = [0u8; 5];
        aeabi_memset(&mut dest, 0xAA, 5);
        assert_eq!(dest, [0xAA; 5]);
    }

    #[test]
    fn test_memset_partial() {
        let mut dest = [0u8; 5];
        aeabi_memset(&mut dest, 0xFF, 3);
        assert_eq!(dest, [0xFF, 0xFF, 0xFF, 0, 0]);
    }

    #[test]
    fn test_memmove() {
        let src = [10u8, 20, 30];
        let mut dest = [0u8; 3];
        aeabi_memmove(&mut dest, &src, 3);
        assert_eq!(dest, [10, 20, 30]);
    }

    #[test]
    fn test_memmove4() {
        let src = [1u8, 2, 3, 4];
        let mut dest = [0u8; 4];
        aeabi_memmove4(&mut dest, &src, 4);
        assert_eq!(dest, [1, 2, 3, 4]);
    }

    #[test]
    fn test_memmove8() {
        let src = [5u8, 6, 7, 8, 9, 10, 11, 12];
        let mut dest = [0u8; 8];
        aeabi_memmove8(&mut dest, &src, 8);
        assert_eq!(dest, [5, 6, 7, 8, 9, 10, 11, 12]);
    }

    // -- UnsignedInt tests --

    #[test]
    fn test_unsigned_int_struct() {
        let ui = UnsignedInt {
            low: 0xDEAD_BEEF,
            high: -1,
        };
        assert_eq!(ui.low, 0xDEAD_BEEF);
        assert_eq!(ui.high, -1);
    }
}
