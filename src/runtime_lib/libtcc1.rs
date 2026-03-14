//! 64-bit arithmetic helpers for the TCC runtime library.
//!
//! Provides software implementations of 64-bit division, modulo, shift,
//! and float conversion operations for targets that lack hardware support.
//! These functions form the core of `libtcc1.a`.
//!
//! C equivalent: `lib/libtcc1.c` (635 lines)
//!
//! # Type Mappings
//!
//! | C Type    | Rust Type | Description            |
//! |-----------|-----------|------------------------|
//! | `Wtype`   | `i32`     | Signed machine word    |
//! | `UWtype`  | `u32`     | Unsigned machine word  |
//! | `DWtype`  | `i64`     | Signed double word     |
//! | `UDWtype` | `u64`     | Unsigned double word   |
//! | `DWunion` | —         | Replaced by bit shifts |
//!
//! # IEEE 754 Constant Translations
//!
//! The float conversion functions operate on the raw IEEE 754 bit
//! representation of floating-point values, extracting exponent and
//! mantissa fields using bitwise operations. The constants below
//! correspond exactly to the `#define` macros in `libtcc1.c`.

// 64-bit arithmetic helpers — float-to-int conversions inherently lose precision.
#![allow(clippy::cast_precision_loss)]

use std::sync::atomic;

// ============================================================================
// IEEE 754 Constants
// ============================================================================

/// Single-precision exponent bias minus 1.
///
/// C equivalent: `#define EXCESS 126` in libtcc1.c.
/// The IEEE 754 single-precision exponent bias is 127. Subtracting 1
/// accounts for the implicit leading 1-bit in the mantissa representation
/// when computing the effective shift amount.
const EXCESS: u32 = 126;

/// Single-precision sign bit mask.
///
/// C equivalent: `#define SIGNBIT 0x80000000` in libtcc1.c.
const SIGNBIT: u32 = 0x8000_0000;

/// Single-precision hidden (implicit) bit.
///
/// C equivalent: `#define HIDDEN (1 << 23)` in libtcc1.c.
/// For normalized IEEE 754 single-precision floats, bit 23 is the implicit
/// leading 1 that is not stored in the mantissa field.
const HIDDEN: u32 = 1 << 23;

/// Double-precision exponent bias minus 1.
///
/// C equivalent: `#define EXCESSD 1022` in libtcc1.c.
/// The IEEE 754 double-precision exponent bias is 1023.
const EXCESSD: u32 = 1022;

/// Double-precision hidden (implicit) bit at the 64-bit mantissa position.
///
/// C equivalent: `#define HIDDEND_LL ((long long)1 << 52)` in libtcc1.c.
const HIDDEND_LL: u64 = 1u64 << 52;

/// Double-precision sign bit mask (bit 63).
///
/// C equivalent: derived from `SIGND(fp)` macro in libtcc1.c.
const SIGNBITD: u64 = 1u64 << 63;

/// Extended-precision (x87 80-bit) exponent bias minus 1.
///
/// C equivalent: `#define EXCESSLD 16382` in libtcc1.c.
/// Since Rust does not have a native 80-bit float type, extended-precision
/// functions approximate using `f64`.
#[allow(dead_code)]
const EXCESSLD: u32 = 16382;

// ============================================================================
// Division and Modulo Operations
// ============================================================================

/// Unsigned 64-bit division with remainder.
///
/// Returns `(quotient, remainder)` for `n / d`.
///
/// C equivalent: `__udivmoddi4(UDWtype n, UDWtype d, UDWtype *rp)` in libtcc1.c.
///
/// The original C implementation uses a multi-case long division algorithm
/// operating on 32-bit word halves because it targets platforms without
/// hardware 64-bit division. Since this is compiled by the Rust compiler
/// (which has native 64-bit support), we use Rust's built-in division
/// operators which produce identical quotient and remainder values.
///
/// # Panics
///
/// Panics if `d` is zero, matching the C behavior where division by zero
/// triggers a hardware fault via `d0 = 1 / d0` (libtcc1.c line ~120).
pub(crate) fn udivmoddi4(n: u64, d: u64) -> (u64, u64) {
    (n / d, n % d)
}

/// Signed 64-bit division.
///
/// Returns the quotient of `u / v` using signed division semantics.
///
/// C equivalent: `__divdi3(DWtype u, DWtype v)` in libtcc1.c.
///
/// The C implementation converts both operands to unsigned magnitude via
/// conditional negation, performs unsigned division via `__udivmoddi4`,
/// then negates the result if the operand signs differed. This logic
/// correctly handles `i64::MIN / -1` (which wraps to `i64::MIN` in two's
/// complement arithmetic, matching C's undefined-but-typical behavior).
///
/// # Panics
///
/// Panics if `v` is zero.
#[allow(clippy::cast_possible_wrap)]
pub(crate) fn divdi3(u: i64, v: i64) -> i64 {
    let negate = (u < 0) != (v < 0);
    // unsigned_abs() handles i64::MIN correctly: |-2^63| = 2^63 as u64
    let uu = u.unsigned_abs();
    let vv = v.unsigned_abs();
    let (q, _) = udivmoddi4(uu, vv);
    // Intentional wrapping: for i64::MIN / -1, q = 2^63 which wraps to i64::MIN
    if negate {
        (q as i64).wrapping_neg()
    } else {
        q as i64
    }
}

/// Signed 64-bit modulo.
///
/// Returns the remainder of `u % v` using signed modulo semantics.
/// The result has the same sign as the dividend `u`.
///
/// C equivalent: `__moddi3(DWtype u, DWtype v)` in libtcc1.c.
///
/// # Panics
///
/// Panics if `v` is zero.
#[allow(clippy::cast_possible_wrap)]
pub(crate) fn moddi3(u: i64, v: i64) -> i64 {
    let negate = u < 0;
    let uu = u.unsigned_abs();
    let vv = v.unsigned_abs();
    let (_, r) = udivmoddi4(uu, vv);
    // Remainder has the same sign as the dividend; magnitude < divisor
    if negate {
        (r as i64).wrapping_neg()
    } else {
        r as i64
    }
}

/// Unsigned 64-bit division (quotient only).
///
/// C equivalent: `__udivdi3(UDWtype n, UDWtype d)` in libtcc1.c.
///
/// # Panics
///
/// Panics if `d` is zero.
pub(crate) fn udivdi3(n: u64, d: u64) -> u64 {
    let (q, _) = udivmoddi4(n, d);
    q
}

/// Unsigned 64-bit modulo (remainder only).
///
/// C equivalent: `__umoddi3(UDWtype n, UDWtype d)` in libtcc1.c.
///
/// # Panics
///
/// Panics if `d` is zero.
pub(crate) fn umoddi3(n: u64, d: u64) -> u64 {
    let (_, r) = udivmoddi4(n, d);
    r
}

// ============================================================================
// Bit Shift Operations
// ============================================================================

/// Arithmetic right shift of a 64-bit signed value.
///
/// Shifts `u` right by `b` bit positions with sign extension.
/// If `b` is 0, returns `u` unchanged. If `b` >= 64, returns 0 or -1
/// depending on the sign of `u`.
///
/// C equivalent: `__ashrdi3(DWtype u, Wtype b)` in libtcc1.c.
///
/// The C implementation (under `__TINYC__`) manually splits the value into
/// two 32-bit halves and performs the shift. On non-TCC compilers, it uses
/// the native 64-bit shift. We use Rust's native arithmetic right shift
/// which produces identical sign-extending behavior.
pub(crate) fn ashrdi3(u: i64, b: u32) -> i64 {
    if b == 0 {
        return u;
    }
    if b >= 64 {
        // Arithmetic shift: all bits become the sign bit
        return if u < 0 { -1 } else { 0 };
    }
    // Rust's >> on i64 is arithmetic (sign-extending), matching C behavior
    u >> b
}

/// Logical right shift of a 64-bit unsigned value.
///
/// Shifts `u` right by `b` bit positions with zero extension.
///
/// C equivalent: `__lshrdi3(DWtype u, Wtype b)` in libtcc1.c.
///
/// Note: Although the C signature uses `DWtype` (signed), the operation
/// is logical (zero-extending), so the Rust parameter is `u64`.
pub(crate) fn lshrdi3(u: u64, b: u32) -> u64 {
    if b == 0 {
        return u;
    }
    if b >= 64 {
        return 0;
    }
    u >> b
}

/// Logical left shift of a 64-bit unsigned value.
///
/// Shifts `u` left by `b` bit positions.
///
/// C equivalent: `__ashldi3(DWtype u, Wtype b)` in libtcc1.c.
pub(crate) fn ashldi3(u: u64, b: u32) -> u64 {
    if b == 0 {
        return u;
    }
    if b >= 64 {
        return 0;
    }
    u << b
}

// ============================================================================
// Unsigned Integer to Float Conversions
// ============================================================================

/// Convert unsigned 64-bit integer to IEEE 754 single-precision float.
///
/// C equivalent: `__floatundisf(UDWtype u)` in libtcc1.c.
///
/// The original C has separate `__TINYC__` and GCC paths. The TCC path
/// manually handles the case where the high bit is set (which would make
/// the value appear negative in a signed context). The GCC path simply
/// casts: `(SFtype) u`. Since Rust's `u64 as f32` correctly handles the
/// full unsigned range with round-to-nearest-even, we use the direct
/// conversion.
#[allow(clippy::cast_possible_truncation)]
pub(crate) fn floatundisf(a: u64) -> f32 {
    // Precision loss is intentional: f32 has only 24 bits of significand,
    // so u64 values > 2^24 will be rounded.
    a as f32
}

/// Convert unsigned 64-bit integer to IEEE 754 double-precision float.
///
/// C equivalent: `__floatundidf(UDWtype u)` in libtcc1.c.
///
/// Values larger than 2^53 may lose precision when converted to f64,
/// as IEEE 754 double-precision has a 53-bit significand.
#[allow(clippy::cast_possible_truncation)]
pub(crate) fn floatundidf(a: u64) -> f64 {
    a as f64
}

/// Convert unsigned 64-bit integer to extended-precision float.
///
/// C equivalent: `__floatundixf(UDWtype u)` in libtcc1.c.
///
/// Since Rust does not have a native 80-bit extended-precision float type
/// (x87 long double), this function uses `f64` as an approximation. On
/// x87 hardware, the C version would return an 80-bit value with a 64-bit
/// mantissa, providing lossless conversion for all u64 values.
#[allow(clippy::cast_possible_truncation)]
pub(crate) fn floatundixf(a: u64) -> f64 {
    a as f64
}

// ============================================================================
// Float to Unsigned Integer Conversions
// ============================================================================

/// Convert IEEE 754 single-precision float to unsigned 64-bit integer.
///
/// C equivalent: `__fixunssfdi(SFtype original_a)` in libtcc1.c.
///
/// Operates on the raw IEEE 754 bit representation rather than using
/// Rust's `as` cast, because the C function has specific behavior for
/// edge cases that differs from Rust's saturating semantics:
///
/// - **Zero/denormals**: returns 0
/// - **Overflow** (magnitude >= 2^65): returns `0x8000_0000_0000_0000`
/// - **Negative values**: returns the two's complement (wrapping negation)
/// - **NaN/Infinity**: returns `0x8000_0000_0000_0000`
///
/// Algorithm:
/// 1. Extract biased exponent (bits 23–30) and mantissa (bits 0–22)
/// 2. Add the implicit hidden bit to form a 24-bit significand
/// 3. Compute shift: `exp = biased_exponent - 150`
/// 4. Shift the significand left or right by `exp` positions
/// 5. Negate (wrapping) if the input was negative
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss
)]
pub(crate) fn fixunssfdi(a: f32) -> u64 {
    let bits = a.to_bits();

    // Extract biased exponent: bits[30:23], range 0..=255
    let exp_bits = (bits >> 23) & 0xFF;

    // Zero or denormalized → return 0
    // C equivalent: `if (!EXP(fl1.l)) return 0;`
    if exp_bits == 0 {
        return 0;
    }

    // Compute effective shift amount.
    // exp = biased_exponent - EXCESS - 24
    //     = biased_exponent - 126 - 24
    //     = biased_exponent - 150
    // Range: exp_bits is 1..=255, so exp is -149..=105
    // All values fit comfortably in i32.
    let exp = (exp_bits as i32) - (EXCESS as i32) - 24;

    // Extract 24-bit mantissa with implicit hidden bit.
    // C equivalent: `MANT(fl1.l)` = `(fl1.l & 0x7FFFFF) | HIDDEN`
    let mut l = u64::from((bits & 0x007F_FFFF) | HIDDEN);

    if exp >= 41 {
        // Overflow: 24-bit mantissa shifted by >= 41 would exceed 64 bits
        // (24 + 41 = 65 > 64). Return the overflow sentinel.
        l = 1u64 << 63;
    } else if exp >= 0 {
        // Non-negative shift: widen the significand
        // exp is 0..=40, safe to use as u32 shift amount
        l <<= exp as u32;
    } else if exp > -24 {
        // Negative shift: narrow the significand (some precision lost)
        // -exp is 1..=23, safe to use as u32 shift amount
        l >>= (-exp) as u32;
    } else {
        // Exponent too small: value rounds to zero
        // (biased_exp <= 126, so the value is < 1.0)
        return 0;
    }

    // For negative inputs, compute two's complement (wrapping negation)
    // C equivalent: `if (fl1.l < 0) l = -l;`
    if bits & SIGNBIT != 0 {
        l = l.wrapping_neg();
    }

    l
}

/// Convert IEEE 754 single-precision float to signed 64-bit integer.
///
/// C equivalent: `__fixsfdi(SFtype a)` in libtcc1.c.
///
/// Converts via absolute value: for non-negative inputs, delegates to
/// `fixunssfdi` and reinterprets the result as signed. For negative
/// inputs, negates the input, converts, and negates the result.
#[allow(clippy::cast_possible_wrap)]
pub(crate) fn fixsfdi(a: f32) -> i64 {
    if a >= 0.0 {
        // Non-negative: unsigned result reinterpreted as signed.
        // For finite values <= i64::MAX this is exact; for larger values
        // the wrap matches C behavior.
        fixunssfdi(a) as i64
    } else {
        // Negative: compute magnitude as unsigned, then negate.
        // wrapping_neg handles the i64::MIN case correctly.
        let magnitude = fixunssfdi(-a);
        (magnitude as i64).wrapping_neg()
    }
}

/// Convert IEEE 754 double-precision float to unsigned 64-bit integer.
///
/// C equivalent: `__fixunsdfdi(DFtype original_a)` in libtcc1.c.
///
/// Operates on the raw IEEE 754 bit representation with the same edge-case
/// behavior as `fixunssfdi`:
///
/// - **Zero/denormals**: returns 0
/// - **Overflow** (magnitude >= 2^65): returns `0x8000_0000_0000_0000`
/// - **Negative values**: returns the two's complement (wrapping negation)
/// - **NaN/Infinity**: returns `0x8000_0000_0000_0000`
///
/// Algorithm:
/// 1. Extract biased exponent (bits 52–62) and mantissa (bits 0–51)
/// 2. Add the implicit hidden bit to form a 53-bit significand
/// 3. Compute shift: `exp = biased_exponent - 1075`
/// 4. Shift the significand left or right by `exp` positions
/// 5. Negate (wrapping) if the input was negative
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss
)]
pub(crate) fn fixunsdfdi(a: f64) -> u64 {
    let bits = a.to_bits();

    // Extract biased exponent: bits[62:52], range 0..=2047
    // Truncation is safe: (bits >> 52) & 0x7FF is at most 2047 which fits u32
    let exp_bits = ((bits >> 52) & 0x7FF) as u32;

    // Zero or denormalized → return 0
    if exp_bits == 0 {
        return 0;
    }

    // Compute effective shift amount.
    // exp = biased_exponent - EXCESSD - 53
    //     = biased_exponent - 1022 - 53
    //     = biased_exponent - 1075
    // Range: exp_bits is 1..=2047, so exp is -1074..=972
    // All values fit comfortably in i32.
    let exp = (exp_bits as i32) - (EXCESSD as i32) - 53;

    // Extract 53-bit mantissa with implicit hidden bit.
    // C equivalent: `MANTD_LL(fl1)` = `(fl1.ll & 0x000FFFFFFFFFFFFF) | HIDDEND_LL`
    let mut l = (bits & 0x000F_FFFF_FFFF_FFFF) | HIDDEND_LL;

    if exp >= 12 {
        // Overflow: 53-bit mantissa shifted by >= 12 would exceed 64 bits
        // (53 + 12 = 65 > 64). Return the overflow sentinel.
        l = 1u64 << 63;
    } else if exp >= 0 {
        // Non-negative shift: widen the significand
        l <<= exp as u32;
    } else if exp > -53 {
        // Negative shift: narrow the significand
        l >>= (-exp) as u32;
    } else {
        // Value rounds to zero
        return 0;
    }

    // For negative inputs, compute two's complement
    if bits & SIGNBITD != 0 {
        l = l.wrapping_neg();
    }

    l
}

/// Convert IEEE 754 double-precision float to signed 64-bit integer.
///
/// C equivalent: `__fixdfdi(DFtype a)` in libtcc1.c.
///
/// Converts via absolute value, same pattern as `fixsfdi`.
#[allow(clippy::cast_possible_wrap)]
pub(crate) fn fixdfdi(a: f64) -> i64 {
    if a >= 0.0 {
        fixunsdfdi(a) as i64
    } else {
        let magnitude = fixunsdfdi(-a);
        (magnitude as i64).wrapping_neg()
    }
}

/// Convert extended-precision float to unsigned 64-bit integer.
///
/// C equivalent: `__fixunsxfdi(XFtype original_a)` in libtcc1.c.
///
/// Since Rust does not have a native 80-bit extended-precision float type
/// (x87 `long double`), this function processes `f64` values using the
/// same algorithm as `fixunsdfdi`. On x87 hardware, the C version operates
/// on the full 80-bit representation with a 64-bit explicit mantissa and
/// 15-bit exponent; here we approximate with the f64 subset.
///
/// The C algorithm for extended precision:
/// - Mantissa is 64 bits with an explicit integer bit (no hidden bit)
/// - `exp = biased_exponent - EXCESSLD - 64`
/// - Overflow if `exp > 0` (value >= 2^64)
/// - Underflow if `exp < -63` (value < 1)
pub(crate) fn fixunsxfdi(a: f64) -> u64 {
    // Delegate to double-precision conversion as approximation.
    // The x87 80-bit format provides higher precision than f64, but since
    // Rust lacks the type, this is the best we can do.
    fixunsdfdi(a)
}

/// Convert extended-precision float to signed 64-bit integer.
///
/// C equivalent: `__fixxfdi(XFtype a)` in libtcc1.c.
///
/// Since Rust lacks native 80-bit float support, delegates to the f64
/// conversion implementation via `fixunsxfdi`.
#[allow(clippy::cast_possible_wrap)]
pub(crate) fn fixxfdi(a: f64) -> i64 {
    if a >= 0.0 {
        fixunsxfdi(a) as i64
    } else {
        let magnitude = fixunsxfdi(-a);
        (magnitude as i64).wrapping_neg()
    }
}

// ============================================================================
// Platform-Specific Operations
// ============================================================================

/// Fast store fence providing sequential consistency memory ordering.
///
/// C equivalent: `__faststorefence()` in libtcc1.c (Windows x86-64 only).
///
/// The original C implementation uses inline assembly
/// (`lock; orl $0,(%rsp)`) on Windows x86-64 to enforce a full store
/// fence. In Rust, `std::sync::atomic::fence(SeqCst)` provides equivalent
/// sequential consistency guarantees across all platforms.
///
/// On non-Windows targets, the C original does not define this function.
/// We provide it unconditionally for API completeness; the optimizer will
/// select the appropriate hardware fence instruction for the target.
pub(crate) fn faststorefence() {
    atomic::fence(atomic::Ordering::SeqCst);
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // --- Division tests ---

    #[test]
    fn test_udivmoddi4_basic() {
        assert_eq!(udivmoddi4(10, 3), (3, 1));
        assert_eq!(udivmoddi4(100, 7), (14, 2));
        assert_eq!(udivmoddi4(0, 1), (0, 0));
        assert_eq!(udivmoddi4(1, 1), (1, 0));
        assert_eq!(udivmoddi4(u64::MAX, 1), (u64::MAX, 0));
        assert_eq!(udivmoddi4(u64::MAX, u64::MAX), (1, 0));
    }

    #[test]
    fn test_divdi3_basic() {
        assert_eq!(divdi3(10, 3), 3);
        assert_eq!(divdi3(-10, 3), -3);
        assert_eq!(divdi3(10, -3), -3);
        assert_eq!(divdi3(-10, -3), 3);
        assert_eq!(divdi3(0, 5), 0);
        assert_eq!(divdi3(i64::MIN, 1), i64::MIN);
    }

    #[test]
    fn test_divdi3_min_div_neg1() {
        // i64::MIN / -1 should wrap to i64::MIN (matching C unsigned-path behavior)
        assert_eq!(divdi3(i64::MIN, -1), i64::MIN);
    }

    #[test]
    fn test_moddi3_basic() {
        assert_eq!(moddi3(10, 3), 1);
        assert_eq!(moddi3(-10, 3), -1);
        assert_eq!(moddi3(10, -3), 1);
        assert_eq!(moddi3(-10, -3), -1);
        assert_eq!(moddi3(0, 5), 0);
    }

    #[test]
    fn test_udivdi3_umoddi3() {
        assert_eq!(udivdi3(100, 7), 14);
        assert_eq!(umoddi3(100, 7), 2);
        assert_eq!(udivdi3(u64::MAX, 2), u64::MAX / 2);
        assert_eq!(umoddi3(u64::MAX, 2), 1);
    }

    // --- Shift tests ---

    #[test]
    fn test_ashrdi3() {
        assert_eq!(ashrdi3(0x100, 4), 0x10);
        assert_eq!(ashrdi3(-1, 1), -1); // sign-extending
        assert_eq!(ashrdi3(-256, 4), -16);
        assert_eq!(ashrdi3(42, 0), 42);
        assert_eq!(ashrdi3(-1, 64), -1);
        assert_eq!(ashrdi3(100, 64), 0);
    }

    #[test]
    fn test_lshrdi3() {
        assert_eq!(lshrdi3(0x100, 4), 0x10);
        assert_eq!(lshrdi3(u64::MAX, 32), 0xFFFF_FFFF);
        assert_eq!(lshrdi3(42, 0), 42);
        assert_eq!(lshrdi3(42, 64), 0);
    }

    #[test]
    fn test_ashldi3() {
        assert_eq!(ashldi3(1, 10), 1024);
        assert_eq!(ashldi3(0xFF, 8), 0xFF00);
        assert_eq!(ashldi3(42, 0), 42);
        assert_eq!(ashldi3(1, 63), 1u64 << 63);
        assert_eq!(ashldi3(1, 64), 0);
    }

    // --- Float conversion tests ---

    #[test]
    fn test_floatundisf() {
        assert_eq!(floatundisf(0), 0.0f32);
        assert_eq!(floatundisf(1), 1.0f32);
        assert_eq!(floatundisf(1000), 1000.0f32);
        // Large value: precision loss but reasonable
        let big = 1u64 << 40;
        let result = floatundisf(big);
        assert!((result - (big as f32)).abs() < 1.0);
    }

    #[test]
    fn test_floatundidf() {
        assert_eq!(floatundidf(0), 0.0f64);
        assert_eq!(floatundidf(1), 1.0f64);
        assert_eq!(floatundidf(1_000_000), 1_000_000.0f64);
    }

    #[test]
    fn test_floatundixf() {
        assert_eq!(floatundixf(0), 0.0f64);
        assert_eq!(floatundixf(1), 1.0f64);
    }

    // --- Fix unsigned tests ---

    #[test]
    fn test_fixunssfdi_basic() {
        assert_eq!(fixunssfdi(0.0f32), 0);
        assert_eq!(fixunssfdi(1.0f32), 1);
        assert_eq!(fixunssfdi(2.5f32), 2);
        assert_eq!(fixunssfdi(100.9f32), 100);
        assert_eq!(fixunssfdi(0.5f32), 0);
        assert_eq!(fixunssfdi(0.99f32), 0);
    }

    #[test]
    fn test_fixunssfdi_large() {
        // 2^63 as float
        let big = (1u64 << 63) as f32;
        assert_eq!(fixunssfdi(big), 1u64 << 63);
    }

    #[test]
    fn test_fixunssfdi_negative() {
        // Negative values produce wrapping negation (matching C behavior)
        let result = fixunssfdi(-1.0f32);
        assert_eq!(result, 1u64.wrapping_neg()); // u64::MAX
    }

    #[test]
    fn test_fixunssfdi_nan() {
        // NaN: biased exponent 255, exp = 105 >= 41, returns overflow sentinel
        assert_eq!(fixunssfdi(f32::NAN), 1u64 << 63);
    }

    #[test]
    fn test_fixsfdi_basic() {
        assert_eq!(fixsfdi(0.0f32), 0);
        assert_eq!(fixsfdi(1.0f32), 1);
        assert_eq!(fixsfdi(-1.0f32), -1);
        assert_eq!(fixsfdi(100.5f32), 100);
        assert_eq!(fixsfdi(-100.5f32), -100);
    }

    #[test]
    fn test_fixunsdfdi_basic() {
        assert_eq!(fixunsdfdi(0.0f64), 0);
        assert_eq!(fixunsdfdi(1.0f64), 1);
        assert_eq!(fixunsdfdi(2.5f64), 2);
        assert_eq!(fixunsdfdi(1_000_000.7f64), 1_000_000);
    }

    #[test]
    fn test_fixunsdfdi_large() {
        // Exact power of 2 within range
        let val = (1u64 << 52) as f64;
        assert_eq!(fixunsdfdi(val), 1u64 << 52);
    }

    #[test]
    fn test_fixunsdfdi_negative() {
        let result = fixunsdfdi(-1.0f64);
        assert_eq!(result, 1u64.wrapping_neg());
    }

    #[test]
    fn test_fixdfdi_basic() {
        assert_eq!(fixdfdi(0.0f64), 0);
        assert_eq!(fixdfdi(1.0f64), 1);
        assert_eq!(fixdfdi(-1.0f64), -1);
        assert_eq!(fixdfdi(123456789.0f64), 123456789);
        assert_eq!(fixdfdi(-123456789.0f64), -123456789);
    }

    #[test]
    fn test_fixunsxfdi() {
        assert_eq!(fixunsxfdi(0.0f64), 0);
        assert_eq!(fixunsxfdi(42.0f64), 42);
    }

    #[test]
    fn test_fixxfdi() {
        assert_eq!(fixxfdi(0.0f64), 0);
        assert_eq!(fixxfdi(42.0f64), 42);
        assert_eq!(fixxfdi(-42.0f64), -42);
    }

    // --- Fence test ---

    #[test]
    fn test_faststorefence() {
        // Just verify it doesn't panic; the fence is a CPU instruction
        faststorefence();
    }
}
